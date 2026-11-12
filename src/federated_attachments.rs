use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, Weak};

use crate::{attachments, error::AppError, fed::FedState, storage};

type FetchKey = (usize, String, usize);
type FetchLocks = Mutex<HashMap<FetchKey, Weak<tokio::sync::Mutex<()>>>>;

fn fetch_lock(fs: &FedState, item: &str, index: usize) -> Arc<tokio::sync::Mutex<()>> {
    static LOCKS: OnceLock<FetchLocks> = OnceLock::new();
    let mut locks = LOCKS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner());
    locks.retain(|_, lock| lock.strong_count() > 0);
    let key = (Arc::as_ptr(&fs.db) as usize, item.to_string(), index);
    if let Some(lock) = locks.get(&key).and_then(Weak::upgrade) {
        return lock;
    }
    let lock = Arc::new(tokio::sync::Mutex::new(()));
    locks.insert(key, Arc::downgrade(&lock));
    lock
}

pub async fn ensure_attachment(
    fs: &Arc<FedState>,
    item: &str,
    index: usize,
) -> Result<(), AppError> {
    ensure_attachment_budget(fs, item, index, std::time::Duration::from_secs(180)).await
}

async fn ensure_attachment_budget(
    fs: &Arc<FedState>,
    item: &str,
    index: usize,
    budget: std::time::Duration,
) -> Result<(), AppError> {
    let deadline = tokio::time::Instant::now() + budget;
    let expired = || AppError::Unavailable("attachment fetch deadline exceeded; retry".into());
    let lock = fetch_lock(fs, item, index);
    let _guard = tokio::time::timeout_at(deadline, lock.lock())
        .await
        .map_err(|_| expired())?;
    let row = {
        let db = fs
            .db
            .lock()
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let row = attachments::get_row(&db, item, index)?
            .ok_or_else(|| AppError::NotFound("attachment not found".into()))?;
        if storage::now_epoch_secs() >= row.expires_at {
            return Err(AppError::GoneDetail("attachment expired".into()));
        }
        if row.upstream.is_empty() || attachments::is_verified(&db, &row)? {
            return Ok(());
        }
        attachments::normalize_refs(
            std::slice::from_ref(&row.attachment),
            fs.max_attachment_bytes,
        )?;
        attachments::clear_fetch_chunks(&db, item, index)?;
        row
    };
    let result = tokio::time::timeout_at(deadline, async {
        let mut data = Vec::new();
        loop {
            if storage::now_epoch_secs() >= row.expires_at {
                return Err(AppError::GoneDetail("attachment expired".into()));
            }
            let remaining = row.attachment.size - data.len();
            let length = fs.max_body.min(remaining.max(1));
            if length == 0 {
                return Err(AppError::Unavailable("attachment chunk limit is zero".into()));
            }
            let chunk = match crate::fed::fetch_attachment_chunk(fs, &row.upstream, item, index, data.len() as u64, length).await {
                Ok(chunk) => chunk,
                Err(AppError::RateLimited(_)) => {
                    tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    continue;
                }
                Err(error) => return Err(error),
            };
            if chunk.len() > remaining || chunk.len() > length {
                return Err(AppError::Integrity("upstream attachment exceeds declared size".into()));
            }
            if chunk.is_empty() && remaining != 0 {
                return Err(AppError::Integrity("upstream attachment is truncated".into()));
            }
            {
                let db = fs.db.lock().map_err(|e| AppError::Internal(e.to_string()))?;
                db.execute("INSERT INTO blob_chunks (owner,upload,offset,data,created_at) VALUES (?1,?2,?3,?4,?5)",
                    rusqlite::params![format!("fetch:{item}"), index.to_string(), data.len() as i64, chunk, storage::now_epoch_secs()])
                    .map_err(|e| AppError::Internal(e.to_string()))?;
            }
            data.extend_from_slice(&chunk);
            if data.len() == row.attachment.size {
                let db = fs.db.lock().map_err(|e| AppError::Internal(e.to_string()))?;
                attachments::publish_verified(&db, &row, &data, storage::now_epoch_secs())?;
                return Ok(());
            }
        }
    }).await.unwrap_or_else(|_| Err(expired()));
    let db = fs
        .db
        .lock()
        .map_err(|e| AppError::Internal(e.to_string()))?;
    attachments::clear_fetch_chunks(&db, item, index)?;
    result
}

#[cfg(test)]
mod deadline_tests {
    use super::*;
    use crate::fed::{PeerConfig, PeersMap, RateLimiter};
    use http_body_util::Full;
    use hyper::{body::Incoming, service::service_fn, Request, Response};
    use rustls::pki_types::CertificateDer;
    use sha2::{Digest, Sha256};
    use std::sync::atomic::AtomicU64;
    use std::time::Duration;

    #[tokio::test]
    async fn fetch_deadline_cleans_partial_progress_after_repeated_rate_limits() {
        let (client_cert, client_key, client_pin) =
            crate::fed::generate_self_signed_ed25519("reader").unwrap();
        let (origin_cert, origin_key, origin_pin) =
            crate::fed::generate_self_signed_ed25519("origin").unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let acceptor = crate::fed::make_tls_acceptor(
            &[CertificateDer::from(origin_cert)],
            &origin_key,
            Arc::new(PeersMap::new(HashMap::from([(
                "reader".into(),
                PeerConfig {
                    name: "reader".into(),
                    pin: Some(client_pin),
                    allow: vec!["reply".into()],
                    ..Default::default()
                },
            )]))),
        )
        .unwrap();
        let requests = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let count = requests.clone();
        let server = tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let tls = acceptor.accept(tcp).await.unwrap();
                let count = count.clone();
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        hyper_util::rt::TokioIo::new(tls),
                        service_fn(move |_request: Request<Incoming>| {
                            let call = count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            async move {
                                let (status, payload) = if call == 0 {
                                    (hyper::StatusCode::OK, b"a".as_slice())
                                } else {
                                    (
                                        hyper::StatusCode::TOO_MANY_REQUESTS,
                                        br#"{"error":"rate_limited","detail":"slow down"}"#
                                            .as_slice(),
                                    )
                                };
                                Ok::<_, std::convert::Infallible>(
                                    Response::builder()
                                        .status(status)
                                        .body(Full::new(bytes::Bytes::copy_from_slice(payload)))
                                        .unwrap(),
                                )
                            }
                        }),
                    )
                    .await;
            }
        });
        let db = rusqlite::Connection::open_in_memory().unwrap();
        crate::storage::init_db(&db).unwrap();
        let (notify, _) = tokio::sync::broadcast::channel(16);
        let state = Arc::new(FedState {
            node_name: "reader".into(),
            peers: Arc::new(PeersMap::new(HashMap::from([(
                "origin".into(),
                PeerConfig {
                    name: "origin".into(),
                    address,
                    pin: Some(origin_pin),
                    allow: vec!["send".into(), "reply".into()],
                    ..Default::default()
                },
            )])))
            .into(),
            cert_der: client_cert,
            cert_chain_der: vec![],
            key_der: client_key,
            rate_limiter: Arc::new(RateLimiter::new(60, 20)),
            db: Arc::new(Mutex::new(db)),
            sessions_dirs: vec![],
            agy_config: crate::agy::AgyConfig {
                presence_dir: Default::default(),
                proc_locks_path: Default::default(),
                proc_root: Default::default(),
                agy_bin: "agy".into(),
                trusted_agy_exes: vec![],
                brain_dir: Default::default(),
            },
            agy_store: crate::agy::new_agy_store(),
            pi_store: crate::pi::new_pi_store(),
            pi_notify_tx: notify.clone(),
            svc_store: crate::svc::new_svc_store(),
            svc_notify_tx: notify.clone(),
            notify_tx: notify,
            max_body: 65536,
            max_attachment_bytes: crate::attachments::DEFAULT_MAX_ATTACHMENT_BYTES,
            is_leaf: false,
            leaf_principal: None,
            outbound_replies_pushed: Arc::new(AtomicU64::new(0)),
            dynamic_tls: Default::default(),
            reply_ttl: Duration::from_secs(3600),
            list_queries: Default::default(),
        });

        let reference = crate::client::wire::AttachmentRef {
            name: "file".into(),
            size: 2,
            media_type: "application/octet-stream".into(),
            sha256: hex::encode(Sha256::digest(b"ab")),
        };
        {
            let db = state.db.lock().unwrap();
            attachments::insert_rows(
                &db,
                "item",
                &[reference],
                storage::now_epoch_secs() + 60,
                "origin",
                "",
            )
            .unwrap();
        }
        let budget = Duration::from_secs(5);
        let began = tokio::time::Instant::now();
        let result = tokio::time::timeout(
            Duration::from_secs(8),
            ensure_attachment_budget(&state, "item", 0, budget),
        )
        .await
        .expect("fetch must terminate within its whole-fetch deadline");
        assert!(
            matches!(result, Err(AppError::Unavailable(ref text)) if text.contains("deadline")),
            "deadline result: {result:?}"
        );
        assert!(
            began.elapsed() >= budget,
            "429 must wait within the same fetch rather than fail immediately"
        );
        assert!(
            requests.load(std::sync::atomic::Ordering::SeqCst) >= 2,
            "fixture must accept partial progress before rate limiting"
        );
        {
            let db = state.db.lock().unwrap();
            for table in ["blob_chunks", "blobs", "attachment_verified"] {
                let count: i64 = db
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                    .unwrap();
                assert_eq!(count, 0, "deadline left partial state in {table}");
            }
        }
        // A queued caller's deadline must not erase the active owner's progress.
        let lock = fetch_lock(&state, "item", 0);
        let _held = lock.lock().await;
        {
            let db = state.db.lock().unwrap();
            db.execute("INSERT INTO blob_chunks (owner,upload,offset,data,created_at) VALUES ('fetch:item','0',0,x'61',?1)", [storage::now_epoch_secs()]).unwrap();
        }
        let queued = ensure_attachment_budget(&state, "item", 0, Duration::from_millis(10)).await;
        assert!(matches!(queued, Err(AppError::Unavailable(_))));
        assert_eq!(
            state
                .db
                .lock()
                .unwrap()
                .query_row("SELECT count(*) FROM blob_chunks", [], |r| r
                    .get::<_, i64>(0))
                .unwrap(),
            1
        );
        server.abort();
        let _ = server.await;
    }
}
