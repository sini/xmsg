//! Opt-in local metadata query. Production qualification is unavailable by default.

#[cfg(test)]
mod lineage_tests;
#[cfg(test)]
mod noninterference_tests;
pub(crate) mod resolve;
#[cfg(test)]
mod tests;

use crate::{client::caller_attribution as wire, http::AppState};
use sha2::{Digest, Sha256};
use std::{
    os::{
        fd::AsFd,
        unix::{fs::PermissionsExt, net::UnixListener},
    },
    path::PathBuf,
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
    thread::JoinHandle,
    time::{Duration, Instant},
};
use wire::{FailureReason, Reply};

pub const AUTHORITY_BUDGET: Duration = Duration::from_secs(2);
pub const MAX_INFLIGHT: usize = 4;
pub const MAX_OWNED_FDS: usize = 32;

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub query_socket: PathBuf,
    pub lifecycle_socket: PathBuf,
    pub expected_uid: u32,
}
#[derive(Clone, PartialEq, Eq)]
struct RuntimeKey {
    os: &'static str,
    arch: &'static str,
    kernel: String,
    pid_namespace: Option<(u64, u64)>,
    build: &'static str,
    uid: u32,
    node: String,
    lifecycle: PathBuf,
}
#[derive(Clone, PartialEq, Eq)]
struct EligibilityFacts {
    key: RuntimeKey,
    assumptions_revision: u64,
    expires: Instant,
    full_reaper_domain_excluded: bool,
    full_matched_identity_domain: bool,
    allowed_branches: Vec<crate::process::StrictPeerBranch>,
}
trait QualificationProvider: Send + Sync {
    fn current(&self, key: &RuntimeKey) -> Option<EligibilityFacts>;
}
#[cfg(test)]
struct FixtureFacts {
    expires: Instant,
    revision: std::sync::atomic::AtomicU64,
    drift: bool,
    reaper_complete: bool,
    match_complete: bool,
}
#[cfg(test)]
impl QualificationProvider for FixtureFacts {
    fn current(&self, key: &RuntimeKey) -> Option<EligibilityFacts> {
        Some(EligibilityFacts {
            key: key.clone(),
            assumptions_revision: if self.drift {
                self.revision.fetch_add(1, Ordering::AcqRel)
            } else {
                self.revision.load(Ordering::Acquire)
            },
            expires: self.expires,
            full_reaper_domain_excluded: self.reaper_complete,
            full_matched_identity_domain: self.match_complete,
            allowed_branches: vec![
                crate::process::StrictPeerBranch::LinuxPinned,
                crate::process::StrictPeerBranch::LinuxUnsupportedFallback,
                crate::process::StrictPeerBranch::MacWeaker,
            ],
        })
    }
}
struct NoQualification;
impl QualificationProvider for NoQualification {
    fn current(&self, _: &RuntimeKey) -> Option<EligibilityFacts> {
        None
    }
}
fn eligibility(
    provider: &dyn QualificationProvider,
    key: &RuntimeKey,
) -> Result<EligibilityFacts, FailureReason> {
    let facts = provider.current(key).ok_or(FailureReason::Unqualified)?;
    if facts.key != *key
        || facts.expires <= Instant::now()
        || !facts.full_reaper_domain_excluded
        || !facts.full_matched_identity_domain
    {
        return Err(FailureReason::Unqualified);
    }
    Ok(facts)
}

#[derive(Default)]
pub struct ServerStats {
    accepted: AtomicUsize,
    active: AtomicUsize,
    peak: AtomicUsize,
    resolved: AtomicUsize,
}
impl ServerStats {
    pub fn accepted(&self) -> usize {
        self.accepted.load(Ordering::Relaxed)
    }
    pub fn active(&self) -> usize {
        self.active.load(Ordering::Relaxed)
    }
    pub fn peak(&self) -> usize {
        self.peak.load(Ordering::Relaxed)
    }
    pub fn resolved(&self) -> usize {
        self.resolved.load(Ordering::Relaxed)
    }
}
pub struct ServerHandle {
    shutdown: Arc<AtomicBool>,
    workers: Vec<JoinHandle<()>>,
    path: PathBuf,
    identity: wire::EndpointIdentity,
    uid: u32,
    stats: Arc<ServerStats>,
}
impl ServerHandle {
    pub fn stats(&self) -> Arc<ServerStats> {
        self.stats.clone()
    }
    pub fn stop(mut self) {
        self.stop_workers();
    }
    fn stop_workers(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
        if wire::private_socket(&self.path, self.uid).ok() == Some(self.identity) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}
impl Drop for ServerHandle {
    fn drop(&mut self) {
        self.stop_workers();
    }
}

/// Binds only an explicitly configured endpoint; no production tuple is enabled here.
pub fn bind_unqualified(
    config: ServerConfig,
    state: Arc<AppState>,
) -> Result<ServerHandle, FailureReason> {
    bind(config, state, Arc::new(NoQualification))
}
fn bind(
    config: ServerConfig,
    state: Arc<AppState>,
    provider: Arc<dyn QualificationProvider>,
) -> Result<ServerHandle, FailureReason> {
    if config.expected_uid != crate::client::current_uid()
        || !config.query_socket.is_absolute()
        || !config.lifecycle_socket.is_absolute()
        || config.query_socket == config.lifecycle_socket
        || state.is_leaf()
    {
        return Err(FailureReason::Endpoint);
    }
    let parent = config
        .query_socket
        .parent()
        .ok_or(FailureReason::Endpoint)?;
    crate::agent::ensure_secure_socket_dir(parent, config.expected_uid)
        .map_err(|_| FailureReason::Endpoint)?;
    if std::fs::symlink_metadata(&config.query_socket).is_ok() {
        return Err(FailureReason::Endpoint);
    }
    let listener = UnixListener::bind(&config.query_socket).map_err(|_| FailureReason::Endpoint)?;
    std::fs::set_permissions(&config.query_socket, std::fs::Permissions::from_mode(0o600))
        .map_err(|_| FailureReason::Endpoint)?;
    let identity = wire::private_socket(&config.query_socket, config.expected_uid)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| FailureReason::Internal)?;
    use std::os::fd::AsRawFd;
    if unsafe { libc::listen(listener.as_raw_fd(), MAX_INFLIGHT as i32) } < 0 {
        return Err(FailureReason::Internal);
    }
    let listener = Arc::new(listener);
    let shutdown = Arc::new(AtomicBool::new(false));
    let stats = Arc::new(ServerStats::default());
    let config = Arc::new(config);
    let mut workers: Vec<JoinHandle<()>> = Vec::new();
    let abort_shutdown = shutdown.clone();
    let abort_path = config.query_socket.clone();
    for _ in 0..MAX_INFLIGHT {
        let listener = listener.clone();
        let shutdown = shutdown.clone();
        let stats = stats.clone();
        let state = state.clone();
        let config = config.clone();
        let provider = provider.clone();
        let worker = std::thread::Builder::new()
            .name("xmsg-attribution".into())
            .spawn(move || {
                // Each fixed worker reserves eight owned-FD credits before accept/recvmsg.
                while !shutdown.load(Ordering::Acquire) {
                    let accepted = wire::with_fd_inheritance_gate(|| listener.accept());
                    let (stream, _) = match accepted {
                        Ok(value) => value,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            let mut poll = libc::pollfd {
                                fd: listener.as_raw_fd(),
                                events: libc::POLLIN,
                                revents: 0,
                            };
                            unsafe {
                                libc::poll(&mut poll, 1, 50);
                            }
                            continue;
                        }
                        Err(_) => break,
                    };
                    let deadline = Instant::now() + AUTHORITY_BUDGET;
                    stats.accepted.fetch_add(1, Ordering::Relaxed);
                    let active = stats.active.fetch_add(1, Ordering::AcqRel) + 1;
                    stats.peak.fetch_max(active, Ordering::Relaxed);
                    let result = handle(
                        &config,
                        &state,
                        provider.as_ref(),
                        &stats,
                        &stream,
                        deadline,
                    );
                    let reply = result.unwrap_or_else(|reason| Reply::Unavailable {
                        v: wire::VERSION,
                        reason,
                    });
                    if Instant::now() < deadline && !shutdown.load(Ordering::Acquire) {
                        let _ = wire::send_reply(&stream, &reply, deadline);
                    }
                    drop(stream);
                    stats.active.fetch_sub(1, Ordering::AcqRel);
                }
            });
        let worker = match worker {
            Ok(worker) => worker,
            Err(_) => {
                abort_shutdown.store(true, Ordering::Release);
                for worker in workers {
                    let _ = worker.join();
                }
                if wire::private_socket(&abort_path, crate::client::current_uid()).ok()
                    == Some(identity)
                {
                    let _ = std::fs::remove_file(&abort_path);
                }
                return Err(FailureReason::Internal);
            }
        };
        workers.push(worker);
    }
    Ok(ServerHandle {
        shutdown,
        workers,
        path: config.query_socket.clone(),
        identity,
        uid: config.expected_uid,
        stats,
    })
}
fn handle(
    config: &ServerConfig,
    state: &AppState,
    provider: &dyn QualificationProvider,
    stats: &ServerStats,
    stream: &std::os::unix::net::UnixStream,
    deadline: Instant,
) -> Result<Reply, FailureReason> {
    if wire::socket_peer(stream.as_fd())
        .map_err(|_| FailureReason::PeerUid)?
        .0
        != config.expected_uid
    {
        return Err(FailureReason::PeerUid);
    }
    let (query, original) = wire::receive_query(stream, deadline)?;
    wire::private_socket(&config.lifecycle_socket, config.expected_uid)?;
    wire::original_endpoint(original.as_fd(), &config.lifecycle_socket)?;
    let original_ids = wire::socket_peer(original.as_fd()).map_err(|_| FailureReason::PeerUid)?;
    if original_ids.0 != config.expected_uid {
        return Err(FailureReason::PeerUid);
    }
    let mut digest = Sha256::new();
    digest.update(wire::CONTEXT_DOMAIN);
    digest.update(wire::context_bytes(&query.context)?);
    if hex::encode(digest.finalize()) != query.context_digest {
        return Err(FailureReason::Context);
    }
    let mut native: libc::utsname = unsafe { std::mem::zeroed() };
    let kernel = if unsafe { libc::uname(&mut native) } == 0 {
        unsafe { std::ffi::CStr::from_ptr(native.release.as_ptr()) }
            .to_string_lossy()
            .into_owned()
    } else {
        return Err(FailureReason::Unsupported);
    };
    #[cfg(target_os = "linux")]
    let pid_namespace = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata("/proc/self/ns/pid")
            .ok()
            .map(|m| (m.dev(), m.ino()))
    };
    #[cfg(not(target_os = "linux"))]
    let pid_namespace = None;
    let key = RuntimeKey {
        os: std::env::consts::OS,
        arch: std::env::consts::ARCH,
        kernel,
        pid_namespace,
        build: option_env!("XMSG_BUILD_REVISION").unwrap_or("unknown"),
        uid: config.expected_uid,
        node: state.node_name.clone(),
        lifecycle: config.lifecycle_socket.clone(),
    };
    let facts = eligibility(provider, &key)?;
    let original_peer =
        crate::process::strict_peer_cred_from_fd(original.as_fd(), &state.agy_config.proc_root)?;
    let query_peer =
        crate::process::strict_peer_cred_from_fd(stream.as_fd(), &state.agy_config.proc_root)?;
    if !facts.allowed_branches.contains(&original_peer.branch)
        || !facts.allowed_branches.contains(&query_peer.branch)
    {
        return Err(FailureReason::Unqualified);
    }
    stats.resolved.fetch_add(1, Ordering::Relaxed);
    let resolved = resolve::resolve(
        state,
        &original_peer.peer,
        &query_peer.peer,
        query.context.as_ref(),
        deadline,
    )?;
    crate::process::strict_revalidate(
        &original_peer,
        original.as_fd(),
        &state.agy_config.proc_root,
    )?;
    crate::process::strict_revalidate(&query_peer, stream.as_fd(), &state.agy_config.proc_root)?;
    if eligibility(provider, &key)? != facts {
        return Err(FailureReason::Changed);
    }
    if Instant::now() >= deadline {
        return Err(FailureReason::Deadline);
    }
    let pid = original_ids.1.ok_or(FailureReason::MissingPid)?;
    if original_peer.peer.pid != Some(pid) || original_peer.peer.uid != original_ids.0 {
        return Err(FailureReason::ContradictoryPeer);
    }
    Ok(Reply::Ok {
        v: wire::VERSION,
        runtime_epoch: query.runtime_epoch,
        call_nonce: query.call_nonce,
        input_digest: query.input_digest,
        context_digest: query.context_digest,
        peer_uid: original_ids.0,
        peer_pid: pid,
        principal: resolved.principal,
        authority_stamp: Box::new(resolved.stamp),
    })
}
