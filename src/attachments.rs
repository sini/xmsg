use base64::{engine::general_purpose::STANDARD, Engine};
use rusqlite::{params, Connection, OptionalExtension};
use serde::Serialize;
use sha2::{Digest, Sha256};

use crate::client::wire::AttachmentRef;
use crate::error::AppError;

pub const DEFAULT_MAX_ATTACHMENT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ATTACHMENTS: usize = 8;

#[derive(Clone, Copy)]
pub struct Limits {
    pub max_bytes: usize,
    pub now: i64,
    pub ttl_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttachmentRow {
    pub item_id: String,
    pub index: usize,
    pub attachment: AttachmentRef,
    pub expires_at: i64,
    pub upstream: String,
    pub downstream: String,
}

#[derive(Debug, Serialize)]
pub struct AttachmentRange {
    pub status: &'static str,
    pub attachment: AttachmentRef,
    pub offset: usize,
    pub length: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next: Option<usize>,
    pub encoding: &'static str,
    pub data: String,
    #[serde(skip)]
    pub raw_bytes: Vec<u8>,
}

fn db_err(e: impl std::fmt::Display) -> AppError {
    AppError::Internal(e.to_string())
}

fn usize_column(row: &rusqlite::Row<'_>, index: usize) -> rusqlite::Result<usize> {
    let value: i64 = row.get(index)?;
    usize::try_from(value).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            index,
            rusqlite::types::Type::Integer,
            Box::new(e),
        )
    })
}

fn expiry(now: i64, ttl_secs: u64) -> i64 {
    now.saturating_add(i64::try_from(ttl_secs).unwrap_or(i64::MAX))
}

fn check_size(size: usize, cap: usize) -> Result<(), AppError> {
    if size > cap || size > i64::MAX as usize {
        return Err(AppError::PayloadTooLarge { size, limit: cap });
    }
    Ok(())
}

pub fn sanitize_name(name: &str) -> Result<String, AppError> {
    let mut out = String::new();
    let mut space = false;
    for c in name.chars() {
        if matches!(c, '"' | '<' | '>' | '/') || c.is_control() {
            continue;
        }
        let c = if c.is_ascii() { c } else { '_' };
        if c.is_whitespace() {
            if out.is_empty() || space {
                continue;
            }
            space = true;
            out.push(' ');
        } else {
            space = false;
            out.push(c);
        }
        if out.len() == 128 {
            break;
        }
    }
    let out = out.trim_end().to_string();
    if out.is_empty() {
        return Err(AppError::BadRequest("attachment name is empty".into()));
    }
    Ok(out)
}

pub fn media_type(value: Option<&str>) -> Result<String, AppError> {
    let value = value.unwrap_or("application/octet-stream");
    let token = |part: &str| {
        !part.is_empty()
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
    };
    if value.len() > 64
        || !value
            .split_once('/')
            .is_some_and(|(a, b)| token(a) && token(b))
    {
        return Err(AppError::BadRequest("invalid attachment media_type".into()));
    }
    Ok(value.to_string())
}

fn valid_hash(hash: &str) -> bool {
    hash.len() == 64
        && hash
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

pub fn normalize_refs(refs: &[AttachmentRef], cap: usize) -> Result<Vec<AttachmentRef>, AppError> {
    if refs.len() > MAX_ATTACHMENTS {
        return Err(AppError::BadRequest(
            "at most 8 attachments are allowed".into(),
        ));
    }
    refs.iter()
        .map(|r| {
            check_size(r.size, cap)?;
            if !valid_hash(&r.sha256) {
                return Err(AppError::BadRequest("invalid attachment sha256".into()));
            }
            Ok(AttachmentRef {
                name: sanitize_name(&r.name)?,
                size: r.size,
                media_type: media_type(Some(&r.media_type))?,
                sha256: r.sha256.clone(),
            })
        })
        .collect()
}

pub fn stage(
    conn: &Connection,
    principal: &str,
    name: &str,
    claimed_media_type: Option<&str>,
    data: &[u8],
    limits: Limits,
) -> Result<AttachmentRef, AppError> {
    check_size(data.len(), limits.max_bytes)?;
    let attachment = AttachmentRef {
        name: sanitize_name(name)?,
        size: data.len(),
        media_type: media_type(claimed_media_type)?,
        sha256: hex::encode(Sha256::digest(data)),
    };
    let tx = conn.unchecked_transaction().map_err(db_err)?;
    stage_blob(&tx, principal, &attachment, data, limits)?;
    tx.commit().map_err(db_err)?;
    Ok(attachment)
}

fn stage_blob(
    conn: &Connection,
    principal: &str,
    attachment: &AttachmentRef,
    data: &[u8],
    limits: Limits,
) -> Result<(), AppError> {
    conn.execute(
        "INSERT OR IGNORE INTO blobs (sha256,size,utf8,data,created_at) VALUES (?1,?2,?3,?4,?5)",
        params![
            attachment.sha256,
            data.len() as i64,
            std::str::from_utf8(data).is_ok(),
            data,
            limits.now
        ],
    )
    .map_err(db_err)?;
    conn.execute(
        "INSERT INTO staged_blobs (principal,sha256,expires_at) VALUES (?1,?2,?3) \
         ON CONFLICT(principal,sha256) DO UPDATE SET expires_at=excluded.expires_at",
        params![
            principal,
            attachment.sha256,
            expiry(limits.now, limits.ttl_secs)
        ],
    )
    .map_err(db_err)?;
    Ok(())
}

fn check_upload(upload: &str) -> Result<(), AppError> {
    if upload.is_empty() || upload.len() > 128 || upload.chars().any(char::is_control) {
        return Err(AppError::BadRequest("invalid attachment upload id".into()));
    }
    Ok(())
}

pub fn append_chunk(
    conn: &Connection,
    principal: &str,
    upload: &str,
    offset: usize,
    data: &[u8],
    limits: Limits,
) -> Result<usize, AppError> {
    check_upload(upload)?;
    if data.is_empty() {
        return Err(AppError::BadRequest("attachment chunk is empty".into()));
    }
    check_size(data.len(), limits.max_bytes)?;
    let tx = conn.unchecked_transaction().map_err(db_err)?;
    let oldest: Option<i64> = tx
        .query_row(
            "SELECT min(created_at) FROM blob_chunks WHERE owner=?1 AND upload=?2",
            params![principal, upload],
            |r| r.get(0),
        )
        .map_err(db_err)?;
    if oldest.is_some_and(|t| expiry(t, limits.ttl_secs) <= limits.now) {
        tx.execute(
            "DELETE FROM blob_chunks WHERE owner=?1 AND upload=?2",
            params![principal, upload],
        )
        .map_err(db_err)?;
    }
    let size: usize = tx
        .query_row(
            "SELECT coalesce(sum(length(data)),0) FROM blob_chunks WHERE owner=?1 AND upload=?2",
            params![principal, upload],
            |r| usize_column(r, 0),
        )
        .map_err(db_err)?;
    if offset <= i64::MAX as usize {
        let held: Option<Vec<u8>> = tx
            .query_row(
                "SELECT data FROM blob_chunks WHERE owner=?1 AND upload=?2 AND offset=?3",
                params![principal, upload, offset as i64],
                |r| r.get(0),
            )
            .optional()
            .map_err(db_err)?;
        if let Some(held) = held {
            if held == data {
                tx.commit().map_err(db_err)?;
                return Ok(size);
            }
            return Err(AppError::Conflict(format!("chunk differs; size={size}")));
        }
    }
    if offset != size {
        return Err(AppError::Conflict(format!(
            "chunk offset differs; size={size}"
        )));
    }
    let total = size
        .checked_add(data.len())
        .ok_or(AppError::PayloadTooLarge {
            size: usize::MAX,
            limit: limits.max_bytes,
        })?;
    check_size(total, limits.max_bytes)?;
    tx.execute(
        "INSERT INTO blob_chunks (owner,upload,offset,data,created_at) VALUES (?1,?2,?3,?4,?5)",
        params![principal, upload, offset as i64, data, limits.now],
    )
    .map_err(db_err)?;
    tx.commit().map_err(db_err)?;
    Ok(total)
}

pub fn finish_upload(
    conn: &Connection,
    principal: &str,
    upload: &str,
    name: &str,
    claimed_media_type: Option<&str>,
    expected_sha: Option<&str>,
    limits: Limits,
) -> Result<AttachmentRef, AppError> {
    check_upload(upload)?;
    let name = sanitize_name(name)?;
    let media_type = media_type(claimed_media_type)?;
    if expected_sha.is_some_and(|h| !valid_hash(h)) {
        return Err(AppError::BadRequest("invalid attachment sha256".into()));
    }
    let tx = conn.unchecked_transaction().map_err(db_err)?;
    let mut stmt = tx
        .prepare("SELECT offset,data,created_at FROM blob_chunks WHERE owner=?1 AND upload=?2 ORDER BY offset")
        .map_err(db_err)?;
    let chunks = stmt
        .query_map(params![principal, upload], |r| {
            Ok((
                usize_column(r, 0)?,
                r.get::<_, Vec<u8>>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .map_err(db_err)?;
    let mut data = Vec::new();
    let mut found = false;
    for chunk in chunks {
        let (offset, bytes, created_at) = chunk.map_err(db_err)?;
        if expiry(created_at, limits.ttl_secs) <= limits.now {
            return Err(AppError::NotFoundDetail("upload expired".into()));
        }
        if offset != data.len() {
            return Err(AppError::Integrity("upload has a missing chunk".into()));
        }
        let total = data
            .len()
            .checked_add(bytes.len())
            .ok_or(AppError::PayloadTooLarge {
                size: usize::MAX,
                limit: limits.max_bytes,
            })?;
        check_size(total, limits.max_bytes)?;
        data.extend_from_slice(&bytes);
        found = true;
    }
    drop(stmt);
    if !found {
        return Err(AppError::NotFoundDetail("unknown attachment upload".into()));
    }
    let sha256 = hex::encode(Sha256::digest(&data));
    if expected_sha.is_some_and(|h| h != sha256) {
        tx.execute(
            "DELETE FROM blob_chunks WHERE owner=?1 AND upload=?2",
            params![principal, upload],
        )
        .map_err(db_err)?;
        tx.commit().map_err(db_err)?;
        return Err(AppError::Integrity("attachment sha256 mismatch".into()));
    }
    let attachment = AttachmentRef {
        name,
        size: data.len(),
        media_type,
        sha256,
    };
    stage_blob(&tx, principal, &attachment, &data, limits)?;
    tx.execute(
        "DELETE FROM blob_chunks WHERE owner=?1 AND upload=?2",
        params![principal, upload],
    )
    .map_err(db_err)?;
    tx.commit().map_err(db_err)?;
    Ok(attachment)
}

pub fn authorize_refs(
    conn: &Connection,
    principal: &str,
    refs: &[AttachmentRef],
    readable_item_ids: &[String],
    now: i64,
) -> Result<(), AppError> {
    for attachment in refs {
        let size: Option<usize> = conn
            .query_row(
                "SELECT size FROM blobs WHERE sha256=?1",
                [&attachment.sha256],
                |r| usize_column(r, 0),
            )
            .optional()
            .map_err(db_err)?;
        let staged: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM staged_blobs WHERE principal=?1 AND sha256=?2 AND expires_at>?3)",
                params![principal, attachment.sha256, now],
                |r| r.get(0),
            )
            .map_err(db_err)?;
        let mut readable = false;
        if !staged {
            for item in readable_item_ids {
                readable = conn
                    .query_row(
                        "SELECT EXISTS(SELECT 1 FROM attachments a WHERE item_id=?1 AND sha256=?2 AND expires_at>?3 AND (upstream='' OR EXISTS(SELECT 1 FROM attachment_verified v WHERE v.item_id=a.item_id AND v.idx=a.idx AND v.sha256=a.sha256 AND v.upstream=a.upstream)))",
                        params![item, attachment.sha256, now],
                        |r| r.get(0),
                    )
                    .map_err(db_err)?;
                if readable {
                    break;
                }
            }
        }
        if !staged && !readable || size.is_none() {
            return Err(AppError::NotFoundDetail(
                "attachment is not available to this sender".into(),
            ));
        }
        if size != Some(attachment.size) {
            return Err(AppError::BadRequest(
                "attachment size does not match stored blob".into(),
            ));
        }
    }
    Ok(())
}

pub fn insert_rows(
    conn: &Connection,
    item_id: &str,
    refs: &[AttachmentRef],
    expires_at: i64,
    upstream: &str,
    downstream: &str,
) -> Result<(), AppError> {
    let existing = list_rows(conn, item_id)?;
    if !existing.is_empty() {
        if existing.len() == refs.len()
            && existing.iter().zip(refs).all(|(held, attachment)| {
                held.attachment == *attachment
                    && held.upstream == upstream
                    && held.downstream == downstream
            })
        {
            return Ok(());
        }
        return Err(AppError::Conflict(
            "item already has different attachments".into(),
        ));
    }
    conn.execute(
        "DELETE FROM attachment_verified WHERE item_id=?1",
        [item_id],
    )
    .map_err(db_err)?;
    for (index, attachment) in refs.iter().enumerate() {
        conn.execute(
            "INSERT INTO attachments (item_id,idx,sha256,name,size,media_type,expires_at,upstream,downstream) \
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            params![item_id, index as i64, attachment.sha256, attachment.name, attachment.size as i64,
                attachment.media_type, expires_at, upstream, downstream],
        )
        .map_err(db_err)?;
    }
    Ok(())
}

fn row_from_sql(row: &rusqlite::Row<'_>) -> rusqlite::Result<AttachmentRow> {
    Ok(AttachmentRow {
        item_id: row.get(0)?,
        index: usize_column(row, 1)?,
        attachment: AttachmentRef {
            sha256: row.get(2)?,
            name: row.get(3)?,
            size: usize_column(row, 4)?,
            media_type: row.get(5)?,
        },
        expires_at: row.get(6)?,
        upstream: row.get(7)?,
        downstream: row.get(8)?,
    })
}

pub fn list_rows(conn: &Connection, item_id: &str) -> Result<Vec<AttachmentRow>, AppError> {
    let mut stmt = conn
        .prepare("SELECT item_id,idx,sha256,name,size,media_type,expires_at,upstream,downstream FROM attachments WHERE item_id=?1 ORDER BY idx")
        .map_err(db_err)?;
    let rows = stmt.query_map([item_id], row_from_sql).map_err(db_err)?;
    rows.collect::<rusqlite::Result<Vec<_>>>().map_err(db_err)
}

pub fn get_row(
    conn: &Connection,
    item_id: &str,
    index: usize,
) -> Result<Option<AttachmentRow>, AppError> {
    if index > i64::MAX as usize {
        return Ok(None);
    }
    conn.query_row(
        "SELECT item_id,idx,sha256,name,size,media_type,expires_at,upstream,downstream FROM attachments WHERE item_id=?1 AND idx=?2",
        params![item_id, index as i64], row_from_sql,
    )
    .optional()
    .map_err(db_err)
}

pub fn is_verified(conn: &Connection, row: &AttachmentRow) -> Result<bool, AppError> {
    conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM attachment_verified WHERE item_id=?1 AND idx=?2 AND sha256=?3 AND upstream=?4)",
        params![row.item_id, row.index as i64, row.attachment.sha256, row.upstream],
        |r| r.get(0),
    ).map_err(db_err)
}

pub fn clear_fetch_chunks(conn: &Connection, item_id: &str, index: usize) -> Result<(), AppError> {
    conn.execute(
        "DELETE FROM blob_chunks WHERE owner=?1 AND upload=?2",
        params![format!("fetch:{item_id}"), index.to_string()],
    )
    .map_err(db_err)?;
    Ok(())
}

pub fn publish_verified(
    conn: &Connection,
    row: &AttachmentRow,
    data: &[u8],
    now: i64,
) -> Result<(), AppError> {
    let tx = conn.unchecked_transaction().map_err(db_err)?;
    let current = get_row(&tx, &row.item_id, row.index)?
        .ok_or_else(|| AppError::GoneDetail("attachment row is gone".into()))?;
    if now >= current.expires_at {
        clear_fetch_chunks(&tx, &row.item_id, row.index)?;
        tx.commit().map_err(db_err)?;
        return Err(AppError::GoneDetail("attachment expired".into()));
    }
    if current != *row {
        return Err(AppError::Conflict(
            "attachment row changed during fetch".into(),
        ));
    }
    if data.len() != row.attachment.size
        || hex::encode(Sha256::digest(data)) != row.attachment.sha256
    {
        clear_fetch_chunks(&tx, &row.item_id, row.index)?;
        tx.commit().map_err(db_err)?;
        return Err(AppError::Integrity(
            "fetched attachment size or sha256 mismatch".into(),
        ));
    }
    tx.execute(
        "INSERT OR IGNORE INTO blobs (sha256,size,utf8,data,created_at) VALUES (?1,?2,?3,?4,?5)",
        params![
            row.attachment.sha256,
            data.len() as i64,
            std::str::from_utf8(data).is_ok(),
            data,
            now
        ],
    )
    .map_err(db_err)?;
    tx.execute(
        "INSERT INTO attachment_verified (item_id,idx,sha256,upstream) VALUES (?1,?2,?3,?4) \
         ON CONFLICT(item_id,idx) DO UPDATE SET sha256=excluded.sha256,upstream=excluded.upstream",
        params![
            row.item_id,
            row.index as i64,
            row.attachment.sha256,
            row.upstream
        ],
    )
    .map_err(db_err)?;
    clear_fetch_chunks(&tx, &row.item_id, row.index)?;
    tx.commit().map_err(db_err)?;
    Ok(())
}

pub fn raw_range(
    conn: &Connection,
    row: &AttachmentRow,
    offset: usize,
    length: Option<usize>,
    max_body: usize,
    now: i64,
) -> Result<Vec<u8>, AppError> {
    if now >= row.expires_at {
        return Err(AppError::GoneDetail("attachment expired".into()));
    }
    let length = length.unwrap_or(max_body).min(max_body);
    if length == 0 || offset > row.attachment.size {
        return Err(AppError::BadRequest("invalid attachment range".into()));
    }
    if !row.upstream.is_empty() && !is_verified(conn, row)? {
        return Err(AppError::Unavailable(
            "attachment requires an upstream fetch".into(),
        ));
    }
    let current = get_row(conn, &row.item_id, row.index)?
        .ok_or_else(|| AppError::GoneDetail("attachment row is gone".into()))?;
    if current != *row {
        return Err(AppError::Conflict(
            "attachment row changed during read".into(),
        ));
    }
    let size: Option<usize> = conn
        .query_row(
            "SELECT size FROM blobs WHERE sha256=?1",
            [&row.attachment.sha256],
            |r| usize_column(r, 0),
        )
        .optional()
        .map_err(db_err)?;
    let size = size.ok_or_else(|| AppError::GoneDetail("attachment bytes are gone".into()))?;
    if size != row.attachment.size {
        return Err(AppError::Integrity(
            "stored attachment size mismatch".into(),
        ));
    }
    let take = length.min(size - offset);
    if take == 0 {
        return Ok(Vec::new());
    }
    conn.query_row(
        "SELECT substr(data,?1+1,?2) FROM blobs WHERE sha256=?3",
        params![offset as i64, take as i64, row.attachment.sha256],
        |r| r.get(0),
    )
    .map_err(db_err)
}

pub fn read_range(
    conn: &Connection,
    row: &AttachmentRow,
    offset: usize,
    length: Option<usize>,
    max_body: usize,
    now: i64,
) -> Result<AttachmentRange, AppError> {
    let mut raw_bytes = raw_range(conn, row, offset, length, max_body, now)?;
    let utf8: bool = conn
        .query_row(
            "SELECT utf8 FROM blobs WHERE sha256=?1",
            [&row.attachment.sha256],
            |r| r.get(0),
        )
        .map_err(db_err)?;
    let size = row.attachment.size;
    let (encoding, data) = if utf8 {
        if raw_bytes.first().is_some_and(|b| b & 0xc0 == 0x80) {
            return Err(AppError::BadRequest(
                "attachment offset is inside a UTF-8 character".into(),
            ));
        }
        match std::str::from_utf8(&raw_bytes) {
            Ok(_) => {}
            Err(e) if e.error_len().is_none() => raw_bytes.truncate(e.valid_up_to()),
            Err(_) => return Err(AppError::Integrity("stored attachment is not UTF-8".into())),
        }
        (
            "utf-8",
            std::str::from_utf8(&raw_bytes).map_err(db_err)?.to_string(),
        )
    } else {
        ("base64", STANDARD.encode(&raw_bytes))
    };
    let end = offset + raw_bytes.len();
    Ok(AttachmentRange {
        status: "ok",
        attachment: row.attachment.clone(),
        offset,
        length: raw_bytes.len(),
        next: (end < size).then_some(end),
        encoding,
        data,
        raw_bytes,
    })
}

pub fn purge(conn: &Connection, now: i64, idempotency_ttl_secs: u64) -> Result<(), AppError> {
    let tx = conn.unchecked_transaction().map_err(db_err)?;
    tx.execute("DELETE FROM attachments WHERE expires_at<=?1", [now])
        .map_err(db_err)?;
    tx.execute(
        "DELETE FROM attachment_verified WHERE NOT EXISTS (SELECT 1 FROM attachments a WHERE a.item_id=attachment_verified.item_id AND a.idx=attachment_verified.idx AND a.sha256=attachment_verified.sha256 AND a.upstream=attachment_verified.upstream)",
        [],
    ).map_err(db_err)?;
    tx.execute("DELETE FROM staged_blobs WHERE expires_at<=?1", [now])
        .map_err(db_err)?;
    let cutoff = now.saturating_sub(i64::try_from(idempotency_ttl_secs).unwrap_or(i64::MAX));
    tx.execute("DELETE FROM blob_chunks WHERE created_at<=?1", [cutoff])
        .map_err(db_err)?;
    tx.execute(
        "DELETE FROM blobs WHERE sha256 NOT IN (SELECT sha256 FROM attachments UNION SELECT sha256 FROM staged_blobs)",
        [],
    ).map_err(db_err)?;
    tx.commit().map_err(db_err)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn db() -> Connection {
        let conn = Connection::open_in_memory().unwrap();
        crate::storage::init_db(&conn).unwrap();
        conn
    }

    fn limits() -> Limits {
        Limits {
            max_bytes: 1024,
            now: 100,
            ttl_secs: 30,
        }
    }

    fn reference(conn: &Connection, bytes: &[u8]) -> AttachmentRow {
        let attachment = stage(conn, "a", "file", None, bytes, limits()).unwrap();
        insert_rows(conn, "message", &[attachment], 200, "", "").unwrap();
        get_row(conn, "message", 0).unwrap().unwrap()
    }

    #[test]
    fn stage_scopes_hash_and_checks_claimed_size() {
        let conn = db();
        let attachment = stage(&conn, "a", "file", None, b"hello", limits()).unwrap();
        authorize_refs(&conn, "a", std::slice::from_ref(&attachment), &[], 101).unwrap();
        assert_eq!(
            authorize_refs(&conn, "b", std::slice::from_ref(&attachment), &[], 101)
                .unwrap_err()
                .code()
                .1,
            "not_found"
        );
        let mut wrong = attachment.clone();
        wrong.size += 1;
        assert_eq!(
            authorize_refs(&conn, "a", &[wrong], &[], 101)
                .unwrap_err()
                .code()
                .1,
            "bad_request"
        );
        insert_rows(
            &conn,
            "received",
            std::slice::from_ref(&attachment),
            200,
            "",
            "",
        )
        .unwrap();
        authorize_refs(
            &conn,
            "b",
            std::slice::from_ref(&attachment),
            &["received".into()],
            101,
        )
        .unwrap();
        assert_eq!(
            authorize_refs(&conn, "a", &[attachment], &[], 130)
                .unwrap_err()
                .code()
                .1,
            "not_found"
        );
    }

    #[test]
    fn upload_and_chunks_enforce_cap_without_writing_overflow() {
        let conn = db();
        let small = Limits {
            max_bytes: 3,
            ..limits()
        };
        assert_eq!(
            stage(&conn, "a", "file", None, b"four", small)
                .unwrap_err()
                .code()
                .1,
            "payload_too_large"
        );
        assert_eq!(append_chunk(&conn, "a", "u", 0, b"abc", small).unwrap(), 3);
        assert_eq!(
            append_chunk(&conn, "a", "u", 3, b"d", small)
                .unwrap_err()
                .code()
                .1,
            "payload_too_large"
        );
        let size: usize = conn
            .query_row("SELECT sum(length(data)) FROM blob_chunks", [], |r| {
                usize_column(r, 0)
            })
            .unwrap();
        assert_eq!(size, 3);
        assert_eq!(
            normalize_refs(
                &[AttachmentRef {
                    name: "x".into(),
                    size: 4,
                    media_type: "text/plain".into(),
                    sha256: "a".repeat(64)
                }],
                3
            )
            .unwrap_err()
            .code()
            .1,
            "payload_too_large"
        );
    }

    #[test]
    fn chunk_retry_is_noop_and_conflicting_offset_does_not_append() {
        let conn = db();
        assert_eq!(
            append_chunk(&conn, "a", "u", 0, b"ab", limits()).unwrap(),
            2
        );
        assert_eq!(
            append_chunk(&conn, "a", "u", 2, b"cd", limits()).unwrap(),
            4
        );
        assert_eq!(
            append_chunk(&conn, "a", "u", 0, b"ab", limits()).unwrap(),
            4
        );
        for (offset, bytes) in [(0, b"zz".as_slice()), (1, b"a"), (5, b"a")] {
            let error = append_chunk(&conn, "a", "u", offset, bytes, limits()).unwrap_err();
            assert_eq!(error.code().1, "conflict");
            assert!(error.detail().contains("size=4"));
        }
        assert_eq!(
            finish_upload(&conn, "a", "u", "file", None, None, limits())
                .unwrap()
                .size,
            4
        );
    }

    #[test]
    fn chunk_owner_and_final_hash_are_checked() {
        let conn = db();
        append_chunk(&conn, "a", "u", 0, b"hello", limits()).unwrap();
        assert_eq!(
            finish_upload(&conn, "b", "u", "file", None, None, limits())
                .unwrap_err()
                .code()
                .1,
            "not_found"
        );
        assert_eq!(
            finish_upload(
                &conn,
                "a",
                "u",
                "file",
                None,
                Some(&"0".repeat(64)),
                limits()
            )
            .unwrap_err()
            .code()
            .1,
            "integrity"
        );
        let count: usize = conn
            .query_row("SELECT count(*) FROM blobs", [], |r| usize_column(r, 0))
            .unwrap();
        assert_eq!(count, 0);
        let count: usize = conn
            .query_row("SELECT count(*) FROM blob_chunks", [], |r| {
                usize_column(r, 0)
            })
            .unwrap();
        assert_eq!(count, 0);
        append_chunk(&conn, "a", "u", 0, b"hello", limits()).unwrap();
        let attachment = finish_upload(
            &conn,
            "a",
            "u",
            "file",
            None,
            Some(&hex::encode(Sha256::digest(b"hello"))),
            limits(),
        )
        .unwrap();
        authorize_refs(&conn, "a", &[attachment], &[], 101).unwrap();
    }

    #[test]
    fn ranged_utf8_stops_before_character_and_rejects_continuation_offset() {
        let conn = db();
        let row = reference(&conn, "a€z".as_bytes());
        let range = read_range(&conn, &row, 0, Some(3), 10, 101).unwrap();
        assert_eq!(
            (
                range.data.as_str(),
                range.next,
                range.length,
                range.encoding
            ),
            ("a", Some(1), 1, "utf-8")
        );
        assert_eq!(
            read_range(&conn, &row, 1, Some(3), 10, 101).unwrap().data,
            "€"
        );
        assert_eq!(
            read_range(&conn, &row, 2, Some(1), 10, 101)
                .unwrap_err()
                .code()
                .1,
            "bad_request"
        );
        assert_eq!(
            read_range(&conn, &row, 0, Some(100), 1, 101)
                .unwrap()
                .length,
            1
        );
        assert_eq!(
            read_range(&conn, &row, 6, Some(1), 10, 101)
                .unwrap_err()
                .code()
                .1,
            "bad_request"
        );
        assert_eq!(
            read_range(&conn, &row, 0, Some(0), 10, 101)
                .unwrap_err()
                .code()
                .1,
            "bad_request"
        );
        let end = read_range(&conn, &row, 5, Some(1), 10, 101).unwrap();
        assert!(end.data.is_empty());
        assert_eq!(end.next, None);
    }

    #[test]
    fn binary_ranges_use_base64_and_empty_blob_has_no_next() {
        let conn = db();
        let row = reference(&conn, &[0xff, 0, 0x80]);
        let range = read_range(&conn, &row, 1, Some(1), 10, 101).unwrap();
        assert_eq!(range.encoding, "base64");
        assert_eq!(range.data, "AA==");
        assert_eq!(range.next, Some(2));
        let attachment = stage(&conn, "a", "empty", None, b"", limits()).unwrap();
        insert_rows(&conn, "empty", &[attachment], 200, "", "").unwrap();
        let row = get_row(&conn, "empty", 0).unwrap().unwrap();
        let end = read_range(&conn, &row, 0, None, 10, 101).unwrap();
        assert_eq!((end.length, end.next), (0, None));
    }

    #[test]
    fn expiry_is_gone_before_gc_and_gc_removes_orphan_only() {
        let conn = db();
        let row = reference(&conn, b"held");
        stage(&conn, "a", "other", None, b"orphan", limits()).unwrap();
        append_chunk(&conn, "a", "u", 0, b"partial", limits()).unwrap();
        assert_eq!(
            read_range(&conn, &row, 0, None, 10, 200)
                .unwrap_err()
                .code()
                .1,
            "gone"
        );
        purge(&conn, 130, 30).unwrap();
        let count: usize = conn
            .query_row("SELECT count(*) FROM blobs", [], |r| usize_column(r, 0))
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(
            read_range(&conn, &row, 0, None, 10, 131).unwrap().data,
            "held"
        );
        let count: usize = conn
            .query_row("SELECT count(*) FROM blob_chunks", [], |r| {
                usize_column(r, 0)
            })
            .unwrap();
        assert_eq!(count, 0);
        purge(&conn, 200, 30).unwrap();
        assert!(get_row(&conn, "message", 0).unwrap().is_none());
        let count: usize = conn
            .query_row("SELECT count(*) FROM blobs", [], |r| usize_column(r, 0))
            .unwrap();
        assert_eq!(count, 0);
    }

    fn remote_reference(conn: &Connection, item: &str, bytes: &[u8]) -> AttachmentRow {
        let attachment = AttachmentRef {
            name: "remote".into(),
            size: bytes.len(),
            media_type: "application/octet-stream".into(),
            sha256: hex::encode(Sha256::digest(bytes)),
        };
        insert_rows(conn, item, &[attachment], 200, "origin", "recipient").unwrap();
        get_row(conn, item, 0).unwrap().unwrap()
    }

    #[test]
    fn remote_cache_proof_is_per_item_and_upstream_for_both_read_paths() {
        let conn = db();
        let a = remote_reference(&conn, "a", b"same bytes");
        let b = remote_reference(&conn, "b", b"same bytes");
        publish_verified(&conn, &a, b"same bytes", 101).unwrap();
        assert_eq!(
            raw_range(&conn, &a, 0, None, 32, 101).unwrap(),
            b"same bytes"
        );
        assert_eq!(
            read_range(&conn, &a, 0, None, 32, 101).unwrap().data,
            "same bytes"
        );
        assert_eq!(
            raw_range(&conn, &b, 0, None, 32, 101).unwrap_err().code().1,
            "unavailable"
        );
        assert_eq!(
            read_range(&conn, &b, 0, None, 32, 101)
                .unwrap_err()
                .code()
                .1,
            "unavailable"
        );
        let mut changed = a;
        changed.upstream = "different".into();
        assert!(!is_verified(&conn, &changed).unwrap());
        assert_eq!(
            raw_range(&conn, &changed, 0, None, 32, 101)
                .unwrap_err()
                .code()
                .1,
            "unavailable"
        );
    }

    #[test]
    fn bad_remote_hash_or_size_clears_chunks_without_publication_and_retry_works() {
        let conn = db();
        let row = remote_reference(&conn, "remote", b"good");
        for bad in [b"evil".as_slice(), b"longer", b"bad"] {
            append_chunk(&conn, "fetch:remote", "0", 0, bad, limits()).unwrap();
            assert_eq!(
                publish_verified(&conn, &row, bad, 101)
                    .unwrap_err()
                    .code()
                    .1,
                "integrity"
            );
            assert!(!is_verified(&conn, &row).unwrap());
            for table in ["blobs", "blob_chunks"] {
                let count: i64 = conn
                    .query_row(&format!("SELECT count(*) FROM {table}"), [], |r| r.get(0))
                    .unwrap();
                assert_eq!(count, 0, "{table}");
            }
        }
        publish_verified(&conn, &row, b"good", 101).unwrap();
        assert!(is_verified(&conn, &row).unwrap());
        assert_eq!(raw_range(&conn, &row, 0, None, 32, 101).unwrap(), b"good");
        assert_eq!(
            get_row(&conn, "remote", 0).unwrap().unwrap().upstream,
            "origin"
        );
    }

    #[test]
    fn remote_raw_range_is_byte_exact_bounded_and_expiring() {
        let conn = db();
        let row = remote_reference(&conn, "remote", "€abc".as_bytes());
        publish_verified(&conn, &row, "€abc".as_bytes(), 101).unwrap();
        assert_eq!(
            raw_range(&conn, &row, 1, Some(100), 1, 101).unwrap(),
            [0x82]
        );
        assert_eq!(raw_range(&conn, &row, 6, None, 2, 101).unwrap(), b"");
        assert_eq!(
            raw_range(&conn, &row, 7, None, 2, 101)
                .unwrap_err()
                .code()
                .1,
            "bad_request"
        );
        assert_eq!(
            raw_range(&conn, &row, 0, Some(0), 2, 101)
                .unwrap_err()
                .code()
                .1,
            "bad_request"
        );
        assert_eq!(
            read_range(&conn, &row, 1, None, 2, 101)
                .unwrap_err()
                .code()
                .1,
            "bad_request"
        );
        assert_eq!(
            raw_range(&conn, &row, 0, None, 2, 200)
                .unwrap_err()
                .code()
                .1,
            "gone"
        );
        assert_eq!(
            read_range(&conn, &row, 0, None, 2, 200)
                .unwrap_err()
                .code()
                .1,
            "gone"
        );
        purge(&conn, 200, 30).unwrap();
        let count: i64 = conn
            .query_row("SELECT count(*) FROM attachment_verified", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn remote_forwarding_requires_its_own_possession_proof() {
        let conn = db();
        let local = reference(&conn, b"same bytes");
        let remote = remote_reference(&conn, "remote", b"same bytes");
        assert_eq!(
            authorize_refs(
                &conn,
                "new-sender",
                std::slice::from_ref(&local.attachment),
                &["remote".into()],
                101
            )
            .unwrap_err()
            .code()
            .1,
            "not_found"
        );
        publish_verified(&conn, &remote, b"same bytes", 101).unwrap();
        authorize_refs(
            &conn,
            "new-sender",
            &[remote.attachment],
            &["remote".into()],
            101,
        )
        .unwrap();
    }

    #[test]
    fn remote_publication_enforces_declared_size_even_for_matching_hash() {
        let conn = db();
        let mut row = remote_reference(&conn, "remote", b"oversized");
        conn.execute("UPDATE attachments SET size=3 WHERE item_id='remote'", [])
            .unwrap();
        row.attachment.size = 3;
        assert_eq!(
            publish_verified(&conn, &row, b"oversized", 101)
                .unwrap_err()
                .code()
                .1,
            "integrity"
        );
        assert!(!is_verified(&conn, &row).unwrap());
        let count: i64 = conn
            .query_row("SELECT count(*) FROM blobs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn remote_publication_rechecks_current_row_and_expiry() {
        let conn = db();
        let row = remote_reference(&conn, "remote", b"good");
        assert_eq!(
            publish_verified(&conn, &row, b"good", 200)
                .unwrap_err()
                .code()
                .1,
            "gone"
        );
        assert!(!is_verified(&conn, &row).unwrap());
        conn.execute(
            "UPDATE attachments SET upstream='other' WHERE item_id='remote'",
            [],
        )
        .unwrap();
        assert_eq!(
            publish_verified(&conn, &row, b"good", 101)
                .unwrap_err()
                .code()
                .1,
            "conflict"
        );
        assert!(!is_verified(&conn, &row).unwrap());
        let count: i64 = conn
            .query_row("SELECT count(*) FROM blobs", [], |r| r.get(0))
            .unwrap();
        assert_eq!(count, 0);
    }

    #[test]
    fn upstream_row_never_uses_locally_present_blob() {
        let conn = db();
        let mut row = reference(&conn, b"same bytes");
        row.upstream = "peer".into();
        assert_eq!(
            read_range(&conn, &row, 0, None, 10, 101)
                .unwrap_err()
                .code()
                .1,
            "unavailable"
        );
    }

    #[test]
    fn metadata_is_bounded_and_canonical() {
        let conn = db();
        let name = format!("/<\"\n€{}", "a".repeat(200));
        let attachment = stage(&conn, "a", &name, None, b"hello", limits()).unwrap();
        assert_eq!(attachment.name.len(), 128);
        assert!(attachment.name.starts_with('_'));
        assert_eq!(attachment.media_type, "application/octet-stream");
        assert_eq!(
            normalize_refs(&vec![attachment.clone(); 9], 100)
                .unwrap_err()
                .code()
                .1,
            "bad_request"
        );
        for bad in [
            "text",
            "text/",
            "/plain",
            "text/plain/extra",
            "text/plain\r\nx:y",
            "t/€",
        ] {
            assert_eq!(media_type(Some(bad)).unwrap_err().code().1, "bad_request");
        }
        let mut bad = attachment.clone();
        bad.sha256 = "A".repeat(64);
        assert_eq!(
            normalize_refs(&[bad], 100).unwrap_err().code().1,
            "bad_request"
        );
    }

    #[test]
    fn repeated_rows_keep_expiry_and_changed_references_conflict() {
        let conn = db();
        let row = reference(&conn, b"hello");
        insert_rows(
            &conn,
            "message",
            std::slice::from_ref(&row.attachment),
            300,
            "",
            "",
        )
        .unwrap();
        assert_eq!(
            get_row(&conn, "message", 0).unwrap().unwrap().expires_at,
            200
        );
        let mut changed = row.attachment;
        changed.name = "different".into();
        assert_eq!(
            insert_rows(&conn, "message", &[changed], 300, "", "")
                .unwrap_err()
                .code()
                .1,
            "conflict"
        );
    }

    #[test]
    fn version_three_upgrade_adds_tables_without_losing_rows() {
        let conn = db();
        conn.execute_batch("INSERT INTO messages (id,created_at,session_id,from_name,bytes,outcome) VALUES ('kept',100,'session','sender',0,'delivered'); DROP TABLE attachments; DROP TABLE staged_blobs; DROP TABLE blob_chunks; DROP TABLE blobs;").unwrap();
        crate::storage::init_db(&conn).unwrap();
        let kept: String = conn
            .query_row("SELECT id FROM messages", [], |r| r.get(0))
            .unwrap();
        assert_eq!(kept, "kept");
        assert_eq!(crate::storage::SCHEMA_VERSION, 3);
        stage(&conn, "a", "empty", None, b"", limits()).unwrap();
        crate::storage::init_db(&conn).unwrap();
        let count: usize = conn
            .query_row("SELECT count(*) FROM blobs", [], |r| usize_column(r, 0))
            .unwrap();
        assert_eq!(count, 1);
    }
}
