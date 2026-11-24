use crate::{
    control::{ErrorCode, LifecycleCall},
    runtime_config::RuntimeConfig,
};
use std::io::{Read, Write};

fn decode(bytes: &[u8]) -> Result<LifecycleCall, ErrorCode> {
    if bytes.is_empty() || bytes.len() > crate::framing::MAX_FRAME_BYTES {
        return Err(ErrorCode::MalformedFrame);
    }
    serde_json::from_slice(bytes).map_err(|_| ErrorCode::MalformedFrame)
}

pub(crate) fn run(configuration: &std::path::Path) -> Result<(), ErrorCode> {
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(crate::framing::MAX_FRAME_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| ErrorCode::MalformedFrame)?;
    let call = decode(&bytes)?;
    let configuration = RuntimeConfig::read(configuration)?;
    let reply =
        crate::human_operator::lifecycle_request(&configuration.paths.lifecycle_socket, &call)?;
    let output = serde_json::to_vec(&reply).map_err(|_| ErrorCode::Storage)?;
    let mut stdout = std::io::stdout().lock();
    stdout.write_all(&output).map_err(|_| ErrorCode::Storage)?;
    stdout.write_all(b"\n").map_err(|_| ErrorCode::Storage)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn cli_call_is_strict_and_cannot_claim_identity_credentials_or_qualification() {
        let request = serde_json::json!({"version":1,"request_id":"cli","verb":"status","target":{"kind":"session","session_id":"session-1"},"args":{"max_events":1,"max_text_bytes":1024}});
        let call = serde_json::json!({"request":request});
        assert!(decode(&serde_json::to_vec(&call).unwrap()).is_ok());
        for field in [
            "principal",
            "credential",
            "parent",
            "qualification",
            "record_id",
        ] {
            let mut claimed = call.clone();
            claimed[field] = "caller-provided".into();
            assert!(decode(&serde_json::to_vec(&claimed).unwrap()).is_err());
        }
        let duplicate=br#"{"request":{"version":1,"request_id":"cli","verb":"steer","target":{"kind":"turn","session_id":"session-1","generation":1,"turn_id":"turn"},"args":{"text":"a","text":"b"}}}"#;
        assert!(decode(duplicate).is_err());
        assert!(decode(&vec![b' '; crate::framing::MAX_FRAME_BYTES + 1]).is_err());
    }
    #[test]
    fn lifecycle_request_has_no_credential_or_identity_prefix() {
        use std::os::{fd::AsRawFd, unix::fs::PermissionsExt};
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let socket = root.path().join("lifecycle");
        let listener = crate::unix::bind_private_socket(&socket).unwrap();
        listener.set_nonblocking(true).unwrap();
        let call=decode(br#"{"request":{"version":1,"request_id":"cli","verb":"status","target":{"kind":"session","session_id":"session-1"},"args":{"max_events":1,"max_text_bytes":1024}}}"#).unwrap();
        let result = std::thread::scope(|scope| {
            let server = scope.spawn(|| {
                let mut ready = libc::pollfd {
                    fd: listener.as_raw_fd(),
                    events: libc::POLLIN,
                    revents: 0,
                };
                assert_eq!(unsafe { libc::poll(&mut ready, 1, 2000) }, 1);
                let (mut stream, _) = listener.accept().unwrap();
                stream.set_nonblocking(true).unwrap();
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(std::time::Duration::from_secs(2)))
                    .unwrap();
                let peer = crate::unix::peer(&stream).unwrap();
                assert_eq!(peer.uid, xmsg::client::current_uid());
                if let Some(pid) = peer.pid {
                    assert_eq!(pid, std::process::id());
                }
                let bytes = crate::unix::line(
                    &mut std::io::BufReader::new(stream.try_clone().unwrap()),
                    crate::framing::MAX_FRAME_BYTES,
                )
                .unwrap();
                assert_eq!(
                    bytes.first(),
                    Some(&b'{'),
                    "lifecycle CLI sent credential framing on the identity-attested socket"
                );
                let parsed: LifecycleCall = serde_json::from_slice(&bytes).unwrap();
                assert_eq!(parsed.request.request_id, "cli");
                assert!(parsed.caller_context.is_none());
                stream
                    .write_all(b"{\"status\":\"error\",\"code\":\"attestation_unavailable\"}\n")
                    .unwrap();
            });
            let result = crate::human_operator::lifecycle_request(&socket, &call);
            server.join().unwrap();
            result
        });
        assert_eq!(result.unwrap_err(), ErrorCode::AttestationUnavailable);
    }
}
