use std::{
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixStream},
};
use xmsg_executor::{
    auth::ProvisionedCredentials,
    control::{ControlService, OwnerConfig},
    protocol::ControlRequest,
};
#[test]
fn external_caller_has_no_fake_attestation_constructor() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let service = ControlService::open(
        &dir.path().join("journal.db"),
        unsafe { libc::geteuid() },
        OwnerConfig {
            revision: 1,
            local_host: "local".into(),
            grants: vec![],
            profiles: vec![],
            defaults: vec![],
        },
        ProvisionedCredentials::from_bytes(&[b'o'; 32], &[b'h'; 32]).unwrap(),
    )
    .unwrap();
    let (mut client, server) = UnixStream::pair().unwrap();
    std::thread::scope(|scope| {
        let handle = scope.spawn(|| service.handle_lifecycle_connection(server).unwrap());
        let mut request = serde_json::to_vec(&ControlRequest::dispatch(
            "external".into(),
            "no runtime".into(),
        ))
        .unwrap();
        request.push(b'\n');
        client.write_all(&request).unwrap();
        client.shutdown(std::net::Shutdown::Write).unwrap();
        let mut reply = String::new();
        client.read_to_string(&mut reply).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&reply).unwrap(),
            serde_json::json!({"status":"error","code":"attestation_unavailable"})
        );
        handle.join().unwrap();
    });
}
