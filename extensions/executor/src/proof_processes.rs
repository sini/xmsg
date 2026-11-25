use std::{fs::OpenOptions, io::Write, os::unix::fs::OpenOptionsExt, process::Child};
static RECEIPT_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

pub(crate) fn configure(command: &mut std::process::Command) {
    for key in ["XMSG_EXECUTOR_PROOF_CHILDREN", "XMSG_EXECUTOR_PROOF_NONCE"] {
        if let Some(value) = std::env::var_os(key) {
            command.env(key, value);
        }
    }
}

pub(crate) fn record(child: &Child) {
    let Some(destination) = std::env::var_os("XMSG_EXECUTOR_PROOF_CHILDREN") else {
        return;
    };
    let nonce = std::env::var("XMSG_EXECUTOR_PROOF_NONCE").expect("proof child nonce missing");
    let _lock = RECEIPT_LOCK
        .lock()
        .expect("proof child receipt lock poisoned");
    assert_eq!(
        option_env!("XMSG_EXECUTOR_BUILD_NONCE"),
        Some(nonce.as_str()),
        "proof child compiled nonce mismatch"
    );
    let pid = i32::try_from(child.id()).expect("proof child PID overflow");
    assert!(pid > 1, "proof child PID is reserved");
    let session = unsafe { libc::getsid(pid) };
    let group = unsafe { libc::getpgid(pid) };
    let own_session = unsafe { libc::getsid(0) };
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(destination)
        .expect("proof child receipt open failed");
    assert!(
        file.metadata().unwrap().len() < 65536,
        "proof child receipts exceed bound"
    );
    let record = serde_json::json!({"pid":pid,"pgid":group,"session":session,"parent_session":own_session,"nonce":nonce});
    let mut data = serde_json::to_vec(&record).expect("proof child receipt encode failed");
    data.push(b'\n');
    file.write_all(&data)
        .expect("proof child receipt write failed");
    file.sync_all().expect("proof child receipt sync failed");
}
