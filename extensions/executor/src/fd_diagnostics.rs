use std::{path::PathBuf, process::Command};

pub(crate) fn before_spawn(command: &mut Command) {
    let Some(root) = std::env::var_os("XMSG_EXECUTOR_FD_DIAGNOSTICS") else {
        return;
    };
    command.env("XMSG_EXECUTOR_FD_DIAGNOSTICS", &root);
    let root = PathBuf::from(root);
    std::fs::create_dir_all(&root).unwrap();
    let mut rows = Vec::new();
    for fd in 3..65536 {
        let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
        if flags < 0 {
            continue;
        }
        let mut kind: libc::c_int = 0;
        let mut length = std::mem::size_of_val(&kind) as libc::socklen_t;
        let socket = unsafe {
            libc::getsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_TYPE,
                (&mut kind as *mut libc::c_int).cast(),
                &mut length,
            )
        } == 0;
        if !socket && fd != 131 && fd != 140 {
            continue;
        }
        let mut metadata: libc::stat = unsafe { std::mem::zeroed() };
        let stat_result = unsafe { libc::fstat(fd, &mut metadata) };
        let mut addresses = Vec::new();
        for peer in [false, true] {
            let mut address: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
            let mut length = std::mem::size_of_val(&address) as libc::socklen_t;
            let result = unsafe {
                if peer {
                    libc::getpeername(
                        fd,
                        (&mut address as *mut libc::sockaddr_storage).cast(),
                        &mut length,
                    )
                } else {
                    libc::getsockname(
                        fd,
                        (&mut address as *mut libc::sockaddr_storage).cast(),
                        &mut length,
                    )
                }
            };
            let bytes = unsafe {
                std::slice::from_raw_parts(
                    (&address as *const libc::sockaddr_storage).cast::<u8>(),
                    (length as usize).min(std::mem::size_of_val(&address)),
                )
            };
            addresses.push(serde_json::json!({"peer":peer,"result":result,"family":address.ss_family,"bytes":bytes}));
        }
        rows.push(serde_json::json!({"fd":fd,"flags":flags,"cloexec":flags & libc::FD_CLOEXEC != 0,"socket_type":kind,"socket":socket,"metadata":serde_json::json!({"result":stat_result,"dev":metadata.st_dev,"ino":metadata.st_ino,"mode":metadata.st_mode}),"addresses":addresses}));
    }
    let pid = std::process::id();
    std::fs::write(root.join(format!("parent-{pid}.json")), serde_json::to_vec_pretty(&serde_json::json!({"pid":pid,"pgid":unsafe{libc::getpgid(0)},"session":unsafe{libc::getsid(0)},"stage":"immediately-before-native-spawn","fds":rows})).unwrap()).unwrap();
}
