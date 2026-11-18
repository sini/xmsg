//! The agy delivery child must not inherit stray descriptors, must report a failed exec, and must
//! not outlive a delivery timeout.

mod write_exe;

use std::fs;
use std::path::Path;
use std::time::{Duration, Instant};

use xmsg::agy::{new_agy_store, AgyConfig, AgyCredentials, AgySessionInfo, AgyStore};
use xmsg::error::AppError;
use xmsg::registry::Session;

const CONV_ID: &str = "a904fe8e-df56-5cf9-8285-e2d97512d4e1";

fn fixture(root: &Path, agy_bin: &str) -> (AgyConfig, AgyStore, Session) {
    let my_pid = std::process::id();
    let proc_root = root.join("proc");
    let pid_dir = proc_root.join(my_pid.to_string());
    fs::create_dir_all(&pid_dir).unwrap();
    fs::write(
        pid_dir.join("stat"),
        format!("{my_pid} (proc) S 1 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 100 0 0 0 0 0 0 0 0 0 0\n"),
    )
    .unwrap();
    let config = AgyConfig {
        presence_dir: root.join("presence"),
        brain_dir: root.join("brain"),
        proc_locks_path: root.join("locks"),
        proc_root,
        agy_bin: agy_bin.to_string(),
        trusted_agy_exes: Vec::new(),
    };
    let store = new_agy_store();
    let info = AgySessionInfo::new(
        CONV_ID.to_string(),
        my_pid,
        "100".to_string(),
        Some(AgyCredentials {
            ls_address: "127.0.0.1:9999".to_string(),
            csrf_token: "token-fds".to_string(),
            is_stale: false,
        }),
    );
    store
        .write()
        .unwrap()
        .insert(info.session_key.clone(), info);
    let session = Session {
        session_id: CONV_ID.to_string(),
        name: None,
        pid: my_pid,
        cwd: String::new(),
        status: "idle".to_string(),
        kind: "agy".to_string(),
        entrypoint: None,
        version: None,
        started_at: 0,
        updated_at: 0,
        harness: "agy".to_string(),
        registered: None,
    };
    (config, store, session)
}

fn write_script(path: &Path, body: &str) {
    write_exe::write_exe(path, format!("#!/bin/sh\n{body}\n"));
}

#[cfg(target_os = "macos")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agy_child_inherits_no_fds_under_concurrent_fd_creation() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    const SPAWNS: usize = 200;
    const CONCURRENCY: usize = 8;

    let tmp = tempfile::tempdir().unwrap();
    let out_dir = tmp.path().join("fds");
    fs::create_dir_all(&out_dir).unwrap();
    // $4 is the --title value. ls opens its own fds, so the clean listing is calibrated below.
    let probe = tmp.path().join("probe.sh");
    write_script(
        &probe,
        &format!("exec /bin/ls /dev/fd > \"{}/$4\"", out_dir.display()),
    );
    let (config, store, session) = fixture(tmp.path(), &probe.to_string_lossy());

    let read_fds = |name: &str| -> Vec<String> {
        fs::read_to_string(out_dir.join(name))
            .unwrap()
            .split_whitespace()
            .map(str::to_string)
            .collect()
    };
    xmsg::agy::deliver_agy_envelope(&config, &store, &session, "calibrate", "x")
        .await
        .expect("calibration delivery must succeed");
    let clean = read_fds("calibrate");
    fs::remove_file(out_dir.join("calibrate")).unwrap();
    assert!(
        clean.len() <= 6 && clean[..3] == ["0", "1", "2"],
        "unexpected quiet-state listing {clean:?}"
    );

    let stop = Arc::new(AtomicBool::new(false));
    let churners: Vec<_> = (0..4)
        .map(|_| {
            let stop = stop.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let _pair = std::os::unix::net::UnixStream::pair().unwrap();
                    let _pipe = std::io::pipe().unwrap();
                }
            })
        })
        .collect();

    for batch in 0..SPAWNS / CONCURRENCY {
        let mut set = tokio::task::JoinSet::new();
        for i in 0..CONCURRENCY {
            let (config, store, session) = (config.clone(), store.clone(), session.clone());
            let title = format!("spawn-{}", batch * CONCURRENCY + i);
            set.spawn(async move {
                xmsg::agy::deliver_agy_envelope(&config, &store, &session, &title, "x").await
            });
        }
        while let Some(res) = set.join_next().await {
            res.unwrap().expect("probe delivery must succeed");
        }
    }
    stop.store(true, Ordering::Relaxed);
    for t in churners {
        t.join().unwrap();
    }

    let mut leaked = Vec::new();
    for entry in fs::read_dir(&out_dir).unwrap() {
        let entry = entry.unwrap();
        let fds = read_fds(&entry.file_name().to_string_lossy());
        if fds != clean {
            leaked.push(format!(
                "{}: {}",
                entry.file_name().to_string_lossy(),
                fds.join(" ")
            ));
        }
    }
    let seen = fs::read_dir(&out_dir).unwrap().count();
    assert_eq!(seen, SPAWNS, "every probe must report");
    assert!(
        leaked.is_empty(),
        "{} of {SPAWNS} agy children inherited fds (clean listing {clean:?}): {:?}",
        leaked.len(),
        &leaked[..leaked.len().min(5)]
    );
}

#[tokio::test]
async fn agy_spawn_of_missing_program_reports_exec_failure() {
    let tmp = tempfile::tempdir().unwrap();
    let missing = tmp.path().join("no-such-agy");
    let (config, store, session) = fixture(tmp.path(), &missing.to_string_lossy());
    let err = xmsg::agy::deliver_agy_envelope(&config, &store, &session, "t", "x")
        .await
        .expect_err("a missing agy binary must fail");
    match err {
        AppError::InboxUnavailable(msg) => assert!(
            msg.starts_with("failed to execute"),
            "exec failure must surface as a spawn error, got {msg:?}"
        ),
        other => panic!("expected InboxUnavailable, got {other:?}"),
    }
}

#[tokio::test]
async fn agy_child_is_killed_and_reaped_on_delivery_timeout() {
    let tmp = tempfile::tempdir().unwrap();
    let pid_file = tmp.path().join("child.pid");
    let slow = tmp.path().join("slow.sh");
    write_script(
        &slow,
        &format!("echo $$ > \"{}\"\nexec sleep 30", pid_file.display()),
    );
    let (config, store, session) = fixture(tmp.path(), &slow.to_string_lossy());
    let err = xmsg::agy::deliver_agy_envelope(&config, &store, &session, "t", "x")
        .await
        .expect_err("a hung agy must time out");
    assert!(matches!(err, AppError::InboxTimeout), "got {err:?}");

    let pid: libc::pid_t = fs::read_to_string(&pid_file)
        .unwrap()
        .trim()
        .parse()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(3);
    let gone = loop {
        // ESRCH only once the child is both dead and reaped; a zombie still answers kill(0).
        if unsafe { libc::kill(pid, 0) } != 0 {
            break true;
        }
        if Instant::now() >= deadline {
            break false;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    if !gone {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    assert!(gone, "agy child {pid} outlived the delivery timeout");
}
