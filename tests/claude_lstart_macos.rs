//! End-to-end check of Claude Code's real macOS `procStart` format.
//!
//! Claude records `LC_ALL=C TZ=UTC ps -o lstart= -p <pid>` text in its session
//! files on macOS. The other live tests write xmsg's own start-time token,
//! which is accepted directly, so only this test exercises the lstart path.
//!
//! The text is rendered with `/bin/date` from the kernel start time: `/bin/ps`
//! is setuid root, and the Nix build environment cannot exec it.
//! `date_rendering_matches_ps` checks the two renderings agree where it can.
#![cfg(target_os = "macos")]

use std::fs;
use std::io::ErrorKind;
use std::path::Path;
use std::process::Command;
use tempfile::tempdir;
use xmsg::process::{starttime, LIVE_PROC_ROOT};
use xmsg::registry::{list_sessions, SessionsQuery};

fn run(cmd: &mut Command) -> std::io::Result<String> {
    let out = cmd.env("LC_ALL", "C").output()?;
    assert!(out.status.success(), "{cmd:?} failed");
    Ok(String::from_utf8(out.stdout).unwrap().trim().to_string())
}

/// Start of this test process, in whole seconds since the epoch.
fn self_start_epoch() -> i64 {
    let micros: i64 = starttime(Path::new(LIVE_PROC_ROOT), std::process::id())
        .unwrap()
        .parse()
        .unwrap();
    micros / 1_000_000
}

/// Renders `epoch` the way `ps -o lstart` does, in time zone `tz`.
fn render(epoch: i64, tz: &str) -> String {
    run(Command::new("/bin/date")
        .env("TZ", tz)
        .args(["-r", &epoch.to_string(), "+%a %b %e %T %Y"]))
    .expect("run /bin/date")
}

fn listed_with(proc_start: &str) -> bool {
    let dir = tempdir().unwrap();
    let pid = std::process::id();
    let json = serde_json::json!({
        "pid": pid,
        "sessionId": "lstart-session",
        "name": "lstart",
        "cwd": "/workspace/lstart",
        "status": "idle",
        "kind": "interactive",
        "startedAt": 1000,
        "updatedAt": 2000,
        "procStart": proc_start,
        "messagingSocketPath": "/tmp/lstart.sock",
    });
    fs::write(dir.path().join(format!("{pid}.json")), json.to_string()).unwrap();
    list_sessions(dir.path(), &SessionsQuery::default())
        .iter()
        .any(|s| s.session_id == "lstart-session" && s.pid == pid)
}

#[test]
fn date_rendering_matches_ps() {
    let ps = run(Command::new("/bin/ps").env("TZ", "UTC").args([
        "-o",
        "lstart=",
        "-p",
        &std::process::id().to_string(),
    ]));
    match ps {
        Ok(lstart) => assert_eq!(render(self_start_epoch(), "UTC"), lstart),
        Err(e) if e.kind() == ErrorKind::PermissionDenied => {
            eprintln!("SKIPPED: cannot exec setuid /bin/ps here ({e})");
        }
        Err(e) => panic!("run /bin/ps: {e}"),
    }
}

#[test]
fn real_claude_proc_start_is_listed() {
    let lstart = render(self_start_epoch(), "UTC");
    assert!(listed_with(&lstart), "real procStart {lstart:?} not listed");
}

#[test]
fn shifted_or_local_proc_start_is_rejected() {
    let epoch = self_start_epoch();
    for (shifted, why) in [
        (render(epoch - 1, "UTC"), "1 s early"),
        (render(epoch + 1, "UTC"), "1 s late"),
        (render(epoch, "Europe/Rome"), "local time east of UTC"),
        (render(epoch, "America/New_York"), "local time west of UTC"),
    ] {
        assert!(!listed_with(&shifted), "{why} {shifted:?} was accepted");
    }
}
