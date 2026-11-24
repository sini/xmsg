//! Guard: no test may fall back to the real `$HOME/.gemini/antigravity-cli/{presence,brain}`
//! (agy's default dirs) or spawn a daemon with the caller's real HOME. A source scan over
//! the test fixtures, because the daemon exposes no agy-dir seam to assert on.

#[path = "support/spawn.rs"]
mod spawn;
use std::fs;
use std::path::Path;

// Parses a flag help/refusal only and exits before touching any agy state.
const SPAWN_EXEMPT: &[&str] = &["gate_ha9_codex.rs"];

fn violations(name: &str, src: &str) -> Vec<String> {
    let mut out = Vec::new();
    for (pat, what) in [
        ("AgyConfig::default()", "default agy config"),
        ("agy_config: Default::default()", "default agy config"),
    ] {
        if src.contains(pat) {
            out.push(format!("{name}: {what} ({pat})"));
        }
    }
    let mut rest = src;
    while let Some(i) = rest.find("AgyConfig {") {
        rest = &rest[i + 1..];
        let end = rest
            .find("\n}")
            .or_else(|| rest.find("\n    }"))
            .unwrap_or(rest.len());
        let block = &rest[..end.min(rest.len())];
        let block = &block[..block.find("},").unwrap_or(block.len())];
        if block.contains("..Default::default()")
            && !(block.contains("presence_dir") && block.contains("brain_dir"))
        {
            out.push(format!(
                "{name}: AgyConfig literal inherits presence/brain dir"
            ));
        }
    }
    if src.contains("CARGO_BIN_EXE_xmsg")
        && src.contains("\"serve\"")
        && !src.contains("HOME")
        && !SPAWN_EXEMPT.iter().any(|e| name.ends_with(e))
    {
        out.push(format!("{name}: spawns `xmsg serve` without setting HOME"));
    }
    out
}

#[test]
fn tests_never_use_the_real_agy_home() {
    let me = Path::new(file!()).file_name().unwrap();
    let mut found = Vec::new();
    let mut scanned = 0;
    for entry in fs::read_dir(Path::new(env!("CARGO_MANIFEST_DIR")).join("tests")).unwrap() {
        let p = entry.unwrap().path();
        if p.extension().is_none_or(|e| e != "rs") || p.file_name() == Some(me) {
            continue;
        }
        scanned += 1;
        let src = fs::read_to_string(&p).unwrap();
        found.extend(violations(&p.file_name().unwrap().to_string_lossy(), &src));
    }
    assert!(scanned > 50, "scanned only {scanned} fixtures");
    assert!(
        found.is_empty(),
        "tests reach the real agy home:\n{}",
        found.join("\n")
    );
}

#[test]
fn scanner_flags_planted_violations() {
    let bad = "state(AgyConfig::default());\nAgyConfig {\n    proc_root: x,\n    ..Default::default()\n}\n\
               Command::new(env!(\"CARGO_BIN_EXE_xmsg\")).args([\"serve\"]);";
    assert_eq!(
        violations("planted.rs", bad).len(),
        3,
        "{:?}",
        violations("planted.rs", bad)
    );
    let ok = "AgyConfig {\n    presence_dir: a,\n    brain_dir: b,\n    ..Default::default()\n}\n";
    assert!(violations("ok.rs", ok).is_empty());
}

#[test]
fn planted_xmsg_env_is_scrubbed_from_spawned_children() {
    use std::os::unix::net::UnixListener;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::Arc;
    use std::time::Duration;

    struct EnvGuard(&'static str, Option<std::ffi::OsString>);
    impl Drop for EnvGuard {
        fn drop(&mut self) {
            match &self.1 {
                Some(v) => std::env::set_var(self.0, v),
                None => std::env::remove_var(self.0),
            }
        }
    }

    let tmp = tempfile::tempdir().unwrap();
    let decoy_sock = tmp.path().join("decoy-agent.sock");
    let decoy_http = tmp.path().join("decoy-http.sock");
    let decoy_db = tmp.path().join("decoy.db");
    let listener = UnixListener::bind(&decoy_sock).unwrap();
    listener.set_nonblocking(true).unwrap();

    let hits = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let hits_bg = Arc::clone(&hits);
    let stop_bg = Arc::clone(&stop);
    let accept_thread = std::thread::spawn(move || {
        while !stop_bg.load(Ordering::Relaxed) {
            match listener.accept() {
                Ok((_stream, _)) => {
                    hits_bg.fetch_add(1, Ordering::SeqCst);
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
    });

    let _g1 = EnvGuard("XMSG_AGENT_SOCK", std::env::var_os("XMSG_AGENT_SOCK"));
    let _g2 = EnvGuard("XMSG_HTTP_SOCK", std::env::var_os("XMSG_HTTP_SOCK"));
    let _g3 = EnvGuard("XMSG_DB_PATH", std::env::var_os("XMSG_DB_PATH"));
    std::env::set_var("XMSG_AGENT_SOCK", &decoy_sock);
    std::env::set_var("XMSG_HTTP_SOCK", &decoy_http);
    std::env::set_var("XMSG_DB_PATH", &decoy_db);

    // 1. A spawned `xmsg list` child must not inherit XMSG_AGENT_SOCK or connect to the decoy.
    let list_out = spawn::command(env!("CARGO_BIN_EXE_xmsg"))
        .args(["list"])
        .env("HOME", tmp.path())
        .env("XDG_RUNTIME_DIR", tmp.path())
        .output()
        .unwrap();
    assert!(
        !list_out.status.success(),
        "xmsg list should fail when XMSG_AGENT_SOCK is scrubbed and no daemon is running"
    );

    // 2. A spawned shell child must not see any of the planted XMSG_* variables.
    let sh_out = spawn::command("sh")
        .args([
            "-c",
            "printf '%s|%s|%s' \"${XMSG_AGENT_SOCK:-}\" \"${XMSG_HTTP_SOCK:-}\" \"${XMSG_DB_PATH:-}\"",
        ])
        .output()
        .unwrap();
    assert!(sh_out.status.success());
    assert_eq!(String::from_utf8_lossy(&sh_out.stdout), "||");

    stop.store(true, Ordering::Relaxed);
    let _ = accept_thread.join();
    assert_eq!(
        hits.load(Ordering::SeqCst),
        0,
        "decoy socket must receive zero connections when XMSG_AGENT_SOCK is scrubbed"
    );
}
