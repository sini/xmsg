//! Guard: no test may fall back to the real `$HOME/.gemini/antigravity-cli/{presence,brain}`
//! (agy's default dirs) or spawn a daemon with the caller's real HOME. A source scan over
//! the test fixtures, because the daemon exposes no agy-dir seam to assert on.

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
