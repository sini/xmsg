//! Guard against latent `ETXTBSY` races and leaked `ANTIGRAVITY_*` credentials in integration
//! tests:
//! 1. No test file outside `tests/write_exe/mod.rs` may write/copy/open a file in-process and
//!    give it executable mode bits or a `#!` shebang; executable fixtures must go through
//!    `write_exe::write_exe` so no write fd is ever held in the parent test process.
//! 2. Every test harness that spawns `xmsg serve` must scrub `ANTIGRAVITY_*` (via
//!    `agy_env::ScrubAgyEnv`, `agy_env::scrub_*`, `.env_clear()`, or explicit `env_remove`s).

#[path = "support/spawn.rs"]
mod spawn;
use std::fs;
use std::path::{Path, PathBuf};

const AGY_VARS: [&str; 3] = [
    "ANTIGRAVITY_CONVERSATION_ID",
    "ANTIGRAVITY_LS_ADDRESS",
    "ANTIGRAVITY_CSRF_TOKEN",
];

fn collect_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            collect_rs_files(&p, out);
        } else if p.extension().is_some_and(|e| e == "rs") {
            out.push(p);
        }
    }
}

fn split_functions(src: &str) -> Vec<&str> {
    let mut starts = vec![0usize];
    for (idx, _) in src.match_indices("\n") {
        let rest = &src[idx + 1..];
        let trimmed = rest.trim_start_matches(' ');
        if trimmed.starts_with("fn ")
            || trimmed.starts_with("async fn ")
            || trimmed.starts_with("pub fn ")
            || trimmed.starts_with("pub async fn ")
        {
            starts.push(idx + 1);
        }
    }
    let mut out = Vec::with_capacity(starts.len());
    for i in 0..starts.len() {
        let end = starts.get(i + 1).copied().unwrap_or(src.len());
        out.push(&src[starts[i]..end]);
    }
    out
}

fn parse_octal_exec_mode(s: &str) -> Option<&str> {
    let mut rest = s;
    while let Some(pos) = rest.find("0o") {
        let after = &rest[pos + 2..];
        let digits: String = after
            .chars()
            .take_while(|c| ('0'..='7').contains(c) || *c == '_')
            .filter(|c| *c != '_')
            .collect();
        if !digits.is_empty() {
            if let Ok(mode) = u32::from_str_radix(&digits, 8) {
                if mode & 0o111 != 0 {
                    return Some(&rest[pos..pos + 2 + digits.len()]);
                }
            }
        }
        rest = after;
    }
    None
}

fn trim_ref(expr: &str) -> &str {
    expr.trim().trim_start_matches('&').trim()
}

fn target_written_in_fn(fn_blk: &str, target: &str) -> bool {
    if target.is_empty() {
        return false;
    }
    for prefix in ["write(", "create(", ".open("] {
        let mut rest = fn_blk;
        while let Some(pos) = rest.find(prefix) {
            let args = rest[pos + prefix.len()..].trim_start();
            let first_end = args.find([',', ')']).unwrap_or(args.len());
            if trim_ref(&args[..first_end]) == target {
                return true;
            }
            rest = &rest[pos + prefix.len()..];
        }
    }
    let mut rest = fn_blk;
    while let Some(pos) = rest.find("copy(") {
        let args = &rest[pos + "copy(".len()..];
        if let Some(comma) = args.find(',') {
            let second = &args[comma + 1..];
            let end = second.find([',', ')']).unwrap_or(second.len());
            if trim_ref(&second[..end]) == target {
                return true;
            }
        }
        rest = args;
    }
    false
}

fn has_agy_scrub(snippet: &str) -> bool {
    snippet.contains(".scrub_agy_env()")
        || snippet.contains("agy_env::scrub_")
        || snippet.contains(".env_clear()")
        || AGY_VARS
            .iter()
            .all(|v| snippet.contains(&format!("env_remove(\"{v}\")")))
}

fn fn_name_of(fn_blk: &str) -> Option<&str> {
    let header = fn_blk.lines().next().unwrap_or("");
    let fn_pos = header.find("fn ")?;
    let after = &header[fn_pos + 3..];
    let name_end = after
        .find(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .unwrap_or(after.len());
    let name = &after[..name_end];
    (!name.is_empty()).then_some(name)
}

fn file_defines_scrubbed_helper(src: &str, call_window: &str) -> bool {
    let fns = split_functions(src);
    let mut scrubbed: Vec<&str> = fns
        .iter()
        .filter(|b| has_agy_scrub(b))
        .filter_map(|b| fn_name_of(b))
        .collect();
    for fn_blk in &fns {
        if let Some(name) = fn_name_of(fn_blk) {
            if !scrubbed.contains(&name)
                && scrubbed.iter().any(|s| fn_blk.contains(&format!("{s}(")))
            {
                scrubbed.push(name);
            }
        }
    }
    scrubbed
        .iter()
        .any(|name| call_window.contains(&format!("{name}(")))
}

fn violations(name: &str, src: &str) -> Vec<String> {
    let mut out = Vec::new();
    let shebang_str = concat!("\"#", "!/");
    let shebang_bytes = concat!("b\"#", "!/");

    for fn_blk in split_functions(src) {
        // Predicate 1: in-process file write/open/copy + set_permissions with executable mode.
        let mut rest = fn_blk;
        while let Some(pos) = rest.find("set_permissions(") {
            let after = &rest[pos + "set_permissions(".len()..];
            let stmt_end = after.find(';').unwrap_or(after.len());
            let stmt = &after[..stmt_end];
            if let Some(comma) = stmt.find(',') {
                let target = trim_ref(&stmt[..comma]);
                let perm_part = &stmt[comma + 1..];
                if perm_part.contains("from_mode") {
                    if let Some(mode_lit) = parse_octal_exec_mode(perm_part) {
                        if target_written_in_fn(fn_blk, target) {
                            out.push(format!(
                                "{name}: in-process write + executable set_permissions({target}, {mode_lit})"
                            ));
                        }
                    }
                }
            }
            rest = &after[stmt_end..];
        }

        // Predicate 2: OpenOptions::new() with executable .mode(0o...).
        let mut rest = fn_blk;
        while let Some(pos) = rest.find("OpenOptions::new()") {
            let after = &rest[pos..];
            let stmt_end = after.find(';').unwrap_or(after.len());
            let stmt = &after[..stmt_end];
            if let Some(mpos) = stmt.find(".mode(") {
                let margs = &stmt[mpos + ".mode(".len()..];
                let mend = margs.find(')').unwrap_or(margs.len());
                if let Some(mode_lit) = parse_octal_exec_mode(&margs[..mend]) {
                    out.push(format!(
                        "{name}: OpenOptions with executable mode ({mode_lit})"
                    ));
                }
            }
            rest = &after[stmt_end..];
        }

        // Predicate 3: in-process fs::write containing a `#!` shebang.
        let mut rest = fn_blk;
        while let Some(pos) = rest.find("fs::write(") {
            let after = &rest[pos..];
            let stmt_end = after.find(");").map(|i| i + 2).unwrap_or(after.len());
            let stmt = &after[..stmt_end];
            if stmt.contains(shebang_str) || stmt.contains(shebang_bytes) {
                out.push(format!("{name}: in-process fs::write of shebang script"));
            }
            rest = &after[stmt_end..];
        }

        // Predicate 4: in-process fs::copy into a path subsequently passed to Command::new.
        let mut rest = fn_blk;
        while let Some(pos) = rest.find("fs::copy(") {
            let after = &rest[pos + "fs::copy(".len()..];
            let stmt_end = after.find(';').unwrap_or(after.len());
            let stmt = &after[..stmt_end];
            if let Some(comma) = stmt.find(',') {
                let second = &stmt[comma + 1..];
                let end = second.find([',', ')']).unwrap_or(second.len());
                let dst = trim_ref(&second[..end]);
                if !dst.is_empty()
                    && (fn_blk.contains(&format!("spawn::command({dst})"))
                        || fn_blk.contains(&format!("spawn::command(&{dst})")))
                {
                    out.push(format!(
                        "{name}: in-process fs::copy({dst}) followed by Command::new"
                    ));
                }
            }
            rest = &after[stmt_end..];
        }
    }

    // Predicate 5: every `xmsg serve` spawn scrubs ANTIGRAVITY_* (or clears env).
    if src.contains("CARGO_BIN_EXE_xmsg") && src.contains("\"serve\"") {
        let lines: Vec<&str> = src.lines().collect();
        for (idx, line) in lines.iter().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("//") {
                continue;
            }
            let direct_serve_arg = line.contains(".arg(\"serve\")")
                || line.contains("args([\"serve\"")
                || trimmed == "\"serve\","
                || trimmed.starts_with("\"serve\", ");
            let vec_serve_arg = trimmed == "\"serve\".into(),";
            if direct_serve_arg {
                let win_start = idx.saturating_sub(18);
                let win_end = (idx + 6).min(lines.len());
                let window = lines[win_start..win_end].join("\n");
                if !has_agy_scrub(&window) && !file_defines_scrubbed_helper(src, &window) {
                    out.push(format!(
                        "{name}:{}: `xmsg serve` spawn does not scrub ANTIGRAVITY_*",
                        idx + 1
                    ));
                }
            } else if vec_serve_arg {
                // Argument vector built ahead of `Command::new(...).args(&args)` / `.args(&self.args)`.
                let mut checked = 0usize;
                for (cidx, cline) in lines.iter().enumerate() {
                    if cline.contains(".args(&args)") || cline.contains(".args(&self.args)") {
                        checked += 1;
                        let wstart = cidx.saturating_sub(10);
                        let wend = (cidx + 4).min(lines.len());
                        let window = lines[wstart..wend].join("\n");
                        if !has_agy_scrub(&window) && !file_defines_scrubbed_helper(src, &window) {
                            out.push(format!(
                                "{name}:{}: `xmsg serve` spawn via args vec does not scrub ANTIGRAVITY_*",
                                cidx + 1
                            ));
                        }
                    }
                }
                if checked == 0 {
                    out.push(format!(
                        "{name}:{}: `serve` args vec has no checked Command::args site",
                        idx + 1
                    ));
                }
            }
        }
    }

    out
}

#[test]
fn tests_never_write_and_exec_in_process_or_leak_agy_env() {
    let tests_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    let mut files = Vec::new();
    collect_rs_files(&tests_root, &mut files);

    let mut found = Vec::new();
    let mut scanned = 0usize;
    for path in files {
        let rel = path
            .strip_prefix(&tests_root)
            .unwrap()
            .to_string_lossy()
            .replace('\\', "/");
        if rel == "write_exe/mod.rs" || rel == "test_write_exe_guard.rs" {
            continue;
        }
        scanned += 1;
        let src = fs::read_to_string(&path).unwrap();
        found.extend(violations(&format!("tests/{rel}"), &src));
    }
    assert!(scanned > 100, "scanned only {scanned} test source files");
    assert!(
        found.is_empty(),
        "in-process write-then-exec or unscrubbed `xmsg serve` violations:\n{}",
        found.join("\n")
    );
}

#[test]
fn scanner_flags_each_planted_violation_and_accepts_clean_cases() {
    // 1. Planted violation: in-process write + executable set_permissions (RED).
    let bad_set_perm = r#"
fn bad() {
    let bin = tmp.path().join("fake");
    fs::write(&bin, "echo hi\n").unwrap();
    fs::set_permissions(&bin, fs::Permissions::from_mode(0o755)).unwrap();
}
"#;
    let v1 = violations("planted_set_perm.rs", bad_set_perm);
    assert!(
        v1.iter().any(|m| m.contains("set_permissions(bin, 0o755)")),
        "expected set_permissions violation, got {v1:?}"
    );

    // 2. Planted violation: OpenOptions with executable .mode() (RED).
    let bad_open_opts = r#"
fn bad() {
    let f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .mode(0o700)
        .open(&bin)
        .unwrap();
}
"#;
    let v2 = violations("planted_open_opts.rs", bad_open_opts);
    assert!(
        v2.iter()
            .any(|m| m.contains("OpenOptions with executable mode (0o700)")),
        "expected OpenOptions violation, got {v2:?}"
    );

    // 3. Planted violation: in-process shebang write without set_permissions (RED).
    let bad_shebang = concat!(
        "fn bad() {\n    fs::write(&script, \"#",
        "!/bin/sh\\nexit 0\\n\").unwrap();\n}\n"
    );
    let v3 = violations("planted_shebang.rs", bad_shebang);
    assert!(
        v3.iter().any(|m| m.contains("shebang")),
        "expected shebang violation, got {v3:?}"
    );

    // 4. Planted violation: in-process fs::copy followed by Command::new (RED).
    let bad_copy = r#"
fn bad() {
    fs::copy(env!("CARGO_BIN_EXE_xmsg"), &copied_bin).unwrap();
    let _ = spawn::command(&copied_bin).status();
}
"#;
    let v4 = violations("planted_copy.rs", bad_copy);
    assert!(
        v4.iter().any(|m| m.contains("fs::copy(copied_bin)")),
        "expected fs::copy violation, got {v4:?}"
    );

    // 5. Planted violation: unscrubbed `xmsg serve` spawn (RED).
    let bad_serve = r#"
fn bad() {
    let bin = env!("CARGO_BIN_EXE_xmsg");
    let _child = spawn::command(bin)
        .env("HOME", dir)
        .arg("serve")
        .spawn()
        .unwrap();
}
"#;
    let v5 = violations("planted_serve.rs", bad_serve);
    assert!(
        v5.iter()
            .any(|m| m.contains("does not scrub ANTIGRAVITY_*")),
        "expected unscrubbed serve violation, got {v5:?}"
    );

    // Clean controls: directory 0o700 + write_exe::write_exe + scrubbed `xmsg serve` (GREEN).
    let clean = concat!(
        "fn good() {\n",
        "    fs::create_dir_all(&run_dir).unwrap();\n",
        "    fs::set_permissions(&run_dir, fs::Permissions::from_mode(0o700)).unwrap();\n",
        "    fs::write(run_dir.join(\"cfg.json\"), \"{}\").unwrap();\n",
        "    write_exe::write_exe(&bin, \"#",
        "!/bin/sh\\nexit 0\\n\");\n",
        "    let xmsg = env!(\"CARGO_BIN_EXE_xmsg\");\n",
        "    let _child = spawn::command(xmsg).scrub_agy_env().env(\"HOME\", &run_dir).arg(\"serve\").spawn();\n",
        "}\n",
    );
    let clean_v = violations("clean.rs", clean);
    assert!(clean_v.is_empty(), "clean case flagged: {clean_v:?}");
}
