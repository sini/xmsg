# Engineering Guide & Internal Architecture Invariants (`AGENTS.md`)

This document records internal engineering invariants, security boundaries, and architecture decision references for agents working on `xmsg`. Public user-facing documentation lives in [README.md](./README.md) and must not reference internal tracker IDs.

## 1. Security & Trust Invariants

- **Same-UID Attribution Boundary (`GT3`, `A15`):**
  All local Unix sockets (`http.sock`, `agent.sock`, `register.sock`) live in `$XDG_RUNTIME_DIR/xmsg/` (mode `0700`, socket mode `0600`) and verify `SO_PEERCRED` (Linux) / `getpeereid` + `LOCAL_PEEREPID` (macOS). Within one UID, process-ancestry caller attribution prevents accidental cross-session or cross-harness misattribution; it does not isolate against deliberate same-UID impersonation.
  - Under the `GT3` same-UID precedent (owner-accepted for `HA9-A.codex` on 2026-11-04), multiple Codex roots sharing a single per-home app-server daemon share that daemon's process ancestry and writer-lock file descriptors. A shell tool inside one root can forge `agent.sock` frames claiming another root or child owned by that same daemon. `--no-daemon` roots have separate owner processes, and all Codex delivery carriers prepend the fixed untrusted-peer-data preamble (`CODEX_UNTRUSTED_PREAMBLE`).
- **No-Symlink & Bounded File Ingestion (`XB1`, `XB2`):**
  Every file-ingestion path that reads harness-controlled or user-writable state (`src/claim.rs`, `src/agy.rs`, `src/codex.rs`) must:
  - Validate UUIDs / subagent IDs (`claim::is_uuid_shaped`, `claim::validate_subagent_id`) before path construction.
  - Walk directory hierarchies via `openat` with `O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK`, rejecting symlinks, FIFOs, sockets, and device nodes (`S_ISREG` / `S_ISDIR`), verifying `st_uid == geteuid()`, and bounding line/record reads (`<= 1 MiB` for Codex rollout `session_meta` first line).
- **Root Stamp Hardening (`XH1`) & Codex Runtime Metadata (`HA9-A.codex`):**
  - For Claude and Antigravity, `PreToolUse` hooks never stamp `as_agent` when `agent_id` is absent or equals the parent session ID.
  - For Codex (`src/mcp.rs`, `src/agent.rs`), there is no `PreToolUse` identity hook or stamp flag. `xmsg mcp` extracts `codex_session` (`params._meta.sessionId`), `codex_thread` (`params._meta.threadId`), and `codex_turn` (`params._meta["x-codex-turn-metadata"].turn_id`) exclusively from the top-level JSON-RPC `params._meta` object — never from `params.arguments` — strips any model-supplied `as_agent` when `_meta` is present, and forwards those fields on `agent.sock` for `list`, `send`, `reply`, `replies`, and `inbox`.
  - On the server (`src/agent.rs`), when the caller's ancestry reaches a trusted `--codex-exe` owner first, caller attribution requires valid `codex_session` and `codex_thread` matching an admitted root whose writer lock and continuous `inotify` lease watch are held by that owner. Missing or mismatched metadata fails closed (`NotRecipient`), including for legacy pre-`HA9-A.codex` MCP sidecars (`XC1`).
- **Restricted Codex Delivery Relay (`src/codex_relay.rs`):**
  - Live push into daemon-backed Codex roots connects only to `<H>/app-server-control/app-server-control.sock` under a canonical configured `--codex-home` `<H>` (verifying `0700` parent directory and `0600` socket owned by effective UID), pins the connected Unix socket peer `(pid, starttime)` to the admitted owner `O`, performs a static `initialize`/`initialized` + `thread/loaded/list` check (requiring `P` in `data`), and sends only a typed text-only `turn/start` request (`<= 1 MiB` frame bound, `2 s` handoff deadline), discarding notifications and never answering server callbacks/approvals.
  - Durable handoff tracking (`codex_handoff`: `pending → inflight → accepted | unknown`) ensures at-most-once automatic handoff across concurrent push and hook drains (`SessionStart`, `UserPromptSubmit`, `Stop`). Uncertain post-write timeouts/disconnects transition to `unknown` (`delivery_unknown`) and are never automatically replayed.

## 2. Verification & CI Discipline

- Run all Rust checks (`cargo test --all-targets`, `cargo clippy --all-targets -- -D warnings`, `cargo fmt -- --check`) and Nix checks (`nix develop ./ci --command ci`, `nix flake check ./ci`).
- Never point Codex tests or probes at `~/.codex`; always use isolated temporary `CODEX_HOME` directories.
