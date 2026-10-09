# Gate Review Report: Unit U6 Implementation Spec

- **Date:** 2026-10-06
- **Reviewer:** Adversarial Spec Reviewer (Antigravity)
- **Target Artefact:** `docs/specs/2026-10-06-xmsg-u6-impl.md`
- **Verdict:** ACCEPT

---

## 1. Review Invariants & Verification Against Gate Report Findings

### Objection 1 (B1): Is the `session:` badge forgeable through any Unicode or category bypass?

- **Finding:** No. `sanitize_from` now executes character stripping (quotes, brackets, invisible and formatting characters) and Unicode NFKC normalization *before* evaluating the prefix. Any string that normalizes/sanitizes to begin with `session:` or `session/` is rejected with `400 Bad Request`. Furthermore, the visual badge `xmsg@<host> · session:<name>` is structurally generated exclusively through the internal `sanitize_attested_from` constructor reachable only via `agent.sock`.
- **Resolution:** ACCEPT.

### Objection 2 (B2): Can a rogue process register a foreign session ID or claim a Claude/Agy identity?

- **Finding:** No.
  1. The server strictly derives the Pi session ID from the attested kernel process (`pi:<peer_pid>:<starttime>`). The request body is prohibited from choosing or overriding the session ID.
  2. Executable verification requires argv[0] or script basename to match `pi`, rejecting substring matches in arbitrary arguments.
  3. Every message stored in SQLite records `recipient_harness`. Reply authorization on `agent.sock` enforces `(caller.harness == msg.recipient_harness && caller.session_id == msg.session_id)`, making cross-harness collisions impossible.
- **Resolution:** ACCEPT.

### Objection 3 (B3): Can an attested sender name break out of the XML envelope or inject headers?

- **Finding:** No.
  1. `sanitize_attested_from` filters control characters, newlines, format characters, quotes, and angle brackets, and enforces the 64-character ceiling across all sinks (`assemble_envelope`, `agy --title`, and inbox headers).
  2. `assemble_envelope` provides defense-in-depth by escaping or stripping `"` in the attribute string.
- **Resolution:** ACCEPT.

### Objection 4 (M1–M4 & P1): Are operational bounds, scoping, and documentation resolved?

- **Finding:**
  - M1: Frame readers bounded with `take(max_body + 4096)`, and `agent.sock` `send` validates `text.len() <= max_body`.
  - M2: `ack_pi_message` predicates on `WHERE id = ? AND session_id = ?`.
  - M3: `messages` purged on TTL cutoff; Pi pending queue capped at 100 per session with HTTP 503 rejection when full.
  - M4: Agy process failures return static error messages; no child stderr/stdout leaked to HTTP.
  - P1: Complete rewrite of `README.md` documenting both sockets, MCP, Pi extension, no-auth loopback posture, and same-UID trust model.
- **Resolution:** ACCEPT.

### Objection 5 (Oracle Honesty O1–O3): Are the test cells honest and race-free?

- **Finding:**
  - O1: `ci/tests/basic.nix` tests package metadata and derivations instead of `true == true`.
  - O2: `tests/pi_proc.rs` explicitly tests rejection of `python3 -c "spin()"`.
  - O3: Permanent test cells created for all gate probes (`tests/gate_probe_http.rs`, `tests/gate_probe_pi.rs`), `/proc/<pid>/stat` paren/space parsing, and race-free pure socket directory testing (`socket_dir_for_env`).
- **Resolution:** ACCEPT.

---

## 2. Verdict

ACCEPT. Unit U6 implementation spec completely closes all blockers, majors, minors, and oracle findings with airtight cryptographic and OS-attestation invariants.
