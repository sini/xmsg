# Adversarial Gate Review: xmsg U1 Implementation Spec

**Date:** 2026-10-06  
**Artefact Under Review:** [`docs/specs/2026-10-06-xmsg-u1-impl.md`](./2026-10-06-xmsg-u1-impl.md)  
**Parent Design:** [`docs/specs/2026-10-06-xmsg-v1-design.md`](./2026-10-06-xmsg-v1-design.md)  
**Reviewer:** `gen-gate` (Adversarial Gate Reviewer)  
**Default Posture:** REJECT  
**Contact:** 1 (final)  

---

## Verdict: REJECT

The implementation spec fails 7 critical construction and protocol checks across the 5 evaluation dimensions. It cannot be approved for dispatch until the structural defects detailed below are revised.

---

## Detailed Objections by Dimension

### 1. Protocol & Error Mappings (§5.4): Complete Omission of HTTP 410 `gone`
- **Defect:** Parent Design §5.4 explicitly specifies:
  `entry stale (pid gone or procStart mismatch) | 410 | gone`
  and distinguishes it from:
  `no live session matches {ref} | 404 | not_found`.
- **Finding:** In `2026-10-06-xmsg-u1-impl.md` §3.3 (`Registry Liveness & Resolution`), step 2 unconditionally skips stale and reused entries during directory scanning, and step 3 returns `404 not_found` when no match is found among the remaining live entries. HTTP 410 `gone` is not mentioned in §2, §3.2, §3.3, §4, or §5.
- **Consequence:** If a session process terminates or its PID is reused, callers resolving that session ref receive `404 not_found` instead of the mandated `410 gone`. This breaks the protocol contract in §5.4.
- **Required Revision:**
  - `registry::resolve_session` must detect when a session file matches `{ref}` on disk but fails the liveness check (dead PID or `procStart` mismatch) and map this to `410 gone`.
  - Include `410 gone` in `ErrorResponse` mapping and add an assertion to §4.3 integration tests.

---

### 2. Envelope & Transport Layer (§5.2): Dangerous Sanitization Contradiction & Missing Invariants
- **Defect 2A (Mid-Body Tag Injection Vulnerability):**
  - In §2 (line 36), the spec states: *"Escapes bodies starting with `/?cross-session-message`."*
  - This is contradicted by §3.3 line 196 (*"Any `<` beginning `/?cross-session-message` (case-insensitive) becomes `<\`"*) and Parent Design §5.2 (*"every `<` that begins `/?cross-session-message` (case-insensitive) becomes `<\`. Nothing else changes"*).
  - Escaping only bodies *starting with* the tag would leave mid-body tag injections unescaped, allowing malicious payloads to terminate the envelope and forge peer messages.
- **Defect 2B (Sanitization Order Inconsistency):**
  - In §2 line 36: *"caps at 64 chars, prefixes `xmsg@<host-label> · `"* (which caps the input first and then prefixes, yielding > 64 chars total).
  - In §3.3 lines 193-194: *"Prefix `xmsg@<host-label> · `. Truncate whole sender string to 64 chars."*
  - The spec contradicts itself. Parent Design §5.2 mandates prefixing then capping the whole sender string at 64 characters.
- **Defect 2C (UTF-8 Slicing Trap):**
  - The middle dot `·` (U+00B7) is a 2-byte UTF-8 sequence (`0xC2 0xB7`). Truncating arbitrary Unicode sender strings by naive byte slicing (`&s[..64]`) in Rust will panic at runtime if a code point boundary is severed. The spec must explicitly prescribe Unicode scalar / grapheme truncation (`.chars().take(64)`).
- **Defect 2D (Omission of Body Logging Ban):**
  - Parent Design §5.4 specifies: *"Each request logs one line to stderr with the request id, the resolved `session_id`, the sanitized `from`, the byte count and the outcome. **Message bodies are never logged.**"*
  - The impl spec mentions skipping/logging malformed entries but omits the request log format and the strict invariant prohibiting body logging.

---

### 3. Gating Oracle (§4 / §7a): Broken Wire Deserialization
- **Defect:** In §3.2 (lines 131-142), `InboxLine<'a>` and `InboxMessage<'a>` derive only `Serialize`:
  ```rust
  #[derive(Debug, Serialize)]
  pub struct InboxLine<'a> { ... }
  ```
  However, in §4.1 (line 217), the property-based test explicitly asserts:
  *- "Output successfully parses as valid JSON into `InboxLine`."*
- **Consequence:** In Rust, `serde_json::from_str::<InboxLine>` will fail to compile because `InboxLine` does not implement `Deserialize`.
- **Required Revision:** Either derive `Deserialize` on `InboxLine` / `InboxMessage` (with proper lifetimes or owned versions for tests) or explicitly define an owned test wire type `InboxLineOwned`.

---

### 4. Input Validation (§4 & §5.4): Missing `deny_unknown_fields` and Empty Text Validation
- **Defect:** Parent Design §4 and §5.4 state:
  *- "The request is `{"from": "<caller name>", "text": "<body>"}`. Unknown fields are rejected."*
  *- "malformed JSON, empty `text`, unknown field -> 400 bad_request"*
- **Finding:** In §3.2, `SendMessageRequest` is declared as:
  ```rust
  #[derive(Debug, Deserialize)]
  pub struct SendMessageRequest {
      pub from: String,
      pub text: String,
  }
  ```
  Without `#[serde(deny_unknown_fields)]`, Axum/Serde silently ignores additional JSON properties instead of returning HTTP 400 `bad_request`. Furthermore, empty `text` (`""`) is accepted by default Serde deserialization unless explicit handler validation is specified.
- **Required Revision:** Add `#[serde(deny_unknown_fields)]` to `SendMessageRequest` and specify handler validation for non-empty `text`.

---

### 5. Packaging & CI Broken in `gen-harness.lib.mkCi`
- **Defect 5A (Inclusion of `default.nix` Collides with `rootSurface` Check):**
  - The spec adds `default.nix` to the root of `xmsg` (§2 line 45, §3.1 line 63).
  - In `gen-harness`, `checks.root-surface` checks all consumers. If `default.nix` exists, `mkCi` mandates that it must be an exported Nix library surface that can be evaluated as `(import ./default.nix) { }` and traversed. A Rust package derivation or an uncallable function will fail evaluation.
  - Furthermore, `gen-harness` explicitly throws if a repository attempts to set `gen.ci.rootSurface.entry = "not-owed"` while `default.nix` exists:
    `"root-surface: declared not-owed but the root has a default.nix; drop the declaration, or remove the root entry"`.
  - Parent Design §6 specifies `flake.nix`, never `default.nix`. `default.nix` must be deleted from the root layout, and `ci/flake.nix` must declare `{ gen.ci.rootSurface.entry = "not-owed"; }` (as done in `den-ag-design/ci/flake.nix`).
- **Defect 5B (Nix Subflake Scope Error in CI Surfacing):**
  - Section 5 (line 253) states: *"In `ci/flake.nix`, a check builds `self.packages.${system}.default`"*.
  - In a standard subflake layout (`ci/flake.nix`), `self` refers to `ci/`, which does not expose `packages.${system}.default`. The package belongs to the parent flake. Calling `self.packages` in `ci/flake.nix` is an immediate evaluation error.
  - The spec must specify the exact mechanism for surfacing the package check in `ci/flake.nix` (e.g. via `extraModules` building the package or importing the root outputs).
- **Defect 5C (Missing `ci/tests/` Directory):**
  - `gen-harness.lib.mkCi` takes a mandatory `testModules` argument (e.g. `testModules = ./tests;`) and runs `(import-tree testModules)`.
  - The project tree in §3.1 lists only `ci/flake.nix`. Without `ci/tests/` existing on disk, `import-tree` throws `path does not exist`.

---

### 6. Scope & API Omissions (§4): Missing Query Parameters on `GET /v1/sessions`
- **Defect:** Parent Design §4 explicitly defines query parameters for `GET /v1/sessions`:
  `GET /v1/sessions | list live sessions; optional ?cwd=, ?status=busy|idle | 200 [Session]`
- **Finding:** The U1 impl spec mentions `GET /v1/sessions` but omits `?cwd=` and `?status=` query filtering entirely. It neither provides models/logic for query filtering nor explicitly rules them deferred.

---

### 7. Test Suite Gaps in §4.3 (Gating Oracle)
- **Defect:** §4.3 only tests 202, 502, 409, 404, 413, and healthz. It completely omits test assertions for:
  1. `410 gone` (stale entry where PID died or `procStart` mismatched).
  2. `400 bad_request` (unknown fields, empty `text`, malformed JSON).
  3. `400 bad_sender` (`from` empty after sanitization).
  4. `504 inbox_timeout` (simulated 5-second socket timeout).
  5. `GET /v1/sessions` and `GET /v1/sessions/{ref}` happy paths.

---

## Actionable Remediations Before Resubmission

1. **Restore HTTP 410 `gone`:** Update `registry::resolve_session` and `ErrorResponse` mapping so that matching a stale session file yields 410.
2. **Harmonize Sanitization:** Fix §2 line 36 to match §3.3 and Parent Design §5.2: every `<` that begins `/?cross-session-message` (case-insensitive) anywhere in the body becomes `<\`. Ensure prefixing occurs before 64-character capping, and prescribe character-safe Unicode truncation.
3. **Derive `Deserialize` for Wire Types:** Add `Deserialize` to `InboxLine` (or specify an owned equivalent) to enable the property test in §4.1.
4. **Enforce Request Validation:** Add `#[serde(deny_unknown_fields)]` to `SendMessageRequest` and mandate non-empty `text` validation.
5. **Correct Packaging & `mkCi` Integration:**
   - Drop `default.nix` from the root tree.
   - In `ci/flake.nix`, add `{ gen.ci.rootSurface.entry = "not-owed"; }` and `{ gen.ci.agentsMd.sheet = "not-owed"; }`.
   - Add `ci/tests/` to the project layout so `testModules` can resolve.
   - Clarify how `ci/flake.nix` references the root package check without invalid `self.packages` references.
6. **Define Query Parameters:** Specify query filtering for `?cwd=` and `?status=busy|idle` on `GET /v1/sessions`.
7. **Expand Gating Oracle Oracles:** Add test cases for 410, 400, 504, and GET endpoints.
8. **Document Body Logging Prohibition:** State the request log format on stderr and the invariant forbidding body logging.

---

## Post-Landing Verification (U1.1 Follow-Up)

### 1. `.key` File Discrimination Control
- **Fault Identified by Orchestrator:** The original `.key` fixture used `chmod 000` permissions. Because an unreadable file is skipped silently by filesystem reads, the negative control could pass even if the code attempted to process `.key` files.
- **Remediation:** The fixture was replaced with a fully valid session JSON referencing the test runner's live PID, with a distinctive name `"KEY-LEAK"`. The test asserts:
  1. `KEY-LEAK` is absent from `list_sessions`.
  2. `resolve_session` for `"KEY-LEAK"` and `"key-leak-session"` returns `Err(AppError::NotFound)`.
- **Planted Violation & Red Run:**
  `src/registry.rs` was temporarily modified to treat `.key` as an allowed extension alongside `.json`:
  ```rust
  let ext = path.extension().and_then(|s| s.to_str());
  if ext != Some("json") && ext != Some("key") { continue; }
  ```
  `cargo test --test registry_fixtures` was executed, failing immediately:
  ```text
  thread 'test_registry_fixtures' panicked at tests/registry_fixtures.rs:99:5:
  assertion `left == right` failed: Only live session should be listed
    left: 2
   right: 1
  ```
  The code was reverted to the strict `.json` check and returned to green (exit code 0).
