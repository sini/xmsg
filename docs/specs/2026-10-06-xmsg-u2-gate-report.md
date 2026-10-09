# Adversarial Gate Review: xmsg U2 Implementation Spec

**Date:** 2026-10-06\
**Artefact Under Review:** [`docs/specs/2026-10-06-xmsg-u2-impl.md`](./2026-10-06-xmsg-u2-impl.md)\
**Parent Design:** [`docs/specs/2026-10-06-xmsg-v1-design.md`](./2026-10-06-xmsg-v1-design.md) (Gist `sini/f65b44cb6ec09c9bd48ea1d569a8c87e` §8, §8.3, §8.5)\
**Reviewer:** `gen-gate` (Adversarial Gate Reviewer)\
**Default Posture:** REJECT\
**Contact:** 1 (final)

---

## Verdict: REJECT

The implementation spec fails 8 critical construction, concurrency, protocol, and testability checks across the evaluation dimensions. It cannot be approved for dispatch until the structural defects and wire inconsistencies detailed below are remediated.

---

## Detailed Objections by Dimension

### 1. Wire Serialization Contradiction in `SendReplyRequest` (§3.2 vs §2 & §3.3)

- **Defect:** In §2 line 58 and §3.3 line 220, the wire payload for `POST /v1/messages/{id}/replies` is explicitly specified as:
  ```json
  {"sessionRef": "<caller_session_id>", "text": "<text>"}
  ```
  However, in §3.2 lines 149–155, `SendReplyRequest` is declared as:
  ```rust
  #[derive(Debug, Deserialize)]
  #[serde(deny_unknown_fields)]
  pub struct SendReplyRequest {
      pub session_ref: String,
      pub text: String,
  }
  ```
- **Consequence:** `SendReplyRequest` enforces `deny_unknown_fields` but omits `#[serde(rename_all = "camelCase")]`. At runtime, Serde will reject the incoming `"sessionRef"` key with HTTP 400 `bad_request` (`unknown field sessionRef, expected session_ref`). The MCP tool written against §3.3 line 220 will fail against the server's own endpoint.
- **Required Revision:** Add `#[serde(rename_all = "camelCase")]` to `SendReplyRequest` in §3.2.

---

### 2. Concurrency Race in Long-Polling Implementation (§3.3 Item 2)

- **Defect:** §3.3 item 2 defines the long-poll resolution flow as:
  1. Parse `after` and `wait`.
  2. Query SQLite for replies with `seq > after`.
  3. If results exist or `wait == 0`, return immediately.
  4. If empty and `wait > 0`:
     - *Subscribe to `tokio::sync::broadcast` notification channel.*
     - *Loop with `tokio::time::timeout(wait, rx.recv())`.*
- **Consequence:** Subscribing to the broadcast channel *after* the initial SQLite query creates a classic race condition. If a reply is inserted and broadcast between steps 2 and 4, the waiter misses the notification. It will hang for the full duration of `wait` (up to 60 seconds) even though the reply is committed in SQLite.
- **Furthermore:** `broadcast::Receiver::recv()` can yield `Err(RecvError::Lagged(_))` if multiple notifications occur. The spec does not handle `Lagged` (which must trigger an immediate database query rather than failing).
- **Required Revision:**
  - Create the subscriber (`let mut rx = tx.subscribe()`) *before* executing the initial query against SQLite.
  - Specify that receiving `Ok(_)` or `Err(RecvError::Lagged(_))` immediately re-queries SQLite.

---

### 3. Missing Wire Contracts & Schemas (§3.2)

- **Defect 3A (`GET /v1/messages/{id}` Missing Response Schema):**
  Parent Design §8.2 and Impl Spec §2 line 51 state that `GET /v1/messages/{id}` returns the delivery record and all replies so far. However, §3.2 defines `MessageRecord` and `ReplyRecord`, but completely omits the composite response struct (e.g. `MessageWithRepliesResponse` or `MessageDetailResponse`). It is unspecified whether fields are flattened, camelCased, or nested under `"message"` / `"replies"`.
- **Defect 3B (`DeliveryResponse` Wire Invariance):**
  §3.3 line 171 updates `DeliveryResponse` to include `message_id`. U1's `DeliveryResponse` derives `#[serde(rename_all = "camelCase")]`. Under standard camelCase, `message_id` serializes as `"messageId"`. However, parent design and endpoint specs refer to `"message_id"`. §3.2 must explicitly define the updated `DeliveryResponse` and specify exact JSON field names (`message_id` vs `messageId`).
- **Defect 3C (`GET /v1/messages/{id}/replies` Non-Existent ID Handling):**
  §3.3 item 2 does not check whether `message_id` exists in the `messages` table. Calling this endpoint with a non-existent ID will silently wait 60 s and return `[]` instead of immediately returning HTTP 404 `not_found`.

---

### 4. Untestable Ancestor Process Walk Mockability Trap (§3.3 & §4.5)

- **Defect:** In §3.3 item 4, the ancestor walk algorithm hardcodes `/proc/<curr_pid>/stat`.
  In §4 item 5, the gating oracle mandates:
  `Fixture with mock /proc: session PID 100 -> wrapper PID 101 -> mcp PID 102. Asserts ancestor walk correctly finds PID 100 through intermediate wrapper PID 101.`
- **Consequence:** In Linux user space and the Nix sandbox, tests cannot mount a custom filesystem at `/proc`. In U1, `is_pid_live` was specifically parameterized as `is_pid_live_in(proc_root: &Path, ...)` to allow test fixtures to pass a mock `/proc` directory. Hardcoding `/proc` in `find_ancestor_session` makes §4.5 impossible to implement and execute.
- **Required Revision:** Parameterize the ancestor walk function:
  `pub fn find_ancestor_session_in(proc_root: &Path, sessions_dir: &Path, start_pid: u32) -> Result<Session, AncestorWalkError>`
  with `pub fn find_ancestor_session(sessions_dir: &Path)` delegating with `Path::new("/proc")` and `std::process::id()`.

---

### 5. Tokio Async vs Rusqlite Concurrency & Missing `AppState` Design (§3.1, §3.2)

- **Defect:**
  1. `rusqlite::Connection` is synchronous and `!Sync`. In Axum/Tokio, executing synchronous SQLite operations directly on async handler threads blocks worker runtimes.
  2. `AppState` in U1 only holds `sessions_dir`, `host_label`, `max_body`, and `request_counter`. The U2 spec does not update `AppState` or define how SQLite and long-poll notification handles are stored and shared.
  3. Missing directory creation: Default DB path is `~/.local/state/xmsg/xmsg.db`. If the directory does not exist, `rusqlite::Connection::open` fails with I/O error. In addition, test harnesses require support for `:memory:` or temp paths.
- **Required Revision:**
  - Define updated `AppState` holding `db: Arc<Mutex<Connection>>` (or a dedicated wrapper) and `broadcast_tx: tokio::sync::broadcast::Sender<String>`.
  - Specify ensuring parent directories exist (`std::fs::create_dir_all`) prior to opening the database.

---

### 6. SQLite Performance Hazard: Missing Index on `replies(created_at)` (§2, §3.3)

- **Defect:** §2 lines 38–40 define an index only on `replies(message_id, seq)`.
  In §3.3 line 194, TTL purge runs:
  `DELETE FROM replies WHERE created_at < now - reply_ttl;`
  on every reply submission in the request path.
- **Consequence:** Without an index on `replies(created_at)`, every reply POST performs an unindexed full table scan of `replies`.
- **Required Revision:** Add `CREATE INDEX IF NOT EXISTS idx_replies_created_at ON replies(created_at);` to the schema.

---

### 7. MCP Stdio Specification & Dependency Gaps (§2, §3.3)

- **Defect 7A (Departure from Parent Design `rmcp` Without Protocol Specification):**
  Parent Design §8.3 specifies building `xmsg mcp` on `rmcp` (the official Rust MCP SDK). U2 spec line 63 departs from this to implement raw stdio JSON-RPC 2.0. However, the spec fails to define the JSON-RPC wire protocol:
  - Supported methods (`initialize`, `notifications/initialized`, `tools/list`, `tools/call`, `ping`).
  - MCP tool call envelope format (`content: [{type: "text", text: "..."}]`, `isError: bool`).
  - Schema definitions for `tools/list` (`inputSchema` with `required`, `additionalProperties: false`).
- **Defect 7B (Missing Production Dependency `reqwest`):**
  `reqwest` is currently in `Cargo.toml` under `[dev-dependencies]`. The `xmsg mcp` subcommand must make HTTP requests to `XMSG_URL`. It cannot compile in release/binary without moving `reqwest` to `[dependencies]`.
- **Defect 7C (Lifecycle of Ancestor Walk):**
  The spec does not clarify when the ancestor walk is executed. If executed at startup and it terminates on failure, external MCP inspectors, testing tools, and `xmsg mcp` run directly from shells fail immediately. Identity resolution must be performed lazily upon `send` and `reply` invocation (or return clean MCP tool errors).

---

### 8. Gating Oracle Coverage Gaps (§4)

- **Defect:** Section 4 omits critical assertions required to verify protocol boundaries:
  1. **Envelope Footer Verification:** Test 1 does not assert that the stand-in inbox socket actually received the raw payload containing `[xmsg] message_id={message_id} — reply with the xmsg reply tool`.
  2. **Error Cases on Reply Endpoint:** No test cases for:
     - Replying to a non-existent `message_id` (assert HTTP 404 `not_found`).
     - Replying with an invalid/stale session ref (assert HTTP 404/410).
     - Empty `text` or extra JSON fields (assert HTTP 400 `bad_request`).
  3. **Long-Poll Edge Cases:** No assertions verifying that `wait` capped at 60 s behaves correctly, that `wait = 0` returns immediately, or that non-existent message IDs return 404 immediately.
  4. **Ancestor Walk Boundary Cases:** No assertions for PID 1 termination, missing stat file, or `procStart` mismatch during walk.

---

## Actionable Remediations Before Resubmission

1. **Fix `SendReplyRequest` Deserialization:** Add `#[serde(rename_all = "camelCase")]` to `SendReplyRequest` in §3.2.
2. **Eliminate Long-Poll Race:** Reorder §3.3 item 2 so subscription to the notification channel occurs *before* querying SQLite, and specify handling for `RecvError::Lagged`.
3. **Specify Missing Wire Types:**
   - Define `MessageDetailResponse` in §3.2 for `GET /v1/messages/{id}`.
   - Define updated `DeliveryResponse` in §3.2 and explicitly state whether `message_id` is camelCase or snake_case on the wire.
   - Mandate that `GET /v1/messages/{id}/replies` checks message existence and returns 404 `not_found` if not found.
4. **Parameterize Ancestor Walk for Testing:** Specify `find_ancestor_session_in(proc_root: &Path, sessions_dir: &Path, start_pid: u32)` and document robust `/proc/<pid>/stat` parsing (splitting after the last `')'`).
5. **Architect SQLite & AppState:**
   - Define the updated `AppState` struct in §3.2 containing the SQLite mutex and broadcast sender.
   - Detail directory creation (`create_dir_all`) and support for in-memory / temporary test databases.
6. **Index `replies(created_at)`:** Add index to §2 and §3.3 schema.
7. **Complete MCP Specification:**
   - Either specify `rmcp` integration or fully detail the JSON-RPC 2.0 MCP wire protocol (`initialize`, `tools/list`, `tools/call`, tool schemas, and MCP error reporting).
   - Move `reqwest` to `[dependencies]` in `Cargo.toml`.
   - Specify that caller session resolution occurs lazily on tool call (or yields clean tool error if unresolvable).
8. **Expand Acceptance Oracles:** Update §4 with test oracles for envelope footer socket verification, 404/400 reply errors, long-poll clamping/wait=0, and ancestor walk boundary conditions.
