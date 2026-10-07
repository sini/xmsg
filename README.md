# xmsg: Local Inter-Agent Messaging & Coordination Bridge

`xmsg` is a fast, lightweight local messaging bridge connecting running AI agent sessions across harnesses (Claude Code, Antigravity, and Pi) on the local host. It provides direct, zero-overhead inbox delivery, attested caller identification, persistent reply threading, and MCP tooling.

---

## 1. Security Architecture & Trust Model

### 1.1 Same-UID Trust Boundary
All local IPC in `xmsg` relies on Unix domain sockets located in `$XDG_RUNTIME_DIR/xmsg/` (mode `0700`, owned by the running user's UID):
- Sockets authenticate connected peers via kernel-attested credentials (`SO_PEERCRED` UID).
- Any process executing under the **same local UID** is within the trust boundary and may connect to the Unix sockets.
- Sockets are protected against symlink attacks and race conditions on startup by verifying directory ownership and permissions prior to binding.

### 1.2 No-Authentication HTTP Posture
> [!WARNING]
> **No-Auth HTTP Service**: The `xmsg` HTTP server provides **no authentication mechanisms**. It is designed solely for local inter-process communication and **MUST STRICTLY bind to the loopback interface (`127.0.0.1`)**. Never expose the HTTP port to external networks, shared interfaces, or container bridges without a dedicated authenticating proxy.

### 1.3 Attestation & Identity Derivation
`xmsg` strictly prevents cross-session and cross-harness impersonation:
- **Claude Sessions:** Discovered via `~/.claude/sessions` and verified for process liveness and starttime continuity via `/proc/<pid>/stat`.
- **Antigravity Sessions:** Verified via presence lock holder files in `/proc/locks`.
- **Pi Sessions:** Session identity is **server-derived** from attested kernel process parameters:
  $$\text{sessionId} = \text{"pi:"} \parallel \text{peer\_pid} \parallel \text{":"} \parallel \text{starttime}$$
  Caller-asserted session IDs in registration payloads are completely ignored.
- **Process Verification:** Pi peer processes are validated by inspecting executable paths and script basenames in `/proc/<pid>/cmdline`, preventing arbitrary processes from registering.
- **Ancestor Process Walk:** For calls to `agent.sock` (such as MCP tools spawned in child shells), `xmsg` traverses parent PIDs upwards through `/proc/<pid>/stat` to identify the originating agent session.
- **Harness-Bound Reply Authorization:** All stored messages record the recipient harness (`claude`, `agy`, or `pi`). A reply is accepted only when:
  $$\text{caller.harness} == \text{msg.recipient\_harness} \quad \land \quad \text{caller.session\_id} == \text{msg.session\_id}$$

### 1.4 Envelope Sanitization & Breakout Protection
- **Reserved Prefix Protection:** HTTP callers are prohibited from using the `session:` or `session/` prefixes. All prefixes are evaluated *after* character stripping and Unicode normalization (NFKC).
- **Attested Visual Badges:** The `xmsg@<host> · session:<name>` badge is strictly generated internally for authenticated socket callers.
- **Sender Sanitization:** Sender names are stripped of quotes, angle brackets, control characters, and newlines, and capped at 64 characters across all sinks (`assemble_envelope`, inbox headers, and UI titles).
- **XML Breakout Defense:** The transport envelope escapes attribute double quotes (`&quot;`), guaranteeing that the `<cross-session-message>` XML tag cannot be broken out of.

---

## 2. IPC Sockets & Components

`xmsg` operates two Unix domain sockets in `$XDG_RUNTIME_DIR/xmsg/`:

### 2.1 `agent.sock`
Used by active agent sessions and MCP tool instances:
- **`reply` action:** Validates caller identity via ancestor walk, verifies recipient authorization against SQLite records, records the reply, and broadcasts notifications.
- **`send` action:** Formats an attested sender badge `xmsg@<host> · session:<name>`, enforces payload limits (`max_body`), and delivers directly to the recipient session.

### 2.2 `register.sock`
Used by non-Claude harnesses for registration and polling:
- **Antigravity Registration:** `xmsg register agy` sends session credentials (`conversation_id`, `ls_address`, `csrf_token`) over this socket to enable outbound HTTP message injection into Antigravity.
- **Pi Registration & Polling:** The Pi extension registers its process and enters an event-driven long-poll loop to receive inbound messages.

---

## 3. Interfaces & Tooling

### 3.1 Model Context Protocol (MCP) Server: `xmsg mcp`
`xmsg` provides a stdio MCP server for agent harnesses:
```json
{
  "mcpServers": {
    "xmsg": {
      "command": "xmsg",
      "args": ["mcp"]
    }
  }
}
```
Exposes three tools (all execute autonomously without user interaction prompts):
- **`list`:** Enumerate active agent sessions across all harnesses.
- **`send`:** Send a message to a session ref (derives attested caller identity; callers cannot override the sender).
- **`reply`:** Reply to a received message by its `message_id` (enforces recipient authorization).

### 3.2 Pi Coding Agent Extension: `extensions/pi/`
TypeScript extension for Pi (`@earendil-works/pi-coding-agent`):
- Connects to `register.sock`, receives server-derived session ID, and long-polls for inbound messages.
- Delivers incoming messages into Pi with `expandPromptTemplates: false` to prevent remote command or prompt template injection.
- Registers a `reply` tool connecting to `agent.sock`.

### 3.3 Antigravity Integration: `xmsg register agy`
Registers local Antigravity credentials with the running `xmsg` server over `register.sock`, allowing seamless bidirectional messaging.

---

## 4. HTTP API Reference

### Health & Sessions
- `GET /healthz`: Server health check.
- `GET /v1/sessions`: List active sessions (supports `?cwd=`, `?status=busy|idle`).
- `GET /v1/sessions/{ref}`: Get single session details by ID, PID, or name.

### Messaging
- `POST /v1/sessions/{ref}/messages`: Inject a message into a session inbox.
  ```json
  {
    "from": "alice-orchestrator",
    "text": "Hello, please review unit tests."
  }
  ```
  Returns `202 Accepted` with ULID `messageId`:
  ```json
  {
    "sessionId": "live-session-1234",
    "fromName": "xmsg@hostname · alice-orchestrator",
    "bytes": 35,
    "messageId": "01J9XYZ..."
  }
  ```

### Replies & Long-Polling
- `GET /v1/messages/{id}`: Retrieve message metadata and all thread replies.
- `GET /v1/messages/{id}/replies?after={seq}&wait={seconds}`: Long-poll for replies (bounded to 60s timeout, max 128 concurrent waiters).

---

## 5. Building & Verification

```bash
# Run Rust test suite
cargo test --all-targets

# Run Clippy lints
cargo clippy --all-targets -- -D warnings

# Check code formatting
cargo fmt -- --check

# Test Pi extension
node extensions/pi/test.mjs

# Build Nix package
nix build .#default --no-link

# Run Nix CI checks
nix flake check ci
```
