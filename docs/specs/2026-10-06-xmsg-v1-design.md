# xmsg v1 — an HTTP bridge into running Claude Code sessions

*Design spec, 2026-10-06. Status: design approved, not yet built.*

## 1. Problem

Claude Code sessions on one machine can message each other (`ListAgents` / `SendMessage`), but only
through a model tool call inside a session. Nothing lets a **script, CI job, or another host** list the
running sessions or push a message into a specific one without spending a model turn.

What was checked first and ruled out:

| Option | Why not |
|---|---|
| Remote Control (cross-machine `ListAgents`) | blocked by our local API proxy |
| Channels (`--channels`) | allowlist-gated in research preview; custom channels need `--dangerously-load-development-channels`, interactive sessions only, a startup warning every launch |
| Headless relay (`claude -p` calling `SendMessage`) | a model turn per message |
| Official CLI send | does not exist; requested in [anthropics/claude-code#99049](https://github.com/anthropics/claude-code/issues/99049) |

The approach is patterned on [codehydra #689](https://github.com/stefanhoelzl/codehydra/pull/689), which
writes directly to a session's inbox socket.

## 2. Measured basis

Measured on Claude Code 2.1.285, Linux, 2026-10-06:

- **Registry.** Each live session writes `~/.claude/sessions/<pid>.json` with `pid`, `sessionId`,
  `name`, `cwd`, `status`, `kind`, `entrypoint`, `version`, `startedAt`, `updatedAt`, `procStart`,
  `messagingSocketPath`. A sibling `<pid>.<hash>.key` holds a peer token; xmsg never reads it.
- **Inbox.** `messagingSocketPath` is a Unix stream socket in a `0700` directory
  (`/run/user/<uid>/cc-socks/`). One newline-terminated JSON line delivers a message:
  ```json
  {"type":"user","message":{"role":"user","content":"<cross-session-message from-name=\"NAME\">\nBODY\n</cross-session-message>"}}
  ```
- **No auth line is needed on Linux.** codehydra also sends `{"type":"auth","token":…}`, which matters on Windows only.
- **Trust.** A message sent from outside the session's process tree to an **auto-mode** session was
  delivered, not held. Per codehydra's test (not re-measured), a `bypassPermissions` session holds such
  a message for its user's approval. The receiver frames it as a peer message that cannot grant
  escalation.
- **Wake.** A **busy** session receives the message at its next tool round. An **idle** session is woken
  and receives it as a new turn.
- **Replies.** The receiver's `SendMessage` back to an unregistered `from-name` was denied by the
  auto-mode classifier. v1 has no reply path.
- **This is an undocumented wire format.** Re-run the live acceptance check (§7) on every Claude Code upgrade.

## 3. Scope

**v1 does two things:** it lists live sessions and delivers a message to one of them.

**Out of v1:** replies, broadcast, send-and-wait, event streaming, auth. The `/v1` prefix leaves room for
these.

## 4. API

The prefix is `/v1`, and all bodies are JSON.

| Method & path | Purpose | Success |
|---|---|---|
| `GET /v1/sessions` | list live sessions; optional `?cwd=`, `?status=busy\|idle` | `200 [Session]` |
| `GET /v1/sessions/{ref}` | one session | `200 Session` |
| `POST /v1/sessions/{ref}/messages` | deliver a message to that session's inbox | `202 Delivery` |
| `GET /healthz` | liveness, plus `sessions_dir: ok\|missing` | `200` |

- **`{ref}`** resolves in this order: `sessionId` (UUID), then pid, then `name`. A name matching more
  than one live session is `409`. Names are derived and change across restarts, so scripts should keep
  the `session_id`.
- **`Session`** has `session_id, name, pid, cwd, status, kind, entrypoint, version, started_at,
  updated_at`. It never exposes the socket path or any token.
- **The request** is `{"from": "<caller name>", "text": "<body>"}`. Unknown fields are rejected.
- **`Delivery`** is `{"session_id", "from_name", "bytes"}`. The status is `202`, not `200`, because the
  bytes reached the inbox and that does not mean the model read them.

## 5. Mechanism

Three modules, each with one job.

### 5.1 `registry`

- It rescans `--sessions-dir` (default `~/.claude/sessions`) on **every request**. There is no cache.
- **Liveness:** an entry is live only if `/proc/<pid>` exists **and** its start time (`/proc/<pid>/stat`
  field 22) equals the entry's `procStart`. This rejects stale files and reused pids.
- It skips and logs malformed entries. It never opens `*.key` files.
- **It is read-only.** xmsg never writes, deletes or "cleans" registry files.

### 5.2 `inbox`: encoding has two layers

**Envelope layer** (inside the content string):

- **`from-name`:** the caller's `from` has whitespace collapsed, then `"`, `<`, `>` and Unicode
  Cc/Cf/Cs/Zl/Zp removed, then is trimmed. The empty string is `400 bad_sender`. The server then
  prefixes `xmsg@<host-label> · ` and caps the whole name at 64 characters, so a caller cannot pose as
  a native peer session.
- **Body:** every `<` that begins `/?cross-session-message` (case-insensitive) becomes `<\`. Nothing
  else changes.

**Transport layer** (the line):

- The line is **always** `serde_json::to_string` of a typed `InboxLine { type: "user", message:
  { role: "user", content } }`, followed by one `\n`. **JSON is never built by `format!` or by
  concatenation.** serde escapes quotes, backslashes and every control character, so any body yields
  exactly one line.
- Delivery opens a `UnixStream` to `messagingSocketPath`, writes the line with a 5 s timeout, and closes.

### 5.3 `http`

- It is built on `axum` and `tokio`.
- Each flag has a matching environment variable: `--listen` (default `127.0.0.1:7787`), `--host-label`
  (default hostname), `--sessions-dir`, `--max-body` (default 64 KiB).
- **Exposure is the operator's decision.** xmsg binds whatever `--listen` names and has **no built-in
  auth**. Binding beyond loopback lets anyone who can reach the port write into your agents'
  context. Restrict it with a firewall or tailnet ACLs.
- **The process must run as the sessions' Unix user**, because the socket directory is `0700`. That
  means a systemd **user** unit or a launchd agent.

### 5.4 Errors

Every error is `{"error": "<code>", "detail": "…"}`.

| Condition | Status | code |
|---|---|---|
| malformed JSON, empty `text`, unknown field | 400 | `bad_request` |
| `from` empty after sanitizing | 400 | `bad_sender` |
| body over `--max-body` | 413 | `too_large` |
| no live session matches `{ref}` | 404 | `not_found` |
| name matches more than one live session (candidates listed) | 409 | `ambiguous` |
| entry stale (pid gone or `procStart` mismatch) | 410 | `gone` |
| connect/write failure (`ENOENT`, `ECONNREFUSED`, `EPIPE`) | 502 | `inbox_unavailable` |
| write timeout | 504 | `inbox_timeout` |

- **There are no server-side retries.** Delivery is at-most-once, and the caller owns any retry.
- Each request logs one line to stderr with the request id, the resolved `session_id`, the sanitized
  `from`, the byte count and the outcome. **Message bodies are never logged.**
- A missing sessions dir does not stop the server from starting. The list returns `[]` and `/healthz`
  reports `missing`.

## 6. Packaging and nix-config integration

- **A public repository, `github:sini/xmsg`.** It is a Rust crate at the repository root, and this spec
  moves into `docs/` when the repository is created.
- **Its flake** exposes `packages.<system>.default`, built with `rustPlatform.buildRustPackage` and
  `cargoLock.lockFile` from the committed lockfile.
- `doCheck` runs the gating oracle (§7a). The live check (§7b) cannot run in the sandbox.

### 6.1 nix-config steps (`github:sini/nix-config`, which is public)

Each step names its file and the existing file it copies. The paths are relative to the nix-config root.

1. **Flake input:** `modules/flake-parts/xmsg.nix`, after `modules/flake-parts/gen-lsp.nix`.
   ```nix
   { ... }:
   {
     flake-file.inputs.xmsg = {
       url = "github:sini/xmsg";
       inputs.nixpkgs.follows = "nixpkgs-unstable";
     };
   }
   ```
2. **Thread the source to pkgs-by-name:** in `pkgs/overlays.nix`, beside `gen-lsp-src`.
   ```nix
   xmsg-src = _final: _prev: { xmsg-src = inputs.xmsg; };
   ```
3. **Package:** `pkgs/by-name/xmsg/package.nix`, after `pkgs/by-name/gen-lsp-mcp/package.nix`. It is a
   fresh `buildRustPackage` over `xmsg-src`, not a re-export of xmsg's own flake package, with
   `meta.mainProgram = "xmsg"`. It is consumed as `pkgs.local.xmsg`.
4. **Aspect:** `modules/den/aspects/applications/dev/ai/mcp/xmsg.nix`, after `mcp/headroom.nix`.
   ```nix
   {
     den.aspects.applications.dev.ai.mcp.xmsg = {
       # Folded into the MCP registries of every agent aspect that reads agent-extensions
       # (agents/claude.nix, agents/antigravity-cli.nix): the reply tool, §8.3.
       agent-extensions =
         { lib, pkgs, ... }:
         {
           type = "mcp";
           mcpServers.xmsg = {
             command = lib.getExe pkgs.local.xmsg;
             args = [ "mcp" ];
           };
         };

       homeManager =
         { lib, pkgs, config, ... }:
         let
           xmsg = lib.getExe pkgs.local.xmsg;
         in
         {
           home.packages = [ pkgs.local.xmsg ];

           # The server runs as the sessions' user, never system-wide (§5.3).
           systemd.user.services.xmsg = lib.mkIf pkgs.stdenv.isLinux {
             Unit.Description = "xmsg: HTTP bridge into running agent sessions";
             Service = {
               ExecStart = "${xmsg} serve --listen 127.0.0.1:7787";
               Restart = "on-failure";
             };
             Install.WantedBy = [ "default.target" ];
           };
           launchd.agents.xmsg = lib.mkIf pkgs.stdenv.isDarwin {
             enable = true;
             config = {
               ProgramArguments = [ xmsg "serve" "--listen" "127.0.0.1:7787" ];
               KeepAlive = true;
             };
           };

           # The owner's explicit authorization of the reply tool (§8.3).
           programs.claude-code.settings.permissions.allow = [ "mcp__xmsg__reply" ];

           # agy first-registration and refresh hook (§9.2). It always prints {"injectSteps":[]}.
           home.file.".gemini/config/hooks.json".text = builtins.toJSON {
             xmsg-register.PreInvocation = [
               {
                 type = "command";
                 command = "${xmsg} register agy";
               }
             ];
           };
         };
     };
   }
   ```
5. **Enable it** in `modules/den/aspects/roles/dev.nix`, in the `applications.dev.ai.mcp.*` list next
   to `applications.dev.ai.mcp.headroom`:
   ```nix
   applications.dev.ai.mcp.xmsg
   ```
6. **pi** (v3): once `xmsg-pi` exists, wire it in the `agents/pi/` aspect.
7. **Verify, then deploy.**
   - Run `nix flake check`.
   - Evaluate a dev host's home config and confirm three things: `xmsg` appears in the claude and agy
     MCP registries, `~/.gemini/config/hooks.json` holds the entry, and `mcp__xmsg__reply` is in the
     allow list.
   - **The owner deploys**: `colmena apply --on <host>` for NixOS, `nh darwin switch .` for darwin.

### 6.2 Integration hazards to check at step 4

- **`hooks.json` ownership.** If the antigravity-cli aspect, or agy itself, ever writes `hooks.json`, a
  home-manager-owned read-only file collides with it. Only one aspect may own the file. If a second
  hook consumer appears, move ownership into `agents/antigravity-cli.nix` and merge entries there.
- **The Claude allow list must merge, not replace.** Check that
  `programs.claude-code.settings.permissions.allow` is a list-merged option in the claude aspect,
  as it is for `mcpServers`.
- **`settings.json` for agy is deliberately unmanaged** (`agents/antigravity-cli.nix`). That is
  unaffected: hooks live in `hooks.json`, a different file.

## 7. Acceptance oracles

### 7a. Gating oracle (ships with v1; `cargo test`, and the build's `doCheck` runs it)

1. **Encoding property test** (`proptest`) over arbitrary `text` and `from`:
   - the output contains exactly one `\n`, and it is the last byte;
   - the output parses as JSON, and `content` equals the expected envelope;
   - the envelope has exactly one opening tag and one closing tag.

   Fixed cases: a body that is only `</cross-session-message>`; NUL and `\r`; U+2028; a 200-character
   `from`.
2. **Registry fixture** containing a live entry (the test's own pid and real `procStart`), a dead pid, a
   reused pid (right pid, wrong `procStart`), malformed JSON, and a `.key` file. The tests assert that
   only the live entry is listed and that the `.key` file is never opened.
3. **End-to-end without Claude.** A `UnixListener` stands in as the inbox and a registry entry points at
   it; the server runs on an ephemeral port and the test sends `POST` requests. Assert:
   - the exact bytes received;
   - `202`;
   - `502` once the listener is closed;
   - `409` for a duplicate name;
   - `404` for an unknown ref;
   - `413` for an oversize body.

### 7b. Guarantee (deferred: the owner runs it by hand, re-armed on each Claude Code upgrade)

`curl -X POST localhost:7787/v1/sessions/<id>/messages -d '{"from":"probe","text":"XMSG-PROBE"}'`
against a real **idle** session. The session must wake with
`<cross-session-message from-name="xmsg@<host> · probe">`. The check does not fit in a build sandbox.

## 8. v2: reply path (design approved 2026-10-06)

**The problem.** The outside sender is not addressable, and the receiver's native `SendMessage` to it was
denied by the auto-mode classifier. The fix is a narrowly scoped, owner-authorized tool. Evading the
classifier is not the goal.

### 8.1 Storage

SQLite at `$XDG_STATE_HOME/xmsg/xmsg.db`. Only the server process opens it, so it is the single writer.

- `messages(id ULID PK, created_at, session_id, from_name, bytes, outcome)`. `outcome` is `delivered`
  or an error code.
- `replies(seq INTEGER PK, message_id FK, created_at, replier_session_id, text)`.
- **Message bodies are not stored. Reply bodies are**, because they are the payload the caller collects.
  Replies are purged after `--reply-ttl` (default 7 d).

### 8.2 API additions

| Method & path | Purpose |
|---|---|
| `POST /v1/sessions/{ref}/messages` | unchanged, except the `202` `Delivery` gains `message_id` |
| `GET /v1/messages/{id}` | the delivery record plus replies so far |
| `GET /v1/messages/{id}/replies?after=<seq>&wait=<s>` | long-poll, with `wait` capped at 60 s, via `tokio::sync::Notify` |
| `POST /v1/messages/{id}/replies` | called by the MCP tool only; `201`, or `403 not_recipient` |

- Replies land on the **same server** the caller posted to (the receiver's host), so there is no
  forwarding between hosts.
- **Envelope footer.** One line is appended inside the body by the envelope layer of §5.2:
  `[xmsg] message_id=<id> — reply with the xmsg reply tool`.

### 8.3 MCP reply tool

- `xmsg mcp` is a stdio subcommand of the same binary, built on `rmcp` (the official Rust MCP SDK).
- It exposes one tool, `reply(message_id, text)`, which `POST`s to `XMSG_URL` (default
  `http://127.0.0.1:7787`). The model's text travels as an MCP argument and is never interpolated into a
  shell command.
- **Who may reply.** The MCP process finds its session by **parent pid** (the `claude` process) and the
  registry. The server accepts a reply only from the session the message was delivered to.
- **nix-config** registers `xmsg` under user-level `mcpServers` and adds `mcp__xmsg__reply` to
  `permissions.allow`. This is an explicit, per-tool owner authorization.

### 8.4 Probes before any v2 code

1. A stub MCP tool with an allow rule, called from an **auto-mode** session. Does the allow rule clear
   the classifier?
2. The MCP subprocess's parent pid. Is it the `claude` pid in the registry?

If either probe fails, the design is revised before any v2 code is written.

### 8.5 Gating oracle additions

- A reply round-trip against the stand-in inbox: `POST` the message, `POST` the reply as the
  recipient, then the long-poll returns it.
- A reply from a non-recipient is `403`.
- A long-poll times out empty after `wait`.
- A purge after the TTL removes the reply.

## 9. v3: other harnesses — Antigravity (`agy`) and pi

*Refined 2026-10-06 together with the Antigravity session that wrote the review `agy-report.md`; the
owner directed the collaboration. Each fact is tagged by who measured it: **[both]**, **[claude]**, or
**[agy]** (the agy agent's measurement, not reproduced here).*

### 9.1 Principle: attached sessions only

xmsg **never spawns or supervises agents**. An earlier draft had a "hosted agent" mode (xmsg running
`agy -p` / `pi --mode rpc` over stdio), and it has been withdrawn:

- users want to reach their *actual* interactive sessions;
- process supervision is not xmsg's job;
- an HTTP-spawnable agent is a trust surface with no good answer.

Every harness is an **adapter** over sessions the user started:

| Harness | Discovery | Liveness | Delivery | Reply |
|---|---|---|---|---|
| `claude` | registry JSON (§5.1) | `procStart` | inbox socket (§5.2) | MCP `reply` (§8.3) |
| `agy` | presence lock + registration (§9.2) | lock held | `agy agentapi send-message` | MCP `reply` |
| `pi` | `xmsg-pi` extension registration (§9.3) | pid + start time | extension long-poll | the extension's `reply` tool |

### 9.2 Antigravity (`agy` 1.2.13)

**Measured basis:**

- `agy agentapi send-message [--title=<t>] <recipient_id> <content>` exists. **[both]**
- Each interactive session holds an exclusive `flock` on
  `~/.gemini/antigravity-cli/presence/<conversation_id>.lock` for its whole life.
  `/proc/locks` maps the lock to the holder pid. **[both]**
- The session's language server binds random loopback ports, and `cli.log` records them. **[both]**
- `agentapi` needs `ANTIGRAVITY_LS_ADDRESS` + `ANTIGRAVITY_CSRF_TOKEN`. A missing token gives
  `Unauthenticated: missing CSRF token`. **[agy]**
- **MCP children do NOT inherit those two.** They are spawned with a static base environment, and only
  `ANTIGRAVITY_CONFIG_DIR` is present. **[both]**
- The lock holder is the direct parent of MCP children. **[both]**
- Tool commands and hooks do inherit them. **[agy]**
- **Hooks (probe 1, passed).** Hooks live in `~/.gemini/config/hooks.json` or `<project>/.agents/hooks.json`.
  - A `PreInvocation` hook fired, and its environment carried `ANTIGRAVITY_LS_ADDRESS`,
    `ANTIGRAVITY_CSRF_TOKEN` and `ANTIGRAVITY_CONVERSATION_ID`, plus `_AGENT`, `_AGENTAPI_EXE`,
    `_APP_DATA_DIR`, `_CONFIG_DIR`, `_LS_VERSION`, `_PROJECT_ID`, `_SOURCE_METADATA` and
    `_TRAJECTORY_ID`. **[agy]**: only names were recorded.
  - Corroborated **[claude]**: `log/cli-20261006_153032.log` records
    `hooks_manager.go:53] loaded 1 named hooks from 1 hooks.json file(s)`. The probe's `hooks.json`
    was removed afterwards.
  - Schema and contract **[agy]**: the command runs under `sh -c`, receives execution metadata on
    stdin, and must print `{"injectSteps":[]}` on stdout.
    ```json
    { "xmsg-register": { "PreInvocation": [ { "type": "command", "command": "xmsg register agy" } ] } }
    ```
  - Consequence: `xmsg register agy` must always print `{"injectSteps":[]}` and exit 0, **even when the
    xmsg server is down**. A registration failure must never block or alter the user's turn; it is
    logged to stderr only.
- `send-message` from a process **outside** agy's tree (`systemd-run --user`) delivers and wakes an idle
  session. **[agy]**

**Registration:**

- A `PreInvocation` hook runs `xmsg register agy`, which reads the credentials **from its environment,
  never argv**. It sends `{conversation_id, ls_address, csrf_token}` over a **Unix socket**,
  `$XDG_RUNTIME_DIR/xmsg/register.sock`, in a `0700` dir.
- **The server verifies:**
  1. `SO_PEERCRED` gives `uid` = the server's own uid, and the peer `pid`.
  2. The holder pid of `presence/<conversation_id>.lock` is read from `/proc/locks`. The check is
     read-only: it never test-acquires the lock, since even a brief acquisition races the session's
     own locking.
  3. The peer pid's parent chain, walked through `/proc/<pid>/stat`, reaches that holder.

  The registration is accepted only if all three hold. **There is no HTTP registration endpoint.**
  A TCP peer's pid cannot be verified, and a port reachable by others must not be able to plant
  credentials.
- The hook fires on every invocation, so registration is an idempotent upsert. A restarted language
  server, which brings a new port and token, re-registers itself on the next turn.
- **Credentials are held in memory only.** They are never written to SQLite, never returned by any
  endpoint, never logged, and never placed in a message body. A registration is dropped when its lock
  is no longer held.

**Credential lifecycle (refresh):**

- **The token cannot be derived; it can only be received.** It is minted in memory per language-server
  start, and only agy's descendants see it. The LS port appears in `cli.log`, but xmsg does not scrape
  it: the hook's value is authoritative.
- **Refresh is push-based, on every turn.** `PreInvocation` fires before each model invocation, so each
  turn re-registers `{ls_address, csrf_token}` as an upsert. If the language server restarts with a new
  port and token, the registration is corrected on the next turn without any polling.
- **Invalidation:**
  1. The presence lock is no longer held: drop the registration. This is checked on every list and send.
  2. `agentapi` exits with `Unauthenticated`, or the LS port refuses the connection: mark the
     registration `stale` and answer `503 credentials_stale`. Do not retry; the next turn's hook
     refreshes it.
  3. A new registration for the same `conversation_id` replaces the old one atomically.
- **Known gap:** an idle session whose language server restarted holds stale credentials until its next
  turn, and xmsg cannot wake it to refresh them. The `503` makes that visible. Probe 2 should also check
  whether the language server ever restarts within a live session.

**First contact (a session that started before the hook existed):**

Probed 2026-10-06 by the agy agent under a fence: no reading other processes' environments, no token
searches, no CSRF probing. A session that has never registered cannot be reached from outside.
**The session itself must announce itself, once.**

| Route | Result |
|---|---|
| Hot-reloading `hooks.json` | **No.** Hooks load only at session start (`hooks_manager.go:53`); `ReloadHooks` fires only on TUI workspace-trust events. **[agy]**, with the log consistent **[claude]** |
| `agy -p --conversation <id>` against a live session | **No.** It starts a **second, competing** agy with its own LS on the same SQLite store, and the live session never sees the message. **[agy]** **xmsg must never do this.** |
| `agy remote-control` / tokenless `agentapi` | **No.** Remote control is Google's cloud relay, and `agentapi` without the env vars is `Unauthenticated`. **[agy]** |
| **Self-announce**: the session runs `xmsg register agy` in one turn | **Yes, for the precondition.** A command run inside a turn inherits `ANTIGRAVITY_LS_ADDRESS`/`_CSRF_TOKEN` and can connect to a Unix socket. This was measured **[agy]** against an ephemeral stub, `/tmp/mock_xmsg_register.sock`. xmsg's own `SO_PEERCRED` and descendant acceptance is **design, untested** until xmsg is built. |

**Lifecycle:**

- **Sessions started after the aspect is deployed** register on their first turn, through the global
  `hooks.json` (§6.1 step 4), with no user action.
- **Sessions already running at deploy time** get a first contact from the user, who runs `/xmsg-register`
  once. That is a skill or slash command shipped by the same aspect, which runs `xmsg register agy`.
  After that, xmsg holds the credentials until the presence lock drops. Such a session never gets the
  per-turn refresh, so it relies on the `503 credentials_stale` path if its LS restarts.
- `GET /v1/sessions` lists an unregistered live agy session with `"registered": false`, so a caller
  can see it exists and that it needs the one-time announce.

**Delivery:**

- The server runs `agy agentapi send-message --title "<from-name>" <conversation_id> <body>` as an
  **argv vector with no shell**.
- The LS address and token go into **the child's environment**, not argv, because argv is
  world-readable in `/proc/<pid>/cmdline`.
- `<from-name>` is the §5.2-sanitized `xmsg@<host> · <from>`. The body starts with the §9.4 header line.
- Exit `0` gives `202`, a non-zero exit gives `502 inbox_unavailable`, and the 5 s timeout gives `504`.

**Replies:**

- The MCP `reply` tool (§8.3) identifies its session by parent pid = the lock holder, which maps to
  `conversation_id` through `/proc/locks` **[both: tree measured]**. No credentials are needed.
- agy's native `send_message` has no route to xmsg, so it is out of scope.

### 9.3 pi (0.87.1)

- **Basis:** an **`xmsg-pi` extension**, read from the bundled `docs/extensions.md`. Nothing is measured.
- **Registration** runs inside the pi process, over the same `register.sock`.
  - `SO_PEERCRED` gives the pi pid, and its start time pins liveness. There is no lock to check, so
    the descendant check is replaced by "the peer *is* the session".
- **Delivery is pull-based.** The extension long-polls over the socket and injects each message with
  `pi.sendUserMessage()`.
- **Replying** uses a `reply` tool registered with `pi.registerTool()`.

### 9.4 Envelope per harness

- Claude keeps `<cross-session-message from-name=…>` (§5.2).
- agy and pi get a plain header line, then a blank line, then the body:
  `[xmsg] from=xmsg@<host> · <from> message_id=<id> — reply with the xmsg reply tool`.
- The same envelope layer is used throughout: bodies are argv or serde-encoded, never concatenated into
  JSON.

### 9.5 API changes

- `GET /v1/sessions` returns sessions from all adapters. Each gains `harness` (`claude` | `agy` | `pi`).
- No other endpoint changes. Registration is socket-only (§9.2).

### 9.6 Probes before v3 code

1. ~~**[agy-hooks]**~~ **PASSED 2026-10-06** (§9.2). The hook fires and sees both credentials. All three
   tightenings are agreed by both agents.
2. **[agy-outside]** The owner reproduces the out-of-tree `send-message` delivery and idle wake.
3. **[pi]** Can the extension's `sendUserMessage` inject into an *idle* interactive session and wake it?
4. **[agy-reply]** Does an agy MCP child reach the loopback xmsg port under `agy --sandbox`?

## 10. Open questions

- **darwin liveness.** The `procStart` format on macOS is not yet measured. Until it is, darwin
  checks only that the pid exists.
- **Behaviour for receivers in `bypassPermissions` mode.** Per codehydra, they hold the message for
  approval; this is not re-measured here.
