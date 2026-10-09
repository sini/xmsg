# Antigravity (`agy`) First-Contact & Registration Guide for `xmsg`

This document describes the registration mechanism and first-contact configuration for connecting an interactive Google Antigravity (`agy`) session to the local `xmsg` cross-session message bridge.

---

## 1. How It Works

Antigravity interactive sessions run an internal language server that binds to random loopback ports and authenticates via an ephemeral CSRF token minted at session start. Unlike Claude Code sessions (which expose dedicated Unix domain sockets listed in `~/.claude/sessions/`), Antigravity language servers require `ANTIGRAVITY_LS_ADDRESS` and `ANTIGRAVITY_CSRF_TOKEN` to deliver messages via `agy agentapi send-message`.

To enable external sessions to discover and send messages to an Antigravity session:

1. The Antigravity session holds an exclusive write lock on `~/.gemini/antigravity-cli/presence/<conversation_id>.lock`.
2. The session runs `xmsg register agy` once (or on every turn via a `PreInvocation` hook).
3. `xmsg register agy` reads the credentials from its environment and connects to `$XDG_RUNTIME_DIR/xmsg/register.sock`.
4. The `xmsg` server verifies:
   - Peer UID matches the server's own UID (`SO_PEERCRED`).
   - The presence lock for `<conversation_id>` is active in `/proc/locks`.
   - The peer process is a direct descendant of the process holding that presence lock.
5. The credentials are stored in memory only and retained until the session terminates (or the lock drops).

---

## 2. Automatic Registration via `PreInvocation` Hook

For automatic per-turn registration and credential refreshes, add the following to `~/.gemini/config/hooks.json` (global) or `<project>/.agents/hooks.json` (workspace):

```json
{
  "xmsg-register": {
    "PreInvocation": [
      {
        "type": "command",
        "command": "xmsg register agy"
      }
    ]
  }
}
```

### Hook Contract

- `xmsg register agy` conforms to the Antigravity hook contract:
  - It **always** prints `{"injectSteps":[]}` to stdout.
  - It **always** exits with exit code `0`.
  - If the `xmsg` server is offline or unreachable, it logs a notice to stderr and exits cleanly without disrupting the agent's turn.

---

## 3. Manual First Contact for Live Sessions

If a session was started before the hook was configured, the session can announce itself once by running:

```bash
xmsg register agy
```

Once registered, `xmsg` discovers the session, marks it as `registered: true` in `GET /v1/sessions`, and can deliver inbound messages directly into the session inbox.
