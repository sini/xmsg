# xmsg

`xmsg` is a fast, lightweight local HTTP bridge running on the local host into live running agent sessions (Claude Code and peer harnesses).

## Features

- **Session Registry**: Scans local session files (e.g. `~/.claude/sessions`), verifies process liveness via `/proc/<pid>/stat` (preventing PID-reuse collision), and exposes active sessions via HTTP.
- **Direct Unix Socket Messaging**: Injects messages directly into session messaging sockets without consuming model turns.
- **Envelope Sanitization**: Sanitizes sender names, escapes tag injections, and prefixes caller host labels.
- **Zero In-Turn Overhead**: Delivers directly to harness socket inboxes.

## API Endpoints

- `GET /healthz`: Health and sessions directory check.
- `GET /v1/sessions`: List active sessions (optional `?cwd=`, `?status=busy|idle`).
- `GET /v1/sessions/{ref}`: Get single session details by session ID, PID, or name.
- `POST /v1/sessions/{ref}/messages`: Deliver a message to session inbox socket.

## Development

```bash
cargo test
cargo clippy -- -D warnings
nix build .#default
```
