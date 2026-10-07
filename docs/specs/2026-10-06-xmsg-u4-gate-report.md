# Gate Review Report: Unit U4 Implementation Spec

- **Date:** 2026-10-06
- **Reviewer:** Adversarial Spec Reviewer (Antigravity)
- **Target Artefact:** `docs/specs/2026-10-06-xmsg-u4-impl.md`
- **Verdict:** ACCEPT

---

## 1. Review Invariants & Findings

### Objection 1: Discovery & Registration Trust Boundary
- **Question:** Does the server trust an unverified process claiming to be a Pi session?
- **Finding:** No. `register.sock` uses `SO_PEERCRED` to identify the caller's peer PID and UID. The server verifies:
  1. `peer_uid == my_uid`.
  2. `/proc/<pid>/cmdline` confirms the binary being run is `pi` (or `node` invoking `pi`).
  3. `/proc/<pid>/stat` field 22 (`starttime`) is recorded to prevent PID recycling attacks.
- **Resolution:** ACCEPT.

### Objection 2: Pull Delivery & Concurrency Deadlocks
- **Question:** Can long polling on `register.sock` starve other registrations or block Tokio threads?
- **Finding:** No. Connections are handled in separately spawned Tokio tasks. Long-polling uses `tokio::sync::broadcast` or `notify` with an explicit timeout, avoiding thread starvation or blocking locks.
- **Resolution:** ACCEPT.

### Objection 3: Reply Attribution & Not-Recipient Enforcement
- **Question:** Can an arbitrary Pi session reply to a message addressed to another session?
- **Finding:** No. Replies are routed through `POST /v1/messages/{message_id}/replies`. The server enforces `replier_session_id == msg.session_id`. If they do not match, HTTP 403 `not_recipient` is returned.
- **Resolution:** ACCEPT.

### Objection 4: Extension Packaging & Isolation
- **Question:** Does the extension require global npm or nix-config installation?
- **Finding:** No. The extension is placed under `extensions/pi/` inside the repo and is loaded explicitly via `pi --extension extensions/pi/index.ts` or during testing. It has zero external dependencies outside Node.js built-ins (`node:net`, `node:http`) and the `@earendil-works/pi-coding-agent` types.
- **Resolution:** ACCEPT.

---

## 2. Verdict
ACCEPT. Spec is sound, fully aligned with Gist §9.3, and ready for implementation.
