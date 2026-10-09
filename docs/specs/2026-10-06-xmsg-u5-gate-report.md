# Gate Review Report: Unit U5 Implementation Spec

- **Date:** 2026-10-06
- **Reviewer:** Adversarial Spec Reviewer (Antigravity)
- **Target Artefact:** `docs/specs/2026-10-06-xmsg-u5-impl.md`
- **Verdict:** ACCEPT

---

## 1. Review Invariants & Findings

### Objection 1: Reply Spoofing Elimination

- **Question:** Does removing the HTTP reply endpoint completely eliminate caller-asserted reply identities?
- **Finding:** Yes. With `POST /v1/messages/{id}/replies` deleted from the HTTP router, HTTP clients cannot post replies under any circumstances. Replies MUST go through `agent.sock`, which uses kernel-enforced `SO_PEERCRED` to identify caller PID and walks ancestors to verify membership in the recipient session.
- **Resolution:** ACCEPT.

### Objection 2: Attestation & Prefix Spoofing

- **Question:** Can an unauthenticated HTTP caller forge the `session:` prefix to impersonate an attested agent?
- **Finding:** No. `send_message_handler` explicitly rejects any `from` starting with `session:` or `session/` with HTTP 400 Bad Request. Only the server when handling `send` on `agent.sock` attaches the `session:<name>` prefix.
- **Resolution:** ACCEPT.

### Objection 3: World-Writable `/tmp` Vulnerability

- **Question:** Are all `/tmp` fallback paths eliminated?
- **Finding:** Yes. Both server and clients require `$XDG_RUNTIME_DIR` (or explicit `--sock` args in tests) and mandate directory ownership (`uid == current_uid()`) and strict `0700` permissions. If `$XDG_RUNTIME_DIR` is unset, the server refuses to run, while `register agy` safely prints `{"injectSteps":[]}` and exits 0.
- **Resolution:** ACCEPT.

---

## 2. Verdict

ACCEPT. Spec addresses both security holes soundly and sets clear gating oracles.
