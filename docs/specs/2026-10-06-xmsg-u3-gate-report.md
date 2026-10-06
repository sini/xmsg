# Adversarial Review Gate Report: xmsg Unit U3 Implementation Spec

**Artefact Under Review:** `docs/specs/2026-10-06-xmsg-u3-impl.md`  
**Parent Design:** `docs/specs/2026-10-06-xmsg-v1-design.md` (§9.1, §9.2, §9.4, §9.5)  
**Date:** 2026-10-06  
**Reviewer:** Adversarial Spec Review Gate (`gen-gate` posture)  
**Initial Posture:** REJECT  
**Final Verdict:** ACCEPT

---

## 1. Executive Summary

The Unit U3 implementation spec covers the attached adapter for Antigravity (`agy`), the adapter abstraction layer refactoring `claude` without regression, read-only presence lock resolution via `/proc/locks`, the root-bounded peer-cred verified registration socket `$XDG_RUNTIME_DIR/xmsg/register.sock`, the `xmsg register agy` CLI command, the first-contact definition file, and MCP `reply` routing for `agy`.

The spec was evaluated against the parent design, wire invariants, concurrency properties, and testability. Four initial objections were identified and resolved in the spec.

---

## 2. Objections & Dispositions

### Objection 1 (Testability): `SO_PEERCRED` Sandbox Spoofing
- **Objection:** In Linux, `SO_PEERCRED` returns the kernel-verified UID/PID of the connecting socket peer. In an automated test suite or Nix build sandbox, tests cannot spoof other UIDs or arbitrary non-child PIDs across user boundaries without root privileges. If the registration handler tightly couples `peer_cred()` extraction with the validation logic, tests cannot verify negative controls for UID mismatches or non-descendant PIDs.
- **Disposition:** ACCEPTED.
- **Resolution:** Decouple `SO_PEERCRED` reading from the verification engine:
  ```rust
  pub fn verify_registration(
      proc_root: &Path,
      proc_locks: &Path,
      presence_dir: &Path,
      my_uid: u32,
      peer_uid: u32,
      peer_pid: u32,
      req: &AgyRegisterRequest,
  ) -> Result<u32, AppError>
  ```
  The socket listener extracts real `peer_cred` and passes them to this function, while unit and fixture tests can pass synthetic peer UIDs and PIDs to test all authorization rejection paths deterministically.

---

### Objection 2 (Device Numbers): Device Major/Minor Representation in `/proc/locks`
- **Objection:** Field 5/6 in `/proc/locks` displays device numbers as hexadecimal strings (e.g. `00:2e`) while `std::fs::Metadata::dev()` returns a decimal 64-bit integer (`dev_t`). Naive decimal string comparisons would fail to match held locks.
- **Disposition:** ACCEPTED.
- **Resolution:** Explicitly specify in §3.1 that the device string in `/proc/locks` must be parsed with `u32::from_str_radix(..., 16)` and compared against standard `libc::major(meta.dev())` and `libc::minor(meta.dev())`, while the inode is parsed in base 10.

---

### Objection 3 (Error Protocol): Distinguishing Stale Credentials from Absent Sessions
- **Objection:** The parent design specifies that an unregistered agy session should appear in `GET /v1/sessions` with `registered: false`. If a caller attempts to deliver a message to an unregistered session, returning 404 `not_found` would mislead the caller into thinking the session does not exist, whereas returning 500 would violate HTTP semantics.
- **Disposition:** ACCEPTED.
- **Resolution:** Define `AppError::CredentialsStale(String)` mapping to HTTP 503 `credentials_stale`. When an agy session is live (presence lock held) but unregistered or marked stale, delivery attempts return HTTP 503 with a clear message indicating registration is required via `xmsg register agy`.

---

### Objection 4 (Security Invariant): `agy agentapi` Child Environment Isolation
- **Objection:** If `ANTIGRAVITY_CSRF_TOKEN` is accidentally passed as a CLI flag or in command line arguments, it would be exposed in `/proc/<pid>/cmdline` to all users on the host. Furthermore, if `xmsg` executes `agy` via `sh -c`, quoting bugs could lead to shell injection.
- **Disposition:** ACCEPTED.
- **Resolution:** Enforce that `xmsg` invokes `tokio::process::Command::new("agy")` directly as an argv array with NO intermediate shell (`sh -c`). Credentials (`ANTIGRAVITY_LS_ADDRESS`, `ANTIGRAVITY_CSRF_TOKEN`) must strictly be set via `.env()`. The test suite oracle must inspect the child's recorded argv and assert the token is absent from argv.

---

## 3. Verdict & Readiness

With all 4 objections resolved and dispositioned into the design, the specification meets all requirements of gist §9.1, §9.2, §9.4, and §9.5.

**Verdict:** ACCEPT  
**Action:** Proceed to implementation of Unit U3.
