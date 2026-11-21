# Optional executor contracts (planned)

This standalone Rust library contains internal contracts, a fail-closed control journal and deterministic ACP fixtures for a future local executor. It has its own Cargo manifest and lockfile; it does not convert the root project into a workspace or add an executable. The bus default package, recipient shapes and six existing MCP tools are unchanged.

There is no public launch producer, installed executable, host-attestation bridge, real harness/backend, native approval relay, reviewer, model/provider invocation, service installation or credential provisioning here. A crate-private supervisor foundation owns real OS child/process-group handles and locks; only test helpers select a fake ACP process. Later runtime stages must supply those implementations and their qualification evidence.

## Contracts

`protocol::ControlRequest` uses a strict versioned `{version, request_id, verb, target, args, deadline}` envelope. Dispatch can supply only its brief and request ID, leaving owner defaults unresolved. The uniform verbs are dispatch, send, steer, interrupt, resume, stop, status, result and approve. Steer and interrupt require an addressed generation and turn; resume distinguishes reconnect from loading a stored conversation. Typed requested/resolved fields keep harness and model separate, carry an executor/host/environment descriptor, immutable workspace references, required capabilities and budget. No raw executable, native flags, workspace path or caller authority is accepted in the request.

Lifecycle calls require peer UID plus an owner-configured verb/target grant bound to the per-call attested principal. The sealed production attestor is unavailable, so production calls return `attestation_unavailable`; only unit tests can install the fake attestor. No per-agent credentials are minted or assumed. Owner administration and synthetic human decisions use separate role credentials, which do not substitute for lifecycle attribution. A label, content message, claimed parent or caller boolean supplies no authority.

`control::ControlService` exposes single-connection Unix handlers, not a server executable. Lifecycle accepts one bounded JSON line; owner/human handlers accept a bounded proof line followed by JSON. The separate SQLite journal records idempotent admissions and historical receipts, immutable resolved dispatch settings/session identity, exact synthetic pending decisions and audit metadata. Proof bytes are never stored. New admissions check current grants, profile, generation/turn and deadlines. Journal session state describes intents; it does not assert that a native process is running or stopped. No pending-action producer or native decision relay exists in this slice.

Authorization, durable admission, native submission and observed effect are separate receipt layers. An SDK `Origin` describes content provenance only. Result/status fields retain generation, turn, provenance, freshness and unfinished work; a model saying “done” is not a completed execution receipt.

`capability::QualificationKey` includes the adapter/native runtime, ACP/schema identity, native mode, review mode, trust profile, model and effective config digest. `matches_pinned_metadata` only compares already-trusted record metadata; it does not verify artifacts or evidence provenance and is not an authorization API.

SAFE and human-only are defaults. Owner-selected UNSAFE is representable on every pin, even when protections are unknown or lost. `owner_selection_required` is trusted-config metadata, not an authenticated caller role. Protection reports never silently turn unknown into proved retained. No profile has been launched or qualified by this library.

## Framing and fake conformance

`framing::FrameReader` accepts individual UTF-8 newline-delimited JSON-RPC 2.0 frames, bounded to 1 MiB including the newline. It supports ACP v1's signed 64-bit/string/null request IDs and omitted params, rejects batches and invalid envelopes, and is permanently poisoned after any frame error. A future transport must discard the failed stream; it cannot resume an oversized tail as a new request. ACP negotiation version 1 is distinct from the JSON-RPC 2.0 envelope.

The test-only fake peers stay in `tests/support/`: deterministic in-memory and subprocess fixtures, not qualified native adapters. The corpus labels its observations `fake_only`. Fake steering/cancellation/child/denial observations do not establish any real-harness capability. All real tuples in `fixtures/pins.json` stay unproven:

- Claude ACP 0.108.0 / Claude 2.1.327;
- Codex ACP 2.7.0 / Codex 0.169.1;
- native agy ACP / agy 1.5.10.

Per-call parent attribution, native ask-mode verification and effective reviewer isolation are explicitly first in the qualification backlog. A source version or a passing fake test is not runtime qualification.

## Staged supervisor, workspaces and content membership

Stop attempts do not prove full group absence from a direct child wait. This stage reports unknown and retains the slot/workspace rather than claiming stopped or permitting cleanup without that proof. The supervisor owns one absolute startup-inclusive wall deadline, including ACP handshake and accepted-client I/O. Backend exit or loss of its output transport is observed before attach/events can publish running.

Launch authority is a private journal-derived lease, never a serialized receipt. Current original-principal grants, profile/policy, generation and resource caps are checked again before launch. A durable spawn intent precedes the OS effect; uncertain ownership stays unknown and consumes its slot. Reconnect authenticates the existing supervisor rather than spawning or replaying prompts. Diagnostic PIDs are not kill authority.

Owner workspace bindings fix the repository, approved root and immutable base. Preparation is revalidated before execution, ignores ambient Git hooks/configuration and refuses unsafe filters/includes/fetches. Ownership markers distinguish worktree incarnations; dirty or unowned work is preserved on cleanup. Context/patch references are bounded, owner-bound and SHA-pinned; no auth files or dirty checkout are copied.

Ordinary SDK service proxies use stable 31-byte names. They retain their registration handle and commit generation-bound message deduplication/content before acknowledgement. Text, JSON, envelopes and origin are content/provenance, never lifecycle or approval authority. The real-bus fixture uses its own scratch daemon and sender, never a live fleet socket.

## Check this package only

From the repository root:

```sh
extensions/executor/scripts/check.sh
```

The check script builds the candidate scratch daemon outside cargo-test and records its binary hash/version, then supplies it explicitly to the required real-bus fixture. It does not install a service or launch a real harness. One ignored libtest helper is a subprocess entrypoint, not a qualification case: parent tests actually execute and reap it. The census distinguishes that exact helper from functional tests and rejects other ignored tests.

Pinned ACP schema basis: [RequestId and v1 schema](https://github.com/agentclientprotocol/agent-client-protocol/blob/fa50fde1ac75ccd22fafff69c3e0ec3562a4f30f/schema/v1/schema.json), [stdio transport](https://agentclientprotocol.com/protocol/v1/transports). This package makes no v2 or real-runtime support claim.
