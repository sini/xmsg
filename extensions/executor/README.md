# Optional executor contracts (planned)

This standalone Rust library contains internal contracts, a fail-closed control journal and deterministic ACP fixtures for a future local executor. It has its own Cargo manifest and lockfile; it does not convert the root project into a workspace or add an executable. The bus default package, recipient shapes and six existing MCP tools are unchanged.

There is no production launcher, listening service, host-attestation bridge, supervisor, native approval relay, approval reviewer, process/model/provider invocation, service installation or credential provisioning here. Later runtime stages must supply those implementations and their qualification evidence.

## Contracts

`protocol::ControlRequest` uses a strict versioned `{version, request_id, verb, target, args, deadline}` envelope. Dispatch can supply only its brief and request ID, leaving owner defaults unresolved. The uniform verbs are dispatch, send, steer, interrupt, resume, stop, status, result and approve. Steer and interrupt require an addressed generation and turn; resume distinguishes reconnect from loading a stored conversation. Typed requested/resolved fields keep harness and model separate, carry an executor/host/environment descriptor, immutable workspace references, required capabilities and budget. No raw executable, native flags, workspace path or caller authority is accepted in the request.

Lifecycle calls require peer UID plus an owner-configured verb/target grant bound to the per-call attested principal. The sealed production attestor is unavailable, so production calls return `attestation_unavailable`; only unit tests can install the fake attestor. No per-agent credentials are minted or assumed. Owner administration and synthetic human decisions use separate role credentials, which do not substitute for lifecycle attribution. A label, content message, claimed parent or caller boolean supplies no authority.

`control::ControlService` exposes single-connection Unix handlers, not a server executable. Lifecycle accepts one bounded JSON line; owner/human handlers accept a bounded proof line followed by JSON. The separate SQLite journal records idempotent admissions and historical receipts, immutable resolved dispatch settings/session identity, exact synthetic pending decisions and audit metadata. Proof bytes are never stored. New admissions check current grants, profile, generation/turn and deadlines. Journal session state describes intents; it does not assert that a native process is running or stopped. No pending-action producer or native decision relay exists in this slice.

Authorization, durable admission, native submission and observed effect are separate receipt layers. An SDK `Origin` describes content provenance only. Result/status fields retain generation, turn, provenance, freshness and unfinished work; a model saying “done” is not a completed execution receipt.

`capability::QualificationKey` includes the adapter/native runtime, ACP/schema identity, native mode, review mode, trust profile, model and effective config digest. `matches_pinned_metadata` only compares already-trusted record metadata; it does not verify artifacts or evidence provenance and is not an authorization API.

SAFE and human-only are defaults. Owner-selected UNSAFE is representable on every pin, even when protections are unknown or lost. `owner_selection_required` is trusted-config metadata, not an authenticated caller role. Protection reports never silently turn unknown into proved retained. No profile has been launched or qualified by this library.

## Framing and fake conformance

`framing::FrameReader` accepts individual UTF-8 newline-delimited JSON-RPC 2.0 frames, bounded to 1 MiB including the newline. It supports ACP v1's signed 64-bit/string/null request IDs and omitted params, rejects batches and invalid envelopes, and is permanently poisoned after any frame error. A future transport must discard the failed stream; it cannot resume an oversized tail as a new request. ACP negotiation version 1 is distinct from the JSON-RPC 2.0 envelope.

The test-only fake peer stays in `tests/support/`; it is an in-memory deterministic fixture, not a process or adapter. The corpus labels its observations `fake_only`. Fake steering/cancellation/child/denial observations do not establish any real-harness capability. All real tuples in `fixtures/pins.json` stay unproven:

- Claude ACP 0.108.0 / Claude 2.1.327;
- Codex ACP 2.7.0 / Codex 0.169.1;
- native agy ACP / agy 1.5.10.

Per-call parent attribution, native ask-mode verification and effective reviewer isolation are explicitly first in the qualification backlog. A source version or a passing fake test is not runtime qualification.

## Check this package only

From the repository root:

```sh
cargo test --manifest-path extensions/executor/Cargo.toml --locked
cargo clippy --manifest-path extensions/executor/Cargo.toml --all-targets --locked -- -D warnings
cargo fmt --manifest-path extensions/executor/Cargo.toml -- --check
```

Pinned ACP schema basis: [RequestId and v1 schema](https://github.com/agentclientprotocol/agent-client-protocol/blob/fa50fde1ac75ccd22fafff69c3e0ec3562a4f30f/schema/v1/schema.json), [stdio transport](https://agentclientprotocol.com/protocol/v1/transports). This package makes no v2 or real-runtime support claim.
