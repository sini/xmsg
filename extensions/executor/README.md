# Optional executor contracts (planned)

This standalone Rust package contains internal contracts, a fail-closed control journal and a staged supervisor entrypoint. It has its own Cargo manifest and lockfile; it does not convert the root project into a workspace or change the bus default package, recipient shapes or existing MCP tools.

Runtime activation is disabled: adapter qualification is empty and trusted caller qualification references remain unavailable. The staged entrypoint does not provide an activation switch. No executable is installed, and no real harness, reviewer, model/provider invocation, service installation or credential provisioning is qualified here. A crate-private supervisor owns real OS child/process-group handles and locks; only test helpers supply fake qualification facts and an ACP process.

The startup channel is restored to close-on-exec before any adapter spawn. Native IO processes at most one frame per iteration before servicing control and queued effects. Definitely pre-launch failures are durable journal outcomes (`failed`, `not_attempted`), excluded from the broker and direct launch lease paths; they release only their unstarted journal slot. Unknown post-spawn executions retain their slot and reconciliation fence.

Owner launch environment is a bounded fixed search path plus an optional real account home validated against the current UID's passwd entry. Preflight lookup occurs outside journal locks; native executable overrides come from pinned program paths. This launch description is not proof of native effective settings, account limits or capability qualification.

Optional owner `bus` configuration exposes only text `list`, `send` and `reply` through a separate execution-bound content socket. The SDK registration remains in the supervisor process. Sidecar initialization and tool discovery are local; SDK calls run on bounded dedicated tasks. Inbound automatic input additionally requires explicit `auto_input: true`: content is committed before ACK and gets its own durable native-delivery intent. A message's sender, origin, JSON or prose cannot create a lifecycle admission or human decision. Unknown transports keep queued content without rebinding or relaunching.

Each outgoing managed content call gets a fresh journal admission check against the original dispatch, owned session/generation/epoch, current grants, caller and adapter eligibility, disable fence and wall bound. The policy/audit transaction commits immediately before one SDK attempt; no journal mutex is held over network IO and no stale authorization is cached. A request admitted before revocation may finish in flight; this does not promise cancellation of an already sent bus message. Later calls are denied.

## Contracts

The staged credential-free `call --config <file>` command reads one bounded `LifecycleCall` JSON object from stdin. It sends no role proof or caller identity prefix: lifecycle authorization comes from the actual kernel peer of that connection plus the configured attestor and current owner grants. `caller_context` is only an accountable selector for an already represented native session/root, never an identity, registration or qualification claim. There is no public control MCP endpoint in this slice.

`runtime_config::RuntimeConfig` describes owner-selected program paths and SHA256 pins, native modes, workspace bindings, service paths and separate credential-file references. Its bounded private-file reader and artifact verification do not execute programs or qualify runtime capabilities. Caller requests cannot replace those settings. Runtime activation remains unavailable until separately reviewed qualification records exist.

Each configured pin has one explicit unified provider/model mapping to its exact `native_model_id`. All templates selecting that pin must match the mapping. The ACP driver must apply and observe that actual native ID before a prompt; an empty acknowledgement or ambient default is insufficient. The launch-settings digest is not evidence of native effective tool/hook inventory.

Dispatch templates may explicitly list `lifecycle_verbs`; the default empty list delegates nothing. Successful dispatch records only those verbs for its attested caller and exact new session/generation. Current owner policy must retain both that holder's dispatch grant and the template verb; removing either revokes the derived lifecycle authority. Explicit owner-configured session grants remain independent. Creation, ancestry and content-proxy registration grant nothing. Replays do not add or widen grants.

The separately authenticated owner can issue `disable_runtime`. That audited fence survives policy replacement and restart, blocks new effect admissions and approval decisions, and preserves authorized inspection and stop. No restore command is supplied in this stage; future owner restoration must revalidate current qualification, expiry and revocation. The adapter qualification registry is empty and cannot be populated through owner configuration.

`ControlService::with_runtime_configuration` applies the reviewed adapter-eligibility fence before creating a runtime admission, session or delegation. Caller attribution remains a separate prerequisite. Candidate package pins and advertised ACP capabilities do not qualify effects; the empty registry denies runtime admissions without launching or inspecting configured programs.

The staged lifecycle journal derives native commands from admitted requests and binds queued content to the exact execution generation, native session and transport epoch. It records submission intent before I/O, rechecks current authority and eligibility before writing, and does not replay uncertain submissions. Fake-only tests exercise serialized ACP effects; no real adapter has been qualified or launched.

Native writes require the supervisor's monotonic-deadline I/O wrapper; a blocking child stdin cannot be passed directly. No native reply is awaited under a journal transaction. A wedged write becomes unknown and releases journal access for authenticated owner disable and inspection.

Adapter eligibility also binds the actual executor binary SHA256; the crate version is not a build identity. Verified executor/adapter/native files remain held and their identities are checked before effects, keeping large file hashing outside the journal lock. Missing or changed artifacts deny new effects. No runtime configuration field can create a qualification record.

Trusted caller qualification references are a separate activation dependency. The daemon supplies attested caller context, not binary/mode qualification or protected-policy-store proof. The extension preserves that context and has an opaque default-deny caller matcher; its production provider has no records, loader or protected-store proof. Diagnostic reference JSON cannot restore authority after provider recreation. Production effects remain unavailable independently of adapter qualification. Queued work never reuses an old PID/socket as an identity oracle or requires its parent process to remain alive.

Admissions persist the exact attested context and immutable caller-record diagnostic receipt. New launch, bootstrap, native/content prompt and permission-response effects require the held reference and current independent caller/adapter checks. A contradictory receipt, lost reference, replacement, expiry or revocation denies new effects. The owner channel can append an exact caller-record ID/revision revocation without changing the adapter policy revision; it cannot add or restore qualification. Real protected-store proof must cover admission/policy binding state too, not just a private record file. Only trusted `cfg(test)` fixtures can reconstruct references from checked persisted metadata.

Native pending requests come only from the driver's current live permission map, bound to the original operation and execution/transport/turn. Native decisions use the separate human credential channel plus `{request, confirmation}` with the exact approval ID, operation digest and fresh confirmation time. Bare legacy approval calls and persistent permission options cannot consume those requests. Interrupt intent invalidates existing asks immediately and prevents late old-turn requests from reopening review. Confirmation is a trusted operator-channel contract, not proof of isolation from same-UID code. Raw bounded request data stays in the private journal; audit metadata contains no authentication proof.

`protocol::ControlRequest` uses a strict versioned `{version, request_id, verb, target, args, deadline}` envelope. Dispatch can supply only its brief and request ID, leaving owner defaults unresolved. The uniform verbs are dispatch, send, steer, interrupt, resume, stop, status, result and approve. Steer and interrupt require an addressed generation and turn; resume distinguishes reconnect from loading a stored conversation. Typed requested/resolved fields keep harness and model separate, carry an executor/host/environment descriptor, immutable workspace references, required capabilities and budget. No raw executable, native flags, workspace path or caller authority is accepted in the request.

Lifecycle calls require peer UID plus an owner-configured verb/target grant bound to the per-call attested principal. The sealed production attestor is unavailable, so production calls return `attestation_unavailable`; only unit tests can install the fake attestor. No per-agent credentials are minted or assumed. Owner administration and synthetic human decisions use separate role credentials, which do not substitute for lifecycle attribution. A label, content message, claimed parent or caller boolean supplies no authority.

`control::ControlService` exposes single-connection Unix handlers used by the staged `serve --config` entrypoint. Lifecycle accepts one bounded JSON line; owner/human handlers accept a bounded proof line followed by JSON. The separate SQLite journal records idempotent admissions and historical receipts, immutable resolved dispatch settings/session identity, exact pending decisions and audit metadata. Proof bytes are never stored. New admissions check current grants, profile, generation/turn and deadlines. Journal session state describes intents; it does not assert that a native process is running or stopped.

The planned `human --config <file> --session <id> --generation <N>` operator queries only genuine current native asks on the human channel. It requires a controlling terminal and an exact per-request typed confirmation; it has no `--yes` or persistent-allow path. The service independently rechecks the approval ID, digest, expiry, generation, turn and current eligibility before recording a decision, then the native actor rechecks before responding. Same-UID code is not physically isolated from the operator. Querying an ask does not consume or confirm it.

The separate `owner-disable --config <file> --expected-revision <N>` command uses the owner credential channel and persists the emergency fence independently of qualification. Human credentials cannot invoke it. There is no restore/enable command; a successful disable does not claim that native processes have already stopped.

Status and result replies identify journal provenance. A finished ACP turn becomes background work with an unverified task outcome, not a completed-task or artifact claim. Failed pre-launch work reports journal `Failed`/`NotAttempted`; uncertain execution remains unknown and consumes its slot.

Qualified `resume(kind: reconnect)` attaches only to the same owned supervisor, generation, native session and transport epoch. It records the observation separately from native submission, rechecks current caller/adapter eligibility after the probe, and never initializes or launches a replacement. Unknown state is not cleared by seeing a live process. An interrupted probe is not automatically replayed. `load_stored_conversation` remains unavailable while safe retirement of the prior owned execution is unproven; the ACP load mapping alone is not a resume qualification.

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
