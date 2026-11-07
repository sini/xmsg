# Rust service client

The `xmsg::client` module implements the Unix-socket service protocol for external
Rust services. It does not embed the daemon, route federation traffic or implement
a consumer's authorization policy. Enable `client` with default features disabled;
the default `daemon` feature retains the executable and existing library surface.
Use the accepted immutable repository revision in consumers' lockfiles.

Register using `RegisteredService::register(ClientOptions)`.
The options specify private socket paths, service, daemon UID, a frame byte limit,
a total operation deadline and `expected_node: Option<String>`. After UID checking,
`None` accepts the daemon's nonempty reported node; `Some(node)` additionally pins
it exactly. Both modes require the real address to equal service@reported-node.
A gateway must require an expected node in its own startup configuration; Matrix
can preserve its local-daemon discovery policy by explicitly passing `None`.
The client checks socket-directory ownership/mode, socket ownership, peer UID and
the actual registration address/node; it never fabricates a registration result.
Consumers can reuse `current_uid()` for the same-user service profile. The daemon
still authenticates the real process executable. Registration, polling
and agent requests must originate from that same process. Child processes do not
inherit the registered service identity. Consumers can call
`xmsg::client::validate_service_name` at config load to enforce the same
service-name validator that `register.sock`, addressing and origin checking use
(`1..=32` ASCII `[A-Za-z0-9_-]`, not `"xmsg"`, not UUID/instance-shaped, and no
`/` or subagent prefix); `register.sock` refuses invalid service names at
registration with `ClientError::Refused { code: "bad_request" }`.
On registration, the daemon also reports its effective limits in force
(`reply_ttl_secs`, `idempotency_ttl_secs`, `svc_queue_cap`, and
`max_body_bytes` in bytes on
`xmsg::client::Registration` and via accessors on `RegisteredService`);
the fields are additive (`Option<...>`), so older clients ignore them and
older daemons decode with `None`.

Keep `RegisteredService` alive for poll/ACK. `agent_client()` returns a clonable
agent handle for list/send/reply without serializing those calls behind a long
poll. Dropping/cancelling/losing registration invalidates that handle once detected.
Cancellation or a failed exchange discards the partial registration stream. The
consumer chooses reconnection/backoff and must obtain a new handle after registering.
The library does not automatically retry a send or a reply. A register-socket
refusal deliberately drops the otherwise synchronised stream too; re-registration
can redeliver in-flight items, which the consumer must deduplicate.

`Delivery` is constructed by the validated decoder and exposes read-only accessors
for message ID, `from_name`, text, envelope, structured origin and in-reply-to.
Origin preserves instance, service and anonymous senders. `from_name` and labels
are display data; the shared transport never promotes them to authenticated identity.
Domain policy, retained Matrix cursor behavior, grants and message custody remain
consumer responsibilities. ACK only after the consumer's required durable record.

Agent requests explicitly carry schema version 2. Registration, poll and ACK do
not carry a version field: older servers refuse unknown fields there. Restricted
service constructors have no impersonation/context fields. Response limits and
operation deadlines apply before decoding; errors do not expose received bodies.
Send/reply receipts preserve upstream IDs and pending/unknown outcomes. A transport
timeout does not prove a mutation was refused. Persist and reuse an idempotency
key when the consumer's policy permits a retry; the transport cannot promise
exactly-once execution.

## Checks

```sh
cargo test --locked --no-default-features --features client --test shared_client
cargo test --locked --no-default-features --features client --lib \
  client::feature_tests::no_daemon -- --ignored --exact
python3 scripts/client-graph.py
python3 scripts/client-mutants.py
```

The mutation runner compiles each control with a separate build budget and then
executes the selected test binary under a shorter runtime bound. Compiler failures
or compilation timeouts never count as killed mutants. CI reuses its configured
Cargo profile rather than starting an unrelated debug dependency build.

The feature sentinel is deliberately ignored by default daemon tests; client CI
explicitly runs it and requires one executed, passing case. The graph check uses
normal production edges, with a default-daemon positive control. The initial
measurement is 23 client packages versus 176 daemon packages; this is a dependency
graph count, not a runtime closure-size measurement.

CI has a separate client-only dependency build. `shared-client` runs the bounded
socket tests, feature sentinel, dependency graph and single-site source mutants.
`shared-client-compat` drives real baseline and candidate daemons, including service
attribution, list, keyed send/deduplication, poll/ACK and pushed reply correlation.
It requires actual executed tests and a completion marker; missing binaries,
wrong revision identity, ignored/skipped cases and zero cases fail.

`ci/xmsg-pin.toml` supplies the baseline revision and expected source hash.
`ci/xmsg-source.nix` includes that revision in the fetch object's name, so changing
only the revision cannot reuse the old fixed-output store path. CI drives that
forgotten-hash re-pin at the Nix fetch layer and requires it to fail; removing the
revision-bearing name must make this oracle red. A hash alone does not bind a
revision label when its already-realised store path can be reused.

The baseline build also patches its CLI version string to include the selected
revision. The live test's comparison checks the binary label against the pin; it
is not independent proof of source provenance. The Nix fetch identity/hash check
provides that binding. The candidate comes from the current Cargo build. Every
pin change reruns compatibility before acceptance; consumers retain their own
pinned compatibility arms during migration.

The default daemon and its tests remain an independent regression plane. CI cost
includes a second client-only dependency build and an old-daemon build; timings
and Nix closure deltas must be measured on actual CI, not inferred from the package
counts. Linux runs live compatibility; macOS runs the daemon and portable client
checks. No fleet sockets, credentials or live peers are used by these fixtures.

## Registration health

`RegisteredService::health()` and `AgentClient::health()` return a nonblocking,
non-consuming snapshot of the registration connection. An idle connection or
pending data is healthy; peer close or write-half shutdown returns
`ClientError::Disconnected`, including when unread bytes precede EOF. Linux uses
`poll` shutdown flags; macOS uses a read `kqueue` event's `EV_EOF` flag. A peek
alone cannot detect shutdown behind pending data.

Health sends no protocol frames and never polls or ACKs the service queue. A
short descriptor-lifetime mutex prevents inspection racing with owner disposal
and descriptor reuse; it is never held across asynchronous I/O. Agent snapshots
do not keep a registration socket open after its owner is dropped. The normal
service reader can still consume a buffered response after health reports EOF.

Agent operations check health before submission and recheck it after an error,
including timeout. A genuine refusal on a healthy registration remains Refused;
an accepted successful receipt remains successful even if EOF follows it.
Health is point-in-time and provides neither delivery guarantees nor automatic
re-registration. Consumers implement recovery through the same validated
registration API and must invalidate their old snapshots.
