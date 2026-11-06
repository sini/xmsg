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
inherit the registered service identity.

Keep `RegisteredService` alive for poll/ACK. `agent_client()` returns a clonable
agent handle for list/send/reply without serializing those calls behind a long
poll. Dropping/cancelling/losing registration invalidates that handle once detected.
Cancellation or a failed exchange discards the partial registration stream. The
consumer chooses reconnection/backoff and must obtain a new handle after registering.
The library does not automatically retry a send or a reply.

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

`ci/xmsg-pin.toml` binds the baseline revision to a fixed-output source hash. The
baseline build patches only its CLI version string to include that revision; the
live cell checks it before use, rather than mistaking every `0.1.0` binary for the
same source. The candidate binary comes from the current Cargo build. Every pin
change reruns compatibility before acceptance. Consumers also keep their pinned
compatibility arms during migration; this baseline does not silently replace them.

The default daemon and its tests remain an independent regression plane. CI cost
includes a second client-only dependency build and an old-daemon build; timings
and Nix closure deltas must be measured on actual CI, not inferred from the package
counts. Linux runs live compatibility; macOS runs the daemon and portable client
checks. No fleet sockets, credentials or live peers are used by these fixtures.
