# xmsg

**Documentation & site:** <https://xmsg.dev>

`xmsg` is a federated message bus between running AI agent sessions ([Claude Code](https://xmsg.dev/harnesses/claude-code/), [Codex](https://xmsg.dev/harnesses/codex/), [Antigravity](https://xmsg.dev/harnesses/antigravity/), [opencode](https://xmsg.dev/harnesses/opencode/), [Hermes](https://xmsg.dev/harnesses/hermes/), and [Pi](https://xmsg.dev/harnesses/pi/)) and headless services, across local Unix domain sockets, mTLS hubs, container leaf pods, and hosted-dot gateways.

---

## Highlights

- **Local-first, zero-ceremony IPC:** Binds Unix domain sockets (`http.sock`, `agent.sock`, `register.sock`) in `$XDG_RUNTIME_DIR/xmsg/` (`0700` dir, `0600` sockets) and authenticates callers via kernel peer credentials (`SO_PEERCRED` on Linux, `getpeereid` on macOS).
- **Attested sender identity:** Every message carries `label · id@node`, `label · <P>/<child>@node`, `name@node`, or `<from> · anon@node`, separating the sender's unverified display label from the `xmsg`-attested address.
- **Five tools across every harness:** `list`, `send`, `reply`, `replies`, and `inbox` (for [delegated subagents](https://xmsg.dev/concepts/sessions-services-subagents/#delegated-subagents-pchildnode)).
- **Durable queueing & cross-machine handoff:** Sends to parked conversations queue in SQLite (`7 days` default reply TTL) and drain in FIFO order when the conversation returns — or follow a Claude conversation across a user's machines over `/fed/v2/handoff`.
- **Cross-host mTLS federation (`/fed/v2`):** Authenticate peers with pinned Ed25519 keys (`pin`) or CA-signed SPIFFE X.509-SVIDs (`ca` + `identities`), with [durable leaf mailboxes, NAT outbound links, and single-hop hub forwarding](https://xmsg.dev/concepts/hubs-and-leaves/).
- **Validated Rust service client (`xmsg::client`):** Lightweight 23-package client feature (`--no-default-features --features client`) for external Rust services (`matrix-xmsg`, `genie-guard`, `xmsg-mcp-gateway`).

---

## Quickstart (Nix & Home Manager)

```nix
{
  inputs.xmsg.url = "github:sini/xmsg";

  imports = [ inputs.xmsg.homeManagerModules.xmsg ];
  programs.xmsg = {
    enable = true;
    harnesses = {
      claude.enable = true;
      codex.enable = true;
      agy.enable = true;
      opencode.enable = true;
      hermes.enable = true;
      pi.enable = true;
    };
  };
}
```

See [NixOS & Home Manager](https://xmsg.dev/operations/nixos-and-home-manager/) for server options and mTLS peer configuration.

With the daemon running, use the [operator CLI](https://xmsg.dev/reference/cli-and-mcp/):

```bash
xmsg list
xmsg send worker "Build status?" --from operator
printf '%s\n' "Build status?" | xmsg send worker - --json
xmsg replies MESSAGE_ID --wait 10
xmsg show MESSAGE_ID --json
```

Run an optional command-backed service explicitly:

```bash
xmsg service exec --name agent-quota -- agent-quota --json
```

---

## Documentation

Full documentation lives at **<https://xmsg.dev>** (source under [`docs/src/content/docs/`](docs/src/content/docs/)):

- **[Overview](https://xmsg.dev/overview/)** — What xmsg is, who it is for, and where to go next.
- **[Architecture](https://xmsg.dev/architecture/)** — The daemon, its sockets, and how the pieces fit together.
- **Concepts**
  - **[Addressing & Resolution](https://xmsg.dev/concepts/addressing/)** — `id@node`, `id~n@node`, `<P>/<child>@node`, `name@node`, local 5-step resolution, and federated view resolution.
  - **[Sessions, Services & Subagents](https://xmsg.dev/concepts/sessions-services-subagents/)** — Instance claims, headless `svc` daemons, and delegated subagent turn mailboxes (`inbox`) with parent fallback.
  - **[Delivery, Queueing & Replies](https://xmsg.dev/concepts/replies/)** — Parked conversation queues, cross-machine queue handoff, symmetric reply authorization, and `idempotency_key` semantics.
  - **[Federation](https://xmsg.dev/concepts/federation/)** — Self-authenticating node names, pinned vs. CA-signed trust models, `peers.json` policies, and mesh `list`.
  - **[Hubs, Leaves & Gateways](https://xmsg.dev/concepts/hubs-and-leaves/)** — Container `--leaf` mode, `"dial": "outbound"` links, single-hop hub forwarding, and hosted-dot gateways.
  - **[Security & Trust Model](https://xmsg.dev/concepts/trust-model/)** — Same-UID attribution boundary, per-harness attestation, and envelope sanitization.
- **Harness Integration**
  - **[Claude Code](https://xmsg.dev/harnesses/claude-code/)** · **[Codex](https://xmsg.dev/harnesses/codex/)** · **[Antigravity](https://xmsg.dev/harnesses/antigravity/)** · **[opencode](https://xmsg.dev/harnesses/opencode/)** · **[Hermes](https://xmsg.dev/harnesses/hermes/)** · **[Pi](https://xmsg.dev/harnesses/pi/)**
- **CLI & API Reference**
  - **[CLI & MCP Server](https://xmsg.dev/reference/cli-and-mcp/)** — `xmsg serve`, `xmsg mcp`, `xmsg register`, `xmsg check-peers`, and MCP tool schemas.
  - **[HTTP API & Unix Sockets](https://xmsg.dev/reference/http-and-sockets/)** — `http.sock`, `agent.sock`, `register.sock`, `/fed/v2/*` routes, and error codes.
  - **[Daemon Protocol & Rust Client](https://xmsg.dev/reference/service-client/)** — Service registration wire frames and the [`xmsg::client`](docs/service-client.md) crate feature.
- **Operations & Platforms**
  - **[NixOS & Home Manager](https://xmsg.dev/operations/nixos-and-home-manager/)** · **[Runtime, Reloading & Systemd](https://xmsg.dev/operations/runtime-and-systemd/)** · **[OCI & Docker](https://xmsg.dev/operations/docker/)** · **[Kubernetes & Helm](https://xmsg.dev/operations/helm-and-kubernetes/)**

---

## Building & Verification

```bash
# Rust test suite, Clippy, and formatting
cargo test --all-targets
cargo clippy --all-targets -- -D warnings
cargo fmt -- --check

# Build the docs site and validate all internal links and code imports
cd docs && pnpm install --frozen-lockfile && pnpm run build

# Nix package, OCI image, and CI checks
nix build .#default --no-link
nix build .#image --no-link
nix flake check ./ci
```
