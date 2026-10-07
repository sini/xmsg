# TODO

## 1. Cross-host delivery (next; needs an owner design session before any spec)
- Address sessions as `<session>@<host>`. A server forwards to the peer host's xmsg.
- The attested badge survives the hop: `xmsg@<host> · <harness>:<name>`.
- A host can vouch only for its OWN sessions. The receiver records the peer host as the source.
- Pushed replies work across hosts.
- Open design question (owner):
  - (a) forward over ssh to the remote agent.sock (ssh -W / ProxyCommand). ssh keys plus the Tailscale names are the trust root, and HTTP stays loopback-only. This is the recommended option.
  - (b) HTTP on the tailnet, with `tailscale whois` peer identity. It adds a network listener and a Tailscale dependency.
- Today's workaround: `ssh <host>.ts.json64.dev curl ...`, which arrives as an anonymous sender, with no reply push.

## 2. CLI client for scripts (pairs with 1)
- `xmsg list`, `xmsg send <ref> "text" [--wait N]`, `xmsg wait <message-id>`, as subcommands of the existing binary.
- They replace hand-written curl JSON, and give cross-host one command shape (`xmsg send ed@cortex ...`).

## 3. Recipient-gone signal
- When a pi registration is removed with undelivered queue rows, mark those rows `recipient_gone`, so `GET /v1/messages/{id}` reports it instead of looking pending forever.
- Consider the same for agy/claude sends that 410 after acceptance.

## 4. Owner-readable message log
- `GET /v1/messages?since=<ts>`: list recent traffic (sender badge, recipient, timestamps, push_outcome) with NO message bodies.
- It gives the owner one place to see agent-to-agent traffic. The data is already in SQLite.

## Deferred / not planned
- Broadcast or topics: no use case yet.
- Self-claimed stable session names: they would reintroduce intra-harness impersonation, and the cwd-basename display name suffices.
- A "go quiet" mode: replying is optional, and an agent can ignore messages.

## Live-verification gaps
- agy has not been exercised live. Session 660dbde7 predates the hook; a fresh agy session should self-register on its first turn. Verify list, send, reply and push with agy.
