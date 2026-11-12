# xmsg Helm chart

This application chart runs one full node or federation hub. It does not package
harnesses, a gateway, a leaf sidecar or a certificate issuer. Install directly from
this checkout with Helm 4.3.1.

Provision an existing `kubernetes.io/tls` Secret containing `tls.crt` and `tls.key`.
Set `canonicalNodeName` to the certificate-derived node name, not a peer nickname:
the local probes deliberately query that name and never fan out to remote peers.
The chart references existing Secrets and mounts no host directories. Pin an immutable
image tag or set `image.digest` (which takes precedence over `image.tag`) for a
persistent installation. `resources` configures container requests and limits.

```sh
helm lint ./charts/xmsg --set-string canonicalNodeName='<canonical-name>' --set tls.existingSecret=xmsg-tls
helm template bus ./charts/xmsg --set-string canonicalNodeName='<canonical-name>' --set tls.existingSecret=xmsg-tls
```

Put the peer entries in `node-values.yaml` under `peers`; the chart writes the
`{"peers": ...}` JSON file. Pinned and CA peer policy is still validated by xmsg.
For CA peers, optionally set `ca.existingConfigMap` and refer to its public bundle
as `/etc/xmsg/ca/<key>` in each peer's `ca` field. This does not issue certificates.
`trustedServices`, for example `status: /bin/xmsg`, adds the corresponding
`--svc-exe` arguments. The default admits no trusted local services or harnesses.

The StatefulSet has exactly **one replica and one database writer**. Its retained
PVC holds `/var/lib/xmsg/state/xmsg.db` and SQLite sidecars. Stop the old writer
before attaching that state to a replacement; never share it with another running
daemon. Kubernetes storage access modes alone do not enforce SQLite's one-writer
operating rule. Changing the configured UID for existing state requires an offline
ownership migration; this chart does not change existing directory ownership.
The runtime socket directory and empty harness placeholders are
separate, disposable `emptyDir` volumes. Startup uses the image's xmsg entrypoint,
with no shell, init container or `chown` command.

Only federation TCP 7788 has a ClusterIP Service. The HTTP API remains on
`/run/xmsg/http.sock`; `XMSG_LISTEN` is not set. Readiness and liveness run
`/bin/xmsg list --http-sock /run/xmsg/http.sock --node <canonical-name> --json`
with a ten-second probe timeout, above the command's five-second request budget.

## Optional ingress policy

NetworkPolicy is off by default. When enabled, it selects this release's xmsg pod
and permits only federation TCP 7788 from the configured peer selectors. An empty
list creates **no ingress rules**, denying ingress. A namespace and pod selector
inside one entry are ANDed; separate entries are alternatives. Empty selector
objects retain Kubernetes' usual match-all semantics, so use explicit labels.
For example, only
selected gateway pods in the gateway namespace can reach federation:

```yaml
networkPolicy:
  enabled: true
  allowedPeers:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: gateway
      podSelector:
        matchLabels:
          app.kubernetes.io/name: xmsg-mcp-gateway
```

The policy requires a network plugin that enforces NetworkPolicy. It is ingress
only; DNS and egress are unchanged. Other ingress policies selecting the same pod
can also allow traffic. Federation mTLS and peer policy remain required.

The disposable example under `examples/helm` has been verified with Helm 4.3.1,
kind 0.33 and Kubernetes 1.37: two releases exchanged a message and correlated
reply; pod recreation and uninstall/reinstall retained state and a new smoke
exchange worked.
`prepare.py` needs Python 3 and OpenSSL (`OPENSSL` may override its executable),
retains existing demo keys/values, and creates private 30-day fixture identities.
`smoke.py` requires an explicit `--kubeconfig`. See the site's Kubernetes & Helm
[guide](https://xmsg.dev/operations/helm-and-kubernetes/) for the namespace, external
Secret and two-release installation commands.
The example's `image.pullPolicy=Never` assumes the matching image is already loaded
on the disposable cluster's nodes.

Default kind networking does not enforce NetworkPolicy. Raw TCP allow/deny checks
used an enforcing controller in the disposable fixture; that controller is test
infrastructure, not a production installation recipe. Production requires an
enforcing CNI. The optional `policy-smoke.py --kubeconfig <file>` changes only the
disposable example and checks new TCP connections for namespace/pod denial and an
empty deny-all policy, then restores release `a`'s policy to off. Lint/render checks
alone establish none of this runtime behavior.
