# The chart's leaf mode renders a pod that keeps the leaf-sidecar invariants
# (ci/tests/check-chart-leaf.py): a 0700 state dir made as xmsg's UID, pinned sockets and DB,
# one shared memory runtime dir, hardened containers, no service-account token, no TCP
# listener beyond loopback.
{
  perSystem =
    { pkgs, ... }:
    {
      checks.chart-leaf =
        pkgs.runCommand "xmsg-chart-leaf"
          {
            nativeBuildInputs = [
              pkgs.kubernetes-helm
              (pkgs.python3.withPackages (p: [ p.pyyaml ]))
            ];
          }
          ''
            export HOME="$TMPDIR"
            python3 ${./check-chart-leaf.py} ${../../charts/xmsg} ${../../examples/helm/leaf-values.yaml}
            touch $out
          '';
    };
}
