{ inputs, lib, ... }:
{
  perSystem =
    { pkgs, system, ... }:
    let
      craneLib = inputs.crane.mkLib pkgs;
      package = inputs.xmsg.packages.${system}.default;
    in
    {
      checks = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
        collector-browser = craneLib.cargoTest {
          pname = "xmsg-collector-browser";
          version = package.version;
          src = package.src;
          strictDeps = true;
          CARGO_PROFILE = "dev";
          cargoArtifacts = inputs.self.checks.${system}.tests.cargoArtifacts;
          cargoExtraArgs = "--locked --test gate_dtxj_collector";
          nativeBuildInputs = [
            (pkgs.python3.withPackages (ps: [ ps.playwright ]))
            pkgs.chromium
          ];
          preCheck = ''
            export XMSG_COLLECTOR_BROWSER_FIXTURE_DIR="$TMPDIR/collector-browser"
            export XMSG_COLLECTOR_BROWSER_PYTHON="${
              pkgs.python3.withPackages (ps: [ ps.playwright ])
            }/bin/python3"
            export XMSG_COLLECTOR_BROWSER_CHROMIUM="${lib.getExe pkgs.chromium}"
            export HOME="$TMPDIR/browser-home"
            mkdir -p "$HOME"
          '';
          postCheck = ''
            set -o pipefail
            python3 tests/dtxj_collector_browser.py \
              --fixture-dir "$XMSG_COLLECTOR_BROWSER_FIXTURE_DIR" \
              --chromium ${lib.getExe pkgs.chromium} | tee collector-browser.log
          '';
          installPhase = ''
            mkdir -p "$out"
            cp collector-browser.log "$out/"
          '';
        };
      };
    };
}
