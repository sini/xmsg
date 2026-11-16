{ inputs, lib, ... }:
{
  perSystem =
    { pkgs, system, ... }:
    let
      craneLib = inputs.crane.mkLib pkgs;
      package = inputs.xmsg.packages.${system}.default;
      oldCollectorSource = pkgs.fetchFromGitHub {
        owner = "sini";
        repo = "xmsg";
        rev = "8090f65259ecb947d72cd74382881763fd6b5da6";
        hash = "sha256-IEyXgGpBG93oso7rNuG+IH50229EyIWQdzZapCgamP0=";
      };
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
            python3 tests/fixtures/dtxj2/run_compat.py \
              --source "$PWD" \
              --output "$TMPDIR/collector-compat" \
              --artifact-seed "''${CARGO_TARGET_DIR:-target}" | tee collector-compat.log
            python3 tests/fixtures/reverse_observe/run_compat.py \
              --source "$PWD" \
              --old-source ${oldCollectorSource} \
              --output "$TMPDIR/reverse-collector-compat" \
              --artifact-seed "''${CARGO_TARGET_DIR:-target}" | tee reverse-collector-compat.log
          '';
          installPhase = ''
            mkdir -p "$out"
            cp collector-browser.log collector-compat.log reverse-collector-compat.log "$out/"
            mkdir -p "$out/reverse-collector-compat"
            cp "$TMPDIR/reverse-collector-compat/"*.json \
              "$TMPDIR/reverse-collector-compat/"*.jsonl \
              "$TMPDIR/reverse-collector-compat/"*.stderr \
              "$TMPDIR/reverse-collector-compat/"*.log "$out/reverse-collector-compat/"
            mkdir -p "$out/collector-compat"
            cp "$TMPDIR/collector-compat/"*.json \
              "$TMPDIR/collector-compat/"*.jsonl \
              "$TMPDIR/collector-compat/"*.stderr \
              "$TMPDIR/collector-compat/"*.log "$out/collector-compat/"
          '';
        };
      };
    };
}
