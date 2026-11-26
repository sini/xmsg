{ inputs, ... }:
{
  perSystem =
    { pkgs, ... }:
    let
      lib = pkgs.lib;
      craneLib = inputs.crane.mkLib pkgs;
      src = lib.cleanSourceWith {
        src = ../..;
        filter =
          path: type:
          let
            rel = lib.removePrefix ((toString ../..) + "/") (toString path);
          in
          rel == "Cargo.toml"
          || rel == "src"
          || lib.hasPrefix "src/" rel
          || rel == "extensions"
          || rel == "extensions/executor"
          || (
            lib.hasPrefix "extensions/executor/" rel
            && baseNameOf path != "target"
            && baseNameOf path != ".artifacts"
          );
      };
      args = {
        pname = "xmsg-executor-contracts";
        version = "0.1.0";
        inherit src;
        strictDeps = true;
        CARGO_PROFILE = "dev";
        cargoExtraArgs = "--manifest-path extensions/executor/Cargo.toml --locked";
        cargoVendorDir = craneLib.vendorCargoDeps { cargoLock = ../../extensions/executor/Cargo.lock; };
      };
    in
    {
      checks.executor-contracts =
        (craneLib.cargoTest (
          args
          // {
            cargoArtifacts = craneLib.buildDepsOnly (
              args
              // {
                preConfigure = "cp ${../../extensions/executor/Cargo.lock} extensions/executor/Cargo.lock";
              }
            );
            nativeBuildInputs = [
              pkgs.python3
              pkgs.git
              pkgs.clippy
              pkgs.rustfmt
            ];
          }
        )).overrideAttrs
          {
            checkPhase = ''
              runHook preCheck
              set -o pipefail
              export XMSG_EXECUTOR_FIXTURE_DAEMON="${
                inputs.xmsg.packages.${pkgs.stdenv.hostPlatform.system}.default
              }/bin/xmsg"
              export XMSG_EXECUTOR_FIXTURE_DAEMON_SHA256="$(sha256sum "$XMSG_EXECUTOR_FIXTURE_DAEMON" | cut -d' ' -f1)"
              export XMSG_EXECUTOR_FIXTURE_PYTHON="${pkgs.python3}/bin/python3"
              "$XMSG_EXECUTOR_FIXTURE_DAEMON" --version
              "$XMSG_EXECUTOR_FIXTURE_PYTHON" --version
              run_captured() {
                local capture_base="$1"
                shift
                local capture_status=0
                "$@" > "$capture_base.log" 2> "$capture_base.stderr.log" || capture_status=$?
                cat "$capture_base.log"
                cat "$capture_base.stderr.log" >&2
                return "$capture_status"
              }
              run_captured executor-list cargoWithProfile test --manifest-path extensions/executor/Cargo.toml --locked -- --list
              run_captured executor-tests cargoWithProfile test --manifest-path extensions/executor/Cargo.toml --locked -- --test-threads=1
              python3 extensions/executor/scripts/census.py --self-test
              python3 extensions/executor/scripts/census.py \
                --inventory extensions/executor/fixtures/test-inventory.json \
                --listing executor-list.log --results executor-tests.log \
                --platform ${
                  if pkgs.stdenv.hostPlatform.isDarwin then "darwin" else "linux"
                } --output executor-census.json
              cargoWithProfile clippy --manifest-path extensions/executor/Cargo.toml --all-targets --locked -- -D warnings
              cargo fmt --manifest-path extensions/executor/Cargo.toml -- --check
              runHook postCheck
            '';
            installPhase = ''
              mkdir -p "$out"
              cp executor-list.log executor-list.stderr.log executor-tests.log executor-tests.stderr.log executor-census.json "$out/"
            '';
          };
    };
}
