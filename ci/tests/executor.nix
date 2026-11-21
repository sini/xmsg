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
              pkgs.clippy
              pkgs.rustfmt
            ];
          }
        )).overrideAttrs
          {
            checkPhase = ''
              runHook preCheck
              set -o pipefail
              cargoWithProfile test --manifest-path extensions/executor/Cargo.toml --locked -- --list > executor-list.log
              cargoWithProfile test --manifest-path extensions/executor/Cargo.toml --locked -- --test-threads=1 2>&1 | tee executor-tests.log
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
              cp executor-list.log executor-tests.log executor-census.json "$out/"
            '';
          };
    };
}
