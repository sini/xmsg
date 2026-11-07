{ inputs, ... }:
{
  perSystem =
    {
      pkgs,
      lib,
      system,
      ...
    }:
    let
      craneLib = inputs.crane.mkLib pkgs;
      package = inputs.xmsg.packages.${system}.default;
      pin = builtins.fromTOML (builtins.readFile ../xmsg-pin.toml);
      baselineSrc = import ../xmsg-source.nix { inherit pkgs pin; };
      baseline = pkgs.rustPlatform.buildRustPackage {
        pname = "xmsg-shared-client-baseline";
        version = "0.1.0";
        src = baselineSrc;
        cargoLock.lockFile = "${baselineSrc}/Cargo.lock";
        postPatch = ''
          substituteInPlace src/main.rs --replace-fail \
            '    version,' '    version = "0.1.0+${pin.revision}",'
        '';
        doCheck = false;
        meta.mainProgram = "xmsg";
      };
      clientArgs = {
        pname = "xmsg-client-tests";
        version = "0.1.0";
        src = package.src;
        strictDeps = true;
        CARGO_PROFILE = "release";
        cargoExtraArgs = "--no-default-features --features client";
        __darwinAllowLocalNetworking = true;
      };
      # The self-dev-dependency mutant intentionally enables daemon. Retain both
      # dependency graphs so no arm pays for a cold daemon build.
      clientArtifacts = craneLib.buildDepsOnly (
        clientArgs // { cargoArtifacts = inputs.xmsg.packages.${system}.cargoArtifacts; }
      );
    in
    {
      checks = {
        shared-client = craneLib.cargoTest (
          clientArgs
          // {
            cargoArtifacts = clientArtifacts;
            nativeBuildInputs = [ pkgs.python3 ];
            cargoTestExtraArgs = "--lib --test shared_client";
            preCheck = ''
              python3 scripts/client-graph.py
            '';
            postCheck = ''
              set -o pipefail
              cargoWithProfile test --locked --no-default-features --features client --test shared_client \
                2>&1 | tee client-completion.log
              grep -F 'test result: ok. 19 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out' client-completion.log
              cargoWithProfile test --locked --no-default-features --features client --lib \
                client::health::tests -- --nocapture 2>&1 | tee health.log
              grep -F 'test result: ok. 3 passed; 0 failed; 0 ignored; 0 measured;' health.log
              cargoWithProfile test --locked --no-default-features --features client --lib \
                client::feature_tests::no_daemon -- --ignored --exact 2>&1 | tee feature.log
              grep -F '1 passed; 0 failed; 0 ignored' feature.log
              python3 scripts/client-mutants.py | tee client-mutants.log
              grep -Fx '25/25 shared-client mutants killed' client-mutants.log
              python3 -c 'import runpy; runpy.run_path("scripts/client-mutants.py")["require_cached_builds"]("client-mutants.log", 46)'
            '';
          }
        );
      }
      // lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
        shared-client-compat = package.overrideAttrs {
          pname = "xmsg-shared-client-compat";
          dontBuild = true;
          installPhase = ''
            touch "$out"
          '';
          XMSG_SHARED_BASELINE_BIN = lib.getExe baseline;
          nativeBuildInputs = (package.nativeBuildInputs or [ ]) ++ [ pkgs.python3 ];
          checkPhase = ''
            runHook preCheck
            set -o pipefail
            cargoWithProfile test --locked --test shared_client_live \
              pinned_and_candidate_service_contract -- --ignored --exact --nocapture 2>&1 | tee compat.log
            grep -F '1 passed; 0 failed; 0 ignored' compat.log
            grep -F 'shared-client: verified baseline and candidate service contract completed' compat.log
            if grep -Eqi 'skipping|0 passed|1 ignored' compat.log; then
              echo 'shared-client live compatibility was skipped' >&2
              exit 1
            fi
            set +e
            XMSG_SHARED_BASELINE_BIN=/nonexistent/required-xmsg-baseline \
              cargoWithProfile test --locked --test shared_client_live \
                pinned_and_candidate_service_contract -- --ignored --exact > missing.log 2>&1
            missing_rc=$?
            set -e
            if [ "$missing_rc" -eq 0 ]; then
              echo 'missing baseline executable was accepted' >&2
              exit 1
            fi
            grep -F 'test pinned_and_candidate_service_contract ... FAILED' missing.log
            python3 scripts/client-mutants.py --live | tee live-mutants.log
            grep -Fx '13/13 shared-client mutants killed' live-mutants.log
            python3 -c 'import runpy; runpy.run_path("scripts/client-mutants.py")["require_cached_builds"]("live-mutants.log", 26)'
            runHook postCheck
          '';
        };
      };
    };
}
