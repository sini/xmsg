{ inputs, ... }:
{
  perSystem =
    { pkgs, system, ... }:
    let
      craneLib = inputs.crane.mkLib pkgs;
      package = inputs.xmsg.packages.${system}.default;
      args = {
        pname = "xmsg-ordinary-tests";
        version = package.version;
        src = package.src;
        strictDeps = true;
        CARGO_PROFILE = "dev";
        __darwinAllowLocalNetworking = true;
      };
      artifacts = craneLib.buildDepsOnly args;
    in
    {
      checks.tests =
        (craneLib.cargoTest (
          args
          // {
            cargoArtifacts = artifacts;
            nativeBuildInputs = [ pkgs.python3 ];
          }
        )).overrideAttrs
          {
            checkPhase = ''
              runHook preCheck
              set -o pipefail
              cargoWithProfile test --locked --color never 2>&1 | tee ordinary-tests.log
              python3 ${../checks/ordinary-counts.py} \
                --expected ${../ordinary-counts.json} \
                --platform ${if pkgs.stdenv.hostPlatform.isDarwin then "darwin" else "linux"} \
                ordinary-tests.log
              runHook postCheck
            '';
            installPhase = ''
              mkdir -p "$out"
              cp ordinary-tests.log "$out/"
            '';
          };
      checks.ordinary-counts =
        pkgs.runCommand "xmsg-ordinary-count-controls"
          {
            nativeBuildInputs = [ pkgs.python3 ];
          }
          ''
            cp ${../checks/ordinary-counts.py} ordinary-counts.py
            cp ${../checks/ordinary-counts-tests.py} ordinary-counts-tests.py
            python3 ordinary-counts-tests.py
            touch "$out"
          '';
    };
}
