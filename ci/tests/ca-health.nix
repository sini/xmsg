{ inputs, ... }:
{
  perSystem =
    {
      pkgs,
      system,
      config,
      ...
    }:
    let
      package = inputs.xmsg.packages.${system}.default;
    in
    {
      checks.ca-health = package.overrideAttrs {
        pname = "xmsg-ca-health-source-faults";
        CARGO_PROFILE = "dev";
        cargoArtifacts = config.checks.tests.cargoArtifacts;
        dontBuild = true;
        doCheck = true;
        preCheck = "";
        nativeBuildInputs = (package.nativeBuildInputs or [ ]) ++ [ pkgs.python3 ];
        checkPhase = ''
          runHook preCheck
          set -o pipefail
          python3 scripts/ca-health-mutants.py | tee ca-health-mutants.log
          runHook postCheck
        '';
        installPhase = ''
          mkdir -p "$out"
          cp ca-health-mutants.log "$out/"
          cp -r .artifacts/ca-health-mutants "$out/mutants"
        '';
      };
    };
}
