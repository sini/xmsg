{ inputs, ... }:
{
  perSystem =
    { pkgs, system, ... }:
    let
      craneLib = inputs.crane.mkLib pkgs;
      package = inputs.xmsg.packages.${system}.default;
    in
    {
      checks.clippy = craneLib.cargoClippy {
        pname = "xmsg-clippy";
        version = package.version;
        src = package.src;
        strictDeps = true;
        CARGO_PROFILE = "release";
        cargoArtifacts = inputs.xmsg.packages.${system}.cargoArtifacts;
        cargoExtraArgs = "--locked";
        cargoClippyExtraArgs = "--all-targets -- -D warnings";
      };
    };
}
