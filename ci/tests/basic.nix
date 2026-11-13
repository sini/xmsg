{ lib, inputs, ... }:
{
  flake.tests.basic = {
    test-meta-description = {
      expr = inputs.xmsg.packages.x86_64-linux.default.meta.description;
      expected = "Fast, lightweight local HTTP bridge into live agent sessions";
    };

    test-compat-checks-retain-historical-sources =
      let
        pkgs = inputs.nixpkgs.legacyPackages.x86_64-linux;
        pin = builtins.fromTOML (builtins.readFile ../xmsg-pin.toml);
        baselineSrc = import ../xmsg-source.nix { inherit pkgs pin; };
        preXl1Src = pkgs.fetchFromGitHub {
          owner = "sini";
          repo = "xmsg";
          rev = "909619979ce2669ed2051a08d2f587d60b1f0d21";
          hash = "sha256-JGE3MFESq632euR3kWgONgv9P9VO9fuZTHgIJ+NP7uk=";
        };
        preDeploySrc = pkgs.fetchFromGitHub {
          owner = "sini";
          repo = "xmsg";
          rev = "9d1f5fa38356a8f9208594db951c8e6502fe8e5d";
          hash = "sha256-NcY8mUx9lfZopi+Ti3vOLumH8m9yWlPhTpDCQLr3ckU=";
        };
        preCodexSrc = pkgs.fetchFromGitHub {
          owner = "sini";
          repo = "xmsg";
          rev = "09af11ba76a6545aa1b26992550e8e706f965564";
          hash = "sha256-7OTL8xTXc8Bj9Db/+IIOvFp/8+Dtj0k8zXXN+FLlOyg=";
        };
        preXl1Install = builtins.unsafeDiscardStringContext inputs.self.checks.x86_64-linux.pre-xl1-compat.installPhase;
        sharedCompatInstall = builtins.unsafeDiscardStringContext inputs.self.checks.x86_64-linux.shared-client-compat-0.installPhase;
      in
      {
        expr = {
          preXl1Src = lib.hasInfix (builtins.unsafeDiscardStringContext "${preXl1Src}") preXl1Install;
          preDeploySrc = lib.hasInfix (builtins.unsafeDiscardStringContext "${preDeploySrc}") preXl1Install;
          preCodexSrc = lib.hasInfix (builtins.unsafeDiscardStringContext "${preCodexSrc}") preXl1Install;
          baselineSrc = lib.hasInfix (builtins.unsafeDiscardStringContext "${baselineSrc}") sharedCompatInstall;
        };
        expected = {
          preXl1Src = true;
          preDeploySrc = true;
          preCodexSrc = true;
          baselineSrc = true;
        };
      };
  };
}
