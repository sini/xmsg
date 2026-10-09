{
  description = "xmsg: Fast, lightweight local HTTP bridge into live agent sessions";

  inputs.nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";

  outputs =
    { self, nixpkgs }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = f: nixpkgs.lib.genAttrs systems (system: f nixpkgs.legacyPackages.${system});
    in
    {
      packages = forAllSystems (pkgs: {
        default = pkgs.rustPlatform.buildRustPackage {
          pname = "xmsg";
          version = "0.1.0";
          src = nixpkgs.lib.cleanSourceWith {
            src = ./.;
            filter =
              path: type:
              let
                base = baseNameOf path;
              in
              !(
                base == "nix"
                || base == "docs"
                || base == "ci"
                || base == ".github"
                || base == "README.md"
                || base == "TODO.md"
                || base == "LICENSE"
                || nixpkgs.lib.hasSuffix ".nix" base
              );
          };
          cargoLock.lockFile = ./Cargo.lock;
          doCheck = true;
          # The tests bind loopback sockets, which the darwin sandbox refuses.
          __darwinAllowLocalNetworking = true;
          meta = {
            description = "Fast, lightweight local HTTP bridge into live agent sessions";
            mainProgram = "xmsg";
            license = nixpkgs.lib.licenses.mit;
          };
        };

        image = pkgs.dockerTools.buildLayeredImage {
          name = "ghcr.io/sini/xmsg";
          tag = "latest";
          contents = [
            pkgs.cacert
            self.packages.${pkgs.system}.default
          ];
          extraCommands = ''
            mkdir -p -m 1777 tmp
            mkdir -p -m 0755 var/lib/xmsg
          '';
          config = {
            User = "10001:10001";
            Entrypoint = [ "${self.packages.${pkgs.system}.default}/bin/xmsg" ];
            Cmd = [ "serve" ];
            WorkingDir = "/var/lib/xmsg";
            Env = [
              "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
            ];
          };
        };
      });

      checks = forAllSystems (
        pkgs:
        nixpkgs.lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
          image =
            pkgs.runCommand "check-image-oracle"
              {
                nativeBuildInputs = [ pkgs.python3 ];
              }
              ''
                python3 ${./nix/check_image.py} ${self.packages.${pkgs.system}.image}
                touch $out
              '';
        }
      );

      devShells = forAllSystems (pkgs: {
        default = pkgs.mkShell {
          packages = [
            pkgs.cargo
            pkgs.rustc
            pkgs.clippy
            pkgs.rustfmt
            pkgs.rust-analyzer
          ];
        };
      });
    };
}
