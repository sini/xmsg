{
  inputs = {
    gen-harness.url = "github:sini/gen-harness";
    # ★ THE SUBJECT IS READ BY RELATIVE PATH, NEVER AS A `path:..` INPUT. Lix refuses a relative
    # `path` node in a lock ("mutable lock"), and a Lix-written `path:..?narHash=…` lock pins a stale
    # snapshot of the tree (den-hoag-lbtnv D1). So `outputs` below applies `../flake.nix`'s own
    # `outputs` to the `nixpkgs` declared here, line for line as `../flake.nix` declares it.
    nixpkgs.url = "https://channels.nixos.org/nixos-unstable/nixexprs.tar.xz";
    crane.url = "github:ipetkov/crane";
    # The flake modules are evaluated against home-manager at nix-config's pin (its
    # `home-manager-unstable` node), so a module change that nix-config cannot take reds here.
    home-manager = {
      url = "github:nix-community/home-manager/fae6e9e42c3b762ab47635cddcfaf6f52374a61b";
      inputs.nixpkgs.follows = "nixpkgs";
    };
    # The hermes switch and the hermes-plugin check run against hermes-agent at nix-config's pin
    # (its `hermes-agent` node). Its own lock is kept, so its package is nix-config's.
    hermes-agent.url = "github:NousResearch/hermes-agent/c538ec5f402e8078248becacd474e47a08c6e79a";
    # nixpkgs packages opencode 1.x only; the opencode2-plugin check runs llm-agents.nix's
    # opencode2 (2.x) and the codex-hook check runs llm-agents.nix's codex (0.166.0).
    # Its own lock is kept, so its packages are the ones llm-agents.nix publishes.
    llm-agents.url = "github:numtide/llm-agents.nix/a854ddf4456f5fd67474e2d844cb4a29c32702d0";
  };

  outputs =
    inputs@{
      gen-harness,
      nixpkgs,
      crane,
      ...
    }:
    let
      # The published surface of THIS tree.
      xmsg = (import ../flake.nix).outputs {
        inherit (inputs) self;
        inherit nixpkgs crane;
      };
    in
    gen-harness.lib.mkCi {
      inputs = inputs // {
        inherit xmsg;
      };
      name = "xmsg";
      testModules = ./tests;
      extraModules = [
        # xmsg is a TOOL, not an ecosystem library: it is absent from the register roster,
        # so its AGENTS.md is agent instructions rather than a capability sheet.
        { gen.ci.agentsMd.sheet = "instructions"; }
        # Nor a root library surface: there is no root default.nix.
        { gen.ci.rootSurface.entry = "not-owed"; }
        # Nor an evaluator matrix: its CI is one upstream-Nix column, not evaluators.yml.
        { gen.ci.evaluators = "not-owed"; }
        {
          gen.ci.examplesExcluded.docker = {
            row = "xmsg-fei.10";
            reason = "Docker/Compose runtime documentation, verified against the built image; no Nix example value to evaluate.";
          };
          gen.ci.examplesExcluded.helm = {
            row = "xmsg-fei.9";
            reason = "Helm/Kubernetes runtime example, verified with two federating releases; no Nix example value to evaluate.";
          };
        }
        # Surface package build in CI checks (doCheck = true runs cargo test)
        {
          perSystem =
            { pkgs, system, ... }:
            {
              checks.package = xmsg.packages.${system}.default;
            };
        }
      ];
    };
}
