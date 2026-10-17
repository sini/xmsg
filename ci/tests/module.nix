# The flake modules (homeManagerModules.xmsg, nixosModules.xmsg), evaluated against
# home-manager at nix-config's pin. Cells are evaluations; `peers-render` builds.
{ lib, inputs, ... }:
let
  inherit (inputs)
    xmsg
    home-manager
    nixpkgs
    hermes-agent
    ;

  # home-manager's own evaluation (its modules/default.nix) without the wrapper that throws
  # on a failed assertion, so a cell can read `assertions` as data.
  hmEval =
    system: extra:
    let
      pkgs = nixpkgs.legacyPackages.${system};
      hmLib = import "${home-manager}/modules/lib/stdlib-extended.nix" nixpkgs.lib;
    in
    (hmLib.evalModules {
      class = "homeManager";
      specialArgs.modulesPath = "${home-manager}/modules";
      modules =
        import "${home-manager}/modules/modules.nix" {
          inherit pkgs;
          lib = hmLib;
          check = true;
        }
        ++ [
          xmsg.homeManagerModules.xmsg
          hermes-agent.homeManagerModules.default
          (
            { pkgs, ... }:
            {
              home = {
                username = "alice";
                homeDirectory = if pkgs.stdenv.hostPlatform.isDarwin then "/Users/alice" else "/home/alice";
                stateVersion = "25.11";
                enableNixpkgsReleaseCheck = false;
              };
              programs.claude-code = {
                enable = true;
                package = null;
              };
              # Evaluated, never built: the anchor only needs a store path.
              programs.antigravity-cli = {
                enable = true;
                package = pkgs.runCommand "antigravity-cli-fixture" { } "mkdir -p $out/bin; touch $out/bin/agy";
              };
              services.hermes-agent.enable = true;
              programs.xmsg = {
                enable = true;
                harnesses = {
                  claude.enable = true;
                  agy.enable = true;
                  pi.enable = true;
                  opencode.enable = true;
                  hermes.enable = true;
                };
                server = {
                  httpSocket = "/run/user/1000/xmsg/http.sock";
                  svcExe.my-bot = "/opt/my-bot/bin/my-bot";
                  federation = {
                    enable = true;
                    port = 7790;
                    cert = "/run/secrets/xmsg.crt";
                    key = "/run/secrets/xmsg.key";
                    reloadInterval = 60;
                    peers.cortex = {
                      address = "cortex.example.org:7790";
                      pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
                      allow = [ "send" ];
                    };
                  };
                };
              };
            }
          )
          extra
        ];
    }).config;

  # The fixture's literal-pin peer, rendered as the loader reads it.
  pinLiteralPeers = nixpkgs.legacyPackages.x86_64-linux.writeText "xmsg-peers.json" (
    builtins.toJSON {
      cortex = {
        address = "cortex.example.org:7790";
        pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        allow = [ "send" ];
      };
    }
  );

  failedAssertions = cfg: map (a: a.message) (lib.filter (a: !a.assertion) cfg.assertions);

  # The failed assertions of the fixture with one more peer, `bad`.
  badPeer =
    peer:
    failedAssertions (hmEval "x86_64-linux" { programs.xmsg.server.federation.peers.bad = peer; });
  badMsg = m: [ "programs.xmsg.server.federation.peers.bad: ${m}" ];
  caPeer = {
    address = "bad.example.org:7790";
    ca = "/run/secrets/xmsg-root.crt";
  };

  # Whether `fed.key` set to `key` passes its type: the refusal is a throw, read as data.
  keyAccepted =
    key:
    let
      c = hmEval "x86_64-linux" { programs.xmsg.server.federation.key = lib.mkForce key; };
    in
    (builtins.tryEval (builtins.deepSeq c.programs.xmsg.server.federation.key true)).success;

  linux = hmEval "x86_64-linux" { };
  exe = lib.getExe xmsg.packages.x86_64-linux.default;
  agyAnchor = "${linux.programs.antigravity-cli.package}/bin/agy";
  file = cfg: name: cfg.home.file.${name};

  darwinCells =
    system:
    let
      c = hmEval system { };
    in
    {
      expr = {
        launchd = c.launchd.agents.xmsg.enable or false;
        launchdArgs = lib.take 2 (c.launchd.agents.xmsg.config.ProgramArguments or [ ]);
        systemd = c.systemd.user.services ? xmsg;
        failed = failedAssertions c;
      };
      expected = {
        launchd = true;
        launchdArgs = [
          (lib.getExe xmsg.packages.${system}.default)
          "serve"
        ];
        systemd = false;
        failed = [ ];
      };
    };

  nixosPorts =
    enable:
    (nixpkgs.lib.nixosSystem {
      system = "x86_64-linux";
      modules = [
        xmsg.nixosModules.xmsg
        {
          programs.xmsg.federation = {
            inherit enable;
            port = 7790;
          };
        }
      ];
    }).config.networking.firewall.allowedTCPPorts;
in
{
  flake.tests.module = {
    # Oracle 1: the Linux unit, restart triggers, startServices warning, and each harness's pieces.
    test-linux-unit = {
      expr = {
        exec = linux.systemd.user.services.xmsg.Service.ExecStart;
        triggers = linux.systemd.user.services.xmsg.Unit.X-Restart-Triggers;
        warnSuggest = (hmEval "x86_64-linux" { systemd.user.startServices = "suggest"; }).warnings;
        warnSdSwitch = (hmEval "x86_64-linux" { systemd.user.startServices = "sd-switch"; }).warnings;
        launchd = linux.launchd.agents ? xmsg;
        failed = failedAssertions linux;
      };
      expected = {
        exec = [
          "${exe} serve --http-sock /run/user/1000/xmsg/http.sock --agy-exe ${agyAnchor} --svc-exe 'my-bot=/opt/my-bot/bin/my-bot' --fed-listen 0.0.0.0:7790 --fed-cert /run/secrets/xmsg.crt --fed-key /run/secrets/xmsg.key --peers-file ${pinLiteralPeers} --fed-reload-interval-secs 60"
        ];
        triggers = [
          "${xmsg.packages.x86_64-linux.default}"
          "${pinLiteralPeers}"
        ];
        warnSuggest = [
          "programs.xmsg.server.enable: systemd.user.startServices is not \"sd-switch\", so a home-manager switch will not restart xmsg.service."
        ];
        warnSdSwitch = [ ];
        launchd = false;
        failed = [ ];
      };
    };
    test-claude = {
      expr = {
        mcp = linux.programs.claude-code.mcpServers.xmsg;
        skill = linux.programs.claude-code.skills.xmsg;
        allow = linux.programs.claude-code.settings.permissions.allow;
        allowPluginOnly =
          (hmEval "x86_64-linux" {
            programs.xmsg.harnesses.claude.permissionPrefixes = [ "mcp__plugin_hm_xmsg" ];
          }).programs.claude-code.settings.permissions.allow;
      };
      expected = {
        mcp = {
          type = "stdio";
          command = exe;
          args = [ "mcp" ];
          env = { };
        };
        skill = ../../nix/modules/skills/xmsg;
        allow = [
          "mcp__plugin_hm_xmsg__list"
          "mcp__plugin_hm_xmsg__send"
          "mcp__plugin_hm_xmsg__reply"
          "mcp__plugin_hm_xmsg__replies"
          "mcp__xmsg__list"
          "mcp__xmsg__send"
          "mcp__xmsg__reply"
          "mcp__xmsg__replies"
        ];
        allowPluginOnly = [
          "mcp__plugin_hm_xmsg__list"
          "mcp__plugin_hm_xmsg__send"
          "mcp__plugin_hm_xmsg__reply"
          "mcp__plugin_hm_xmsg__replies"
        ];
      };
    };
    test-agy = {
      expr = {
        mcp = linux.programs.antigravity-cli.mcpServers.xmsg;
        skill = linux.programs.antigravity-cli.skills.xmsg;
        # `.source` is a writeText derivation; its `text` attribute is the file, read without IFD.
        hooks = builtins.fromJSON (
          builtins.unsafeDiscardStringContext (file linux ".gemini/config/hooks.json").source.text
        );
        hooksCustomLabel = builtins.fromJSON (
          builtins.unsafeDiscardStringContext
            (file (hmEval "x86_64-linux" {
              programs.xmsg.harnesses.agy.label = "work";
            }) ".gemini/config/hooks.json").source.text
        );
      };
      expected = {
        mcp = {
          command = exe;
          args = [ "mcp" ];
        };
        skill = ../../nix/modules/skills/xmsg;
        hooks.xmsg-register.PreInvocation = [
          {
            type = "command";
            command = "${exe} register agy --hook";
          }
        ];
        hooksCustomLabel.xmsg-register.PreInvocation = [
          {
            type = "command";
            command = "${exe} register agy --hook --label work";
          }
        ];
      };
    };
    test-pi = {
      expr = {
        extension = builtins.readFile (file linux ".pi/agent/extensions/xmsg-pi.ts").source;
        skill = builtins.readFile (file linux ".pi/agent/skills/xmsg/SKILL.md").source;
      };
      expected = {
        extension = builtins.readFile ../../extensions/pi/index.ts;
        skill = builtins.readFile ../../nix/modules/skills/xmsg/SKILL.md;
      };
    };
    # XH2 oracle 12 + XH1.1: the opencode switch writes the plugin and the skill, no opencode.json,
    # orders legacy store-symlink cleanup before `linkGeneration`, and keeps `programs.opencode` off.
    test-opencode = {
      expr = {
        plugin = builtins.readFile linux.xdg.configFile."opencode/plugin/xmsg.ts".source;
        skill = builtins.readFile linux.xdg.configFile."opencode/skills/xmsg/SKILL.md".source;
        opencodeJson = linux.xdg.configFile ? "opencode/opencode.json";
        programsOpencode = linux.programs.opencode.enable;
        cleanupBefore = linux.home.activation.xmsgCleanupLegacyOpencodeSkill.before;
      };
      expected = {
        plugin = builtins.readFile ../../extensions/opencode/xmsg.ts;
        skill = builtins.readFile ../../nix/modules/skills/xmsg/SKILL.md;
        opencodeJson = false;
        programsOpencode = false;
        cleanupBefore = [ "linkGeneration" ];
      };
    };
    # XH3: the hermes switch adds its plugin (linked as `nix-managed-xmsg`), enables it by its
    # manifest name, allows injection on the TUI and desktop host, and installs the skill.
    test-hermes = {
      expr = {
        plugins = map lib.getName linux.services.hermes-agent.extraPlugins;
        settings = linux.services.hermes-agent.settings.plugins;
        skill = linux.services.hermes-agent.hermesHomeFiles."skills/xmsg/SKILL.md";
      };
      expected = {
        plugins = [ "xmsg" ];
        settings = {
          enabled = [ "xmsg" ];
          entries.xmsg.allow_gateway_injection = true;
        };
        skill = ../../nix/modules/skills/xmsg + "/SKILL.md";
      };
    };

    # hermes's `settings` merge replaces a list (lib.recursiveUpdate), so the switch's
    # `plugins.enabled` joins the user's own entries rather than dropping them; a user list
    # ordered after the switch's would drop `xmsg`, and is refused naming it.
    test-hermes-enabled-joins = {
      expr =
        let
          c = hmEval "x86_64-linux" { services.hermes-agent.settings.plugins.enabled = [ "foo" ]; };
        in
        {
          enabled = c.services.hermes-agent.settings.plugins.enabled;
          failed = failedAssertions c;
        };
      expected = {
        enabled = [
          "foo"
          "xmsg"
        ];
        failed = [ ];
      };
    };
    test-hermes-enabled-lost = {
      expr = failedAssertions (
        hmEval "x86_64-linux" {
          services.hermes-agent.settings = lib.mkOrder 2000 { plugins.enabled = [ "foo" ]; };
        }
      );
      expected = [
        "programs.xmsg.harnesses.hermes.enable: services.hermes-agent.settings.plugins.enabled lost [\"xmsg\"]. hermes merges `settings` by lib.recursiveUpdate, which replaces a list, and a definition ordered after the switch's (lib.mkAfter) replaced its list; define that one without the later order."
      ];
    };

    # Oracle 7: the installed skill teaches A13's four tools, A12's labels and the error
    # vocabulary, and the http.sock limits (A15, HA2); nothing of the retired surface or of an
    # owner's hosts. `builtins.split` searches without a `.*` regex over the file.
    test-skill =
      let
        text = builtins.readFile "${linux.programs.claude-code.skills.xmsg}/SKILL.md";
        has = t: builtins.length (builtins.split (lib.escapeRegex t) text) > 1;
      in
      {
        expr = {
          missing = lib.filter (t: !has t) [
            "`list`"
            "`send`"
            "`reply`"
            "`replies`"
            "label · id@node"
            "id~n@node"
            "`delivered`"
            "`queued`"
            "`not_found`"
            "`ambiguous`"
            "`unavailable`"
            "`denied`"
            "`gone`"
            "`bad_request`"
            "http.sock"
            "<from> · anon@node"
            "opencode or hermes process"
          ];
          present = lib.filter has [
            "svc:"
            "/v1/sessions"
            "bitstream"
            "cortex"
            "json64"
          ];
        };
        expected = {
          missing = [ ];
          present = [ ];
        };
      };

    # C3: the module owns hooks.json. A second `.text` is refused by assertion; a second
    # `.source` conflicts in the option's merge (a throw, read as data).
    test-agy-hooks-owned = {
      expr = {
        text = failedAssertions (
          hmEval "x86_64-linux" { home.file.".gemini/config/hooks.json".text = "{}"; }
        );
        source =
          (builtins.tryEval (
            builtins.deepSeq (toString
              (hmEval "x86_64-linux" { home.file.".gemini/config/hooks.json".source = ./fixtures/peer.crt; })
              .home.file.".gemini/config/hooks.json".source
            ) true
          )).success;
      };
      expected = {
        text = [
          "programs.xmsg.harnesses.agy.enable owns ~/.gemini/config/hooks.json; remove the other home.file.\".gemini/config/hooks.json\".text definition."
        ];
        source = false;
      };
    };

    # C4: `fed.key` is a runtime path; a store path is refused.
    test-fed-key-not-store = {
      expr = {
        interpolated = keyAccepted "${./fixtures/peer.crt}";
        storeString = keyAccepted "${builtins.storeDir}/0000000000000000000000000000000-k";
        runtime = keyAccepted "/run/secrets/k";
      };
      expected = {
        interpolated = false;
        storeString = false;
        runtime = true;
      };
    };

    # C5: the loader's peer rules, refused at evaluation (src/fed.rs).
    test-peer-ca-needs-identities = {
      expr = badPeer caPeer;
      expected = badMsg "ca needs identities.";
    };
    test-peer-identities-not-with-pin = {
      expr = badPeer {
        address = "bad.example.org:7790";
        pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        identities = [ "spiffe://example.org/host/bad/user/alice" ];
      };
      expected = badMsg "identities is only valid with ca, not with pin or pinFromCert.";
    };
    test-peer-identities-exactly-one = {
      expr = badPeer (
        caPeer
        // {
          identities = [
            "spiffe://example.org/host/bad/user/alice"
            "spiffe://example.org/host/bad/user/bob"
          ];
        }
      );
      expected = badMsg "identities holds exactly one identity.";
    };
    test-peer-from-nonempty = {
      expr = badPeer {
        address = "bad.example.org:7790";
        pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        from = [ ];
      };
      expected = badMsg "from must hold at least one CIDR, or be null.";
    };

    # D19 (and XH3 oracle 7): a switch whose harness module is off is refused, naming the option.
    test-switch-needs-harness = {
      expr = failedAssertions (
        hmEval "x86_64-linux" {
          programs.claude-code.enable = lib.mkForce false;
          programs.antigravity-cli.enable = lib.mkForce false;
          services.hermes-agent.enable = lib.mkForce false;
        }
      );
      expected = [
        "programs.xmsg.harnesses.claude.enable needs programs.claude-code.enable = true."
        "programs.xmsg.harnesses.agy.enable needs programs.antigravity-cli.enable = true."
        "programs.xmsg.harnesses.hermes.enable needs services.hermes-agent.enable = true."
      ];
    };

    # Oracle 3: darwin has the launchd agent and no systemd unit (evaluation only).
    # aarch64 only: nixpkgs 26.11 has dropped x86_64-darwin.
    test-darwin-aarch64 = darwinCells "aarch64-darwin";

    # Oracle 4: the NixOS module opens the port only with federation on.
    test-nixos-port = {
      expr = {
        on = lib.elem 7790 (nixosPorts true);
        off = lib.elem 7790 (nixosPorts false);
      };
      expected = {
        on = true;
        off = false;
      };
    };
  };
}
