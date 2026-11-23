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
              programs.codex = {
                enable = true;
                package = pkgs.runCommand "codex-fixture" { } "mkdir -p $out/bin; touch $out/bin/codex";
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
                  codex.enable = true;
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
  codexAnchor = "${linux.programs.codex.package}/bin/codex";
  file = cfg: name: cfg.home.file.${name};

  darwinCells =
    system:
    let
      c = hmEval system { };
      darwinExe = lib.getExe xmsg.packages.${system}.default;
    in
    {
      expr = {
        launchd = c.launchd.agents.xmsg.enable or false;
        launchdArgs = lib.take 2 (c.launchd.agents.xmsg.config.ProgramArguments or [ ]);
        nullArgs =
          lib.take 1
            (hmEval system { programs.xmsg.server.stableExecutable = null; })
            .launchd.agents.xmsg.config.ProgramArguments;
        install = {
          inherit (c.home.activation.xmsgInstallStableExe) after before;
          # Context discarded: hasInfix builds a regex, which refuses a store path.
          copiesExe = lib.hasInfix "install -m 0755 ${builtins.unsafeDiscardStringContext darwinExe} " (
            builtins.unsafeDiscardStringContext c.home.activation.xmsgInstallStableExe.data
          );
          # `mv -T` is GNU-only: the rename must name coreutils, never BSD /bin/mv.
          gnuMv = lib.hasInfix "run ${builtins.unsafeDiscardStringContext nixpkgs.legacyPackages.${system}.coreutils}/bin/mv -fT " (
            builtins.unsafeDiscardStringContext c.home.activation.xmsgInstallStableExe.data
          );
        };
        restart = {
          inherit (c.home.activation.xmsgRestartStableExe) after;
          kicks = lib.hasInfix "kickstart -k \"gui/$UID/org.nix-community.home.xmsg\"" c.home.activation.xmsgRestartStableExe.data;
        };
        nullActivation = lib.attrNames (
          lib.filterAttrs (n: _: lib.hasPrefix "xmsg" n && lib.hasSuffix "StableExe" n)
            (hmEval system { programs.xmsg.server.stableExecutable = null; }).home.activation
        );
        codexCollision = failedAssertions (
          hmEval system {
            programs.xmsg.server.stableExecutable = "/Users/alice/.local/share/xmsg/bin/xmsg";
          }
        );
        logs = {
          inherit (c.launchd.agents.xmsg.config) StandardOutPath StandardErrorPath Umask;
          dir = c.home.activation.xmsgLogDir;
        };
        badPaths =
          map (p: failedAssertions (hmEval system { programs.xmsg.server.stableExecutable = p; }))
            [
              "xmsg/serve/xmsg"
              "${builtins.storeDir}/x-xmsg/bin/xmsg"
            ];
        systemd = c.systemd.user.services ? xmsg;
        failed = failedAssertions c;
      };
      expected = {
        launchd = true;
        logs = {
          StandardOutPath = "/Users/alice/Library/Logs/xmsg/stdout.log";
          StandardErrorPath = "/Users/alice/Library/Logs/xmsg/stderr.log";
          Umask = 63;
          dir = {
            after = [ "writeBoundary" ];
            before = [ "setupLaunchAgents" ];
            data = "run mkdir -p -m 0700 /Users/alice/Library/Logs/xmsg";
          };
        };
        launchdArgs = [
          "/Users/alice/.local/share/xmsg/serve/xmsg"
          "serve"
        ];
        nullArgs = [ darwinExe ];
        install = {
          after = [ "writeBoundary" ];
          before = [ "setupLaunchAgents" ];
          copiesExe = true;
          gnuMv = true;
        };
        restart = {
          after = [ "setupLaunchAgents" ];
          kicks = true;
        };
        nullActivation = [ ];
        codexCollision = [
          "programs.xmsg.server.stableExecutable: /Users/alice/.local/share/xmsg/bin/xmsg is the Codex harness's store link; pick another path."
        ];
        badPaths = [
          [ "programs.xmsg.server.stableExecutable: xmsg/serve/xmsg is not an absolute path." ]
          [
            "programs.xmsg.server.stableExecutable: ${builtins.storeDir}/x-xmsg/bin/xmsg is in the Nix store; it must be a mutable path."
          ]
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

  # programs.xmsg.server.sockets.dir: the fixture with every consumer a socket pin reaches (the
  # activity hook and one exec service on), and the same fixture pinned.
  pinFixture = {
    programs.xmsg = {
      activity.enable = true;
      server.execServices.quota.command = "/opt/quota/bin/quota";
    };
  };
  pinDir = "/run/user/1000/xmsg-sockets";
  pinnedEval =
    system:
    hmEval system {
      imports = [ pinFixture ];
      programs.xmsg.server = {
        sockets.dir = pinDir;
        httpSocket = lib.mkForce null;
      };
    };
  pin = {
    http = "${pinDir}/http.sock";
    agent = "${pinDir}/agent.sock";
    register = "${pinDir}/register.sock";
  };
  pinEnv = {
    XMSG_HTTP_SOCK = pin.http;
    XMSG_AGENT_SOCK = pin.agent;
    XMSG_REGISTER_SOCK = pin.register;
  };

  # Every surface a socket pin can reach, store paths replaced by placeholders (`@xmsg@` for
  # the xmsg package) so a render compares across source and lock revisions. A plugin installed as the shipped file reads "static".
  pinSurface =
    system: c:
    let
      pkg = "${xmsg.packages.${system}.default}";
      darwin = lib.hasSuffix "darwin" system;
      fileOr = shipped: src: if toString src == toString shipped then "static" else src.text; # writeText, no IFD
      surface = {
        serve =
          if darwin then
            c.launchd.agents.xmsg.config.ProgramArguments
          else
            c.systemd.user.services.xmsg.Service.ExecStart;
        mcp = {
          claude = c.programs.claude-code.mcpServers.xmsg;
          agy = c.programs.antigravity-cli.mcpServers.xmsg;
          codex = c.programs.codex.settings.mcp_servers.xmsg;
        };
        claudeHooks = c.programs.claude-code.settings.hooks;
        agyHooks = builtins.fromJSON (
          builtins.unsafeDiscardStringContext c.home.file.".gemini/config/hooks.json".source.text
        );
        codexHooks = c.programs.xmsg.harnesses.codex.hooks;
        exec =
          if darwin then
            c.launchd.agents.quota.config.EnvironmentVariables or null
          else
            c.systemd.user.services.quota.Service.Environment or null;
        session = c.home.sessionVariables;
        userManager = c.systemd.user.sessionVariables;
        pi = fileOr ../../extensions/pi/index.ts c.home.file.".pi/agent/extensions/xmsg-pi.ts".source;
        opencode =
          fileOr ../../extensions/opencode/xmsg.ts
            c.xdg.configFile."opencode/plugin/xmsg.ts".source;
        hermes = c.services.hermes-agent.environment;
      };
    in
    builtins.fromJSON (
      lib.concatMapStrings (part: if builtins.isList part then "@store@-" else part) (
        builtins.split "${builtins.storeDir}/[0-9a-z]{32}-" (
          builtins.unsafeDiscardStringContext (
            builtins.replaceStrings [ pkg ] [ "@xmsg@" ] (builtins.toJSON surface)
          )
        )
      )
    );
  # Every hook `command` string in a hooks attrset, in order.
  commandsIn =
    v:
    if builtins.isAttrs v then
      lib.optional (v ? command) v.command
      ++ lib.concatMap commandsIn (lib.attrValues (removeAttrs v [ "command" ]))
    else if builtins.isList v then
      lib.concatMap commandsIn v
    else
      [ ];

  # P1: per system, the unset surface (also checked against the pre-change render) and the
  # pinned one; a pinned consumer must equal its unset render plus exactly its pins.
  pinCells =
    f:
    lib.genAttrs [ "x86_64-linux" "aarch64-darwin" ] (
      system:
      f {
        inherit system;
        unset = pinSurface system (hmEval system pinFixture);
        set = pinSurface system (pinnedEval system);
      }
    );
  pinCell = f: {
    expr = pinCells (x: (f x).expr);
    expected = pinCells (x: (f x).expected);
  };
  # The suffix each pinned hook command gains.
  hookCell =
    infix: suffix:
    pinCell (
      { unset, set, ... }:
      let
        pick = field: lib.filter (lib.hasInfix infix) (commandsIn field);
      in
      {
        expr = map pick [
          set.claudeHooks
          set.agyHooks
          set.codexHooks
        ];
        expected = map (h: map (c: c + suffix) (pick h)) [
          unset.claudeHooks
          unset.agyHooks
          unset.codexHooks
        ];
      }
    );
  prelude =
    "// programs.xmsg.server.sockets.dir\n"
    + "process.env.XMSG_AGENT_SOCK ??= \"${pin.agent}\";\n"
    + "process.env.XMSG_HTTP_SOCK ??= \"${pin.http}\";\n"
    + "process.env.XMSG_REGISTER_SOCK ??= \"${pin.register}\";\n";
  # P2: the failed assertions of the pinned fixture with `dir`, on `system`.
  pinFailures =
    system: dir: extra:
    failedAssertions (
      hmEval system {
        imports = [ extra ];
        programs.xmsg.server = {
          sockets.dir = dir;
          httpSocket = lib.mkForce null;
        };
      }
    );
  # A directory whose `/register.sock` (14 bytes) totals `n` bytes.
  dirOfLength = n: "/" + lib.concatStrings (lib.replicate (n - 15) "a");
in
{
  flake.tests.module = {
    test-linux-unit = {
      expr = {
        exec = linux.systemd.user.services.xmsg.Service.ExecStart;
        triggers = linux.systemd.user.services.xmsg.Unit.X-Restart-Triggers;
        warnSuggest = (hmEval "x86_64-linux" { systemd.user.startServices = "suggest"; }).warnings;
        warnSdSwitch = (hmEval "x86_64-linux" { systemd.user.startServices = "sd-switch"; }).warnings;
        launchd = linux.launchd.agents ? xmsg;
        darwinOnlyActivation = lib.filter (n: lib.hasSuffix "StableExe" n || n == "xmsgLogDir") (
          lib.attrNames linux.home.activation
        );
        failed = failedAssertions linux;
      };
      expected = {
        exec = [
          "${exe} serve --http-sock /run/user/1000/xmsg/http.sock --agy-exe ${agyAnchor} --codex-exe ${codexAnchor} --codex-home /home/alice/.codex --svc-exe 'my-bot=/opt/my-bot/bin/my-bot' --fed-listen 0.0.0.0:7790 --fed-cert /run/secrets/xmsg.crt --fed-key /run/secrets/xmsg.key --peers-file ${pinLiteralPeers} --fed-reload-interval-secs 60"
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
        darwinOnlyActivation = [ ];
        failed = [ ];
      };
    };
    # XH3: safe hardening subset for systemd --user (no CLONE_NEWUSER / CLONE_NEWNS).
    test-linux-unit-hardening = {
      expr = {
        inherit (linux.systemd.user.services.xmsg.Service)
          NoNewPrivileges
          LockPersonality
          RestrictRealtime
          RestrictSUIDSGID
          SystemCallArchitectures
          RestrictAddressFamilies
          UMask
          ;
        hasProtectSystem = linux.systemd.user.services.xmsg.Service ? ProtectSystem;
        hasPrivateUsers = linux.systemd.user.services.xmsg.Service ? PrivateUsers;
      };
      expected = {
        NoNewPrivileges = true;
        LockPersonality = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
          "AF_NETLINK"
        ];
        UMask = "0077";
        hasProtectSystem = false;
        hasPrivateUsers = false;
      };
    };
    # XS1: sessionsDirs and extraSessionsDirs render XMSG_SESSIONS_DIR on the serve unit
    # only when the effective list differs from the default.
    test-sessions-dirs =
      let
        linuxEnv =
          srv:
          (hmEval "x86_64-linux" {
            programs.xmsg.server = srv;
          }).systemd.user.services.xmsg.Service.Environment or null;
        darwinEnv =
          srv:
          (hmEval "aarch64-darwin" {
            programs.xmsg.server = srv;
          }).launchd.agents.xmsg.config.EnvironmentVariables or null;
      in
      {
        expr = {
          defaultLinux = linuxEnv { };
          defaultDarwin = darwinEnv { };
          extraLinux = linuxEnv {
            extraSessionsDirs = [
              "/var/lib/genie-agent/claude-public/sessions"
              "/var/lib/genie-agent/claude-trusted/sessions"
            ];
          };
          extraDarwin = darwinEnv {
            extraSessionsDirs = [ "/var/lib/genie-agent/claude-public/sessions" ];
          };
          overrideLinux = linuxEnv {
            sessionsDirs = [ "/custom/sessions" ];
          };
          overrideDarwin = darwinEnv {
            sessionsDirs = [ "/custom/sessions" ];
          };
        };
        expected = {
          defaultLinux = [ ];
          defaultDarwin = null;
          extraLinux = [
            "XMSG_SESSIONS_DIR=/home/alice/.claude/sessions:/var/lib/genie-agent/claude-public/sessions:/var/lib/genie-agent/claude-trusted/sessions"
          ];
          extraDarwin = {
            XMSG_SESSIONS_DIR = "/Users/alice/.claude/sessions:/var/lib/genie-agent/claude-public/sessions";
          };
          overrideLinux = [
            "XMSG_SESSIONS_DIR=/custom/sessions"
          ];
          overrideDarwin = {
            XMSG_SESSIONS_DIR = "/custom/sessions";
          };
        };
      };
    test-claude =
      let
        claudeHook = [
          {
            type = "command";
            command = "${exe} register claude --hook";
          }
        ];
      in
      {
        expr = {
          mcp = linux.programs.claude-code.mcpServers.xmsg;
          skill = linux.programs.claude-code.skills.xmsg;
          allow = linux.programs.claude-code.settings.permissions.allow;
          hooks = linux.programs.claude-code.settings.hooks;
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
          skill = ../../assets/claude/xmsg;
          allow = [
            "mcp__plugin_hm_xmsg__list"
            "mcp__plugin_hm_xmsg__send"
            "mcp__plugin_hm_xmsg__reply"
            "mcp__plugin_hm_xmsg__replies"
            "mcp__plugin_hm_xmsg__inbox"
            "mcp__xmsg__list"
            "mcp__xmsg__send"
            "mcp__xmsg__reply"
            "mcp__xmsg__replies"
            "mcp__xmsg__inbox"
          ];
          hooks = {
            PreToolUse = [
              {
                matcher = "^mcp__plugin_hm_xmsg__(send|reply|inbox|list|replies)$";
                hooks = claudeHook;
              }
              {
                matcher = "^mcp__xmsg__(send|reply|inbox|list|replies)$";
                hooks = claudeHook;
              }
            ];
            PostToolUse = [
              {
                matcher = "^(Agent|SendMessage)$";
                hooks = claudeHook;
              }
            ];
            SubagentStart = [ { hooks = claudeHook; } ];
            SubagentStop = [ { hooks = claudeHook; } ];
          };
          allowPluginOnly = [
            "mcp__plugin_hm_xmsg__list"
            "mcp__plugin_hm_xmsg__send"
            "mcp__plugin_hm_xmsg__reply"
            "mcp__plugin_hm_xmsg__replies"
            "mcp__plugin_hm_xmsg__inbox"
          ];
        };
      };

    test-claude-canonical-skill-destination =
      let
        destination = "${linux.home.homeDirectory}/.claude/skills/xmsg";
        canonical = ../../assets/claude/xmsg;
        installed = linux.home.file.${destination};
      in
      {
        expr = {
          sameDestination = builtins.hasAttr destination linux.home.file;
          sameCanonicalSource = toString installed.source == toString canonical;
          sameCanonicalBytes =
            builtins.readFile "${installed.source}/SKILL.md" == builtins.readFile "${canonical}/SKILL.md";
          sameOption = linux.programs.claude-code.skills.xmsg == canonical;
        };
        expected = {
          sameDestination = true;
          sameCanonicalSource = true;
          sameCanonicalBytes = true;
          sameOption = true;
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
        skill = ../../assets/claude/xmsg;
        hooks.xmsg-register = {
          PreInvocation = [
            {
              type = "command";
              command = "${exe} register agy --hook --event pre-invocation";
            }
          ];
          PreToolUse = [
            {
              matcher = "call_mcp_tool|mcp_xmsg_.*";
              hooks = [
                {
                  type = "command";
                  command = "${exe} register agy --hook --event pre-tool-use";
                  timeout = 5;
                }
              ];
            }
          ];
          Stop = [
            {
              type = "command";
              command = "${exe} register agy --hook --event stop";
              timeout = 5;
            }
          ];
        };
        hooksCustomLabel.xmsg-register = {
          PreInvocation = [
            {
              type = "command";
              command = "${exe} register agy --hook --event pre-invocation --label work";
            }
          ];
          PreToolUse = [
            {
              matcher = "call_mcp_tool|mcp_xmsg_.*";
              hooks = [
                {
                  type = "command";
                  command = "${exe} register agy --hook --event pre-tool-use";
                  timeout = 5;
                }
              ];
            }
          ];
          Stop = [
            {
              type = "command";
              command = "${exe} register agy --hook --event stop";
              timeout = 5;
            }
          ];
        };
      };
    };
    test-pi = {
      expr = {
        extension = builtins.readFile (file linux ".pi/agent/extensions/xmsg-pi.ts").source;
        skill = builtins.readFile (file linux ".pi/agent/skills/xmsg/SKILL.md").source;
      };
      expected = {
        extension = builtins.readFile ../../extensions/pi/index.ts;
        skill = builtins.readFile ../../assets/claude/xmsg/SKILL.md;
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
        skill = builtins.readFile ../../assets/claude/xmsg/SKILL.md;
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
        skill = ../../assets/claude/xmsg + "/SKILL.md";
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

    # HA9-A.codex (C2, C8, C11): the Codex switch configures MCP (with XDG_RUNTIME_DIR and
    # default_tools_approval_mode), skill, stable xdg.dataFile."xmsg/bin/xmsg", read-only
    # hooks in Claude shape, and server --codex-exe / --codex-home.
    test-codex =
      let
        stableCmd = ev: "/home/alice/.local/share/xmsg/bin/xmsg register codex --hook --event ${ev}";
        mkEventGroup = ev: timeout: [
          {
            hooks = [
              {
                type = "command";
                command = stableCmd ev;
                inherit timeout;
              }
            ];
          }
        ];
        guardHooks = {
          SessionStart = [
            {
              hooks = [
                {
                  type = "command";
                  command = "/nix/store/guard/bin/codex-guard";
                  timeout = 5;
                }
              ];
            }
          ];
        };
        foldHooks =
          a: b:
          lib.zipAttrsWith (_: lists: lib.concatLists lists) [
            a
            b
          ];
        foldedEnabled = foldHooks guardHooks linux.programs.xmsg.harnesses.codex.hooks;
        disabledCfg = hmEval "x86_64-linux" { programs.xmsg.harnesses.codex.enable = lib.mkForce false; };
        foldedDisabled = foldHooks guardHooks disabledCfg.programs.xmsg.harnesses.codex.hooks;
        retargetedCfg = hmEval "x86_64-linux" {
          programs.xmsg.package = nixpkgs.legacyPackages.x86_64-linux.runCommand "xmsg-retargeted" {
            meta.mainProgram = "xmsg";
          } "mkdir -p $out/bin; touch $out/bin/xmsg";
        };
      in
      {
        expr = {
          mcp = linux.programs.codex.settings.mcp_servers.xmsg;
          mcpOption = linux.programs.xmsg.harnesses.codex.mcpServer;
          skill = linux.programs.codex.skills.xmsg;
          stableBin = linux.xdg.dataFile."xmsg/bin/xmsg".source;
          hooks = linux.programs.xmsg.harnesses.codex.hooks;
          hooksWhenDisabled = disabledCfg.programs.xmsg.harnesses.codex.hooks;
          hooksWhenXmsgDisabled =
            (hmEval "x86_64-linux" { programs.xmsg.enable = lib.mkForce false; })
            .programs.xmsg.harnesses.codex.hooks;
          guardFirstInSessionStart = map (g: (lib.head g.hooks).command) foldedEnabled.SessionStart;
          foldedWhenDisabled = foldedDisabled;
          retargetedHooksEqual =
            retargetedCfg.programs.xmsg.harnesses.codex.hooks == linux.programs.xmsg.harnesses.codex.hooks;
          hasPreToolUse = linux.programs.xmsg.harnesses.codex.hooks ? PreToolUse;
          noHooksJsonHomeFile = linux.home.file ? ".codex/hooks.json";
          configTomlRespectsLensDisable =
            (hmEval "x86_64-linux" {
              home.file.".codex/config.toml".enable = lib.mkForce false;
            }).home.file.".codex/config.toml".enable;
          noCodexSystemdUnit = linux.systemd.user.services ? codex;
          darwinAccepted =
            let
              d = hmEval "aarch64-darwin" {
                programs.xmsg.harnesses.codex.enable = lib.mkForce true;
              };
              progArgs = d.launchd.agents.xmsg.config.ProgramArguments or [ ];
              codexAnchorDarwin = "${d.programs.codex.package}/bin/codex";
            in
            {
              failed = failedAssertions d;
              hasCodexExe = lib.elem "--codex-exe" progArgs && lib.elem codexAnchorDarwin progArgs;
              hasCodexHome = lib.elem "--codex-home" progArgs && lib.elem "/Users/alice/.codex" progArgs;
            };
        };
        expected = {
          mcp = {
            command = exe;
            args = [ "mcp" ];
            env_vars = [ "XDG_RUNTIME_DIR" ];
            default_tools_approval_mode = "approve";
          };
          mcpOption = {
            command = exe;
            args = [ "mcp" ];
            env_vars = [ "XDG_RUNTIME_DIR" ];
            default_tools_approval_mode = "approve";
          };
          skill = ../../assets/claude/xmsg;
          stableBin = exe;
          hooks = {
            SessionStart = mkEventGroup "SessionStart" 5;
            UserPromptSubmit = mkEventGroup "UserPromptSubmit" 5;
            PreModelRequest = mkEventGroup "PreModelRequest" 5;
            SubagentStart = mkEventGroup "SubagentStart" 5;
            SubagentStop = mkEventGroup "SubagentStop" 5;
            Stop = mkEventGroup "Stop" 5;
            SessionEnd = mkEventGroup "SessionEnd" 1;
          };
          hooksWhenDisabled = { };
          hooksWhenXmsgDisabled = { };
          guardFirstInSessionStart = [
            "/nix/store/guard/bin/codex-guard"
            (stableCmd "SessionStart")
          ];
          foldedWhenDisabled = guardHooks;
          retargetedHooksEqual = true;
          hasPreToolUse = false;
          noHooksJsonHomeFile = false;
          configTomlRespectsLensDisable = false;
          noCodexSystemdUnit = false;
          darwinAccepted = {
            failed = [ ];
            hasCodexExe = true;
            hasCodexHome = true;
          };
        };
      };

    # HA9-A.codex (C8): pure-Nix trustState parity against R §10 vectors, normalization,
    # group reordering, package retargeting, and fail-closed validation throws.
    test-codex-trust-state =
      let
        inherit (linux.programs.xmsg.harnesses.codex) trustState;
        throws = v: !(builtins.tryEval (builtins.deepSeq v true)).success;
        r10Probe = trustState "/tmp/ha9-trust-ui-home-if3mo0m6/hooks.json" {
          PreToolUse = [
            {
              matcher = "Bash";
              hooks = [
                {
                  type = "command";
                  command = "sh /tmp/ha9-followup/hash-script-command.sh";
                  commandWindows = "echo WINDOWS_OVERRIDE";
                  timeout = 0;
                  async = false;
                  additionalContextLimit = 2500;
                }
              ];
            }
          ];
        };
        r10Norm = trustState "/tmp/ha9-trust-ui-home-if3mo0m6/hooks.json" {
          SessionEnd = [
            {
              matcher = "other";
              hooks = [
                {
                  type = "command";
                  command = "printf '%s\\n' 'café'";
                  timeout = 99;
                  async = true;
                  statusMessage = "finishing café";
                  additionalContextLimit = 123;
                }
              ];
            }
          ];
        };
        stopMatcherIgnored = trustState "/home/alice/.codex/hooks.json" {
          Stop = [
            {
              matcher = "ignored-on-stop";
              hooks = [
                {
                  type = "command";
                  command = "/bin/stop";
                  timeout = 5;
                }
              ];
            }
            {
              hooks = [
                {
                  type = "command";
                  command = "/bin/stop";
                  timeout = 5;
                }
              ];
            }
          ];
        };
        orderA = trustState "/home/alice/.codex/hooks.json" {
          SessionStart = [
            {
              hooks = [
                {
                  type = "command";
                  command = "/bin/guard";
                  timeout = 5;
                }
              ];
            }
            {
              hooks = [
                {
                  type = "command";
                  command = "/bin/xmsg";
                  timeout = 5;
                }
              ];
            }
          ];
        };
        orderB = trustState "/home/alice/.codex/hooks.json" {
          SessionStart = [
            {
              hooks = [
                {
                  type = "command";
                  command = "/bin/xmsg";
                  timeout = 5;
                }
              ];
            }
            {
              hooks = [
                {
                  type = "command";
                  command = "/bin/guard";
                  timeout = 5;
                }
              ];
            }
          ];
        };
        endClamp = trustState "/home/alice/.codex/hooks.json" {
          SessionEnd = [
            {
              hooks = [
                {
                  type = "command";
                  command = "/bin/end";
                  timeout = 10;
                }
              ];
            }
            {
              hooks = [
                {
                  type = "command";
                  command = "/bin/end";
                  timeout = 3;
                }
              ];
            }
          ];
        };
      in
      {
        expr = {
          r10ProbeHash =
            r10Probe.hooks.state."/tmp/ha9-trust-ui-home-if3mo0m6/hooks.json:pre_tool_use:0:0".trusted_hash;
          r10NormHash =
            r10Norm.hooks.state."/tmp/ha9-trust-ui-home-if3mo0m6/hooks.json:session_end:0:0".trusted_hash;
          stopIgnoresMatcher =
            stopMatcherIgnored.hooks.state."/home/alice/.codex/hooks.json:stop:0:0".trusted_hash
            == stopMatcherIgnored.hooks.state."/home/alice/.codex/hooks.json:stop:1:0".trusted_hash;
          reorderSwapsGroupHashes =
            orderA.hooks.state."/home/alice/.codex/hooks.json:session_start:0:0".trusted_hash
            == orderB.hooks.state."/home/alice/.codex/hooks.json:session_start:1:0".trusted_hash
            &&
              orderA.hooks.state."/home/alice/.codex/hooks.json:session_start:0:0".trusted_hash
              != orderB.hooks.state."/home/alice/.codex/hooks.json:session_start:0:0".trusted_hash;
          sessionEndClampedTo3 =
            endClamp.hooks.state."/home/alice/.codex/hooks.json:session_end:0:0".trusted_hash
            == endClamp.hooks.state."/home/alice/.codex/hooks.json:session_end:1:0".trusted_hash;
          rejectsRelativeHooksPath = throws (
            trustState "hooks.json" {
              Stop = [
                {
                  hooks = [
                    {
                      type = "command";
                      command = "/bin/true";
                    }
                  ];
                }
              ];
            }
          );
          rejectsNonCommandHandler = throws (
            trustState "/home/alice/.codex/hooks.json" {
              Stop = [
                {
                  hooks = [
                    {
                      type = "prompt";
                      prompt = "hi";
                    }
                  ];
                }
              ];
            }
          );
          rejectsNegativeTimeout = throws (
            trustState "/home/alice/.codex/hooks.json" {
              Stop = [
                {
                  hooks = [
                    {
                      type = "command";
                      command = "/bin/true";
                      timeout = -1;
                    }
                  ];
                }
              ];
            }
          );
          rejectsDuplicateWinKeys = throws (
            trustState "/home/alice/.codex/hooks.json" {
              Stop = [
                {
                  hooks = [
                    {
                      type = "command";
                      command = "/bin/true";
                      commandWindows = "cmd";
                      command_windows = "cmd";
                    }
                  ];
                }
              ];
            }
          );
        };
        expected = {
          r10ProbeHash = "sha256:bfe666789cdad46e7049f1189e3ffc663fdf259b2104651c8c7e0644a7827e90";
          r10NormHash = "sha256:8993e3888afd211af4b1cc5c57ec4f93a20e92912f4b6727ae8cb107238a1661";
          stopIgnoresMatcher = true;
          reorderSwapsGroupHashes = true;
          sessionEndClampedTo3 = true;
          rejectsRelativeHooksPath = true;
          rejectsNonCommandHandler = true;
          rejectsNegativeTimeout = true;
          rejectsDuplicateWinKeys = true;
        };
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
            "`inbox`"
            "label · id@node"
            "id~n@node"
            "id/child@node"
            "<P>/<child>@<node>"
            "to=<P>/<child> agent_id=<id>"
            "Claude Code"
            "Codex"
            "opencode 1.x and 2.x"
            "Antigravity"
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
    test-peer-observe-labels-needs-observe = {
      expr = badPeer {
        address = "bad.example.org:7790";
        pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        allow = [ "list" ];
        observeLabels = true;
      };
      expected = badMsg "observeLabels requires \"observe\" in allow.";
    };
    test-peer-observe-labels =
      let
        c = hmEval "x86_64-linux" {
          programs.xmsg.server.federation.peers = {
            collector = {
              address = "collector.example.org:7788";
              pin = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
              allow = [ "observe" ];
              observeLabels = true;
            };
            quiet = {
              address = "quiet.example.org:7788";
              pin = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
              allow = [ "observe" ];
            };
          };
        };
        expectedPeers = nixpkgs.legacyPackages.x86_64-linux.writeText "xmsg-peers.json" (
          builtins.toJSON {
            collector = {
              address = "collector.example.org:7788";
              allow = [ "observe" ];
              observe_labels = true;
              pin = "sha256:1111111111111111111111111111111111111111111111111111111111111111";
            };
            cortex = {
              address = "cortex.example.org:7790";
              allow = [ "send" ];
              pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
            };
            quiet = {
              address = "quiet.example.org:7788";
              allow = [ "observe" ];
              pin = "sha256:2222222222222222222222222222222222222222222222222222222222222222";
            };
          }
        );
      in
      {
        expr = {
          failed = failedAssertions c;
          hasPeersFile = lib.hasInfix "--peers-file ${builtins.unsafeDiscardStringContext expectedPeers}" (
            builtins.unsafeDiscardStringContext (lib.head c.systemd.user.services.xmsg.Service.ExecStart)
          );
        };
        expected = {
          failed = [ ];
          hasPeersFile = true;
        };
      };
    # An omitted address renders no `address` key; the loader decides whether omission is valid.
    test-peer-address-optional =
      let
        c = hmEval "x86_64-linux" {
          programs.xmsg.server.federation.peers.laptop = {
            pin = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
            allow = [ "send" ];
          };
        };
        expectedPeers = nixpkgs.legacyPackages.x86_64-linux.writeText "xmsg-peers.json" (
          builtins.toJSON {
            cortex = {
              address = "cortex.example.org:7790";
              allow = [ "send" ];
              pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
            };
            laptop = {
              allow = [ "send" ];
              pin = "sha256:3333333333333333333333333333333333333333333333333333333333333333";
            };
          }
        );
      in
      {
        expr = {
          failed = failedAssertions c;
          peersFile = "${c.programs.xmsg.server.federation.peersFile}";
        };
        expected = {
          failed = [ ];
          peersFile = "${expectedPeers}";
        };
      };
    test-observe-collector =
      let
        ocCfg = {
          client_cert = "/run/xmsg-observer/client.pem";
          client_key = "/run/xmsg-observer/client.key";
          auth = {
            issuer = "https://idp.example.org/oauth2/openid/observer";
            introspection_url = "https://idp.example.org/oauth2/token/introspect";
            subjects = [ "owner-subject" ];
            audience = "observer";
            hosted_client = "observer";
            lookup_client = "observer-lookup";
            lookup_secret_file = "/run/xmsg-observer/lookup-secret";
          };
          web_tls = {
            cert = "/run/xmsg-observer/server.pem";
            key = "/run/xmsg-observer/server.key";
          };
          sources = [
            {
              node = "cortex.example.org";
              address = "cortex.example.org:7788";
            }
          ];
        };
        linuxOc = hmEval "x86_64-linux" {
          programs.xmsg.observeCollector = {
            enable = true;
            config = ocCfg;
            stateDir = "/var/lib/xmsg/collector";
          };
        };
        linuxConfigFile = nixpkgs.legacyPackages.x86_64-linux.writeText "xmsg-observe-collector.json" (
          builtins.toJSON ocCfg
        );
        darwinOc = hmEval "aarch64-darwin" {
          programs.xmsg.observeCollector = {
            enable = true;
            config = ocCfg;
          };
        };
        darwinExe = lib.getExe xmsg.packages.aarch64-darwin.default;
        darwinConfigFile = nixpkgs.legacyPackages.aarch64-darwin.writeText "xmsg-observe-collector.json" (
          builtins.toJSON ocCfg
        );
      in
      {
        expr = {
          defaultOff = {
            linux = linux.systemd.user.services ? xmsg-observe-collector;
            darwin = (hmEval "aarch64-darwin" { }).launchd.agents ? xmsg-observe-collector;
          };
          linux = {
            exec = linuxOc.systemd.user.services.xmsg-observe-collector.Service.ExecStart;
            triggers = linuxOc.systemd.user.services.xmsg-observe-collector.Unit.X-Restart-Triggers;
            restart = linuxOc.systemd.user.services.xmsg-observe-collector.Service.Restart;
            umask = linuxOc.systemd.user.services.xmsg-observe-collector.Service.UMask;
            wantedBy = linuxOc.systemd.user.services.xmsg-observe-collector.Install.WantedBy;
            launchd = linuxOc.launchd.agents ? xmsg-observe-collector;
            failed = failedAssertions linuxOc;
          };
          darwin = {
            enable = darwinOc.launchd.agents.xmsg-observe-collector.enable;
            args = darwinOc.launchd.agents.xmsg-observe-collector.config.ProgramArguments;
            stdout = darwinOc.launchd.agents.xmsg-observe-collector.config.StandardOutPath;
            stderr = darwinOc.launchd.agents.xmsg-observe-collector.config.StandardErrorPath;
            umask = darwinOc.launchd.agents.xmsg-observe-collector.config.Umask;
            systemd = darwinOc.systemd.user.services ? xmsg-observe-collector;
            failed = failedAssertions darwinOc;
          };
        };
        expected = {
          defaultOff = {
            linux = false;
            darwin = false;
          };
          linux = {
            exec = [
              "${exe} observe-collector --config ${linuxConfigFile} --state-dir /var/lib/xmsg/collector"
            ];
            triggers = [
              "${xmsg.packages.x86_64-linux.default}"
              "${linuxConfigFile}"
            ];
            restart = "on-failure";
            umask = "0077";
            wantedBy = [ "default.target" ];
            launchd = false;
            failed = [ ];
          };
          darwin = {
            enable = true;
            args = [
              darwinExe
              "observe-collector"
              "--config"
              "${darwinConfigFile}"
              "--state-dir"
              "/Users/alice/.local/state/xmsg/observe-collector"
            ];
            stdout = "/Users/alice/Library/Logs/xmsg/observe-collector-stdout.log";
            stderr = "/Users/alice/Library/Logs/xmsg/observe-collector-stderr.log";
            umask = 63;
            systemd = false;
            failed = [ ];
          };
        };
      };
    test-observe-collector-no-secrets = {
      expr = {
        inlineKey = failedAssertions (
          hmEval "x86_64-linux" {
            programs.xmsg.observeCollector = {
              enable = true;
              config = {
                client_cert = "/run/xmsg-observer/client.pem";
                client_key = "-----BEGIN PRIVATE KEY-----\nCANARY_KEY";
              };
            };
          }
        );
        inlineCert = failedAssertions (
          hmEval "x86_64-linux" {
            programs.xmsg.observeCollector = {
              enable = true;
              config = {
                client_cert = "-----BEGIN CERTIFICATE-----\nCANARY_CERT";
                client_key = "/run/xmsg-observer/client.key";
              };
            };
          }
        );
        inlineSecret = failedAssertions (
          hmEval "x86_64-linux" {
            programs.xmsg.observeCollector = {
              enable = true;
              config = {
                client_cert = "/run/xmsg-observer/client.pem";
                client_key = "/run/xmsg-observer/client.key";
                auth.lookup_secret = "CANARY_SECRET";
              };
            };
          }
        );
      };
      expected = {
        inlineKey = [
          "programs.xmsg.observeCollector.config.client_key: must be a runtime file path, never a Nix store path or inline key/cert material."
        ];
        inlineCert = [
          "programs.xmsg.observeCollector.config.client_cert: must be a file path, never inline certificate material."
        ];
        inlineSecret = [
          "programs.xmsg.observeCollector.config.auth: must reference secrets by runtime file path (lookup_secret_file), never inline secret values."
        ];
      };
    };

    # Public certificates may be store paths (as federation.cert and peers.*.ca); private
    # keys and secrets stay runtime paths.
    test-observe-collector-public-certs =
      let
        storeCert = builtins.toFile "client.pem" "public";
        collector =
          config:
          failedAssertions (
            hmEval "x86_64-linux" {
              programs.xmsg.observeCollector = {
                enable = true;
                config = {
                  client_cert = "/run/xmsg-observer/client.pem";
                  client_key = "/run/xmsg-observer/client.key";
                }
                // config;
              };
            }
          );
        refused = field: [
          "programs.xmsg.observeCollector.config.${field}: must be a runtime file path, never a Nix store path or inline key/cert material."
        ];
      in
      {
        expr = {
          storeCerts = collector {
            client_cert = storeCert;
            web_tls = {
              cert = "${builtins.storeDir}/xxx-web.pem";
              key = "/run/xmsg-observer/web.key";
            };
          };
          storeClientKey = collector { client_key = storeCert; };
          storeWebKey = collector {
            web_tls = {
              cert = "/run/xmsg-observer/web.pem";
              key = "${builtins.storeDir}/xxx-web.key";
            };
          };
          storeLookupSecret = collector { auth.lookup_secret_file = storeCert; };
        };
        expected = {
          storeCerts = [ ];
          storeClientKey = refused "client_key";
          storeWebKey = refused "web_tls.key";
          storeLookupSecret = refused "auth.lookup_secret_file";
        };
      };

    # The rendered peers file, read-only, is the one `--peers-file` names.
    test-federation-peers-file = {
      expr = "${linux.programs.xmsg.server.federation.peersFile}";
      expected = "${pinLiteralPeers}";
    };

    # execServices: one entry admits xmsg's own executable under its name and runs
    # `xmsg service exec` as a user service on each platform.
    test-exec-services =
      let
        entry = {
          programs.xmsg.server.execServices = {
            quota = {
              command = "/opt/quota/bin/quota";
              args = [ "--json" ];
              environment.QUOTA_MODE = "read-only";
            };
            off = {
              enable = false;
              command = "/opt/off/bin/off";
            };
          };
        };
        l = hmEval "x86_64-linux" entry;
        d = hmEval "aarch64-darwin" entry;
        darwinExe = lib.getExe xmsg.packages.aarch64-darwin.default;
      in
      {
        expr = {
          svcExe = l.programs.xmsg.server.svcExe;
          exec = l.systemd.user.services.quota.Service.ExecStart;
          inherit (l.systemd.user.services.quota.Service) Restart RestartSec Environment;
          inherit (l.systemd.user.services.quota.Unit) After;
          wantedBy = l.systemd.user.services.quota.Install.WantedBy;
          linuxOff = l.systemd.user.services ? off;
          linuxLaunchd = l.launchd.agents ? quota;
          darwinArgs = d.launchd.agents.quota.config.ProgramArguments;
          darwinEnv = d.launchd.agents.quota.config.EnvironmentVariables;
          darwinSvcExe = d.programs.xmsg.server.svcExe.quota;
          darwinOff = d.launchd.agents ? off;
          darwinSystemd = d.systemd.user.services ? quota;
          failed = failedAssertions l ++ failedAssertions d;
        };
        expected = {
          svcExe = {
            my-bot = "/opt/my-bot/bin/my-bot";
            quota = exe;
          };
          exec = [ "${exe} service exec --name quota -- /opt/quota/bin/quota --json" ];
          Restart = "on-failure";
          RestartSec = 10;
          Environment = [ "QUOTA_MODE=read-only" ];
          After = [ "xmsg.service" ];
          wantedBy = [ "default.target" ];
          linuxOff = false;
          linuxLaunchd = false;
          darwinArgs = [
            darwinExe
            "service"
            "exec"
            "--name"
            "quota"
            "--"
            "/opt/quota/bin/quota"
            "--json"
          ];
          darwinEnv.QUOTA_MODE = "read-only";
          darwinSvcExe = darwinExe;
          darwinOff = false;
          darwinSystemd = false;
          failed = [ ];
        };
      };

    # D19 (and XH3 oracle 7): a switch whose harness module is off is refused, naming the option.
    test-switch-needs-harness = {
      expr = failedAssertions (
        hmEval "x86_64-linux" {
          programs.claude-code.enable = lib.mkForce false;
          programs.antigravity-cli.enable = lib.mkForce false;
          services.hermes-agent.enable = lib.mkForce false;
          programs.codex.enable = lib.mkForce false;
        }
      );
      expected = [
        "programs.xmsg.harnesses.claude.enable needs programs.claude-code.enable = true."
        "programs.xmsg.harnesses.agy.enable needs programs.antigravity-cli.enable = true."
        "programs.xmsg.harnesses.hermes.enable needs services.hermes-agent.enable = true."
        "programs.xmsg.harnesses.codex.enable needs programs.codex.enable = true."
      ];
    };

    # Oracle 3: darwin has the launchd agent and no systemd unit (evaluation only).
    # aarch64 only: nixpkgs 26.11 has dropped x86_64-darwin.
    test-darwin-aarch64 = darwinCells "aarch64-darwin";

    # P1 (programs.xmsg.server.sockets.dir unset): every pin surface equals the render before the
    # option existed, recorded from that revision in fixtures/sockets-dir-unset-*.json.
    test-sockets-dir-unset = {
      expr = pinCells ({ unset, ... }: unset);
      expected = {
        x86_64-linux = lib.importJSON ./fixtures/sockets-dir-unset-linux.json;
        aarch64-darwin = lib.importJSON ./fixtures/sockets-dir-unset-darwin.json;
      };
    };
    # P1, M-P1-serve: the daemon binds the three pins.
    test-sockets-dir-serve = pinCell (
      {
        system,
        unset,
        set,
      }:
      {
        expr = set.serve;
        expected =
          if system == "aarch64-darwin" then
            lib.concatMap (
              a:
              if a == "/run/user/1000/xmsg/http.sock" then
                [
                  pin.http
                  "--agent-sock"
                  pin.agent
                  "--register-sock"
                  pin.register
                ]
              else
                [ a ]
            ) unset.serve
          else
            map (lib.replaceStrings
              [ "--http-sock /run/user/1000/xmsg/http.sock " ]
              [ "--http-sock ${pin.http} --agent-sock ${pin.agent} --register-sock ${pin.register} " ]
            ) unset.serve;
      }
    );
    # P1, M-P1-mcp: every MCP entry (claude, agy, codex) passes the agent and http pins.
    test-sockets-dir-mcp = pinCell (
      { unset, set, ... }:
      {
        expr = set.mcp;
        expected = lib.mapAttrs (
          _: e:
          e
          // {
            args = e.args ++ [
              "--agent-sock"
              pin.agent
              "--http-sock"
              pin.http
            ];
          }
        ) unset.mcp;
      }
    );
    # P1, M-P1-claude-hook / M-P1-activity / M-P1-agy-hook / M-P1-codex-hook: each hook command
    # is its unset command plus its socket flags (lists: claude, agy, codex hooks).
    test-sockets-dir-claude-hook = hookCell "register claude" " --sock ${pin.agent}";
    test-sockets-dir-activity = hookCell "activity hook" " --sock ${pin.agent}";
    test-sockets-dir-agy-hook = hookCell "register agy" " --sock ${pin.register} --agent-sock ${pin.agent}";
    test-sockets-dir-codex-hook = hookCell "register codex" " --sock ${pin.agent}";
    # P1, M-P1-exec: an execServices unit (Linux) or agent (darwin) carries the three pins.
    test-sockets-dir-exec = pinCell (
      { system, set, ... }:
      {
        expr = set.exec;
        expected =
          if system == "aarch64-darwin" then pinEnv else lib.mapAttrsToList (k: v: "${k}=${v}") pinEnv;
      }
    );
    # P1, M-P1-session / M-P1-user-manager: login shells get the pins; the user manager does not.
    test-sockets-dir-session = pinCell (
      { unset, set, ... }:
      {
        expr = set.session;
        expected = unset.session // pinEnv;
      }
    );
    test-sockets-dir-user-manager = pinCell (
      { unset, set, ... }:
      {
        expr = set.userManager;
        expected = unset.userManager;
      }
    );
    # P1, M-P1-pi / M-P1-opencode / M-P1-hermes: each plugin's pin input. pi and opencode install
    # the shipped file behind a prelude that sets XMSG_*_SOCK unless set; hermes's .env carries them.
    test-sockets-dir-pi = pinCell (
      { set, ... }:
      {
        expr = set.pi;
        expected = prelude + builtins.readFile ../../extensions/pi/index.ts;
      }
    );
    test-sockets-dir-opencode = pinCell (
      { set, ... }:
      {
        expr = set.opencode;
        expected = prelude + builtins.readFile ../../extensions/opencode/xmsg.ts;
      }
    );
    test-sockets-dir-hermes = pinCell (
      { set, ... }:
      {
        expr = set.hermes;
        expected = pinEnv;
      }
    );
    # P2: a relative path, an over-budget register.sock and the httpSocket combination each fail
    # with their message; the largest path that fits evaluates (107 bytes Linux, 103 darwin).
    test-sockets-dir-assertions =
      let
        over =
          sys: n:
          "programs.xmsg.server.sockets.dir: ${dirOfLength n}/register.sock is ${toString n} bytes; a socket path on this platform holds at most ${toString (n - 1)}.";
      in
      {
        expr = {
          relative = pinFailures "x86_64-linux" "run/xmsg-sockets" { };
          linuxOver = pinFailures "x86_64-linux" (dirOfLength 108) { };
          linuxFits = pinFailures "x86_64-linux" (dirOfLength 107) { };
          darwinOver = pinFailures "aarch64-darwin" (dirOfLength 104) { };
          darwinFits = pinFailures "aarch64-darwin" (dirOfLength 103) { };
          withHttpSocket = pinFailures "x86_64-linux" pinDir {
            programs.xmsg.server.httpSocket = lib.mkOverride 10 "/run/user/1000/xmsg/http.sock";
          };
          pinnedFixture =
            failedAssertions (pinnedEval "x86_64-linux") ++ failedAssertions (pinnedEval "aarch64-darwin");
        };
        expected = {
          relative = [ "programs.xmsg.server.sockets.dir: run/xmsg-sockets is not an absolute path." ];
          linuxOver = [ (over "x86_64-linux" 108) ];
          linuxFits = [ ];
          darwinOver = [ (over "aarch64-darwin" 104) ];
          darwinFits = [ ];
          withHttpSocket = [
            "programs.xmsg.server.sockets.dir pins http.sock; unset programs.xmsg.server.httpSocket."
          ];
          pinnedFixture = [ ];
        };
      };

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
