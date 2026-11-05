# homeManagerModules.xmsg: the `xmsg serve` user service and the per-harness pieces
# (MCP entry, skill, agy hook, pi extension, opencode plugin, hermes plugin).
#
# `packages` is this flake's `packages` output, the default for `programs.xmsg.package`.
{ packages }:
{
  config,
  lib,
  options,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkEnableOption
    mkIf
    mkMerge
    mkOption
    types
    ;
  cfg = config.programs.xmsg;
  srv = cfg.server;
  fed = srv.federation;
  exe = lib.getExe cfg.package;
  skill = ./skills/xmsg;

  # The hermes plugin directory (plugin.yaml and __init__.py). `extraPlugins` links it as
  # `plugins/nix-managed-<name>`; hermes keys a plugin by its manifest name, `xmsg`.
  hermesPlugin = pkgs.runCommand "xmsg" { } ''
    mkdir $out
    cp ${../../extensions/hermes/plugin.yaml} $out/plugin.yaml
    cp ${../../extensions/hermes/__init__.py} $out/__init__.py
  '';

  # The MCP server every MCP harness runs: `xmsg mcp`, a stdio server.
  mcpEntry = {
    command = exe;
    args = [ "mcp" ];
  };

  codexMcpServer = mcpEntry // {
    env_vars = [ "XDG_RUNTIME_DIR" ];
    default_tools_approval_mode = "approve";
  };

  codexStableBin = "${config.xdg.dataHome}/xmsg/bin/xmsg";
  codexHookCmd = event: "${lib.escapeShellArg codexStableBin} register codex --hook --event ${event}";

  codexHooks = {
    SessionStart = [
      {
        hooks = [
          {
            type = "command";
            command = codexHookCmd "SessionStart";
            timeout = 5;
          }
        ];
      }
    ];
    UserPromptSubmit = [
      {
        hooks = [
          {
            type = "command";
            command = codexHookCmd "UserPromptSubmit";
            timeout = 5;
          }
        ];
      }
    ];
    PreModelRequest = [
      {
        hooks = [
          {
            type = "command";
            command = codexHookCmd "PreModelRequest";
            timeout = 5;
          }
        ];
      }
    ];
    SubagentStart = [
      {
        hooks = [
          {
            type = "command";
            command = codexHookCmd "SubagentStart";
            timeout = 5;
          }
        ];
      }
    ];
    SubagentStop = [
      {
        hooks = [
          {
            type = "command";
            command = codexHookCmd "SubagentStop";
            timeout = 5;
          }
        ];
      }
    ];
    Stop = [
      {
        hooks = [
          {
            type = "command";
            command = codexHookCmd "Stop";
            timeout = 5;
          }
        ];
      }
    ];
    SessionEnd = [
      {
        hooks = [
          {
            type = "command";
            command = codexHookCmd "SessionEnd";
            timeout = 1;
          }
        ];
      }
    ];
  };

  codexEventNames = {
    PreModelRequest = "pre_model_request";
    PostModelRequest = "post_model_request";
    PreToolUse = "pre_tool_use";
    PermissionRequest = "permission_request";
    PostToolUse = "post_tool_use";
    PreCompact = "pre_compact";
    PostCompact = "post_compact";
    SessionStart = "session_start";
    SessionEnd = "session_end";
    UserPromptSubmit = "user_prompt_submit";
    SubagentStart = "subagent_start";
    SubagentStop = "subagent_stop";
    Stop = "stop";
    Interrupt = "interrupt";
  };

  codexMatchedEvents = [
    "PreToolUse"
    "PermissionRequest"
    "PostToolUse"
    "PreCompact"
    "PostCompact"
    "SessionStart"
    "SessionEnd"
    "SubagentStart"
    "SubagentStop"
  ];

  codexAdditionalEvents = [
    "PreToolUse"
    "PostToolUse"
    "SessionStart"
    "UserPromptSubmit"
    "SubagentStart"
  ];

  normalizeCodexHookIdentity =
    event: group: handler:
    let
      _ =
        if !(codexEventNames ? ${event}) then
          throw "programs.xmsg.harnesses.codex.trustState: unknown Codex hook event '${event}'"
        else if (handler.type or null) != "command" then
          throw "programs.xmsg.harnesses.codex.trustState: only ordinary command hook declarations are supported"
        else if (handler ? commandWindows) && (handler ? command_windows) then
          throw "programs.xmsg.harnesses.codex.trustState: duplicate Windows command aliases"
        else
          true;
      rawCommand = handler.command or null;
      _cmdCheck =
        if !(builtins.isString rawCommand) || (lib.trim rawCommand) == "" then
          throw "programs.xmsg.harnesses.codex.trustState: command must be a non-empty string"
        else
          true;
      altWin = handler.commandWindows or (handler.command_windows or null);
      _winCheck =
        if altWin != null && !(builtins.isString altWin) then
          throw "programs.xmsg.harnesses.codex.trustState: commandWindows must be a string"
        else
          true;
      isEnd = event == "SessionEnd" || event == "Interrupt";
      rawTimeout = handler.timeout or null;
      _timeoutCheck =
        if rawTimeout != null && (!(builtins.isInt rawTimeout) || rawTimeout < 0) then
          throw "programs.xmsg.harnesses.codex.trustState: timeout must be a non-negative integer"
        else
          true;
      baseTimeout = if rawTimeout == null then (if isEnd then 1 else 600) else rawTimeout;
      minTimeout = lib.max 1 baseTimeout;
      timeout = if isEnd then lib.min 3 minTimeout else minTimeout;
      asynchronous = if (handler.async or null) == null then false else handler.async;
      _asyncCheck =
        if !(builtins.isBool asynchronous) then
          throw "programs.xmsg.harnesses.codex.trustState: async must be a boolean"
        else
          true;
      status = handler.statusMessage or null;
      _statusCheck =
        if status != null && !(builtins.isString status) then
          throw "programs.xmsg.harnesses.codex.trustState: statusMessage must be a string"
        else
          true;
      limit = handler.additionalContextLimit or null;
      _limitCheck =
        if limit != null && (!(builtins.isInt limit) || limit < 0) then
          throw "programs.xmsg.harnesses.codex.trustState: additionalContextLimit must be a non-negative integer"
        else
          true;
      matcher = group.matcher or null;
      _matcherCheck =
        if matcher != null && !(builtins.isString matcher) then
          throw "programs.xmsg.harnesses.codex.trustState: matcher must be a string"
        else
          true;
      normalizedHandler = {
        type = "command";
        command = rawCommand;
        inherit timeout;
        async = asynchronous;
      }
      // lib.optionalAttrs (status != null) { statusMessage = status; }
      // lib.optionalAttrs (limit != null && builtins.elem event codexAdditionalEvents && limit != 2500) {
        additionalContextLimit = limit;
      };
    in
    builtins.seq _ (
      builtins.seq _cmdCheck (
        builtins.seq _winCheck (
          builtins.seq _timeoutCheck (
            builtins.seq _asyncCheck (
              builtins.seq _statusCheck (
                builtins.seq _limitCheck (
                  builtins.seq _matcherCheck (
                    {
                      event_name = codexEventNames.${event};
                      hooks = [ normalizedHandler ];
                    }
                    // lib.optionalAttrs (matcher != null && builtins.elem event codexMatchedEvents) {
                      inherit matcher;
                    }
                  )
                )
              )
            )
          )
        )
      )
    );

  computeCodexTrustedHash =
    event: group: handler:
    "sha256:"
    + builtins.hashString "sha256" (builtins.toJSON (normalizeCodexHookIdentity event group handler));

  codexTrustState =
    hooksPath: finalHooks:
    let
      _pathCheck =
        if !(builtins.isString hooksPath) || !(lib.hasPrefix "/" hooksPath) then
          throw "programs.xmsg.harnesses.codex.trustState: hooksPath must be an absolute path string"
        else
          true;
      eventsMap =
        if
          finalHooks ? hooks && builtins.isAttrs finalHooks.hooks && !(builtins.isList finalHooks.hooks)
        then
          finalHooks.hooks
        else
          finalHooks;
    in
    builtins.seq _pathCheck {
      hooks.state = lib.listToAttrs (
        lib.concatLists (
          lib.concatLists (
            lib.mapAttrsToList (
              event: groups:
              lib.imap0 (
                groupIndex: group:
                lib.imap0 (
                  handlerIndex: handler:
                  lib.nameValuePair
                    "${hooksPath}:${codexEventNames.${event}}:${toString groupIndex}:${toString handlerIndex}"
                    { trusted_hash = computeCodexTrustedHash event group handler; }
                ) (group.hooks or [ ])
              ) groups
            ) eventsMap
          )
        )
      );
    };

  claudeTools = [
    "list"
    "send"
    "reply"
    "replies"
    "inbox"
  ];

  claudeHook = [
    {
      type = "command";
      command = "${exe} register claude --hook";
    }
  ];

  # Prior to XH2, opencode's skill was linked as the directory symlink
  # `$XDG_CONFIG_HOME/opencode/skills/xmsg -> /nix/store/...`. Now that `SKILL.md` is linked
  # inside it, `linkGeneration` aborts on `mkdir` through the read-only store directory
  # symlink (preventing `reloadSystemd` from running). Remove it before `linkGeneration`
  # only when it is a symlink whose target is under `/nix/store`; leave any real directory
  # or non-store symlink untouched for home-manager's collision check.
  cleanupLegacyOpencodeSkill = ''
    legacy_skill="''${XDG_CONFIG_HOME:-$HOME/.config}/opencode/skills/xmsg"
    if [ -L "$legacy_skill" ]; then
      target=$(readlink "$legacy_skill" || true)
      case "$target" in
        ${builtins.storeDir}/*)
          ''${DRY_RUN_CMD:-} rm -f "$legacy_skill"
          ;;
      esac
    fi
  '';

  peerType = types.submodule {
    options = {
      address = mkOption {
        type = types.str;
        description = "The peer's federation endpoint, `host:port`.";
      };
      pin = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "The peer's SPKI pin, `sha256:<hex>`. Exactly one of `pin`, `pinFromCert` and `ca`.";
      };
      pinFromCert = mkOption {
        type = types.nullOr types.path;
        default = null;
        description = "A PEM certificate whose SPKI SHA-256 becomes the entry's `pin`, computed at build time.";
      };
      ca = mkOption {
        type = types.nullOr (types.either types.path types.str);
        default = null;
        description = "PEM trust anchor bundle. A path is copied to the store; a string is a runtime path. Needs `identities`.";
      };
      identities = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
        description = "The peer certificate's URI SAN (exactly one). Required with `ca`.";
      };
      allow = mkOption {
        type = types.listOf (
          types.enum [
            "send"
            "reply"
            "list"
            "forward"
            "relayed"
            "relay"
          ]
        );
        default = [ ];
        description = "Operations the peer may perform here, as the loader reads them (src/fed.rs): on a hub, `forward` relays the peer's sends; on a recipient, `relayed` (or `relay`) accepts what the peer relays (README 7.7).";
      };
      from = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
        description = "Source CIDR blocks the peer may connect from.";
      };
      leaf = mkOption {
        type = types.bool;
        default = false;
        description = "The peer is a leaf: sends to it are queued for it to collect, never pushed.";
      };
      principals = mkOption {
        type = types.listOf types.str;
        default = [ ];
        description = "Sender filters: a service name, an instance ID, or `anon:<from>`.";
      };
      targets = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
        description = "Local targets the peer may reach: a service name or an instance ID. Null admits every target.";
      };
      dial = mkOption {
        type = types.nullOr (types.enum [ "outbound" ]);
        default = null;
        description = "`outbound`: this node dials the peer and holds the link open (README 7.6).";
      };
    };
  };

  # One entry in xmsg's peers-file schema (README 7.3): absent fields are omitted, as the
  # loader's defaults read them.
  renderPeer =
    _: p:
    lib.filterAttrs (_: v: v != null) {
      inherit (p)
        address
        pin
        identities
        allow
        from
        targets
        dial
        ;
      ca = if p.ca == null then null else "${p.ca}";
    }
    // lib.optionalAttrs p.leaf { leaf = true; }
    // lib.optionalAttrs (p.principals != [ ]) { inherit (p) principals; };

  peersJson = builtins.toJSON (lib.mapAttrs renderPeer fed.peers);
  pinned = lib.filterAttrs (_: p: p.pinFromCert != null) fed.peers;
  # The pin is the SHA-256 of the cert's DER SubjectPublicKeyInfo, as xmsg's
  # spki_sha256_from_der computes it (src/fed.rs).
  peersBase = pkgs.writeText "xmsg-peers.json" peersJson;
  peersFile =
    if pinned == { } then
      peersBase
    else
      pkgs.runCommand "xmsg-peers.json"
        {
          nativeBuildInputs = [
            pkgs.jq
            pkgs.openssl
          ];
        }
        ''
          cp ${peersBase} peers.json
          ${lib.concatStrings (
            lib.mapAttrsToList (name: p: ''
              openssl x509 -in ${p.pinFromCert} -pubkey -noout > pub.pem
              openssl pkey -pubin -in pub.pem -outform DER > spki.der
              pin=$(sha256sum spki.der | cut -d' ' -f1)
              jq --arg name ${lib.escapeShellArg name} --arg pin "sha256:$pin" '.[$name].pin = $pin' peers.json > next.json
              mv next.json peers.json
            '') pinned
          )}
          cp peers.json $out
        '';

  serveArgs =
    lib.optionals (srv.httpSocket != null) [
      "--http-sock"
      srv.httpSocket
    ]
    ++ lib.concatMap (p: [
      "--agy-exe"
      p
    ]) srv.agyExe
    ++ lib.concatMap (p: [
      "--codex-exe"
      (toString p)
    ]) srv.codexExe
    ++ lib.optionals (cfg.harnesses.codex.enable || srv.codexExe != [ ]) (
      lib.concatMap (p: [
        "--codex-home"
        (toString p)
      ]) srv.codexHome
    )
    ++ lib.concatLists (
      lib.mapAttrsToList (name: p: [
        "--svc-exe"
        "${name}=${p}"
      ]) srv.svcExe
    )
    ++ lib.optionals fed.enable (
      [
        "--fed-listen"
        "${fed.listenAddress}:${toString fed.port}"
        "--fed-cert"
        "${fed.cert}"
        "--fed-key"
        fed.key
        "--peers-file"
        "${peersFile}"
      ]
      ++ lib.optionals (fed.reloadInterval != null) [
        "--fed-reload-interval-secs"
        (toString fed.reloadInterval)
      ]
    );

  defaultSessionsDirs = [ "${config.home.homeDirectory}/.claude/sessions" ];
  effectiveSessionsDirs = map toString (srv.sessionsDirs ++ srv.extraSessionsDirs);
  hasCustomSessionsDirs = effectiveSessionsDirs != defaultSessionsDirs;
  sessionsDirsEnv = lib.concatStringsSep ":" effectiveSessionsDirs;

  # This module's own definitions, told apart from the user's (`definitionsWithLocations`).
  thisFile = toString ./home-manager.nix;

  # hermes's `settings` merges by `lib.recursiveUpdate` (hermes-agent's deepConfigType,
  # nix/moduleCommon.nix), which replaces a list whole: of two `plugins.enabled` definitions the
  # later one wins and the other's entries are dropped. So the switch's own `plugins.enabled` is
  # every other definition's entries plus `xmsg`, defined last (`mkAfter`); a definition ordered
  # after it would still replace it, which the switch refuses, naming what was lost.
  hermesEnabled =
    defs: lib.concatMap (d: if d.value ? plugins.enabled then d.value.plugins.enabled else [ ]) defs;
  hermesEnabledElsewhere = lib.optionals (options ? services.hermes-agent.settings) (
    hermesEnabled (
      lib.filter (d: d.file != thisFile) options.services.hermes-agent.settings.definitionsWithLocations
    )
  );

  # A switch whose harness module is off would install nothing; refuse it, naming the option.
  requireHarness = switch: option: enabled: {
    assertion = enabled;
    message = "programs.xmsg.harnesses.${switch}.enable needs ${option} = true.";
  };
in
{
  _file = thisFile;

  options.programs.xmsg = {
    enable = mkEnableOption "xmsg, the bridge into running agent sessions";

    package = mkOption {
      type = types.package;
      default = packages.${pkgs.stdenv.hostPlatform.system}.default;
      defaultText = lib.literalExpression "xmsg.packages.\${system}.default";
      description = "The xmsg package.";
    };

    server = {
      enable = mkOption {
        type = types.bool;
        default = true;
        description = "Run `xmsg serve` as a user service (systemd on Linux, launchd on darwin).";
      };
      httpSocket = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "`--http-sock`. Null takes xmsg's default, `$XDG_RUNTIME_DIR/xmsg/http.sock`.";
      };
      agyExe = mkOption {
        type = types.listOf types.str;
        default = lib.optional (
          cfg.harnesses.agy.enable && config.programs.antigravity-cli.package != null
        ) "${config.programs.antigravity-cli.package}/bin/agy";
        defaultText = lib.literalExpression ''[ "''${config.programs.antigravity-cli.package}/bin/agy" ] when harnesses.agy is on'';
        description = "`--agy-exe`: the agy executables whose sessions xmsg attests (the identity anchor).";
      };
      codexExe = mkOption {
        type = types.listOf types.str;
        default = lib.optional (
          cfg.harnesses.codex.enable && (config.programs.codex.package or null) != null
        ) "${config.programs.codex.package}/bin/codex";
        defaultText = lib.literalExpression ''[ "''${config.programs.codex.package}/bin/codex" ] when harnesses.codex is on'';
        description = "`--codex-exe`: the Codex executables whose sessions xmsg attests (the identity anchor).";
      };
      codexHome = mkOption {
        type = types.listOf (types.either types.path types.str);
        default = [ "${config.home.homeDirectory}/.codex" ];
        defaultText = lib.literalExpression ''[ "''${config.home.homeDirectory}/.codex" ]'';
        description = "`--codex-home`: the Codex home directories `xmsg serve` trusts (`--codex-home`, repeatable).";
      };
      svcExe = mkOption {
        type = types.attrsOf types.str;
        default = { };
        example = lib.literalExpression "{ my-bot = lib.getExe pkgs.my-bot; }";
        description = "`--svc-exe NAME=PATH`: the service names xmsg admits, each only from its executable.";
      };
      sessionsDirs = mkOption {
        type = types.listOf (types.either types.path types.str);
        default = defaultSessionsDirs;
        defaultText = lib.literalExpression ''[ "''${config.home.homeDirectory}/.claude/sessions" ]'';
        description = "Session directories `xmsg serve` scans (`XMSG_SESSIONS_DIR`, colon-joined).";
      };
      extraSessionsDirs = mkOption {
        type = types.listOf (types.either types.path types.str);
        default = [ ];
        description = "Additional session directories appended to `programs.xmsg.server.sessionsDirs`.";
      };
      federation = {
        enable = mkEnableOption "cross-host federation (`--fed-listen`, `--fed-cert`, `--fed-key`, `--peers-file`)";
        listenAddress = mkOption {
          type = types.str;
          default = "0.0.0.0";
          description = "Address the federation listener binds.";
        };
        port = mkOption {
          type = types.port;
          default = 7788;
          description = "Federation listener port.";
        };
        cert = mkOption {
          type = types.either types.path types.str;
          description = "`--fed-cert`: this node's PEM certificate.";
        };
        key = mkOption {
          type = types.addCheck types.str (s: !builtins.hasContext s && !lib.hasPrefix builtins.storeDir s);
          description = "`--fed-key`: this node's PEM private key, a runtime path (never a store path).";
        };
        reloadInterval = mkOption {
          type = types.nullOr types.ints.unsigned;
          default = null;
          description = "`--fed-reload-interval-secs`. Null takes xmsg's default (30).";
        };
        peers = mkOption {
          type = types.attrsOf peerType;
          default = { };
          description = "The peers file (`--peers-file`), keyed by node name or nickname (README 7.3).";
        };
      };
    };

    harnesses = {
      claude = {
        enable = mkEnableOption "the xmsg MCP server, skill and tool permissions in Claude Code (`programs.claude-code`)";
        permissionPrefixes = mkOption {
          type = types.listOf types.str;
          default = [
            "mcp__plugin_hm_xmsg"
            "mcp__xmsg"
          ];
          description = "Tool-name prefixes allowed in `programs.claude-code.settings.permissions.allow` for `{list,send,reply,replies}`. Home Manager packages `programs.claude-code.mcpServers.xmsg` into its `hm` plugin (`mcp__plugin_hm_xmsg__*`), while a server registered outside that plugin uses `mcp__xmsg__*`.";
        };
      };
      agy = {
        enable = mkEnableOption "the xmsg MCP server, skill and PreInvocation hook in Antigravity (`programs.antigravity-cli`); the module owns `~/.gemini/config/hooks.json`";
        label = mkOption {
          type = types.str;
          default = "agy";
          description = "Label assigned to registered Antigravity sessions (`--label` on `xmsg register agy`).";
        };
      };
      pi.enable = mkEnableOption "the xmsg pi extension and skill (`~/.pi/agent`)";
      opencode.enable = mkEnableOption "the xmsg opencode plugin and skill (`$XDG_CONFIG_HOME/opencode`); no MCP entry and no `opencode.json`";
      hermes.enable = mkEnableOption "the xmsg hermes plugin and skill (`services.hermes-agent`); the plugin may inject on the TUI and desktop host (`plugins.entries.xmsg.allow_gateway_injection`)";
      codex = {
        enable = mkEnableOption "the xmsg MCP server, skill, hook declarations and trust-state helper in Codex (`programs.codex`)";
        hooks = mkOption {
          type = types.attrsOf (types.listOf types.attrs);
          readOnly = true;
          default = if cfg.enable && cfg.harnesses.codex.enable then codexHooks else { };
          defaultText = lib.literalExpression "lifecycle and drain hook declarations when harnesses.codex is on, else { }";
          description = "Read-only Codex hook declarations in Claude hook shape (`{ Event = [ { matcher?; hooks = [ { type = \"command\"; command; timeout?; } ]; } ]; }`).";
        };
        trustState = mkOption {
          type = types.functionTo (types.functionTo types.attrs);
          readOnly = true;
          default = codexTrustState;
          defaultText = lib.literalExpression "hooksPath: finalHooks: { hooks.state.<key>.trusted_hash = \"sha256:...\"; }";
          description = "Read-only function computing `hooks.state.<key>.trusted_hash` entries for every handler in a final `.codex/hooks.json` object.";
        };
        mcpServer = mkOption {
          type = types.attrs;
          readOnly = true;
          default = codexMcpServer;
          defaultText = lib.literalExpression "{ command = lib.getExe config.programs.xmsg.package; args = [ \"mcp\" ]; env_vars = [ \"XDG_RUNTIME_DIR\" ]; default_tools_approval_mode = \"approve\"; }";
          description = "Read-only MCP server data assigned to `programs.codex.settings.mcp_servers.xmsg`.";
        };
      };
    };
  };

  config = mkIf cfg.enable (mkMerge [
    {
      home.packages = [ cfg.package ];

      warnings =
        lib.optional (srv.enable && pkgs.stdenv.hostPlatform.isLinux && !config.systemd.user.startServices)
          "programs.xmsg.server.enable: systemd.user.startServices is not \"sd-switch\", so a home-manager switch will not restart xmsg.service.";

      assertions =
        lib.optional cfg.harnesses.claude.enable (
          requireHarness "claude" "programs.claude-code.enable" config.programs.claude-code.enable
        )
        ++ lib.optional cfg.harnesses.agy.enable (
          requireHarness "agy" "programs.antigravity-cli.enable" config.programs.antigravity-cli.enable
        )
        ++ lib.optional cfg.harnesses.hermes.enable (
          requireHarness "hermes" "services.hermes-agent.enable" (
            config.services.hermes-agent.enable or false
          )
        )
        ++ lib.optionals cfg.harnesses.codex.enable [
          (requireHarness "codex" "programs.codex.enable" (config.programs.codex.enable or false))
        ]
        ++ lib.concatLists (
          lib.mapAttrsToList (
            name: p:
            let
              peer = rule: message: {
                assertion = rule;
                message = "programs.xmsg.server.federation.peers.${name}: ${message}";
              };
            in
            # The loader's rules (src/fed.rs, PeersMap parse), refused here rather than at `xmsg serve`.
            [
              (peer (
                lib.count (x: x != null) [
                  p.pin
                  p.pinFromCert
                  p.ca
                ] == 1
              ) "set exactly one of pin, pinFromCert and ca.")
              (peer (p.ca == null || p.identities != null) "ca needs identities.")
              (peer (
                p.pin == null && p.pinFromCert == null || p.identities == null
              ) "identities is only valid with ca, not with pin or pinFromCert.")
              (peer (
                p.identities == null || lib.length p.identities == 1
              ) "identities holds exactly one identity.")
              (peer (p.from != [ ]) "from must hold at least one CIDR, or be null.")
            ]
          ) fed.peers
        )
        # The module owns hooks.json through `.source`; a `.text` definition elsewhere would
        # otherwise lose silently to it (HM sets `source` from `text` at default priority).
        ++ lib.optional cfg.harnesses.agy.enable {
          assertion = config.home.file.".gemini/config/hooks.json".text == null;
          message = "programs.xmsg.harnesses.agy.enable owns ~/.gemini/config/hooks.json; remove the other home.file.\".gemini/config/hooks.json\".text definition.";
        }
        ++ lib.optional (cfg.harnesses.hermes.enable && options ? services.hermes-agent.settings) (
          let
            lost = lib.subtractLists (config.services.hermes-agent.settings.plugins.enabled or [ ]) (
              hermesEnabled options.services.hermes-agent.settings.definitionsWithLocations
            );
          in
          {
            assertion = lost == [ ];
            message = "programs.xmsg.harnesses.hermes.enable: services.hermes-agent.settings.plugins.enabled lost ${builtins.toJSON lost}. hermes merges `settings` by lib.recursiveUpdate, which replaces a list, and a definition ordered after the switch's (lib.mkAfter) replaced its list; define that one without the later order.";
          }
        );
    }

    # Runs as the sessions' own user: the inbox sockets live in 0700 dirs. Its HTTP API is
    # a unix socket with the peer uid checked, and there is no TCP listener.
    (mkIf (srv.enable && pkgs.stdenv.hostPlatform.isLinux) {
      systemd.user.services.xmsg = {
        Unit = {
          Description = "xmsg: bridge into running agent sessions";
          X-Restart-Triggers = [
            "${cfg.package}"
          ]
          ++ lib.optional fed.enable "${peersFile}";
        };
        Service = {
          ExecStart = "${exe} serve ${lib.escapeShellArgs serveArgs}";
          Restart = "on-failure";
          # Safe hardening subset for systemd --user (no CLONE_NEWUSER / CLONE_NEWNS):
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
        }
        // lib.optionalAttrs hasCustomSessionsDirs {
          Environment = [ "XMSG_SESSIONS_DIR=${sessionsDirsEnv}" ];
        };
        Install.WantedBy = [ "default.target" ];
      };
    })

    (mkIf (srv.enable && pkgs.stdenv.hostPlatform.isDarwin) {
      launchd.agents.xmsg = {
        enable = true;
        config = {
          ProgramArguments = [
            exe
            "serve"
          ]
          ++ serveArgs;
          KeepAlive.SuccessfulExit = false;
          RunAtLoad = true;
        }
        // lib.optionalAttrs hasCustomSessionsDirs {
          EnvironmentVariables.XMSG_SESSIONS_DIR = sessionsDirsEnv;
        };
      };
    })

    (mkIf cfg.harnesses.claude.enable {
      programs.claude-code = {
        mcpServers.xmsg = mcpEntry // {
          type = "stdio";
          env = { };
        };
        skills.xmsg = skill;
        # The tools are authorized explicitly: allowed calls skip the auto-mode classifier.
        # Home Manager wraps `mcpServers.xmsg` in its generated `hm` plugin
        # (`mcp__plugin_hm_xmsg__*`); direct registrations use `mcp__xmsg__*`.
        settings = {
          permissions.allow = lib.concatMap (
            prefix: map (tool: "${prefix}__${tool}") claudeTools
          ) cfg.harnesses.claude.permissionPrefixes;
          hooks = {
            PreToolUse = map (prefix: {
              matcher = "^${prefix}__(send|reply|inbox|list|replies)$";
              hooks = claudeHook;
            }) cfg.harnesses.claude.permissionPrefixes;
            PostToolUse = [
              {
                matcher = "^(Agent|SendMessage)$";
                hooks = claudeHook;
              }
            ];
            SubagentStart = [ { hooks = claudeHook; } ];
            SubagentStop = [ { hooks = claudeHook; } ];
          };
        };
      };
    })

    (mkIf cfg.harnesses.agy.enable {
      programs.antigravity-cli = {
        mcpServers.xmsg = mcpEntry;
        skills.xmsg = skill;
      };
      # agy registers its language-server credentials before every turn. `--hook` reads them
      # from the hook's stdin JSON. programs.antigravity-cli has no hook option, so this
      # module owns the whole file.
      home.file.".gemini/config/hooks.json".source = pkgs.writeText "hooks.json" (
        builtins.toJSON {
          xmsg-register = {
            PreInvocation = [
              {
                type = "command";
                command =
                  "${exe} register agy --hook --event pre-invocation"
                  + lib.optionalString (
                    cfg.harnesses.agy.label != "agy"
                  ) " --label ${lib.escapeShellArg cfg.harnesses.agy.label}";
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
        }
      );
    })

    # pi auto-discovers extensions under ~/.pi/agent/extensions.
    (mkIf cfg.harnesses.pi.enable {
      home.file.".pi/agent/extensions/xmsg-pi.ts".source = ../../extensions/pi/index.ts;
      home.file.".pi/agent/skills/xmsg/SKILL.md".source = skill + "/SKILL.md";
    })

    # opencode auto-loads {plugin,plugins}/*.ts from its config dir. Files, not
    # `programs.opencode`: that module applies only when enabled and has no plugin option, so
    # these compose with any opencode configuration and need no harness module (harness C9).
    (mkIf cfg.harnesses.opencode.enable {
      xdg.configFile."opencode/plugin/xmsg.ts".source = ../../extensions/opencode/xmsg.ts;
      xdg.configFile."opencode/skills/xmsg/SKILL.md".source = skill + "/SKILL.md";
      home.activation.xmsgCleanupLegacyOpencodeSkill = lib.hm.dag.entryBefore [
        "linkGeneration"
      ] cleanupLegacyOpencodeSkill;
    })

    # hermes-agent's own home-manager module (`services.hermes-agent`) installs the plugin and
    # writes config.yaml; `plugins.enabled` joins the user's own (`hermesEnabledElsewhere`).
    # Defined only where that module is imported; elsewhere the switch's assertion names the option.
    (lib.optionalAttrs (options ? services.hermes-agent) (
      mkIf cfg.harnesses.hermes.enable {
        services.hermes-agent = {
          extraPlugins = [ hermesPlugin ];
          settings = mkMerge [
            # Without it the TUI and desktop host refuses every injection (hermes_cli/plugins_injection.py).
            { plugins.entries.xmsg.allow_gateway_injection = true; }
            (lib.mkAfter { plugins.enabled = lib.unique (hermesEnabledElsewhere ++ [ "xmsg" ]); })
          ];
          hermesHomeFiles."skills/xmsg/SKILL.md" = skill + "/SKILL.md";
        };
      }
    ))

    (mkIf cfg.harnesses.codex.enable {
      xdg.dataFile."xmsg/bin/xmsg".source = exe;
    })

    (lib.optionalAttrs (options ? programs.codex) (
      mkIf cfg.harnesses.codex.enable {
        programs.codex = {
          skills.xmsg = skill;
          settings.mcp_servers.xmsg = codexMcpServer;
        };
      }
    ))
  ]);
}
