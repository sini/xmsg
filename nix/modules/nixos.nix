# nixosModules.xmsg: firewall port helper (`programs.xmsg.federation`) and
# multi-instance system services (`services.xmsg.instances.<name>`).
{ packages }:
{
  config,
  lib,
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
  inherit (import ./_lib.nix { inherit lib; }) peerType mkPeersFile;

  fedCfg = config.programs.xmsg.federation;
  instances = lib.filterAttrs (_: icfg: icfg.enable) config.services.xmsg.instances;

  instanceSubmodule =
    { name, config, ... }:
    let
      icfg = config;
    in
    {
      options = {
        enable = mkOption {
          type = types.bool;
          default = true;
          description = "Run this `xmsg serve` system instance (`xmsg-${name}.service`).";
        };
        package = mkOption {
          type = types.package;
          default = packages.${pkgs.stdenv.hostPlatform.system}.default;
          defaultText = lib.literalExpression "packages.<system>.default";
          description = "The xmsg package for this instance.";
        };
        user = mkOption {
          type = types.str;
          default = "xmsg-${name}";
          description = "System user account that owns this instance's runtime dir, state dir, and sockets.";
        };
        group = mkOption {
          type = types.str;
          default = icfg.user;
          defaultText = lib.literalExpression "config.user";
          description = "Primary group for this instance's systemd service.";
        };
        home = mkOption {
          type = types.nullOr types.str;
          default = "/var/lib/xmsg-${name}";
          description = "`HOME` environment variable for the instance service; null omits `HOME`.";
        };
        runtimeDir = mkOption {
          type = types.addCheck types.str (s: lib.hasPrefix "/run/" s);
          default = "/run/xmsg-${name}";
          description = "Runtime directory under `/run/` (`RuntimeDirectory`, `XDG_RUNTIME_DIR`), mode `0700`.";
        };
        stateDir = mkOption {
          type = types.addCheck types.str (s: lib.hasPrefix "/var/lib/" s);
          default = "/var/lib/xmsg-${name}";
          description = "State directory under `/var/lib/` (`StateDirectory`), mode `0700`; holds `xmsg.db` (`XMSG_DB_PATH`).";
        };
        sessionsDirs = mkOption {
          type = types.listOf (types.either types.path types.str);
          default = [ ];
          description = "Session directories scanned by `xmsg serve` (`XMSG_SESSIONS_DIR`, colon-joined).";
        };
        svcExe = mkOption {
          type = types.attrsOf types.str;
          default = { };
          example = lib.literalExpression "{ my-bot = lib.getExe pkgs.my-bot; }";
          description = "`--svc-exe NAME=PATH`: service names this instance admits, each only from its executable.";
        };
        sockets = {
          http = mkOption {
            type = types.nullOr types.str;
            default = "${icfg.runtimeDir}/xmsg/http.sock";
            defaultText = lib.literalExpression ''"''${config.runtimeDir}/xmsg/http.sock"'';
            description = "`XMSG_HTTP_SOCK`: pinned HTTP socket path. Defaults under `runtimeDir` so system-service restarts never hit `UnprovenExistingSocket`.";
          };
          agent = mkOption {
            type = types.nullOr types.str;
            default = "${icfg.runtimeDir}/xmsg/agent.sock";
            defaultText = lib.literalExpression ''"''${config.runtimeDir}/xmsg/agent.sock"'';
            description = "`XMSG_AGENT_SOCK`: pinned agent socket path.";
          };
          register = mkOption {
            type = types.nullOr types.str;
            default = "${icfg.runtimeDir}/xmsg/register.sock";
            defaultText = lib.literalExpression ''"''${config.runtimeDir}/xmsg/register.sock"'';
            description = "`XMSG_REGISTER_SOCK`: pinned registration socket path.";
          };
        };
        allowTcpListen = mkOption {
          type = types.bool;
          default = false;
          description = "Allow binding a TCP HTTP listener (`--listen` / `XMSG_LISTEN`). False asserts against any TCP listen configuration.";
        };
        listen = mkOption {
          type = types.nullOr types.str;
          default = null;
          description = "`XMSG_LISTEN` TCP address (`host:port`). Requires `allowTcpListen = true`.";
        };
        extraArgs = mkOption {
          type = types.listOf types.str;
          default = [ ];
          description = "Extra CLI arguments appended to `xmsg serve`.";
        };
        extraEnvironment = mkOption {
          type = types.attrsOf types.str;
          default = { };
          description = "Extra environment variables set on `xmsg-${name}.service`.";
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
            description = "`--fed-cert`: this instance's PEM certificate.";
          };
          key = mkOption {
            type = types.addCheck types.str (s: !builtins.hasContext s && !lib.hasPrefix builtins.storeDir s);
            description = "`--fed-key`: this instance's PEM private key, a runtime path (never a store path).";
          };
          reloadInterval = mkOption {
            type = types.nullOr types.ints.unsigned;
            default = null;
            description = "`--fed-reload-interval-secs`. Null takes xmsg's default (30).";
          };
          peers = mkOption {
            type = types.attrsOf peerType;
            default = { };
            description = "The peers file (`--peers-file`), keyed by node name or nickname.";
          };
          openFirewall = mkOption {
            type = types.bool;
            default = false;
            description = "Open `federation.port` in `networking.firewall.allowedTCPPorts`.";
          };
        };
      };
    };

  mkInstanceService =
    name: icfg:
    let
      fed = icfg.federation;
      peersFile = mkPeersFile pkgs fed.peers;
      svcExeArgs = lib.concatLists (
        lib.mapAttrsToList (svcName: path: [
          "--svc-exe"
          "${svcName}=${path}"
        ]) icfg.svcExe
      );
      fedArgs = lib.optionals fed.enable (
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
    in
    {
      description = "xmsg daemon (${name})";
      wantedBy = [ "multi-user.target" ];
      environment = {
        XDG_RUNTIME_DIR = icfg.runtimeDir;
        XMSG_DB_PATH = "${icfg.stateDir}/xmsg.db";
      }
      // lib.optionalAttrs (icfg.home != null) {
        HOME = icfg.home;
      }
      // lib.optionalAttrs (icfg.sockets.http != null) {
        XMSG_HTTP_SOCK = icfg.sockets.http;
      }
      // lib.optionalAttrs (icfg.sockets.agent != null) {
        XMSG_AGENT_SOCK = icfg.sockets.agent;
      }
      // lib.optionalAttrs (icfg.sockets.register != null) {
        XMSG_REGISTER_SOCK = icfg.sockets.register;
      }
      // lib.optionalAttrs (icfg.sessionsDirs != [ ]) {
        XMSG_SESSIONS_DIR = lib.concatStringsSep ":" (map toString icfg.sessionsDirs);
      }
      // lib.optionalAttrs (icfg.listen != null) {
        XMSG_LISTEN = icfg.listen;
      }
      // icfg.extraEnvironment;
      serviceConfig = {
        User = icfg.user;
        Group = icfg.group;
        RuntimeDirectory = lib.removePrefix "/run/" icfg.runtimeDir;
        RuntimeDirectoryMode = "0700";
        RuntimeDirectoryPreserve = "yes";
        StateDirectory = lib.removePrefix "/var/lib/" icfg.stateDir;
        StateDirectoryMode = "0700";
        ExecStart = lib.escapeShellArgs (
          [
            (lib.getExe icfg.package)
            "serve"
          ]
          ++ svcExeArgs
          ++ fedArgs
          ++ icfg.extraArgs
        );
        Type = "notify";
        Restart = "on-failure";
        ProtectSystem = "strict";
        ProtectHome = true;
        PrivateTmp = true;
        PrivateDevices = true;
        NoNewPrivileges = true;
        CapabilityBoundingSet = "";
        AmbientCapabilities = "";
        ProtectHostname = true;
        ProtectClock = true;
        ProtectKernelTunables = true;
        ProtectKernelModules = true;
        ProtectKernelLogs = true;
        ProtectControlGroups = true;
        # xmsg reads /proc/<peer> to attest callers, and every caller shares
        # the bus's uid, so hiding other users' processes hides no caller.
        # No PrivatePIDs, which would hide them all.
        ProtectProc = "invisible";
        ProcSubset = "pid";
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        RemoveIPC = true;
        LockPersonality = true;
        MemoryDenyWriteExecute = true;
        SystemCallArchitectures = "native";
        SystemCallFilter = [
          "@system-service"
          "~@privileged"
          "~@resources"
        ];
        RestrictAddressFamilies = [
          "AF_UNIX"
          "AF_INET"
          "AF_INET6"
        ];
        UMask = "0077";
      };
    };
in
{
  options.programs.xmsg.federation = {
    enable = mkEnableOption "the xmsg federation port in the firewall";
    port = mkOption {
      type = types.port;
      default = 7788;
      description = "The federation port to open; match `programs.xmsg.server.federation.port` in home-manager.";
    };
  };

  options.services.xmsg.instances = mkOption {
    type = types.attrsOf (types.submodule instanceSubmodule);
    default = { };
    description = "System-level `xmsg serve` daemon instances, each isolated under its own user, runtime directory, and state directory.";
  };

  config = mkMerge [
    (mkIf fedCfg.enable {
      networking.firewall.allowedTCPPorts = [ fedCfg.port ];
    })
    (mkIf (instances != { }) {
      assertions = lib.concatLists (
        lib.mapAttrsToList (
          name: icfg:
          let
            hasListenArg = lib.any (a: a == "--listen" || lib.hasPrefix "--listen=" a) icfg.extraArgs;
            hasListenEnv = icfg.extraEnvironment ? XMSG_LISTEN;
          in
          [
            {
              assertion = icfg.allowTcpListen || (icfg.listen == null && !hasListenArg && !hasListenEnv);
              message = "services.xmsg.instances.${name}: TCP listen (--listen / XMSG_LISTEN / listen) is forbidden unless allowTcpListen = true.";
            }
          ]
        ) instances
      );

      systemd.services = lib.mapAttrs' (
        name: icfg: lib.nameValuePair "xmsg-${name}" (mkInstanceService name icfg)
      ) instances;

      networking.firewall.allowedTCPPorts = lib.concatLists (
        lib.mapAttrsToList (
          _: icfg: lib.optional (icfg.federation.enable && icfg.federation.openFirewall) icfg.federation.port
        ) instances
      );
    })
  ];
}
