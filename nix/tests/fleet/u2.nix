{
  pkgs,
  lib,
  fleet,
  homeManagerModule,
  nixosModule,
  baseFleet,
}:
let
  aliceHubGold = fleet.peersRenderedFor {
    fleet = baseFleet;
    self = "alice.hub";
  };
  aliceLaptopGold = fleet.peersRenderedFor {
    fleet = baseFleet;
    self = "alice.laptop";
  };
  bobDeskGold = fleet.peersRenderedFor {
    fleet = baseFleet;
    self = "bob.desk";
  };
  gatewayGold = fleet.peersRenderedFor {
    fleet = baseFleet;
    self = "gateway.mcp";
  };

  extHost = {
    address = "ext.example.org:7788";
    ca = "/etc/xmsg/ca/ext.crt";
    identities = [ "spiffe://ext.example.org/host/ext/user/ext" ];
    allow = [ "send" ];
  };
  extHostMod = {
    address = "ext.example.org:7788";
    ca = "/etc/xmsg/ca/ext.crt";
    identities = [ "spiffe://ext.example.org/host/ext/user/ext" ];
    allow = [ "send" ];
  };

  # Minimal HM / NixOS module evaluation harnesses for pure eval checks.
  hmStub =
    { lib, ... }:
    {
      options = {
        xdg = {
          stateHome = lib.mkOption {
            type = lib.types.str;
            default = "/home/test/.local/state";
          };
          configHome = lib.mkOption {
            type = lib.types.str;
            default = "/home/test/.config";
          };
          dataHome = lib.mkOption {
            type = lib.types.str;
            default = "/home/test/.local/share";
          };
          configFile = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = { };
          };
          dataFile = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = { };
          };
        };
        home = {
          username = lib.mkOption {
            type = lib.types.str;
            default = "test";
          };
          homeDirectory = lib.mkOption {
            type = lib.types.str;
            default = "/home/test";
          };
          packages = lib.mkOption {
            type = lib.types.listOf lib.types.package;
            default = [ ];
          };
          sessionVariables = lib.mkOption {
            type = lib.types.attrsOf lib.types.str;
            default = { };
          };
          file = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = { };
          };
          activation = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = { };
          };
        };
        systemd.user = {
          startServices = lib.mkOption {
            type = lib.types.anything;
            default = "sd-switch";
          };
          services = lib.mkOption {
            type = lib.types.attrsOf lib.types.anything;
            default = { };
          };
        };
        launchd.agents = lib.mkOption {
          type = lib.types.attrsOf lib.types.anything;
          default = { };
        };
        programs = {
          claude-code = lib.mkOption {
            type = lib.types.anything;
            default = { };
          };
          antigravity-cli = lib.mkOption {
            type = lib.types.anything;
            default = { };
          };
          codex = lib.mkOption {
            type = lib.types.anything;
            default = { };
          };
        };
        services.hermes-agent = lib.mkOption {
          type = lib.types.anything;
          default = { };
        };
        assertions = lib.mkOption {
          type = lib.types.listOf lib.types.anything;
          default = [ ];
        };
        warnings = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
        };
      };
    };

  nixosStub =
    { lib, ... }:
    {
      options = {
        assertions = lib.mkOption {
          type = lib.types.listOf lib.types.anything;
          default = [ ];
        };
        warnings = lib.mkOption {
          type = lib.types.listOf lib.types.str;
          default = [ ];
        };
        systemd.services = lib.mkOption {
          type = lib.types.attrsOf lib.types.anything;
          default = { };
        };
        networking.firewall.allowedTCPPorts = lib.mkOption {
          type = lib.types.listOf lib.types.port;
          default = [ ];
        };
      };
    };

  evalHM =
    mod:
    (lib.evalModules {
      specialArgs = { inherit pkgs; };
      modules = [
        hmStub
        homeManagerModule
        mod
      ];
    }).config;

  evalNixos =
    mod:
    (lib.evalModules {
      specialArgs = { inherit pkgs; };
      modules = [
        nixosModule
        nixosStub
        mod
      ];
    }).config;

  failedMsgs = cfg: map (a: a.message) (lib.filter (a: !a.assertion) cfg.assertions);

  # Common HM/NixOS base configs.
  hmFleetBase =
    {
      self ? "alice.hub",
      port ? 7788,
      hostOwned ? [ ],
      extraPeers ? { },
      fleetVal ? baseFleet,
    }:
    evalHM {
      programs.xmsg = {
        enable = true;
        server = {
          enable = true;
          federation = {
            enable = true;
            inherit port;
            cert = "/etc/xmsg/node.crt";
            key = "/run/secrets/node.key";
            fleet = {
              value = fleetVal;
              inherit self hostOwned;
            };
            peers = extraPeers;
          };
        };
      };
    };

  hmStandalone =
    peers:
    evalHM {
      programs.xmsg = {
        enable = true;
        server = {
          enable = true;
          federation = {
            enable = true;
            cert = "/etc/xmsg/node.crt";
            key = "/run/secrets/node.key";
            inherit peers;
          };
        };
      };
    };

  nixosFleetBase =
    {
      self ? "alice.hub",
      port ? 7788,
      hostOwned ? [ ],
      extraPeers ? { },
      fleetVal ? baseFleet,
    }:
    evalNixos {
      services.xmsg.instances.main = {
        federation = {
          enable = true;
          inherit port;
          cert = "/etc/xmsg/node.crt";
          key = "/run/secrets/node.key";
          fleet = {
            value = fleetVal;
            inherit self hostOwned;
          };
          peers = extraPeers;
        };
      };
    };

  nixosStandalone =
    peers:
    evalNixos {
      services.xmsg.instances.main = {
        federation = {
          enable = true;
          cert = "/etc/xmsg/node.crt";
          key = "/run/secrets/node.key";
          inherit peers;
        };
      };
    };

  cf =
    {
      self ? "alice.laptop",
      file,
      hostOwned ? [ ],
      value ? baseFleet,
    }:
    fleet.checkFinal {
      inherit
        value
        self
        file
        hostOwned
        ;
    };

  cfMsgs = args: map (c: c.message) (cf args);

  hasInfixAny = pat: msgs: lib.any (lib.hasInfix pat) msgs;

  natFleet = baseFleet // {
    nodes = baseFleet.nodes // {
      "bob.desk" = baseFleet.nodes."bob.desk" // {
        address = "bob.example.org:443";
        listenPort = 7788;
      };
    };
  };

  addr443Fleet = baseFleet // {
    nodes = baseFleet.nodes // {
      "bob.desk" = baseFleet.nodes."bob.desk" // {
        address = "bob.example.org:443";
      };
    };
  };

  noMailboxLeafFleet = baseFleet // {
    nodes = baseFleet.nodes // {
      "extra.leaf" = {
        kind = "leaf";
      };
    };
  };

  u2Positive = [
    {
      name = "u2 green: NAT fixture HM passes V5";
      ok =
        failedMsgs (hmFleetBase {
          self = "bob.desk";
          port = 7788;
          fleetVal = natFleet;
        }) == [ ];
    }
    {
      name = "u2 green: NAT fixture NixOS passes V5";
      ok =
        failedMsgs (nixosFleetBase {
          self = "bob.desk";
          port = 7788;
          fleetVal = natFleet;
        }) == [ ];
    }
    {
      name = "u2 green: outbound-only gateway.mcp pure checkFinal passes";
      ok =
        cf {
          self = "gateway.mcp";
          file = gatewayGold;
        } == [ ];
    }
    {
      name = "u2 green: checkFinal accepts bare §4 goldens";
      ok =
        (
          cf {
            self = "alice.hub";
            file = aliceHubGold;
          } == [ ]
        )
        && (
          cf {
            self = "alice.laptop";
            file = aliceLaptopGold;
          } == [ ]
        )
        && (
          cf {
            self = "bob.desk";
            file = bobDeskGold;
          } == [ ]
        )
        && (
          cf {
            self = "gateway.mcp";
            file = gatewayGold;
          } == [ ]
        );
    }
    {
      name = "u2 green: checkFinal accepts wrapped §4 goldens";
      ok =
        (
          cf {
            self = "alice.hub";
            file = {
              peers = aliceHubGold;
            };
          } == [ ]
        )
        && (
          cf {
            self = "alice.laptop";
            file = {
              peers = aliceLaptopGold;
            };
          } == [ ]
        )
        && (
          cf {
            self = "bob.desk";
            file = {
              peers = bobDeskGold;
            };
          } == [ ]
        )
        && (
          cf {
            self = "gateway.mcp";
            file = {
              peers = gatewayGold;
            };
          } == [ ]
        );
    }
    {
      name = "u2 green: HM peersFile equals golden";
      ok =
        builtins.readFile (hmFleetBase { self = "alice.hub"; }).programs.xmsg.server.federation.peersFile
        == builtins.readFile ../../../tests/vectors/fleet/alice.hub.json
        &&
          builtins.readFile (hmFleetBase { self = "alice.laptop"; }).programs.xmsg.server.federation.peersFile
          == builtins.readFile ../../../tests/vectors/fleet/alice.laptop.json
        &&
          builtins.readFile (hmFleetBase { self = "bob.desk"; }).programs.xmsg.server.federation.peersFile
          == builtins.readFile ../../../tests/vectors/fleet/bob.desk.json;
    }
    {
      name = "u2 green: NixOS peersFile equals golden";
      ok =
        builtins.readFile
          (nixosFleetBase { self = "alice.hub"; }).services.xmsg.instances.main.federation.peersFile
        == builtins.readFile ../../../tests/vectors/fleet/alice.hub.json
        &&
          builtins.readFile
            (nixosFleetBase { self = "alice.laptop"; }).services.xmsg.instances.main.federation.peersFile
          == builtins.readFile ../../../tests/vectors/fleet/alice.laptop.json
        &&
          builtins.readFile
            (nixosFleetBase { self = "bob.desk"; }).services.xmsg.instances.main.federation.peersFile
          == builtins.readFile ../../../tests/vectors/fleet/bob.desk.json;
    }
    {
      name = "u2 green: observeCollector.fleet sets config.sources";
      ok =
        (evalHM {
          programs.xmsg = {
            enable = true;
            observeCollector.fleet = {
              value = baseFleet;
              self = "alice.collector";
            };
          };
        }).programs.xmsg.observeCollector.config.sources == fleet.collectorSourcesFor {
          fleet = baseFleet;
          self = "alice.collector";
        };
    }
    {
      name = "u2 green: non-fleet HM valid pin peer";
      ok =
        failedMsgs (hmStandalone {
          peer1 = {
            address = "p.example.org:7788";
            pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
            allow = [ "send" ];
          };
        }) == [ ];
    }
    {
      name = "u2 green: non-fleet NixOS valid pin peer";
      ok =
        failedMsgs (nixosStandalone {
          peer1 = {
            address = "p.example.org:7788";
            pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
            allow = [ "send" ];
          };
        }) == [ ];
    }
    {
      name = "u2 green: non-fleet HM valid pinFromCert peer";
      ok =
        failedMsgs (hmStandalone {
          peer1 = {
            address = "p.example.org:7788";
            pinFromCert = ./default.nix;
            allow = [ "send" ];
          };
        }) == [ ];
    }
    {
      name = "u2 green: non-fleet NixOS valid pinFromCert peer";
      ok =
        failedMsgs (nixosStandalone {
          peer1 = {
            address = "p.example.org:7788";
            pinFromCert = ./default.nix;
            allow = [ "send" ];
          };
        }) == [ ];
    }
    {
      name = "u2 green: checkFinal observe_labels with observe passes CS3 C6";
      ok =
        cf {
          file = aliceLaptopGold // {
            "ext.host" = extHost // {
              allow = [ "observe" ];
              observe_labels = true;
            };
          };
          hostOwned = [ "ext.host" ];
        } == [ ];
    }
    {
      name = "u2 green: checkFinal hostOwned dial=outbound without leaf passes CS3 C7";
      ok =
        cf {
          file = aliceLaptopGold // {
            "ext.host" = extHost // {
              dial = "outbound";
            };
          };
          hostOwned = [ "ext.host" ];
        } == [ ];
    }
    {
      name = "u2 green: checkFinal observe_labels omitted without observe passes CS3 C6 and K";
      ok =
        cf {
          file = aliceLaptopGold // {
            "ext.host" = extHost;
          };
          hostOwned = [ "ext.host" ];
        } == [ ];
    }
    {
      name = "u2 green: checkFinal observe_labels=false with observe passes CS3 C6 and K";
      ok =
        cf {
          file = aliceLaptopGold // {
            "ext.host" = extHost // {
              allow = [ "observe" ];
              observe_labels = false;
            };
          };
          hostOwned = [ "ext.host" ];
        } == [ ];
    }
    {
      name = "u2 green: checkFinal CA entry with principals, from, name==key passes K and C1-C7";
      ok =
        cf {
          file = aliceLaptopGold // {
            "ext.host" = extHost // {
              name = "ext.host";
              principals = [ "ci" ];
              from = [ "10.0.0.0/8" ];
            };
          };
          hostOwned = [ "ext.host" ];
        } == [ ];
    }
    {
      name = "u2 green: checkFinal leaf=false passes K(c) and C7";
      ok =
        cf {
          file = aliceLaptopGold // {
            "ext.host" = extHost // {
              leaf = false;
              dial = "outbound";
            };
          };
          hostOwned = [ "ext.host" ];
        } == [ ];
    }
    {
      name = "u2 green: checkFinal default_route=false passes K(c) and V3";
      ok =
        cf {
          file = aliceLaptopGold // {
            "ext.host" = extHost // {
              default_route = false;
            };
          };
          hostOwned = [ "ext.host" ];
        } == [ ];
    }
    {
      name = "u2 green: checkFinal wrapped with deny, reverse_observe, discovery passes S";
      ok =
        cf {
          file = {
            peers = aliceLaptopGold;
            deny = { };
            reverse_observe = { };
            discovery = { };
          };
        } == [ ];
    }
    {
      name = "u2 green: checkFinal bare with hub and deny members classified bare";
      ok =
        cf {
          file = aliceLaptopGold // {
            hub = extHost;
            deny = extHost;
          };
          hostOwned = [
            "hub"
            "deny"
          ];
        } == [ ];
    }
    {
      name = "u2 green: hostOwned entry with leaf=true passes V6 (M05)";
      ok =
        cf {
          file = aliceLaptopGold // {
            "ext.host" = extHost // {
              leaf = true;
            };
          };
          hostOwned = [ "ext.host" ];
        } == [ ];
    }
  ];

  u2Faults = [
    {
      name = "u2 fault V1: fleet entry differs from derived";
      ok = hasInfixAny "V1" (cfMsgs {
        file = aliceLaptopGold // {
          "alice.hub" = aliceLaptopGold."alice.hub" // {
            allow = [ "send" ];
          };
        };
      });
    }
    {
      name = "u2 fault V2: entry not derived and not in hostOwned";
      ok = hasInfixAny "V2" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost;
        };
      });
    }
    {
      name = "u2 fault V2: hostOwned name absent from file";
      ok = hasInfixAny "V2" (cfMsgs {
        file = aliceLaptopGold;
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault V2: hostOwned entry named for fleet node";
      ok = hasInfixAny "V2" (cfMsgs {
        file = aliceLaptopGold // {
          "bob.desk" = extHost;
        };
        hostOwned = [ "bob.desk" ];
      });
    }
    {
      name = "u2 fault V2: hostOwned entry carries fleet node identity";
      ok = hasInfixAny "V2" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            identities = [ "spiffe://example.org/host/desk/user/bob" ];
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault V2: hostOwned entry with pin";
      ok = hasInfixAny "V2" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = {
            address = "ext.example.org:7788";
            pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
            allow = [ "send" ];
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault V3: two default_route entries";
      ok = hasInfixAny "V3" (cfMsgs {
        file = aliceLaptopGold // {
          "alice.hub" = aliceLaptopGold."alice.hub" // {
            default_route = true;
          };
          "ext.host" = extHost // {
            default_route = true;
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault V4: entry with no ca (pin only)";
      ok = hasInfixAny "V4" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = {
            address = "ext.example.org:7788";
            pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
            allow = [ "send" ];
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 C1: pin and ca together";
      ok = hasInfixAny "set exactly one of pin, pinFromCert and ca." (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 C2: ca with no identities";
      ok = hasInfixAny "ca needs identities." (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = builtins.removeAttrs extHost [ "identities" ];
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 C3: identities with pin";
      ok = hasInfixAny "identities is only valid with ca" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = {
            address = "ext.example.org:7788";
            pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
            identities = [ "spiffe://ext.example.org/host/ext/user/ext" ];
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 C4: two identities";
      ok = hasInfixAny "identities holds exactly one identity." (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            identities = [
              "spiffe://ext.example.org/host/ext/user/ext"
              "spiffe://ext.example.org/host/ext2/user/ext"
            ];
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 C5: from = []";
      ok = hasInfixAny "from must hold at least one CIDR" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            from = [ ];
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 C6: observe_labels without observe";
      ok = hasInfixAny "observeLabels requires \"observe\" in allow." (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            observe_labels = true;
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 C6: observe_labels=true with allow absent";
      ok = hasInfixAny "observeLabels requires \"observe\" in allow." (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = (builtins.removeAttrs extHost [ "allow" ]) // {
            observe_labels = true;
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 C6: observe_labels=false without observe";
      ok = hasInfixAny "observeLabels requires \"observe\" in allow." (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            observe_labels = false;
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(b): pin null next to ca";
      ok = hasInfixAny "K(b)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            pin = null;
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(b): dial null";
      ok = hasInfixAny "K(b)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            dial = null;
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(b): from null";
      ok = hasInfixAny "K(b)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            from = null;
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(b): identities null next to ca";
      ok = hasInfixAny "K(b)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            identities = null;
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(b): allow null with observe_labels=true";
      ok = hasInfixAny "K(b)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            allow = null;
            observe_labels = true;
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(a): unknown key colour";
      ok = hasInfixAny "K(a)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            colour = "blue";
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(a): stray pinFromCert key";
      ok = hasInfixAny "K(a)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            pinFromCert = ./default.nix;
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(a): no_whois key";
      ok = hasInfixAny "K(a)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            no_whois = true;
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): observe_labels yes with observe";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            allow = [ "observe" ];
            observe_labels = "yes";
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): allow string";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            allow = "send";
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): allow string with observe_labels=true";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            allow = "send";
            observe_labels = true;
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): dial inbound";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            dial = "inbound";
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): leaf yes";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            leaf = "yes";
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): identities [ 1 ]";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            identities = [ 1 ];
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): identities [ str 1 ]";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            identities = [
              "spiffe://example.org/host/h"
              1
            ];
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): allow [ send 1 ]";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            allow = [
              "send"
              1
            ];
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): from [ cidr 1 ]";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            from = [
              "10.0.0.0/8"
              1
            ];
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): principals [ ci 1 ]";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            principals = [
              "ci"
              1
            ];
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): targets [ inbox 1 ]";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            targets = [
              "inbox"
              1
            ];
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): default_route yes";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            default_route = "yes";
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): name 1";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            name = 1;
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): address 7788";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            address = 7788;
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): pin 1 next to ca";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            pin = 1;
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): ca list";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            ca = [ "/a.crt" ];
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): from string";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            from = "10.0.0.0/8";
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): principals string";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            principals = "ci";
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): targets string";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            targets = "inbox";
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault S: wrapped unknown top-level key";
      ok = hasInfixAny "checkFinal S:" (cfMsgs {
        self = "alice.hub";
        file = {
          peers = aliceHubGold;
          colour = "blue";
        };
      });
    }
    {
      name = "u2 fault S: array form";
      ok = hasInfixAny "checkFinal S:" (cfMsgs {
        self = "alice.hub";
        file = [ extHost ];
      });
    }
    {
      name = "u2 fault S: top-level scalar";
      ok = hasInfixAny "checkFinal S:" (cfMsgs {
        self = "alice.hub";
        file = "x";
      });
    }
    {
      name = "u2 fault S: wrapped peers not attrset";
      ok = hasInfixAny "checkFinal S:" (cfMsgs {
        self = "alice.hub";
        file = {
          peers = [ ];
        };
      });
    }
    {
      name = "u2 fault S: bare non-object member";
      ok = hasInfixAny "checkFinal S[" (cfMsgs {
        self = "alice.hub";
        file = aliceHubGold // {
          h = "x";
        };
      });
    }
    {
      name = "u2 fault S: wrapped non-object member";
      ok = hasInfixAny "checkFinal S[" (cfMsgs {
        self = "alice.hub";
        file = {
          peers = aliceHubGold // {
            h = 1;
          };
        };
      });
    }
    {
      name = "u2 fault S: bare derived member not object";
      ok = hasInfixAny "checkFinal S[" (cfMsgs {
        self = "alice.hub";
        file = aliceHubGold // {
          "alice.laptop" = "x";
        };
      });
    }
    {
      name = "u2 fault V1: well-formed file omits derived entry";
      ok = hasInfixAny "V1" (cfMsgs {
        self = "alice.hub";
        file = builtins.removeAttrs aliceHubGold [ "alice.laptop" ];
      });
    }
    {
      name = "u2 fault CS3 K(c): hostOwned identities string under V2";
      ok = hasInfixAny "K(c)" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            identities = "spiffe://ext.example.org/host/ext/user/ext";
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault CS1 C6: non-fleet HM observeLabels without observe";
      ok = hasInfixAny "observeLabels requires \"observe\" in allow." (
        failedMsgs (hmStandalone {
          peer1 = {
            address = "p.example.org:7788";
            pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
            observeLabels = true;
          };
        })
      );
    }
    {
      name = "u2 fault CS2 C6: non-fleet NixOS observeLabels without observe";
      ok = hasInfixAny "observeLabels requires \"observe\" in allow." (
        failedMsgs (nixosStandalone {
          peer1 = {
            address = "p.example.org:7788";
            pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
            observeLabels = true;
          };
        })
      );
    }
    {
      name = "u2 fault CS3 C7: both leaf and dial";
      ok = hasInfixAny "leaf and dial cannot both be set." (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            leaf = true;
            dial = "outbound";
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault V6: leaf=true for fleet node/leaf with no mailbox grant";
      ok = hasInfixAny "V6" (cfMsgs {
        self = "alice.hub";
        file = aliceHubGold // {
          "alice.laptop" = aliceHubGold."alice.laptop" // {
            leaf = true;
          };
        };
      });
    }
    {
      name = "u2 fault V7: hostOwned with forward";
      ok = hasInfixAny "V7" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            allow = [ "forward" ];
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault V7: hostOwned with relayed";
      ok = hasInfixAny "V7" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            allow = [ "relayed" ];
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault V7: hostOwned with relay";
      ok = hasInfixAny "V7" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            allow = [ "relay" ];
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault V7: hostOwned with default_route";
      ok = hasInfixAny "V7" (cfMsgs {
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            default_route = true;
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault hub refusal: file with hub section";
      ok = hasInfixAny "hub refusal" (cfMsgs {
        file = {
          peers = aliceLaptopGold;
          hub = { };
        };
      });
    }
    {
      name = "u2 fault HM checkFinal: plain host definition merged onto derived entry";
      ok = hasInfixAny "V1" (
        failedMsgs (hmFleetBase {
          self = "alice.laptop";
          extraPeers."bob.desk".allow = [ "list" ];
        })
      );
    }
    {
      name = "u2 fault NixOS checkFinal: plain host definition merged onto derived entry";
      ok = hasInfixAny "V1" (
        failedMsgs (nixosFleetBase {
          self = "alice.laptop";
          extraPeers."bob.desk".allow = [ "list" ];
        })
      );
    }
    {
      name = "u2 fault HM P1: hostOwned with pinFromCert";
      ok = hasInfixAny "P1:" (
        failedMsgs (hmFleetBase {
          self = "alice.laptop";
          hostOwned = [ "ext.host" ];
          extraPeers."ext.host" = {
            address = "ext.example.org:7788";
            pinFromCert = ./default.nix;
            allow = [ "send" ];
          };
        })
      );
    }
    {
      name = "u2 fault NixOS P1: hostOwned with pinFromCert";
      ok = hasInfixAny "P1:" (
        failedMsgs (nixosFleetBase {
          self = "alice.laptop";
          hostOwned = [ "ext.host" ];
          extraPeers."ext.host" = {
            address = "ext.example.org:7788";
            pinFromCert = ./default.nix;
            allow = [ "send" ];
          };
        })
      );
    }
    {
      name = "u2 fault HM CS1 C1: pinFromCert added to derived entry";
      ok = hasInfixAny "set exactly one of pin, pinFromCert and ca." (
        failedMsgs (hmFleetBase {
          self = "alice.laptop";
          extraPeers."bob.desk".pinFromCert = ./default.nix;
        })
      );
    }
    {
      name = "u2 fault NixOS CS2 C1: pinFromCert added to derived entry";
      ok = hasInfixAny "set exactly one of pin, pinFromCert and ca." (
        failedMsgs (nixosFleetBase {
          self = "alice.laptop";
          extraPeers."bob.desk".pinFromCert = ./default.nix;
        })
      );
    }
    {
      name = "u2 fault HM CS1 C3: identities with pinFromCert";
      ok = hasInfixAny "identities is only valid with ca" (
        failedMsgs (hmFleetBase {
          self = "alice.laptop";
          hostOwned = [ "ext.host" ];
          extraPeers."ext.host" = {
            address = "ext.example.org:7788";
            pinFromCert = ./default.nix;
            identities = [ "spiffe://ext.example.org/host/ext/user/ext" ];
          };
        })
      );
    }
    {
      name = "u2 fault NixOS CS2 C3: identities with pinFromCert";
      ok = hasInfixAny "identities is only valid with ca" (
        failedMsgs (nixosFleetBase {
          self = "alice.laptop";
          hostOwned = [ "ext.host" ];
          extraPeers."ext.host" = {
            address = "ext.example.org:7788";
            pinFromCert = ./default.nix;
            identities = [ "spiffe://ext.example.org/host/ext/user/ext" ];
          };
        })
      );
    }
    {
      name = "u2 fault CS1 C1: non-fleet HM none of pin, pinFromCert, ca";
      ok = hasInfixAny "set exactly one of pin, pinFromCert and ca." (
        failedMsgs (hmStandalone {
          peer1 = {
            address = "p.example.org:7788";
          };
        })
      );
    }
    {
      name = "u2 fault CS2 C1: non-fleet NixOS none of pin, pinFromCert, ca";
      ok = hasInfixAny "set exactly one of pin, pinFromCert and ca." (
        failedMsgs (nixosStandalone {
          peer1 = {
            address = "p.example.org:7788";
          };
        })
      );
    }
    {
      name = "u2 fault CS1 C1: non-fleet HM pin and pinFromCert together";
      ok = hasInfixAny "set exactly one of pin, pinFromCert and ca." (
        failedMsgs (hmStandalone {
          peer1 = {
            address = "p.example.org:7788";
            pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
            pinFromCert = ./default.nix;
          };
        })
      );
    }
    {
      name = "u2 fault CS2 C1: non-fleet NixOS pin and pinFromCert together";
      ok = hasInfixAny "set exactly one of pin, pinFromCert and ca." (
        failedMsgs (nixosStandalone {
          peer1 = {
            address = "p.example.org:7788";
            pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
            pinFromCert = ./default.nix;
          };
        })
      );
    }
    {
      name = "u2 fault CS1 C5: non-fleet HM from = []";
      ok = hasInfixAny "from must hold at least one CIDR" (
        failedMsgs (hmStandalone {
          peer1 = {
            address = "p.example.org:7788";
            pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
            from = [ ];
          };
        })
      );
    }
    {
      name = "u2 fault CS2 C5: non-fleet NixOS from = []";
      ok = hasInfixAny "from must hold at least one CIDR" (
        failedMsgs (nixosStandalone {
          peer1 = {
            address = "p.example.org:7788";
            pin = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
            from = [ ];
          };
        })
      );
    }
    {
      name = "u2 fault CS1 C2: non-fleet HM ca with no identities";
      ok = hasInfixAny "ca needs identities." (
        failedMsgs (hmStandalone {
          peer1 = {
            address = "p.example.org:7788";
            ca = "/etc/xmsg/ca.crt";
          };
        })
      );
    }
    {
      name = "u2 fault CS2 C2: non-fleet NixOS ca with no identities";
      ok = hasInfixAny "ca needs identities." (
        failedMsgs (nixosStandalone {
          peer1 = {
            address = "p.example.org:7788";
            ca = "/etc/xmsg/ca.crt";
          };
        })
      );
    }
    {
      name = "u2 fault HM V5: federation.port differs from listenPort";
      ok = hasInfixAny "must equal fleet node" (
        failedMsgs (hmFleetBase {
          self = "alice.hub";
          port = 9999;
        })
      );
    }
    {
      name = "u2 fault NixOS V5: federation.port differs from listenPort";
      ok = hasInfixAny "must equal fleet node" (
        failedMsgs (nixosFleetBase {
          self = "alice.hub";
          port = 9999;
        })
      );
    }
    {
      name = "u2 fault HM module scope: self is a leaf";
      ok = hasInfixAny "must have kind == \"node\"" (
        failedMsgs (hmFleetBase {
          self = "gateway.mcp";
        })
      );
    }
    {
      name = "u2 fault HM module scope: self is a collector";
      ok = hasInfixAny "must have kind == \"node\"" (
        failedMsgs (hmFleetBase {
          self = "alice.collector";
        })
      );
    }
    {
      name = "u2 fault NixOS module scope: self is a leaf";
      ok = hasInfixAny "must have kind == \"node\"" (
        failedMsgs (nixosFleetBase {
          self = "gateway.mcp";
        })
      );
    }
    {
      name = "u2 fault NixOS module scope: self is a collector";
      ok = hasInfixAny "must have kind == \"node\"" (
        failedMsgs (nixosFleetBase {
          self = "alice.collector";
        })
      );
    }
    {
      name = "u2 fault HM module scope: federation.fleet with federation.enable = false";
      ok =
        !(builtins.tryEval (
          builtins.deepSeq (failedMsgs (evalHM {
            programs.xmsg = {
              enable = true;
              server = {
                enable = true;
                federation = {
                  enable = false;
                  fleet = {
                    value = baseFleet;
                    self = "alice.hub";
                  };
                };
              };
            };
          })) true
        )).success;
    }
    {
      name = "u2 fault NixOS module scope: federation.fleet with federation.enable = false";
      ok =
        !(builtins.tryEval (
          builtins.deepSeq (failedMsgs (evalNixos {
            services.xmsg.instances.main.federation = {
              enable = false;
              fleet = {
                value = baseFleet;
                self = "alice.hub";
              };
            };
          })) true
        )).success;
    }
    {
      name = "u2 fault HM V5: address :443 without listenPort and federation.port=7788 (M01)";
      ok = hasInfixAny "must equal fleet node" (
        failedMsgs (hmFleetBase {
          self = "bob.desk";
          port = 7788;
          fleetVal = addr443Fleet;
        })
      );
    }
    {
      name = "u2 fault NixOS V5: address :443 without listenPort and federation.port=7788 (M02)";
      ok = hasInfixAny "must equal fleet node" (
        failedMsgs (nixosFleetBase {
          self = "bob.desk";
          port = 7788;
          fleetVal = addr443Fleet;
        })
      );
    }
    {
      name = "u2 fault V2: hostOwned name equal to non-derived fleet node (M03)";
      ok = hasInfixAny "V2" (cfMsgs {
        self = "alice.laptop";
        file = aliceLaptopGold // {
          "gateway.mcp" = extHost;
        };
        hostOwned = [ "gateway.mcp" ];
      });
    }
    {
      name = "u2 fault V2: hostOwned identity equal to non-derived fleet node (M04)";
      ok = hasInfixAny "V2" (cfMsgs {
        self = "alice.laptop";
        file = aliceLaptopGold // {
          "ext.host" = extHost // {
            identities = [ "spiffe://example.org/ns/mcp/sa/gateway" ];
          };
        };
        hostOwned = [ "ext.host" ];
      });
    }
    {
      name = "u2 fault HM observeCollector.fleet: non-collector self throws (M17)";
      ok =
        !(builtins.tryEval (
          builtins.deepSeq
            (evalHM {
              programs.xmsg = {
                enable = true;
                observeCollector.fleet = {
                  value = baseFleet;
                  self = "alice.hub";
                };
              };
            }).programs.xmsg.observeCollector.config.sources
            true
        )).success;
    }
  ];
in
u2Positive ++ u2Faults
