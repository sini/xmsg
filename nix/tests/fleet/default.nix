{
  pkgs,
  lib,
  fleet,
}:
let
  baseFleet = {
    trustDomain = "example.org";
    ca = "/etc/xmsg/ca/root.crt";
    nodes = {
      "alice.hub" = {
        address = "hub.example.net:7788";
        addresses.lan = "10.0.0.2:7788";
      };
      "alice.laptop" = {
        address = "laptop.example.net:7788";
        acceptRelayed = [ "alice.hub" ];
      };
      "bob.desk" = {
        address = "desk.example.net:7788";
        from = [ "192.0.2.0/24" ];
      };
      "gateway.mcp" = {
        kind = "leaf";
        network = "lan";
        ca = "/etc/xmsg/tls/ca.crt";
      };
      "alice.collector" = {
        kind = "collector";
      };
    };
    meshes = [
      {
        members = [
          "alice.hub"
          "alice.laptop"
        ];
        allow = [
          "send"
          "reply"
          "list"
        ];
      }
      {
        members = [
          "alice.hub"
          "alice.laptop"
          "bob.desk"
        ];
        allow = [
          "send"
          "reply"
          "list"
        ];
      }
    ];
    grants = {
      "alice.hub"."gateway.mcp" = {
        mailbox = true;
        allow = [
          "send"
          "reply"
          "list"
        ];
      };
      "gateway.mcp"."alice.hub" = {
        allow = [
          "send"
          "reply"
          "list"
        ];
      };
      "bob.desk"."alice.laptop" = {
        replace = true;
        allow = [
          "send"
          "reply"
        ];
        targets = [ "inbox" ];
        principals = [ "ci" ];
      };
      "alice.hub"."alice.collector" = {
        allow = [ "observe" ];
      };
      "alice.laptop"."alice.collector" = {
        allow = [ "observe" ];
      };
    };
    relays."gateway.mcp" = {
      via = "alice.hub";
      to = [ "alice.laptop" ];
    };
  };

  nothingGrantedFleet = {
    trustDomain = "example.org";
    ca = "/etc/xmsg/ca/root.crt";
    nodes = {
      "alice.hub" = {
        address = "hub.example.net:7788";
      };
      "carol.x" = {
        address = "x.example.net:7788";
      };
    };
    grants."carol.x"."alice.hub".allow = [ "send" ];
  };

  v6Fleet = {
    trustDomain = "example.org";
    ca = "/etc/xmsg/tls/ca.crt";
    nodes."alice.v6".address = "[::1]:7788";
  };

  # _lib.nix defaultRoute check
  xmsgLib = import ../../modules/_lib.nix { inherit lib; };
  evalPeer =
    cfg:
    (lib.evalModules {
      modules = [
        {
          options.p = lib.mkOption { type = xmsgLib.peerType; };
          config.p = cfg;
        }
      ];
    }).config.p;
  renderedDefault = xmsgLib.renderPeer "h" (evalPeer { });
  renderedRoute = xmsgLib.renderPeer "h" (evalPeer {
    defaultRoute = true;
  });
  libChecks = [
    {
      name = "renderPeer omits default_route when false";
      ok = !(builtins.hasAttr "default_route" renderedDefault);
    }
    {
      name = "renderPeer emits default_route=true when true";
      ok = (renderedRoute.default_route or null) == true;
    }
  ];

  # Positive checks
  goldenChecks = [
    {
      name = "golden alice.hub";
      ok =
        fleet.peersJsonFor {
          fleet = baseFleet;
          self = "alice.hub";
        } == builtins.readFile ../../../tests/vectors/fleet/alice.hub.json;
    }
    {
      name = "golden alice.laptop";
      ok =
        fleet.peersJsonFor {
          fleet = baseFleet;
          self = "alice.laptop";
        } == builtins.readFile ../../../tests/vectors/fleet/alice.laptop.json;
    }
    {
      name = "golden bob.desk";
      ok =
        fleet.peersJsonFor {
          fleet = baseFleet;
          self = "bob.desk";
        } == builtins.readFile ../../../tests/vectors/fleet/bob.desk.json;
    }
    {
      name = "golden gateway.mcp";
      ok =
        fleet.peersJsonFor {
          fleet = baseFleet;
          self = "gateway.mcp";
        } == builtins.readFile ../../../tests/vectors/fleet/gateway.mcp.json;
    }
    {
      name = "golden nothing-granted";
      ok =
        fleet.peersJsonFor {
          fleet = nothingGrantedFleet;
          self = "alice.hub";
        } == builtins.readFile ../../../tests/vectors/fleet/nothing-granted.json;
    }
    {
      name = "collectorSourcesFor";
      ok =
        fleet.collectorSourcesFor {
          fleet = baseFleet;
          self = "alice.collector";
        } == [
          {
            node = "alice.hub";
            address = "hub.example.net:7788";
            identity = "spiffe://example.org/host/hub/user/alice";
            ca = "/etc/xmsg/ca/root.crt";
          }
          {
            node = "alice.laptop";
            address = "laptop.example.net:7788";
            identity = "spiffe://example.org/host/laptop/user/alice";
            ca = "/etc/xmsg/ca/root.crt";
          }
        ];
    }
    {
      name = "reachableFor";
      ok =
        fleet.reachableFor {
          fleet = baseFleet;
          self = "gateway.mcp";
        } == {
          direct = [ "alice.hub" ];
          relayed = [
            {
              via = "alice.hub";
              to = [ "alice.laptop" ];
            }
          ];
        };
    }
    {
      name = "baseFleet clean";
      ok = fleet.check baseFleet == [ ];
    }
    {
      name = "ipv6 literal [::1]:7788 passes F4a";
      ok = fleet.check v6Fleet == [ ];
    }
    {
      name = "B2 leaf/collector invalid address uses viewer listenPort/address port";
      ok =
        let
          f9000 = baseFleet // {
            nodes = baseFleet.nodes // {
              "alice.hub" = baseFleet.nodes."alice.hub" // {
                address = "hub.example.net:9000";
              };
            };
          };
          f7000 = baseFleet // {
            nodes = baseFleet.nodes // {
              "alice.hub" = baseFleet.nodes."alice.hub" // {
                listenPort = 7000;
              };
            };
          };
          p9000 = fleet.peersRenderedFor {
            fleet = f9000;
            self = "alice.hub";
          };
          p7000 = fleet.peersRenderedFor {
            fleet = f7000;
            self = "alice.hub";
          };
        in
        p9000."gateway.mcp".address == "gateway.mcp.invalid:9000"
        && p9000."alice.collector".address == "alice.collector.invalid:9000"
        && p7000."gateway.mcp".address == "gateway.mcp.invalid:7000";
    }
    {
      name = "N3/N4/N7 second-hub non-relay grant has no forward, no default_route, not in reachableFor.direct";
      ok =
        let
          twoHub = baseFleet // {
            grants = baseFleet.grants // {
              "bob.desk" = (baseFleet.grants."bob.desk" or { }) // {
                "gateway.mcp" = {
                  mailbox = true;
                  allow = [ "list" ];
                };
              };
              "gateway.mcp" = baseFleet.grants."gateway.mcp" // {
                "bob.desk".allow = [ "list" ];
              };
            };
          };
          bobPeers = fleet.peersRenderedFor {
            fleet = twoHub;
            self = "bob.desk";
          };
          gwPeers = fleet.peersRenderedFor {
            fleet = twoHub;
            self = "gateway.mcp";
          };
          gwReach = fleet.reachableFor {
            fleet = twoHub;
            self = "gateway.mcp";
          };
        in
        !(builtins.elem "forward" bobPeers."gateway.mcp".allow)
        && (gwPeers."alice.hub".default_route or false)
        && !(gwPeers."bob.desk".default_route or false)
        && gwReach.direct == [ "alice.hub" ];
    }
    {
      name = "N10 unnormalised allow renders deduplicated in enum order";
      ok =
        let
          fUnnorm = baseFleet // {
            grants = baseFleet.grants // {
              "bob.desk" = (baseFleet.grants."bob.desk" or { }) // {
                "alice.laptop" = {
                  replace = true;
                  allow = [
                    "list"
                    "send"
                    "reply"
                    "send"
                  ];
                };
              };
            };
          };
          p = fleet.peersRenderedFor {
            fleet = fUnnorm;
            self = "bob.desk";
          };
        in
        p."alice.laptop".allow == [
          "send"
          "reply"
          "list"
        ];
    }
    {
      name = "N4 reachableFor on mesh node excludes self";
      ok =
        let
          r = fleet.reachableFor {
            fleet = baseFleet;
            self = "alice.hub";
          };
        in
        !(builtins.elem "alice.hub" r.direct);
    }
    {
      name = "F5 positive control: observeLabels = true on collector observe grant passes";
      ok =
        fleet.check (
          baseFleet
          // {
            grants = baseFleet.grants // {
              "alice.hub" = baseFleet.grants."alice.hub" // {
                "alice.collector" = {
                  allow = [ "observe" ];
                  observeLabels = true;
                };
              };
            };
          }
        ) == [ ];
    }
  ];

  # Fault helper: assert clause prefix appears in check messages.
  expectFault =
    name: prefix: badFleet:
    let
      res = fleet.check badFleet;
      msgs = map (c: c.message) (lib.filter (c: !c.assertion) res);
    in
    {
      inherit name;
      ok = lib.any (m: lib.hasPrefix prefix m) msgs;
    };

  faults = [
    # F1
    (expectFault "F1 undeclared granter" "F1:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "ghost.box"."alice.hub".allow = [ "send" ];
        };
      }
    ))
    (expectFault "F1 undeclared grantee" "F1:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "ghost.box".allow = [ "send" ];
          };
        };
      }
    ))
    (expectFault "F1 undeclared mesh member" "F1:" (
      baseFleet
      // {
        meshes = baseFleet.meshes ++ [
          {
            members = [
              "alice.hub"
              "ghost.box"
            ];
            allow = [ "send" ];
          }
        ];
      }
    ))
    (expectFault "F1 undeclared relay key" "F1:" (
      baseFleet
      // {
        relays = baseFleet.relays // {
          "ghost.leaf".via = "alice.hub";
        };
      }
    ))
    (expectFault "F1 undeclared relay via" "F1:" (
      baseFleet
      // {
        relays = {
          "gateway.mcp" = {
            via = "ghost.hub";
            to = [ "alice.laptop" ];
          };
        };
      }
    ))
    (expectFault "F1 undeclared relay to" "F1:" (
      baseFleet
      // {
        relays = {
          "gateway.mcp" = {
            via = "alice.hub";
            to = [ "ghost.box" ];
          };
        };
      }
    ))
    (expectFault "F1 undeclared acceptRelayed" "F1:" (
      baseFleet
      // {
        nodes = baseFleet.nodes // {
          "alice.laptop" = baseFleet.nodes."alice.laptop" // {
            acceptRelayed = [ "ghost.hub" ];
          };
        };
      }
    ))
    (expectFault "F1 self-grant" "F1:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "alice.hub".allow = [ "send" ];
          };
        };
      }
    ))

    # F2
    (expectFault "F2 identity mismatch" "F2:" (
      baseFleet
      // {
        nodes = baseFleet.nodes // {
          "bob.desk" = baseFleet.nodes."bob.desk" // {
            identity = "spiffe://example.org/host/other/user/bob";
          };
        };
      }
    ))
    (expectFault "F2 node named *.collector" "F2:" {
      trustDomain = "example.org";
      ca = "/etc/xmsg/tls/ca.crt";
      nodes."alice.collector" = {
        kind = "node";
        address = "c.example.net:7788";
        identity = "spiffe://example.org/host/collector/user/alice";
      };
    })

    # F3
    (expectFault "F3 duplicate identity" "F3:" (
      baseFleet
      // {
        nodes = baseFleet.nodes // {
          "bob.desk" = baseFleet.nodes."bob.desk" // {
            identity = "spiffe://example.org/host/hub/user/alice";
          };
        };
      }
    ))
    (expectFault "F3 wildcard identity" "F3:" (
      baseFleet
      // {
        nodes = baseFleet.nodes // {
          "bob.desk" = baseFleet.nodes."bob.desk" // {
            identity = "spiffe://example.org/host/*/user/bob";
          };
        };
      }
    ))

    # F4a
    (expectFault "F4a leaf links leaf" "F4a:" (
      baseFleet
      // {
        nodes = baseFleet.nodes // {
          "other.leaf" = {
            kind = "leaf";
          };
        };
        grants = baseFleet.grants // {
          "gateway.mcp" = baseFleet.grants."gateway.mcp" // {
            "other.leaf" = {
              mailbox = true;
              allow = [ "send" ];
            };
          };
        };
      }
    ))
    (expectFault "F4a leaf links collector" "F4a:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "gateway.mcp" = baseFleet.grants."gateway.mcp" // {
            "zed.collector".allow = [ "send" ];
          };
        };
        nodes = baseFleet.nodes // {
          "zed.collector".kind = "collector";
        };
      }
    ))
    (expectFault "F4a leaf links no node" "F4a:" {
      trustDomain = "example.org";
      ca = "/etc/xmsg/tls/ca.crt";
      nodes."lonely.leaf".kind = "leaf";
    })
    (expectFault "F4a node no address" "F4a:" {
      trustDomain = "example.org";
      ca = "/etc/xmsg/tls/ca.crt";
      nodes."alice.hub" = { };
    })
    (expectFault "F4a address no port" "F4a:" {
      trustDomain = "example.org";
      ca = "/etc/xmsg/tls/ca.crt";
      nodes."alice.hub".address = "hub.example.net";
    })
    (expectFault "F4a empty host" "F4a:" {
      trustDomain = "example.org";
      ca = "/etc/xmsg/tls/ca.crt";
      nodes."alice.hub".address = ":7788";
    })
    (expectFault "F4a port 0" "F4a:" {
      trustDomain = "example.org";
      ca = "/etc/xmsg/tls/ca.crt";
      nodes."alice.hub".address = "h:0";
    })
    (expectFault "F4a port 65536" "F4a:" {
      trustDomain = "example.org";
      ca = "/etc/xmsg/tls/ca.crt";
      nodes."alice.hub".address = "h:65536";
    })
    (expectFault "F4a oversized port (totality)" "F4a:" {
      trustDomain = "example.org";
      ca = "/etc/xmsg/tls/ca.crt";
      nodes."alice.hub".address = "h:99999999999999999999";
    })
    (expectFault "F4a non-numeric port" "F4a:" {
      trustDomain = "example.org";
      ca = "/etc/xmsg/tls/ca.crt";
      nodes."alice.hub".address = "h:http";
    })
    (expectFault "F4a userinfo in host" "F4a:" {
      trustDomain = "example.org";
      ca = "/etc/xmsg/tls/ca.crt";
      nodes."alice.hub".address = "u@h:7788";
    })
    (expectFault "F4a slash in host" "F4a:" {
      trustDomain = "example.org";
      ca = "/etc/xmsg/tls/ca.crt";
      nodes."alice.hub".address = "h/x:7788";
    })
    (expectFault "F4a unbracketed ipv6" "F4a:" {
      trustDomain = "example.org";
      ca = "/etc/xmsg/tls/ca.crt";
      nodes."alice.hub".address = "::1:7788";
    })

    # F4b & F4c
    (expectFault "F4b leaf grant without hub mailbox" "F4b:" {
      trustDomain = "example.org";
      ca = "/etc/xmsg/tls/ca.crt";
      nodes = {
        "alice.hub".address = "hub.example.net:7788";
        "gateway.mcp".kind = "leaf";
      };
      grants = {
        "gateway.mcp"."alice.hub".allow = [ "send" ];
        "alice.hub"."gateway.mcp".allow = [ "send" ];
      };
    })
    (expectFault "F4b leaf grant with no hub grant" "F4b:" {
      trustDomain = "example.org";
      ca = "/etc/xmsg/tls/ca.crt";
      nodes = {
        "alice.hub".address = "hub.example.net:7788";
        "gateway.mcp".kind = "leaf";
      };
      grants."gateway.mcp"."alice.hub".allow = [ "send" ];
    })
    (expectFault "F4b relay via hub without mailbox" "F4b:" {
      trustDomain = "example.org";
      ca = "/etc/xmsg/tls/ca.crt";
      nodes = {
        "alice.hub".address = "hub.example.net:7788";
        "bob.desk".address = "bob.example.net:7788";
        "gateway.mcp".kind = "leaf";
      };
      relays."gateway.mcp" = {
        via = "alice.hub";
        to = [ "bob.desk" ];
      };
    })
    (expectFault "F4c leaf grant without mailbox" "F4c:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "gateway.mcp" = {
              mailbox = false;
              allow = [ "send" ];
            };
          };
        };
      }
    ))
    (expectFault "F4c mailbox on non-leaf" "F4c:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "bob.desk" = {
              replace = true;
              mailbox = true;
              allow = [ "send" ];
            };
          };
        };
      }
    ))

    # F5
    (expectFault "F5 observe cross-user" "F5:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "bob.desk" = baseFleet.grants."bob.desk" // {
            "alice.collector".allow = [ "observe" ];
          };
        };
      }
    ))
    (expectFault "F5 observe to non-collector" "F5:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "alice.laptop" = {
              replace = true;
              allow = [ "observe" ];
            };
          };
        };
      }
    ))
    (expectFault "F5 observe with send" "F5:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "alice.collector".allow = [
              "observe"
              "send"
            ];
          };
        };
      }
    ))
    (expectFault "F5 observe with targets" "F5:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "alice.collector" = {
              allow = [ "observe" ];
              targets = [ "inbox" ];
            };
          };
        };
      }
    ))
    (expectFault "F5 observe with principals" "F5:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "alice.collector" = {
              allow = [ "observe" ];
              principals = [ "ci" ];
            };
          };
        };
      }
    ))
    (expectFault "F5 same-user send-only to collector" "F5:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "alice.collector".allow = [ "send" ];
          };
        };
      }
    ))
    (expectFault "F5 same-user list-only to collector" "F5:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "alice.collector".allow = [ "list" ];
          };
        };
      }
    ))
    (expectFault "F5 same-user observe+list to collector" "F5:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "alice.collector".allow = [
              "observe"
              "list"
            ];
          };
        };
      }
    ))
    (expectFault "F5 same-user observe+reply to collector" "F5:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "alice.collector".allow = [
              "observe"
              "reply"
            ];
          };
        };
      }
    ))
    (expectFault "F5 same-user empty allow to collector" "F5:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "alice.collector".allow = [ ];
          };
        };
      }
    ))
    {
      name = "F5 cross-user send to collector names bob.desk, alice.collector and send";
      ok =
        let
          res = fleet.check (
            baseFleet
            // {
              grants = baseFleet.grants // {
                "bob.desk" = (baseFleet.grants."bob.desk" or { }) // {
                  "alice.collector".allow = [ "send" ];
                };
              };
            }
          );
          msgs = map (c: c.message) (lib.filter (c: !c.assertion) res);
        in
        lib.any (
          m:
          lib.hasPrefix "F5:" m
          && lib.hasInfix "bob.desk" m
          && lib.hasInfix "alice.collector" m
          && lib.hasInfix "send" m
        ) msgs;
    }
    {
      name = "F5c same-user observe+send+list to collector names both send and list";
      ok =
        let
          res = fleet.check (
            baseFleet
            // {
              grants = baseFleet.grants // {
                "alice.hub" = baseFleet.grants."alice.hub" // {
                  "alice.collector".allow = [
                    "observe"
                    "send"
                    "list"
                  ];
                };
              };
            }
          );
          msgs = map (c: c.message) (lib.filter (c: !c.assertion) res);
        in
        lib.any (m: lib.hasPrefix "F5:" m && lib.hasInfix "send" m && lib.hasInfix "list" m) msgs;
    }
    {
      name = "D2/B3 unknown op sned in grant allow is an eval error";
      ok =
        !(builtins.tryEval (
          builtins.deepSeq (fleet.check (
            baseFleet
            // {
              grants = baseFleet.grants // {
                "gateway.mcp" = baseFleet.grants."gateway.mcp" // {
                  "alice.hub".allow = [
                    "sned"
                    "reply"
                  ];
                };
              };
            }
          )) true
        )).success;
    }
    {
      name = "D2b unknown op sned in mesh allow is an eval error";
      ok =
        !(builtins.tryEval (
          builtins.deepSeq (fleet.check (
            baseFleet
            // {
              meshes = [
                {
                  members = [
                    "alice.hub"
                    "alice.laptop"
                  ];
                  allow = [
                    "sned"
                    "reply"
                  ];
                }
              ];
            }
          )) true
        )).success;
    }
    {
      name = "N3 mesh mailbox = true is rejected";
      ok =
        !(builtins.tryEval (
          builtins.deepSeq (fleet.check (
            baseFleet
            // {
              meshes = [
                {
                  members = [
                    "alice.hub"
                    "alice.laptop"
                  ];
                  allow = [ "send" ];
                  mailbox = true;
                }
              ];
            }
          )) true
        )).success;
    }
    (expectFault "F5 collector grants something" "F5:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.collector"."alice.hub".allow = [ "send" ];
        };
      }
    ))
    (expectFault "F5 collector as relay via" "F5:" (
      baseFleet
      // {
        relays = {
          "gateway.mcp" = {
            via = "alice.collector";
            to = [ "alice.laptop" ];
          };
        };
      }
    ))
    (expectFault "F5 collector in relay to" "F5:" (
      baseFleet
      // {
        relays = {
          "gateway.mcp" = {
            via = "alice.hub";
            to = [ "alice.collector" ];
          };
        };
      }
    ))

    # F6
    (expectFault "F6 mesh one member" "F6:" (
      baseFleet
      // {
        meshes = [
          {
            members = [ "alice.hub" ];
            allow = [ "send" ];
          }
        ];
      }
    ))
    (expectFault "F6 leaf in mesh" "F6:" (
      baseFleet
      // {
        meshes = baseFleet.meshes ++ [
          {
            members = [
              "alice.hub"
              "gateway.mcp"
            ];
            allow = [ "send" ];
          }
        ];
      }
    ))
    (expectFault "F6 collector in mesh" "F6:" (
      baseFleet
      // {
        meshes = baseFleet.meshes ++ [
          {
            members = [
              "alice.hub"
              "alice.collector"
            ];
            allow = [ "send" ];
          }
        ];
      }
    ))

    # F7
    (expectFault "F7(i) relay without recipient consent (two recipients, bad second)" "F7(i):" (
      baseFleet
      // {
        relays = {
          "gateway.mcp" = {
            via = "alice.hub";
            to = [
              "alice.laptop"
              "bob.desk"
            ];
          };
        };
      }
    ))
    (expectFault "F7(ii) two leaves via one hub with different to" "F7(ii):" (
      baseFleet
      // {
        nodes = baseFleet.nodes // {
          "other.mcp".kind = "leaf";
        };
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "other.mcp" = {
              mailbox = true;
              allow = [
                "send"
                "reply"
                "list"
              ];
            };
          };
        };
        relays = baseFleet.relays // {
          "other.mcp" = {
            via = "alice.hub";
            to = [ "bob.desk" ];
          };
        };
      }
    ))
    (expectFault "F7(iii) G(H,L) without send" "F7(iii):" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "gateway.mcp" = {
              mailbox = true;
              allow = [ "list" ];
            };
          };
        };
      }
    ))
    (expectFault "F7(iii) G(R,H) without send" "F7(iii):" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.laptop" = baseFleet.grants."alice.laptop" // {
            "alice.hub" = {
              replace = true;
              allow = [ "list" ];
            };
          };
        };
      }
    ))
    (expectFault "F7(iii) G(H,R) none (two recipients, bad second)" "F7(iii):" (
      baseFleet
      // {
        nodes = baseFleet.nodes // {
          "bob.desk" = baseFleet.nodes."bob.desk" // {
            acceptRelayed = [ "alice.hub" ];
          };
        };
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "bob.desk" = {
              replace = true;
              allow = [ "send" ];
              targets = [ ];
            };
          };
          "bob.desk" = (baseFleet.grants."bob.desk" or { }) // {
            "alice.hub".allow = [ "send" ];
          };
        };
        relays = {
          "gateway.mcp" = {
            via = "alice.hub";
            to = [
              "alice.laptop"
              "bob.desk"
            ];
          };
        };
      }
    ))
    (expectFault "F7(iii) G(H,R) targets=[]" "F7(iii):" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "alice.laptop" = {
              replace = true;
              allow = [ "send" ];
              targets = [ ];
            };
          };
        };
      }
    ))
    (expectFault "F7(iii) relay to leaf" "F7(iii):" (
      baseFleet
      // {
        relays = {
          "gateway.mcp" = {
            via = "alice.hub";
            to = [ "gateway.mcp" ];
          };
        };
      }
    ))
    (expectFault "F7(iv) acceptRelayed with no relay to it" "F7(iv):" (
      baseFleet
      // {
        nodes = baseFleet.nodes // {
          "bob.desk" = baseFleet.nodes."bob.desk" // {
            acceptRelayed = [ "alice.hub" ];
          };
        };
      }
    ))
    (expectFault "F7(v) relay key is a node" "F7(v):" (
      baseFleet
      // {
        relays = {
          "bob.desk" = {
            via = "alice.hub";
            to = [ "alice.laptop" ];
          };
        };
      }
    ))

    # F8
    (expectFault "F8 forward in explicit grant" "F8:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "bob.desk" = {
              replace = true;
              allow = [
                "send"
                "forward"
              ];
            };
          };
        };
      }
    ))
    (expectFault "F8 forward in mesh allow" "F8:" (
      baseFleet
      // {
        meshes = [
          {
            members = [
              "alice.hub"
              "alice.laptop"
            ];
            allow = [
              "send"
              "forward"
            ];
          }
        ];
      }
    ))
    (expectFault "F8 relayed in explicit grant" "F8:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "bob.desk" = {
              replace = true;
              allow = [
                "send"
                "relayed"
              ];
            };
          };
        };
      }
    ))
    (expectFault "F8 relayed in mesh allow" "F8:" (
      baseFleet
      // {
        meshes = [
          {
            members = [
              "alice.hub"
              "alice.laptop"
            ];
            allow = [
              "send"
              "relayed"
            ];
          }
        ];
      }
    ))
    (expectFault "F8 relay in explicit grant" "F8:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "bob.desk" = {
              replace = true;
              allow = [
                "send"
                "relay"
              ];
            };
          };
        };
      }
    ))
    (expectFault "F8 relay in mesh allow" "F8:" (
      baseFleet
      // {
        meshes = [
          {
            members = [
              "alice.hub"
              "alice.laptop"
            ];
            allow = [
              "send"
              "relay"
            ];
          }
        ];
      }
    ))
    (expectFault "F8 observeLabels without observe" "F8:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "bob.desk" = {
              replace = true;
              allow = [ "send" ];
              observeLabels = true;
            };
          };
        };
      }
    ))
    (expectFault "F8 empty target string" "F8:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "bob.desk" = {
              replace = true;
              allow = [ "send" ];
              targets = [ "" ];
            };
          };
        };
      }
    ))
    (expectFault "F8 empty principal string" "F8:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "bob.desk" = {
              replace = true;
              allow = [ "send" ];
              principals = [ "" ];
            };
          };
        };
      }
    ))
    (expectFault "F8 retired kind in targets" "F8:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "bob.desk" = {
              replace = true;
              allow = [ "send" ];
              targets = [ "svc:inbox" ];
            };
          };
        };
      }
    ))
    (expectFault "F8 retired kind in principals" "F8:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "bob.desk" = {
              replace = true;
              allow = [ "send" ];
              principals = [ "session:abc" ];
            };
          };
        };
      }
    ))

    # F9
    (expectFault "F9 conflicting meshes" "F9:" {
      trustDomain = "example.org";
      ca = "/etc/xmsg/tls/ca.crt";
      nodes = {
        "alice.hub".address = "hub.example.net:7788";
        "bob.desk".address = "bob.example.net:7788";
      };
      meshes = [
        {
          members = [
            "alice.hub"
            "bob.desk"
          ];
          allow = [ "send" ];
        }
        {
          members = [
            "alice.hub"
            "bob.desk"
          ];
          allow = [
            "send"
            "reply"
          ];
        }
      ];
    })
    (expectFault "F9 explicit on mesh pair without replace" "F9:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "bob.desk" = {
            "alice.laptop" = {
              allow = [ "send" ];
            };
          };
        };
      }
    ))
    (expectFault "F9 replace on uncovered pair" "F9:" (
      baseFleet
      // {
        grants = baseFleet.grants // {
          "alice.hub" = baseFleet.grants."alice.hub" // {
            "gateway.mcp" = {
              mailbox = true;
              replace = true;
              allow = [ "send" ];
            };
          };
        };
      }
    ))

    # F10
    (expectFault "F10 one-sided grant between same-user nodes" "F10:" {
      trustDomain = "example.org";
      ca = "/etc/xmsg/tls/ca.crt";
      nodes = {
        "alice.hub".address = "hub.example.net:7788";
        "alice.laptop".address = "laptop.example.net:7788";
      };
      grants."alice.hub"."alice.laptop".allow = [ "send" ];
    })
  ];

  # No-bypass throw checks (tryEval + deepSeq)
  badFleet = baseFleet // {
    grants = baseFleet.grants // {
      "ghost.box"."alice.hub".allow = [ "send" ];
    };
  };
  noBypass = name: r: {
    inherit name;
    ok = !(builtins.tryEval (builtins.deepSeq r r)).success;
  };
  noBypassChecks = [
    (noBypass "no-bypass peersFor" (
      fleet.peersFor {
        fleet = badFleet;
        self = "alice.hub";
      }
    ))
    (noBypass "no-bypass peersRenderedFor" (
      fleet.peersRenderedFor {
        fleet = badFleet;
        self = "alice.hub";
      }
    ))
    (noBypass "no-bypass peersJsonFor" (
      fleet.peersJsonFor {
        fleet = badFleet;
        self = "alice.hub";
      }
    ))
    (noBypass "no-bypass collectorSourcesFor" (
      fleet.collectorSourcesFor {
        fleet = badFleet;
        self = "alice.collector";
      }
    ))
    (noBypass "no-bypass reachableFor" (
      fleet.reachableFor {
        fleet = badFleet;
        self = "gateway.mcp";
      }
    ))
  ];

  allChecks = libChecks ++ goldenChecks ++ faults ++ noBypassChecks;
  failures = lib.filter (c: !c.ok) allChecks;
in
if failures == [ ] then
  pkgs.runCommand "check-fleet" { } ''
    echo "fleet-check-complete:${toString (builtins.length allChecks)}" > $out
  ''
else
  builtins.throw "fleet check failed:\n${
    lib.concatMapStringsSep "\n" (c: "  FAIL ${c.name}") failures
  }"
