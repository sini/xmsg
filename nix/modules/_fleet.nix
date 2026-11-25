# Pure fleet topology library (`lib.fleet`) — U1.
{ lib }:
let
  inherit (lib) mkOption types;
  xmsgLib = import ./_lib.nix { inherit lib; };

  allowEnumType = types.enum [
    "send"
    "reply"
    "list"
    "observe"
    "forward"
    "relayed"
    "relay"
  ];

  allowOrder = [
    "send"
    "reply"
    "list"
    "forward"
    "relayed"
    "observe"
  ];

  retiredPrefixes = [
    "svc:"
    "session:"
    "claude:"
    "agy:"
    "pi:"
    "http:"
  ];

  userOf = name: builtins.head (lib.splitString "." name);

  defaultIdentityFor =
    fleet: name: n:
    let
      td = if n.trustDomain != null then n.trustDomain else fleet.trustDomain;
      parts = lib.splitString "." name;
      first = builtins.head parts;
      second = lib.concatStringsSep "." (builtins.tail parts);
    in
    if n.kind == "collector" then
      "spiffe://${td}/host/collector/user/${first}"
    else if n.kind == "leaf" then
      "spiffe://${td}/ns/${second}/sa/${first}"
    else
      "spiffe://${td}/host/${second}/user/${first}";

  identityOf =
    fleet: name:
    let
      n = fleet.nodes.${name};
    in
    if n.identity != null then n.identity else defaultIdentityFor fleet name n;

  deriveNameFromUri =
    uri:
    let
      mHost = builtins.match "^spiffe://[^/]+/host/([^/]+)/user/([^/]+)$" uri;
      mNs = builtins.match "^spiffe://[^/]+/ns/([^/]+)/sa/([^/]+)$" uri;
    in
    if mHost != null then
      let
        host = builtins.elemAt mHost 0;
        user = builtins.elemAt mHost 1;
      in
      if host == "" || user == "" || lib.hasInfix "." host || lib.hasInfix "." user then
        null
      else
        "${user}.${host}"
    else if mNs != null then
      let
        ns = builtins.elemAt mNs 0;
        sa = builtins.elemAt mNs 1;
      in
      if ns == "" || sa == "" || lib.hasInfix "." ns || lib.hasInfix "." sa then null else "${sa}.${ns}"
    else
      null;

  validAddress =
    addr:
    if addr == null then
      false
    else
      let
        mV6Raw = builtins.match "^\\[([^/]+)]:([0-9]{1,5})$" addr;
        mV6 = if mV6Raw != null && !(lib.hasInfix "]" (builtins.elemAt mV6Raw 0)) then mV6Raw else null;
        mHost = builtins.match "^([^:@/]+):([0-9]{1,5})$" addr;
        portStr =
          if mV6 != null then
            builtins.elemAt mV6 1
          else if mHost != null then
            builtins.elemAt mHost 1
          else
            null;
        port = if portStr != null then lib.toIntBase10 portStr else 0;
      in
      portStr != null && !(lib.hasPrefix "0" portStr) && port >= 1 && port <= 65535;

  orderAllow = raw: lib.filter (op: builtins.elem op raw) allowOrder;

  normPolicy = p: {
    allow = orderAllow p.allow;
    targets = if p.targets == null then null else lib.sort builtins.lessThan (lib.unique p.targets);
    principals = lib.sort builtins.lessThan (lib.unique p.principals);
    inherit (p) observeLabels;
    mailbox = p.mailbox or false;
  };

  nodeType = types.submodule {
    options = {
      kind = mkOption {
        type = types.enum [
          "node"
          "leaf"
          "collector"
        ];
        default = "node";
      };
      address = mkOption {
        type = types.nullOr types.str;
        default = null;
      };
      addresses = mkOption {
        type = types.attrsOf types.str;
        default = { };
      };
      network = mkOption {
        type = types.nullOr types.str;
        default = null;
      };
      identity = mkOption {
        type = types.nullOr types.str;
        default = null;
      };
      trustDomain = mkOption {
        type = types.nullOr types.str;
        default = null;
      };
      ca = mkOption {
        type = types.nullOr (types.either types.path types.str);
        default = null;
      };
      from = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
      };
      listenPort = mkOption {
        type = types.nullOr types.port;
        default = null;
      };
      acceptRelayed = mkOption {
        type = types.listOf types.str;
        default = [ ];
      };
    };
  };

  meshType = types.submodule {
    options = {
      members = mkOption {
        type = types.listOf types.str;
        default = [ ];
      };
      allow = mkOption {
        type = types.listOf allowEnumType;
        default = [ ];
      };
      targets = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
      };
      principals = mkOption {
        type = types.listOf types.str;
        default = [ ];
      };
      observeLabels = mkOption {
        type = types.bool;
        default = false;
      };
    };
  };

  grantType = types.submodule {
    options = {
      allow = mkOption {
        type = types.listOf allowEnumType;
        default = [ ];
      };
      targets = mkOption {
        type = types.nullOr (types.listOf types.str);
        default = null;
      };
      principals = mkOption {
        type = types.listOf types.str;
        default = [ ];
      };
      observeLabels = mkOption {
        type = types.bool;
        default = false;
      };
      mailbox = mkOption {
        type = types.bool;
        default = false;
      };
      replace = mkOption {
        type = types.bool;
        default = false;
      };
    };
  };

  relayType = types.submodule {
    options = {
      via = mkOption {
        type = types.str;
      };
      to = mkOption {
        type = types.listOf types.str;
        default = [ ];
      };
    };
  };

  fleetType = types.submodule {
    options = {
      trustDomain = mkOption {
        type = types.str;
      };
      ca = mkOption {
        type = types.nullOr (types.either types.path types.str);
        default = null;
      };
      nodes = mkOption {
        type = types.attrsOf nodeType;
        default = { };
      };
      meshes = mkOption {
        type = types.listOf meshType;
        default = [ ];
      };
      grants = mkOption {
        type = types.attrsOf (types.attrsOf grantType);
        default = { };
      };
      relays = mkOption {
        type = types.attrsOf relayType;
        default = { };
      };
    };
  };

  evalFleet =
    raw:
    (lib.evalModules {
      modules = [
        {
          options.fleet = mkOption { type = fleetType; };
          config.fleet = raw;
        }
      ];
    }).config.fleet;

  effectiveGrant =
    fleet: g: e:
    let
      coveringMeshes = lib.filter (
        m: builtins.elem g m.members && builtins.elem e m.members
      ) fleet.meshes;
      hasExplicit = builtins.hasAttr g fleet.grants && builtins.hasAttr e fleet.grants.${g};
      explicit = fleet.grants.${g}.${e};
      base =
        if hasExplicit && (explicit.replace || coveringMeshes == [ ]) then
          {
            inherit (explicit)
              allow
              targets
              principals
              observeLabels
              mailbox
              ;
          }
        else if coveringMeshes != [ ] then
          let
            m = builtins.head coveringMeshes;
          in
          {
            inherit (m)
              allow
              targets
              principals
              observeLabels
              ;
            mailbox = false;
          }
        else
          null;
      relayForward = builtins.hasAttr e fleet.relays && fleet.relays.${e}.via == g;
      relayRelayed =
        builtins.elem e (fleet.nodes.${g}.acceptRelayed or [ ])
        && lib.any (r: r.via == e && builtins.elem g r.to) (builtins.attrValues fleet.relays);
    in
    if base == null then
      null
    else
      base
      // {
        allow = orderAllow (
          base.allow ++ lib.optional relayForward "forward" ++ lib.optional relayRelayed "relayed"
        );
      };

  check =
    raw:
    let
      fleet = evalFleet raw;
      nodes = fleet.nodes;
      nodeNames = builtins.attrNames nodes;
      isDeclared = n: builtins.hasAttr n nodes;

      # F1: every name in meshes, grants, relays, acceptRelayed is declared; no self-grant.
      f1Undeclared =
        lib.concatLists (
          lib.mapAttrsToList (
            g: gs:
            lib.optional (!isDeclared g) "F1: undeclared granter '${g}'"
            ++ lib.concatLists (
              lib.mapAttrsToList (
                e: _:
                lib.optional (!isDeclared e) "F1: undeclared grantee '${e}' under '${g}'"
                ++ lib.optional (g == e) "F1: self-grant on '${g}'"
              ) gs
            )
          ) fleet.grants
        )
        ++ lib.concatLists (
          lib.imap0 (
            i: m:
            lib.concatMap (
              mem: lib.optional (!isDeclared mem) "F1: undeclared mesh[${toString i}] member '${mem}'"
            ) m.members
          ) fleet.meshes
        )
        ++ lib.concatLists (
          lib.mapAttrsToList (
            l: r:
            lib.optional (!isDeclared l) "F1: undeclared relay key '${l}'"
            ++ lib.optional (!isDeclared r.via) "F1: undeclared relay '${l}' via '${r.via}'"
            ++ lib.concatMap (t: lib.optional (!isDeclared t) "F1: undeclared relay '${l}' to '${t}'") r.to
          ) fleet.relays
        )
        ++ lib.concatLists (
          lib.mapAttrsToList (
            name: n:
            lib.concatMap (
              h: lib.optional (!isDeclared h) "F1: undeclared acceptRelayed '${h}' on '${name}'"
            ) n.acceptRelayed
          ) nodes
        );

      # F2: node name equals identity's derived name; no node named <u>.collector.
      f2Msgs = lib.concatLists (
        lib.mapAttrsToList (
          name: n:
          let
            id = identityOf fleet name;
            derived = deriveNameFromUri id;
          in
          lib.optional (derived != name) "F2: node '${name}' identity '${id}' derives '${toString derived}'"
          ++ lib.optional (
            n.kind == "node" && lib.hasSuffix ".collector" name
          ) "F2: node '${name}' must not be named '*.collector'"
        ) nodes
      );

      # F3: identities unique, none contains '*'.
      idsList = map (name: {
        inherit name;
        id = identityOf fleet name;
      }) nodeNames;
      f3Wildcard = lib.concatMap (
        x: lib.optional (lib.hasInfix "*" x.id) "F3: wildcard identity '${x.id}' on '${x.name}'"
      ) idsList;
      idGroups = builtins.groupBy (x: x.id) idsList;
      f3Dup = lib.concatLists (
        lib.mapAttrsToList (
          id: xs:
          lib.optional (builtins.length xs > 1)
            "F3: duplicate identity '${id}' on ${lib.concatMapStringsSep ", " (x: x.name) xs}"
        ) idGroups
      );

      # F4: leaf links & addresses; leaf->hub requires hub->leaf mailbox; mailbox iff target is leaf.
      f4Msgs =
        lib.concatLists (
          lib.mapAttrsToList (
            name: n:
            if n.kind == "node" then
              lib.optional (
                !validAddress n.address
              ) "F4a: node '${name}' has invalid address '${toString n.address}'"
            else if n.kind == "leaf" then
              let
                partners = lib.unique (
                  (if builtins.hasAttr name fleet.grants then builtins.attrNames fleet.grants.${name} else [ ])
                  ++ lib.filter (g: builtins.hasAttr name (fleet.grants.${g} or { })) (
                    builtins.attrNames fleet.grants
                  )
                  ++ lib.optional (builtins.hasAttr name fleet.relays) fleet.relays.${name}.via
                );
              in
              lib.optional (partners == [ ]) "F4a: leaf '${name}' links no node"
              ++ lib.concatMap (
                p:
                lib.optional (
                  isDeclared p && nodes.${p}.kind != "node"
                ) "F4a: leaf '${name}' links non-node '${p}' (${nodes.${p}.kind})"
              ) partners
            else
              [ ]
          ) nodes
        )
        ++ lib.concatLists (
          lib.mapAttrsToList (
            l: r:
            lib.optional (
              isDeclared l
              && isDeclared r.via
              && nodes.${l}.kind == "leaf"
              && !((fleet.grants.${r.via}.${l}.mailbox or false))
            ) "F4b: relay '${l}' via '${r.via}' requires '${r.via}' to grant '${l}' mailbox = true"
          ) fleet.relays
        )
        ++ lib.concatLists (
          lib.mapAttrsToList (
            g: gs:
            lib.concatLists (
              lib.mapAttrsToList (
                e: gr:
                let
                  gIsLeaf = isDeclared g && nodes.${g}.kind == "leaf";
                  eIsLeaf = isDeclared e && nodes.${e}.kind == "leaf";
                in
                lib.optional (
                  gIsLeaf && isDeclared e && nodes.${e}.kind == "node" && !((fleet.grants.${e}.${g}.mailbox or false))
                ) "F4b: leaf '${g}' grant to '${e}' requires '${e}' to grant '${g}' mailbox = true"
                ++ lib.optional (eIsLeaf && !gr.mailbox) "F4c: grant '${g}' -> leaf '${e}' must set mailbox = true"
                ++ lib.optional (
                  !eIsLeaf && isDeclared e && gr.mailbox
                ) "F4c: grant '${g}' -> non-leaf '${e}' must not set mailbox = true"
              ) gs
            )
          ) fleet.grants
        );

      # F5: observe rules and collector restrictions (spec F5 erratum).
      f5Msgs =
        lib.concatLists (
          lib.mapAttrsToList (
            g: gs:
            lib.concatLists (
              lib.mapAttrsToList (
                e: gr:
                let
                  eIsCollector = isDeclared e && nodes.${e}.kind == "collector";
                  gIsNode = isDeclared g && nodes.${g}.kind == "node";
                  extraOps = lib.filter (op: op != "observe") gr.allow;
                  badRights =
                    if gr.allow == [ ] then
                      "none"
                    else if extraOps != [ ] then
                      lib.concatStringsSep ", " extraOps
                    else
                      "";
                in
                if eIsCollector then
                  lib.optional (
                    !gIsNode || userOf g != userOf e
                  ) "F5: grant '${g}' -> collector '${e}' must be from a node of '${userOf e}'"
                  ++
                    lib.optional (!(builtins.elem "observe" gr.allow) || extraOps != [ ])
                      "F5: grant '${g}' -> collector '${e}' must have allow = [ \"observe\" ] (offending rights: ${badRights})"
                  ++ lib.optional (
                    gr.targets != null || gr.principals != [ ]
                  ) "F5: grant '${g}' -> collector '${e}' must omit targets and principals"
                else
                  lib.optional (builtins.elem "observe" gr.allow) "F5: grant '${g}' -> '${e}' cannot grant observe to non-collector"
              ) gs
            )
          ) fleet.grants
        )
        ++ lib.concatLists (
          lib.imap0 (
            i: m:
            lib.optional (builtins.elem "observe" m.allow) "F5: mesh[${toString i}] must not grant observe"
          ) fleet.meshes
        )
        ++ lib.concatLists (
          lib.mapAttrsToList (
            name: n:
            if n.kind == "collector" then
              lib.optional (
                (fleet.grants.${name} or { }) != { }
              ) "F5: collector '${name}' must not grant anything"
              ++ lib.optional (
                builtins.hasAttr name fleet.relays
                || lib.any (r: r.via == name || builtins.elem name r.to) (builtins.attrValues fleet.relays)
                || n.acceptRelayed != [ ]
              ) "F5: collector '${name}' must take no part in a relay"
            else
              [ ]
          ) nodes
        );

      # F6: mesh members are nodes, >= 2 per mesh.
      f6Msgs = lib.concatLists (
        lib.imap0 (
          i: m:
          lib.optional (builtins.length m.members < 2) "F6: mesh[${toString i}] must have at least 2 members"
          ++ lib.concatMap (
            mem:
            lib.optional (
              isDeclared mem && nodes.${mem}.kind != "node"
            ) "F6: mesh[${toString i}] member '${mem}' is not a node"
          ) m.members
        ) fleet.meshes
      );

      # F7: relays (i)-(v).
      f7Msgs =
        lib.concatLists (
          lib.mapAttrsToList (
            l: r:
            let
              h = r.via;
              gHL = if isDeclared h && isDeclared l then effectiveGrant fleet h l else null;
            in
            lib.optional (isDeclared l && nodes.${l}.kind != "leaf") "F7(v): relay key '${l}' must be a leaf"
            ++ lib.optional (
              isDeclared h && nodes.${h}.kind != "node"
            ) "F7(v): relay '${l}' via '${h}' must be a node"
            ++ lib.optional (
              isDeclared l
              && isDeclared h
              && nodes.${l}.kind == "leaf"
              && nodes.${h}.kind == "node"
              && (gHL == null || !(builtins.elem "send" gHL.allow))
            ) "F7(iii): relay '${l}' via '${h}' requires G(${h}, ${l}) to include send"
            ++ lib.concatMap (
              dest:
              let
                gRH = if isDeclared dest && isDeclared h then effectiveGrant fleet dest h else null;
                gHR = if isDeclared h && isDeclared dest then effectiveGrant fleet h dest else null;
              in
              lib.optional (
                isDeclared dest && nodes.${dest}.kind != "node"
              ) "F7(iii): relay '${l}' to '${dest}' must be a node"
              ++ lib.optional (
                isDeclared dest && isDeclared h && !(builtins.elem h nodes.${dest}.acceptRelayed)
              ) "F7(i): relay '${l}' to '${dest}' via '${h}' lacks acceptRelayed on '${dest}'"
              ++ lib.optional (
                isDeclared dest
                && isDeclared h
                && nodes.${dest}.kind == "node"
                && (gRH == null || !(builtins.elem "send" gRH.allow))
              ) "F7(iii): relay '${l}' to '${dest}' via '${h}' requires G(${dest}, ${h}) to include send"
              ++ lib.optional (
                isDeclared dest
                && isDeclared h
                && nodes.${dest}.kind == "node"
                && (gHR == null || gHR.targets == [ ])
              ) "F7(iii): relay '${l}' to '${dest}' via '${h}' requires non-empty G(${h}, ${dest})"
            ) r.to
          ) fleet.relays
        )
        ++ lib.concatLists (
          lib.mapAttrsToList (
            dest: n:
            lib.concatMap (
              h:
              let
                relaysViaH = lib.filterAttrs (_: r: r.via == h) fleet.relays;
                anyHasDest = lib.any (r: builtins.elem dest r.to) (builtins.attrValues relaysViaH);
                allHaveDest = lib.all (r: builtins.elem dest r.to) (builtins.attrValues relaysViaH);
              in
              lib.optional (
                !anyHasDest
              ) "F7(iv): '${dest}' acceptRelayed '${h}' has no relay to '${dest}' via '${h}'"
              ++ lib.optional (
                anyHasDest && !allHaveDest
              ) "F7(ii): '${dest}' acceptRelayed '${h}' is missing from some relay via '${h}'"
            ) n.acceptRelayed
          ) nodes
        );

      # F8: no forward/relayed/relay in mesh/grant allow; observeLabels needs observe; non-empty & no retired prefixes.
      checkPolicyF8 =
        label: p:
        let
          forbiddenOps = lib.filter (
            op:
            builtins.elem op [
              "forward"
              "relayed"
              "relay"
            ]
          ) p.allow;
          badStrings = lib.filter (s: s == "" || lib.any (pre: lib.hasPrefix pre s) retiredPrefixes) (
            (if p.targets == null then [ ] else p.targets) ++ p.principals
          );
        in
        lib.optional (
          forbiddenOps != [ ]
        ) "F8: ${label} allow contains forbidden op(s): ${lib.concatStringsSep ", " forbiddenOps}"
        ++ lib.optional (
          p.observeLabels && !(builtins.elem "observe" p.allow)
        ) "F8: ${label} observeLabels requires observe in allow"
        ++ lib.optional (
          badStrings != [ ]
        ) "F8: ${label} targets/principals contains empty or retired string";

      f8Msgs =
        lib.concatLists (lib.imap0 (i: m: checkPolicyF8 "mesh[${toString i}]" m) fleet.meshes)
        ++ lib.concatLists (
          lib.mapAttrsToList (
            g: gs: lib.concatLists (lib.mapAttrsToList (e: gr: checkPolicyF8 "grant '${g}' -> '${e}'" gr) gs)
          ) fleet.grants
        );

      # F9: mesh conflict on a direction; explicit on mesh pair without replace; replace on uncovered pair.
      indexedMeshes = lib.imap0 (i: m: {
        inherit i m;
        norm = normPolicy m;
      }) fleet.meshes;
      f9MeshMsgs = lib.concatLists (
        builtins.map (
          a:
          lib.concatLists (
            builtins.map (
              b:
              if b.i <= a.i || a.norm == b.norm then
                [ ]
              else
                let
                  shared = lib.filter (x: builtins.elem x b.m.members) a.m.members;
                in
                lib.optional (
                  builtins.length shared >= 2
                ) "F9: mesh[${toString a.i}] and mesh[${toString b.i}] conflict on shared members"
            ) indexedMeshes
          )
        ) indexedMeshes
      );
      f9ExplicitMsgs = lib.concatLists (
        lib.mapAttrsToList (
          g: gs:
          lib.concatLists (
            lib.mapAttrsToList (
              e: gr:
              let
                covered = lib.any (m: builtins.elem g m.members && builtins.elem e m.members) fleet.meshes;
              in
              lib.optional (
                covered && !gr.replace
              ) "F9: explicit grant '${g}' -> '${e}' on mesh pair requires replace = true"
              ++ lib.optional (
                !covered && gr.replace
              ) "F9: explicit grant '${g}' -> '${e}' sets replace = true with no covering mesh"
            ) gs
          )
        ) fleet.grants
      );

      # F10: for two nodes of one user, G(a, b) is none iff G(b, a) is none.
      sameUserNodePairs = lib.concatLists (
        builtins.map (
          a:
          builtins.map
            (b: {
              inherit a b;
            })
            (
              lib.filter (
                b: a < b && nodes.${a}.kind == "node" && nodes.${b}.kind == "node" && userOf a == userOf b
              ) nodeNames
            )
        ) (lib.filter (a: nodes.${a}.kind == "node") nodeNames)
      );
      f10Msgs = lib.concatLists (
        builtins.map (
          pair:
          let
            ab = effectiveGrant fleet pair.a pair.b;
            ba = effectiveGrant fleet pair.b pair.a;
          in
          lib.optional (
            (ab == null) != (ba == null)
          ) "F10: one-sided grant between same-user nodes '${pair.a}' and '${pair.b}'"
        ) sameUserNodePairs
      );

      allFailures =
        f1Undeclared
        ++ f2Msgs
        ++ f3Wildcard
        ++ f3Dup
        ++ f4Msgs
        ++ f5Msgs
        ++ f6Msgs
        ++ f7Msgs
        ++ f8Msgs
        ++ f9MeshMsgs
        ++ f9ExplicitMsgs
        ++ f10Msgs;
    in
    if allFailures == [ ] then
      [ ]
    else
      map (message: {
        assertion = false;
        inherit message;
      }) allFailures;

  assertFleet =
    raw:
    let
      res = check raw;
    in
    if res == [ ] then
      evalFleet raw
    else
      builtins.throw (lib.concatMapStringsSep "\n" (c: c.message) res);

  portOf =
    viewer:
    if viewer.listenPort != null then
      toString viewer.listenPort
    else
      let
        m = builtins.match "^.*:([0-9]{1,5})$" (if viewer.address == null then "" else viewer.address);
      in
      if m != null then builtins.elemAt m 0 else "7788";

  addressFor =
    viewer: nName: n:
    if n.kind != "node" then
      "${nName}.invalid:${portOf viewer}"
    else if viewer.network != null && builtins.hasAttr viewer.network n.addresses then
      n.addresses.${viewer.network}
    else
      n.address;

  caFor =
    fleet: viewer:
    let
      raw = if viewer.ca != null then viewer.ca else fleet.ca;
    in
    if raw == null then null else "${raw}";

  peersFor =
    {
      fleet,
      self,
    }:
    let
      f = assertFleet fleet;
      viewer = f.nodes.${self};
      viewerCa = caFor f viewer;
      others = lib.filter (n: n != self) (builtins.attrNames f.nodes);
      mkEntry =
        nName:
        let
          n = f.nodes.${nName};
          # G(self, nName) is what nName may do at self; G(nName, self) is what self may do at nName.
          gIn = effectiveGrant f self nName;
          gOut = effectiveGrant f nName self;
          isDefaultRoute = viewer.kind == "leaf" && (f.relays.${self}.via or null) == nName;
        in
        if gIn == null && gOut == null then
          null
        else
          let
            allow = if gIn != null then gIn.allow else [ ];
            targets = if gIn != null then gIn.targets else [ ];
            principals = if gIn != null then gIn.principals else [ ];
            observeLabels = if gIn != null then gIn.observeLabels else false;
          in
          {
            address = addressFor viewer nName n;
            ca = viewerCa;
            identities = [ (identityOf f nName) ];
            inherit
              allow
              targets
              principals
              observeLabels
              ;
            from = n.from;
            leaf = n.kind == "leaf";
            defaultRoute = isDefaultRoute;
            pin = null;
            pinFromCert = null;
            dial = null;
          };
    in
    lib.filterAttrs (_: v: v != null) (lib.genAttrs others mkEntry);

  peersRenderedFor = args: lib.mapAttrs xmsgLib.renderPeer (peersFor args);

  peersJsonFor = args: builtins.toJSON (peersRenderedFor args);

  collectorSourcesFor =
    {
      fleet,
      self,
    }:
    let
      # N8 equivalence (counting any grant to self) holds unconditionally because assertFleet throws on F5 first and self is a collector.
      f = assertFleet fleet;
      viewer = f.nodes.${self};
      viewerCa = caFor f viewer;
      sources = lib.filter (
        nName:
        let
          g = effectiveGrant f nName self;
        in
        g != null && builtins.elem "observe" g.allow
      ) (lib.sort builtins.lessThan (builtins.attrNames f.nodes));
    in
    if viewer.kind != "collector" then
      builtins.throw "collectorSourcesFor: '${self}' is not a collector"
    else
      map (nName: {
        node = nName;
        address = addressFor viewer nName f.nodes.${nName};
        identity = identityOf f nName;
        ca = viewerCa;
      }) sources;

  reachableFor =
    {
      fleet,
      self,
    }:
    let
      f = assertFleet fleet;
      direct = lib.filter (
        nName:
        let
          g = effectiveGrant f nName self;
        in
        nName != self && g != null && builtins.elem "send" g.allow
      ) (lib.sort builtins.lessThan (builtins.attrNames f.nodes));
      relayed =
        if builtins.hasAttr self f.relays then
          [
            {
              inherit (f.relays.${self}) via;
              to = lib.sort builtins.lessThan f.relays.${self}.to;
            }
          ]
        else
          [ ];
    in
    {
      inherit direct relayed;
    };
  checkFinal =
    {
      value,
      self,
      file,
      hostOwned ? [ ],
    }:
    let
      f = assertFleet value;
      derived = peersRenderedFor {
        fleet = value;
        inherit self;
      };
      derivedNames = builtins.attrNames derived;
      fleetIdentities = map (n: identityOf f n) (builtins.attrNames f.nodes);

      # S: file structure classification by `peers` key alone.
      isFileAttrs = builtins.isAttrs file;
      isWrapped = isFileAttrs && builtins.hasAttr "peers" file;
      knownTopKeys = [
        "peers"
        "hub"
        "deny"
        "reverse_observe"
        "discovery"
      ];
      sTopFailures =
        if !isFileAttrs then
          [ "checkFinal S: peers file must be an attrset." ]
        else if isWrapped then
          (lib.optional (builtins.hasAttr "hub" file) "checkFinal hub refusal: 'hub' section is not allowed in fleet peers files.")
          ++ (map (k: "checkFinal S: unknown top-level key '${k}' in wrapped peers file.") (
            lib.filter (k: !(builtins.elem k knownTopKeys)) (builtins.attrNames file)
          ))
          ++ (lib.optional (
            !builtins.isAttrs file.peers
          ) "checkFinal S: 'peers' in wrapped peers file must be an attrset.")
        else
          [ ];

      rawEntries =
        if !isFileAttrs then
          { }
        else if isWrapped then
          (if builtins.isAttrs file.peers then file.peers else { })
        else
          file;

      sMemberFailures = lib.concatLists (
        lib.mapAttrsToList (
          name: val:
          lib.optional (!builtins.isAttrs val) "checkFinal S[${name}]: peer entry must be an attrset."
        ) rawEntries
      );

      validMembers = lib.filterAttrs (_: builtins.isAttrs) rawEntries;

      # K: canonical spelling of raw entries (CS3 only).
      allowedEntryKeys = [
        "name"
        "address"
        "pin"
        "ca"
        "identities"
        "allow"
        "from"
        "leaf"
        "principals"
        "targets"
        "dial"
        "default_route"
        "observe_labels"
      ];
      boolKeys = [
        "leaf"
        "observe_labels"
        "default_route"
      ];
      strKeys = [
        "name"
        "address"
        "pin"
        "ca"
      ];
      listStrKeys = [
        "identities"
        "allow"
        "from"
        "principals"
        "targets"
      ];
      isValidKeyType =
        k: v:
        if builtins.elem k boolKeys then
          builtins.isBool v
        else if builtins.elem k strKeys then
          builtins.isString v
        else if k == "dial" then
          builtins.isString v && v == "outbound"
        else if builtins.elem k listStrKeys then
          builtins.isList v && lib.all builtins.isString v
        else
          true;

      kFailures = lib.concatLists (
        lib.mapAttrsToList (
          name: raw:
          let
            keys = builtins.attrNames raw;
            ka = map (k: "checkFinal K(a)[${name}]: unknown key '${k}'.") (
              lib.filter (k: !(builtins.elem k allowedEntryKeys)) keys
            );
            kb = map (k: "checkFinal K(b)[${name}]: key '${k}' must not be null.") (
              lib.filter (k: raw.${k} == null) keys
            );
            kc = map (k: "checkFinal K(c)[${name}]: key '${k}' has invalid type or value.") (
              lib.filter (
                k: builtins.elem k allowedEntryKeys && raw.${k} != null && !(isValidKeyType k raw.${k})
              ) keys
            );
          in
          ka ++ kb ++ kc
        ) validMembers
      );

      strippedMembers = lib.mapAttrs (
        _: raw: lib.filterAttrs (k: v: v != null && isValidKeyType k v) raw
      ) validMembers;

      viewFor = stripped: {
        pin = stripped.pin or null;
        pinFromCert = null;
        ca = stripped.ca or null;
        identities = stripped.identities or null;
        from = stripped.from or null;
        observeLabels = builtins.hasAttr "observe_labels" stripped;
        allow = stripped.allow or [ ];
        leaf = stripped.leaf or false;
        dial = stripped.dial or null;
      };

      cs3Failures = lib.concatLists (
        lib.mapAttrsToList (
          name: stripped: xmsgLib.peerAssertions "checkFinal CS3[${name}]" (viewFor stripped)
        ) strippedMembers
      );

      # V1: each derived entry equals its derived rendering (total, never unguarded lookup).
      v1Failures = lib.concatLists (
        map (
          n:
          if !(builtins.hasAttr n strippedMembers) then
            [ "checkFinal V1: derived entry '${n}' is missing from peers file." ]
          else if strippedMembers.${n} != derived.${n} then
            [ "checkFinal V1: derived entry '${n}' differs from fleet-derived rendering." ]
          else
            [ ]
        ) derivedNames
      );

      # V2: names lie in derived U hostOwned; every hostOwned present; no fleet name/identity collision; no pin.
      v2ExtraFailures = lib.concatLists (
        lib.mapAttrsToList (
          n: _:
          lib.optional (
            !(builtins.hasAttr n derived) && !(builtins.elem n hostOwned)
          ) "checkFinal V2: entry '${n}' is neither derived from fleet nor listed in hostOwned."
        ) strippedMembers
      );
      v2HostOwnedFailures = lib.concatLists (
        map (
          h:
          (lib.optional (
            !(builtins.hasAttr h strippedMembers)
          ) "checkFinal V2: hostOwned entry '${h}' is missing from peers file.")
          ++ (lib.optional (builtins.hasAttr h f.nodes) "checkFinal V2: hostOwned name '${h}' collides with a fleet node.")
          ++ lib.optionals (builtins.hasAttr h strippedMembers) (
            let
              e = strippedMembers.${h};
            in
            (lib.optional (builtins.any (id: builtins.elem id fleetIdentities) (
              e.identities or [ ]
            )) "checkFinal V2: hostOwned entry '${h}' carries a fleet node's identity.")
            ++ (lib.optional (builtins.hasAttr "pin" e) "checkFinal V2: hostOwned entry '${h}' must not use pin in fleet mode.")
          )
        ) hostOwned
      );

      # V3: at most one default_route.
      defaultRouteNames = lib.filter (n: (strippedMembers.${n}.default_route or false) == true) (
        builtins.attrNames strippedMembers
      );
      v3Failures =
        lib.optional (builtins.length defaultRouteNames > 1)
          "checkFinal V3: at most one entry may set default_route (found: ${lib.concatStringsSep ", " defaultRouteNames}).";

      # V4: CA-only clause (reads CS3 view).
      v4Failures = lib.concatLists (
        lib.mapAttrsToList (
          n: stripped:
          lib.optional (
            (viewFor stripped).ca == null
          ) "checkFinal V4: entry '${n}' must use ca (CA-only in fleet mode)."
        ) strippedMembers
      );

      # V6: every leaf = true entry is derived from a mailbox grant or is hostOwned.
      v6Failures = lib.concatLists (
        lib.mapAttrsToList (
          n: e:
          let
            isDerivedLeaf = builtins.hasAttr n derived && (derived.${n}.leaf or false) == true;
          in
          lib.optional ((e.leaf or false) == true && !isDerivedLeaf && !(builtins.elem n hostOwned))
            "checkFinal V6: leaf = true on '${n}' is only valid for a fleet mailbox leaf or a hostOwned entry."
        ) strippedMembers
      );

      # V7: forward/relayed/relay only on derived entries matching §6; no hostOwned carries them or default_route.
      relayRights = [
        "forward"
        "relayed"
        "relay"
      ];
      hasRelayRight = e: builtins.any (r: builtins.elem r (e.allow or [ ])) relayRights;
      v7Failures = lib.concatLists (
        lib.mapAttrsToList (
          n: e:
          if builtins.elem n hostOwned then
            (lib.optional (hasRelayRight e) "checkFinal V7: hostOwned entry '${n}' must not grant forward, relayed, or relay.")
            ++ (lib.optional (
              (e.default_route or false) == true
            ) "checkFinal V7: hostOwned entry '${n}' must not set default_route.")
          else if builtins.hasAttr n derived then
            let
              dRelay = lib.filter (r: builtins.elem r (derived.${n}.allow or [ ])) relayRights;
              eRelay = lib.filter (r: builtins.elem r (e.allow or [ ])) relayRights;
            in
            lib.optional (
              dRelay != eRelay
            ) "checkFinal V7: relay rights on '${n}' must match fleet-derived §6 rights."
          else
            lib.optional (hasRelayRight e) "checkFinal V7: non-derived entry '${n}' must not grant forward, relayed, or relay."
        ) strippedMembers
      );

      allMessages =
        sTopFailures
        ++ sMemberFailures
        ++ kFailures
        ++ v1Failures
        ++ v2ExtraFailures
        ++ v2HostOwnedFailures
        ++ v3Failures
        ++ v4Failures
        ++ v6Failures
        ++ v7Failures;
    in
    (map (message: {
      assertion = false;
      inherit message;
    }) allMessages)
    ++ cs3Failures;
in
{
  type = fleetType;
  inherit
    check
    checkFinal
    peersFor
    peersRenderedFor
    peersJsonFor
    collectorSourcesFor
    reachableFor
    ;
}
