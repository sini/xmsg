# Shared helpers for homeManagerModules.xmsg and nixosModules.xmsg.
{ lib }:
let
  inherit (lib) mkOption types;

  peerType = types.submodule {
    options = {
      address = mkOption {
        type = types.nullOr types.str;
        default = null;
        description = "The peer's federation endpoint, `host:port`. Omit it for a leaf, a peer reached through the default route, or an exact-identity peer (a pin, or a CA entry with one identity) that an enabled discovery source finds; the loader refuses any other omission.";
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
            "observe"
          ]
        );
        default = [ ];
        description = "Operations the peer may perform here, as the loader reads them (src/fed.rs): on a hub, `forward` relays the peer's sends; on a recipient, `relayed` (or `relay`) accepts what the peer relays (README 7.7); `observe` allows fleet observation reads.";
      };
      observeLabels = mkOption {
        type = types.bool;
        default = false;
        description = "Include observed session labels in `observe` responses; requires `\"observe\"` in `allow` (src/fed.rs).";
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
    // lib.optionalAttrs p.observeLabels { observe_labels = true; }
    // lib.optionalAttrs (p.principals != [ ]) { inherit (p) principals; };

  mkPeersFile =
    pkgs: peers:
    let
      peersJson = builtins.toJSON (lib.mapAttrs renderPeer peers);
      pinned = lib.filterAttrs (_: p: p.pinFromCert != null) peers;
      peersBase = pkgs.writeText "xmsg-peers.json" peersJson;
    in
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
in
{
  inherit peerType mkPeersFile;
}
