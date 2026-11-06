{ pkgs, pin }:
let
  repository = builtins.match "https://github.com/([^/]+)/([^/]+)" pin.repository;
in
assert repository != null;
pkgs.fetchFromGitHub {
  name = "xmsg-${pin.revision}-source";
  owner = builtins.elemAt repository 0;
  repo = builtins.elemAt repository 1;
  rev = pin.revision;
  hash = pin.source_hash;
}
