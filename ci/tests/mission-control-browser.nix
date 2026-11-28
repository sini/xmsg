{ inputs, lib, ... }:
{
  perSystem =
    { pkgs, system, ... }:
    let
      package = inputs.xmsg.packages.${system}.default;
      py = pkgs.python3.withPackages (ps: [ ps.playwright ]);
    in
    {
      checks = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
        mission-control-browser =
          pkgs.runCommand "xmsg-mission-control-browser"
            {
              nativeBuildInputs = [
                pkgs.nodejs
                pkgs.esbuild
                py
                pkgs.chromium
                pkgs.openssl
              ];
              src = package.src;
            }
            ''
              set -euo pipefail
              export HOME="$TMPDIR/browser-home"
              export XDG_CONFIG_HOME="$TMPDIR/browser-config"
              export XDG_CACHE_HOME="$TMPDIR/browser-cache"
              mkdir -p "$HOME" "$XDG_CONFIG_HOME" "$XDG_CACHE_HOME" "$out"
              cd "$src"
              node web/mc-roster/build.mjs --check | tee "$out/bundle-freshness.log"
              node --experimental-strip-types --test tests/mc_roster_unit.mjs | tee "$out/mc-roster-unit.log"
              python3 tests/tmjs_web_roster_browser.py \
                --assets-dir assets/mc-roster \
                --chromium "${lib.getExe pkgs.chromium}" | tee "$out/mission-control-browser.log"
              python3 tests/tmjs_wr8b_live_acceptance.py \
                --xmsg-bin "${package}/bin/xmsg" \
                --assets-dir assets/mc-roster \
                --chromium "${lib.getExe pkgs.chromium}" | tee "$out/tmjs-wr8b-live-acceptance.log"
            '';
      };
    };
}
