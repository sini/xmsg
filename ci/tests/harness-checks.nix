# Checks that run this revision's code (Linux only: agy's presence locks are read from
# /proc/locks, and the darwin job builds only `checks.package`).
#
# - `agy-hook` (plan oracle 3): the command the module renders into agy's hooks.json, run by a
#   fake agy against a real `xmsg serve`, registers the fake agy's conversation C, and C is
#   addressed as C. Only Arm A is tested: here /proc/locks and the children file are readable,
#   so the hook registers C itself. B′ (non-Linux, or no children file: the hook answers with an
#   inject step) has no sandbox oracle.
# - `opencode-plugin` (XH2 oracles 8-11, release, restart): the real opencode, with the plugin file the module
#   renders, against a real `xmsg serve` and a mock model on loopback
#   (extensions/opencode/check.py). This is nixpkgs' opencode, 1.x.
# - `opencode2-plugin`: the same oracles against opencode 2.x, llm-agents.nix's `opencode2`.
# - `hermes-plugin` (XH3 oracles 1-6): the real hermes CLI on a pty, and hermes's tui_gateway
#   (the desktop host), with the plugin and config.yaml settings the module renders, against a
#   real `xmsg serve` and a mock model on loopback (extensions/hermes/check.py).
# - `pi-extension`, `pi-paths`: the pi extension's own node tests (extensions/pi). The
#   extension's darwin `getconf DARWIN_USER_TEMP_DIR` fallback is not covered by CI.
{ inputs, ... }:
{
  perSystem =
    {
      pkgs,
      lib,
      system,
      ...
    }:
    let
      inherit (inputs)
        xmsg
        home-manager
        hermes-agent
        llm-agents
        ;
      xmsgPkg = xmsg.packages.${system}.default;

      hooksJson =
        (home-manager.lib.homeManagerConfiguration {
          inherit pkgs;
          modules = [
            xmsg.homeManagerModules.xmsg
            {
              home = {
                username = "alice";
                homeDirectory = "/home/alice";
                stateVersion = "25.11";
                enableNixpkgsReleaseCheck = false;
              };
              programs.antigravity-cli = {
                enable = true;
                package = pkgs.runCommand "antigravity-cli-fixture" { } "mkdir -p $out/bin; touch $out/bin/agy";
              };
              programs.xmsg = {
                enable = true;
                harnesses.agy.enable = true;
              };
            }
          ];
        }).config.home.file.".gemini/config/hooks.json".source;

      # One agy turn, run by the fake agy (`flock`, holding C's presence lock): the
      # PreInvocation hook with C on stdin, then the turn's command with agy's language-server
      # credentials in its environment. The turn ends in a child without those credentials, so
      # the lock holder outlives the turn but a later registration finds nothing to read.
      agyTurn = pkgs.writeShellScript "agy-turn" ''
        hook=$1 conv=$2 done=$3
        out=$(printf '{"conversationId":"%s"}' "$conv" | sh -c "$hook")
        echo "agy-hook: hook printed: $out"
        export ANTIGRAVITY_CONVERSATION_ID=$conv ANTIGRAVITY_LS_ADDRESS=127.0.0.1:1 ANTIGRAVITY_CSRF_TOKEN=fixture-token
        sleep 1
        touch "$done"
        exec env -u ANTIGRAVITY_LS_ADDRESS -u ANTIGRAVITY_CSRF_TOKEN sleep 120
      '';

      opencodePlugin =
        (home-manager.lib.homeManagerConfiguration {
          inherit pkgs;
          modules = [
            xmsg.homeManagerModules.xmsg
            {
              home = {
                username = "alice";
                homeDirectory = "/home/alice";
                stateVersion = "25.11";
                enableNixpkgsReleaseCheck = false;
              };
              programs.xmsg = {
                enable = true;
                harnesses.opencode.enable = true;
              };
            }
          ];
        }).config.xdg.configFile."opencode/plugin/xmsg.ts".source;

      # The hermes switch's rendering: its one plugin and its config.yaml settings.
      hermesCfg =
        (home-manager.lib.homeManagerConfiguration {
          inherit pkgs;
          modules = [
            xmsg.homeManagerModules.xmsg
            hermes-agent.homeManagerModules.default
            {
              home = {
                username = "alice";
                homeDirectory = "/home/alice";
                stateVersion = "25.11";
                enableNixpkgsReleaseCheck = false;
              };
              services.hermes-agent.enable = true;
              programs.xmsg = {
                enable = true;
                harnesses.hermes.enable = true;
              };
            }
          ];
        }).config.services.hermes-agent;
      hermesPlugin = lib.head hermesCfg.extraPlugins;
      hermesSettings = pkgs.writeText "hermes-settings.json" (builtins.toJSON hermesCfg.settings);

      opencodeCheck =
        name: opencode:
        pkgs.runCommand "xmsg-${name}" { nativeBuildInputs = [ pkgs.python3 ]; } ''
          python3 ${../../extensions/opencode/check.py} ${lib.getExe xmsgPkg} ${lib.getExe opencode} ${opencodePlugin}
          touch $out
        '';

      nodeCheck =
        name: script:
        pkgs.runCommand "xmsg-${name}"
          {
            nativeBuildInputs = [
              pkgs.nodejs
              pkgs.pi-coding-agent
              pkgs.which
            ];
          }
          ''
            export HOME=$TMPDIR
            node ${../../extensions/pi}/${script}
            touch $out
          '';
    in
    {
      checks = lib.optionalAttrs pkgs.stdenv.hostPlatform.isLinux {
        pi-extension = nodeCheck "pi-extension" "test.mjs";
        pi-paths = nodeCheck "pi-paths" "test-paths.mjs";

        opencode-plugin = opencodeCheck "opencode-plugin" pkgs.opencode;
        opencode2-plugin = opencodeCheck "opencode2-plugin" llm-agents.packages.${system}.opencode2;

        hermes-plugin =
          pkgs.runCommand "xmsg-hermes-plugin"
            {
              nativeBuildInputs = [
                pkgs.python3
              ];
            }
            ''
              python3 ${../../extensions/hermes/check.py} ${lib.getExe xmsgPkg} ${
                lib.getExe' hermes-agent.packages.${system}.default "hermes"
              } ${hermesPlugin} ${hermesSettings}
              touch $out
            '';

        agy-hook =
          pkgs.runCommand "xmsg-agy-hook"
            {
              nativeBuildInputs = [
                pkgs.jq
                pkgs.curl
                pkgs.socat
                pkgs.util-linux
              ];
            }
            ''
              export HOME=$TMPDIR/home XDG_RUNTIME_DIR=$TMPDIR/run
              mkdir -p "$HOME/.gemini/antigravity-cli/presence" "$XDG_RUNTIME_DIR"
              chmod 700 "$XDG_RUNTIME_DIR"
              sock=$XDG_RUNTIME_DIR/xmsg
              conv=4a111111-2222-4333-8444-555555555555
              lock=$HOME/.gemini/antigravity-cli/presence/$conv.lock
              : > "$lock"
              hook=$(jq -er '."xmsg-register".PreInvocation[0].command' ${hooksJson})
              echo "agy-hook: rendered hook command: $hook"

              fail() {
                echo "agy-hook: $*" >&2
                echo "--- xmsg serve log ---" >&2
                cat serve.log >&2
                kill "$agy" "$serve" 2>/dev/null
                exit 1
              }
              waitfor() {
                for _ in $(seq 200); do
                  [ -e "$1" ] && return 0
                  sleep 0.1
                done
                return 1
              }

              # The fake agy's executable is flock: it holds C's presence lock and runs the turn.
              ${lib.getExe xmsgPkg} serve --agy-exe ${pkgs.util-linux}/bin/flock --db-path "$TMPDIR/xmsg.db" > serve.log 2>&1 &
              serve=$!
              agy=
              waitfor "$sock/register.sock" || fail "xmsg serve did not open register.sock"
              waitfor "$sock/http.sock" || fail "xmsg serve did not open http.sock"

              flock "$lock" ${agyTurn} "$hook" "$conv" "$TMPDIR/turn-done" &
              agy=$!
              waitfor "$TMPDIR/turn-done" || fail "the agy turn did not finish"

              # One check frame: it reports whether C holds credentials, i.e. is registered.
              check=$(printf '{"action":"check","conversation_id":"%s"}\n' "$conv" | socat -t 2 - "UNIX-CONNECT:$sock/register.sock")
              echo "agy-hook: check: $check"
              [ "$(printf '%s' "$check" | jq -r .hasCredentials)" = true ] \
                || fail "the hook command did not register conversation $conv: $check"

              listed=$(curl -sf --unix-socket "$sock/http.sock" http://localhost/v1/recipients) \
                || fail "GET /v1/recipients failed"
              echo "agy-hook: recipients: $listed"
              printf '%s' "$listed" | jq -e --arg c "$conv" \
                'any(.recipients[]; .kind == "instance" and .address == "\($c)@\(.node)")' > /dev/null \
                || fail "conversation $conv is not addressed as $conv: $listed"

              kill "$agy" "$serve"
              echo "agy-hook: the rendered hook registered $conv, addressed as $conv"
              touch $out
            '';
      };
    };
}
