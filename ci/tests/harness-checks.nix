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
# - `pre-xl1-compat` (XF3.1): runs `gate_xf3_list_compat_and_agy_label` with `XMSG_PRE_XL1_BIN`
#   pointing at the pre-XL1 (`9096199`) binary (`doCheck = false`) and asserts that the live
#   two-binary subprocess oracle actually ran (no skip line).
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
      xmsgPreXl1Src = pkgs.fetchFromGitHub {
        owner = "sini";
        repo = "xmsg";
        rev = "909619979ce2669ed2051a08d2f587d60b1f0d21";
        hash = "sha256-JGE3MFESq632euR3kWgONgv9P9VO9fuZTHgIJ+NP7uk=";
      };
      xmsgPreXl1 = pkgs.rustPlatform.buildRustPackage {
        pname = "xmsg-pre-xl1";
        version = "0.1.0";
        src = xmsgPreXl1Src;
        cargoLock.lockFile = "${xmsgPreXl1Src}/Cargo.lock";
        doCheck = false;
        meta.mainProgram = "xmsg";
      };

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
      # credentials in its environment, and then child X's PreInvocation, PreToolUse and Stop
      # commands (HA9-A.agy G3, G9). The turn ends in a child without those credentials, so
      # the lock holder outlives the turn but a later registration finds nothing to read.
      agyTurn = pkgs.writeShellScript "agy-turn" ''
        hook=$1 pre_tool_hook=$2 stop_hook=$3 conv=$4 child=$5 done=$6
        out=$(printf '{"conversationId":"%s"}' "$conv" | sh -c "$hook")
        echo "agy-hook: hook printed (invocation 1, stand-down): $out"
        printf '%s' "$out" | ${pkgs.jq}/bin/jq -e '. == {}' > /dev/null \
          || { echo "agy-hook: expected {} on invocation 1 stand-down, got: $out" >&2; exit 1; }
        out2=$(printf '{"conversationId":"%s"}' "$conv" | sh -c "$hook")
        echo "agy-hook: hook printed (invocation 2, inject): $out2"
        printf '%s' "$out2" | ${pkgs.jq}/bin/jq -e '
          (.injectSteps | type == "array" and length == 1)
          and (.injectSteps[0].ephemeralMessage | type == "string" and contains("register agy"))
          and (.injectSteps[0] | has("userMessage") | not)
        ' > /dev/null \
          || { echo "agy-hook: expected injectSteps[0].ephemeralMessage (not userMessage), got: $out2" >&2; exit 1; }
        export ANTIGRAVITY_CONVERSATION_ID=$conv ANTIGRAVITY_LS_ADDRESS=127.0.0.1:1 ANTIGRAVITY_CSRF_TOKEN=fixture-token
        sleep 1

        # Wait until the proc watcher has registered C before driving child X's hooks (G3, G9).
        for _ in $(seq 50); do
          check_c=$(printf '{"action":"check","conversation_id":"%s"}\n' "$conv" | ${pkgs.socat}/bin/socat -t 1 - "UNIX-CONNECT:$XDG_RUNTIME_DIR/xmsg/register.sock" || true)
          [ "$(printf '%s' "$check_c" | ${pkgs.jq}/bin/jq -r .hasCredentials 2>/dev/null)" = true ] && break
          sleep 0.1
        done

        # G3: child X's PreInvocation prints `{}` on every invocation (no registration ask).
        child_out1=$(printf '{"conversationId":"%s"}' "$child" | sh -c "$hook")
        echo "agy-hook: child PreInvocation 1: $child_out1"
        printf '%s' "$child_out1" | ${pkgs.jq}/bin/jq -e '. == {}' > /dev/null \
          || { echo "agy-hook: expected {} for child PreInvocation 1, got: $child_out1" >&2; exit 1; }
        child_out2=$(printf '{"conversationId":"%s"}' "$child" | sh -c "$hook")
        echo "agy-hook: child PreInvocation 2: $child_out2"
        printf '%s' "$child_out2" | ${pkgs.jq}/bin/jq -e '. == {}' > /dev/null \
          || { echo "agy-hook: expected {} for child PreInvocation 2, got: $child_out2" >&2; exit 1; }

        # G9: drive PreToolUse and Stop from the rendered hooks.json.
        stamp_out=$(printf '{"conversationId":"%s","toolCall":{"name":"call_mcp_tool","args":{"ServerName":"xmsg","ToolName":"send","Arguments":{"to":"peer","text":"hi","as_agent":"forged"}}}}' "$child" | sh -c "$pre_tool_hook")
        echo "agy-hook: child PreToolUse: $stamp_out"
        printf '%s' "$stamp_out" | ${pkgs.jq}/bin/jq -e --arg x "$child" '
          .decision == "allow" and .overwrite.Arguments.as_agent == $x and .overwrite.Arguments.text == "hi"
        ' > /dev/null \
          || { echo "agy-hook: unexpected PreToolUse output: $stamp_out" >&2; exit 1; }

        stop_out=$(printf '{"conversationId":"%s"}' "$child" | sh -c "$stop_hook")
        echo "agy-hook: child Stop: $stop_out"
        printf '%s' "$stop_out" | ${pkgs.jq}/bin/jq -e '. == {}' > /dev/null \
          || { echo "agy-hook: expected {} for child Stop, got: $stop_out" >&2; exit 1; }

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
        pkgs.runCommand "xmsg-${name}"
          {
            nativeBuildInputs = [
              pkgs.python3
              pkgs.nodejs
            ];
          }
          ''
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
              child=4b222222-3333-4444-8555-666666666666
              lock=$HOME/.gemini/antigravity-cli/presence/$conv.lock
              : > "$lock"
              mkdir -p "$HOME/.gemini/antigravity-cli/brain/$conv/.system_generated/subagents"
              printf '{"conversationId":"%s","subagentDescriptor":{"role":"kid","typeName":"self"},"spawnStepIndex":4}\n' "$child" \
                > "$HOME/.gemini/antigravity-cli/brain/$conv/.system_generated/subagents/$child.json"

              # G9: assert hooks.json renders the three entries of §2.6 with the right --event.
              jq -e '
                (."xmsg-register".PreInvocation[0].command | endswith("register agy --hook --event pre-invocation"))
                and (."xmsg-register".PreToolUse[0].matcher == "call_mcp_tool|mcp_xmsg_.*")
                and (."xmsg-register".PreToolUse[0].hooks[0].command | endswith("register agy --hook --event pre-tool-use"))
                and (."xmsg-register".PreToolUse[0].hooks[0].timeout == 5)
                and (."xmsg-register".Stop[0].command | endswith("register agy --hook --event stop"))
                and (."xmsg-register".Stop[0].timeout == 5)
              ' ${hooksJson} > /dev/null || { echo "agy-hook: hooks.json did not match §2.6 schema" >&2; cat ${hooksJson} >&2; exit 1; }

              hook=$(jq -er '."xmsg-register".PreInvocation[0].command' ${hooksJson})
              pre_tool_hook=$(jq -er '."xmsg-register".PreToolUse[0].hooks[0].command' ${hooksJson})
              stop_hook=$(jq -er '."xmsg-register".Stop[0].command' ${hooksJson})
              echo "agy-hook: rendered hook commands: $hook | $pre_tool_hook | $stop_hook"

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

              flock "$lock" ${agyTurn} "$hook" "$pre_tool_hook" "$stop_hook" "$conv" "$child" "$TMPDIR/turn-done" &
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
              printf '%s' "$listed" | jq -e --arg sub "$conv/kid" \
                'any(.recipients[]; .kind == "subagent" and .harness == "agy" and .address == "\($sub)@\(.node)")' > /dev/null \
                || fail "child $conv/kid is not listed as subagent: $listed"

              kill "$agy" "$serve"
              echo "agy-hook: the rendered hook registered $conv, addressed as $conv"
              touch $out
            '';

        pre-xl1-compat = xmsgPkg.overrideAttrs {
          pname = "xmsg-pre-xl1-compat";
          dontBuild = true;
          XMSG_PRE_XL1_BIN = lib.getExe xmsgPreXl1;
          checkPhase = ''
            runHook preCheck
            set -o pipefail
            cargoWithProfile test --locked --test gate_xf3_list_compat_and_agy_label -- test_oracle_1_pre_xl1_wire_compat_direct_and_dialout --exact --nocapture 2>&1 | tee test.log
            if grep -Fq "XMSG_PRE_XL1_BIN unset; skipping live two-binary pre-XL1 (9096199) subprocess check" test.log; then
              echo "pre-xl1-compat: live two-binary pre-XL1 check was skipped" >&2
              exit 1
            fi
            runHook postCheck
          '';
          installPhase = ''
            echo "${xmsgPreXl1}" > $out
          '';
        };
      };
    };
}
