{ inputs, ... }:
{
  perSystem =
    {
      pkgs,
      system,
      ...
    }:
    let
      package = inputs.xmsg.packages.${system}.default;
    in
    {
      checks.e2e-hooks-absent =
        pkgs.runCommand "xmsg-e2e-hooks-absent"
          {
            nativeBuildInputs = [
              pkgs.curl
              pkgs.gnugrep
              pkgs.coreutils
            ];
          }
          ''
            set -euo pipefail
            XMSG_BIN="${package}/bin/xmsg"

            # 1. Binary must not contain test-hook env var or #[cfg(test)] RNG symbol.
            if grep -Fqa "XMSG_TEST_E2E_CRASH_AT" "$XMSG_BIN"; then
              echo "FAIL: release binary contains XMSG_TEST_E2E_CRASH_AT" >&2
              exit 1
            fi
            if grep -Fqa "seal_with_rng" "$XMSG_BIN"; then
              echo "FAIL: release binary contains seal_with_rng symbol" >&2
              exit 1
            fi

            # 2. Positive real startup check on release binary (/healthz).
            export HOME="$TMPDIR/home"
            export XDG_RUNTIME_DIR="$TMPDIR/run"
            export XDG_DATA_HOME="$TMPDIR/data"
            mkdir -p "$HOME" "$XDG_RUNTIME_DIR/xmsg" "$XDG_DATA_HOME"
            chmod 0700 "$XDG_RUNTIME_DIR" "$XDG_RUNTIME_DIR/xmsg"

            "$XMSG_BIN" serve \
              --http-sock "$TMPDIR/http1.sock" \
              --db-path "$TMPDIR/xmsg1.db" \
              >"$TMPDIR/serve1.log" 2>&1 &
            PID1=$!
            ready=0
            for _ in $(seq 1 50); do
              if curl --unix-socket "$TMPDIR/http1.sock" -fsS http://localhost/healthz >"$TMPDIR/health1.out" 2>/dev/null; then
                ready=1
                break
              fi
              sleep 0.2
            done
            kill "$PID1" 2>/dev/null || true
            wait "$PID1" 2>/dev/null || true
            if [ "$ready" -ne 1 ]; then
              echo "FAIL: release xmsg serve did not become healthy" >&2
              cat "$TMPDIR/serve1.log" >&2 || true
              exit 1
            fi

            # 3. Invoking with XMSG_TEST_E2E_CRASH_AT=probe must still serve normally and emit no crash-ready marker.
            XMSG_TEST_E2E_CRASH_AT=probe "$XMSG_BIN" serve \
              --http-sock "$TMPDIR/http2.sock" \
              --db-path "$TMPDIR/xmsg2.db" \
              >"$TMPDIR/serve2.log" 2>&1 &
            PID2=$!
            ready2=0
            for _ in $(seq 1 50); do
              if curl --unix-socket "$TMPDIR/http2.sock" -fsS http://localhost/healthz >"$TMPDIR/health2.out" 2>/dev/null; then
                ready2=1
                break
              fi
              sleep 0.2
            done
            kill "$PID2" 2>/dev/null || true
            wait "$PID2" 2>/dev/null || true
            if [ "$ready2" -ne 1 ]; then
              echo "FAIL: release xmsg serve with XMSG_TEST_E2E_CRASH_AT=probe did not become healthy" >&2
              cat "$TMPDIR/serve2.log" >&2 || true
              exit 1
            fi
            if grep -Fq "crash-ready" "$TMPDIR/serve2.log"; then
              echo "FAIL: release binary emitted crash-ready marker" >&2
              exit 1
            fi

            mkdir -p "$out"
            cp "$TMPDIR/health1.out" "$out/health1.out"
            cp "$TMPDIR/health2.out" "$out/health2.out"
            echo "e2e-hooks-absent: OK" > "$out/status"
          '';
    };
}
