#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
binary=$(command -v "${XMSG_BINARY:-xmsg}")
unset XMSG_AGY_EXE XMSG_CODEX_EXE XMSG_CODEX_HOME XMSG_LEAF XMSG_LEAF_PRINCIPAL XMSG_LISTEN
exec "$binary" serve \
  --db-path "$PWD/.local/host/state/xmsg.db" \
  --sessions-dir "$PWD/.local/host/state/sessions" \
  --codex-home "$PWD/.local/host/state/codex" \
  --http-sock "$PWD/.local/host/run/http.sock" \
  --register-sock "$PWD/.local/host/run/register.sock" \
  --agent-sock "$PWD/.local/host/run/agent.sock" \
  --fed-listen "${XMSG_HOST_FED_LISTEN:-0.0.0.0:17898}" \
  --fed-cert "$PWD/.local/host/identity/node.crt" \
  --fed-key "$PWD/.local/host/identity/node.key" \
  --peers-file "$PWD/.local/host/peers.json" \
  --svc-exe "status=$binary"
