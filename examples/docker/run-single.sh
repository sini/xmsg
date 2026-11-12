#!/usr/bin/env bash
set -euo pipefail
cd -- "$(dirname -- "$0")"
engine=${DOCKER:-docker}
image=${1:-ghcr.io/sini/xmsg:latest}
exec "$engine" run --detach --name "${XMSG_CONTAINER_NAME:-xmsg-single}" \
  --user "$(id -u):$(id -g)" \
  --env XDG_RUNTIME_DIR=/run \
  --env XMSG_DB_PATH=/var/lib/xmsg/xmsg.db \
  --env XMSG_LISTEN=0.0.0.0:7787 \
  --env XMSG_FED_LISTEN=0.0.0.0:7788 \
  --env XMSG_PEERS_FILE=/etc/xmsg/peers.json \
  --env XMSG_FED_CERT=/etc/xmsg/identity/node.crt \
  --env XMSG_FED_KEY=/etc/xmsg/identity/node.key \
  --env XMSG_SESSIONS_DIR=/var/lib/xmsg/sessions \
  --env XMSG_CODEX_HOME=/var/lib/xmsg/codex \
  --publish "127.0.0.1:${XMSG_HTTP_PORT:-17787}:7787" \
  --publish "127.0.0.1:${XMSG_FED_PORT:-17788}:7788" \
  --mount "type=bind,src=$PWD/.local/a/state,dst=/var/lib/xmsg" \
  --mount "type=bind,src=$PWD/.local/a/run,dst=/run/xmsg" \
  --mount "type=bind,src=$PWD/.local/a/identity,dst=/etc/xmsg/identity,readonly" \
  --mount "type=bind,src=$PWD/.local/a/peers.single.json,dst=/etc/xmsg/peers.json,readonly" \
  "$image" serve --svc-exe status=/bin/xmsg
