#!/usr/bin/env bash
set -euo pipefail
repo_root=$(git -C "$(dirname "$0")" rev-parse --show-toplevel)
cd "$repo_root"
fixture_target="$repo_root/.artifacts/executor-fixture-target"
revision=$(git rev-parse HEAD)
XMSG_BUILD_REVISION="$revision" CARGO_TARGET_DIR="$fixture_target" cargo build --locked --no-default-features --features daemon --bin xmsg -j4
export XMSG_EXECUTOR_FIXTURE_DAEMON="$fixture_target/debug/xmsg"
export XMSG_EXECUTOR_FIXTURE_DAEMON_SHA256
XMSG_EXECUTOR_FIXTURE_DAEMON_SHA256=$(python3 -c 'import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],"rb").read()).hexdigest())' "$XMSG_EXECUTOR_FIXTURE_DAEMON")
export XMSG_EXECUTOR_FIXTURE_PYTHON
XMSG_EXECUTOR_FIXTURE_PYTHON=$(python3 -c 'import sys;print(sys.executable)')
printf 'fixture daemon revision=%s sha256=%s\n' "$revision" "$XMSG_EXECUTOR_FIXTURE_DAEMON_SHA256"
"$XMSG_EXECUTOR_FIXTURE_DAEMON" --version
"$XMSG_EXECUTOR_FIXTURE_PYTHON" --version
cargo test --manifest-path extensions/executor/Cargo.toml --locked -j4 -- --test-threads=1
cargo clippy --manifest-path extensions/executor/Cargo.toml --all-targets --locked -j4 -- -D warnings
cargo fmt --manifest-path extensions/executor/Cargo.toml -- --check
