"""Check production edges, with a daemon-enabled positive control."""
import subprocess


def packages(args):
    result = subprocess.run(["cargo", "tree", "--locked", "-e", "normal", "--prefix", "none", "--format", "{p}", *args], check=True, capture_output=True, text=True)
    return {line.split(" v", 1)[0] for line in result.stdout.splitlines()}


forbidden = {"rusqlite", "libsqlite3-sys", "axum", "rustls", "tokio-rustls", "matrix-sdk"}
client = packages(["--no-default-features", "--features", "client"])
daemon = packages([])
assert {"rusqlite", "axum", "rustls"} <= daemon, "broken positive dependency control"
assert not forbidden & client, forbidden & client
print(f"client-only normal graph: {len(client)} packages; daemon: {len(daemon)}; forbidden dependencies absent with live daemon positive control")
