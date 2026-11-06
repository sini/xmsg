"""Check production edges, with a daemon-enabled positive control."""
import subprocess
import tomllib
from pathlib import Path


def packages(args):
    result = subprocess.run(["cargo", "tree", "--locked", "-e", "normal", "--prefix", "none", "--format", "{p}", *args], check=True, capture_output=True, text=True)
    return {line.split(" v", 1)[0] for line in result.stdout.splitlines()}


forbidden = {"rusqlite", "libsqlite3-sys", "axum", "rustls", "tokio-rustls"}
client = packages(["--no-default-features", "--features", "client"])
daemon = packages([])
assert {"rusqlite", "axum", "rustls"} <= daemon, "broken positive dependency control"
assert not forbidden & client, forbidden & client
print(f"client-only normal graph: {len(client)} packages; daemon: {len(daemon)}; forbidden dependencies absent with live daemon positive control")

manifest = tomllib.loads(Path("Cargo.toml").read_text())
registered = {target["path"] for target in manifest["test"]}
actual = {str(file) for file in Path("tests").glob("*.rs")}
assert registered == actual, ("test target inventory mismatch", registered ^ actual)
print(f"all {len(actual)} integration targets registered with feature requirements")

for target in manifest["test"]:
    expected = ["client"] if target["name"] == "shared_client" else ["daemon"]
    assert target.get("required-features") == expected, ("test feature requirement mismatch", target)
