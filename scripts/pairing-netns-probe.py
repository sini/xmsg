#!/usr/bin/env python3
"""Probe two-namespace veth + TLS 1.3 isolation on Linux CI runners."""

import os
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


TLS_SERVER_CODE = """
import socket, ssl, sys
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_cert_chain(sys.argv[1], sys.argv[2])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as srv:
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("10.200.1.1", 8443))
    srv.listen(1)
    with open(sys.argv[3], "w") as ready:
        ready.write("ready\\n")
    conn, _ = srv.accept()
    with ctx.wrap_socket(conn, server_side=True) as tls:
        data = tls.recv(1024)
        tls.sendall(b"pong:" + tls.version().encode() + b":" + data)
"""

TLS_CLIENT_CODE = """
import socket, ssl, sys, time
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
ctx.minimum_version = ssl.TLSVersion.TLSv1_3
ctx.load_verify_locations(sys.argv[1])
ctx.check_hostname = False
deadline = time.monotonic() + 5.0
while not __import__("os").path.exists(sys.argv[2]):
    if time.monotonic() > deadline:
        raise SystemExit("server did not become ready")
    time.sleep(0.05)
with socket.create_connection(("10.200.1.1", 8443), timeout=5) as sock:
    with ctx.wrap_socket(sock) as tls:
        tls.sendall(b"hello-netns")
        reply = tls.recv(1024).decode()
        assert reply == "pong:TLSv1.3:hello-netns", reply
        print(f"client-ok:{reply}")
"""


def probe_unprivileged(cert: Path, key: Path, ready: Path) -> bool:
    check = subprocess.run(
        ["unshare", "-Urn", "ip", "link", "show", "lo"],
        capture_output=True,
        text=True,
    )
    if check.returncode != 0:
        return False
    script = f"""
set -euo pipefail
unshare -n sleep 15 &
ns_b_pid=$!
trap 'kill "$ns_b_pid" 2>/dev/null || true' EXIT
for _ in $(seq 1 20); do
  if ip link add veth-a type veth peer name veth-b 2>/dev/null; then
    break
  fi
  sleep 0.05
done
ip link set veth-b netns "$ns_b_pid"
ip link set lo up
ip addr add 10.200.1.1/24 dev veth-a
ip link set veth-a up
nsenter -t "$ns_b_pid" -n --no-fork ip link set lo up
nsenter -t "$ns_b_pid" -n --no-fork ip addr add 10.200.1.2/24 dev veth-b
nsenter -t "$ns_b_pid" -n --no-fork ip link set veth-b up
{shlex.quote(sys.executable)} -c {shlex.quote(TLS_SERVER_CODE)} {shlex.quote(str(cert))} {shlex.quote(str(key))} {shlex.quote(str(ready))} &
srv_pid=$!
nsenter -t "$ns_b_pid" -n --no-fork {shlex.quote(sys.executable)} -c {shlex.quote(TLS_CLIENT_CODE)} {shlex.quote(str(cert))} {shlex.quote(str(ready))}
wait "$srv_pid"
"""
    res = subprocess.run(["unshare", "-Urn", "bash", "-c", script], check=False)
    if res.returncode != 0:
        raise SystemExit(f"unprivileged unshare -Urn probe failed: exit {res.returncode}")
    print("pairing-netns-probe: mode=unprivileged tls=TLSv1.3 ok")
    return True


def probe_sudo_ip_netns(cert: Path, key: Path, ready: Path) -> bool:
    if subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode != 0:
        return False
    user = os.environ.get("USER") or subprocess.check_output(["id", "-un"], text=True).strip()
    suffix = str(os.getpid())
    ns_a = f"xmsg-probe-a-{suffix}"
    ns_b = f"xmsg-probe-b-{suffix}"
    veth_a = f"veth-a-{suffix}"[:15]
    veth_b = f"veth-b-{suffix}"[:15]
    try:
        subprocess.run(["sudo", "ip", "netns", "add", ns_a], check=True)
        subprocess.run(["sudo", "ip", "netns", "add", ns_b], check=True)
        subprocess.run(["sudo", "ip", "link", "add", veth_a, "type", "veth", "peer", "name", veth_b], check=True)
        subprocess.run(["sudo", "ip", "link", "set", veth_a, "netns", ns_a], check=True)
        subprocess.run(["sudo", "ip", "link", "set", veth_b, "netns", ns_b], check=True)
        for ns, dev, addr in [(ns_a, veth_a, "10.200.1.1/24"), (ns_b, veth_b, "10.200.1.2/24")]:
            subprocess.run(["sudo", "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"], check=True)
            subprocess.run(["sudo", "ip", "netns", "exec", ns, "ip", "addr", "add", addr, "dev", dev], check=True)
            subprocess.run(["sudo", "ip", "netns", "exec", ns, "ip", "link", "set", dev, "up"], check=True)
        srv = subprocess.Popen(
            ["sudo", "ip", "netns", "exec", ns_a, "sudo", "-u", user, sys.executable, "-c", TLS_SERVER_CODE, str(cert), str(key), str(ready)]
        )
        try:
            subprocess.run(
                ["sudo", "ip", "netns", "exec", ns_b, "sudo", "-u", user, sys.executable, "-c", TLS_CLIENT_CODE, str(cert), str(ready)],
                check=True,
            )
            srv.wait(timeout=10)
            if srv.returncode != 0:
                raise SystemExit(f"sudo ip netns server failed: exit {srv.returncode}")
        finally:
            if srv.poll() is None:
                srv.kill()
    finally:
        subprocess.run(["sudo", "ip", "netns", "del", ns_a], capture_output=True)
        subprocess.run(["sudo", "ip", "netns", "del", ns_b], capture_output=True)
    print("pairing-netns-probe: mode=sudo-ip-netns tls=TLSv1.3 ok")
    return True


def main() -> int:
    if sys.platform != "linux":
        print("isolation unavailable on non-Linux: no network namespaces")
        return 1
    for tool in ("ip", "openssl"):
        if not shutil.which(tool):
            raise SystemExit(f"isolation unavailable: missing {tool}")
    with tempfile.TemporaryDirectory(prefix="xmsg-netns-probe-") as tmp:
        root = Path(tmp)
        cert = root / "cert.pem"
        key = root / "key.pem"
        ready = root / "ready"
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "ed25519",
                "-keyout", str(key), "-out", str(cert),
                "-days", "1", "-nodes", "-subj", "/CN=xmsg-netns-probe",
            ],
            check=True,
            capture_output=True,
        )
        if probe_unprivileged(cert, key, ready):
            return 0
        if probe_sudo_ip_netns(cert, key, ready):
            return 0
    raise SystemExit("isolation unavailable: neither unshare -Urn nor passwordless sudo ip netns is available")


if __name__ == "__main__":
    raise SystemExit(main())
