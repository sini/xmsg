#!/usr/bin/env python3
"""Real two-daemon netns acceptance gate for xmsg discovery PR 4 (xmsg-7m27).

Runs two independently configured `xmsg serve` processes in separate network
namespaces (`unshare -Urn` or passwordless `sudo ip netns`), with separate
SQLite stores, separate HOME/runtime dirs, synthetic Ed25519 credentials,
real TLS 1.3 `xmsg-pair/1`, and an independent Python CBOR+OpenSSL receipt
verifier (not calling xmsg's codec).
"""

import hashlib
import json
import os
import shlex
import shutil
import socket
import sqlite3
import ssl
import struct
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def decode_cbor(data: bytes, offset: int = 0):
    if offset >= len(data):
        raise ValueError("unexpected end of CBOR")
    ib = data[offset]
    offset += 1
    major = ib >> 5
    ai = ib & 0x1F

    def read_uint(a: int, pos: int):
        if a < 24:
            return a, pos
        if a == 24:
            return data[pos], pos + 1
        if a == 25:
            return struct.unpack(">H", data[pos : pos + 2])[0], pos + 2
        if a == 26:
            return struct.unpack(">I", data[pos : pos + 4])[0], pos + 4
        if a == 27:
            return struct.unpack(">Q", data[pos : pos + 8])[0], pos + 8
        raise ValueError(f"unsupported CBOR additional info {a}")

    if major == 0:
        return read_uint(ai, offset)
    if major == 1:
        val, pos = read_uint(ai, offset)
        return -1 - val, pos
    if major == 2:
        ln, pos = read_uint(ai, offset)
        return data[pos : pos + ln], pos + ln
    if major == 3:
        ln, pos = read_uint(ai, offset)
        return data[pos : pos + ln].decode("utf-8"), pos + ln
    if major == 4:
        ln, pos = read_uint(ai, offset)
        arr = []
        for _ in range(ln):
            item, offset = decode_cbor(data, pos)
            arr.append(item)
            pos = offset
        return arr, pos
    if major == 5:
        ln, pos = read_uint(ai, offset)
        mp = {}
        for _ in range(ln):
            k, pos = decode_cbor(data, pos)
            v, pos = decode_cbor(data, pos)
            mp[k] = v
        return mp, pos
    if major == 6:
        tag, pos = read_uint(ai, offset)
        val, pos = decode_cbor(data, pos)
        return ("tag", tag, val), pos
    if major == 7:
        if ai == 22:
            return None, offset
        if ai == 20:
            return False, offset
        if ai == 21:
            return True, offset
    raise ValueError(f"unsupported CBOR major={major} ai={ai}")


def encode_cbor(val) -> bytes:
    def hdr(major: int, n: int) -> bytes:
        if n < 24:
            return bytes([(major << 5) | n])
        if n < 0x100:
            return bytes([(major << 5) | 24, n])
        if n < 0x10000:
            return bytes([(major << 5) | 25]) + struct.pack(">H", n)
        if n < 0x100000000:
            return bytes([(major << 5) | 26]) + struct.pack(">I", n)
        return bytes([(major << 5) | 27]) + struct.pack(">Q", n)

    if isinstance(val, bytes):
        return hdr(2, len(val)) + val
    if isinstance(val, str):
        b = val.encode("utf-8")
        return hdr(3, len(b)) + b
    if isinstance(val, list):
        return hdr(4, len(val)) + b"".join(encode_cbor(x) for x in val)
    raise ValueError(f"unsupported type {type(val)}")


def verify_cose_sign1_ed25519(
    cose_bytes: bytes, exporter: bytes, pub_pem: Path, expected_role: int
) -> dict:
    """Independent COSE_Sign1 (tag 18) + Ed25519 verifier using Python CBOR + OpenSSL."""
    tagged, end = decode_cbor(cose_bytes)
    assert end == len(cose_bytes), "trailing bytes in COSE_Sign1"
    assert isinstance(tagged, tuple) and tagged[0] == "tag" and tagged[1] == 18, "not tag 18"
    arr = tagged[2]
    assert isinstance(arr, list) and len(arr) == 4, "expected 4-element COSE_Sign1"
    protected_bstr, unprotected, payload_bstr, sig = arr
    assert unprotected == {}, f"unprotected map not empty: {unprotected}"
    protected, _ = decode_cbor(protected_bstr)
    assert protected[1] == -19, f"expected Ed25519 (-19), got {protected.get(1)}"

    # RFC 9052 Sig_structure: ["Signature1", body_protected, external_aad, payload]
    # external_aad = ["xmsg-pair-receipt-v1", exporter]
    aad = encode_cbor(["xmsg-pair-receipt-v1", exporter])
    sig_structure = encode_cbor(["Signature1", protected_bstr, aad, payload_bstr])

    with tempfile.TemporaryDirectory() as td:
        msg_p = Path(td) / "msg.bin"
        sig_p = Path(td) / "sig.bin"
        msg_p.write_bytes(sig_structure)
        sig_p.write_bytes(sig)
        res = subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-verify",
                "-pubin",
                "-inkey",
                str(pub_pem),
                "-rawin",
                "-in",
                str(msg_p),
                "-sigfile",
                str(sig_p),
            ],
            capture_output=True,
            text=True,
        )
        assert res.returncode == 0, f"independent Ed25519 verify failed: {res.stderr}"

    payload, _ = decode_cbor(payload_bstr)
    assert payload[3] == expected_role, f"expected role {expected_role}, got {payload.get(3)}"
    return payload


def gen_ed25519_identity(root: Path, name: str):
    key_pem = root / f"{name}.key.pem"
    pub_pem = root / f"{name}.pub.pem"
    cert_pem = root / f"{name}.cert.pem"
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-newkey",
            "ed25519",
            "-keyout",
            str(key_pem),
            "-out",
            str(cert_pem),
            "-days",
            "1",
            "-nodes",
            "-subj",
            f"/CN={name}",
        ],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["openssl", "pkey", "-in", str(key_pem), "-pubout", "-out", str(pub_pem)],
        check=True,
        capture_output=True,
    )
    os.chmod(key_pem, 0o600)
    return key_pem, pub_pem, cert_pem


def run_acceptance(xmsg_bin: Path) -> None:
    if sys.platform != "linux":
        print("SKIP: isolation unavailable on non-Linux: no network namespaces")
        return
    for tool in ("ip", "openssl"):
        if not shutil.which(tool):
            raise SystemExit(f"isolation unavailable: missing {tool}")

    use_unpriv = (
        subprocess.run(
            ["unshare", "-Urn", "ip", "link", "show", "lo"],
            capture_output=True,
        ).returncode
        == 0
    )
    use_sudo = (
        not use_unpriv
        and subprocess.run(["sudo", "-n", "true"], capture_output=True).returncode == 0
    )
    if not use_unpriv and not use_sudo:
        raise SystemExit(
            "isolation unavailable: neither unshare -Urn nor passwordless sudo ip netns is available"
        )

    with tempfile.TemporaryDirectory(prefix="xmsg-pair-accept-") as tmp:
        root = Path(tmp)
        home_a, home_b = root / "home-a", root / "home-b"
        state_a, state_b = root / "state-a", root / "state-b"
        run_a, run_b = root / "run-a", root / "run-b"
        for d in (home_a, home_b, state_a, state_b, run_a, run_b):
            d.mkdir(parents=True)
            os.chmod(d, 0o700)

        key_a, pub_a, cert_a = gen_ed25519_identity(root, "node-a")
        key_b, pub_b, cert_b = gen_ed25519_identity(root, "node-b")
        peers_a = root / "peers-a.json"
        peers_b = root / "peers-b.json"
        peers_a.write_text("{}\n")
        peers_b.write_text("{}\n")

        # Q2-14: verify peers-file rejects deferred preference keys in both wrapped and bare forms.
        bad_bare = root / "bad-bare.json"
        bad_bare.write_text('{"pairing.confirm": true}\n')
        res_bare = subprocess.run(
            [str(xmsg_bin), "check-peers", str(bad_bare)],
            capture_output=True,
            text=True,
        )
        assert res_bare.returncode != 0 and "pairing.confirm" in (
            res_bare.stdout + res_bare.stderr
        ), f"bare deferred key not rejected: {res_bare.stdout} {res_bare.stderr}"

        bad_wrap = root / "bad-wrap.json"
        bad_wrap.write_text('{"peers": {}, "auto_accept": {}}\n')
        res_wrap = subprocess.run(
            [str(xmsg_bin), "check-peers", str(bad_wrap)],
            capture_output=True,
            text=True,
        )
        assert res_wrap.returncode != 0 and "auto_accept" in (
            res_wrap.stdout + res_wrap.stderr
        ), f"wrapped deferred key not rejected: {res_wrap.stdout} {res_wrap.stderr}"

        sock_a = run_a / "http.sock"
        sock_b = run_b / "http.sock"
        db_a = state_a / "xmsg.db"
        db_b = state_b / "xmsg.db"
        sess_a = state_a / "sessions"
        sess_b = state_b / "sessions"
        sess_a.mkdir()
        sess_b.mkdir()
        log_a = root / "srv-a.log"
        log_b = root / "srv-b.log"

        # Driver Python script run across the two namespaces.
        driver = f"""
import json, os, sqlite3, subprocess, sys, time
from pathlib import Path

xmsg = {str(xmsg_bin)!r}
sock_a, sock_b = {str(sock_a)!r}, {str(sock_b)!r}
agent_sock_a = {str(run_a / "register.sock")!r}
db_a, db_b = {str(db_a)!r}, {str(db_b)!r}
log_a, log_b = {str(log_a)!r}, {str(log_b)!r}

def wait_sock(p, log_p):
    deadline = time.monotonic() + 15
    while not Path(p).exists():
        if time.monotonic() > deadline:
            log_txt = Path(log_p).read_text() if Path(log_p).exists() else ""
            raise RuntimeError(f"socket {{p}} did not appear; log:\\n{{log_txt}}")
        time.sleep(0.05)

wait_sock(sock_a, log_a)
wait_sock(sock_b, log_b)

id_a = subprocess.check_output([xmsg, "pair", "--http-sock", sock_a, "id"], text=True).strip()
id_b = subprocess.check_output([xmsg, "pair", "--http-sock", sock_b, "id"], text=True).strip()
assert id_a.startswith("xmsg-spki1:") and id_b.startswith("xmsg-spki1:") and id_a != id_b

# Q2-5a & Q2-10: contact without --target refuses pairing.targets_required
no_target = subprocess.run(
    [xmsg, "pair", "--http-sock", sock_a, "accept", id_b, "--profile", "contact"],
    capture_output=True, text=True,
)
assert no_target.returncode != 0 and "pairing.targets_required" in (no_target.stdout + no_target.stderr)

# Q2-10 + Q2-1: Asymmetric accept (A=contact svc-a) and start (B=owner-device)
accept_proc = subprocess.Popen(
    [xmsg, "pair", "--http-sock", sock_a, "accept", id_b, "--profile", "contact", "--target", "svc-a", "--json"],
    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
)
time.sleep(0.3)

# Q2-5a: second accept with different profile refuses pairing.intent_exists
conflict = subprocess.run(
    [xmsg, "pair", "--http-sock", sock_a, "accept", id_b, "--profile", "owner-device", "--no-wait"],
    capture_output=True, text=True,
)
assert conflict.returncode != 0 and "pairing.intent_exists" in (conflict.stdout + conflict.stderr), conflict.stderr

start_out = subprocess.check_output(
    [xmsg, "pair", "--http-sock", sock_b, "start", id_a, "--profile", "owner-device", "--address", "10.201.1.1:7788", "--json"],
    text=True,
)
start_json = json.loads(start_out)
assert start_json["committed"] is True
assert start_json["installed_revision"] >= start_json["committed_revision"]

accept_out, accept_err = accept_proc.communicate(timeout=15)
assert accept_proc.returncode == 0, f"accept failed: {{accept_err}}"
accept_json = json.loads(accept_out)
assert accept_json["committed"] is True

# Q2-7a: both pair lists show installed == committed
list_a = json.loads(subprocess.check_output([xmsg, "pair", "--http-sock", sock_a, "list", "--json"], text=True))
list_b = json.loads(subprocess.check_output([xmsg, "pair", "--http-sock", sock_b, "list", "--json"], text=True))
assert list_a["installed_revision"] == list_a["committed_revision"] >= 1
assert list_b["installed_revision"] == list_b["committed_revision"] >= 1
assert len(list_a["grants"]) == 1 and len(list_b["grants"]) == 1

# Q2-7a & Q2-9 BY EFFECT: B->A send to target 'svc-a' is authorized by A (reaches recipient lookup, not op_denied);
# 'other' is denied by Q2-9 target enforcement.
import http.client

def unix_get(sock_path, path):
    class UnixConn(http.client.HTTPConnection):
        def connect(self):
            import socket as _s
            s = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
            s.connect(sock_path)
            self.sock = s
    conn = UnixConn("localhost")
    conn.request("GET", path)
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", "replace")
    return resp.status, body

def unix_post(sock_path, path, payload):
    class UnixConn(http.client.HTTPConnection):
        def connect(self):
            import socket as _s
            s = _s.socket(_s.AF_UNIX, _s.SOCK_STREAM)
            s.connect(sock_path)
            self.sock = s
    conn = UnixConn("localhost")
    conn.request("POST", path, json.dumps(payload), {{"Content-Type": "application/json"}})
    resp = conn.getresponse()
    body = resp.read().decode("utf-8", "replace")
    return resp.status, body

# Start a real svc-a recipient on node A over agent.sock so the pre-block send succeeds with a real reply.
import socket as _sock, threading as _thr
svc_ready = _thr.Event()
svc_errs = []
def run_svc_a():
    try:
        s = _sock.socket(_sock.AF_UNIX, _sock.SOCK_STREAM)
        s.connect(agent_sock_a)
        f = s.makefile("rw", encoding="utf-8")
        f.write(json.dumps({{"harness": "svc", "name": "svc-a"}}) + "\\n")
        f.flush()
        reg_line = json.loads(f.readline())
        assert reg_line.get("status") == "ok", f"svc-a register failed: {{reg_line}}"
        svc_ready.set()
        f.write(json.dumps({{"action": "poll", "waitSecs": 15}}) + "\\n")
        f.flush()
        msg_line = json.loads(f.readline())
        msg_id = msg_line.get("messageId") or msg_line.get("id")
        assert msg_id and msg_line.get("text") == "hello-q2-7a", f"unexpected svc-a delivery: {{msg_line}}"
        f.write(json.dumps({{"action": "reply", "messageId": msg_id, "text": "pong-from-svc-a"}}) + "\\n")
        f.flush()
        _ = f.readline()
        s.close()
    except Exception as exc:
        svc_errs.append(repr(exc))
        svc_ready.set()

wait_sock(agent_sock_a, log_a)
svc_thread = _thr.Thread(target=run_svc_a, daemon=True)
svc_thread.start()
assert svc_ready.wait(timeout=10) and not svc_errs, f"svc-a failed to register: {{svc_errs}}"

st_send_ok, body_send_ok = unix_post(sock_b, "/v1/messages", {{"from": "b-client", "to": f"svc-a@{{id_a}}", "text": "hello-q2-7a"}})
svc_thread.join(timeout=10)
assert not svc_thread.is_alive(), "svc-a thread still alive after join (did not complete delivery/reply)"
assert not svc_errs, f"svc-a recipient error: {{svc_errs}}"
assert st_send_ok in (200, 202), f"Q2-7a first send B->A failed: {{st_send_ok}} {{body_send_ok}}"
send_ok_json = json.loads(body_send_ok)
msg_id_ok = send_ok_json.get("message_id")
assert send_ok_json.get("outcome") in ("queued", "delivered") and msg_id_ok, f"Q2-7a first send unexpected response: {{send_ok_json}}"
reply_seen = False
for _ in range(40):
    st_get, body_get = unix_get(sock_a, f"/v1/messages/{{msg_id_ok}}")
    if st_get == 200 and "pong-from-svc-a" in body_get:
        reply_seen = True
        break
    time.sleep(0.05)
assert reply_seen, f"Q2-7a svc-a reply 'pong-from-svc-a' not recorded on node A for {{msg_id_ok}}: {{st_get}} {{body_get}}"

st_send_other, body_send_other = unix_post(sock_b, "/v1/messages", {{"from": "b-client", "to": f"other@{{id_a}}", "text": "deny-q2-9"}})
assert st_send_other == 403 and json.loads(body_send_other).get("error") == "denied", f"Q2-9 send to unlisted target 'other' unexpectedly succeeded: {{st_send_other}} {{body_send_other}}"

def assert_refused(st, body, label):
    payload = json.loads(body)
    err = payload.get("error")
    detail = (payload.get("detail") or "").lower()
    ok = (
        (st == 403 and err == "denied")
        or (
            st == 503
            and err == "peer_unreachable"
            and any(
                tok in detail
                for tok in (
                    "connection error",
                    "tls handshake failed",
                    "peer rejected",
                    "certificate",
                    "denied",
                    "unknownissuer",
                )
            )
        )
    )
    assert ok, f"{{label}} expected specific refusal (403 denied or 503 TLS/connection refusal), got {{st}} {{body}}"

def check_fed_listener(host, port):
    probe = f"import socket; s = socket.create_connection(({{host!r}}, {{port}}), timeout=2); s.close()"
    ns_b_pid = os.environ.get("XMSG_ACC_NS_B_PID")
    ns_b_name = os.environ.get("XMSG_ACC_NS_B")
    if ns_b_pid:
        cmd = ["nsenter", "-t", ns_b_pid, "-n", "--no-fork", sys.executable, "-c", probe]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    elif ns_b_name:
        cmd = ["sudo", "ip", "netns", "exec", ns_b_name, sys.executable, "-c", probe]
        subprocess.run(cmd, check=True, capture_output=True, text=True)
    else:
        s = _sock.create_connection((host, port), timeout=2)
        s.close()

# Revocation + nothing revives BY EFFECT: block B on A -> installed_revision == committed_revision, A is live & logs TLS rejection of B, and B->A send refused.
log_a_off1 = Path(log_a).stat().st_size
blk_proc = subprocess.run([xmsg, "pair", "--http-sock", sock_a, "block", id_b], check=True, capture_output=True, text=True)
blk_json = json.loads(blk_proc.stdout)
assert blk_json.get("committed") is True and blk_json.get("installed_revision") == blk_json.get("committed_revision"), f"pair block did not publish committed revision: {{blk_json}}"
list_after_blk = json.loads(subprocess.check_output([xmsg, "pair", "--http-sock", sock_a, "list", "--json"], text=True))
assert any(b.get("peer_id") == id_b for b in list_after_blk.get("blocks", [])), f"pair list missing block for {{id_b}}: {{list_after_blk}}"
st_after_blk, body_after_blk = unix_post(sock_b, "/v1/messages", {{"from": "b-client", "to": f"svc-a@{{id_a}}", "text": "blocked"}})
assert_refused(st_after_blk, body_after_blk, "revoked send after block")
assert unix_get(sock_a, "/healthz")[0] == 200, "node A /healthz liveness check failed after block"
time.sleep(0.1)
log_delta1 = Path(log_a).read_bytes()[log_a_off1:].decode("utf-8", "replace").lower()
assert any("from 10.201.1.2:" in line and "peer certificate is denied" in line for line in log_delta1.splitlines()), f"node A log did not record active rejection of blocked B (from 10.201.1.2: ... peer certificate is denied): {{log_delta1!r}}"
check_fed_listener("10.201.1.1", 7788)

grant_a_hex = list_a["grants"][0]["grant_id"]
subprocess.run([xmsg, "pair", "--http-sock", sock_a, "remove", grant_a_hex], check=True, capture_output=True)
subprocess.run([xmsg, "pair", "--http-sock", sock_a, "unblock", id_b], check=True, capture_output=True)
log_a_off2 = Path(log_a).stat().st_size
st_after_unblk, body_after_unblk = unix_post(sock_b, "/v1/messages", {{"from": "b-client", "to": f"svc-a@{{id_a}}", "text": "nothing-revives"}})
assert_refused(st_after_unblk, body_after_unblk, "nothing-revives send after remove+unblock")
assert unix_get(sock_a, "/healthz")[0] == 200, "node A /healthz liveness check failed after remove+unblock"
time.sleep(0.1)
log_delta2 = Path(log_a).read_bytes()[log_a_off2:].decode("utf-8", "replace").lower()
assert any("from 10.201.1.2:" in line and "unknownissuer" in line for line in log_delta2.splitlines()), f"node A log did not record active rejection of B after remove+unblock (from 10.201.1.2: ... unknownissuer): {{log_delta2!r}}"
check_fed_listener("10.201.1.1", 7788)

# Q2-16: block A on B, then unblock fails pairing.unblock_would_restore while grant exists; remove then unblock succeeds
subprocess.run([xmsg, "pair", "--http-sock", sock_b, "block", id_a], check=True, capture_output=True)
unblock_fail = subprocess.run([xmsg, "pair", "--http-sock", sock_b, "unblock", id_a], capture_output=True, text=True)
assert unblock_fail.returncode != 0 and "pairing.unblock_would_restore" in (unblock_fail.stdout + unblock_fail.stderr)
grant_b_hex = list_b["grants"][0]["grant_id"]
subprocess.run([xmsg, "pair", "--http-sock", sock_b, "remove", grant_b_hex], check=True, capture_output=True)
subprocess.run([xmsg, "pair", "--http-sock", sock_b, "unblock", id_a], check=True, capture_output=True)
print("two-daemon-driver:ok")
"""

        if use_unpriv:
            print("isolation:unshare-urn")
            driver_path = root / "driver.py"
            driver_path.write_text(driver)
            script = f"""
set -euo pipefail
unshare -n sleep 60 &
ns_b_pid=$!
trap 'kill "$ns_b_pid" 2>/dev/null || true' EXIT
for _ in $(seq 1 20); do
  if ip link add veth-a type veth peer name veth-b 2>/dev/null; then break; fi
  sleep 0.05
done
ip link set veth-b netns "$ns_b_pid"
ip link set lo up
ip addr add 10.201.1.1/24 dev veth-a
ip link set veth-a up
nsenter -t "$ns_b_pid" -n --no-fork ip link set lo up
nsenter -t "$ns_b_pid" -n --no-fork ip addr add 10.201.1.2/24 dev veth-b
nsenter -t "$ns_b_pid" -n --no-fork ip link set veth-b up

HOME={shlex.quote(str(home_a))} XDG_RUNTIME_DIR={shlex.quote(str(run_a))} RUST_LOG=info,xmsg::fed=debug {shlex.quote(str(xmsg_bin))} serve \\
  --http-sock {shlex.quote(str(sock_a))} --register-sock {shlex.quote(str(run_a / "register.sock"))} --sessions-dir {shlex.quote(str(sess_a))} \\
  --db-path {shlex.quote(str(db_a))} --fed-listen 10.201.1.1:7788 \\
  --fed-cert {shlex.quote(str(cert_a))} --fed-key {shlex.quote(str(key_a))} \\
  --svc-exe svc-a={shlex.quote(sys.executable)} \\
  --peers-file {shlex.quote(str(peers_a))} --fed-reload-interval-secs 1 >{shlex.quote(str(log_a))} 2>&1 &
srv_a=$!

nsenter -t "$ns_b_pid" -n --no-fork env HOME={shlex.quote(str(home_b))} XDG_RUNTIME_DIR={shlex.quote(str(run_b))} {shlex.quote(str(xmsg_bin))} serve \\
  --http-sock {shlex.quote(str(sock_b))} --sessions-dir {shlex.quote(str(sess_b))} \\
  --db-path {shlex.quote(str(db_b))} --fed-listen 10.201.1.2:7788 \\
  --fed-cert {shlex.quote(str(cert_b))} --fed-key {shlex.quote(str(key_b))} \\
  --peers-file {shlex.quote(str(peers_b))} --fed-reload-interval-secs 1 >{shlex.quote(str(log_b))} 2>&1 &
srv_b=$!

trap 'kill "$srv_a" "$srv_b" "$ns_b_pid" 2>/dev/null || true' EXIT
XMSG_ACC_NS_B_PID="$ns_b_pid" {shlex.quote(sys.executable)} {shlex.quote(str(driver_path))}
"""
            subprocess.run(["unshare", "-Urn", "bash", "-c", script], check=True)
        else:
            print("isolation:sudo-ip-netns")
            user = os.environ.get("USER") or subprocess.check_output(["id", "-un"], text=True).strip()
            suffix = str(os.getpid())
            ns_a, ns_b = f"xmsg-acc-a-{suffix}", f"xmsg-acc-b-{suffix}"
            va, vb = f"va-{suffix}"[:15], f"vb-{suffix}"[:15]
            driver_path = root / "driver.py"
            driver_path.write_text(driver)
            srv_a = srv_b = None
            try:
                subprocess.run(["sudo", "ip", "netns", "add", ns_a], check=True)
                subprocess.run(["sudo", "ip", "netns", "add", ns_b], check=True)
                subprocess.run(["sudo", "ip", "link", "add", va, "type", "veth", "peer", "name", vb], check=True)
                subprocess.run(["sudo", "ip", "link", "set", va, "netns", ns_a], check=True)
                subprocess.run(["sudo", "ip", "link", "set", vb, "netns", ns_b], check=True)
                for ns, dev, addr in [(ns_a, va, "10.201.1.1/24"), (ns_b, vb, "10.201.1.2/24")]:
                    subprocess.run(["sudo", "ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"], check=True)
                    subprocess.run(["sudo", "ip", "netns", "exec", ns, "ip", "addr", "add", addr, "dev", dev], check=True)
                    subprocess.run(["sudo", "ip", "netns", "exec", ns, "ip", "link", "set", dev, "up"], check=True)

                srv_a = subprocess.Popen(
                    [
                        "sudo", "ip", "netns", "exec", ns_a, "sudo", "-u", user,
                        "env", f"HOME={home_a}", f"XDG_RUNTIME_DIR={run_a}", "RUST_LOG=info,xmsg::fed=debug",
                        str(xmsg_bin), "serve",
                        "--http-sock", str(sock_a), "--register-sock", str(run_a / "register.sock"),
                        "--sessions-dir", str(sess_a),
                        "--db-path", str(db_a), "--fed-listen", "10.201.1.1:7788",
                        "--fed-cert", str(cert_a), "--fed-key", str(key_a),
                        "--svc-exe", f"svc-a={sys.executable}",
                        "--peers-file", str(peers_a), "--fed-reload-interval-secs", "1",
                    ],
                    stdout=log_a.open("wb"),
                    stderr=subprocess.STDOUT,
                )
                srv_b = subprocess.Popen(
                    [
                        "sudo", "ip", "netns", "exec", ns_b, "sudo", "-u", user,
                        "env", f"HOME={home_b}", f"XDG_RUNTIME_DIR={run_b}",
                        str(xmsg_bin), "serve",
                        "--http-sock", str(sock_b), "--sessions-dir", str(sess_b),
                        "--db-path", str(db_b), "--fed-listen", "10.201.1.2:7788",
                        "--fed-cert", str(cert_b), "--fed-key", str(key_b),
                        "--peers-file", str(peers_b), "--fed-reload-interval-secs", "1",
                    ],
                    stdout=log_b.open("wb"),
                    stderr=subprocess.STDOUT,
                )
                subprocess.run([sys.executable, str(driver_path)], env={**os.environ, "XMSG_ACC_NS_B": ns_b}, check=True)
            finally:
                for p in (srv_a, srv_b):
                    if p is not None and p.poll() is None:
                        p.terminate()
                subprocess.run(["sudo", "ip", "netns", "del", ns_a], capture_output=True)
                subprocess.run(["sudo", "ip", "netns", "del", ns_b], capture_output=True)

        # Independent verification of ReceiptI, ReceiptR, key 12 (exporter), and key 8 (E digest) in BOTH stores.
        conn_a = sqlite3.connect(db_a)
        conn_b = sqlite3.connect(db_b)
        row_a = conn_a.execute(
            "SELECT exporter, receipt_local, receipt_remote, exposure, issuer, subject FROM pairing_grants WHERE provenance='manual_authenticated_oob'"
        ).fetchone()
        row_b = conn_b.execute(
            "SELECT exporter, receipt_local, receipt_remote, exposure, issuer, subject FROM pairing_grants WHERE provenance='manual_authenticated_oob'"
        ).fetchone()
        assert row_a is not None and row_b is not None, "manual grant missing in store"
        exp_a, rl_a, rr_a, e_a, iss_a, sub_a = row_a
        exp_b, rl_b, rr_b, e_b, iss_b, sub_b = row_b
        assert len(exp_a) == 32 and exp_a == exp_b, "key 12 exporter mismatch between Node A and Node B"
        assert rl_a == rr_b and rr_a == rl_b, "stored receipts differ across Node A and Node B"
        assert iss_a == sub_b and sub_a == iss_b, "issuer/subject pin mismatch across Node A and Node B"

        # On Node A (responder), receipt_local is ReceiptR (role=1), receipt_remote is ReceiptI (role=0).
        p_r = verify_cose_sign1_ed25519(rl_a, exp_a, pub_a, expected_role=1)
        p_i = verify_cose_sign1_ed25519(rr_a, exp_b, pub_b, expected_role=0)
        assert p_r[6] == "contact" and p_i[6] == "owner-device", (p_r[6], p_i[6])
        assert p_r[8] == hashlib.sha256(e_a).digest(), "Q2-10 ReceiptR key 8 != sha256(E_A)"
        assert p_i[8] == hashlib.sha256(e_b).digest(), "Q2-10 ReceiptI key 8 != sha256(E_B)"
        assert p_r[8] != p_i[8], "asymmetric E digests should differ"

        # Negative control: planted bad receipt must drive the verifier RED.
        bad_receipt = bytearray(rl_a)
        bad_receipt[-1] ^= 0xFF
        bad_failed = False
        try:
            verify_cose_sign1_ed25519(bytes(bad_receipt), exp_a, pub_a, expected_role=1)
        except AssertionError:
            bad_failed = True
        assert bad_failed, "planted bad receipt did not fail independent verifier"
        print("independent-receipt-verifier:ok")
        print("pairing-two-daemon-acceptance:PASSED")


if __name__ == "__main__":
    bin_path = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("target/debug/xmsg")
    run_acceptance(bin_path.resolve())
