#!/usr/bin/env python3
"""WR-8b live collector J5 acceptance gate for xmsg-tmjs.9.6.

Exercises a real `xmsg observe-collector` binary with:
- mTLS poll source (`delivery: "delayed"` poll seam) carrying hostile XSS strings;
- cross-site HTTPS OIDC IdP (`https://localhost:<port>`);
- loopback HTTPS reverse proxy (`https://127.0.0.1:<port>`) forwarding HTTP + WebSocket;
- Playwright/Chromium verifying WR-1, WR-2, WR-5 (Delayed, current §2.12),
  authenticated SSR/WS projection, and identical checked-in asset hashes.
"""

import argparse
import base64
import hashlib
import http.server
import json
import os
import select
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from pathlib import Path

from playwright.sync_api import sync_playwright

CANONICAL_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "font-src 'self'; connect-src 'self'; frame-src 'none'; frame-ancestors 'none'; "
    "object-src 'none'; base-uri 'none'; form-action 'self'; require-trusted-types-for 'script'"
)

HOSTILE_LABEL = '<script>window.__pwn=1</script><img src=x onerror="window.__pwn=2">'
HOSTILE_TASK = "<script>xss</script>"
HOSTILE_REPO = "javascript:alert(1)"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def openssl_gen_pki(work: Path) -> dict:
    """Generate test CA, IdP cert, proxy cert, source-node cert+pin, collector client cert, and OIDC RSA key."""
    ca_key = work / "ca.key"
    ca_crt = work / "ca.crt"
    subprocess.run(
        [
            "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
            "-keyout", str(ca_key), "-out", str(ca_crt),
            "-days", "1", "-subj", "/CN=xmsg-wr8b-test-ca",
            "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign",
        ],
        check=True, capture_output=True,
    )

    def sign_cert(name: str, san: str) -> tuple[Path, Path]:
        key = work / f"{name}.key"
        csr = work / f"{name}.csr"
        crt = work / f"{name}.crt"
        ext = work / f"{name}.ext"
        ext.write_text(f"subjectAltName={san}\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n")
        subprocess.run(
            ["openssl", "req", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key), "-out", str(csr), "-subj", f"/CN={name}"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "x509", "-req", "-in", str(csr), "-CA", str(ca_crt), "-CAkey", str(ca_key), "-CAcreateserial", "-out", str(crt), "-days", "1", "-extfile", str(ext)],
            check=True, capture_output=True,
        )
        return key, crt

    idp_key, idp_crt = sign_cert("localhost", "DNS:localhost,IP:127.0.0.1")
    proxy_key, proxy_crt = sign_cert("proxy", "IP:127.0.0.1,DNS:localhost")
    node_key, node_crt = sign_cert("live-j5", "IP:127.0.0.1,DNS:live-j5")
    client_key, client_crt = sign_cert("collector", "DNS:collector")

    pub_der = subprocess.check_output(
        ["openssl", "x509", "-in", str(node_crt), "-pubkey", "-noout"]
    )
    spki_der = subprocess.check_output(
        ["openssl", "pkey", "-pubin", "-outform", "DER"],
        input=pub_der,
    )
    node_pin = hashlib.sha256(spki_der).hexdigest()

    oidc_rsa = work / "oidc_rsa.key"
    subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048", "-out", str(oidc_rsa)],
        check=True, capture_output=True,
    )
    pub_txt = subprocess.check_output(
        ["openssl", "rsa", "-in", str(oidc_rsa), "-pubout", "-modulus", "-noout"],
        text=True,
    )
    mod_hex = pub_txt.strip().split("=", 1)[1]
    n_bytes = bytes.fromhex(mod_hex)
    e_bytes = (65537).to_bytes(3, "big")

    return {
        "ca_crt": ca_crt,
        "idp_key": idp_key, "idp_crt": idp_crt,
        "proxy_key": proxy_key, "proxy_crt": proxy_crt,
        "node_key": node_key, "node_crt": node_crt, "node_pin": node_pin,
        "client_key": client_key, "client_crt": client_crt,
        "oidc_rsa": oidc_rsa,
        "jwk": {"kty": "RSA", "kid": "k1", "use": "sig", "alg": "RS256", "n": b64url(n_bytes), "e": b64url(e_bytes)},
    }


def sign_jwt(oidc_rsa: Path, payload: dict) -> str:
    hdr = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": "k1"}, separators=(",", ":")).encode())
    body = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{hdr}.{body}".encode("ascii")
    sig = subprocess.check_output(
        ["openssl", "dgst", "-sha256", "-sign", str(oidc_rsa)],
        input=signing_input,
    )
    return f"{hdr}.{body}.{b64url(sig)}"


class SourceNodeState:
    def __init__(self):
        self.scope = "a" * 64
        self.snapshot_hits = 0
        self.events_hits = 0


def start_source_node(pki: dict, state: SourceNodeState) -> tuple[socketserver.ThreadingTCPServer, int]:
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_GET(self):
            now = int(time.time())
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/fed/v2/observe/snapshot":
                state.snapshot_hits += 1
                body = json.dumps({
                    "v": 2,
                    "node": "live-j5",
                    "scope": state.scope,
                    "observed_at": now,
                    "endpoints": [
                        {
                            "id": "agent-xss@live-j5",
                            "node": "live-j5",
                            "kind": "instance",
                            "harness": "claude",
                            "state": "seen",
                            "source_at": now,
                            "label": HOSTILE_LABEL,
                            "activity": {
                                "state": "working",
                                "reason": "unreported",
                                "state_epoch": "0" * 32,
                                "incarnation": 1,
                                "revision": 1,
                                "changed_at": now,
                                "fresh_at": now,
                            },
                        }
                    ],
                    "truncated": False,
                    "available": "available",
                    "activity": {
                        "status": "enabled",
                        "complete": True,
                    },
                }).encode("utf-8")
            elif parsed.path == "/fed/v2/observe/events":
                state.events_hits += 1
                body = json.dumps({
                    "v": 2,
                    "node": "live-j5",
                    "epoch": "epoch-1",
                    "scope": state.scope,
                    "events": [],
                    "next": 0,
                    "has_more": False,
                    "gaps": [],
                    "available": True,
                }).encode("utf-8")
            else:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(pki["node_crt"]), str(pki["node_key"]))
    ctx.load_verify_locations(str(pki["ca_crt"]))
    ctx.verify_mode = ssl.CERT_REQUIRED
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    port = srv.server_address[1]
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, port


def start_oidc_idp(pki: dict, issuer_origin: str, port: int, hits: list) -> socketserver.ThreadingTCPServer:
    codes: dict[str, str] = {}

    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, fmt, *args):
            pass

        def do_GET(self):
            hits.append(self.path)
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/.well-known/openid-configuration":
                doc = json.dumps({
                    "issuer": issuer_origin,
                    "authorization_endpoint": f"{issuer_origin}/authorize",
                    "token_endpoint": f"{issuer_origin}/token",
                    "jwks_uri": f"{issuer_origin}/jwks.json",
                    "response_types_supported": ["code"],
                    "subject_types_supported": ["public"],
                    "id_token_signing_alg_values_supported": ["RS256"],
                }).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(doc)))
                self.end_headers()
                self.wfile.write(doc)
            elif parsed.path == "/jwks.json":
                doc = json.dumps({"keys": [pki["jwk"]]}).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(doc)))
                self.end_headers()
                self.wfile.write(doc)
            elif parsed.path == "/authorize":
                qs = urllib.parse.parse_qs(parsed.query)
                redirect_uri = qs["redirect_uri"][0]
                state = qs["state"][0]
                nonce = qs.get("nonce", [""])[0]
                code = f"code-{len(codes) + 1}"
                codes[code] = nonce
                sep = "&" if "?" in redirect_uri else "?"
                loc = f"{redirect_uri}{sep}code={urllib.parse.quote(code)}&state={urllib.parse.quote(state)}"
                self.send_response(302)
                self.send_header("Location", loc)
                self.end_headers()
            else:
                self.send_response(404)
                self.end_headers()

        def do_POST(self):
            if self.path != "/token":
                self.send_response(404)
                self.end_headers()
                return
            n = int(self.headers.get("Content-Length", "0"))
            raw = self.rfile.read(n).decode("utf-8")
            form = urllib.parse.parse_qs(raw)
            code = form["code"][0]
            nonce = codes.pop(code, "")
            now = int(time.time())
            id_token = sign_jwt(pki["oidc_rsa"], {
                "iss": issuer_origin,
                "sub": "owner-sub-1",
                "aud": "mc-web-client",
                "iat": now,
                "exp": now + 300,
                "nonce": nonce,
                "email": "owner@example.org",
                "email_verified": True,
            })
            tok = json.dumps({
                "access_token": "idp-access-token",
                "token_type": "Bearer",
                "expires_in": 300,
                "id_token": id_token,
            }).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(tok)))
            self.end_headers()
            self.wfile.write(tok)

    srv = socketserver.ThreadingTCPServer(("127.0.0.1", port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(pki["idp_crt"]), str(pki["idp_key"]))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def start_reverse_proxy(pki: dict, proxy_port: int, backend_port: int, mutant: str) -> socketserver.ThreadingTCPServer:
    """Loopback HTTPS reverse proxy forwarding HTTP + WebSocket upgrades to observe-collector."""

    def read_http_head(sock) -> tuple[bytes, bytes]:
        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            chunk = sock.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
        idx = buf.find(b"\r\n\r\n")
        if idx < 0:
            return bytes(buf), b""
        return bytes(buf[: idx + 4]), bytes(buf[idx + 4 :])

    def splice(a, b):
        try:
            while True:
                r, _, _ = select.select([a, b], [], [], 30)
                if not r:
                    break
                if a in r:
                    d = a.recv(8192)
                    if not d:
                        break
                    b.sendall(d)
                if b in r:
                    d = b.recv(8192)
                    if not d:
                        break
                    a.sendall(d)
        except OSError:
            pass

    class ProxyServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            client = self.request
            backend = None
            try:
                head_bytes, leftover = read_http_head(client)
                if not head_bytes:
                    return
                lines = head_bytes.decode("latin-1").split("\r\n")
                req_line = lines[0]
                hdr_lines = [l for l in lines[1:] if l]
                is_upgrade = any(l.lower().startswith("upgrade:") and "websocket" in l.lower() for l in hdr_lines)

                if mutant == "proxy-drop-upgrade" and is_upgrade:
                    hdr_lines = [
                        l for l in hdr_lines
                        if not l.lower().startswith("upgrade:") and not l.lower().startswith("connection:")
                    ]

                content_len = 0
                for l in hdr_lines:
                    if l.lower().startswith("content-length:"):
                        content_len = int(l.split(":", 1)[1].strip())
                body = bytearray(leftover)
                while len(body) < content_len:
                    chunk = client.recv(content_len - len(body))
                    if not chunk:
                        break
                    body.extend(chunk)

                backend = socket.create_connection(("127.0.0.1", backend_port), timeout=10)
                raw_req = (req_line + "\r\n" + "\r\n".join(hdr_lines) + "\r\n\r\n").encode("latin-1") + bytes(body)
                backend.sendall(raw_req)

                resp_head, resp_left = read_http_head(backend)
                if not resp_head:
                    return
                resp_lines = resp_head.decode("latin-1").split("\r\n")
                status_line = resp_lines[0]
                if " 101 " in status_line:
                    client.sendall(resp_head)
                    if resp_left:
                        client.sendall(resp_left)
                    splice(client, backend)
                    return

                # Non-upgrade HTTP response: read full body (Content-Length or chunked or EOF)
                resp_cl = None
                is_chunked = False
                is_html = False
                for l in resp_lines[1:]:
                    ll = l.lower()
                    if ll.startswith("content-length:"):
                        resp_cl = int(l.split(":", 1)[1].strip())
                    elif ll.startswith("transfer-encoding:") and "chunked" in ll:
                        is_chunked = True
                    elif ll.startswith("content-type:") and "text/html" in ll:
                        is_html = True

                if mutant == "asset-hash" and is_html and resp_cl is not None:
                    rbuf = bytearray(resp_left)
                    while len(rbuf) < resp_cl:
                        c = backend.recv(resp_cl - len(rbuf))
                        if not c:
                            break
                        rbuf.extend(c)
                    txt = bytes(rbuf).decode("utf-8", "replace")
                    import re
                    txt = re.sub(r"/assets/mc-roster\.[0-9a-f]+\.js", "/assets/mc-roster.000000000000.js", txt)
                    new_body = txt.encode("utf-8")
                    new_lines = [
                        (f"Content-Length: {len(new_body)}" if l.lower().startswith("content-length:") else l)
                        for l in resp_lines
                    ]
                    client.sendall("\r\n".join(new_lines).encode("latin-1") + new_body)
                    return

                req_target = req_line.split(" ", 2)[1] if len(req_line.split(" ", 2)) >= 2 else ""
                if (
                    mutant == "asset-bytes"
                    and resp_cl is not None
                    and req_target.startswith("/assets/mc-roster.")
                    and (req_target.endswith(".js") or req_target.endswith(".css"))
                ):
                    rbuf = bytearray(resp_left)
                    while len(rbuf) < resp_cl:
                        c = backend.recv(resp_cl - len(rbuf))
                        if not c:
                            break
                        rbuf.extend(c)
                    new_body = bytes(rbuf) + b"\n/*x*/"
                    new_lines = [
                        (f"Content-Length: {len(new_body)}" if l.lower().startswith("content-length:") else l)
                        for l in resp_lines
                    ]
                    client.sendall("\r\n".join(new_lines).encode("latin-1") + new_body)
                    return

                client.sendall(resp_head)
                if resp_left:
                    client.sendall(resp_left)
                if resp_cl is not None:
                    rem = resp_cl - len(resp_left)
                    while rem > 0:
                        c = backend.recv(min(8192, rem))
                        if not c:
                            break
                        client.sendall(c)
                        rem -= len(c)
                elif is_chunked:
                    # Relay until closing chunk 0\r\n\r\n
                    tail = bytearray(resp_left)
                    while not tail.endswith(b"0\r\n\r\n"):
                        c = backend.recv(8192)
                        if not c:
                            break
                        client.sendall(c)
                        tail.extend(c)
                else:
                    while True:
                        c = backend.recv(8192)
                        if not c:
                            break
                        client.sendall(c)
            except OSError:
                pass
            finally:
                if backend is not None:
                    try:
                        backend.close()
                    except OSError:
                        pass

    srv = ProxyServer(("127.0.0.1", proxy_port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(str(pki["proxy_crt"]), str(pki["proxy_key"]))
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--xmsg-bin", required=True)
    ap.add_argument("--assets-dir", required=True)
    ap.add_argument("--chromium", default="")
    ap.add_argument("--evidence-dir", default="")
    ap.add_argument("--mutant", default="none", choices=["none", "asset-hash", "asset-bytes", "proxy-drop-upgrade"])
    args = ap.parse_args()

    assets_dir = Path(args.assets_dir).resolve()
    js_files = list(assets_dir.glob("mc-roster.*.js"))
    css_files = list(assets_dir.glob("mc-roster.*.css"))
    assert len(js_files) == 1 and len(css_files) == 1, f"expected 1 js and 1 css in {assets_dir}"
    expected_js_name = js_files[0].name
    expected_css_name = css_files[0].name
    expected_js_sha = hashlib.sha256(js_files[0].read_bytes()).hexdigest()
    expected_css_sha = hashlib.sha256(css_files[0].read_bytes()).hexdigest()

    with tempfile.TemporaryDirectory(prefix="xmsg-wr8b-") as tmp:
        work = Path(tmp)
        pki = openssl_gen_pki(work)
        src_state = SourceNodeState()
        src_srv, src_port = start_source_node(pki, src_state)

        idp_port = free_port()
        idp_origin = f"https://127.0.0.1:{idp_port}"
        idp_hits = []
        idp_srv = start_oidc_idp(pki, idp_origin, idp_port, idp_hits)

        proxy_port = free_port()
        collector_port = free_port()
        proxy_origin = f"https://127.0.0.1:{proxy_port}"
        proxy_srv = start_reverse_proxy(pki, proxy_port, collector_port, args.mutant)

        secret_file = work / "oidc-secret"
        secret_file.write_text("fixture-client-secret\n")
        os.chmod(secret_file, 0o600)

        cfg_path = work / "collector.json"
        cfg_path.write_text(json.dumps({
            "client_cert": str(pki["client_crt"]),
            "client_key": str(pki["client_key"]),
            "sources": [{
                "node": "live-j5",
                "address": f"127.0.0.1:{src_port}",
                "pin": pki["node_pin"],
                "labels": True,
            }],
            "mission_control": {
                "public_origin": proxy_origin,
                "issuer": idp_origin,
                "accepted_iss": [idp_origin],
                "client_id": "mc-web-client",
                "client_secret_file": str(secret_file),
                "redirect_uri": f"{proxy_origin}/login/callback",
                "allowlist": ["owner@example.org"],
                "native_client_id": "xmsg-tui",
            },
        }))
        state_dir = work / "collector-state"
        state_dir.mkdir()
        os.chmod(state_dir, 0o700)
        collector_log = work / "collector.log"

        env = os.environ.copy()
        env["SSL_CERT_FILE"] = str(pki["ca_crt"])
        env.setdefault("RUST_LOG", "debug")
        proc = subprocess.Popen(
            [
                args.xmsg_bin, "observe-collector",
                "--config", str(cfg_path),
                "--state-dir", str(state_dir),
                "--listen", f"127.0.0.1:{collector_port}",
            ],
            env=env,
            stdout=collector_log.open("wb"),
            stderr=subprocess.STDOUT,
        )
        try:
            # Wait for collector HTTP listener & initial source poll
            deadline = time.monotonic() + 20
            ready = False
            while time.monotonic() < deadline:
                if proc.poll() is not None:
                    raise RuntimeError(f"observe-collector exited early ({proc.returncode}) idp_hits={idp_hits}:\n{collector_log.read_text()}")
                try:
                    with urllib.request.urlopen(f"http://127.0.0.1:{collector_port}/", timeout=2) as r:
                        if r.status == 200 and src_state.snapshot_hits >= 1:
                            ready = True
                            break
                except Exception:
                    pass
                time.sleep(0.15)
            assert ready, f"observe-collector did not become ready:\n{collector_log.read_text()}"
            # Give publish_poll_view a moment to push the snapshot into ReadHub
            time.sleep(0.3)

            launch_kw = {"headless": True, "args": ["--ignore-certificate-errors"]}
            if args.chromium:
                launch_kw["executable_path"] = args.chromium

            with sync_playwright() as p:
                browser = p.chromium.launch(**launch_kw)
                try:
                    # 1. WR-1 + identical CSS hash on unauthenticated GET /
                    ctx = browser.new_context(ignore_https_errors=True)
                    page = ctx.new_page()
                    main_resp = page.goto(f"{proxy_origin}/", wait_until="domcontentloaded")
                    assert main_resp is not None and main_resp.status == 200
                    hdrs = {k.lower(): v for k, v in main_resp.all_headers().items()}
                    assert hdrs.get("cache-control") == "no-store", hdrs
                    assert hdrs.get("x-content-type-options") == "nosniff", hdrs
                    assert hdrs.get("referrer-policy") == "no-referrer", hdrs
                    assert hdrs.get("content-security-policy") == CANONICAL_CSP, hdrs.get("content-security-policy")

                    css_href = page.locator("link[rel='stylesheet']").get_attribute("href")
                    assert css_href == f"/assets/{expected_css_name}", f"unauth CSS mismatch: {css_href} != /assets/{expected_css_name}"

                    # 2. OIDC login through proxy + cross-site IdP -> callback -> authenticated SSR + WS
                    cb_headers = {}
                    def on_resp(resp):
                        if urllib.parse.urlparse(resp.url).path == "/login/callback" and resp.status == 200:
                            cb_headers.update({k.lower(): v for k, v in resp.all_headers().items()})
                    page.on("response", on_resp)
                    page.locator("a[href='/login']").click()

                    # WR-5 (Delayed): real observe-collector poll seam MUST show Delayed
                    try:
                        page.wait_for_selector("[data-connection-badge='Delayed']", timeout=10000)
                    except Exception as exc:
                        raise RuntimeError(
                            f"{exc}\nBODY:\n{page.inner_html('body')}\nCOLLECTOR_LOG:\n{collector_log.read_text()}"
                        ) from exc
                    assert cb_headers.get("cache-control") == "no-store", cb_headers
                    assert cb_headers.get("x-content-type-options") == "nosniff", cb_headers
                    assert cb_headers.get("referrer-policy") == "no-referrer", cb_headers
                    assert cb_headers.get("content-security-policy") == CANONICAL_CSP, cb_headers

                    # Verify identical served JS & CSS asset hashes through proxy
                    js_src = page.locator("script[src^='/assets/mc-roster.']").get_attribute("src")
                    auth_css = page.locator("link[rel='stylesheet']").get_attribute("href")
                    assert js_src == f"/assets/{expected_js_name}", f"JS path mismatch: {js_src} != /assets/{expected_js_name}"
                    assert auth_css == f"/assets/{expected_css_name}", f"CSS path mismatch: {auth_css} != /assets/{expected_css_name}"

                    ssl_ctx = ssl.create_default_context(cafile=str(pki["ca_crt"]))
                    with urllib.request.urlopen(f"{proxy_origin}{js_src}", context=ssl_ctx, timeout=5) as r:
                        served_js_sha = hashlib.sha256(r.read()).hexdigest()
                    with urllib.request.urlopen(f"{proxy_origin}{auth_css}", context=ssl_ctx, timeout=5) as r:
                        served_css_sha = hashlib.sha256(r.read()).hexdigest()
                    assert served_js_sha == expected_js_sha, f"served JS sha mismatch: {served_js_sha} != {expected_js_sha}"
                    assert served_css_sha == expected_css_sha, f"served CSS sha mismatch: {served_css_sha} != {expected_css_sha}"

                    # Verify authenticated SSR/WS projection of live-j5 + hostile XSS escaped (WR-2)
                    try:
                        page.wait_for_selector("tr[data-endpoint='agent-xss@live-j5']", timeout=8000)
                    except Exception as exc:
                        raise RuntimeError(
                            f"{exc}\nBODY:\n{page.inner_html('body')}\nCOLLECTOR_LOG:\n{collector_log.read_text()}"
                        ) from exc
                    assert page.evaluate(
                        "() => document.body.textContent.includes('agent-xss@live-j5')"
                    )
                    assert page.locator("text=live-j5").count() >= 1
                    assert page.locator(f"text={HOSTILE_TASK}").count() >= 1 or page.evaluate(
                        "() => document.body.textContent.includes('<script>window.__pwn=1</script>')"
                    )
                    assert page.evaluate("() => window.__pwn === undefined"), "XSS executed!"
                    forbidden = page.evaluate(
                        "() => document.querySelectorAll(\"script:not([src^='/assets/mc-roster.']), img, iframe, svg\").length"
                    )
                    assert forbidden == 0, f"forbidden DOM nodes found: {forbidden}"
                    ctx.close()

                    # 3. WR-2 under bypass_csp=True + authenticated SSR HTML check (with JS disabled)
                    ctx_nocsp = browser.new_context(ignore_https_errors=True, bypass_csp=True)
                    p2 = ctx_nocsp.new_page()
                    p2.goto(f"{proxy_origin}/", wait_until="domcontentloaded")
                    p2.locator("a[href='/login']").click()
                    p2.wait_for_selector("[data-connection-badge='Delayed']", timeout=10000)
                    assert p2.evaluate("() => window.__pwn === undefined"), "XSS executed under bypass_csp!"
                    # Fetch authenticated SSR HTML directly using the browser's __Host-mc_session cookie
                    cookies = ctx_nocsp.cookies(proxy_origin)
                    mc_cookie = next(c for c in cookies if c["name"] == "__Host-mc_session")
                    req = urllib.request.Request(
                        f"{proxy_origin}/",
                        headers={
                            "Cookie": f"__Host-mc_session={mc_cookie['value']}",
                            "Sec-Fetch-Site": "same-origin",
                        },
                    )
                    with urllib.request.urlopen(req, context=ssl_ctx, timeout=5) as r:
                        ssr_html = r.read().decode("utf-8")
                    assert "data-ssr-node=\"live-j5\"" in ssr_html, "SSR missing live-j5"
                    assert "&lt;script&gt;window.__pwn=1&lt;/script&gt;" in ssr_html, "SSR did not escape hostile label"
                    assert "<script>window.__pwn=1</script>" not in ssr_html, "raw unescaped script in SSR HTML"
                    ctx_nocsp.close()

                    if args.evidence_dir:
                        ev = Path(args.evidence_dir)
                        ev.mkdir(parents=True, exist_ok=True)
                        (ev / "wr8b-acceptance.json").write_text(json.dumps({
                            "status": "PASSED",
                            "js_path": js_src,
                            "js_sha256": served_js_sha,
                            "css_path": auth_css,
                            "css_sha256": served_css_sha,
                            "source_snapshot_hits": src_state.snapshot_hits,
                            "connection_badge": "Delayed",
                            "ssr_escaped": True,
                            "bypass_csp_pwn_undefined": True,
                        }, indent=2) + "\n")

                    print("WR-8b live collector J5 acceptance PASS")
                    return 0
                finally:
                    browser.close()
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
            src_srv.shutdown()
            idp_srv.shutdown()
            proxy_srv.shutdown()


if __name__ == "__main__":
    raise SystemExit(main())
