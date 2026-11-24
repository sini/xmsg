#!/usr/bin/env python3
"""Playwright/Chromium browser gate for xmsg-tmjs.9 Mission Control web roster (WR-1..WR-8a)."""

import argparse
import base64
import hashlib
import http.server
import json
import secrets
import socket
import struct
import threading
import urllib.parse
from pathlib import Path

from playwright.sync_api import sync_playwright

CANONICAL_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; "
    "font-src 'self'; connect-src 'self'; frame-src 'none'; frame-ancestors 'none'; "
    "object-src 'none'; base-uri 'none'; form-action 'self'; require-trusted-types-for 'script'"
)

WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


def ws_recv_frame(sock):
    hdr = sock.recv(2)
    if len(hdr) < 2:
        return None, None
    b1, b2 = hdr[0], hdr[1]
    opcode = b1 & 0x0F
    masked = (b2 & 0x80) != 0
    length = b2 & 0x7F
    if length == 126:
        length = struct.unpack("!H", sock.recv(2))[0]
    elif length == 127:
        length = struct.unpack("!Q", sock.recv(8))[0]
    mask = sock.recv(4) if masked else b""
    data = bytearray()
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            break
        data.extend(chunk)
    if masked:
        for i in range(len(data)):
            data[i] ^= mask[i % 4]
    return opcode, bytes(data)


def ws_send_text(sock, text: str):
    payload = text.encode("utf-8")
    n = len(payload)
    if n < 126:
        hdr = bytes([0x81, n])
    elif n < 65536:
        hdr = struct.pack("!BBH", 0x81, 126, n)
    else:
        hdr = struct.pack("!BBQ", 0x81, 127, n)
    sock.sendall(hdr + payload)


def ws_send_close(sock, code: int, reason: str = ""):
    payload = struct.pack("!H", code) + reason.encode("utf-8")
    hdr = bytes([0x88, len(payload)])
    try:
        sock.sendall(hdr + payload)
    except OSError:
        pass


class FixtureState:
    def __init__(self, assets_dir: Path, js_name: str, css_name: str):
        self.assets_dir = assets_dir
        self.js_name = js_name
        self.css_name = css_name
        self.scenario = "normal"
        self.ws_attempts = 0
        self.probe_count = 0
        self.probe_status = 200
        self.ws_upgrade_status = 101
        self.client_hellos = []
        self.client_frames = []
        self.ws_conns = []
        self.login_hits = 0
        self.records = {}  # cookie -> {"revoked": bool}
        self.idp_auto_approve = False
        self.idp_origin = ""
        self.app_origin = ""

    def ssr_html(self, signed_in: bool, cross_site: bool = False) -> str:
        if not signed_in:
            return (
                "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                "<title>Mission Control</title>"
                f"<link rel=\"stylesheet\" href=\"/assets/{self.css_name}\">"
                "</head><body><main><header class=\"mc-shell-bar\"><h1>Mission Control</h1>"
                "<nav class=\"mc-shell-actions\"><a class=\"mc-btn\" href=\"/login\">Sign in</a></nav>"
                "</header><p class=\"mc-muted\">Sign in to inspect this fleet.</p></main></body></html>"
            )
        if cross_site:
            return (
                "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
                "<title>Mission Control</title>"
                f"<link rel=\"stylesheet\" href=\"/assets/{self.css_name}\">"
                "</head><body><main><header class=\"mc-shell-bar\"><h1>Mission Control</h1>"
                "<nav class=\"mc-shell-actions\"><a class=\"mc-btn\" href=\"/\">Open Mission Control</a></nav>"
                "</header><p class=\"mc-muted\">Open Mission Control directly.</p></main></body></html>"
            )
        return (
            "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
            "<title>Mission Control</title>"
            f"<link rel=\"stylesheet\" href=\"/assets/{self.css_name}\">"
            f"<script defer src=\"/assets/{self.js_name}\"></script>"
            "</head><body><main>"
            "<header class=\"mc-shell-bar\"><h1>Mission Control</h1>"
            "<nav class=\"mc-shell-actions\"><a class=\"mc-btn\" href=\"/device\">Connect a device</a>"
            "<form method=\"post\" action=\"/logout\"><input type=\"hidden\" name=\"csrf\" value=\"tok\">"
            "<button class=\"mc-btn\" type=\"submit\">Sign out</button></form></nav></header>"
            "<div id=\"mc-live\"></div>"
            "<div id=\"mc-ssr\"><section class=\"mc-node\" data-ssr-node=\"sentinel-node\">"
            "<h2>sentinel-node</h2><p>SSR sentinel row</p></section></div>"
            "</main></body></html>"
        )


def make_idp_handler(state: FixtureState):
    class IdpHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urllib.parse.urlparse(self.path)
            if parsed.path == "/authorize":
                qs = urllib.parse.parse_qs(parsed.query)
                redir = qs.get("redirect_uri", [f"{state.app_origin}/login/callback"])[0]
                if state.idp_auto_approve:
                    self.send_response(302)
                    self.send_header("Location", f"{redir}?code=c_auto&state=s1")
                    self.end_headers()
                    return
                body = (
                    "<!doctype html><html><body><h1>Fixture IdP</h1>"
                    f"<a id=\"approve\" href=\"{redir}?code=c_manual&state=s1\">Approve</a>"
                    "</body></html>"
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.end_headers()
                self.wfile.write(body)
                return
            self.send_response(404)
            self.end_headers()

        def log_message(self, *_):
            pass

    return IdpHandler


def make_handler(state: FixtureState):
    class Handler(http.server.BaseHTTPRequestHandler):
        def _has_valid_cookie(self) -> str | None:
            raw = self.headers.get("Cookie", "")
            for part in raw.split(";"):
                k, _, v = part.strip().partition("=")
                if k == "__Host-mc_session" and v in state.records and not state.records[v]["revoked"]:
                    return v
            return None

        def do_POST(self):
            path = self.path.split("?")[0]
            if path == "/logout":
                tok = self._has_valid_cookie()
                if tok:
                    state.records[tok]["revoked"] = True
                self.send_response(303)
                self.send_header("Location", "/")
                self.send_header("Set-Cookie", "__Host-mc_session=; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=0")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                return
            self.send_response(405)
            self.end_headers()

        def do_GET(self):
            path = self.path.split("?")[0]
            if self.headers.get("Upgrade", "").lower() == "websocket" and path == "/v1/mission-control/session":
                state.ws_attempts += 1
                if state.ws_upgrade_status != 101:
                    self.send_response(state.ws_upgrade_status)
                    if state.ws_upgrade_status == 302:
                        self.send_header("Location", "/login")
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    return
                key = self.headers.get("Sec-WebSocket-Key", "")
                accept = base64.b64encode(hashlib.sha1((key + WS_GUID).encode()).digest()).decode()
                self.send_response(101, "Switching Protocols")
                self.send_header("Upgrade", "websocket")
                self.send_header("Connection", "Upgrade")
                self.send_header("Sec-WebSocket-Accept", accept)
                self.send_header("Sec-WebSocket-Protocol", "xmsg.mission-control.v1")
                self.end_headers()
                conn = self.connection
                state.ws_conns.append(conn)
                self._serve_ws(conn)
                return

            if path == f"/assets/{state.js_name}":
                self._send(200, "application/javascript; charset=utf-8", (state.assets_dir / state.js_name).read_bytes())
            elif path == f"/assets/{state.css_name}":
                self._send(200, "text/css; charset=utf-8", (state.assets_dir / state.css_name).read_bytes())
            elif path == "/favicon.ico":
                self._send(204, "image/x-icon", b"")
            elif path == "/login":
                state.login_hits += 1
                self.send_response(302)
                self.send_header("Location", f"{state.idp_origin}/authorize?redirect_uri={state.app_origin}/login/callback")
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
            elif path == "/login/callback":
                tok = secrets.token_hex(16)
                state.records[tok] = {"revoked": False}
                body = b"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta http-equiv=\"refresh\" content=\"0;url=/\"><title>Signing in</title></head><body><main><p>Signed in. <a href=\"/\">Continue</a></p></main></body></html>"
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
                self.send_header("Cache-Control", "no-store")
                self.send_header("X-Content-Type-Options", "nosniff")
                self.send_header("Referrer-Policy", "no-referrer")
                self.send_header("Content-Security-Policy", CANONICAL_CSP)
                self.send_header("Set-Cookie", f"__Host-mc_session={tok}; Path=/; HttpOnly; SameSite=Strict; Secure; Max-Age=3600")
                self.end_headers()
                self.wfile.write(body)
            elif path == "/v1/mission-control/snapshot/attention":
                state.probe_count += 1
                if state.probe_status == 302:
                    self.send_response(302)
                    self.send_header("Location", "/login")
                    self.send_header("Cache-Control", "no-store")
                    self.end_headers()
                    return
                self._send(state.probe_status, "application/json", b"{}")
            elif path == "/dom-positive":
                self._send(200, "text/html; charset=utf-8", b"<html><body><img src='/resource-positive'><script>window.__domPos=1</script></body></html>")
            elif path == "/network-positive":
                self._send(200, "text/html; charset=utf-8", b"<html><body><img src='https://attacker.invalid/positive'></body></html>")
            elif path == "/ws-positive":
                self._send(200, "text/html; charset=utf-8", b"<html><body><script>try{new WebSocket('wss://attacker.invalid/ws')}catch(e){}</script></body></html>")
            elif path == "/":
                if state.scenario != "normal":
                    self._send(200, "text/html; charset=utf-8", state.ssr_html(True, False).encode())
                    return
                tok = self._has_valid_cookie()
                sfs = self.headers.get("Sec-Fetch-Site", "")
                if tok is None:
                    self._send(200, "text/html; charset=utf-8", state.ssr_html(False).encode())
                elif sfs in ("same-origin", "none"):
                    self._send(200, "text/html; charset=utf-8", state.ssr_html(True, False).encode())
                else:
                    self._send(200, "text/html; charset=utf-8", state.ssr_html(True, True).encode())
            else:
                self._send(404, "text/plain", b"not found")

        def _send(self, code, ctype, body):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy", CANONICAL_CSP)
            self.end_headers()
            if body:
                self.wfile.write(body)

        def _serve_ws(self, conn):
            conn.settimeout(10.0)
            try:
                while True:
                    op, data = ws_recv_frame(conn)
                    if op is None or op == 0x8:
                        break
                    if op == 0x1:
                        msg = json.loads(data.decode("utf-8"))
                        state.client_frames.append(msg)
                        if msg.get("type") == "hello":
                            state.client_hellos.append(msg)
                            ws_send_text(
                                conn,
                                json.dumps({
                                    "v": 1,
                                    "type": "hello",
                                    "re": msg["id"],
                                    "protocol": 1,
                                    "capabilities": ["observe", "activity"],
                                    "connection": f"c_{state.ws_attempts}",
                                    "actor": {"principal": "p_1", "display": "owner", "class": "browser"},
                                    "lease_expires_at": 1795000010000,
                                    "server_at": 1795000000000,
                                    "limits": {
                                        "max_client_message_bytes": 16384,
                                        "max_server_message_bytes": 262144,
                                        "max_json_depth": 16,
                                        "subscriptions_per_connection": 16,
                                        "tick_interval_ms": 15000,
                                    },
                                }),
                            )
                        elif msg.get("type") == "subscribe":
                            sub = msg["sub"]
                            kind = msg["scope"]["kind"]
                            has_cursor = "cursor" in msg
                            ws_send_text(
                                conn,
                                json.dumps({
                                    "v": 1,
                                    "type": "subscribed",
                                    "re": msg["id"],
                                    "sub": sub,
                                    "mode": "resume" if has_cursor else "snapshot",
                                    "stream_epoch": "e1",
                                }),
                            )
                            if not has_cursor:
                                self._send_initial_snapshot(conn, sub, kind, msg["scope"].get("node"))
            except OSError:
                pass

        def _send_initial_snapshot(self, conn, sub, kind, node_name):
            if kind == "attention":
                ws_send_text(
                    conn,
                    json.dumps({
                        "v": 1, "type": "snapshot", "sub": sub, "part": 0, "final": True,
                        "stream_epoch": "e1", "cursor": "att_c1", "server_at": 1795000000100,
                        "truncated": False, "nodes": [],
                        "attention": [{"id": "att_1", "kind": "node_unreachable", "node": "laptop-stale", "since": 1794999990000, "detail": {"delivery": "delayed"}}],
                    }),
                )
                return

            if kind == "node":
                ws_send_text(
                    conn,
                    json.dumps({
                        "v": 1, "type": "snapshot", "sub": sub, "part": 0, "final": True,
                        "stream_epoch": "e1", "cursor": f"node_{node_name}_c1", "server_at": 1795000000100,
                        "truncated": False,
                        "nodes": [{
                            "node": node_name, "status": "healthy", "delivery": "delayed", "last_source_at": 1794999998000,
                            "history_hidden": False, "activity_authority": "complete",
                            "endpoints": [{
                                "descriptor": {
                                    "id": f"claude-1@{node_name}", "node": node_name, "kind": "instance", "harness": "claude", "state": "seen",
                                    "label": "<script>window.__pwn=1</script>agent",
                                    "context": {"repo": "<img src=x onerror=\"window.__pwn=2\">", "branch": "javascript:alert(1)", "updated_at": 1794999990, "generation": 1, "stale": False},
                                },
                                "activity": {"state": "unknown", "reason": "restarted", "state_epoch": "0a1b", "incarnation": 1, "revision": 2, "changed_at": 1794999900, "fresh_at": 1794999990},
                            }],
                            "endpoints_truncated": False, "exchanges": [], "source_gaps": [],
                        }],
                    }),
                )
                return

            if state.scenario == "empty":
                nodes = []
            elif state.scenario == "all-loading":
                nodes = [{"node": "load-1", "status": "loading", "delivery": "live", "history_hidden": False, "endpoints": [], "endpoints_truncated": False, "exchanges": [], "source_gaps": []}]
            elif state.scenario == "all-loading-delayed":
                nodes = [{"node": "load-1", "status": "loading", "delivery": "delayed", "history_hidden": False, "endpoints": [], "endpoints_truncated": False, "exchanges": [], "source_gaps": []}]
            else:
                nodes = [
                    {
                        "node": "laptop-a", "status": "healthy", "delivery": "delayed", "last_source_at": 1794999998000,
                        "via_hub": "<script>window.__pwn=3</script>hub-1", "history_hidden": False, "activity_authority": "complete",
                        "endpoints": [
                            {"descriptor": {"id": "z-idle@laptop-a", "node": "laptop-a", "kind": "instance", "harness": "pi", "state": "seen"},
                             "activity": {"state": "idle", "reason": "scheduled_wake", "state_epoch": "0a1b", "incarnation": 1, "revision": 1, "changed_at": 1794999995, "fresh_at": 1794999995}},
                            {"descriptor": {"id": "a-perm@laptop-a", "node": "laptop-a", "kind": "instance", "harness": "claude", "state": "seen", "label": "<script>window.__pwn=1</script>perm"},
                             "activity": {"state": "blocked", "block": "permission", "state_epoch": "0a1b", "incarnation": 1, "revision": 1, "changed_at": 1794999990, "fresh_at": 1794999990}},
                            {"descriptor": {"id": "b-input@laptop-a", "node": "laptop-a", "kind": "instance", "harness": "claude", "state": "seen", "label": "input"},
                             "activity": {"state": "blocked", "block": "input", "state_epoch": "0a1b", "incarnation": 1, "revision": 1, "changed_at": 1794999900, "fresh_at": 1794999990}},
                        ],
                        "endpoints_truncated": False, "exchanges": [], "source_gaps": [],
                    },
                    {
                        "node": "laptop-stale", "status": "stale", "delivery": "live", "history_hidden": False,
                        "endpoints": [{"descriptor": {"id": "s-blocked@laptop-stale", "node": "laptop-stale", "kind": "instance", "harness": "codex", "state": "seen"},
                                       "activity": {"state": "blocked", "block": "input", "state_epoch": "0a1b", "incarnation": 1, "revision": 1, "changed_at": 1794999900, "fresh_at": 1794999900}}],
                        "endpoints_truncated": False, "exchanges": [], "source_gaps": [],
                    },
                    {
                        "node": "old-retained", "status": "removed_retained", "delivery": "delayed", "last_activity_at": 1794990000000,
                        "history_hidden": False, "endpoints": [], "endpoints_truncated": False, "exchanges": [], "source_gaps": [],
                    },
                ]
            if state.scenario == "multipart":
                ws_send_text(conn, json.dumps({"v": 1, "type": "snapshot", "sub": sub, "part": 0, "final": False, "stream_epoch": "e1", "server_at": 1795000000100, "nodes": nodes[:1]}))
                return
            ws_send_text(
                conn,
                json.dumps({"v": 1, "type": "snapshot", "sub": sub, "part": 0, "final": True, "stream_epoch": "e1", "cursor": "fleet_c1", "server_at": 1795000000100, "truncated": False, "nodes": nodes}),
            )

        def log_message(self, *_):
            pass

    return Handler


def check_positive_controls(browser, origin):
    for pos_path in ("/dom-positive", "/network-positive", "/ws-positive"):
        ctx = browser.new_context(bypass_csp=True)
        page = ctx.new_page()
        reqs, ws_urls = [], []
        page.on("request", lambda r: reqs.append(r.url))
        page.on("websocket", lambda w: ws_urls.append(w.url))
        page.goto(f"{origin}{pos_path}", wait_until="domcontentloaded")
        page.wait_for_timeout(150)
        caught = (
            (pos_path == "/dom-positive" and (page.locator("img").count() > 0 or page.evaluate("window.__domPos === 1")))
            or (pos_path == "/network-positive" and any("attacker.invalid" in u for u in reqs))
            or (pos_path == "/ws-positive" and any("attacker.invalid" in u for u in ws_urls))
        )
        ctx.close()
        assert caught, f"positive control {pos_path} was NOT caught under bypass_csp=True"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--chromium", required=True)
    parser.add_argument("--assets-dir", type=Path, required=True)
    args = parser.parse_args()

    js_files = [p.name for p in args.assets_dir.iterdir() if p.name.endswith(".js")]
    css_files = [p.name for p in args.assets_dir.iterdir() if p.name.endswith(".css")]
    assert len(js_files) == 1 and len(css_files) == 1
    js_name, css_name = js_files[0], css_files[0]

    state = FixtureState(args.assets_dir, js_name, css_name)
    app_srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), make_handler(state))
    idp_srv = http.server.ThreadingHTTPServer(("localhost", 0), make_idp_handler(state))
    state.app_origin = f"http://127.0.0.1:{app_srv.server_port}"
    state.idp_origin = f"http://localhost:{idp_srv.server_port}"
    threading.Thread(target=app_srv.serve_forever, daemon=True).start()
    threading.Thread(target=idp_srv.serve_forever, daemon=True).start()
    origin = state.app_origin

    sub_allowlist = {
        f"{origin}/",
        f"{origin}/assets/{js_name}",
        f"{origin}/assets/{css_name}",
        f"{origin}/favicon.ico",
        f"{origin}/v1/mission-control/session",
        f"{origin}/v1/mission-control/snapshot/attention",
    }
    ws_allowlist = {f"ws://127.0.0.1:{app_srv.server_port}/v1/mission-control/session"}

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(
                executable_path=args.chromium,
                args=["--no-sandbox", "--disable-dev-shm-usage", "--disable-gpu"],
            )
            try:
                # WR-1 positive controls
                check_positive_controls(browser, origin)

                # WR-1, WR-2, WR-6, WR-7 under bypass_csp=False and True
                state.scenario = "auth_ssr_fixture"
                for bypass in (False, True):
                    ctx = browser.new_context(bypass_csp=bypass)
                    page = ctx.new_page()
                    reqs, ws_urls, page_errors = [], [], []
                    page.on("request", lambda r: reqs.append(r.url))
                    page.on("websocket", lambda w: ws_urls.append(w.url))
                    page.on("pageerror", lambda e: page_errors.append(str(e)))
                    resp = page.goto(f"{origin}/", wait_until="domcontentloaded")
                    assert resp.status == 200
                    assert resp.headers.get("content-security-policy") == CANONICAL_CSP
                    page.wait_for_selector("[data-connection-badge='Delayed']", timeout=5000)
                    assert page.evaluate("window.__pwn === undefined")
                    assert page.locator("iframe, object, embed, img").count() == 0
                    assert not page_errors
                    for u in reqs:
                        assert u in sub_allowlist, f"off-allowlist request: {u}"
                    for u in ws_urls:
                        assert u in ws_allowlist, f"off-allowlist ws: {u}"
                    hello = state.client_hellos[-1]
                    assert hello["capabilities"] == ["observe", "activity"]
                    assert hello["require"] == ["observe"]
                    rows = page.locator("[data-node='laptop-a'] tbody tr")
                    assert rows.nth(0).get_attribute("data-endpoint") == "b-input@laptop-a"
                    assert rows.nth(1).get_attribute("data-endpoint") == "a-perm@laptop-a"
                    assert rows.nth(2).get_attribute("data-endpoint") == "z-idle@laptop-a"
                    assert page.locator("[data-node='laptop-stale'] .mc-status-unreachable").count() == 1
                    assert page.locator("[data-node='old-retained'] button", has_text="Node detail").count() == 0
                    # WR-6: history_hidden immediate deletion + detail teardown
                    page.locator("[data-node='laptop-a'] button", has_text="Node detail").click()
                    page.wait_for_selector("[data-detail-node='laptop-a']", timeout=5000)
                    manage_btn = page.locator("[data-detail-node='laptop-a'] button", has_text="Manage")
                    assert manage_btn.is_disabled()
                    assert manage_btn.evaluate("el => el.disabled") is True
                    ws_send_text(
                        state.ws_conns[-1],
                        json.dumps({"v": 1, "type": "event", "sub": "fleet", "seq": 100, "cursor": "c_mask", "at": 1795000002000,
                                    "delta": {"kind": "node_status", "node": "laptop-a", "status": "healthy", "delivery": "delayed", "history_hidden": True}}),
                    )
                    page.wait_for_timeout(150)
                    assert page.locator("[data-detail-node='laptop-a']").count() == 0, "detail panel not torn down on mask"
                    assert page.locator("[data-node='laptop-a'] tbody tr").count() == 0, "masked rows not deleted"
                    ctx.close()

                # WR-4(a) No-JS SSR + WR-4(b) multipart atomic commit
                ctx = browser.new_context(java_script_enabled=False)
                page = ctx.new_page()
                page.goto(f"{origin}/", wait_until="domcontentloaded")
                assert page.locator("[data-ssr-node='sentinel-node']").count() == 1
                ctx.close()

                state.scenario = "multipart"
                ctx = browser.new_context()
                page = ctx.new_page()
                page.goto(f"{origin}/", wait_until="domcontentloaded")
                page.wait_for_timeout(200)
                assert page.locator("[data-ssr-node='sentinel-node']").count() == 1, "partial part:0 overwrote SSR"
                assert page.locator("[data-connection-badge='Unknown']").count() == 1
                ctx.close()

                # WR-5(a): empty, all-loading, all-loading-delayed
                for scen, expected_badge in [("empty", "Unknown"), ("all-loading", "Unknown"), ("all-loading-delayed", "Delayed")]:
                    state.scenario = scen
                    ctx = browser.new_context()
                    page = ctx.new_page()
                    page.goto(f"{origin}/", wait_until="domcontentloaded")
                    if scen == "empty":
                        page.wait_for_selector(".mc-empty", state="attached", timeout=5000)
                        assert page.locator(f"[data-connection-badge='{expected_badge}']").count() == 1
                    else:
                        page.wait_for_selector("[data-node='load-1']", timeout=5000)
                        assert page.locator(f"[data-connection-badge='{expected_badge}']").count() == 1
                        assert "coverage: empty" in (page.locator(".mc-banner").text_content() or "")
                    ctx.close()

                # WR-5(b),(c),(d),(e),(g): fake clock, 1006 resume+stale, 4401, 4403, 4409, and 302/401/403/503 probes
                state.scenario = "auth_ssr_fixture"
                state.ws_upgrade_status = 101
                state.probe_status = 200
                state.ws_attempts = 0
                state.client_frames.clear()
                ctx = browser.new_context()
                page = ctx.new_page()
                page.clock.install()
                page.goto(f"{origin}/", wait_until="domcontentloaded")
                page.wait_for_selector("[data-connection-badge='Delayed']", timeout=5000)
                page.wait_for_selector("[data-node='laptop-a']", timeout=5000)

                # WR-5(b): 1006 -> Reconnecting -> lossless cursor resume -> Stale after stale_after_ms (tick does not reset age)
                state.client_frames.clear()
                conns_before = len(state.ws_conns)
                state.ws_conns[-1].shutdown(socket.SHUT_RDWR)
                state.ws_conns[-1].close()
                page.wait_for_selector("[data-connection-badge='Reconnecting']", timeout=5000)
                page.clock.run_for(2500)
                page.wait_for_selector("[data-connection-badge='Delayed']", timeout=5000)
                assert len(state.ws_conns) == conns_before + 1
                fleet_resumes = [f for f in state.client_frames if f.get("type") == "subscribe" and f.get("sub") == "fleet"]
                assert fleet_resumes and fleet_resumes[-1].get("cursor") == "fleet_c1", f"expected cursor resume, got {fleet_resumes}"
                # tick must not reset node source age; > 2*tick (31s) -> Unknown; >= staleAfterMs (46s) -> Stale
                ws_send_text(state.ws_conns[-1], json.dumps({"v": 1, "type": "tick", "server_at": 1795000030000}))
                page.clock.run_for(15000)
                node_hdr = page.locator("[data-node='laptop-a'] .mc-node-header").text_content() or ""
                assert "source 0s ago" not in node_hdr, f"tick reset source age: {node_hdr}"
                page.clock.run_for(16000)
                page.wait_for_selector("[data-connection-badge='Unknown']", timeout=5000)
                page.clock.run_for(15000)
                page.wait_for_selector("[data-connection-badge='Stale']", timeout=5000)

                # Refresh live state before 4401/4403/4409
                ws_send_text(
                    state.ws_conns[-1],
                    json.dumps({"v": 1, "type": "event", "sub": "fleet", "seq": 2, "cursor": "c_live", "at": 1795000062000,
                                "delta": {"kind": "node_status", "node": "laptop-a", "status": "healthy", "delivery": "delayed", "history_hidden": False}}),
                )
                page.wait_for_selector("[data-connection-badge='Delayed']", timeout=5000)

                # WR-5(c): 4401 -> one immediate re-admit and cursor resume
                state.client_frames.clear()
                conns_before = len(state.ws_conns)
                ws_send_close(state.ws_conns[-1], 4401, "auth expired")
                page.wait_for_timeout(150)
                page.wait_for_selector("[data-connection-badge='Delayed']", timeout=5000)
                assert len(state.ws_conns) == conns_before + 1
                fleet_4401 = [f for f in state.client_frames if f.get("type") == "subscribe" and f.get("sub") == "fleet"]
                assert fleet_4401 and fleet_4401[-1].get("cursor") == "c_live", f"4401 must resume cursor, got {fleet_4401}"

                # WR-5(d): 4403 -> state cleared, one re-admit (no cursor), then refused re-admit stops at re-authenticate
                state.client_frames.clear()
                conns_before = len(state.ws_conns)
                ws_send_close(state.ws_conns[-1], 4403, "policy changed")
                page.wait_for_timeout(150)
                page.wait_for_selector("[data-connection-badge='Delayed']", timeout=5000)
                assert len(state.ws_conns) == conns_before + 1
                subs_4403 = [f for f in state.client_frames if f.get("type") == "subscribe"]
                assert len(subs_4403) >= 2 and all("cursor" not in f for f in subs_4403), f"4403 must clear all cursors, got {subs_4403}"

                # Second 4403 where re-admit upgrade fails -> stops at re-authenticate
                state.ws_upgrade_status = 403
                attempts_before = state.ws_attempts
                ws_send_close(state.ws_conns[-1], 4403, "policy revoked")
                page.wait_for_selector("a[href='/login']", timeout=5000)
                page.clock.run_for(5000)
                assert page.locator("[data-node='laptop-a']").count() == 0
                assert state.ws_attempts == attempts_before + 1
                ctx.close()
                state.ws_upgrade_status = 101

                # WR-5(e): 4409 -> client incompatible, 0 retries
                ctx = browser.new_context()
                page = ctx.new_page()
                page.clock.install()
                page.goto(f"{origin}/", wait_until="domcontentloaded")
                page.wait_for_selector("[data-connection-badge='Delayed']", timeout=5000)
                prev_attempts = state.ws_attempts
                ws_send_close(state.ws_conns[-1], 4409, "version mismatch")
                page.wait_for_selector(".mc-error", state="attached", timeout=5000)
                page.clock.run_for(5000)
                assert "client incompatible" in (page.locator(".mc-banner").text_content() or "")
                assert state.ws_attempts == prev_attempts
                ctx.close()

                # WR-5(g): 302, 401, 403 probes stop & clear sentinel; 503 probe resumes backoff
                for probe_code in (302, 401, 403):
                    state.ws_upgrade_status = probe_code
                    state.probe_status = probe_code
                    state.probe_count = 0
                    state.ws_attempts = 0
                    ctx = browser.new_context()
                    page = ctx.new_page()
                    page.goto(f"{origin}/", wait_until="domcontentloaded")
                    page.wait_for_selector("a[href='/login']", timeout=5000)
                    assert state.probe_count == 1, f"probe {probe_code} count={state.probe_count}"
                    assert state.ws_attempts == 1
                    assert page.locator("[data-ssr-node='sentinel-node']").count() == 0
                    ctx.close()

                state.ws_upgrade_status = 503
                state.probe_status = 503
                state.probe_count = 0
                state.ws_attempts = 0
                ctx = browser.new_context()
                page = ctx.new_page()
                page.clock.install()
                page.goto(f"{origin}/", wait_until="domcontentloaded")
                page.wait_for_selector("[data-connection-badge='Reconnecting']", timeout=5000)
                assert state.probe_count >= 1
                page.clock.run_for(2500)
                page.wait_for_timeout(200)
                assert state.ws_attempts >= 2, f"503 probe must resume backoff, attempts={state.ws_attempts}"
                # Exhaust all 8 reconnect_max_attempts (1 initial + 8 retries = 9 total) -> Stale + manual Reconnect
                for _ in range(10):
                    page.clock.run_for(31000)
                    page.wait_for_timeout(80)
                page.wait_for_selector("[data-connection-badge='Stale']", timeout=5000)
                assert page.locator("button:has-text('Reconnect')").count() == 1, "exhausted reconnect must show manual Reconnect button"
                assert state.ws_attempts == 9, f"expected 1 initial + 8 reconnect_max_attempts = 9, got {state.ws_attempts}"
                ctx.close()
                state.ws_upgrade_status = 101
                state.probe_status = 200

                # WR-8a: real cross-site OIDC login/callback/logout with auto-approving IdP
                state.scenario = "normal"
                state.idp_auto_approve = True
                state.login_hits = 0
                state.records.clear()
                ctx = browser.new_context()
                page = ctx.new_page()
                page.goto(f"{origin}/", wait_until="domcontentloaded")
                assert page.locator("a[href='/login']").count() == 1
                assert page.locator("form[action='/logout']").count() == 0
                assert state.login_hits == 0
                page.locator("a[href='/login']").click()
                page.wait_for_selector("[data-connection-badge='Delayed']", timeout=5000)
                assert state.login_hits == 1, f"expected 1 /login hit, got {state.login_hits}"
                assert len(state.records) == 1, f"expected 1 record, got {len(state.records)}"
                # Logout must hold even against auto-approving IdP
                page.locator("form[action='/logout'] button").click()
                page.wait_for_selector("a[href='/login']", timeout=5000)
                assert state.login_hits == 1, "logout re-triggered /login!"
                assert len(state.records) == 1
                assert all(r["revoked"] for r in state.records.values())
                ctx.close()

                print("WR-1..WR-8a browser gate PASS")
            finally:
                browser.close()
    finally:
        app_srv.shutdown()
        idp_srv.shutdown()


if __name__ == "__main__":
    main()
