#!/usr/bin/env python3
"""HA9-A.codex real-binary CI integration check (C2, C8, C9, C11, C12, C14).

Runs against the real Codex 0.166.0 binary and real `xmsg serve` in isolated
throwaway CODEX_HOME directories using a deterministic local loopback Responses
SSE provider (no auth, no external network).
"""

import base64
import fcntl
import hashlib
import http.server
import json
import os
import pty
import select
import shutil
import socket
import socketserver
import struct
import subprocess
import sys
import tempfile
import termios
import threading
import time
from pathlib import Path

import tomlkit

# ---------------------------------------------------------------------------
# Reference trusted_hash implementation (R §10) for C8 parity
# ---------------------------------------------------------------------------

EVENTS = {
    "PreModelRequest": "pre_model_request",
    "PostModelRequest": "post_model_request",
    "PreToolUse": "pre_tool_use",
    "PermissionRequest": "permission_request",
    "PostToolUse": "post_tool_use",
    "PreCompact": "pre_compact",
    "PostCompact": "post_compact",
    "SessionStart": "session_start",
    "SessionEnd": "session_end",
    "UserPromptSubmit": "user_prompt_submit",
    "SubagentStart": "subagent_start",
    "SubagentStop": "subagent_stop",
    "Stop": "stop",
    "Interrupt": "interrupt",
}
MATCHED = {
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "PreCompact",
    "PostCompact",
    "SessionStart",
    "SessionEnd",
    "SubagentStart",
    "SubagentStop",
}
ADDITIONAL = {
    "PreToolUse",
    "PostToolUse",
    "SessionStart",
    "UserPromptSubmit",
    "SubagentStart",
}


def ref_normalized_identity(event, group, handler, platform="unix"):
    assert event in EVENTS, f"unknown event {event}"
    assert handler.get("type") == "command"
    command = handler["command"]
    alternate = handler.get("commandWindows", handler.get("command_windows"))
    if platform == "windows" and alternate is not None:
        command = alternate
    end = event in ("SessionEnd", "Interrupt")
    timeout = handler.get("timeout")
    timeout = (1 if end else 600) if timeout is None else int(timeout)
    timeout = max(1, timeout)
    if end:
        timeout = min(3, timeout)
    asynchronous = bool(handler.get("async", False))
    normalized = {
        "type": "command",
        "command": command,
        "timeout": timeout,
        "async": asynchronous,
    }
    status = handler.get("statusMessage")
    if status is not None:
        normalized["statusMessage"] = status
    limit = handler.get("additionalContextLimit")
    if limit is not None and event in ADDITIONAL and limit != 2500:
        normalized["additionalContextLimit"] = int(limit)
    identity = {"event_name": EVENTS[event], "hooks": [normalized]}
    matcher = group.get("matcher")
    if matcher is not None and event in MATCHED:
        identity["matcher"] = matcher
    return identity


def ref_trusted_hash(event, group, handler, platform="unix"):
    identity = ref_normalized_identity(event, group, handler, platform)
    canonical = json.dumps(
        identity,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")
    return "sha256:" + hashlib.sha256(canonical).hexdigest()


def ref_compute_trust_state(hooks_path, hooks_obj):
    state = {}
    for event, groups in hooks_obj.items():
        if event not in EVENTS:
            continue
        for g_idx, group in enumerate(groups):
            for h_idx, handler in enumerate(group.get("hooks", [])):
                key = f"{hooks_path}:{EVENTS[event]}:{g_idx}:{h_idx}"
                state[key] = {"trusted_hash": ref_trusted_hash(event, group, handler)}
    return {"hooks": {"state": state}}


# ---------------------------------------------------------------------------
# Reference lens projection (_lens-toml.py) for C8
# ---------------------------------------------------------------------------


def _leaves(d, prefix=()):
    for k, v in d.items():
        if isinstance(v, dict):
            yield from _leaves(v, prefix + (k,))
        else:
            yield prefix + (k,), v


def _table_at(doc, path):
    t = doc
    for k in path:
        if k not in t:
            t[k] = tomlkit.table(is_super_table=True)
        t = t[k]
    return t


def _remove(doc, path):
    chain = [doc]
    for k in path[:-1]:
        if not isinstance(chain[-1], dict) or k not in chain[-1]:
            return
        chain.append(chain[-1][k])
    if isinstance(chain[-1], dict) and path[-1] in chain[-1]:
        del chain[-1][path[-1]]
    for i in range(len(chain) - 1, 0, -1):
        if len(chain[i]) == 0:
            del chain[i - 1][path[i - 1]]


def apply_lens_toml(target_path: Path, managed_dict: dict):
    state_path = target_path.parent / f".{target_path.name}.hm-lens"
    target_path.parent.mkdir(parents=True, exist_ok=True)
    if target_path.exists():
        doc = tomlkit.parse(target_path.read_text(encoding="utf-8"))
    else:
        doc = tomlkit.document()

    managed = dict(_leaves(managed_dict))
    if state_path.exists():
        before = {tuple(p) for p in json.loads(state_path.read_text(encoding="utf-8"))}
    else:
        before = set()

    for path in sorted(before - managed.keys(), key=len, reverse=True):
        _remove(doc, path)
    for path, value in managed.items():
        _table_at(doc, path[:-1])[path[-1]] = value

    out = tomlkit.dumps(doc)
    tomlkit.parse(out)
    target_path.write_text(out, encoding="utf-8")
    state_path.write_text(json.dumps(sorted(managed)), encoding="utf-8")


# ---------------------------------------------------------------------------
# Deterministic Local Loopback Responses SSE Server
# ---------------------------------------------------------------------------


class LocalResponsesState:
    def __init__(self):
        self.lock = threading.Lock()
        self.requests = []
        self.counter = 0
        self.hold_busy_event = threading.Event()
        self.busy_turn_entered = threading.Event()
        self.custom_handler = None

    def next_id(self, prefix="item"):
        with self.lock:
            self.counter += 1
            return f"{prefix}_{self.counter}"


class LocalResponsesServer:
    def __init__(self):
        self.state = LocalResponsesState()
        state = self.state

        class Handler(http.server.BaseHTTPRequestHandler):
            def log_message(self, fmt, *args):
                pass

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length).decode("utf-8", errors="replace")
                try:
                    body = json.loads(raw)
                except Exception:
                    body = {"_raw": raw}

                with state.lock:
                    req_idx = len(state.requests)
                    state.requests.append({"path": self.path, "body": body})

                items_out, hold_event = self._plan_response(req_idx, body)
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.end_headers()

                resp_id = state.next_id("resp")
                created = {
                    "type": "response.created",
                    "response": {
                        "id": resp_id,
                        "object": "response",
                        "status": "in_progress",
                        "output": [],
                    },
                }
                self._write_sse(created)

                if hold_event is not None:
                    state.busy_turn_entered.set()
                    hold_event.wait(timeout=10.0)

                completed_output = []
                for out_item in items_out:
                    added = {
                        "type": "response.output_item.added",
                        "output_index": len(completed_output),
                        "item": out_item,
                    }
                    self._write_sse(added)
                    done = {
                        "type": "response.output_item.done",
                        "output_index": len(completed_output),
                        "item": out_item,
                    }
                    self._write_sse(done)
                    completed_output.append(out_item)

                comp = {
                    "type": "response.completed",
                    "response": {
                        "id": resp_id,
                        "object": "response",
                        "status": "completed",
                        "output": completed_output,
                        "usage": {
                            "input_tokens": 10,
                            "output_tokens": 10,
                            "total_tokens": 20,
                        },
                    },
                }
                self._write_sse(comp)

            def _write_sse(self, obj):
                data = f"data: {json.dumps(obj)}\n\n".encode("utf-8")
                self.wfile.write(data)
                self.wfile.flush()

            def _msg_item(self, text):
                return {
                    "id": state.next_id("msg"),
                    "type": "message",
                    "role": "assistant",
                    "status": "completed",
                    "content": [{"type": "output_text", "text": text}],
                }

            def _fc_item(self, name, args_dict, namespace=None):
                item = {
                    "id": state.next_id("fc"),
                    "type": "function_call",
                    "name": name,
                    "call_id": state.next_id("call"),
                    "arguments": json.dumps(args_dict),
                    "status": "completed",
                }
                if namespace is not None:
                    item["namespace"] = namespace
                return item

            def _plan_response(self, req_idx, body):
                if state.custom_handler is not None:
                    res = state.custom_handler(req_idx, body, self._msg_item, self._fc_item, state)
                    if res is not None:
                        return res

                inp = body.get("input", [])
                flat_text = json.dumps(inp)
                # Check if the latest item is a function_call_output
                last_item = inp[-1] if inp else {}
                if last_item.get("type") == "function_call_output":
                    out_str = last_item.get("output", "")
                    return ([self._msg_item(f"TOOL_DONE:{out_str}")], None)

                if "HOLD_BUSY_TURN" in flat_text and not state.busy_turn_entered.is_set():
                    return ([self._msg_item(f"BUSY_DONE:{flat_text}")], state.hold_busy_event)

                return ([self._msg_item(f"ECHO:{flat_text}")], None)

        class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
            daemon_threads = True
            allow_reuse_address = True

        self.httpd = ThreadedHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


# ---------------------------------------------------------------------------
# JSON-RPC over stdio / Unix WebSocket client helpers
# ---------------------------------------------------------------------------


class StdioAppServerClient:
    def __init__(self, codex_bin, codex_home, env_extra=None):
        env = os.environ.copy()
        env["CODEX_HOME"] = str(codex_home)
        for k in ("CODEX_SESSION_ID", "CODEX_THREAD_ID", "CODEX_TOOL_CALL_ID"):
            env.pop(k, None)
        if env_extra:
            env.update(env_extra)
        self.proc = subprocess.Popen(
            [str(codex_bin), "app-server"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            env=env,
        )
        self._lock = threading.Lock()
        self._next_id = 0
        self.notifications = []
        self._responses = {}
        self._cv = threading.Condition()
        self._reader = threading.Thread(target=self._read_loop, daemon=True)
        self._reader.start()

    def _read_loop(self):
        for line in self.proc.stdout:
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                continue
            with self._cv:
                if "id" in msg and ("result" in msg or "error" in msg):
                    self._responses[msg["id"]] = msg
                else:
                    self.notifications.append(msg)
                self._cv.notify_all()

    def request(self, method, params=None, timeout=15.0):
        with self._lock:
            self._next_id += 1
            req_id = self._next_id
            payload = {"jsonrpc": "2.0", "id": req_id, "method": method}
            if params is not None:
                payload["params"] = params
            self.proc.stdin.write(json.dumps(payload) + "\n")
            self.proc.stdin.flush()

        deadline = time.time() + timeout
        with self._cv:
            while req_id not in self._responses:
                rem = deadline - time.time()
                if rem <= 0:
                    raise TimeoutError(f"RPC {method} timed out")
                self._cv.wait(timeout=rem)
            return self._responses.pop(req_id)

    def notify(self, method, params=None):
        with self._lock:
            payload = {"jsonrpc": "2.0", "method": method}
            if params is not None:
                payload["params"] = params
            self.proc.stdin.write(json.dumps(payload) + "\n")
            self.proc.stdin.flush()

    def initialize(self):
        res = self.request(
            "initialize",
            {"clientInfo": {"name": "check-codex", "version": "0.1.0"}},
        )
        assert "result" in res, f"initialize failed: {res}"
        self.notify("initialized", {})
        return res["result"]

    def close(self):
        try:
            self.proc.terminate()
            self.proc.wait(timeout=5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass


class UnixWsClient:
    """Minimal RFC 6455 WebSocket client over Unix domain socket."""

    def __init__(self, sock_path: Path, timeout=10.0):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(timeout)
        self.sock.connect(str(sock_path))
        key = base64.b64encode(os.urandom(16)).decode("ascii")
        req = (
            "GET / HTTP/1.1\r\n"
            "Host: localhost\r\n"
            "Upgrade: websocket\r\n"
            "Connection: Upgrade\r\n"
            f"Sec-WebSocket-Key: {key}\r\n"
            "Sec-WebSocket-Version: 13\r\n\r\n"
        )
        self.sock.sendall(req.encode("ascii"))
        buf = b""
        while b"\r\n\r\n" not in buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise RuntimeError("EOF during WS upgrade")
            buf += chunk
        header, self._rem = buf.split(b"\r\n\r\n", 1)
        assert b"101" in header.splitlines()[0], f"WS upgrade failed: {header}"
        self._next_id = 0
        self.notifications = []

    def _recv_exact(self, n):
        while len(self._rem) < n:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError("WS EOF")
            self._rem += chunk
        out, self._rem = self._rem[:n], self._rem[n:]
        return out

    def send_json(self, obj):
        payload = json.dumps(obj).encode("utf-8")
        mask = os.urandom(4)
        header = bytearray([0x81])
        n = len(payload)
        if n < 126:
            header.append(0x80 | n)
        elif n < 65536:
            header.append(0x80 | 126)
            header.extend(n.to_bytes(2, "big"))
        else:
            header.append(0x80 | 127)
            header.extend(n.to_bytes(8, "big"))
        header.extend(mask)
        masked = bytes(b ^ mask[i % 4] for i, b in enumerate(payload))
        self.sock.sendall(bytes(header) + masked)

    def recv_json(self):
        while True:
            b0, b1 = self._recv_exact(2)
            opcode = b0 & 0x0F
            masked = (b1 & 0x80) != 0
            length = b1 & 0x7F
            if length == 126:
                length = int.from_bytes(self._recv_exact(2), "big")
            elif length == 127:
                length = int.from_bytes(self._recv_exact(8), "big")
            mask = self._recv_exact(4) if masked else b""
            data = self._recv_exact(length)
            if masked:
                data = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
            if opcode == 0x8:
                raise EOFError("WS close frame")
            if opcode == 0x9:
                # Ping -> Pong
                pong = bytearray([0x8A, 0x80, 0, 0, 0, 0])
                self.sock.sendall(bytes(pong))
                continue
            if opcode in (0x1, 0x2):
                return json.loads(data.decode("utf-8"))

    def request(self, method, params=None):
        self._next_id += 1
        req_id = self._next_id
        msg = {"jsonrpc": "2.0", "id": req_id, "method": method}
        if params is not None:
            msg["params"] = params
        self.send_json(msg)
        while True:
            frame = self.recv_json()
            if frame.get("id") == req_id and ("result" in frame or "error" in frame):
                return frame
            self.notifications.append(frame)

    def notify(self, method, params=None):
        msg = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            msg["params"] = params
        self.send_json(msg)

    def initialize(self):
        res = self.request(
            "initialize",
            {"clientInfo": {"name": "check-codex-ws", "version": "0.1.0"}},
        )
        assert "result" in res, f"WS initialize failed: {res}"
        self.notify("initialized", {})
        return res["result"]

    def close(self):
        try:
            self.sock.close()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# xmsg Unix socket helpers (HTTP / register / agent)
# ---------------------------------------------------------------------------


def unix_http_request(http_sock: Path, method: str, path: str, body=None) -> tuple[int, dict]:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(str(http_sock))
    payload = b"" if body is None else json.dumps(body).encode("utf-8")
    req = (
        f"{method} {path} HTTP/1.1\r\n"
        f"Host: localhost\r\n"
        f"Content-Type: application/json\r\n"
        f"Content-Length: {len(payload)}\r\n"
        f"Connection: close\r\n\r\n"
    ).encode("utf-8") + payload
    s.sendall(req)
    resp = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    s.close()
    head, raw_body = resp.split(b"\r\n\r\n", 1)
    status = int(head.splitlines()[0].split()[1])
    # Handle chunked if present
    if b"transfer-encoding: chunked" in head.lower():
        decoded = b""
        rest = raw_body
        while rest:
            line, rest = rest.split(b"\r\n", 1)
            sz = int(line.strip(), 16)
            if sz == 0:
                break
            decoded += rest[:sz]
            rest = rest[sz + 2 :]
        raw_body = decoded
    return status, json.loads(raw_body.decode("utf-8")) if raw_body else {}


def unix_line_rpc(sock_path: Path, req_obj: dict) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(5.0)
    s.connect(str(sock_path))
    s.sendall((json.dumps(req_obj) + "\n").encode("utf-8"))
    s.shutdown(socket.SHUT_WR)
    buf = b""
    while True:
        c = s.recv(4096)
        if not c:
            break
        buf += c
    s.close()
    return json.loads(buf.decode("utf-8").strip())


class PluginReceiver:
    """A plugin connection on register.sock holding session 'peer'."""

    def __init__(self, reg_sock: Path):
        self.s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.s.settimeout(10.0)
        self.s.connect(str(reg_sock))
        self.f = self.s.makefile("rw", encoding="utf-8")
        self.n = 0
        self._lock = threading.Lock()
        self.received = []
        self._put({"harness": "opencode"})
        hello = json.loads(self.f.readline())
        assert hello.get("status") == "ok", f"PluginReceiver hello failed: {hello}"
        reg = self.call({"action": "register", "session": "peer"})
        self.address = reg["address"]

    def _put(self, frame: dict):
        self.f.write(json.dumps(frame) + "\n")
        self.f.flush()

    def call(self, frame: dict) -> dict:
        with self._lock:
            self.n += 1
            frame = dict(frame)
            frame["request_id"] = f"r{self.n}"
            self._put(frame)
            line = self.f.readline()
            assert line, f"EOF on PluginReceiver for {frame}"
            ans = json.loads(line)
            assert ans.get("request_id") == frame["request_id"] and ans.get("status") != "error", (
                f"PluginReceiver error on {frame}: {ans}"
            )
            return ans

    def drain_available(self, wait_secs=0.5) -> list[dict]:
        end = time.time() + wait_secs
        while time.time() < end:
            ans = self.call({"action": "poll", "wait": 0})
            if ans.get("action") == "deliver":
                self.call({"action": "ack", "session": "peer", "message_id": ans["message_id"]})
                self.received.append(ans)
            else:
                time.sleep(0.05)
        return list(self.received)

    def wait_for_text(self, substring: str, timeout=10.0) -> dict:
        deadline = time.time() + timeout
        while time.time() < deadline:
            for m in self.received:
                if substring in m.get("text", ""):
                    return m
            self.drain_available(0.15)
        raise AssertionError(
            f"PluginReceiver did not receive {substring!r} within {timeout}s; got: {self.received}"
        )

    def close(self):
        try:
            self.s.close()
        except Exception:
            pass


def wait_for_sock(path: Path, timeout=15.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if path.exists():
            try:
                s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect(str(path))
                s.close()
                return
            except Exception:
                pass
        time.sleep(0.05)
    raise TimeoutError(f"Socket {path} did not become ready")


def write_codex_config(
    codex_home: Path,
    work_dir: Path,
    provider_port: int,
    xmsg_bin: Path,
    trust_state: dict | None = None,
    include_xdg_env: bool = True,
    mcp_wrapper: Path | None = None,
):
    codex_home.mkdir(parents=True, exist_ok=True)
    doc = tomlkit.document()
    doc["model"] = "gpt-5.4"
    doc["model_provider"] = "mock"
    doc["approval_policy"] = "never"
    doc["sandbox_mode"] = "danger-full-access"
    doc["thread_unload_delay_secs"] = 0

    features = tomlkit.table()
    features["codex_hooks"] = True
    features["multi_agent"] = True
    doc["features"] = features

    providers = tomlkit.table()
    mock = tomlkit.table()
    mock["name"] = "MockLoopback"
    mock["base_url"] = f"http://127.0.0.1:{provider_port}/v1"
    mock["wire_api"] = "responses"
    mock["requires_openai_auth"] = False
    providers["mock"] = mock
    doc["model_providers"] = providers

    projects = tomlkit.table()
    for p in (str(work_dir), str(codex_home)):
        pt = tomlkit.table()
        pt["trust_level"] = "trusted"
        projects[p] = pt
    doc["projects"] = projects

    mcp_servers = tomlkit.table()
    xmsg_mcp = tomlkit.table()
    xmsg_mcp["command"] = str(mcp_wrapper or xmsg_bin)
    xmsg_mcp["args"] = ["mcp"]
    if include_xdg_env:
        xmsg_mcp["env_vars"] = ["XDG_RUNTIME_DIR"]
    xmsg_mcp["default_tools_approval_mode"] = "approve"
    mcp_servers["xmsg"] = xmsg_mcp
    doc["mcp_servers"] = mcp_servers

    if trust_state and "hooks" in trust_state and "state" in trust_state["hooks"]:
        hooks_tbl = tomlkit.table()
        state_tbl = tomlkit.table()
        for k, v in trust_state["hooks"]["state"].items():
            entry = tomlkit.table()
            entry["trusted_hash"] = v["trusted_hash"]
            state_tbl[k] = entry
        hooks_tbl["state"] = state_tbl
        doc["hooks"] = hooks_tbl

    cfg_path = codex_home / "config.toml"
    cfg_path.write_text(tomlkit.dumps(doc), encoding="utf-8")


def materialize_hooks_for_home(
    rendered_hooks_obj: dict,
    codex_home: Path,
    real_xmsg_bin: Path,
    guard_script: Path,
) -> tuple[dict, dict]:
    """Rewrite the HM-rendered hooks object to point at our isolated runtime paths
    when needed, or install a symlink at the exact HM-rendered stable path."""
    # Because HM renders `/tmp/xmsg-codex-ci-user-home/.local/share/xmsg/bin/xmsg`
    # and `/tmp/xmsg-codex-ci-user-home/.claude/bash-guard.sh`, we can actually create
    # `/tmp/xmsg-codex-ci-user-home/.local/share/xmsg/bin/xmsg` -> real_xmsg_bin and
    # `/tmp/xmsg-codex-ci-user-home/.claude/bash-guard.sh` -> guard_script!
    user_home = Path("/tmp/xmsg-codex-ci-user-home")
    xmsg_link = user_home / ".local/share/xmsg/bin/xmsg"
    xmsg_link.parent.mkdir(parents=True, exist_ok=True)
    if xmsg_link.exists() or xmsg_link.is_symlink():
        xmsg_link.unlink()
    xmsg_link.symlink_to(real_xmsg_bin)

    guard_link = user_home / ".claude/bash-guard.sh"
    guard_link.parent.mkdir(parents=True, exist_ok=True)
    guard_link.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    guard_link.chmod(0o755)

    hooks_file = codex_home / "hooks.json"
    codex_home.mkdir(parents=True, exist_ok=True)
    hooks_file.write_text(json.dumps({"hooks": rendered_hooks_obj}), encoding="utf-8")
    trust = ref_compute_trust_state(str(hooks_file), rendered_hooks_obj)
    return rendered_hooks_obj, trust


# ---------------------------------------------------------------------------
# Oracle 1: C8 Hash & Lens Parity + Real Codex Trust Without Bypass
# ---------------------------------------------------------------------------


def run_oracle_c8(
    codex_bin: Path,
    xmsg_bin: Path,
    hm_final_hooks: dict,
    hm_trust_state: dict,
    hm_retargeted_trust_state: dict,
    hm_vectors_hooks: dict,
    hm_vectors_trust_state: dict,
    hm_reordered_vectors_hooks: dict,
    hm_reordered_vectors_trust_state: dict,
    provider_port: int,
    work_dir: Path,
):
    print("=== C8: Hash/lens parity & real Codex hooks/list trust verification ===")
    ci_home = Path("/tmp/xmsg-codex-ci-home")
    if ci_home.exists():
        shutil.rmtree(ci_home)
    ci_home.mkdir(parents=True, exist_ok=True)

    # 1. Package retargeting keeps identical trustState
    assert hm_trust_state == hm_retargeted_trust_state, (
        "C8 failed: package retargeting changed trustState"
    )

    # 2. Pure Nix hash == reference trusted_hash.py for all handlers in hm_final_hooks and hm_vectors_hooks
    ref_final = ref_compute_trust_state("/tmp/xmsg-codex-ci-home/hooks.json", hm_final_hooks)
    assert hm_trust_state == ref_final, (
        f"C8 failed: Nix trustState != reference trusted_hash.py on final hooks:\n"
        f"Nix: {json.dumps(hm_trust_state, indent=2)}\nRef: {json.dumps(ref_final, indent=2)}"
    )

    ref_vectors = ref_compute_trust_state("/tmp/xmsg-codex-ci-home/hooks.json", hm_vectors_hooks)
    assert hm_vectors_trust_state == ref_vectors, (
        f"C8 failed: Nix trustState != reference trusted_hash.py on normalization vectors:\n"
        f"Nix: {json.dumps(hm_vectors_trust_state, indent=2)}\nRef: {json.dumps(ref_vectors, indent=2)}"
    )

    ref_reordered = ref_compute_trust_state(
        "/tmp/xmsg-codex-ci-home/hooks.json", hm_reordered_vectors_hooks
    )
    assert hm_reordered_vectors_trust_state == ref_reordered, (
        "C8 failed: Nix reordered trustState != reference"
    )

    # 3. Verify against real Codex `hooks/list` on `/tmp/xmsg-codex-ci-home/hooks.json`:
    #    (a) hm_vectors_hooks + hm_vectors_trust_state -> all handlers trusted, currentHash == Nix hash
    hooks_json_path = ci_home / "hooks.json"
    hooks_json_path.write_text(json.dumps({"hooks": hm_vectors_hooks}), encoding="utf-8")
    write_codex_config(ci_home, work_dir, provider_port, xmsg_bin, hm_vectors_trust_state)

    client = StdioAppServerClient(codex_bin, ci_home)
    try:
        client.initialize()
        res = client.request("hooks/list", {"cwds": [str(work_dir)]})
        hooks_list = res["result"]["data"][0]["hooks"]
        expected_map = hm_vectors_trust_state["hooks"]["state"]
        assert len(hooks_list) == len(expected_map), (
            f"C8 failed: expected {len(expected_map)} hooks from Codex hooks/list, got {len(hooks_list)}"
        )
        for item in hooks_list:
            key = item["key"]
            assert key in expected_map, f"C8 failed: unexpected key {key} from hooks/list"
            nix_hash = expected_map[key]["trusted_hash"]
            assert item["currentHash"] == nix_hash, (
                f"C8 failed: Codex currentHash {item['currentHash']} != Nix hash {nix_hash} for {key}"
            )
            assert item["trustStatus"] == "trusted", (
                f"C8 failed: expected trusted for {key}, got {item['trustStatus']}"
            )
    finally:
        client.close()

    #    (b) Reorder groups in hooks.json while keeping OLD hm_vectors_trust_state:
    #        reordered PreToolUse and SessionEnd keys must be "untrusted"
    hooks_json_path.write_text(json.dumps({"hooks": hm_reordered_vectors_hooks}), encoding="utf-8")
    client = StdioAppServerClient(codex_bin, ci_home)
    try:
        client.initialize()
        res = client.request("hooks/list", {"cwds": [str(work_dir)]})
        hooks_list = res["result"]["data"][0]["hooks"]
        by_key = {item["key"]: item for item in hooks_list}
        for ev_label in ("pre_tool_use", "session_end"):
            k0 = f"/tmp/xmsg-codex-ci-home/hooks.json:{ev_label}:0:0"
            k1 = f"/tmp/xmsg-codex-ci-home/hooks.json:{ev_label}:1:0"
            assert by_key[k0]["trustStatus"] != "trusted", (
                f"C8 failed: reordered {k0} remained trusted under old state: {by_key[k0]}"
            )
            assert by_key[k1]["trustStatus"] != "trusted", (
                f"C8 failed: reordered {k1} remained trusted under old state: {by_key[k1]}"
            )
    finally:
        client.close()

    #    (c) Write newly recomputed hm_reordered_vectors_trust_state -> all trusted again
    write_codex_config(ci_home, work_dir, provider_port, xmsg_bin, hm_reordered_vectors_trust_state)
    client = StdioAppServerClient(codex_bin, ci_home)
    try:
        client.initialize()
        res = client.request("hooks/list", {"cwds": [str(work_dir)]})
        hooks_list = res["result"]["data"][0]["hooks"]
        for item in hooks_list:
            assert item["trustStatus"] == "trusted", (
                f"C8 failed: reordered {item['key']} not trusted after recomputation: {item}"
            )
    finally:
        client.close()

    # 4. Lens projection: preserves unmanaged keys and removes retired managed trust keys
    lens_dir = Path(tempfile.mkdtemp(prefix="xmsg-codex-lens-"))
    lens_cfg = lens_dir / "config.toml"
    unmanaged_key = "/unmanaged/user/hooks.json:stop:0:0"
    retired_key = "/tmp/xmsg-codex-ci-home/hooks.json:pre_tool_use:99:0"
    lens_cfg.write_text(
        '[projects."/tmp/user-proj"]\n'
        'trust_level = "trusted"\n\n'
        f'[hooks.state."{unmanaged_key}"]\n'
        'trusted_hash = "sha256:0000000000000000000000000000000000000000000000000000000000000000"\n',
        encoding="utf-8",
    )
    gen1 = json.loads(json.dumps(hm_trust_state))
    gen1["hooks"]["state"][retired_key] = {
        "trusted_hash": "sha256:1111111111111111111111111111111111111111111111111111111111111111"
    }
    apply_lens_toml(lens_cfg, gen1)
    parsed1 = tomlkit.parse(lens_cfg.read_text(encoding="utf-8"))
    assert retired_key in parsed1["hooks"]["state"]
    assert unmanaged_key in parsed1["hooks"]["state"]

    # Second activation drops retired_key
    apply_lens_toml(lens_cfg, hm_trust_state)
    parsed2 = tomlkit.parse(lens_cfg.read_text(encoding="utf-8"))
    assert retired_key not in parsed2["hooks"]["state"], (
        "C8 failed: lens projection did not remove retired managed trust key"
    )
    assert unmanaged_key in parsed2["hooks"]["state"], (
        "C8 failed: lens projection erased unmanaged trust key"
    )
    assert parsed2["projects"]["/tmp/user-proj"]["trust_level"] == "trusted", (
        "C8 failed: lens projection erased unmanaged project key"
    )
    shutil.rmtree(lens_dir, ignore_errors=True)
    shutil.rmtree(ci_home, ignore_errors=True)
    print("=== C8 PASSED ===")


# ---------------------------------------------------------------------------
# Oracle 2: C11 Real Binary Source Enumeration & Fresh/Compact/Resume Sources
# ---------------------------------------------------------------------------


def run_oracle_c11_with_homes(
    codex_bin: Path,
    xmsg_bin: Path,
    hm_final_hooks: dict,
    hm_mcp_server: dict,
    provider: LocalResponsesServer,
    http_sock: Path,
    reg_sock: Path,
    work_dir: Path,
    codex_home: Path,
    tui_home: Path,
):
    print("=== C11: HM render & real binary SessionStart sources (startup/clear/fork/compact/resume) ===")
    # 1. Verify HM render shape
    assert set(hm_final_hooks.keys()) == {
        "PreToolUse",
        "SessionStart",
        "UserPromptSubmit",
        "Stop",
        "SubagentStart",
        "PreModelRequest",
        "SubagentStop",
        "SessionEnd",
    }
    assert "matcher" not in hm_final_hooks["SessionStart"][0], (
        "C11 failed: SessionStart has a matcher"
    )
    assert hm_mcp_server["args"] == ["mcp"]
    assert hm_mcp_server["env_vars"] == ["XDG_RUNTIME_DIR"]
    assert hm_mcp_server["default_tools_approval_mode"] == "approve"

    # 2. Enumerate startup/resume/clear/compact/fork in the real codex binary
    raw_bytes = Path(codex_bin).read_bytes()
    for token in (b"startup", b"resume", b"clear", b"compact", b"fork"):
        assert token in raw_bytes, f"C11 failed: source token {token!r} missing from codex binary"

    # Prepare codex_home with HM hooks + trust
    _, trust = materialize_hooks_for_home(
        hm_final_hooks, codex_home, xmsg_bin, work_dir / "guard.sh"
    )
    write_codex_config(codex_home, work_dir, provider.port, xmsg_bin, trust)

    def wait_turn_done(cli: StdioAppServerClient, thread_id: str, turn_id: str | None = None):
        deadline = time.time() + 15.0
        while time.time() < deadline:
            if any(
                n.get("method") == "turn/completed"
                and n.get("params", {}).get("threadId") == thread_id
                and (turn_id is None or n.get("params", {}).get("turn", {}).get("id") == turn_id)
                for n in cli.notifications
            ):
                return
            time.sleep(0.05)
        raise AssertionError(f"Timed out waiting for turn/completed on {thread_id} ({turn_id})")

    def unload_thread(cli: StdioAppServerClient, thread_id: str):
        ur = cli.request("thread/unsubscribe", {"threadId": thread_id})
        assert "result" in ur, f"thread/unsubscribe failed: {ur}"
        deadline = time.time() + 10.0
        while time.time() < deadline:
            loaded = cli.request("thread/loaded/list", {}).get("result", {}).get("data", [])
            if thread_id not in loaded:
                return
            time.sleep(0.05)
        raise AssertionError(f"thread {thread_id} did not unload after unsubscribe; loaded={loaded}")

    # 3. Drive startup, fork, compact, and resume on real codex app-server
    client = StdioAppServerClient(codex_bin, codex_home)
    try:
        client.initialize()
        # (a) startup: thread/start + turn/start
        t_start = client.request("thread/start", {"cwd": str(work_dir)})
        root_p = t_start["result"]["thread"]["id"]
        turn1 = client.request(
            "turn/start",
            {
                "threadId": root_p,
                "input": [{"type": "text", "text": "C11_STARTUP_PROMPT"}],
            },
        )
        assert "result" in turn1
        wait_turn_done(client, root_p, turn1["result"]["turn"]["id"])
        _, recips = unix_http_request(http_sock, "GET", "/v1/recipients")
        assert any(
            r.get("kind") == "instance"
            and r.get("harness") == "codex"
            and r.get("address", "").startswith(f"{root_p}@")
            for r in recips.get("recipients", [])
        ), f"C11 failed: startup root {root_p} did not register: {recips}"

        # (b) compact: thread/compact/start on registered root_p -> revalidates, stays registered
        notifs_before_compact = len(client.notifications)
        c_res = client.request("thread/compact/start", {"threadId": root_p})
        assert "result" in c_res, f"thread/compact/start failed: {c_res}"
        deadline = time.time() + 10.0
        while time.time() < deadline:
            if any(
                n.get("method") == "turn/completed"
                and n.get("params", {}).get("threadId") == root_p
                for n in client.notifications[notifs_before_compact:]
            ):
                break
            time.sleep(0.05)
        _, recips = unix_http_request(http_sock, "GET", "/v1/recipients")
        assert any(
            r.get("address", "").startswith(f"{root_p}@") for r in recips.get("recipients", [])
        ), f"C11 failed: compact revoked active root {root_p}"

        # (c) fork: thread/fork + turn/start -> registers forked root as fresh
        f_res = client.request("thread/fork", {"threadId": root_p})
        assert "result" in f_res, f"thread/fork failed: {f_res}"
        fork_p = f_res["result"]["thread"]["id"]
        assert fork_p != root_p
        f_turn = client.request(
            "turn/start",
            {
                "threadId": fork_p,
                "input": [{"type": "text", "text": "C11_FORK_PROMPT"}],
            },
        )
        wait_turn_done(client, fork_p, f_turn["result"]["turn"]["id"])
        _, recips = unix_http_request(http_sock, "GET", "/v1/recipients")
        assert any(
            r.get("address", "").startswith(f"{fork_p}@") for r in recips.get("recipients", [])
        ), f"C11 failed: forked root {fork_p} did not register: {recips}"

        # (d) resume (§6): thread/unsubscribe parks root_p into StaleAfterResume; thread/resume + turn/start re-attests and rebinds root_p!
        unload_thread(client, root_p)
        _, recips_unloaded = unix_http_request(http_sock, "GET", "/v1/recipients")
        assert not any(
            r.get("address", "").startswith(f"{root_p}@")
            for r in recips_unloaded.get("recipients", [])
        ), f"C11 failed: unloaded root {root_p} remained listed before resume: {recips_unloaded}"
        r_res = client.request("thread/resume", {"threadId": root_p})
        assert "result" in r_res, f"thread/resume failed: {r_res}"
        r_turn = client.request(
            "turn/start",
            {
                "threadId": root_p,
                "input": [{"type": "text", "text": "C11_RESUME_PROMPT"}],
            },
        )
        wait_turn_done(client, root_p, r_turn["result"]["turn"]["id"])
        _, recips = unix_http_request(http_sock, "GET", "/v1/recipients")
        assert any(
            r.get("address", "").startswith(f"{root_p}@") for r in recips.get("recipients", [])
        ), f"C11/C17 failed: resumed root {root_p} with valid witness did not re-attest: {recips}"
        # Sibling fork_p remains registered!
        assert any(
            r.get("address", "").startswith(f"{fork_p}@") for r in recips.get("recipients", [])
        ), f"C11 failed: sibling fork_p {fork_p} was lost when {root_p} resumed"
    finally:
        client.close()

    # 4. Drive TUI `/clear` and `/new` on a PTY (real TUI auto-daemon topology + C14 plain TUI push!)
    _, tui_trust = materialize_hooks_for_home(
        hm_final_hooks, tui_home, xmsg_bin, work_dir / "guard.sh"
    )
    write_codex_config(tui_home, work_dir, provider.port, xmsg_bin, tui_trust)

    master, slave = pty.openpty()
    fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack("HHHH", 40, 120, 0, 0))
    env = os.environ.copy()
    env["CODEX_HOME"] = str(tui_home)
    env["TERM"] = "xterm-256color"
    for k in ("CODEX_SESSION_ID", "CODEX_THREAD_ID", "CODEX_TOOL_CALL_ID"):
        env.pop(k, None)

    tui_proc = subprocess.Popen(
        [str(codex_bin), "--no-alt-screen", "-C", str(work_dir), "INITIAL_TUI_PROMPT"],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        env=env,
        close_fds=True,
    )
    os.close(slave)
    pty_out = bytearray()

    def drain_pty(duration=0.2):
        end = time.time() + duration
        while time.time() < end:
            r, _, _ = select.select([master], [], [], 0.05)
            if master in r:
                try:
                    chunk = os.read(master, 4096)
                    if not chunk:
                        break
                    pty_out.extend(chunk)
                    # Respond to DSR cursor position query ESC[6n
                    if b"\x1b[6n" in chunk:
                        os.write(master, b"\x1b[1;1R")
                except OSError:
                    break

    def wait_pty(needle: bytes, since_idx: int = 0, timeout: float = 15.0) -> int:
        deadline = time.time() + timeout
        while time.time() < deadline:
            pos = pty_out.find(needle, since_idx)
            if pos != -1:
                return pos + len(needle)
            drain_pty(0.05)
        raise AssertionError(
            f"C11 timed out waiting for PTY signal {needle!r} after offset {since_idx}. "
            f"PTY tail: {bytes(pty_out[since_idx:][-600:] )!r}"
        )

    try:
        # Wait for initial TUI root registration AND its initial turn completion (`ECHO:`)
        tui_root_1 = None
        deadline = time.time() + 15.0
        while time.time() < deadline:
            drain_pty(0.1)
            locks_dir = tui_home / "thread-writer-locks"
            if locks_dir.exists():
                locks = [p.stem for p in locks_dir.glob("*.lock")]
                if locks:
                    _, recips = unix_http_request(http_sock, "GET", "/v1/recipients")
                    for cand in locks:
                        if any(
                            r.get("address", "").startswith(f"{cand}@")
                            for r in recips.get("recipients", [])
                        ):
                            tui_root_1 = cand
                            break
            if tui_root_1:
                break
        assert tui_root_1 is not None, (
            f"C11/C14 failed: plain TUI did not register initial root. PTY: {pty_out.decode('utf-8', 'replace')[-600:]}"
        )
        mark = wait_pty(b"ECHO:", 0)

        # C14 check on plain TUI auto-daemon topology: app-server-control.sock exists and live push delivers!
        ctrl_sock = tui_home / "app-server-control" / "app-server-control.sock"
        assert ctrl_sock.exists() or ctrl_sock.is_symlink(), (
            "C14 failed: plain TUI did not auto-start app-server-control.sock"
        )
        st, push_res = unix_http_request(
            http_sock,
            "POST",
            "/v1/messages",
            {"from": "peer", "to": tui_root_1, "text": "PLAIN_TUI_LIVE_PUSH_MARKER"},
        )
        assert st in (200, 201, 202) and push_res.get("outcome") == "delivered", (
            f"C14 failed: live push to plain auto-daemon TUI {tui_root_1} did not deliver: {st} {push_res}"
        )
        # Wait for the live-pushed turn to finish (`ECHO:`) before typing `/clear`
        mark = wait_pty(b"ECHO:", mark)

        # Send `/clear`, wait for slash-command completion popup (`clear the terminal`),
        # press Enter, wait for the fresh composer placeholder (`Ask Codex to do anything`),
        # type `AFTER_CLEAR_PROMPT`, wait for echo, and press Enter.
        os.write(master, b"/clear")
        mark = wait_pty(b"clear the terminal", mark)
        os.write(master, b"\r")
        mark = wait_pty(b"Ask Codex to do anything", mark)
        os.write(master, b"AFTER_CLEAR_PROMPT")
        mark = wait_pty(b"AFTER_CLEAR_PROMPT", mark)
        os.write(master, b"\r")

        tui_root_clear = None
        deadline = time.time() + 15.0
        while time.time() < deadline:
            drain_pty(0.1)
            locks_dir = tui_home / "thread-writer-locks"
            if locks_dir.exists():
                for p in locks_dir.glob("*.lock"):
                    cand = p.stem
                    if cand != tui_root_1:
                        _, recips = unix_http_request(http_sock, "GET", "/v1/recipients")
                        if any(
                            r.get("address", "").startswith(f"{cand}@")
                            for r in recips.get("recipients", [])
                        ):
                            tui_root_clear = cand
                            break
            if tui_root_clear:
                break
        assert tui_root_clear is not None, (
            f"C11 failed: TUI /clear did not register a fresh root. PTY: {pty_out.decode('utf-8', 'replace')[-600:]}"
        )
        # Wait for `AFTER_CLEAR_PROMPT` turn to finish (`ECHO:`) so the composer is idle before `/new`!
        mark = wait_pty(b"ECHO:", mark)

        # Send `/new`, wait for slash-command completion popup (`start a new chat`),
        # press Enter, wait for the fresh composer placeholder (`Ask Codex to do anything`),
        # type `AFTER_NEW_PROMPT`, wait for echo, and press Enter.
        os.write(master, b"/new")
        mark = wait_pty(b"start a new chat", mark)
        os.write(master, b"\r")
        mark = wait_pty(b"Ask Codex to do anything", mark)
        os.write(master, b"AFTER_NEW_PROMPT")
        mark = wait_pty(b"AFTER_NEW_PROMPT", mark)
        os.write(master, b"\r")

        tui_root_new = None
        deadline = time.time() + 15.0
        while time.time() < deadline:
            drain_pty(0.1)
            locks_dir = tui_home / "thread-writer-locks"
            if locks_dir.exists():
                for p in locks_dir.glob("*.lock"):
                    cand = p.stem
                    if cand not in (tui_root_1, tui_root_clear):
                        _, recips = unix_http_request(http_sock, "GET", "/v1/recipients")
                        if any(
                            r.get("address", "").startswith(f"{cand}@")
                            for r in recips.get("recipients", [])
                        ):
                            tui_root_new = cand
                            break
            if tui_root_new:
                break
        assert tui_root_new is not None, (
            f"C11 failed: TUI /new did not register a fresh root. PTY: {pty_out.decode('utf-8', 'replace')[-600:]}"
        )
        mark = wait_pty(b"ECHO:", mark)
    finally:
        try:
            os.close(master)
        except Exception:
            pass
        try:
            tui_proc.terminate()
            tui_proc.wait(timeout=3)
        except Exception:
            try:
                tui_proc.kill()
            except Exception:
                pass
        # Kill any auto-started codex daemon whose CODEX_HOME is tui_home (never xmsg serve!)
        for proc_dir in Path("/proc").glob("[0-9]*"):
            try:
                env_bytes = (proc_dir / "environ").read_bytes()
                if f"CODEX_HOME={tui_home}".encode() in env_bytes:
                    os.kill(int(proc_dir.name), 15)
            except Exception:
                pass
        shutil.rmtree(tui_home, ignore_errors=True)

    print("=== C11 PASSED ===")


# ---------------------------------------------------------------------------
# Oracle 3: C2, C9, C12 (MCP env_vars, Real MCP Composition & Child Lifecycle)
# ---------------------------------------------------------------------------


def run_oracle_c2_c9_c12_with_homes(
    codex_bin: Path,
    xmsg_bin: Path,
    hm_final_hooks: dict,
    provider: LocalResponsesServer,
    http_sock: Path,
    reg_sock: Path,
    recv: PluginReceiver,
    work_dir: Path,
    codex_home: Path,
    emb_home: Path,
    noenv_home: Path,
):
    print("=== C2, C9, C12: Real MCP composition, child lifecycle & turn fallback ===")
    # Install an MCP tee wrapper so we record exact raw JSON-RPC requests (`params._meta`)
    # sent by Codex 0.166.0 to `xmsg mcp` while forwarding stdin/stdout untouched.
    mcp_log = work_dir / "mcp-wire.jsonl"
    if mcp_log.exists():
        mcp_log.unlink()
    mcp_wrapper = work_dir / "xmsg-mcp-tee.py"
    mcp_wrapper.write_text(
        f"""#!{sys.executable}
import os, subprocess, sys, threading
log_path = {str(mcp_log)!r}
real_bin = {str(xmsg_bin)!r}
proc = subprocess.Popen([real_bin] + sys.argv[1:], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=sys.stderr)
def pump_in():
    with open(log_path, "ab") as lf:
        while True:
            line = sys.stdin.buffer.readline()
            if not line:
                break
            lf.write(line)
            lf.flush()
            proc.stdin.write(line)
            proc.stdin.flush()
    proc.stdin.close()
t = threading.Thread(target=pump_in, daemon=True)
t.start()
while True:
    line = proc.stdout.readline()
    if not line:
        break
    sys.stdout.buffer.write(line)
    sys.stdout.flush()
sys.exit(proc.wait())
""",
        encoding="utf-8",
    )
    mcp_wrapper.chmod(0o755)

    _, trust = materialize_hooks_for_home(
        hm_final_hooks, codex_home, xmsg_bin, work_dir / "guard.sh"
    )
    write_codex_config(
        codex_home, work_dir, provider.port, xmsg_bin, trust, include_xdg_env=True, mcp_wrapper=mcp_wrapper
    )

    # Program the deterministic local Responses provider for the daemon-backed C9/C12 scenario:
    # Step 1 (root prompt "RUN_DAEMON_SCENARIO"):
    #   - Root calls mcp__xmsg__send(to="peer", text="ROOT_DAEMON_MSG_1")
    #   - Root calls mcp__xmsg__list()
    #   - Root calls multi_agent_v1::spawn_agent(agent_type="explorer", message="CHILD_DAEMON_TASK_1")
    #   - After spawn_agent returns {"agent_id": X, ...}, root calls multi_agent_v1::wait_agent(timeout_ms=10000)
    #   - Meanwhile child X runs:
    #       1) Child calls mcp__xmsg__send(to="peer", text="CHILD_DAEMON_MSG_1")
    #       2) Child calls mcp__xmsg__inbox() and mcp__xmsg__list()
    #       3) Child finishes turn 1 with assistant message "CHILD_TURN_1_COMPLETE"
    #   - Wait_agent returns child completion to root.
    # Step 2 (after child X has stopped, test script sends a message to P/X which falls back to P,
    #         and a reply to root's msg, then starts turn 2 on root with "RUN_DAEMON_FOLLOWUP:<X>:<root_msg_id>"):
    #   - Root calls mcp__xmsg__inbox() and mcp__xmsg__replies(id=root_msg_id)
    #   - Root calls multi_agent_v1::send_input(target=X, message="CHILD_FOLLOWUP_TASK")
    #   - Root calls multi_agent_v1::wait_agent(timeout_ms=10000)
    #   - Child X runs follow-up turn (PreModelRequest fires again for X!):
    #       1) Child calls mcp__xmsg__send(to="peer", text="CHILD_DAEMON_MSG_2")
    #       2) Child calls mcp__xmsg__inbox()
    #       3) Child finishes follow-up turn with "CHILD_TURN_2_COMPLETE"
    scenario_state = {
        "child_active_checked": False,
        "child_id": None,
        "child_msg_1_id": None,
        "root_tool_outputs": [],
        "child_tool_outputs": [],
    }

    def fco_str(x):
        out = x.get("output", "")
        return out if isinstance(out, str) else json.dumps(out)

    def c9_c12_handler(req_idx, body, msg_fn, fc_fn, st):
        inp = body.get("input", [])
        user_texts = []
        fc_outputs = []
        fc_calls = []
        for item in inp:
            if item.get("type") == "message" and item.get("role") == "user":
                for c in item.get("content", []):
                    if isinstance(c, dict) and "text" in c:
                        user_texts.append(c["text"])
            elif item.get("type") == "function_call":
                fc_calls.append(item)
            elif item.get("type") == "function_call_output":
                fc_outputs.append(item)

        joined_user = "\n".join(user_texts)

        # Child initial task
        if "CHILD_DAEMON_TASK_1" in joined_user and "CHILD_FOLLOWUP_TASK" not in joined_user:
            if len(fc_outputs) == 0:
                return (
                    [
                        fc_fn("send", {"to": "peer", "text": "CHILD_DAEMON_MSG_1"}, "mcp__xmsg"),
                        fc_fn("list", {}, "mcp__xmsg"),
                    ],
                    None,
                )
            elif len(fc_outputs) == 2:
                # While child is still in its active turn, send a private message from peer -> P/X
                # and let child call inbox() to receive it!
                scenario_state["child_tool_outputs"].extend(fco_str(x) for x in fc_outputs)
                _, recips = unix_http_request(http_sock, "GET", "/v1/recipients")
                sub_recips = [
                    r
                    for r in recips.get("recipients", [])
                    if r.get("kind") == "subagent" and r.get("harness") == "codex"
                ]
                if sub_recips:
                    scenario_state["child_active_checked"] = True
                    sub_addr = sub_recips[0]["address"].split("@")[0]
                    scenario_state["child_id"] = sub_addr.split("/")[1]
                    unix_http_request(
                        http_sock,
                        "POST",
                        "/v1/messages",
                        {"from": "peer", "to": sub_addr, "text": "PRIVATE_TO_ACTIVE_CHILD"},
                    )
                return ([fc_fn("inbox", {}, "mcp__xmsg")], None)
            else:
                scenario_state["child_tool_outputs"].extend(fco_str(x) for x in fc_outputs)
                return ([msg_fn("CHILD_TURN_1_COMPLETE")], None)

        # Child follow-up task (triggered via send_input)
        if "CHILD_FOLLOWUP_TASK" in joined_user:
            # Count how many function calls happened after CHILD_FOLLOWUP_TASK
            idx_follow = max(
                i
                for i, it in enumerate(inp)
                if it.get("type") == "message" and "CHILD_FOLLOWUP_TASK" in json.dumps(it)
            )
            post_outputs = [
                it for it in inp[idx_follow:] if it.get("type") == "function_call_output"
            ]
            if len(post_outputs) == 0:
                return (
                    [
                        fc_fn("send", {"to": "peer", "text": "CHILD_DAEMON_MSG_2"}, "mcp__xmsg"),
                        fc_fn("inbox", {}, "mcp__xmsg"),
                    ],
                    None,
                )
            else:
                scenario_state["child_tool_outputs"].extend(
                    fco_str(x) for x in post_outputs
                )
                return ([msg_fn("CHILD_TURN_2_COMPLETE")], None)

        if "REBIND_SEND_AFTER_RESUME" in joined_user:
            idx_reb = max(
                i
                for i, it in enumerate(inp)
                if it.get("type") == "message" and "REBIND_SEND_AFTER_RESUME" in json.dumps(it)
            )
            post_outputs = [it for it in inp[idx_reb:] if it.get("type") == "function_call_output"]
            if len(post_outputs) == 0:
                return (
                    [fc_fn("send", {"to": "peer", "text": "REBOUND_AFTER_RESUME_OK"}, "mcp__xmsg")],
                    None,
                )
            else:
                return ([msg_fn("REBOUND_SEND_DONE")], None)

        if "SECOND_PROMPT_AFTER_RESUME" in joined_user:
            scenario_state["root_t4_input"] = json.dumps(inp)
            return ([msg_fn("SECOND_RESUME_PROMPT_DONE")], None)

        if "TRY_SEND_AFTER_RESUME" in joined_user:
            scenario_state["root_t3_input"] = json.dumps(inp)
            idx_t3 = max(
                i
                for i, it in enumerate(inp)
                if it.get("type") == "message" and "TRY_SEND_AFTER_RESUME" in json.dumps(it)
            )
            post_outputs = [it for it in inp[idx_t3:] if it.get("type") == "function_call_output"]
            if len(post_outputs) == 0:
                return (
                    [fc_fn("send", {"to": "peer", "text": "SHOULD_REFUSE_AFTER_RESUME"}, "mcp__xmsg")],
                    None,
                )
            else:
                scenario_state["resume_tool_outputs"] = [fco_str(x) for x in post_outputs]
                return ([msg_fn("RESUME_SEND_ATTEMPTED")], None)

        # Root turn 2: RUN_DAEMON_FOLLOWUP:<child_id>:<root_msg_id>
        if "RUN_DAEMON_FOLLOWUP:" in joined_user:
            scenario_state["root_t2_input"] = json.dumps(inp)
            idx_t2 = max(
                i
                for i, it in enumerate(inp)
                if it.get("type") == "message" and "RUN_DAEMON_FOLLOWUP:" in json.dumps(it)
            )
            t2_text = json.dumps(inp[idx_t2])
            parts = [p for p in t2_text.split('"') if "RUN_DAEMON_FOLLOWUP:" in p][0]
            _, child_id, root_msg_id = parts.split(":", 2)
            post_outputs = [it for it in inp[idx_t2:] if it.get("type") == "function_call_output"]
            if len(post_outputs) == 0:
                return (
                    [
                        fc_fn("replies", {"message_id": root_msg_id}, "mcp__xmsg"),
                        fc_fn(
                            "send_input",
                            {"target": child_id, "message": "CHILD_FOLLOWUP_TASK"},
                            "multi_agent_v1",
                        ),
                    ],
                    None,
                )
            elif len(post_outputs) == 2:
                scenario_state["root_tool_outputs"].extend(
                    fco_str(x) for x in post_outputs
                )
                return (
                    [
                        fc_fn(
                            "wait_agent",
                            {"targets": [child_id], "timeout_ms": 10000},
                            "multi_agent_v1",
                        )
                    ],
                    None,
                )
            else:
                scenario_state["root_tool_outputs"].extend(
                    fco_str(x) for x in post_outputs
                )
                return ([msg_fn("ROOT_TURN_2_COMPLETE")], None)

        # Root turn 1: RUN_DAEMON_SCENARIO
        if "RUN_DAEMON_SCENARIO" in joined_user:
            if len(fc_outputs) == 0:
                return (
                    [
                        fc_fn("send", {"to": "peer", "text": "ROOT_DAEMON_MSG_1"}, "mcp__xmsg"),
                        fc_fn("list", {}, "mcp__xmsg"),
                        fc_fn(
                            "spawn_agent",
                            {"message": "CHILD_DAEMON_TASK_1"},
                            "multi_agent_v1",
                        ),
                    ],
                    None,
                )
            elif len(fc_outputs) == 3:
                scenario_state["root_tool_outputs"].extend(fco_str(x) for x in fc_outputs)
                spawn_out = next(
                    json.loads(fco_str(x))
                    for x in fc_outputs
                    if "agent_id" in fco_str(x)
                )
                spawn_id = spawn_out["agent_id"]
                return (
                    [
                        fc_fn(
                            "wait_agent",
                            {"targets": [spawn_id], "timeout_ms": 10000},
                            "multi_agent_v1",
                        )
                    ],
                    None,
                )
            else:
                scenario_state["root_tool_outputs"].extend(fco_str(x) for x in fc_outputs)
                return ([msg_fn("ROOT_TURN_1_COMPLETE")], None)

        # Embedded scenario: RUN_EMBEDDED_SCENARIO
        if "RUN_EMBEDDED_SCENARIO" in joined_user:
            if len(fc_outputs) == 0:
                return (
                    [
                        fc_fn("send", {"to": "peer", "text": "ROOT_EMBEDDED_MSG"}, "mcp__xmsg"),
                        fc_fn(
                            "spawn_agent",
                            {"message": "CHILD_EMBEDDED_TASK"},
                            "multi_agent_v1",
                        ),
                    ],
                    None,
                )
            elif len(fc_outputs) == 2:
                spawn_out = next(
                    json.loads(fco_str(x))
                    for x in fc_outputs
                    if "agent_id" in fco_str(x)
                )
                spawn_id = spawn_out["agent_id"]
                return (
                    [
                        fc_fn(
                            "wait_agent",
                            {"targets": [spawn_id], "timeout_ms": 10000},
                            "multi_agent_v1",
                        )
                    ],
                    None,
                )
            else:
                return ([msg_fn("EMBEDDED_ROOT_DONE")], None)

        if "CHILD_EMBEDDED_TASK" in joined_user:
            if len(fc_outputs) == 0:
                return (
                    [fc_fn("send", {"to": "peer", "text": "CHILD_EMBEDDED_MSG"}, "mcp__xmsg")],
                    None,
                )
            else:
                return ([msg_fn("EMBEDDED_CHILD_DONE")], None)

        if "SIBLING_LIVE_SEND" in joined_user:
            if len(fc_outputs) == 0:
                return (
                    [fc_fn("send", {"to": "peer", "text": "SIBLING_STILL_LIVE"}, "mcp__xmsg")],
                    None,
                )
            else:
                return ([msg_fn("SIBLING_DONE")], None)

        if "OMITTED_ENV_SEND" in joined_user:
            if len(fc_outputs) == 0:
                return (
                    [fc_fn("send", {"to": "peer", "text": "SHOULD_FAIL_NO_ENV"}, "mcp__xmsg")],
                    None,
                )
            else:
                scenario_state["omitted_env_output"] = fco_str(fc_outputs[-1])
                return ([msg_fn("OMITTED_ENV_DONE")], None)

        return None

    provider.state.custom_handler = c9_c12_handler

    client = StdioAppServerClient(codex_bin, codex_home)
    try:
        client.initialize()
        # Start root P and sibling P_sib on the same daemon
        root_p = client.request("thread/start", {"cwd": str(work_dir)})["result"]["thread"]["id"]
        sib_p = client.request("thread/start", {"cwd": str(work_dir)})["result"]["thread"]["id"]

        # Start sibling turn so it stays registered
        client.request(
            "turn/start",
            {"threadId": sib_p, "input": [{"type": "text", "text": "SIBLING_INIT"}]},
        )

        # Start root P turn 1 (runs root send, list, spawns child X, child sends, receives active inbox, stops)
        t1 = client.request(
            "turn/start",
            {"threadId": root_p, "input": [{"type": "text", "text": "RUN_DAEMON_SCENARIO"}]},
        )
        turn1_id = t1["result"]["turn"]["id"]

        # Wait for turn 1 completion
        deadline = time.time() + 20.0
        while time.time() < deadline:
            if any(
                n.get("method") == "turn/completed"
                and n.get("params", {}).get("threadId") == root_p
                and n.get("params", {}).get("turn", {}).get("id") == turn1_id
                for n in client.notifications
            ):
                break
            time.sleep(0.05)
        else:
            raise AssertionError(f"C9/C12 failed: root turn 1 did not complete: {client.notifications[-5:]}")

        assert scenario_state["child_active_checked"], (
            f"C9 failed: child was not observed as active subagent recipient during its turn; root_out={scenario_state['root_tool_outputs']} child_out={scenario_state['child_tool_outputs']}"
        )
        child_x = scenario_state["child_id"]
        assert child_x and child_x != root_p, f"C9/C12 failed: bad child_id {child_x}"

        # Verify active child received PRIVATE_TO_ACTIVE_CHILD in its inbox
        joined_child_out = "\n".join(scenario_state["child_tool_outputs"])
        assert "PRIVATE_TO_ACTIVE_CHILD" in joined_child_out, (
            f"C9 failed: active child did not receive private inbox message: {joined_child_out}"
        )

        # Verify after SubagentStop, child_x remains addressable in D8 recipients while root_p is live
        time.sleep(0.2)
        _, recips_after = unix_http_request(http_sock, "GET", "/v1/recipients")
        assert any(
            r.get("address", "").startswith(f"{root_p}/{child_x}@")
            for r in recips_after.get("recipients", [])
        ), f"C9 failed: child {root_p}/{child_x} missing from D8 recipients while root live: {recips_after}"

        # Check peer's inbox for ROOT_DAEMON_MSG_1 and CHILD_DAEMON_MSG_1
        root_msg = recv.wait_for_text("ROOT_DAEMON_MSG_1")
        child_msg = recv.wait_for_text("CHILD_DAEMON_MSG_1")

        assert f" · {root_p}@" in root_msg["from_name"], (
            f"C12 bad root from_name: {root_msg}"
        )
        assert child_msg["from_name"] == f"default · {root_p}/{child_x}@{ child_msg['from_name'].split('@')[1] }", (
            f"C12 bad child from_name: {child_msg}"
        )

        # Now test C9 stopped-child fallback to root P + C12 replies:
        # 1) Peer sends a message to stopped child `<root_p>/<child_x>`
        st_fb, fb_res = unix_http_request(
            http_sock,
            "POST",
            "/v1/messages",
            {
                "from": "peer",
                "to": f"{root_p}/{child_x}",
                "text": "FALLBACK_TO_STOPPED_CHILD_MARKER",
            },
        )
        assert st_fb in (200, 202), f"C9 failed: send to stopped child failed: {st_fb} {fb_res}"

        # 2) Peer replies to root_msg["message_id"]
        rep_res = recv.call(
            {
                "action": "reply",
                "session": "peer",
                "message_id": root_msg["message_id"],
                "text": "REPLY_TO_ROOT_MARKER",
            }
        )
        assert rep_res.get("status") == "ok", f"C12 failed: reply to root failed: {rep_res}"

        # Start root turn 2: UserPromptSubmit drains the stopped-child fallback message into root's turn context,
        # root calls replies(message_id=root_msg["message_id"]), and calls send_input(target=child_x)
        # to trigger in-runtime child follow-up (PreModelRequest)!
        t2 = client.request(
            "turn/start",
            {
                "threadId": root_p,
                "input": [
                    {
                        "type": "text",
                        "text": f"RUN_DAEMON_FOLLOWUP:{child_x}:{root_msg['message_id']}",
                    }
                ],
            },
        )
        turn2_id = t2["result"]["turn"]["id"]
        deadline = time.time() + 20.0
        while time.time() < deadline:
            if any(
                n.get("method") == "turn/completed"
                and n.get("params", {}).get("threadId") == root_p
                and n.get("params", {}).get("turn", {}).get("id") == turn2_id
                for n in client.notifications
            ):
                break
            time.sleep(0.05)
        else:
            raise AssertionError("C9/C12 failed: root turn 2 did not complete")

        joined_root_out = "\n".join(scenario_state["root_tool_outputs"])
        root_t2_in = scenario_state.get("root_t2_input", "")
        assert f"to={root_p}/{child_x} agent_id={child_x}" in root_t2_in, (
            f"C9 failed: root did not receive stopped-child fallback header in turn context: {root_t2_in}"
        )
        assert "FALLBACK_TO_STOPPED_CHILD_MARKER" in root_t2_in
        assert "REPLY_TO_ROOT_MARKER" in joined_root_out, (
            f"C12 failed: root replies() did not return REPLY_TO_ROOT_MARKER: {joined_root_out}"
        )

        # Verify child follow-up send (`CHILD_DAEMON_MSG_2`) arrived at peer attributed to P/X!
        child_msg2 = recv.wait_for_text("CHILD_DAEMON_MSG_2")
        assert f"{root_p}/{child_x}@" in child_msg2["from_name"]

        # C9/C17 same-daemon unload parks root_p and clears child_x; thread/resume + turn/start re-attests root_p under g'
        # while child_x remains unlisted until re-spawned, and sibling `sib_p` remains continuously live!
        client.request("thread/unsubscribe", {"threadId": root_p})
        deadline = time.time() + 10.0
        while time.time() < deadline:
            loaded = client.request("thread/loaded/list", {}).get("result", {}).get("data", [])
            if root_p not in loaded:
                break
            time.sleep(0.05)
        client.request("thread/resume", {"threadId": root_p})
        _, recips_revoked = unix_http_request(http_sock, "GET", "/v1/recipients")
        assert not any(
            r.get("address", "").startswith(f"{root_p}")
            for r in recips_revoked.get("recipients", [])
        ), f"C9 failed: unloaded root {root_p} or its child still listed before turn: {recips_revoked}"

        t_reb = client.request(
            "turn/start",
            {"threadId": root_p, "input": [{"type": "text", "text": "REBIND_SEND_AFTER_RESUME"}]},
        )
        t_reb_id = t_reb["result"]["turn"]["id"]
        deadline = time.time() + 15.0
        while time.time() < deadline:
            if any(
                n.get("method") == "turn/completed"
                and n.get("params", {}).get("turn", {}).get("id") == t_reb_id
                for n in client.notifications
            ):
                break
            time.sleep(0.05)
        reb_msg = recv.wait_for_text("REBOUND_AFTER_RESUME_OK")
        assert f"{root_p}@" in reb_msg["from_name"], (
            f"C17 failed: rebound root {root_p} bad attribution after same-daemon resume: {reb_msg}"
        )

        # Now operator-revoke `root_p` (`xmsg unregister --codex-session <root_p>` -> `RevokedByOperator`, C16 + C17.7)
        # while `root_p` still holds its valid live writer lock and rollout:
        subprocess.run(
            [str(xmsg_bin), "unregister", "--codex-session", root_p],
            env=os.environ.copy(),
            check=True,
        )

        t3 = client.request(
            "turn/start",
            {"threadId": root_p, "input": [{"type": "text", "text": "TRY_SEND_AFTER_RESUME"}]},
        )
        t3_id = t3["result"]["turn"]["id"]
        t_sib = client.request(
            "turn/start",
            {"threadId": sib_p, "input": [{"type": "text", "text": "SIBLING_LIVE_SEND"}]},
        )
        t_sib_id = t_sib["result"]["turn"]["id"]
        deadline = time.time() + 15.0
        while time.time() < deadline:
            done_root = any(
                n.get("method") == "turn/completed"
                and n.get("params", {}).get("turn", {}).get("id") == t3_id
                for n in client.notifications
            )
            done_sib = any(
                n.get("method") == "turn/completed"
                and n.get("params", {}).get("turn", {}).get("id") == t_sib_id
                for n in client.notifications
            )
            if done_root and done_sib:
                break
            time.sleep(0.05)

        sib_msg = recv.wait_for_text("SIBLING_STILL_LIVE")
        assert f"{sib_p}@" in sib_msg["from_name"], (
            f"C9 failed: continuously live sibling {sib_p} bad attribution: {sib_msg}"
        )
        assert not any(
            "SHOULD_REFUSE_AFTER_RESUME" in m.get("text", "") for m in recv.received
        ), "C9/C17.7 failed: RevokedByOperator root was able to send despite operator revocation"
        resume_outs = scenario_state.get("resume_tool_outputs", [])
        assert len(resume_outs) == 1 and (
            "revoked" in resume_outs[0] or "not admitted" in resume_outs[0]
        ), f"C9/fail-open failed: expected server MCP refusal on revoked root tool call, got: {resume_outs}"
        note_str = "xmsg unavailable for this thread (resumed); start a fresh thread to use xmsg"
        t3_in_str = scenario_state.get("root_t3_input", "")
        assert t3_in_str.count(note_str) == 1, (
            f"C9/fail-open failed: expected unavailable note once on first resumed turn, got count={t3_in_str.count(note_str)} in {t3_in_str}"
        )

        # Second prompt on resumed `root_p` must exit 0 and NOT repeat the note!
        t4 = client.request(
            "turn/start",
            {"threadId": root_p, "input": [{"type": "text", "text": "SECOND_PROMPT_AFTER_RESUME"}]},
        )
        t4_id = t4["result"]["turn"]["id"]
        deadline = time.time() + 15.0
        while time.time() < deadline:
            if any(
                n.get("method") == "turn/completed"
                and n.get("params", {}).get("turn", {}).get("id") == t4_id
                for n in client.notifications
            ):
                break
            time.sleep(0.05)
        t4_in_str = scenario_state.get("root_t4_input", "")
        assert t4_in_str.count(note_str) == 1, (
            f"C9/fail-open failed: unavailable note repeated on second resumed prompt (count={t4_in_str.count(note_str)})"
        )
    finally:
        client.close()

    # Now run embedded topology (`codex exec` / `--no-daemon`) for C12:
    _, emb_trust = materialize_hooks_for_home(
        hm_final_hooks, emb_home, xmsg_bin, work_dir / "guard.sh"
    )
    write_codex_config(
        emb_home, work_dir, provider.port, xmsg_bin, emb_trust, include_xdg_env=True, mcp_wrapper=mcp_wrapper
    )
    env_emb = os.environ.copy()
    env_emb["CODEX_HOME"] = str(emb_home)
    for k in ("CODEX_SESSION_ID", "CODEX_THREAD_ID", "CODEX_TOOL_CALL_ID"):
        env_emb.pop(k, None)
    cp = subprocess.run(
        [
            str(codex_bin),
            "exec",
            "--skip-git-repo-check",
            "-C",
            str(work_dir),
            "--json",
            "RUN_EMBEDDED_SCENARIO",
        ],
        env=env_emb,
        capture_output=True,
        text=True,
        timeout=30,
    )
    assert cp.returncode == 0, f"C12 embedded exec failed: {cp.stderr}\n{cp.stdout}"

    emb_root_msg = recv.wait_for_text("ROOT_EMBEDDED_MSG")
    emb_child_msg = recv.wait_for_text("CHILD_EMBEDDED_MSG")
    emb_p = emb_root_msg["from_name"].split(" · ")[1].split("@")[0]
    emb_px = emb_child_msg["from_name"].split(" · ")[1].split("@")[0]
    assert emb_px.startswith(f"{emb_p}/"), f"C12 embedded child not under {emb_p}: {emb_px}"
    emb_x = emb_px.split("/")[1]

    # Verify captured MCP wire frames (`params._meta`) for both daemon and embedded root & child!
    wire_frames = [
        json.loads(line)
        for line in mcp_log.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    tool_calls = [f for f in wire_frames if f.get("method") == "tools/call"]
    assert len(tool_calls) >= 6, f"C12 failed: expected >=6 MCP tools/call frames, got {len(tool_calls)}"

    def find_call_by_text(marker):
        for tc in tool_calls:
            args = tc.get("params", {}).get("arguments", {})
            if args.get("text") == marker:
                return tc
        raise AssertionError(f"C12 failed: MCP call for {marker} not found in wire log")

    for r_id, c_id, r_marker, c_marker in (
        (root_p, child_x, "ROOT_DAEMON_MSG_1", "CHILD_DAEMON_MSG_1"),
        (emb_p, emb_x, "ROOT_EMBEDDED_MSG", "CHILD_EMBEDDED_MSG"),
    ):
        rc = find_call_by_text(r_marker)
        cc = find_call_by_text(c_marker)
        assert "as_agent" not in rc["params"].get("arguments", {}), (
            f"C12 failed: model supplied as_agent on root call: {rc}"
        )
        assert "as_agent" not in cc["params"].get("arguments", {}), (
            f"C12 failed: model supplied as_agent on child call: {cc}"
        )
        r_meta = rc["params"]["_meta"]
        c_meta = cc["params"]["_meta"]
        assert r_meta["sessionId"] == r_id and r_meta["threadId"] == r_id, (
            f"C12 failed: root _meta mismatch: {r_meta} vs {r_id}"
        )
        assert c_meta["sessionId"] == r_id and c_meta["threadId"] == c_id, (
            f"C12 failed: child _meta mismatch: {c_meta} vs {r_id}/{c_id}"
        )
        assert c_meta["x-codex-turn-metadata"]["parent_thread_id"] == r_id, (
            f"C12 failed: child parent_thread_id != {r_id}: {c_meta}"
        )

    shutil.rmtree(emb_home, ignore_errors=True)

    # C2 Negative control: omitted `env_vars = ["XDG_RUNTIME_DIR"]` fails socket resolution
    _, noenv_trust = materialize_hooks_for_home(
        hm_final_hooks, noenv_home, xmsg_bin, work_dir / "guard.sh"
    )
    write_codex_config(
        noenv_home, work_dir, provider.port, xmsg_bin, noenv_trust, include_xdg_env=False
    )
    env_no = os.environ.copy()
    env_no["CODEX_HOME"] = str(noenv_home)
    for k in ("CODEX_SESSION_ID", "CODEX_THREAD_ID", "CODEX_TOOL_CALL_ID"):
        env_no.pop(k, None)
    subprocess.run(
        [
            str(codex_bin),
            "exec",
            "--skip-git-repo-check",
            "-C",
            str(work_dir),
            "--json",
            "OMITTED_ENV_SEND",
        ],
        env=env_no,
        capture_output=True,
        text=True,
        timeout=30,
    )
    recv.drain_available(0.3)
    assert not any(
        "SHOULD_FAIL_NO_ENV" in m.get("text", "") for m in recv.received
    ), "C2 failed: send succeeded even with XDG_RUNTIME_DIR omitted from env_vars"
    omitted_out = scenario_state.get("omitted_env_output", "")
    assert any(
        s in omitted_out
        for s in ("XDG_RUNTIME_DIR", "insecure agent socket directory", "/nonexistent")
    ), f"C2 failed: expected socket resolution error when env_vars omitted, got: {omitted_out}"
    shutil.rmtree(noenv_home, ignore_errors=True)
    provider.state.custom_handler = None
    print("=== C2, C9, C12 PASSED ===")


# ---------------------------------------------------------------------------
# Oracle 4: C14 Real App-Server Idle/Busy Push, Model Echo, Embedded Stop Drain & Impostor Listener
# ---------------------------------------------------------------------------


class ImpostorAppServer:
    """Listens on a Unix socket speaking WebSocket JSON-RPC as a fake app-server
    owned by python3 (not the trusted codex executable) to prove C14's peer check."""

    def __init__(self, sock_path: Path, loaded_ids: list[str]):
        self.sock_path = sock_path
        self.loaded_ids = loaded_ids
        self.recorded_requests = []
        self.recorded_TurnStart = 0
        self.recorded_callbacks_answered = 0
        self._stop = False
        sock_path.parent.mkdir(parents=True, exist_ok=True)
        sock_path.parent.chmod(0o700)
        if sock_path.exists() or sock_path.is_symlink():
            sock_path.unlink()
        self.srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.srv.bind(str(sock_path))
        os.chmod(sock_path, 0o600)
        self.srv.listen(5)
        self.srv.settimeout(0.2)
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        while not self._stop:
            try:
                conn, _ = self.srv.accept()
            except socket.timeout:
                continue
            except Exception:
                break
            threading.Thread(target=self._handle_conn, args=(conn,), daemon=True).start()

    def _handle_conn(self, conn: socket.socket):
        try:
            conn.settimeout(2.0)
            buf = b""
            while b"\r\n\r\n" not in buf:
                c = conn.recv(4096)
                if not c:
                    return
                buf += c
            head = buf.split(b"\r\n\r\n", 1)[0].decode("utf-8", "replace")
            key = ""
            for line in head.splitlines():
                if line.lower().startswith("sec-websocket-key:"):
                    key = line.split(":", 1)[1].strip()
            accept = base64.b64encode(
                hashlib.sha1((key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11").encode()).digest()
            ).decode()
            resp = (
                "HTTP/1.1 101 Switching Protocols\r\n"
                "Upgrade: websocket\r\n"
                "Connection: Upgrade\r\n"
                f"Sec-WebSocket-Accept: {accept}\r\n\r\n"
            )
            conn.sendall(resp.encode("ascii"))
            while not self._stop:
                b = conn.recv(2)
                if len(b) < 2:
                    break
                masked = (b[1] & 0x80) != 0
                length = b[1] & 0x7F
                if length == 126:
                    length = int.from_bytes(conn.recv(2), "big")
                elif length == 127:
                    length = int.from_bytes(conn.recv(8), "big")
                mask = conn.recv(4) if masked else b""
                data = conn.recv(length)
                if masked:
                    data = bytes(x ^ mask[i % 4] for i, x in enumerate(data))
                msg = json.loads(data.decode("utf-8"))
                self.recorded_requests.append(msg)
                if msg.get("method") == "turn/start":
                    self.recorded_TurnStart += 1
                if "result" in msg and "method" not in msg:
                    self.recorded_callbacks_answered += 1
        except Exception:
            pass
        finally:
            conn.close()

    def close(self):
        self._stop = True
        try:
            self.srv.close()
        except Exception:
            pass


def run_oracle_c14(
    codex_bin: Path,
    xmsg_bin: Path,
    hm_final_hooks: dict,
    provider: LocalResponsesServer,
    http_sock: Path,
    work_dir: Path,
    codex_home: Path,
    imp_home: Path,
):
    print("=== C14: Real app-server idle & busy live push, model echo, embedded Stop drain & impostor listener ===")
    _, trust = materialize_hooks_for_home(
        hm_final_hooks, codex_home, xmsg_bin, work_dir / "guard.sh"
    )
    write_codex_config(codex_home, work_dir, provider.port, xmsg_bin, trust)

    # Start real `codex app-server --listen unix://`
    env = os.environ.copy()
    env["CODEX_HOME"] = str(codex_home)
    for k in ("CODEX_SESSION_ID", "CODEX_THREAD_ID", "CODEX_TOOL_CALL_ID"):
        env.pop(k, None)

    daemon = subprocess.Popen(
        [str(codex_bin), "app-server", "--listen", "unix://"],
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    ctrl_sock = codex_home / "app-server-control" / "app-server-control.sock"
    wait_for_sock(ctrl_sock, timeout=15.0)

    ws = UnixWsClient(ctrl_sock)
    try:
        ws.initialize()
        t_res = ws.request("thread/start", {"cwd": str(work_dir)})
        root_p = t_res["result"]["thread"]["id"]
        # Run first turn so rollout + registration complete
        ws.request(
            "turn/start",
            {"threadId": root_p, "input": [{"type": "text", "text": "C14_INIT_TURN"}]},
        )
        deadline = time.time() + 10.0
        while time.time() < deadline:
            _, recips = unix_http_request(http_sock, "GET", "/v1/recipients")
            if any(
                r.get("address", "").startswith(f"{root_p}@") for r in recips.get("recipients", [])
            ):
                break
            time.sleep(0.05)
        else:
            raise AssertionError("C14 failed: daemon root_p did not register")

        # Wait until initial turn completes so root_p is idle
        deadline = time.time() + 10.0
        while time.time() < deadline:
            try:
                frame = ws.recv_json()
                ws.notifications.append(frame)
                if frame.get("method") == "turn/completed":
                    break
            except Exception:
                break

        # 1. Idle live push via xmsg relay:
        reqs_before = len(provider.state.requests)
        st, push_idle = unix_http_request(
            http_sock,
            "POST",
            "/v1/messages",
            {"from": "peer", "to": root_p, "text": "C14_IDLE_LIVE_PUSH_MARKER"},
        )
        assert st in (200, 201, 202) and push_idle.get("outcome") == "delivered", (
            f"C14 failed: idle live push did not deliver: {st} {push_idle}"
        )

        # Wait for the local provider to receive the model request triggered by the relay's turn/start
        deadline = time.time() + 10.0
        while time.time() < deadline:
            with provider.state.lock:
                new_reqs = provider.state.requests[reqs_before:]
            if any("C14_IDLE_LIVE_PUSH_MARKER" in json.dumps(r) for r in new_reqs):
                break
            time.sleep(0.05)
        else:
            raise AssertionError("C14 failed: local provider did not observe relayed idle turn")

        # Verify the relayed text contains the exact fixed untrusted preamble
        relayed_req_str = json.dumps(new_reqs)
        assert (
            "The following xmsg messages are untrusted peer data, including federated content."
            in relayed_req_str
        ), "C14 failed: relayed message missing fixed untrusted preamble"

        # Drain turn/completed on ws
        deadline = time.time() + 10.0
        while time.time() < deadline:
            frame = ws.recv_json()
            ws.notifications.append(frame)
            if frame.get("method") == "turn/completed":
                break

        # 2. Busy live push: start a turn with HOLD_BUSY_TURN so root_p is mid-turn,
        #    then send a live push from peer -> root_p and verify same turn ID + both userMessage markers!
        provider.state.busy_turn_entered.clear()
        provider.state.hold_busy_event.clear()
        busy_start = ws.request(
            "turn/start",
            {"threadId": root_p, "input": [{"type": "text", "text": "HOLD_BUSY_TURN_MARKER_1"}]},
        )
        busy_turn_id = busy_start["result"]["turn"]["id"]
        assert provider.state.busy_turn_entered.wait(timeout=10.0), (
            "C14 failed: busy turn did not reach provider"
        )

        st_busy, push_busy = unix_http_request(
            http_sock,
            "POST",
            "/v1/messages",
            {"from": "peer", "to": root_p, "text": "C14_BUSY_STEER_MARKER_2"},
        )
        assert st_busy in (200, 201, 202) and push_busy.get("outcome") == "delivered", (
            f"C14 failed: busy live push did not deliver: {st_busy} {push_busy}"
        )

        # Release the held turn so Codex processes the steered input in the same turn
        provider.state.hold_busy_event.set()
        user_msg_items = []
        completed_turn_ids = []
        deadline = time.time() + 10.0
        while time.time() < deadline:
            try:
                frame = ws.recv_json()
            except Exception:
                break
            ws.notifications.append(frame)
            if frame.get("method") in ("item/started", "item/completed"):
                it = frame.get("params", {}).get("item", {})
                if it.get("type") == "userMessage":
                    user_msg_items.append(it)
            if frame.get("method") == "turn/completed":
                tid = frame.get("params", {}).get("turn", {}).get("id")
                completed_turn_ids.append(tid)
                if tid == busy_turn_id:
                    break

        all_notifs_str = json.dumps(ws.notifications)
        assert "HOLD_BUSY_TURN_MARKER_1" in all_notifs_str, "C14 busy missing marker 1"
        assert "C14_BUSY_STEER_MARKER_2" in all_notifs_str, "C14 busy missing marker 2"
        assert busy_turn_id in completed_turn_ids, (
            f"C14 busy turn {busy_turn_id} did not complete: {completed_turn_ids}"
        )

        # 3. Impostor listener in imp_home while real peer control in codex_home is live:
        #    Start an embedded codex process in imp_home that holds a writer lock + registration,
        #    and plant an impostor Python listener at imp_home/app-server-control/app-server-control.sock!
        _, imp_trust = materialize_hooks_for_home(
            hm_final_hooks, imp_home, xmsg_bin, work_dir / "guard.sh"
        )
        write_codex_config(imp_home, work_dir, provider.port, xmsg_bin, imp_trust)

        provider.state.busy_turn_entered.clear()
        provider.state.hold_busy_event.clear()
        env_imp = os.environ.copy()
        env_imp["CODEX_HOME"] = str(imp_home)
        for k in ("CODEX_SESSION_ID", "CODEX_THREAD_ID", "CODEX_TOOL_CALL_ID"):
            env_imp.pop(k, None)

        imp_proc = subprocess.Popen(
            [
                str(codex_bin),
                "exec",
                "--skip-git-repo-check",
                "-C",
                str(work_dir),
                "--json",
                "HOLD_BUSY_TURN_EMBEDDED_IMPOSTOR",
            ],
            env=env_imp,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert provider.state.busy_turn_entered.wait(timeout=15.0), (
            "C14 failed: embedded process in imp_home did not enter turn"
        )
        imp_locks = [
            p
            for p in (imp_home / "thread-writer-locks").glob("*.lock")
            if not p.name.startswith(".")
        ]
        assert len(imp_locks) == 1, f"C14 expected 1 lock in imp_home, got {imp_locks}"
        imp_root = imp_locks[0].stem

        # Plant impostor listener at imp_home/app-server-control/app-server-control.sock
        impostor = ImpostorAppServer(
            imp_home / "app-server-control" / "app-server-control.sock", [imp_root]
        )
        try:
            st_imp, res_imp = unix_http_request(
                http_sock,
                "POST",
                "/v1/messages",
                {"from": "peer", "to": imp_root, "text": "C14_SECRET_FOR_EMBEDDED_AND_STOP_DRAIN"},
            )
            # Because the listener is owned by python3 (not the trusted codex exe/owner),
            # xmsg serve must refuse the impostor BEFORE connecting/sending text and queue the message!
            assert st_imp in (200, 202) and res_imp.get("outcome") == "queued", (
                f"C14 failed: send to root with impostor listener was not queued: {st_imp} {res_imp}"
            )
            assert impostor.recorded_TurnStart == 0, (
                f"C14 failed: impostor listener received turn/start: {impostor.recorded_requests}"
            )
            assert "C14_SECRET_FOR_EMBEDDED_AND_STOP_DRAIN" not in json.dumps(
                impostor.recorded_requests
            ), "C14 failed: impostor listener observed message text!"

            # Same-run positive control: real daemon peer in codex_home still delivers!
            st_ctrl, res_ctrl = unix_http_request(
                http_sock,
                "POST",
                "/v1/messages",
                {"from": "peer", "to": root_p, "text": "C14_REAL_PEER_CONTROL_MARKER"},
            )
            assert st_ctrl in (200, 201, 202) and res_ctrl.get("outcome") == "delivered", (
                f"C14 failed: same-run real peer control failed: {st_ctrl} {res_ctrl}"
            )
        finally:
            impostor.close()

        # Now release `imp_proc`'s held turn so it reaches `Stop` hook, drains the queued
        # `C14_SECRET_FOR_EMBEDDED_AND_STOP_DRAIN` via `decision: "block", reason: ...`,
        # and continues its turn to echo the marker!
        provider.state.hold_busy_event.set()
        imp_stdout, imp_stderr = imp_proc.communicate(timeout=20)
        assert imp_proc.returncode == 0, f"C14 embedded proc failed: {imp_stderr}\n{imp_stdout}"
        assert "C14_SECRET_FOR_EMBEDDED_AND_STOP_DRAIN" in imp_stdout, (
            f"C14 failed: embedded process did not drain queued message at Stop hook: {imp_stdout}"
        )
    finally:
        ws.close()
        try:
            daemon.terminate()
            daemon.wait(timeout=5)
        except Exception:
            try:
                daemon.kill()
            except Exception:
                pass

    print("=== C14 PASSED ===")


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main():
    (
        codex_bin_s,
        xmsg_bin_s,
        hm_final_hooks_path,
        hm_trust_path,
        hm_retargeted_trust_path,
        hm_vectors_hooks_path,
        hm_vectors_trust_path,
        hm_reordered_hooks_path,
        hm_reordered_trust_path,
        hm_mcp_server_path,
    ) = sys.argv[1:11]

    codex_bin = Path(codex_bin_s).resolve()
    xmsg_bin = Path(xmsg_bin_s).resolve()
    hm_final_hooks = json.loads(Path(hm_final_hooks_path).read_text(encoding="utf-8"))
    hm_trust_state = json.loads(Path(hm_trust_path).read_text(encoding="utf-8"))
    hm_retargeted_trust_state = json.loads(
        Path(hm_retargeted_trust_path).read_text(encoding="utf-8")
    )
    hm_vectors_hooks = json.loads(Path(hm_vectors_hooks_path).read_text(encoding="utf-8"))
    hm_vectors_trust_state = json.loads(Path(hm_vectors_trust_path).read_text(encoding="utf-8"))
    hm_reordered_hooks = json.loads(Path(hm_reordered_hooks_path).read_text(encoding="utf-8"))
    hm_reordered_trust_state = json.loads(Path(hm_reordered_trust_path).read_text(encoding="utf-8"))
    hm_mcp_server = json.loads(Path(hm_mcp_server_path).read_text(encoding="utf-8"))

    base_tmp = Path(tempfile.mkdtemp(prefix="xmsg-codex-check-"))
    xdg_run = base_tmp / "run"
    xdg_run.mkdir(parents=True, exist_ok=True)
    xdg_run.chmod(0o700)
    os.environ["XDG_RUNTIME_DIR"] = str(xdg_run)
    os.environ["HOME"] = str(base_tmp / "home")
    Path(os.environ["HOME"]).mkdir(parents=True, exist_ok=True)

    work_dir = base_tmp / "work"
    work_dir.mkdir(parents=True, exist_ok=True)

    codex_home_1 = base_tmp / "codex-home-1"
    codex_home_2 = base_tmp / "codex-home-2"
    codex_home_3 = base_tmp / "codex-home-3"
    imp_home = base_tmp / "codex-home-imp"

    provider = LocalResponsesServer()
    serve_proc = None
    try:
        # Run Oracle C8 first
        run_oracle_c8(
            codex_bin,
            xmsg_bin,
            hm_final_hooks,
            hm_trust_state,
            hm_retargeted_trust_state,
            hm_vectors_hooks,
            hm_vectors_trust_state,
            hm_reordered_hooks,
            hm_reordered_trust_state,
            provider.port,
            work_dir,
        )

        # Start real `xmsg serve` trusting codex_bin and our isolated homes
        # Wait: C11 also uses a dynamic `tui_home` under `/tmp/xmsg-codex-tui-home-*` and C12 uses `emb_home`.
        # Let's allocate all homes up front and pass `--codex-home` for each to `xmsg serve`!
        tui_home = base_tmp / "codex-home-tui"
        emb_home = base_tmp / "codex-home-emb"
        noenv_home = base_tmp / "codex-home-noenv"
        for h in (codex_home_1, codex_home_2, codex_home_3, imp_home, tui_home, emb_home, noenv_home):
            if h.exists():
                shutil.rmtree(h)
            h.mkdir(parents=True, exist_ok=True)

        serve_cmd = [
            str(xmsg_bin),
            "serve",
            "--db-path",
            str(base_tmp / "xmsg.db"),
            "--codex-exe",
            str(codex_bin),
        ]
        for h in (codex_home_1, codex_home_2, codex_home_3, imp_home, tui_home, emb_home, noenv_home):
            serve_cmd.extend(["--codex-home", str(h)])

        serve_log = base_tmp / "serve.log"
        serve_proc = subprocess.Popen(
            serve_cmd,
            stdout=open(serve_log, "w"),
            stderr=subprocess.STDOUT,
            env=os.environ.copy(),
        )

        sock_dir = xdg_run / "xmsg"
        http_sock = sock_dir / "http.sock"
        reg_sock = sock_dir / "register.sock"
        agent_sock = sock_dir / "agent.sock"
        wait_for_sock(http_sock)
        wait_for_sock(reg_sock)
        wait_for_sock(agent_sock)

        # Register `peer` recipient via a plugin connection on register.sock
        recv = PluginReceiver(reg_sock)

        run_oracle_c11_with_homes(
            codex_bin,
            xmsg_bin,
            hm_final_hooks,
            hm_mcp_server,
            provider,
            http_sock,
            reg_sock,
            work_dir,
            codex_home_1,
            tui_home,
        )

        run_oracle_c2_c9_c12_with_homes(
            codex_bin,
            xmsg_bin,
            hm_final_hooks,
            provider,
            http_sock,
            reg_sock,
            recv,
            work_dir,
            codex_home_2,
            emb_home,
            noenv_home,
        )

        run_oracle_c14(
            codex_bin,
            xmsg_bin,
            hm_final_hooks,
            provider,
            http_sock,
            work_dir,
            codex_home_3,
            imp_home,
        )

        print("ALL CODEX REAL-BINARY CI ORACLES (C2, C8, C9, C11, C12, C14) PASSED!")
    except Exception:
        if (base_tmp / "serve.log").exists():
            print("--- xmsg serve.log ---", file=sys.stderr)
            print((base_tmp / "serve.log").read_text(encoding="utf-8", errors="replace"), file=sys.stderr)
        raise
    finally:
        provider.close()
        if serve_proc is not None:
            try:
                serve_proc.terminate()
                serve_proc.wait(timeout=5)
            except Exception:
                try:
                    serve_proc.kill()
                except Exception:
                    pass
        shutil.rmtree(base_tmp, ignore_errors=True)
        for p in (
            Path("/tmp/xmsg-codex-tui-fixed-home"),
            Path("/tmp/xmsg-codex-emb-fixed-home"),
            Path("/tmp/xmsg-codex-noenv-fixed-home"),
            Path("/tmp/xmsg-codex-ci-user-home"),
        ):
            shutil.rmtree(p, ignore_errors=True)


if __name__ == "__main__":
    main()
