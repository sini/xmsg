"""How the hermes plugin finds the daemon, runnable without hermes: XMSG_*_SOCK, then a cached
`xmsg doctor --json`, then the legacy $XDG_RUNTIME_DIR/xmsg/. A fake `xmsg` on PATH plays doctor
and fake register.sock servers record which one the plugin connected to.
Run with: python3 extensions/hermes/test_endpoints.py"""

import importlib.util
import json
import logging
import os
import shutil
import socket
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
TMP = tempfile.mkdtemp(prefix="hermes-endpoints-")
os.chmod(TMP, 0o700)
BIN = os.path.join(TMP, "bin")
CALLS = os.path.join(TMP, "doctor-calls")
MANAGED = os.path.join(TMP, "xmsg-1000-0123456789ab")
for d in (BIN, MANAGED, os.path.join(TMP, "xmsg"), os.path.join(TMP, "pinned")):
    os.makedirs(d, mode=0o700)
USABLE = json.dumps({"endpoints_usable": True, "register_socket": f"{MANAGED}/register.sock",
                     "leaf_register_socket": None, "agent_socket": f"{MANAGED}/agent.sock"})
UNUSABLE = json.dumps({"endpoints_usable": False, "register_socket": f"{MANAGED}/register.sock"})
UNSUPPORTED = "error: unrecognized subcommand 'doctor'\\n\\nUsage: xmsg <COMMAND>\\n\\nFor more information, try '--help'.\\n"
# Each mode prints doctor's stdout (exit 1, as doctor does with a failed check) or misbehaves.
with open(os.path.join(BIN, "xmsg"), "w") as f:
    f.write(f"""#!/bin/sh
[ "$1 $2" = "doctor --json" ] || exit 9
echo x >> '{CALLS}'
case "$FAKE_DOCTOR" in
  usable) echo '{USABLE}'; exit 1 ;;
  unusable) echo '{UNUSABLE}'; exit 1 ;;
  malformed) echo '{{not json'; exit 1 ;;
  unsupported) printf "{UNSUPPORTED}" >&2; exit 2 ;;
  timeout) exec sleep 10 ;;
esac
""")
os.chmod(os.path.join(BIN, "xmsg"), 0o755)
SYSTEM_PATH = os.environ.get("PATH", "")


def probes():
    try:
        with open(CALLS) as f:
            return len(f.read().split())
    except FileNotFoundError:
        return 0


class Server:
    """A register.sock that answers the hello and every request but poll; it counts hellos."""

    def __init__(self, path):
        self.hellos, self.conns = 0, []
        self.s = socket.socket(socket.AF_UNIX)
        self.s.bind(path)
        self.s.listen()
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            c, _ = self.s.accept()
            self.conns.append(c)
            threading.Thread(target=self._serve, args=(c,), daemon=True).start()

    def _serve(self, c):
        try:
            for line in c.makefile("r"):
                frame = json.loads(line)
                if "harness" in frame:
                    self.hellos += 1
                    c.sendall(b'{"status":"ok"}\n')
                elif frame.get("action") != "poll":
                    c.sendall((json.dumps({"status": "ok", "request_id": frame["request_id"]}) + "\n").encode())
        except OSError:
            pass

    def drop(self):
        for c in self.conns:
            c.shutdown(socket.SHUT_RDWR)
        self.conns = []


SERVERS = {"managed": Server(f"{MANAGED}/register.sock"), "legacy": Server(os.path.join(TMP, "xmsg", "register.sock")),
           "pinned": Server(os.path.join(TMP, "pinned", "register.sock"))}


class Records(logging.Handler):
    lines = []

    def emit(self, record):
        self.lines.append(record.getMessage())


logging.getLogger().addHandler(Records())


class Ctx:
    _manager = None  # no CLI: the plugin runs as on the TUI and desktop host

    def __init__(self):
        self.tools = {}

    def register_tool(self, name, handler, **_):
        self.tools[name] = handler

    def register_hook(self, *_):
        pass


LOADS = [0]


def load(**env):
    """A fresh plugin module per case, so each case starts with an empty doctor cache."""
    for k in ("XMSG_REGISTER_SOCK", "XMSG_AGENT_SOCK", "FAKE_DOCTOR"):
        os.environ.pop(k, None)
    os.environ.update(XDG_RUNTIME_DIR=TMP, HERMES_HOME=os.path.join(TMP, "hermes"), PATH=f"{BIN}:{SYSTEM_PATH}")
    os.environ.update(env)
    if os.path.exists(CALLS):
        os.unlink(CALLS)
    Records.lines.clear()
    for s in SERVERS.values():
        s.hellos = 0
    LOADS[0] += 1
    spec = importlib.util.spec_from_file_location(f"xmsg_hermes_case{LOADS[0]}", os.path.join(HERE, "__init__.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    ctx = Ctx()
    module.register(ctx)
    return ctx


def listing(ctx):
    return json.loads(ctx.tools["xmsg_list"]({}, session_id="s1"))


def main():
    # Precedence: the env pin wins without a probe; else doctor; else the legacy directory.
    ctx = load(FAKE_DOCTOR="usable", XMSG_REGISTER_SOCK=os.path.join(TMP, "pinned", "register.sock"))
    listing(ctx)
    assert SERVERS["pinned"].hellos == 1, "env pin connects to the pinned socket"
    assert SERVERS["managed"].hellos + SERVERS["legacy"].hellos == 0
    assert probes() == 0, "an env pin needs no doctor probe"

    ctx = load(FAKE_DOCTOR="usable")
    listing(ctx)
    assert SERVERS["managed"].hellos == 1, "doctor's register_socket is used"
    assert SERVERS["legacy"].hellos == 0, "the legacy directory is not used when doctor answers"
    # The probe is cached: load-time resolution and more calls on the connection ran it once.
    listing(ctx)
    listing(ctx)
    assert probes() == 1, f"one probe for load and three tool calls, saw {probes()}"
    # A disconnect re-runs it at the next connect.
    SERVERS["managed"].drop()
    time.sleep(0.2)
    listing(ctx)
    assert SERVERS["managed"].hellos == 2, "reconnected after the drop"
    assert probes() == 2, "the disconnect re-ran the probe"

    # A missing xmsg binary, or one without doctor, falls through to the legacy directory with one log line.
    for env, reason in ((dict(PATH=os.path.join(TMP, "empty")), "xmsg CLI not found"),
                        (dict(FAKE_DOCTOR="unsupported"), "xmsg CLI has no doctor")):
        ctx = load(**env)
        listing(ctx)
        listing(ctx)
        assert SERVERS["legacy"].hellos == 1, f"legacy fallback ({reason})"
        lines = [line for line in Records.lines if "legacy socket directory" in line]
        assert len(lines) == 1 and reason in lines[0], f"one fallback log line: {Records.lines}"

    # Unusable endpoints, malformed output and a timeout refuse: the plugin is off, and nothing
    # connects to the legacy directory.
    for mode, reason in (("unusable", "unusable"), ("malformed", "invalid JSON"), ("timeout", "time bound")):
        ctx = load(FAKE_DOCTOR=mode)
        assert ctx.tools == {}, f"{mode}: the plugin is off"
        assert any(reason in line and "plugin is off" in line for line in Records.lines), f"{mode}: {Records.lines}"
        assert SERVERS["legacy"].hellos + SERVERS["managed"].hellos == 0, f"{mode}: no connection"

    print("✔ hermes finds the daemon through XMSG_REGISTER_SOCK, a cached xmsg doctor probe, then the legacy "
          "runtime dir; doctor refusals never reroute")


try:
    main()
finally:
    shutil.rmtree(TMP, ignore_errors=True)
sys.exit(0)
