#!/usr/bin/env python3
"""XH3 oracles 1-6: the real hermes CLI (the classic REPL, on a pty), with the plugin and the
config.yaml settings the home-manager switch renders, against a real `xmsg serve`. The model is
a mock OpenAI-compatible server on loopback. A user message containing `CALL <tool> <json>`
makes it call that tool once, and `CALL <tool> <json> THEN <tool> <json>` makes it call the
second after the first one's result; one containing `SLOW` gets its answer streamed slowly, so
a turn is running while a message is pushed; anything else gets the answer `ok`. A fake plugin
connection on register.sock is the receiver whose deliveries show each send's attribution.
Oracle 6 and its control run on the desktop host instead: hermes's tui_gateway, the backend of
the Ink TUI and the desktop app, driven over its stdio JSON-RPC.

usage: check.py <xmsg> <hermes> <plugin dir> <settings.json>
Exits non-zero naming the first oracle that fails."""
import http.server, json, os, pty, select, signal, socket, subprocess, sys, threading, time, uuid

XMSG, HERMES, PLUGIN, SETTINGS = sys.argv[1:5]
TMP = os.environ.get("TMPDIR", "/tmp")
RUN = os.path.join(TMP, "run")
SOCKS = os.path.join(RUN, "xmsg")
HOME = os.path.join(TMP, "home")
HH = os.path.join(HOME, ".hermes")
procs = []
T0 = time.time()
SLOW_CHUNKS, SLOW_GAP = 16, 0.5


def fail(msg):
    print(f"hermes-plugin: FAIL {msg}", file=sys.stderr)
    for name in ("serve.log", "mock.log"):
        p = os.path.join(TMP, name)
        if os.path.exists(p):
            print(f"--- {name} ---\n" + open(p, errors="replace").read()[-5000:], file=sys.stderr)
    print("--- hermes screen (tail) ---\n" + screen()[-5000:], file=sys.stderr)
    p = os.path.join(HH, "logs", "agent.log")
    if os.path.exists(p):
        print("--- agent.log (xmsg lines) ---", file=sys.stderr)
        print("".join(l for l in open(p, errors="replace") if "xmsg" in l)[-4000:], file=sys.stderr)
    for p in procs:
        p.kill()
    if hermes_pid:
        os.kill(hermes_pid, signal.SIGKILL)
    sys.exit(1)


def ok(msg):
    print(f"hermes-plugin: ok {msg} ({time.time() - T0:.0f}s)", flush=True)


def wait_until(pred, secs, what):
    end = time.time() + secs
    while time.time() < end:
        v = pred()
        if v:
            return v
        time.sleep(0.1)
    fail(f"timed out after {secs}s waiting for {what}")


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --- the mock model ----------------------------------------------------------------------

requests = []  # every chat request: its messages, and for a SLOW one whether it was cut off
req_lock = threading.Lock()
mlog = open(os.path.join(TMP, "mock.log"), "a")


def text_of(m):
    c = m.get("content")
    if isinstance(c, list):
        return "".join(p.get("text", "") for p in c if isinstance(p, dict))
    return c or ""


def calls_of(txt):
    """The calls a user message asks for: it starts `CALL <tool> <json>`, then any `THEN <tool>
    <json>`. hermes's notice of a finished delegate quotes the delegate's goal, but never starts so."""
    out = []
    if not txt.startswith("CALL "):
        return out
    rest = txt[5:]
    while True:
        tool, _, args = rest.partition(" ")
        args = args.lstrip()
        obj, end = json.JSONDecoder().raw_decode(args)
        out.append((tool, obj))
        rest = args[end:].lstrip()
        if not rest.startswith("THEN "):
            return out
        rest = rest[5:]


def chunk(delta, finish=None):
    return ("data: " + json.dumps({"id": "m", "object": "chat.completion.chunk", "created": 0, "model": "m",
                                   "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}) + "\n\n").encode()


class Mock(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def reply_json(self, obj):
        b = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_GET(self):
        self.reply_json({"object": "list", "data": [{"id": "m", "object": "model", "context_length": 200000}]})

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        msgs = body.get("messages", [])
        last = msgs[-1] if msgs else {}
        txt = text_of(last) if last.get("role") == "user" else ""
        rec = {"messages": msgs, "done": False, "aborted": False, "stream": bool(body.get("stream"))}
        with req_lock:
            requests.append(rec)
        tools = sorted(t.get("function", {}).get("name", "") for t in body.get("tools") or [])
        mlog.write(f"{time.time() - T0:.1f} POST stream={rec['stream']} n={len(msgs)} tools={len(tools)}"
                   f"{' xmsg' if 'xmsg_send' in tools else ''} last={json.dumps(last)[:240]}\n")
        if os.environ.get("XH3_DEBUG_TOOLS"):
            mlog.write(f"  tools: {tools}\n")
        mlog.flush()
        call = None
        # The latest user message's calls, one per request: the next one after each tool result.
        ui = max((i for i, m in enumerate(msgs) if m.get("role") == "user"), default=None)
        want = calls_of(text_of(msgs[ui])) if ui is not None else []
        k = sum(m.get("role") == "tool" for m in msgs[ui + 1:]) if ui is not None else 0
        if k < len(want) and body.get("tools"):
            tool, obj = want[k]
            if tool not in tools and "tool_call" in tools:
                # hermes defers plugin tools behind its Tool Search bridge (tools.tool_search).
                tool, obj = "tool_call", {"calls": [{"name": tool, "arguments": obj}]}
            call = {"index": 0, "id": f"call_{uuid.uuid4().hex[:8]}", "type": "function",
                    "function": {"name": tool, "arguments": json.dumps(obj)}}
        if not rec["stream"]:
            msg = {"role": "assistant", "content": "ok"}
            if call:
                msg = {"role": "assistant", "content": None, "tool_calls": [dict(call, index=None)]}
            self.reply_json({"id": "m", "object": "chat.completion", "created": 0, "model": "m",
                             "choices": [{"index": 0, "message": msg, "finish_reason": "tool_calls" if call else "stop"}],
                             "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2}})
            rec["done"] = True
            return
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.send_header("connection", "close")
        self.end_headers()
        self.close_connection = True
        try:
            if call:
                self.wfile.write(chunk({"role": "assistant", "tool_calls": [call]}) + chunk({}, "tool_calls"))
            elif "SLOW" in txt:
                rec["slow"] = True
                self.wfile.write(chunk({"role": "assistant", "content": ""}))
                for i in range(SLOW_CHUNKS):
                    self.wfile.write(chunk({"content": f"s{i} "}))
                    self.wfile.flush()
                    time.sleep(SLOW_GAP)
                self.wfile.write(chunk({}, "stop"))
            else:
                self.wfile.write(chunk({"role": "assistant", "content": "ok"}) + chunk({}, "stop"))
            self.wfile.write(b"data: [DONE]\n\n")
            self.wfile.flush()
            rec["done"] = True
        except (BrokenPipeError, ConnectionResetError):
            rec["aborted"] = True
            mlog.write(f"{time.time() - T0:.1f} aborted by the client\n")


def seen(text):
    """The requests whose last message carries `text`."""
    with req_lock:
        return [r for r in requests if r["messages"] and text in text_of(r["messages"][-1])]


def anywhere(text):
    with req_lock:
        return [r for r in requests if any(text in text_of(m) for m in r["messages"])]


# --- xmsg: http.sock and a fake plugin connection ----------------------------------------


def xmsg_http(method, path, body=None):
    s = socket.socket(socket.AF_UNIX)
    s.connect(os.path.join(SOCKS, "http.sock"))
    data = json.dumps(body) if body is not None else ""
    s.sendall((f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
               f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n{data}").encode())
    out = b""
    while c := s.recv(65536):
        out += c
    head, _, rest = out.decode().partition("\r\n\r\n")
    if "chunked" in head.lower():
        body_, rest2 = "", rest
        while rest2:
            n, _, rest2 = rest2.partition("\r\n")
            n = int(n, 16)
            if n == 0:
                break
            body_ += rest2[:n]
            rest2 = rest2[n + 2:]
        rest = body_
    return int(head.split()[1]), json.loads(rest) if rest else None


def recipients():
    status, body = xmsg_http("GET", "/v1/recipients")
    if status != 200:
        fail(f"GET /v1/recipients: {status} {body}")
    return body["recipients"]


def hermes_entries():
    return [e for e in recipients() if e.get("label") != "receiver" and e.get("kind") == "instance"
            and e.get("harness", "hermes") == "hermes"]


def entry(label):
    return next((e for e in recipients() if e.get("label") == label), None)


class Receiver:
    """A plugin connection holding one session: the receiver of every send."""

    def __init__(self):
        self.s = socket.socket(socket.AF_UNIX)
        self.s.connect(os.path.join(SOCKS, "register.sock"))
        self.f = self.s.makefile("rw")
        self.n = 0
        self.put({"harness": "opencode"})
        hello = json.loads(self.f.readline())
        if hello.get("status") != "ok":
            fail(f"receiver connection refused: {hello}")
        self.address = self.call({"action": "register", "session": "receiver"})["address"]

    def put(self, frame):
        self.f.write(json.dumps(frame) + "\n")
        self.f.flush()

    def call(self, frame, check=True):
        self.n += 1
        frame["request_id"] = f"r{self.n}"
        self.put(frame)
        a = json.loads(self.f.readline())
        if a.get("request_id") != frame["request_id"] or (check and a.get("status") == "error"):
            fail(f"receiver frame {frame}: {a}")
        return a

    def send(self, to, text):
        return self.call({"action": "send", "session": "receiver", "to": to, "text": text}, check=False)

    def deliveries(self, count, secs=60):
        got = []
        end = time.time() + secs
        while len(got) < count and time.time() < end:
            a = self.call({"action": "poll", "wait": 2})
            if a.get("action") == "deliver":
                self.call({"action": "ack", "session": "receiver", "message_id": a["message_id"]})
                got.append(a)
        if len(got) < count:
            fail(f"the receiver got {len(got)} of {count} messages: {got}")
        return got


def acked(message_id):
    """Whether a plugin session's queued message was acked: the queue row's `delivered_at`
    (src/storage.rs). The send's `outcome` is `queued` until the ack and `delivered` after it."""
    import sqlite3
    db = sqlite3.connect(f"file:{os.path.join(TMP, 'xmsg.db')}?mode=ro", uri=True)
    try:
        row = db.execute("SELECT delivered_at FROM pi_pending_messages WHERE id = ?", (message_id,)).fetchone()
    finally:
        db.close()
    if row is None:
        fail(f"message {message_id} is not in xmsg's plugin queue")
    return row[0] is not None


# --- hermes on a pty ---------------------------------------------------------------------

hermes_pid = None
hermes_fd = None
scr = bytearray()
scr_lock = threading.Lock()


def screen():
    with scr_lock:
        return scr.decode(errors="replace")


def pump():
    while True:
        try:
            r, _, _ = select.select([hermes_fd], [], [], 0.5)
            if r:
                data = os.read(hermes_fd, 65536)
                if not data:
                    return
                with scr_lock:
                    scr.extend(data)
        except OSError:
            return


def type_line(text):
    os.write(hermes_fd, text.encode())
    time.sleep(0.4)  # past the CLI's rapid-input window, so Enter submits
    os.write(hermes_fd, b"\r")


def turn(text, secs=60):
    """Submit `text` and wait until the model has answered it and the CLI is idle again."""
    n = len(requests)
    type_line(text)
    wait_until(lambda: any(r["done"] and not r.get("slow") for r in requests[n:]
                           if r["messages"] and any(text in text_of(m) for m in r["messages"])), secs,
               f"the model's answer to {text!r}")
    time.sleep(2)


# --- run ---------------------------------------------------------------------------------

os.makedirs(os.path.join(HH, "plugins"), exist_ok=True)
os.makedirs(RUN, mode=0o700, exist_ok=True)
os.chmod(RUN, 0o700)
work = os.path.join(TMP, "work")
os.makedirs(work, exist_ok=True)
# As the hermes module's activation installs extraPlugins (nix/moduleCommon.nix).
os.symlink(PLUGIN, os.path.join(HH, "plugins", "nix-managed-xmsg"))

mock_port = free_port()
mock = http.server.ThreadingHTTPServer(("127.0.0.1", mock_port), Mock)
threading.Thread(target=mock.serve_forever, daemon=True).start()

settings = json.load(open(SETTINGS))
settings.update({
    "model": {"provider": "custom", "base_url": f"http://127.0.0.1:{mock_port}/v1", "default": "m",
              "context_length": 200000, "max_tokens": 1000},
    "telemetry": {"shared_metrics": {"enabled": False, "send": False, "offer_version": 2}},
    # Oracle 3 needs a compression that continues the conversation under a new session id. That is
    # hermes's legacy rotating compaction; its default compacts in place and keeps the id.
    "compression": {"in_place": False},
})
with open(os.path.join(HH, "config.yaml"), "w") as f:
    json.dump(settings, f)  # JSON is YAML

env = dict(os.environ, HOME=HOME, HERMES_HOME=HH, XDG_RUNTIME_DIR=RUN, TERM="xterm-256color",
           COLUMNS="160", LINES="50")
procs.append(subprocess.Popen([XMSG, "serve", "--db-path", os.path.join(TMP, "xmsg.db")], env=env,
                              stdout=open(os.path.join(TMP, "serve.log"), "a"), stderr=subprocess.STDOUT))
wait_until(lambda: os.path.exists(os.path.join(SOCKS, "http.sock"))
           and os.path.exists(os.path.join(SOCKS, "register.sock")), 30, "xmsg serve")
recv = Receiver()


def start_hermes():
    global hermes_pid, hermes_fd
    hermes_pid, hermes_fd = pty.fork()
    if hermes_pid == 0:
        os.chdir(work)
        os.execvpe(HERMES, [HERMES], env)
    threading.Thread(target=pump, daemon=True).start()
    wait_until(lambda: "❯" in screen(), 120, "the hermes prompt")
    time.sleep(3)


start_hermes()
ok("hermes CLI is up")

# 1. The plugin loads and registers: the session is listed under its own id (its native label).
turn("hello")
(e1,) = wait_until(lambda: hermes_entries() or None, 20, "a hermes session listed")
s1 = e1["label"]
if not e1["address"].endswith("@" + e1["node"]):
    fail(f"1: {s1}'s entry: {e1}")
turn(f"CALL xmsg_send {json.dumps({'to': recv.address, 'text': 'from s1'})}")
(d,) = recv.deliveries(1)
if d["from_name"] != f"{s1} · {e1['address']}":
    fail(f"1: the send is attributed to {d['from_name']!r}, not {s1} · {e1['address']}")
ok(f"1: {s1} is listed as {e1['address']} and its send is attributed to it")

# 4. A delegate does not take its parent's address, and its calls go out as the root.
goal = f"CALL xmsg_send {json.dumps({'to': recv.address, 'text': 'from the delegate'})}"
turn(f"CALL delegate_task {json.dumps({'tasks': [{'goal': goal}]})}", secs=120)
(d,) = recv.deliveries(1)
if d["from_name"] != f"{s1} · {e1['address']}":
    fail(f"4: the delegate's send is attributed to {d['from_name']!r}, not its root {s1} · {e1['address']}")
now = hermes_entries()
if [(e["label"], e["address"]) for e in now] != [(s1, e1["address"])]:
    fail(f"4: after the delegate ran, the hermes entries are {now}, not only {s1} at {e1['address']}")
ok(f"4: the delegate's send is attributed to {s1}, which keeps {e1['address']}")


# 5. Busy behaviour (F1 arm A: hermes's own routing of Enter while a turn runs).
def busy(mode, start, cue):
    type_line(f"/busy {mode}")
    time.sleep(1.5)
    n = len(requests)
    text = f"push-{mode}-{uuid.uuid4().hex[:8]}"
    type_line(start)
    wait_until(lambda: cue(requests[n:]), 30, f"the {mode} turn to be running")
    time.sleep(1)
    sent = recv.send(e1["address"], text)
    if sent.get("status") == "error":
        fail(f"5 {mode}: send to {e1['address']}: {sent}")
    wait_until(lambda: seen(text) or anywhere(text), 60, f"the {mode} message to reach the model")
    wait_until(lambda: all(r["done"] or r["aborted"] for r in requests[n:]), 60, f"the {mode} turn to settle")
    time.sleep(2)
    wait_until(lambda: acked(sent["message_id"]), 20, f"the {mode} message acked")
    return text, requests[n:]


def slow(rs):
    return next((r for r in rs if r.get("slow")), None)


text, rs = busy("queue", "SLOW queue", lambda rs: slow(rs) is not None)
r = anywhere(text)[0]
prev = r["messages"][-2]
if slow(rs)["aborted"] or prev.get("role") != "assistant" or f"s{SLOW_CHUNKS - 1}" not in text_of(prev):
    fail(f"5 queue: the running turn was cut off (aborted={slow(rs)['aborted']}); before the message: {prev}")
ok("5 queue: the message ran as the next turn, after the running turn finished")

text, rs = busy("interrupt", "SLOW interrupt", lambda rs: slow(rs) is not None)
r = anywhere(text)[0]
if not slow(rs)["aborted"] or text not in text_of(r["messages"][-1]):
    fail(f"5 interrupt: the running turn was not redirected (aborted={slow(rs)['aborted']})")
ok("5 interrupt: the running model request was cut off and the message redirected the turn")

sleep_call = f"CALL terminal {json.dumps({'command': 'sleep 6'})}"
text, rs = busy("steer", sleep_call, lambda rs: any(r["done"] and sleep_call in text_of(r["messages"][-1]) for r in rs))
r = anywhere(text)[0]
i = next(i for i, m in enumerate(r["messages"]) if text in text_of(m))
if r["messages"][i - 1].get("role") != "tool":
    fail(f"5 steer: the message did not follow the running turn's tool result: {r['messages'][i - 1]}")
ok("5 steer: the message was steered into the running turn, after its tool result")

# 3. A compression keeps the address (C4, A19).
n = len(requests)
type_line("/compress")
wait_until(lambda: any(r["done"] for r in requests[n:]), 60, "the compression's summary request")
time.sleep(3)
text = f"after-compression-{uuid.uuid4().hex[:8]}"
sent = recv.send(e1["address"], text)
if sent.get("status") == "error":
    fail(f"3: after the compression, a send to {e1['address']} answers {sent}")
wait_until(lambda: seen(text), 60, "the message to the pre-compression address in the continued session")
(e2,) = hermes_entries()
s2 = e2["label"]
if s2 == s1 or e2["address"] != e1["address"]:
    fail(f"3: after the compression the hermes entry is {e2}, not a continuation of {s1} at {e1['address']}")
ok(f"3: {s1} continued as {s2}, which keeps {e1['address']} and receives its messages")

# 2 (HA8): /new detaches the old session (since it stays resumable in state.db via /resume);
# a send to it is queued for the parked address and injects nothing into the new session.
type_line("/new now")
time.sleep(3)
text = f"after-new-{uuid.uuid4().hex[:8]}"
sent = recv.send(e1["address"], text)
if sent.get("outcome") != "queued":
    fail(f"2: after /new, a send to detached {e1['address']} answers {sent}, not queued")
time.sleep(5)
if anywhere(text):
    fail(f"2: the message to the old address reached the model in the new session")
turn("hello again")
(e3,) = wait_until(lambda: hermes_entries() or None, 20, "the new session listed")
if e3["address"] == e1["address"] or e3["label"] in (s1, s2):
    fail(f"2: the new session's entry is {e3}")
if anywhere(text):
    fail(f"2: the message to the old address reached the model in the new session")
ok(f"2 (HA8): after /new {e1['address']} is parked/queued and {e3['label']} has {e3['address']}")

# 2, /resume (no plugin hook, HA8): the CLI moves back to `s2` (which continued from `s1` via
# `continues`, moving the stored reclaim key from `s1` to `s2`). A message to `e3` (the session
# it left) triggers `observe(s2)` on delivery, which detaches `e3` (leaving that message queued
# for `e3` and never injected into `s2`) and reclaims `s2` at `e1['address']`, delivering the
# message `text` that was queued for `e1['address']` while `s2` was detached!
type_line(f"/resume {s2}")
time.sleep(4)
text_e3 = f"after-resume-{uuid.uuid4().hex[:8]}"
sent = recv.send(e3["address"], text_e3)
wait_until(lambda: seen(text), 60, f"the queued message {text} delivered to reclaimed {s2} at {e1['address']}")
time.sleep(5)
if anywhere(text_e3):
    fail(f"2 resume: after /resume {s2}, the message to {e3['label']}'s address reached the model")
(e2_reclaimed,) = hermes_entries()
if e2_reclaimed["label"] != s2 or e2_reclaimed["address"] != e1["address"]:
    fail(f"2 resume: after /resume {s2}, hermes entry is {e2_reclaimed}, expected {s2} at {e1['address']}")
again = recv.send(e3["address"], "again")
if again.get("outcome") != "queued":
    fail(f"2 resume: after /resume {s2}, a send to detached {e3['address']} answers {again}, not queued")
ok(f"2 resume (HA8): /resume {s2} reclaims {e1['address']} (after continues {s1}->{s2}) and receives its queued message; {e3['address']} is detached/queued")

# 2, a background delegate: it keeps running after /new, and its call acts as the ended
# session: it answers gone, and the new session keeps its address.
goal = f"CALL terminal {json.dumps({'command': 'sleep 12'})} THEN xmsg_list {{}}"
n = len(requests)
type_line(f"CALL delegate_task {json.dumps({'tasks': [{'goal': goal}]})}")
wait_until(lambda: any(r["messages"] and goal in text_of(r["messages"][-1]) for r in requests[n:]), 60,
           "the delegate's first request")
time.sleep(1)
type_line("/new now")
time.sleep(3)
turn("hello four")
(e4,) = wait_until(lambda: [e for e in hermes_entries() if e["label"] != s2] or None, 20,
                   "the session after the second /new listed")
r = wait_until(lambda: next((r for r in requests[n:] if any(goal in text_of(m) for m in r["messages"])
                             and sum(m.get("role") == "tool" for m in r["messages"]) >= 2), None), 60,
               "the delegate's xmsg call")
result = text_of(r["messages"][-1])
now = [(e["label"], e["address"]) for e in hermes_entries()]
if '"gone"' not in result.replace('\\"', '"') or now != [(e4["label"], e4["address"])]:
    fail(f"2 delegate: after /new, {s2}'s delegate's xmsg_list answered {result[:300]!r}; "
         f"the hermes entries are {now}, not only {e4['label']} at {e4['address']}")
ok(f"2 delegate: {s2}'s delegate, running on after /new, is answered gone; {e4['label']} keeps {e4['address']}")

os.kill(hermes_pid, signal.SIGKILL)
hermes_pid = None


# --- the desktop host: hermes's tui_gateway (the backend of the Ink TUI and the desktop app) ---

def wrapper_var(name):
    """A path the hermes wrapper script exports (its python, its install root)."""
    for line in open(HERMES):
        if line.startswith(f"export {name}="):
            return line.split("=", 1)[1].strip().strip("'")
    fail(f"the hermes wrapper {HERMES} exports no {name}")


class Desktop:
    """One tui_gateway process on its own HERMES_HOME, driven over its stdio JSON-RPC."""

    def __init__(self, name, settings):
        home = os.path.join(TMP, name)
        hh = os.path.join(home, ".hermes")
        os.makedirs(os.path.join(hh, "plugins"))
        os.symlink(PLUGIN, os.path.join(hh, "plugins", "nix-managed-xmsg"))
        with open(os.path.join(hh, "config.yaml"), "w") as f:
            json.dump(settings, f)
        denv = dict(env, HOME=home, HERMES_HOME=hh, PYTHONPATH=wrapper_var("HERMES_INSTALL_ROOT"))
        self.p = subprocess.Popen([wrapper_var("HERMES_PYTHON"), "-m", "tui_gateway.entry"], stdin=subprocess.PIPE,
                                  stdout=subprocess.PIPE, stderr=open(os.path.join(TMP, f"{name}.log"), "w"),
                                  env=denv, cwd=work, text=True)
        procs.append(self.p)
        self.answers, self.n = {}, 0
        threading.Thread(target=self._read, daemon=True).start()

    def _read(self):
        for line in self.p.stdout:
            try:
                m = json.loads(line)
            except ValueError:
                continue
            if "id" in m and "method" not in m:
                self.answers[m["id"]] = m

    def rpc(self, method, params):
        self.n += 1
        i = self.n
        self.p.stdin.write(json.dumps({"jsonrpc": "2.0", "id": i, "method": method, "params": params}) + "\n")
        self.p.stdin.flush()
        a = wait_until(lambda: self.answers.get(i), 120, f"tui_gateway's answer to {method}")
        if "error" in a:
            fail(f"tui_gateway {method}: {a['error']}")
        return a["result"]

    def session(self):
        """A session with one finished turn: the plugin registers it at that turn's pre_llm_call."""
        r = self.rpc("session.create", {})
        key = r["stored_session_id"]
        self.rpc("prompt.submit", {"session_id": r["session_id"], "text": f"hello from {key}"})
        e = wait_until(lambda: entry(key), 60, f"the desktop session {key} listed")
        wait_until(lambda: any(x["done"] for x in seen(f"hello from {key}")), 60, "the desktop turn")
        time.sleep(2)
        return key, e, r["session_id"]

    def close(self):
        self.p.kill()


desktop_settings = json.load(open(SETTINGS))
desktop_settings.update({k: settings[k] for k in ("model", "telemetry")})

# The control: with the switch's settings, a push reaches the desktop session and is acked.
d = Desktop("desktop-allowed", desktop_settings)
key, e, sid = d.session()
text = f"desktop-{uuid.uuid4().hex[:8]}"
sent = recv.send(e["address"], text)
wait_until(lambda: seen(text), 60, "the pushed message in the desktop session")
wait_until(lambda: acked(sent["message_id"]), 20, "the desktop message acked")
ok(f"desktop: with allow_gateway_injection a push to {key} runs in it and is acked")

# 2, desktop close (HA8): a closed session in tui_gateway stays resumable in state.db, so
# on_session_finalize detaches it (parked & queued), and nothing of it blocks another session
# of the same process; resuming it reclaims the same address and delivers the queued message.
key2, e2, _ = d.session()
d.rpc("session.close", {"session_id": sid})
time.sleep(3)
closed_text = f"to-closed-{uuid.uuid4().hex[:8]}"
sent_closed = recv.send(e["address"], closed_text)
if sent_closed.get("outcome") != "queued" or entry(key):
    fail(f"2 close: after session.close of {key}, a send to {e['address']} answers {sent_closed}; listed: {entry(key)}")
text = f"desktop-live-{uuid.uuid4().hex[:8]}"
sent = recv.send(e2["address"], text)
wait_until(lambda: seen(text), 60, f"the message to the live desktop session {key2}")
wait_until(lambda: acked(sent["message_id"]), 20, f"the message to {key2} acked")
d.close()
ok(f"2 close (HA8): closed {key} is detached/queued, and {key2} in the same process still receives")

# 6. A refused injection stays pending: without allow_gateway_injection, inject_message returns
# False on this host (plugins_injection.py), so the message is neither acked nor injected.
refused = json.loads(json.dumps(desktop_settings))
del refused["plugins"]["entries"]["xmsg"]["allow_gateway_injection"]
d = Desktop("desktop-refused", refused)
key, e, _ = d.session()
text = f"refused-{uuid.uuid4().hex[:8]}"
sent = recv.send(e["address"], text)
time.sleep(6)  # several poll rounds
if acked(sent["message_id"]) or anywhere(text):
    fail(f"6: the refused message was acked ({acked(sent['message_id'])}) or reached the model ({bool(anywhere(text))})")
ok(f"6: refused by hermes, the message to {key} is still pending, not acked and not injected")
d.close()

for p in procs:
    p.kill()
print("hermes-plugin: all oracles passed")
