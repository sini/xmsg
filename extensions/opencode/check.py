#!/usr/bin/env python3
"""XH2 oracles 8-11, release and restart: the real opencode, with the plugin file the
home-manager switch renders in its plugin/ directory, against a real `xmsg serve`. The model
is a mock OpenAI-compatible server on loopback: a user message `CALL <tool> <json>` makes it
call that tool once, and anything else gets the answer `ok`. A fake plugin connection on
register.sock is the receiver whose deliveries show each send's attribution. It drives either
opencode 1.x or 2.x, by the major version `opencode --version` reports: the plugin serves both.

usage: check.py <xmsg> <opencode> <plugin.ts>
Exits non-zero naming the first oracle that fails."""
import base64, http.server, json, os, re, socket, subprocess, sys, threading, time, urllib.request, uuid

XMSG, OPENCODE, PLUGIN = sys.argv[1:4]
TMP = os.environ.get("TMPDIR", "/tmp")
RUN = os.path.join(TMP, "run")
SOCKS = os.path.join(RUN, "xmsg")
procs = []
T0 = time.time()


def fail(msg):
    print(f"opencode-plugin: FAIL {msg}", file=sys.stderr)
    for name in ("serve.log", "opencode.log"):
        p = os.path.join(TMP, name)
        if os.path.exists(p):
            print(f"--- {name} ---\n" + open(p).read()[-6000:], file=sys.stderr)
    for p in procs:
        p.kill()
    sys.exit(1)


def ok(msg):
    print(f"opencode-plugin: ok {msg} ({time.time() - T0:.0f}s)")


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


def chunk(delta, finish=None):
    return "data: " + json.dumps({"id": "m", "object": "chat.completion.chunk", "created": 0, "model": "m",
                                  "choices": [{"index": 0, "delta": delta, "finish_reason": finish}]}) + "\n\n"


def text_of(m):
    c = m.get("content")
    if isinstance(c, list):
        return "".join(p.get("text", "") for p in c if isinstance(p, dict))
    return c or ""


class Mock(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        b = json.dumps({"object": "list", "data": [{"id": "m", "object": "model"}]}).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(b)))
        self.end_headers()
        self.wfile.write(b)

    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["content-length"])))
        msgs = body.get("messages", [])
        last = msgs[-1] if msgs else {}
        txt = text_of(last).strip() if last.get("role") == "user" else ""
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        if txt.startswith("CALL ") and body.get("tools") is not None:
            _, tool, args = txt.split(" ", 2)
            out = chunk({"role": "assistant", "tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                                                              "function": {"name": tool, "arguments": args}}]})
            out += chunk({}, "tool_calls")
        else:
            out = chunk({"role": "assistant", "content": "ok"}) + chunk({}, "stop")
        self.wfile.write((out + "data: [DONE]\n\n").encode())
        self.wfile.flush()


# --- xmsg: http.sock and a fake plugin connection ----------------------------------------


def xmsg_http(method, path, body=None):
    s = socket.socket(socket.AF_UNIX)
    s.connect(os.path.join(SOCKS, "http.sock"))
    data = json.dumps(body) if body is not None else ""
    s.sendall((f"{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\n"
               f"Content-Length: {len(data)}\r\nConnection: close\r\n\r\n{data}").encode())
    out = b""
    while chunk_ := s.recv(65536):
        out += chunk_
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

    def call(self, frame):
        self.n += 1
        frame["request_id"] = f"r{self.n}"
        self.put(frame)
        a = json.loads(self.f.readline())
        if a.get("request_id") != frame["request_id"] or a.get("status") == "error":
            fail(f"receiver frame {frame}: {a}")
        return a

    def deliveries(self, count, secs=30):
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


# --- opencode --------------------------------------------------------------------------


# 2.x serves its API under /api behind basic auth with the server password, and a prompt is
# queued: the turn is awaited separately.
VERSION = subprocess.run([OPENCODE, "--version"], capture_output=True, text=True, env=dict(os.environ, HOME=TMP)).stdout
MAJOR = re.search(r"\bv?(\d+)\.", VERSION)
if MAJOR is None:
    sys.exit(f"opencode-plugin: cannot read a version from `opencode --version`: {VERSION!r}")
V2 = int(MAJOR.group(1)) >= 2
API = "/api" if V2 else ""
PASSWORD = uuid.uuid4().hex
AUTH = {"authorization": "Basic " + base64.b64encode(f"opencode:{PASSWORD}".encode()).decode()} if V2 else {}


def oc(method, path, body=None, timeout=60):
    req = urllib.request.Request(f"{OC}{API}{path}", method=method,
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"content-type": "application/json", **AUTH})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        raw = r.read()
        out = json.loads(raw) if raw else None
        return out["data"] if V2 and isinstance(out, dict) and "data" in out else out


def new_session(parent=None):
    return oc("POST", "/session", {"parentID": parent} if parent else {})["id"]


def say(session, text):
    if not V2:
        return oc("POST", f"/session/{session}/message", {"parts": [{"type": "text", "text": text}]}, timeout=120)
    oc("POST", f"/session/{session}/prompt", {"text": text})
    oc("POST", f"/experimental/session/{session}/wait", timeout=120)


def call_tool(session, tool, args):
    say(session, f"CALL {tool} {json.dumps(args)}")


def entry(label):
    return next((e for e in recipients() if e.get("label") == label), None)


def user_texts(session):
    if V2:
        return [m["text"] for m in oc("GET", f"/session/{session}/message") if m["type"] == "user"]
    out = []
    for m in oc("GET", f"/session/{session}/message"):
        if m["info"]["role"] == "user":
            out.append("".join(p.get("text", "") for p in m["parts"] if p.get("type") == "text"))
    return out


# --- run ---------------------------------------------------------------------------------

home = os.path.join(TMP, "home")
os.makedirs(os.path.join(home, ".config", "opencode", "plugin"), exist_ok=True)
os.makedirs(RUN, mode=0o700, exist_ok=True)
os.chmod(RUN, 0o700)
work = os.path.join(TMP, "work")
os.makedirs(work, exist_ok=True)
with open(PLUGIN) as src, open(os.path.join(home, ".config", "opencode", "plugin", "xmsg.ts"), "w") as dst:
    dst.write(src.read())

env = dict(os.environ, HOME=home, XDG_RUNTIME_DIR=RUN, XDG_CONFIG_HOME=os.path.join(home, ".config"),
           XDG_DATA_HOME=os.path.join(TMP, "data"), XDG_CACHE_HOME=os.path.join(TMP, "cache"),
           XDG_STATE_HOME=os.path.join(TMP, "state"), OPENCODE_DISABLE_AUTOUPDATE="1",
           OPENCODE_DISABLE_MODELS_FETCH="1")

def serve():
    p = subprocess.Popen([XMSG, "serve", "--db-path", os.path.join(TMP, "xmsg.db")], env=env,
                         stdout=open(os.path.join(TMP, "serve.log"), "a"), stderr=subprocess.STDOUT)
    procs.append(p)
    wait_until(lambda: os.path.exists(os.path.join(SOCKS, "http.sock"))
               and os.path.exists(os.path.join(SOCKS, "register.sock")), 20, "xmsg serve")
    return p


server = serve()

mock_port = free_port()
mock = http.server.ThreadingHTTPServer(("127.0.0.1", mock_port), Mock)
threading.Thread(target=mock.serve_forever, daemon=True).start()

port = free_port()
OC = f"http://127.0.0.1:{port}"
env["OPENCODE_CONFIG_CONTENT"] = json.dumps({
    "update": "disable", "share": "disabled", "model": "mock/m",
    "providers": {"mock": {"package": "@opencode/ai/providers/openai-compatible", "name": "mock",
                           "settings": {"baseURL": f"http://127.0.0.1:{mock_port}/v1"},
                           "models": {"m": {"name": "m", "capabilities": {"tools": True}}}}},
} if V2 else {
    "autoupdate": False, "share": "disabled", "model": "mock/m", "small_model": "mock/m",
    "provider": {"mock": {"npm": "@ai-sdk/openai-compatible", "name": "mock",
                          "options": {"baseURL": f"http://127.0.0.1:{mock_port}/v1"}, "models": {"m": {"name": "m"}}}},
})
if V2:
    env["OPENCODE_SERVER_PASSWORD"] = PASSWORD
procs.append(subprocess.Popen([OPENCODE, "serve", "--port", str(port), "--hostname", "127.0.0.1"], cwd=work, env=env,
                              stdout=open(os.path.join(TMP, "opencode.log"), "w"), stderr=subprocess.STDOUT))


def oc_up():
    try:
        oc("GET", "/session", timeout=120)
        return True
    except Exception as e:
        print(f"opencode-plugin: waiting for opencode: {e!r}")
        time.sleep(1)
        return False


wait_until(oc_up, 180, "opencode serve")
ok("opencode serve answers")
recv = Receiver()

# 8. The real plugin loads and registers.
s1 = new_session()
say(s1, "hello")
e1 = wait_until(lambda: entry(s1), 20, f"{s1} listed")
if e1["kind"] != "instance" or not e1["address"].endswith("@" + e1["node"]):
    fail(f"8: {s1}'s entry: {e1}")
ok(f"8: {s1} is listed as {e1['address']} with its label")

# 9. Attribution through the real plugin: two sessions of one process.
s2 = new_session()
say(s2, "hello")
e2 = wait_until(lambda: entry(s2), 20, f"{s2} listed")
if e2["address"] == e1["address"]:
    fail(f"9: two sessions share one address: {e1} {e2}")
call_tool(s1, "xmsg_send", {"to": recv.address, "text": "from s1"})
call_tool(s2, "xmsg_send", {"to": recv.address, "text": "from s2"})
by_text = {d["text"]: d["from_name"] for d in recv.deliveries(2)}
for text, e, s in (("from s1", e1, s1), ("from s2", e2, s2)):
    if by_text.get(text) != f"{s} · {e['address']}":
        fail(f"9: '{text}' is attributed to {by_text.get(text)!r}, not {s} · {e['address']}")
ok("9: each session's send is attributed to its own address")

# 10. A child session acts as its root.
child = new_session(parent=s1)
call_tool(child, "xmsg_send", {"to": recv.address, "text": "from the child"})
(d,) = recv.deliveries(1)
if d["from_name"] != f"{s1} · {e1['address']}":
    fail(f"10: the child's send is attributed to {d['from_name']!r}, not its root {s1}")
if entry(child):
    fail(f"10: the child {child} is registered")
ok(f"10: the child's send is attributed to its root {s1}")

# 11. Push: a message to an idle session appears in it through promptAsync, acked once.
s3 = new_session()
say(s3, "hello")
e3 = wait_until(lambda: entry(s3), 20, f"{s3} listed")
body = f"push {uuid.uuid4().hex}"
sent = recv.call({"action": "send", "session": "receiver", "to": e3["address"], "text": body})
wait_until(lambda: any(body in t for t in user_texts(s3)), 30, f"the pushed message in {s3}")
time.sleep(4)  # several poll rounds: an unacked message would be offered and prompted again
seen = sum(body in t for t in user_texts(s3))
if seen != 1:
    fail(f"11: the pushed message appears {seen} times in {s3}")
ok(f"11: message {sent['message_id']} appears once in {s3}")

# Deleting a session releases its address.
oc("DELETE", f"/session/{s2}")
status, _ = wait_until(lambda: (lambda r: r if r[0] == 410 else None)(
    xmsg_http("POST", "/v1/messages", {"to": e2["address"], "from": "ci", "text": "x"})), 20, f"{s2}'s address gone")
ok(f"deleting {s2} releases {e2['address']} (gone)")

# HA8: a restarted server detaches the old connection; the plugin reconnects and reclaims
# its roots' exact addresses using the stored reclaim secrets, and receives messages queued
# while disconnected.
server.kill()
server.wait()
for name in ("http.sock", "register.sock", "agent.sock"):
    try:
        os.remove(os.path.join(SOCKS, name))
    except FileNotFoundError:
        pass
server = serve()
e1b = wait_until(lambda: (lambda e: e if e and e["address"] == e1["address"] else None)(entry(s1)), 30,
                 f"{s1} reclaimed {e1['address']} after the restart")
body_reclaimed = f"reclaimed {uuid.uuid4().hex}"
status, body = xmsg_http("POST", "/v1/messages", {"to": e1["address"], "from": "ci", "text": body_reclaimed})
if status != 202:
    fail(f"restart: {s1}'s reclaimed address {e1['address']} answers {status} {body}, not 202")
wait_until(lambda: any(body_reclaimed in t for t in user_texts(s1)), 30, f"the message to reclaimed {s1}")
ok(f"restart (HA8): {s1} reclaims {e1b['address']} and receives messages")

for p in procs:
    p.kill()
print("opencode-plugin: all oracles passed")
