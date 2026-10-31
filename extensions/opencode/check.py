#!/usr/bin/env python3
"""XH2 oracles 8-11, release and restart: the real opencode, with the plugin file the
home-manager switch renders in its plugin/ directory, against a real `xmsg serve`. The model
is a mock OpenAI-compatible server on loopback: a user message `CALL <tool> <json>` makes it
call that tool once, and anything else gets the answer `ok`. A fake plugin connection on
register.sock is the receiver whose deliveries show each send's attribution. It drives either
opencode 1.x or 2.x, by the major version `opencode --version` reports: the plugin serves both.

usage: check.py <xmsg> <opencode> <plugin.ts>
Exits non-zero naming the first oracle that fails."""
import base64, http.server, json, os, re, socket, sqlite3, subprocess, sys, threading, time, urllib.request, uuid

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


tool_results = []
inbox_call_started = threading.Event()


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
        if last.get("role") == "tool":
            tool_results.append(text_of(last).strip())
        txt = text_of(last).strip() if last.get("role") == "user" else ""
        lines = [l.strip() for l in txt.splitlines() if l.strip()]
        cmd = lines[-1] if lines else ""
        self.send_response(200)
        self.send_header("content-type", "text/event-stream")
        self.end_headers()
        if cmd.startswith("CALL ") and body.get("tools") is not None:
            _, tool, args = cmd.split(" ", 2)
            if tool == "xmsg_inbox":
                inbox_call_started.set()
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
    return next((e for e in recipients() if e.get("label") == label and e.get("kind") == "instance"), None)


def sub_entry(addr_prefix):
    return next((e for e in recipients() if e.get("kind") == "subagent" and e.get("address", "").startswith(addr_prefix + "@")), None)


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

# XH1-D4: Direct unit check on xmsg.ts (`setup` 2.x with undefined `ctx.session.get` response,
# and `run` with empty `sessionID` refused before `session.get` or socket send).
plugin_ts_copy = os.path.join(home, ".config", "opencode", "plugin", "xmsg.ts")
d4_node_script = """
import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";

const mod = await import(pathToFileURL(process.env.PLUGIN_TS).href);
const plugin = mod.default;
const tools = {};
let getCalledWithEmpty = false;
const ctx = {
  session: {
    get: async ({ sessionID }) => {
      if (!sessionID) getCalledWithEmpty = true;
      return undefined;
    },
    prompt: async () => {},
    hook: async () => ({ dispose: async () => {} }),
  },
  tool: {
    transform: async (cb) => {
      cb({
        add: (def) => {
          tools[def.name] = def;
        },
      });
      return { dispose: async () => {} };
    },
  },
  event: {
    subscribe: async function* ({ signal }) {
      await new Promise((resolve) => signal.addEventListener("abort", resolve, { once: true }));
    },
  },
};

const cleanup = await plugin.setup(ctx);
try {
  // 1. Empty sessionID is refused with 'xmsg: tool call has no sessionID' without calling session.get
  await assert.rejects(
    () => tools.xmsg_list.execute({}, { sessionID: "" }),
    /xmsg: tool call has no sessionID/,
    "XH1-D4: empty sessionID must throw 'xmsg: tool call has no sessionID'"
  );
  assert.equal(getCalledWithEmpty, false, "XH1-D4: session.get must not be called when sessionID is empty");

  // 2. When ctx.session.get({ sessionID }) returns undefined on 2.x, parentOf uses ?.parentID
  // and does not throw TypeError: Cannot read properties of undefined (reading 'parentID')
  const res = await tools.xmsg_list.execute({}, { sessionID: "ses_ephemeral_2x" });
  const parsed = JSON.parse(res.content);
  assert.equal(parsed.status, "ok", `XH1-D4: expected status ok from xmsg_list, got: ${res.content}`);
} finally {
  await cleanup();
}
"""
d4_res = subprocess.run(
    ["node", "--experimental-transform-types", "--input-type=module", "-e", d4_node_script],
    env=dict(env, PLUGIN_TS=plugin_ts_copy),
    capture_output=True,
    text=True,
)
if d4_res.returncode != 0:
    fail(f"XH1-D4 node unit check failed (rc={d4_res.returncode}):\nstdout: {d4_res.stdout}\nstderr: {d4_res.stderr}")
ok("XH1-D4: 2.x parentOf handles undefined session.get and run() rejects empty sessionID")

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

# 10 (HA9-A.oc C3, C1, C4, C5, C8): Delegated sub-addresses for child sessions.
p_bare = e1["address"].split("@")[0]
child = new_session(parent=s1)
child_sub_prefix = f"{p_bare}/{child}"
child_sub_addr = f"{child_sub_prefix}@{e1['node']}"

# C3: After a child turn that makes no xmsg tool call (the mock answers "ok"), `list` shows
# `kind:"subagent"`, `address` `<P>/<child>@<node>`, `harness:"opencode"`, with the parent's
# status. No `kind:"instance"` entry is labelled with the child.
say(child, "hello child")
ec = wait_until(lambda: sub_entry(child_sub_prefix), 20, f"subagent {child_sub_prefix} listed")
if (ec.get("kind") != "subagent" or ec.get("address") != child_sub_addr
        or ec.get("harness") != "opencode" or ec.get("status") != e1.get("status")):
    fail(f"C3: subagent entry mismatch: {ec} vs expected {child_sub_addr}")
if any(e.get("kind") == "instance" and e.get("label") == child for e in recipients()):
    fail(f"C3: child {child} registered as kind=instance: {recipients()}")
ok(f"C3: child {child} bound at prompt as subagent {child_sub_addr} before any xmsg tool call")

# C1: A `POST /session {parentID: s1}` child calls `xmsg_send`. The receiver's `from_name`
# ends `<P>/<child_ses>@<node>`, where P is s1's address. s1's own send in the same run is
# `s1 · <P>@<node>`.
call_tool(child, "xmsg_send", {"to": recv.address, "text": "from the child"})
(d,) = recv.deliveries(1)
if not d["from_name"].endswith(child_sub_addr):
    fail(f"C1: the child's send is attributed to {d['from_name']!r}, expected suffix {child_sub_addr!r}")
if any(e.get("kind") == "instance" and e.get("label") == child for e in recipients()):
    fail(f"C1: the child {child} is registered as an instance")
reclaim_path = os.path.join(TMP, "state", "opencode", "xmsg-reclaim.json")
reclaim_store = json.loads(open(reclaim_path).read()) if os.path.exists(reclaim_path) else {}
if child in reclaim_store or s1 not in reclaim_store:
    fail(f"C8: reclaim store has child key or lacks root key: {reclaim_store}")
ok(f"C1/C8: the child's send is attributed to {d['from_name']} and xmsg-reclaim.json holds no child key")

# C4: Delivery in a turn. The child's turn calls `xmsg_inbox {"wait":20}`. During the wait,
# `POST /v1/messages` to `<P>/<child>` returns `queued`. The inbox result holds that message
# and the child's own address. The message's outcome becomes `delivered`.
inbox_call_started.clear()
prev_results_len = len(tool_results)
inbox_thread = threading.Thread(target=lambda: call_tool(child, "xmsg_inbox", {"wait": 20}))
inbox_thread.start()
if not inbox_call_started.wait(20):
    fail("C4: timed out waiting for child xmsg_inbox tool call to start")
time.sleep(0.3)
body_c4 = f"in-turn {uuid.uuid4().hex}"
st_c4, sent_c4 = xmsg_http("POST", "/v1/messages", {"to": child_sub_prefix, "from": "ci", "text": body_c4})
if st_c4 != 202 or sent_c4.get("outcome") != "queued":
    fail(f"C4: POST /v1/messages to {child_sub_prefix} during turn returned {st_c4} {sent_c4}")
inbox_thread.join(timeout=30)
if inbox_thread.is_alive():
    fail("C4: child xmsg_inbox turn did not finish")
wait_until(lambda: len(tool_results) > prev_results_len, 10, "C4 tool result")
inbox_payload = json.loads(tool_results[-1])
if inbox_payload.get("address") != child_sub_addr:
    fail(f"C4: inbox address {inbox_payload.get('address')!r} != {child_sub_addr!r}")
if not any(body_c4 in m.get("body", "") for m in inbox_payload.get("messages", [])):
    fail(f"C4: inbox messages did not contain {body_c4!r}: {inbox_payload}")
db_conn = sqlite3.connect(os.path.join(TMP, "xmsg.db"))
row_c4 = db_conn.execute("SELECT outcome FROM messages WHERE id = ?", (sent_c4["message_id"],)).fetchone()
db_conn.close()
if not row_c4 or row_c4[0] != "delivered":
    fail(f"C4: message {sent_c4['message_id']} outcome in db is {row_c4}, expected 'delivered'")
ok(f"C4: in-turn message {sent_c4['message_id']} delivered via xmsg_inbox to {child_sub_addr}")

# C5: Turn end, then fallback. After the child's turn ends, a send to `<P>/<child>` appears
# as a user prompt in s1 containing `to=<P>/<child> agent_id=<child>`, within 30 s.
def child_turn_cleared():
    c = sqlite3.connect(os.path.join(TMP, "xmsg.db"))
    r = c.execute("SELECT turn_pid FROM subagents WHERE parent = ? AND agent_id = ?", (p_bare, child)).fetchone()
    c.close()
    return r is not None and r[0] is None

wait_until(child_turn_cleared, 10, f"C5: {child} turn_pid cleared after turn end")
body_c5 = f"fallback {uuid.uuid4().hex}"
st_c5, sent_c5 = xmsg_http("POST", "/v1/messages", {"to": child_sub_prefix, "from": "ci", "text": body_c5})
if st_c5 != 202:
    fail(f"C5: POST /v1/messages to {child_sub_prefix} after turn end returned {st_c5} {sent_c5}")
expected_hdr = f"to={child_sub_prefix} agent_id={child}"
wait_until(lambda: any(body_c5 in t and expected_hdr in t for t in user_texts(s1)), 30,
           f"C5: fallback message in root {s1} with header {expected_hdr!r}")
ok(f"C5: post-turn message {sent_c5['message_id']} fell back to {s1} with '{expected_hdr}'")

# OQ1 / E12: on 2.x, a child spawned via the built-in `subagent` tool (`agent: "general"`)
# carries `parentID`, fires the `prompt` hook, attributes its `xmsg_send` to
# `general · <P>/<spawned_ses>@<node>`, and clears its turn on `session.execution.succeeded`.
if V2:
    sub_text = f"from-2x-subagent-{uuid.uuid4().hex}"
    call_tool(s1, "subagent", {
        "agent": "general",
        "description": "oq1 spawned child",
        "prompt": f'CALL xmsg_send {json.dumps({"to": recv.address, "text": sub_text})}',
    })
    (d_sub,) = recv.deliveries(1)
    if not (d_sub["from_name"].startswith(f"general · {p_bare}/ses_") and d_sub["from_name"].endswith("@" + e1["node"])):
        fail(f"OQ1/E12: 2.x subagent-spawned send attributed to {d_sub['from_name']!r}")
    ok(f"OQ1/E12: 2.x subagent tool child attributed to {d_sub['from_name']}")

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

# C6: After `xmsg serve` restarts and s1 reclaims P, `list` still shows `<P>/<child>`,
# and a send to it falls back to s1.
wait_until(lambda: sub_entry(child_sub_prefix), 20, f"C6: {child_sub_prefix} listed after restart")
body_c6 = f"restart-sub {uuid.uuid4().hex}"
st_c6, sent_c6 = xmsg_http("POST", "/v1/messages", {"to": child_sub_prefix, "from": "ci", "text": body_c6})
if st_c6 != 202:
    fail(f"C6: POST /v1/messages to {child_sub_prefix} after restart returned {st_c6} {sent_c6}")
wait_until(lambda: any(body_c6 in t and expected_hdr in t for t in user_texts(s1)), 30,
           f"C6: fallback message to {child_sub_prefix} in {s1} after restart")
ok(f"C6: after restart, {child_sub_addr} stays listed and falls back to {s1}")

# C9: Delete ends the binding. `DELETE /session/<child>`, then a send to `<P>/<child>`
# returns 404 and `list` omits it.
oc("DELETE", f"/session/{child}")
wait_until(lambda: sub_entry(child_sub_prefix) is None, 20, f"C9: {child_sub_prefix} omitted from list after DELETE")
st_c9, body_c9 = xmsg_http("POST", "/v1/messages", {"to": child_sub_prefix, "from": "ci", "text": "after-delete"})
if st_c9 != 404:
    fail(f"C9: POST /v1/messages to deleted {child_sub_prefix} returned {st_c9} {body_c9}, expected 404")
ok(f"C9: deleting child {child} removes {child_sub_addr} from list and answers 404")

for p in procs:
    p.kill()
print("opencode-plugin: all oracles passed")
