"""xmsg for hermes (plan XH3; HA2, HA3, HA4, HA7; the XH3 design step in xmsg-harness-design.md).

One `register.sock` connection per hermes process, many sessions on it. A root session
registers at the first `pre_llm_call` or tool call carrying its unseen `session_id`, and gets
its own server-minted address. A delegate (a subagent, whose `pre_llm_call` names its
`parent_session_id`) acts as its root and is never registered (HA7).

A session that ends (`on_session_finalize`: a desktop session closed, the CLI's `/new` or exit)
has its address released (harness C3). In the classic CLI one session is live per process.
`/new` finalizes the old session, then fires `on_session_reset` with the new id; `/resume` and
`/branch` fire no plugin hook, so a changed `session_id` is seen at the next hook, tool call or
push (the CLI's `session_id`), and the old session's address is released then, unless hermes's
session store records the new session as a compression continuation of the old, when it moves
with `continues` (C4, A19). That store read is internal hermes API. A tool call acting as an
ended session (its background delegate, still running after `/new`) answers `gone` and
registers nothing.

A pushed message goes in through the CLI's own Enter dispatch while a turn runs
(`_tui_enter_while_busy`, so `busy_input_mode` routes it exactly as typed input: queue, steer
or interrupt), and through `inject_message` otherwise (F1 arm A; private names `_manager`,
`_cli_ref`, `_agent_running`, `_tui_enter_while_busy`). On the TUI and desktop host it goes
through `inject_message(session_key=...)`, which queues in every mode (F2 arm a). It is acked
only when hermes accepted it; a refusal leaves it pending.
"""

import json
import logging
import os
import socket
import subprocess
import sys
import threading
import time

logger = logging.getLogger(__name__)


def _register_sock():
    """register.sock, resolved as the xmsg binary does: $XDG_RUNTIME_DIR, else on macOS the
    Darwin user temp dir."""
    if os.environ.get("XMSG_REGISTER_SOCK"):
        return os.environ["XMSG_REGISTER_SOCK"]
    d = os.environ.get("XDG_RUNTIME_DIR", "").strip()
    if not d and sys.platform == "darwin":
        try:
            d = subprocess.run(["/usr/bin/getconf", "DARWIN_USER_TEMP_DIR"], capture_output=True, text=True,
                               check=True).stdout.strip()
        except (OSError, subprocess.CalledProcessError):
            d = ""
    return os.path.join(d, "xmsg", "register.sock") if d else None


def _reclaim_store_path():
    home = os.environ.get("HERMES_HOME", "").strip() or os.path.expanduser("~/.hermes")
    return os.path.join(home, "xmsg-reclaim.json")


def _load_reclaim_store(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
            return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


# Crash window (HA8 Change 7): if the plugin process dies after the server rotates the
# secret on a reclaim response and before this atomic file write completes, the stored
# secret on disk is stale; the next reclaim attempt receives `denied` ("reclaim refused")
# and falls back to minting a fresh address (any messages queued to the old address are lost).
def _save_reclaim_store(path, store):
    d = os.path.dirname(path)
    os.makedirs(d, mode=0o700, exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}.{time.time_ns()}"
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(store, f)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


class Connection:
    """The process's one connection. Frames carry a `request_id`; a reader thread hands each
    answer to its caller, so tool frames are answered while the poll is pending."""

    def __init__(self, path, deliver, store_path=None):
        self.path, self.deliver = path, deliver
        self.store_path = store_path or _reclaim_store_path()
        self.lock = threading.Lock()
        self.sock = None
        self.waiting = {}
        self.n = 0
        # Sessions held on the current connection, and the sessions this process wants held
        # (re-registered with their reclaim tokens after a reconnect: HA8).
        self.held = set()
        self.wanted = set()
        threading.Thread(target=self._poll_loop, name="xmsg-poll", daemon=True).start()

    def _connect(self):
        with self.lock:
            if self.sock is not None:
                return self.sock
            s = socket.socket(socket.AF_UNIX)
            s.connect(self.path)
            s.sendall(b'{"harness":"hermes"}\n')
            f = s.makefile("r", encoding="utf-8")
            hello = json.loads(f.readline() or "{}")
            if hello.get("status") != "ok":
                s.close()
                raise ConnectionError(f"xmsg refused the connection: {hello}")
            self.sock = s
            self.held = set()
        threading.Thread(target=self._read, args=(s, f), name="xmsg-read", daemon=True).start()
        return s

    def _read(self, s, f):
        try:
            for line in f:
                a = json.loads(line)
                with self.lock:
                    w = self.waiting.pop(a.get("request_id"), None)
                if w is not None:
                    w[1] = a
                    w[0].set()
        except (OSError, ValueError):
            pass
        with self.lock:
            if self.sock is s:
                self.sock = None
                self.held = set()
            waiting, self.waiting = self.waiting, {}
        for w in waiting.values():
            w[1] = {"status": "error", "error": "closed", "detail": "xmsg connection closed"}
            w[0].set()

    def call(self, frame, timeout=90):
        s = self._connect()
        w = [threading.Event(), None]
        with self.lock:
            self.n += 1
            rid = f"r{self.n}"
            self.waiting[rid] = w
            s.sendall((json.dumps(dict(frame, request_id=rid)) + "\n").encode())
        if not w[0].wait(timeout):
            with self.lock:
                self.waiting.pop(rid, None)
            return {"status": "error", "error": "timeout", "detail": f"xmsg did not answer {frame['action']}"}
        return w[1]

    def register(self, session):
        self.wanted.add(session)
        if session in self.held:
            return
        store = _load_reclaim_store(self.store_path)
        saved = store.get(session)
        frame = {"action": "register", "session": session}
        if isinstance(saved, dict) and saved.get("id") and saved.get("reclaim"):
            frame["reclaim"] = {"id": saved["id"], "secret": saved["reclaim"]}
        a = self.call(frame)
        if "reclaim" in frame and a.get("status") == "error" and a.get("error") == "denied":
            # Stale or expired reclaim window: delete saved entry and mint a fresh address.
            latest = _load_reclaim_store(self.store_path)
            latest.pop(session, None)
            _save_reclaim_store(self.store_path, latest)
            a = self.call({"action": "register", "session": session})
        if a.get("status") == "ok":
            # Persist the new/rotated secret atomically BEFORE acting on the registration.
            addr = a.get("address", "")
            secret = a.get("reclaim", "")
            if addr and secret:
                inst_id = addr.split("@", 1)[0]
                latest = _load_reclaim_store(self.store_path)
                latest[session] = {"id": inst_id, "address": addr, "reclaim": secret}
                _save_reclaim_store(self.store_path, latest)
            self.held.add(session)
        else:
            logger.warning("xmsg: registering %s: %s", session, a)

    def detach(self, session):
        """Detaches `session` from this connection while keeping its reclaim secret on disk
        and its `reclaim_hash` on the server so a later `/resume` or restart reclaims it (HA8 §3.1)."""
        self.wanted.discard(session)
        if session in self.held:
            self.held.discard(session)
            self.call({"action": "detach", "session": session})

    def release(self, session):
        """Permanently ends `session`: deletes its stored secret and clears `reclaim_hash` on the server."""
        latest = _load_reclaim_store(self.store_path)
        if session in latest:
            latest.pop(session, None)
            _save_reclaim_store(self.store_path, latest)
        self.wanted.discard(session)
        if session in self.held:
            self.held.discard(session)
            self.call({"action": "release", "session": session})

    def continues(self, frm, to):
        a = self.call({"action": "continues", "from": frm, "to": to})
        if a.get("status") != "ok":
            logger.warning("xmsg: continues %s -> %s: %s", frm, to, a)
            return False
        # Move the stored reclaim entry from `frm` to `to` on disk (HA8 §2.4).
        latest = _load_reclaim_store(self.store_path)
        entry = latest.pop(frm, None)
        if entry is not None:
            latest[to] = entry
            _save_reclaim_store(self.store_path, latest)
        self.wanted.discard(frm)
        self.held.discard(frm)
        self.wanted.add(to)
        self.held.add(to)
        return True

    def _poll_loop(self):
        while True:
            try:
                if not self.wanted:
                    time.sleep(0.5)
                    continue
                for session in list(self.wanted - self.held):
                    self.register(session)
                a = self.call({"action": "poll", "wait": 30}, timeout=45)
                if a.get("action") != "deliver":
                    if a.get("status") == "error":
                        time.sleep(1)
                    continue
                if self.deliver(a):
                    self.call({"action": "ack", "session": a["session"], "message_id": a["message_id"]})
                else:
                    # Left pending; it is offered again on a later poll.
                    time.sleep(1)
            except Exception:
                logger.warning("xmsg: poll loop", exc_info=True)
                time.sleep(1.5)


class Xmsg:
    def __init__(self, ctx, path):
        self.ctx = ctx
        self.lock = threading.RLock()
        self.current = None  # the CLI's live session
        self.parents = {}  # delegate session -> its parent (HA7)
        self.moved = {}  # session -> the continuation its address moved to
        self.ended = set()  # finalized roots; only the root's own turn or the CLI brings one back
        self.conn = Connection(path, self.deliver)

    def _cli(self):
        return getattr(self.ctx._manager, "_cli_ref", None)

    def _root(self, session):
        seen = set()
        while session in self.parents and session not in seen:
            seen.add(session)
            session = self.parents[session]
        return session

    @staticmethod
    def _continued(frm, to):
        """Whether hermes's session store records `to` in `frm`'s compression chain."""
        try:
            from hermes_state import SessionDB

            db = SessionDB(read_only=True)
            try:
                return to in db.get_compression_chain(frm)
            finally:
                db.close()
        except Exception:
            logger.warning("xmsg: reading the compression chain of %s", frm, exc_info=True)
            return False

    def observe(self, session):
        """`session`, a root, is live: hold its address, moving or detaching what it replaces."""
        with self.lock:
            self.ended.discard(session)
            if session in self.conn.wanted:
                return
            cli = self._cli() is not None
            prev = [self.current] if cli and self.current else list(self.conn.wanted)
            if cli:
                self.current = session
            for p in prev:
                if self._continued(p, session) and self.conn.continues(p, session):
                    self.moved[p] = session
                    return
            if cli and prev:
                self.conn.detach(prev[0])
            self.conn.register(session)

    def pre_llm_call(self, session_id="", parent_session_id="", **_):
        if not session_id:
            return None
        if parent_session_id:
            self.parents[session_id] = parent_session_id
            return None
        try:
            self.observe(session_id)
        except OSError:
            logger.warning("xmsg: registering %s", session_id, exc_info=True)
        return None

    def on_session_finalize(self, session_id="", **_):
        """A session finalized: a desktop/TUI session closed, or the CLI's `/new` or exit.
        In hermes these sessions stay resumable in state.db via `/resume` or `session.resume`,
        so this is a detach (HA8 §3.1): the address becomes parked and reclaimable."""
        try:
            with self.lock:
                if self.current == session_id:
                    self.current = None
                self.ended.add(session_id)
                self.conn.detach(session_id)
        except OSError:
            logger.warning("xmsg: detaching %s", session_id, exc_info=True)

    def on_session_reset(self, session_id="", **_):
        """The CLI's `/new`: the new session is registered (the old one was finalized)."""
        if not session_id:
            return
        try:
            self.observe(session_id)
        except OSError:
            logger.warning("xmsg: switching to %s", session_id, exc_info=True)

    def deliver(self, a):
        env, session = a["envelope"], a["session"]
        cli = self._cli()
        if cli is None:
            # The TUI and desktop host: `session_key` is the session id there.
            return bool(self.ctx.inject_message(env, session_key=session))
        live = getattr(cli, "session_id", None)
        if live and live != session:
            # A switch no hook announced (/resume, /branch): never inject into another session.
            self.observe(live)
            if self.moved.get(session) != live:
                return False
        if getattr(cli, "_agent_running", False):
            cli._tui_enter_while_busy(env, [], env)
            return True
        return bool(self.ctx.inject_message(env))

    def tool(self, action, fields):
        def handler(args, session_id=None, **_):
            if not session_id:
                return json.dumps({"status": "error", "error": "no_session",
                                   "detail": "hermes passed this tool call no session_id"})
            root = self._root(session_id)
            if root in self.ended:
                # An ended session's call, e.g. from its background delegate, which keeps
                # running after `/new`: registering the root again would release the live session.
                return json.dumps({"status": "error", "error": "gone",
                                   "detail": f"the hermes session {root} has ended"})
            frame = {"action": action, "session": root}
            frame.update({k: args[k] for k in fields if args.get(k) is not None})
            try:
                self.observe(root)
                return json.dumps(self.conn.call(frame))
            except OSError as e:
                return json.dumps({"status": "error", "error": "unavailable", "detail": f"xmsg: {e}"})

        return handler


def _schema(name, description, properties, required=()):
    return {"name": name, "description": description,
            "parameters": {"type": "object", "properties": properties, "required": list(required)}}


def _str(description):
    return {"type": "string", "description": description}


TOOLS = [
    ("xmsg_list", "list", ("name", "node", "kind", "status", "within"), _schema(
        "xmsg_list",
        "List the xmsg recipients you can message: by default live recipients (with harness and registered_at); with status='inactive', parked and closed instances seen within `within` seconds (default 86400 = 24h, capped at reply TTL, with harness and last_seen; a peer older than XL1 lists no inactive entries).",
        {
            "name": _str("only recipients with this label or service name"),
            "node": _str("ask only this node"),
            "kind": _str("service or instance"),
            "status": _str("live (default) or inactive"),
            "within": {"type": "number", "description": "for status='inactive', seconds to look back (default 86400)"},
        })),
    ("xmsg_send", "send", ("to", "text"), _schema(
        "xmsg_send", "Send a message to an xmsg recipient. `to` is an address (id@node) or a label.",
        {"to": _str("recipient address or label"), "text": _str("message text")}, ("to", "text"))),
    ("xmsg_reply", "reply", ("message_id", "text"), _schema(
        "xmsg_reply", "Reply to an xmsg message you received, by its message_id.",
        {"message_id": _str("the message_id you are replying to"), "text": _str("reply text")},
        ("message_id", "text"))),
    ("xmsg_replies", "replies", ("message_id", "wait"), _schema(
        "xmsg_replies", "Read the replies to a message you sent, waiting up to `wait` seconds (0 to 60) for the first.",
        {"message_id": _str("the message_id you sent"), "wait": {"type": "number", "description": "seconds to wait"}},
        ("message_id",))),
]


def register(ctx):
    path = _register_sock()
    if not path:
        logger.warning("xmsg: XDG_RUNTIME_DIR is not set; the xmsg plugin is off")
        return
    x = Xmsg(ctx, path)
    for name, action, fields, schema in TOOLS:
        ctx.register_tool(name=name, toolset="xmsg", schema=schema, handler=x.tool(action, fields), emoji="✉")
    ctx.register_hook("pre_llm_call", x.pre_llm_call)
    ctx.register_hook("on_session_reset", x.on_session_reset)
    ctx.register_hook("on_session_finalize", x.on_session_finalize)
