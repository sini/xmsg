// xmsg for opencode (plan XH2; HA2, HA3, HA4, HA7). opencode auto-loads this file from
// `<config>/opencode/plugin/`.
//
// One `register.sock` connection per opencode process, many sessions on it. A root
// session registers at its first user prompt and gets its own server-minted address;
// a child session (a task subagent) acts as its root, found by walking `parentID`, and is
// never registered. The tools `xmsg_list`, `xmsg_send`, `xmsg_reply` and `xmsg_replies`
// send their frames on that connection under the root's session, so the server attributes
// them to its address. A pushed message is prompted into its session and acked once
// opencode accepts it. A deleted session releases its address.
//
// The default export serves both plugin APIs: opencode 1.x calls `server`, opencode 2.x
// calls `setup`. Each adapts its API to `Xmsg`, which holds the behaviour.
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import readline from "node:readline";

// The runtime dir holding xmsg/, resolved as the xmsg binary does: $XDG_RUNTIME_DIR, else
// on macOS the Darwin user temp dir.
function registerSockPath(): string | undefined {
  if (process.env.XMSG_REGISTER_SOCK) return process.env.XMSG_REGISTER_SOCK;
  let dir = process.env.XDG_RUNTIME_DIR?.trim();
  if (!dir && process.platform === "darwin") {
    try {
      dir = execFileSync("/usr/bin/getconf", ["DARWIN_USER_TEMP_DIR"], { encoding: "utf8" }).trim();
    } catch {}
  }
  return dir ? path.join(dir, "xmsg", "register.sock") : undefined;
}

function reclaimStorePath(): string {
  const stateHome = process.env.XDG_STATE_HOME?.trim() || path.join(os.homedir(), ".local", "state");
  return path.join(stateHome, "opencode", "xmsg-reclaim.json");
}

interface ReclaimEntry {
  id: string;
  address: string;
  reclaim: string;
}

function loadReclaimStore(filePath: string): Record<string, ReclaimEntry> {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch {
    return {};
  }
}

// Crash window (HA8 Change 7): if the plugin process dies after the server rotates the
// secret on a reclaim response and before this atomic file write completes, the stored
// secret on disk is stale; the next reclaim attempt receives `denied` ("reclaim refused")
// and falls back to minting a fresh address (any messages queued to the old address are lost).
function saveReclaimStore(filePath: string, store: Record<string, ReclaimEntry>): void {
  const dir = path.dirname(filePath);
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  const tmpPath = `${filePath}.tmp.${process.pid}.${Date.now()}`;
  fs.writeFileSync(tmpPath, JSON.stringify(store), { mode: 0o600 });
  fs.chmodSync(tmpPath, 0o600);
  fs.renameSync(tmpPath, filePath);
}

type Answer = Record<string, any>;

class Connection {
  private socket?: net.Socket;
  private waiting = new Map<string, (a: Answer) => void>();
  private next = 0;
  // Root sessions and their registrations on the current connection.
  private registered = new Map<string, Promise<Answer>>();
  private roots = new Set<string>();
  private ready?: Promise<void>;
  private closed = false;
  private storePath = reclaimStorePath();

  constructor(
    private sock: string,
    private deliver: (a: Answer) => Promise<boolean>,
  ) {}

  private connect(): Promise<void> {
    if (this.closed) return Promise.reject(new Error("xmsg plugin stopped"));
    this.ready ??= new Promise((resolve, reject) => {
      const s = net.createConnection(this.sock);
      s.once("error", (e) => {
        this.ready = undefined;
        reject(e);
      });
      const lines = readline.createInterface({ input: s });
      let hello = true;
      lines.on("line", (line) => {
        const a = JSON.parse(line);
        if (hello) {
          hello = false;
          if (a.status !== "ok") return reject(new Error(`xmsg refused the connection: ${line}`));
          this.socket = s;
          resolve();
          void this.pollLoop(s);
          for (const root of this.roots) void this.register(root);
          return;
        }
        this.waiting.get(a.request_id)?.(a);
        this.waiting.delete(a.request_id);
      });
      s.on("close", () => {
        // Every address on a closed connection is detached (HA8): register again with reclaim.
        if (this.socket === s) this.socket = undefined;
        this.ready = undefined;
        this.registered.clear();
        for (const [, resolve] of this.waiting) resolve({ status: "error", error: "closed", detail: "xmsg connection closed" });
        this.waiting.clear();
        if (this.roots.size && !this.closed) setTimeout(() => void this.connect().catch(() => {}), 1500);
      });
      s.write(JSON.stringify({ harness: "opencode" }) + "\n");
    });
    return this.ready;
  }

  async call(frame: Answer): Promise<Answer> {
    await this.connect();
    const request_id = `r${++this.next}`;
    return new Promise((resolve) => {
      this.waiting.set(request_id, resolve);
      this.socket!.write(JSON.stringify({ ...frame, request_id }) + "\n");
    });
  }

  private async doRegister(root: string): Promise<Answer> {
    const store = loadReclaimStore(this.storePath);
    const saved = store[root];
    let a = await this.call({
      action: "register",
      session: root,
      ...(saved ? { reclaim: { id: saved.id, secret: saved.reclaim } } : {}),
    });
    if (saved && a.status === "error" && a.error === "denied") {
      // Stale or expired reclaim window: delete saved entry and mint a fresh address.
      const latest = loadReclaimStore(this.storePath);
      delete latest[root];
      saveReclaimStore(this.storePath, latest);
      a = await this.call({ action: "register", session: root });
    }
    if (a.status === "ok" && a.address && a.reclaim) {
      // Persist the new/rotated secret atomically BEFORE acting on the registration.
      const id = String(a.address).split("@")[0];
      const latest = loadReclaimStore(this.storePath);
      latest[root] = { id, address: a.address, reclaim: a.reclaim };
      saveReclaimStore(this.storePath, latest);
    }
    return a;
  }

  register(root: string): Promise<Answer> {
    this.roots.add(root);
    let r = this.registered.get(root);
    if (!r) {
      r = this.doRegister(root);
      this.registered.set(root, r);
      r.catch(() => this.registered.delete(root));
    }
    return r;
  }

  async release(session: string) {
    const latest = loadReclaimStore(this.storePath);
    if (session in latest) {
      delete latest[session];
      saveReclaimStore(this.storePath, latest);
    }
    if (!this.roots.delete(session)) return;
    this.registered.delete(session);
    await this.call({ action: "release", session });
  }

  // Waits for a registration in flight, so a tool call never overtakes it.
  async settled(root: string) {
    await this.registered.get(root)?.catch(() => {});
  }

  // Closing the connection detaches every address on it (HA8); nothing reconnects. The
  // next `setup` after a plugin reload reclaims them from the store.
  close() {
    this.closed = true;
    this.roots.clear();
    this.socket?.destroy();
  }

  private async pollLoop(s: net.Socket) {
    while (this.socket === s) {
      const a = await this.call({ action: "poll", wait: 30 }).catch(() => undefined);
      if (a?.action !== "deliver") {
        if (a?.status === "error") await new Promise((r) => setTimeout(r, 1000));
        continue;
      }
      if (await this.deliver(a)) {
        await this.call({ action: "ack", session: a.session, message_id: a.message_id });
      } else {
        // Left pending; it is offered again on a later poll.
        await new Promise((r) => setTimeout(r, 1000));
      }
    }
  }
}

// The two calls that differ between the plugin APIs.
interface Host {
  parentOf(session: string): Promise<string | undefined>;
  // Prompts `text` into `session`; true once opencode accepted it.
  prompt(session: string, text: string): Promise<boolean>;
}

class Xmsg {
  private conn: Connection;

  constructor(
    sock: string,
    private host: Host,
  ) {
    this.conn = new Connection(sock, (a) => host.prompt(a.session, a.envelope));
  }

  // HA7: a child session acts as its root conversation.
  private async rootOf(id: string): Promise<string> {
    for (let parent = await this.host.parentOf(id); parent; parent = await this.host.parentOf(id)) id = parent;
    return id;
  }

  async prompted(session: string) {
    try {
      if (!(await this.host.parentOf(session))) await this.conn.register(session);
    } catch (e) {
      console.warn(`[xmsg] registering ${session}: ${e}`);
    }
  }

  async deleted(session: string) {
    await this.conn.release(session).catch(() => {});
  }

  async run(frame: Answer, sessionID: string): Promise<string> {
    const session = await this.rootOf(sessionID);
    await this.conn.settled(session);
    return JSON.stringify(await this.conn.call({ ...frame, session }));
  }

  close() {
    this.conn.close();
  }
}

const str = (description: string) => ({ type: "string", description });
// `required` defaults to every arg.
const TOOLS: { name: string; description: string; args: Answer; required?: string[]; frame: (a: Answer) => Answer }[] = [
  {
    name: "xmsg_list",
    description:
      "List the xmsg recipients you can message: by default live recipients (with harness and registered_at); with status='inactive', parked and closed instances seen within `within` seconds (default 86400 = 24h, capped at reply TTL, with harness and last_seen; a peer older than XL1 lists no inactive entries).",
    args: {
      name: str("only recipients with this label or service name"),
      node: str("ask only this node"),
      kind: str("service or instance"),
      status: str("live (default) or inactive"),
      within: { type: "number", description: "for status='inactive', seconds to look back (default 86400)" },
    },
    required: [],
    frame: (a) => ({
      action: "list",
      ...(a?.name != null ? { name: a.name } : {}),
      ...(a?.node != null ? { node: a.node } : {}),
      ...(a?.kind != null ? { kind: a.kind } : {}),
      ...(a?.status != null ? { status: a.status } : {}),
      ...(a?.within != null ? { within: a.within } : {}),
    }),
  },
  {
    name: "xmsg_send",
    description: "Send a message to an xmsg recipient. `to` is an address (id@node) or a label.",
    args: { to: str("recipient address or label"), text: str("message text") },
    frame: (a) => ({ action: "send", to: a.to, text: a.text }),
  },
  {
    name: "xmsg_reply",
    description: "Reply to an xmsg message you received, by its message_id.",
    args: { message_id: str("the message_id you are replying to"), text: str("reply text") },
    frame: (a) => ({ action: "reply", message_id: a.message_id, text: a.text }),
  },
  {
    name: "xmsg_replies",
    description: "Read the replies to a message you sent, waiting up to `wait` seconds (0 to 60) for the first.",
    args: { message_id: str("the message_id you sent"), wait: { type: "number", description: "seconds to wait" } },
    frame: (a) => ({ action: "replies", message_id: a.message_id, wait: a.wait }),
  },
];

const noSock = () => console.warn("[xmsg] XDG_RUNTIME_DIR is not set; the xmsg plugin is off");

// opencode 1.x: hooks returned from `server`, the SDK client for sessions.
const server = async ({ client }: any) => {
  const sock = registerSockPath();
  if (!sock) return noSock(), {};

  const parentOf = async (id: string): Promise<string | undefined> => {
    const res = await client.session.get({ path: { id } });
    if (res.error) throw new Error(`session ${id}: ${JSON.stringify(res.error)}`);
    return res.data?.parentID;
  };
  const xmsg = new Xmsg(sock, {
    parentOf,
    prompt: async (id, text) => {
      const res = await client.session
        .promptAsync({ path: { id }, body: { parts: [{ type: "text", text }] } })
        .catch((e: unknown) => ({ error: e }));
      return !res.error;
    },
  });

  return {
    "chat.message": (input: { sessionID: string }) => xmsg.prompted(input.sessionID),
    event: async ({ event }: any) => {
      if (event.type === "session.deleted") await xmsg.deleted(event.properties.info.id);
    },
    tool: Object.fromEntries(
      TOOLS.map((t) => [
        t.name,
        { description: t.description, args: t.args, execute: (a: Answer, ctx: any) => xmsg.run(t.frame(a), ctx.sessionID) },
      ]),
    ),
  };
};

// opencode 2.x: `setup(ctx)` registers hooks, tools and an event subscription, and returns
// their cleanup, which a plugin reload runs before the next `setup`.
const setup = async (ctx: any) => {
  const sock = registerSockPath();
  if (!sock) return noSock();

  const xmsg = new Xmsg(sock, {
    parentOf: async (sessionID) => (await ctx.session.get({ sessionID })).parentID,
    prompt: (sessionID, text) =>
      ctx.session.prompt({ sessionID, text }).then(
        () => true,
        () => false,
      ),
  });

  const hook = await ctx.session.hook("prompt", (input: { sessionID: string }) => xmsg.prompted(input.sessionID));
  // Out of Code Mode, so the model calls the tools by name, as it does on 1.x.
  const tools = await ctx.tool.transform((editor: any) => {
    for (const t of TOOLS) {
      editor.add({
        name: t.name,
        description: t.description,
        options: { codemode: false },
        input: { type: "object", properties: t.args, required: t.required ?? Object.keys(t.args), additionalProperties: false },
        execute: async (a: Answer, tc: { sessionID: string }) => ({ content: await xmsg.run(t.frame(a), tc.sessionID) }),
      });
    }
  });
  const abort = new AbortController();
  const events = (async () => {
    try {
      for await (const event of ctx.event.subscribe({ signal: abort.signal })) {
        if (event.type === "session.deleted") await xmsg.deleted(event.data.sessionID);
      }
    } catch (e) {
      if (!abort.signal.aborted) console.warn(`[xmsg] event subscription: ${e}`);
    }
  })();

  return async () => {
    xmsg.close();
    abort.abort();
    await events;
    await Promise.all([hook.dispose(), tools.dispose()]);
  };
};

export default { id: "xmsg", server, setup };
