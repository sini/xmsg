// xmsg for opencode (plan XH2; HA2, HA3, HA4, HA7). opencode auto-loads this file from
// `<config>/opencode/plugin/`.
//
// One `register.sock` connection per opencode process, many sessions on it. A root
// session registers at its first `chat.message` and gets its own server-minted address;
// a child session (a task subagent) acts as its root, found by walking `parentID`, and is
// never registered. The tools `xmsg_list`, `xmsg_send`, `xmsg_reply` and `xmsg_replies`
// send their frames on that connection under the root's session, so the server attributes
// them to its address. A pushed message is handed to its session with `promptAsync` and
// acked once that accepts it. A deleted session releases its address.
import { execFileSync } from "node:child_process";
import net from "node:net";
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

type Answer = Record<string, any>;

class Connection {
  private socket?: net.Socket;
  private waiting = new Map<string, (a: Answer) => void>();
  private next = 0;
  // Root sessions and their registrations on the current connection.
  private registered = new Map<string, Promise<Answer>>();
  private roots = new Set<string>();
  private ready?: Promise<void>;

  constructor(
    private sock: string,
    private deliver: (a: Answer) => Promise<boolean>,
  ) {}

  private connect(): Promise<void> {
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
        // Every address on a closed connection is released (P6): register again.
        if (this.socket === s) this.socket = undefined;
        this.ready = undefined;
        this.registered.clear();
        for (const [, resolve] of this.waiting) resolve({ status: "error", error: "closed", detail: "xmsg connection closed" });
        this.waiting.clear();
        if (this.roots.size) setTimeout(() => void this.connect().catch(() => {}), 1500);
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

  register(root: string): Promise<Answer> {
    this.roots.add(root);
    let r = this.registered.get(root);
    if (!r) {
      r = this.call({ action: "register", session: root });
      this.registered.set(root, r);
      r.catch(() => this.registered.delete(root));
    }
    return r;
  }

  async release(session: string) {
    if (!this.roots.delete(session)) return;
    this.registered.delete(session);
    await this.call({ action: "release", session });
  }

  // Waits for a registration in flight, so a tool call never overtakes it.
  async settled(root: string) {
    await this.registered.get(root)?.catch(() => {});
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

export const XmsgPlugin = async ({ client }: any) => {
  const sock = registerSockPath();
  if (!sock) {
    console.warn("[xmsg] XDG_RUNTIME_DIR is not set; the xmsg plugin is off");
    return {};
  }

  const parentOf = async (id: string): Promise<string | undefined> => {
    const res = await client.session.get({ path: { id } });
    if (res.error) throw new Error(`session ${id}: ${JSON.stringify(res.error)}`);
    return res.data?.parentID;
  };
  // HA7: a child session acts as its root conversation.
  const rootOf = async (id: string): Promise<string> => {
    for (let parent = await parentOf(id); parent; parent = await parentOf(id)) id = parent;
    return id;
  };

  const conn = new Connection(sock, async (a) => {
    const res = await client.session
      .promptAsync({ path: { id: a.session }, body: { parts: [{ type: "text", text: a.envelope }] } })
      .catch((e: unknown) => ({ error: e }));
    return !res.error;
  });

  const run = async (frame: Answer, sessionID: string) => {
    const session = await rootOf(sessionID);
    await conn.settled(session);
    return JSON.stringify(await conn.call({ ...frame, session }));
  };
  const str = (description: string) => ({ type: "string", description });

  return {
    "chat.message": async (input: { sessionID: string }) => {
      try {
        if (!(await parentOf(input.sessionID))) await conn.register(input.sessionID);
      } catch (e) {
        console.warn(`[xmsg] registering ${input.sessionID}: ${e}`);
      }
    },
    event: async ({ event }: any) => {
      if (event.type === "session.deleted") await conn.release(event.properties.info.id).catch(() => {});
    },
    tool: {
      xmsg_list: {
        description:
          "List the xmsg recipients you can message: by default live recipients (with harness and registered_at); with status='inactive', parked and closed instances seen within `within` seconds (default 86400 = 24h, capped at reply TTL, with harness and last_seen; a peer older than XL1 lists no inactive entries).",
        args: {
          name: str("only recipients with this label or service name"),
          node: str("ask only this node"),
          kind: str("service or instance"),
          status: str("live (default) or inactive"),
          within: { type: "number", description: "for status='inactive', seconds to look back (default 86400)" },
        },
        execute: (a: Answer, ctx: any) =>
          run(
            {
              action: "list",
              ...(a?.name != null ? { name: a.name } : {}),
              ...(a?.node != null ? { node: a.node } : {}),
              ...(a?.kind != null ? { kind: a.kind } : {}),
              ...(a?.status != null ? { status: a.status } : {}),
              ...(a?.within != null ? { within: a.within } : {}),
            },
            ctx.sessionID,
          ),
      },
      xmsg_send: {
        description: "Send a message to an xmsg recipient. `to` is an address (id@node) or a label.",
        args: { to: str("recipient address or label"), text: str("message text") },
        execute: (a: Answer, ctx: any) => run({ action: "send", to: a.to, text: a.text }, ctx.sessionID),
      },
      xmsg_reply: {
        description: "Reply to an xmsg message you received, by its message_id.",
        args: { message_id: str("the message_id you are replying to"), text: str("reply text") },
        execute: (a: Answer, ctx: any) =>
          run({ action: "reply", message_id: a.message_id, text: a.text }, ctx.sessionID),
      },
      xmsg_replies: {
        description: "Read the replies to a message you sent, waiting up to `wait` seconds (0 to 60) for the first.",
        args: { message_id: str("the message_id you sent"), wait: { type: "number", description: "seconds to wait" } },
        execute: (a: Answer, ctx: any) =>
          run({ action: "replies", message_id: a.message_id, wait: a.wait }, ctx.sessionID),
      },
    },
  };
};
