import { execFile, execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import path from "node:path";
import readline from "node:readline";

function ownEnvironment(): { kind: string; ref?: string } {
  for (const [name, kind] of [["ZELLIJ_SESSION_NAME", "zellij"], ["TMUX_PANE", "tmux"], ["HERDR_PANE_ID", "herdr"]]) {
    const value = process.env[name];
    if (value !== undefined) {
      let reference = "";
      for (const char of value.replace(/[\u0000-\u001f\u007f-\u009f]/g, "")) {
        if (Buffer.byteLength(reference + char, "utf8") > 64) break;
        reference += char;
      }
      return { kind, ref: reference };
    }
  }
  return { kind: "none" };
}

import { Type } from "typebox";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

let darwinUserTempDir: string | null | undefined;

// The runtime dir holding xmsg/, resolved like the xmsg binary does:
// $XDG_RUNTIME_DIR, else on macOS confstr(_CS_DARWIN_USER_TEMP_DIR). TMPDIR is
// not used because it can be missing or different under launchd. A blank
// XDG_RUNTIME_DIR counts as unset, as in the binary's socket_dir_for_env.
export function defaultRuntimeDir(): string | undefined {
  const xdg = process.env.XDG_RUNTIME_DIR;
  if (xdg && xdg.trim()) {
    return xdg;
  }
  if (process.platform !== "darwin") {
    return undefined;
  }
  if (darwinUserTempDir === undefined) {
    try {
      const out = execFileSync("/usr/bin/getconf", ["DARWIN_USER_TEMP_DIR"], { encoding: "utf8" });
      darwinUserTempDir = out.trim() || null;
    } catch (err: any) {
      console.error(`[xmsg-pi] getconf DARWIN_USER_TEMP_DIR failed: ${err.message || err}`);
      darwinUserTempDir = null;
    }
  }
  return darwinUserTempDir ?? undefined;
}

export type Endpoint = "register" | "agent" | "http";
export type DoctorResult = { stdout: string; stderr: string; error: any };
export type DoctorProbe = () => Promise<DoctorResult>;
export interface EndpointResolver {
  resolve(name: Endpoint): Promise<string | undefined>;
  invalidate(): void;
}
export class XmsgEndpointError extends Error {}

const ENDPOINT_ENV = { register: "XMSG_REGISTER_SOCK", agent: "XMSG_AGENT_SOCK", http: "XMSG_HTTP_SOCK" } as const;
// Only the exact clap parse error of a CLI that predates `doctor` falls through to the legacy path.
const UNSUPPORTED_DOCTOR = "error: unrecognized subcommand 'doctor'\n\nUsage: xmsg <COMMAND>\n\nFor more information, try '--help'.\n";

const runDoctor: DoctorProbe = () =>
  new Promise((resolve) =>
    execFile("xmsg", ["doctor", "--json"], { timeout: 3000, maxBuffer: 64 * 1024, killSignal: "SIGKILL", encoding: "utf8" },
      (error, stdout, stderr) => resolve({ error, stdout, stderr })),
  );

// The daemon's sockets: XMSG_*_SOCK, else what `xmsg doctor --json` resolves (run once and
// cached until invalidate(), which a caller makes after a disconnect), else the legacy
// <runtime dir>/xmsg/ when no CLI with doctor is installed. A doctor that answers with
// unusable endpoints, malformed output or a timeout is refused, never rerouted.
export function createEndpointResolver(probe: DoctorProbe = runDoctor, log = (line: string) => console.error(line)): EndpointResolver {
  let found: Promise<Partial<Record<Endpoint, string>> | string> | undefined;
  let loggedFallback = false;
  const refuse = (why: string): never => {
    throw new XmsgEndpointError(`xmsg doctor ${why}`);
  };
  const discover = async () => {
    const { stdout, stderr, error } = await probe();
    if (error?.killed || error?.signal || error?.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER") refuse("exceeded its time or output bound");
    if (error?.code === "ENOENT") return "xmsg CLI not found";
    if (error?.code === 2 && stdout === "" && stderr === UNSUPPORTED_DOCTOR) return "xmsg CLI has no doctor";
    let report: any;
    try {
      report = JSON.parse(stdout);
    } catch {
      refuse("returned invalid JSON");
    }
    if (report?.endpoints_usable === false) refuse("reports the endpoints unusable; run `xmsg doctor`");
    if (report?.endpoints_usable !== true) refuse("returned an invalid endpoint report");
    const fields = { register: report.register_socket ?? report.leaf_register_socket, agent: report.agent_socket, http: report.http_socket };
    const paths: Partial<Record<Endpoint, string>> = {};
    for (const [name, value] of Object.entries(fields) as [Endpoint, unknown][]) {
      if (value === null || value === undefined) continue;
      if (typeof value !== "string" || !path.isAbsolute(value) || value.includes("\0")) refuse(`returned a non-absolute ${name} socket`);
      paths[name] = value as string;
    }
    return paths;
  };
  return {
    async resolve(name) {
      const pinned = process.env[ENDPOINT_ENV[name]];
      if (pinned) return pinned;
      const result = await (found ??= discover());
      if (typeof result !== "string") return result[name] ?? refuse(`reported no ${name} socket`);
      if (!loggedFallback) {
        loggedFallback = true;
        log(`[xmsg] ${result}; using the legacy socket directory`);
      }
      const runtimeDir = defaultRuntimeDir();
      return runtimeDir ? path.join(runtimeDir, "xmsg", `${name}.sock`) : undefined;
    },
    invalidate() {
      found = undefined;
    },
  };
}

// One doctor probe per process, shared by every bridge.
export const endpoints = createEndpointResolver();

export function verifySecureSocketDir(sockPath: string): boolean {
  try {
    const dir = path.dirname(sockPath);
    const stat = fs.lstatSync(dir);
    if (stat.isSymbolicLink()) {
      console.error(`[xmsg-pi] socket directory ${dir} is a symlink`);
      return false;
    }
    if (!stat.isDirectory()) {
      console.error(`[xmsg-pi] socket directory ${dir} is not a directory`);
      return false;
    }
    const uid = typeof process.getuid === "function" ? process.getuid() : 1000;
    if (stat.uid !== uid) {
      console.error(`[xmsg-pi] socket directory ${dir} owned by UID ${stat.uid}, expected ${uid}`);
      return false;
    }
    const mode = stat.mode & 0o777;
    if (mode !== 0o700) {
      console.error(`[xmsg-pi] socket directory ${dir} has mode ${mode.toString(8)}, expected 0700`);
      return false;
    }
    return true;
  } catch (err: any) {
    console.error(`[xmsg-pi] failed to verify socket directory: ${err.message || err}`);
    return false;
  }
}

export function defaultXmsgUrl(): string | undefined {
  const url = process.env.XMSG_URL;
  if (url && url.trim()) {
    return url.trim().replace(/\/$/, "");
  }
  return undefined;
}

import os from "node:os";

export function defaultReclaimPath(): string {
  const dir = process.env.PI_CODING_AGENT_SESSION_DIR?.trim() || path.join(os.homedir(), ".pi", "agent");
  return path.join(dir, "xmsg-reclaim.json");
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

export interface ExtensionOptions {
  sockPath?: string;
  agentSockPath?: string;
  httpSockPath?: string;
  xmsgUrl?: string;
  reclaimPath?: string;
  pollWaitSecs?: number;
  reconnectDelayMs?: number;
  endpoints?: EndpointResolver;
}

export class XmsgPiBridge {
  private pi: ExtensionAPI;
  private sockPath?: string;
  private agentSockPath?: string;
  private httpSockPath?: string;
  private xmsgUrl?: string;
  private reclaimPath: string;
  private pollWaitSecs: number;
  private reconnectDelayMs: number;
  private endpoints: EndpointResolver;
  private lastWarning?: string;
  private socket?: net.Socket;
  private rl?: readline.Interface;
  private running = false;
  private piSessionId?: string;
  private currentSessionId?: string;
  private currentSessionName?: string;
  private currentCwd?: string;

  constructor(pi: ExtensionAPI, options: ExtensionOptions = {}) {
    this.pi = pi;
    this.sockPath = options.sockPath;
    this.agentSockPath = options.agentSockPath;
    this.httpSockPath = options.httpSockPath;
    this.endpoints = options.endpoints ?? endpoints;
    this.xmsgUrl = options.xmsgUrl || defaultXmsgUrl();
    this.reclaimPath = options.reclaimPath || defaultReclaimPath();
    this.pollWaitSecs = options.pollWaitSecs ?? 30;
    this.reconnectDelayMs = options.reconnectDelayMs ?? 1500;
  }

  public setSession(sessionId: string, sessionName?: string, cwd?: string) {
    this.piSessionId = sessionId;
    this.currentSessionId = sessionId;
    const resolvedCwd = cwd || process.cwd();
    this.currentCwd = resolvedCwd;
    if (sessionName && sessionName.trim()) {
      this.currentSessionName = sessionName.trim();
    } else {
      const base = path.basename(resolvedCwd);
      this.currentSessionName = base || "pi";
    }
  }

  public getSessionId(): string | undefined {
    return this.currentSessionId;
  }

  // An explicit path, else the shared resolver.
  public endpoint(name: Endpoint): Promise<string | undefined> {
    const explicit = { register: this.sockPath, agent: this.agentSockPath, http: this.httpSockPath }[name];
    return explicit ? Promise.resolve(explicit) : this.endpoints.resolve(name);
  }

  private warn(line: string) {
    if (line !== this.lastWarning) console.warn(line);
    this.lastWarning = line;
  }

  public start() {
    if (this.running) return;
    this.running = true;
    this.connectLoop();
  }

  public stop() {
    this.running = false;
    if (this.socket) {
      this.socket.destroy();
      this.socket = undefined;
    }
    if (this.rl) {
      this.rl.close();
      this.rl = undefined;
    }
  }

  private async connectLoop() {
    while (this.running) {
      if (!this.piSessionId) {
        await new Promise((r) => setTimeout(r, 500));
        continue;
      }

      let sockPath: string | undefined;
      let refused = false;
      try {
        sockPath = await this.endpoint("register");
      } catch (err: any) {
        refused = true;
        this.warn(`[xmsg-pi] ${err.message || err}; retrying`);
      }
      if (!sockPath && !refused) {
        console.warn("[xmsg-pi] socket directory not found (XDG_RUNTIME_DIR is unset, the macOS fallback is unavailable, and no sockPath was provided); disabling socket polling");
        this.running = false;
        return;
      }
      if (sockPath && !verifySecureSocketDir(sockPath)) {
        this.warn(`[xmsg-pi] socket directory for ${sockPath} failed security check; retrying`);
      } else if (sockPath) {
        try {
          await this.runConnection(sockPath);
        } catch (_err) {
          // connection closed or failed
        }
        // Re-resolve after a disconnect, so a restarted daemon is found through the backoff.
        this.endpoints.invalidate();
      }

      if (this.running) {
        await new Promise((r) => setTimeout(r, this.reconnectDelayMs));
      }
    }
  }

  private runConnection(sockPath: string): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.piSessionId) {
        return resolve();
      }
      const piKey = this.piSessionId;
      const store = loadReclaimStore(this.reclaimPath);
      const saved = store[piKey];

      const socket = net.connect(sockPath);
      this.socket = socket;

      let settled = false;
      const finish = (err?: Error) => {
        if (!settled) {
          settled = true;
          this.socket = undefined;
          this.rl = undefined;
          if (err) reject(err);
          else resolve();
        }
      };

      socket.on("error", (err) => finish(err));
      socket.on("close", () => finish());

      const rl = readline.createInterface({ input: socket, crlfDelay: Infinity });
      this.rl = rl;

      const lineIterator = rl[Symbol.asyncIterator]();

      (async () => {
        try {
          // 1. Send registration (with reclaim token if saved for this pi session ID)
          const regPayload: Record<string, any> = {
            harness: "pi",
            sessionId: piKey,
            env: ownEnvironment(),
            sessionName: this.currentSessionName,
            cwd: this.currentCwd,
            ...(saved ? { reclaim: { id: saved.id, secret: saved.reclaim } } : {}),
          };
          socket.write(JSON.stringify(regPayload) + "\n");

          // 2. Read registration response
          const regRespItem = await lineIterator.next();
          if (regRespItem.done) throw new Error("Socket closed before registration response");
          const regResp = JSON.parse(regRespItem.value);
          if (regResp.status !== "ok") {
            if (saved && regResp.error === "denied") {
              // Stale or expired reclaim window: clear the saved token so the next
              // reconnect mints a fresh address cleanly.
              const latest = loadReclaimStore(this.reclaimPath);
              delete latest[piKey];
              saveReclaimStore(this.reclaimPath, latest);
            }
            throw new Error(`Registration failed: ${regResp.detail || JSON.stringify(regResp)}`);
          }
          // Persist the new/rotated secret atomically BEFORE acting on the registration.
          if (regResp.sessionId && regResp.reclaim) {
            const latest = loadReclaimStore(this.reclaimPath);
            latest[piKey] = {
              id: regResp.sessionId,
              address: regResp.address || regResp.sessionId,
              reclaim: regResp.reclaim,
            };
            saveReclaimStore(this.reclaimPath, latest);
          }
          if (regResp.sessionId) {
            this.currentSessionId = regResp.sessionId;
          }

          // 3. Enter polling loop
          while (this.running) {
            const pollCmd = {
              action: "poll",
              sessionId: this.currentSessionId,
              waitSecs: this.pollWaitSecs,
            };
            socket.write(JSON.stringify(pollCmd) + "\n");

            const item = await lineIterator.next();
            if (item.done) break;

            const msg = JSON.parse(item.value);
            if (msg.action === "deliver") {
              // BINDING SECURITY INVARIANT:
              // expandPromptTemplates MUST be false explicitly to prevent remote command/skill execution
              this.pi.sendUserMessage(msg.envelope, {
                deliverAs: "followUp",
                expandPromptTemplates: false,
              });

              // Send ack
              const ackCmd = {
                action: "ack",
                messageId: msg.messageId,
              };
              socket.write(JSON.stringify(ackCmd) + "\n");

              // Read ack response
              const ackRespItem = await lineIterator.next();
              if (ackRespItem.done) break;
            } else if (msg.action === "timeout") {
              // No message in wait interval, loop around
              continue;
            } else if (msg.status === "error") {
              await new Promise((r) => setTimeout(r, 1000));
            }
          }
          finish();
        } catch (e: any) {
          finish(e);
        }
      })();
    });
  }

  private async callAgentSock(req: any): Promise<any> {
    let agentSockPath: string | undefined;
    try {
      agentSockPath = await this.endpoint("agent");
    } catch (err: any) {
      return {
        content: [{ type: "text", text: `Error: ${err.message || err}` }],
        details: { error: "endpoint_refused", detail: String(err.message || err) },
      };
    }
    if (!agentSockPath) {
      return {
        content: [{ type: "text", text: "Error: agent.sock path unknown (XDG_RUNTIME_DIR unset)" }],
        details: { error: "agent_sock_unknown" },
      };
    }
    if (!verifySecureSocketDir(agentSockPath)) {
      return Promise.resolve({
        content: [{ type: "text", text: "Error: agent.sock directory failed security check" }],
        details: { error: "insecure_socket_dir" },
      });
    }

    return new Promise((resolve) => {
      let client: net.Socket;
      try {
        client = net.connect(agentSockPath, () => {
          client.write(JSON.stringify(req) + "\n");
        });
      } catch (err: any) {
        resolve({
          content: [{ type: "text", text: `Error connecting to agent socket: ${err.message}` }],
          details: { error: "socket_error", detail: err.message },
        });
        return;
      }

      let data = "";
      client.on("data", (chunk) => {
        data += chunk.toString();
        if (data.includes("\n")) {
          client.end();
        }
      });

      client.on("error", (err) => {
        this.endpoints.invalidate();
        resolve({
          content: [{ type: "text", text: `Error connecting to agent socket: ${err.message}` }],
          details: { error: "socket_error", detail: err.message },
        });
      });

      client.on("close", () => {
        try {
          const line = data.trim().split("\n")[0];
          if (!line) {
            resolve({
              content: [{ type: "text", text: "Error: empty response from agent socket" }],
              details: { error: "empty_response" },
            });
            return;
          }
          const resp = JSON.parse(line);
          resolve(resp);
        } catch (err: any) {
          resolve({
            content: [{ type: "text", text: `Error parsing agent response: ${err.message}` }],
            details: { error: "parse_error", detail: String(err) },
          });
        }
      });
    });
  }

  public registerListTool() {
    this.pi.registerTool({
      name: "list",
      label: "List",
      description: "List the recipients you can message: by default shows live recipients (with harness and registered_at); with status='inactive' shows parked and closed instances seen within `within` seconds (default 86400 = 24h, capped at reply TTL, with harness and last_seen; a peer older than XL1 lists no inactive entries). Filter by name, node or kind; node lists a federated peer.",
      parameters: Type.Object({
        name: Type.Optional(Type.String({ description: "Only recipients with this label or service name" })),
        node: Type.Optional(Type.String({ description: "List this node (a federated peer) instead of the local one" })),
        kind: Type.Optional(Type.Union([Type.Literal("service"), Type.Literal("instance")], { description: "Only services or only instances" })),
        status: Type.Optional(Type.Union([Type.Literal("live"), Type.Literal("inactive")], { description: "Whether to list live recipients (default) or inactive (parked and closed) instances" })),
        within: Type.Optional(Type.Integer({ minimum: 0, description: "For status='inactive', include entries seen within this many seconds (default 86400 = 24h, capped at reply TTL)" })),
      }),
      execute: async (_toolCallId: string, params: { name?: string; node?: string; kind?: string; status?: string; within?: number } = {}) => {
        const query = new URLSearchParams();
        for (const key of ["name", "node", "kind", "status"] as const) {
          if (params?.[key]) query.set(key, params[key] as string);
        }
        if (params?.within !== undefined && params?.within !== null) {
          query.set("within", String(params.within));
        }
        const qs = query.toString();
        const queryPath = qs ? `/v1/recipients?${qs}` : "/v1/recipients";
        if (this.xmsgUrl) {
          try {
            const res = await fetch(`${this.xmsgUrl}${queryPath}`);
            if (!res.ok) {
              const errText = await res.text();
              return {
                content: [{ type: "text", text: `HTTP ${res.status}: ${errText}` }],
                details: { error: "http_error", status: res.status },
              };
            }
            const data = await res.json();
            return {
              content: [{ type: "text", text: JSON.stringify(data, null, 2) }],
              details: data,
            };
          } catch (err: any) {
            return {
              content: [{ type: "text", text: `Error listing sessions: ${err.message}` }],
              details: { error: "fetch_error", detail: err.message },
            };
          }
        }

        let sockPath: string | undefined;
        try {
          sockPath = await this.endpoint("http");
        } catch (err: any) {
          return {
            content: [{ type: "text", text: `Error listing sessions: ${err.message || err}` }],
            details: { error: "endpoint_refused", detail: String(err.message || err) },
          };
        }
        if (!sockPath) {
          const expectedPath = "$XDG_RUNTIME_DIR/xmsg/http.sock";
          return {
            content: [{ type: "text", text: `Error listing sessions: http.sock path unknown (XDG_RUNTIME_DIR unset; expected ${expectedPath})` }],
            details: { error: "http_sock_unknown", socketPath: expectedPath },
          };
        }

        if (!verifySecureSocketDir(sockPath)) {
          return {
            content: [{ type: "text", text: `Error listing sessions: socket directory failed security check or does not exist for ${sockPath}` }],
            details: { error: "insecure_socket_dir", socketPath: sockPath },
          };
        }

        return new Promise((resolve) => {
          let req: http.ClientRequest;
          try {
            req = http.request(
              {
                socketPath: sockPath,
                path: queryPath,
                method: "GET",
                headers: {
                  host: "localhost",
                },
              },
              (res) => {
                let data = "";
                res.setEncoding("utf8");
                res.on("data", (chunk) => {
                  data += chunk;
                });
                res.on("end", () => {
                  const status = res.statusCode ?? 200;
                  if (status < 200 || status >= 300) {
                    resolve({
                      content: [{ type: "text", text: `HTTP ${status}: ${data}` }],
                      details: { error: "http_error", status, socketPath: sockPath },
                    });
                    return;
                  }
                  try {
                    const json = JSON.parse(data);
                    resolve({
                      content: [{ type: "text", text: JSON.stringify(json, null, 2) }],
                      details: json,
                    });
                  } catch (err: any) {
                    resolve({
                      content: [{ type: "text", text: `Error parsing sessions response from ${sockPath}: ${err.message}` }],
                      details: { error: "parse_error", socketPath: sockPath, detail: err.message },
                    });
                  }
                });
              },
            );
          } catch (err: any) {
            resolve({
              content: [{ type: "text", text: `Error connecting to http socket (${sockPath}): ${err.message}` }],
              details: { error: "socket_error", socketPath: sockPath, detail: err.message },
            });
            return;
          }

          req.on("error", (err: any) => {
            this.endpoints.invalidate();
            resolve({
              content: [{ type: "text", text: `Error connecting to http socket (${sockPath}): ${err.message}` }],
              details: { error: "socket_error", socketPath: sockPath, detail: err.message },
            });
          });

          req.end();
        });
      },
    });
  }

  public registerSendTool() {
    this.pi.registerTool({
      name: "send",
      label: "Send",
      description: "Send a message. `to` is an instance ID (a UUID, optionally ~n), a service name or an instance label, optionally followed by @node to reach another node (one @ at most). A name resolves among services first and only when exactly one live recipient carries it; otherwise the error lists the candidates. Returns the message ID, the resolved address (use it for follow-ups) and the outcome. Your identity is derived from your session; replies are pushed to you.",
      parameters: Type.Object({
        to: Type.String({ description: "<id or name>[@<node>]" }),
        text: Type.String({ description: "Message content" }),
      }),
      execute: async (_toolCallId, params: any) => {
        const req = {
          action: "send",
          schema_version: 2,
          to: params.to,
          text: params.text,
        };
        const resp = await this.callAgentSock(req);
        if (resp.status === "ok") {
          const { status: _status, ...result } = resp;
          return {
            content: [{ type: "text", text: `Message sent to ${resp.address} (id ${resp.message_id}, ${resp.outcome})` }],
            details: result,
          };
        } else {
          return {
            content: [{ type: "text", text: `Error sending message: ${resp.detail || resp.error || JSON.stringify(resp)}` }],
            details: resp,
          };
        }
      },
    });
  }

  public registerReplyTool() {
    this.pi.registerTool({
      name: "reply",
      label: "Reply",
      description: "Reply to a received cross-session message by message_id",
      parameters: Type.Object({
        message_id: Type.String({ description: "The ID of the message being replied to" }),
        text: Type.String({ description: "Reply content" }),
      }),
      execute: async (_toolCallId, params: any) => {
        const req = {
          action: "reply",
          schema_version: 2,
          message_id: params.message_id,
          text: params.text,
        };
        const resp = await this.callAgentSock(req);
        if (resp.status === "ok") {
          return {
            content: [{ type: "text", text: `Reply sent (seq ${resp.reply?.seq})` }],
            details: resp.reply,
          };
        } else if (resp.error === "denied") {
          return {
            content: [{ type: "text", text: `Error: not recipient of message ${params.message_id}` }],
            details: { error: "denied", status: 403, detail: resp.detail },
          };
        } else {
          return {
            content: [{ type: "text", text: `Error sending reply: ${resp.detail || resp.error || JSON.stringify(resp)}` }],
            details: resp,
          };
        }
      },
    });
  }

  public registerRepliesTool() {
    this.pi.registerTool({
      name: "replies",
      label: "Replies",
      description: "Read the stored replies to a message you sent, waiting up to `wait` seconds (at most 60) for the first. Use it after a restart or a missed push, or to send and then block for the answer.",
      parameters: Type.Object({
        message_id: Type.String({ description: "ID of the message you sent" }),
        wait: Type.Optional(Type.Integer({ minimum: 0, description: "Seconds to wait for a first reply (capped at 60)" })),
      }),
      execute: async (_toolCallId, params: any) => {
        const wait = Math.min(params.wait ?? 0, 60);
        const req = { action: "replies", schema_version: 2, message_id: params.message_id, wait };
        const resp = await this.callAgentSock(req);
        if (resp.status === "ok") {
          return {
            content: [{ type: "text", text: JSON.stringify(resp.replies, null, 2) }],
            details: resp.replies,
          };
        }
        return {
          content: [{ type: "text", text: `Error reading replies: ${resp.detail || resp.error || JSON.stringify(resp)}` }],
          details: resp,
        };
      },
    });
  }

  public registerTools() {
    this.registerListTool();
    this.registerSendTool();
    this.registerReplyTool();
    this.registerRepliesTool();
  }
}

export default function (pi: ExtensionAPI) {
  const bridge = new XmsgPiBridge(pi);
  bridge.registerTools();

  pi.on("session_start", async (_event, ctx) => {
    const sessionId = ctx.sessionManager.getSessionId();
    const sessionName = pi.getSessionName();
    const cwd = ctx.cwd || process.cwd();
    bridge.setSession(sessionId, sessionName, cwd);
    bridge.start();
  });

  pi.on("session_shutdown", async () => {
    bridge.stop();
  });

  if (process.env.XMSG_ACTIVITY === "1") {
    let actSeq = 0;
    const emitPiActivity = (ev: string, sessionId: string, block?: string, correlation?: string) => {
      if (!sessionId) return;
      actSeq += 1;
      const frame = JSON.stringify({
        action: "activity",
        schema_version: 1,
        harness: "pi",
        event: ev,
        session: sessionId,
        native_seq: actSeq,
        ...(correlation ? { correlation } : {}),
        ...(block ? { block } : {}),
        background: "absent",
        wake: "absent",
      });
      if (frame.length >= 1024) return;
      bridge.endpoint("agent").then((sock) => {
        if (!sock) return;
        const c = net.createConnection(sock, () => c.end(`${frame}\n`));
        c.setTimeout(50, () => c.destroy());
        c.on("error", () => {});
      }, () => {});
    };
    for (const ev of ["agent_start", "turn_start", "agent_settled", "agent_end"] as const) {
      pi.on(ev as any, async (_e: any, ctx: any) => {
        const sid = ctx?.sessionManager?.getSessionId?.();
        if (sid) emitPiActivity(ev, sid);
      });
    }
    pi.on("ui_prompt_start" as any, async (e: any, ctx: any) => {
      const sid = ctx?.sessionManager?.getSessionId?.();
      if (sid) emitPiActivity("ui_prompt_start", sid, "input", e?.id ? String(e.id) : undefined);
    });
    pi.on("ui_prompt_end" as any, async (e: any, ctx: any) => {
      const sid = ctx?.sessionManager?.getSessionId?.();
      if (sid) emitPiActivity("ui_prompt_end", sid, undefined, e?.id ? String(e.id) : undefined);
    });
  }
}
