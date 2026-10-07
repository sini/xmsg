import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import readline from "node:readline";
import { Type } from "typebox";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

export function defaultRegisterSockPath(): string | undefined {
  if (process.env.XMSG_REGISTER_SOCK) {
    return process.env.XMSG_REGISTER_SOCK;
  }
  if (process.env.XDG_RUNTIME_DIR) {
    return path.join(process.env.XDG_RUNTIME_DIR, "xmsg", "register.sock");
  }
  return undefined;
}

export function defaultAgentSockPath(): string | undefined {
  if (process.env.XMSG_AGENT_SOCK) {
    return process.env.XMSG_AGENT_SOCK;
  }
  if (process.env.XDG_RUNTIME_DIR) {
    return path.join(process.env.XDG_RUNTIME_DIR, "xmsg", "agent.sock");
  }
  return undefined;
}

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

export function defaultXmsgUrl(): string {
  return (process.env.XMSG_URL || "http://127.0.0.1:7787").replace(/\/$/, "");
}

export interface ExtensionOptions {
  sockPath?: string;
  agentSockPath?: string;
  xmsgUrl?: string;
  pollWaitSecs?: number;
  reconnectDelayMs?: number;
}

export class XmsgPiBridge {
  private pi: ExtensionAPI;
  private sockPath?: string;
  private agentSockPath?: string;
  private xmsgUrl: string;
  private pollWaitSecs: number;
  private reconnectDelayMs: number;
  private socket?: net.Socket;
  private rl?: readline.Interface;
  private running = false;
  private currentSessionId?: string;
  private currentSessionName?: string;
  private currentCwd?: string;

  constructor(pi: ExtensionAPI, options: ExtensionOptions = {}) {
    this.pi = pi;
    this.sockPath = options.sockPath || defaultRegisterSockPath();
    this.agentSockPath = options.agentSockPath || defaultAgentSockPath();
    this.xmsgUrl = options.xmsgUrl || defaultXmsgUrl();
    this.pollWaitSecs = options.pollWaitSecs ?? 30;
    this.reconnectDelayMs = options.reconnectDelayMs ?? 1500;
  }

  public setSession(sessionId: string, sessionName?: string, cwd?: string) {
    this.currentSessionId = sessionId;
    this.currentSessionName = sessionName;
    this.currentCwd = cwd || process.cwd();
  }

  public getSessionId(): string | undefined {
    return this.currentSessionId;
  }

  public start() {
    if (this.running) return;
    if (!this.sockPath) {
      console.warn("[xmsg-pi] XDG_RUNTIME_DIR is not set and no sockPath provided; disabling socket polling");
      return;
    }
    if (!verifySecureSocketDir(this.sockPath)) {
      console.warn(`[xmsg-pi] socket directory for ${this.sockPath} failed security check; disabling socket polling`);
      return;
    }
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
      if (!this.currentSessionId) {
        await new Promise((r) => setTimeout(r, 500));
        continue;
      }

      try {
        await this.runConnection();
      } catch (_err) {
        // connection closed or failed
      }

      if (this.running) {
        await new Promise((r) => setTimeout(r, this.reconnectDelayMs));
      }
    }
  }

  private runConnection(): Promise<void> {
    return new Promise((resolve, reject) => {
      if (!this.sockPath) {
        return resolve();
      }
      const socket = net.connect(this.sockPath);
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
          // 1. Send registration
          const regPayload = {
            harness: "pi",
            sessionId: this.currentSessionId,
            sessionName: this.currentSessionName,
            cwd: this.currentCwd,
          };
          socket.write(JSON.stringify(regPayload) + "\n");

          // 2. Read registration response
          const regRespItem = await lineIterator.next();
          if (regRespItem.done) throw new Error("Socket closed before registration response");
          const regResp = JSON.parse(regRespItem.value);
          if (regResp.status !== "ok") {
            throw new Error(`Registration failed: ${regResp.detail || JSON.stringify(regResp)}`);
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

  public registerReplyTool() {
    this.pi.registerTool({
      name: "reply",
      label: "Reply",
      description: "Reply to a received cross-session message by message_id",
      parameters: Type.Object({
        message_id: Type.String({ description: "The ID of the message being replied to" }),
        text: Type.String({ description: "Reply content" }),
      }),
      execute: async (_toolCallId, params) => {
        if (!this.agentSockPath) {
          return {
            content: [{ type: "text", text: "Error: agent.sock path unknown (XDG_RUNTIME_DIR unset)" }],
            details: { error: "agent_sock_unknown" },
          };
        }
        if (!verifySecureSocketDir(this.agentSockPath)) {
          return {
            content: [{ type: "text", text: "Error: agent.sock directory failed security check" }],
            details: { error: "insecure_socket_dir" },
          };
        }

        return new Promise((resolve) => {
          let client: net.Socket;
          try {
            client = net.connect(this.agentSockPath!, () => {
              const req = {
                action: "reply",
                messageId: params.message_id,
                text: params.text,
              };
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
              if (resp.status === "ok") {
                resolve({
                  content: [{ type: "text", text: `Reply sent (seq ${resp.reply.seq})` }],
                  details: resp.reply,
                });
              } else if (resp.error === "not_recipient") {
                resolve({
                  content: [{ type: "text", text: `Error: not recipient of message ${params.message_id}` }],
                  details: { error: "not_recipient", status: 403, detail: resp.detail },
                });
              } else {
                resolve({
                  content: [{ type: "text", text: `Error sending reply: ${resp.detail || resp.error}` }],
                  details: resp,
                });
              }
            } catch (err: any) {
              resolve({
                content: [{ type: "text", text: `Error parsing agent response: ${err.message}` }],
                details: { error: "parse_error", detail: String(err) },
              });
            }
          });
        });
      },
    });
  }
}

export default function (pi: ExtensionAPI) {
  const bridge = new XmsgPiBridge(pi);
  bridge.registerReplyTool();

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
}
