import net from "node:net";
import path from "node:path";
import readline from "node:readline";
import { Type } from "typebox";
import type { ExtensionAPI, ExtensionContext } from "@earendil-works/pi-coding-agent";

export function defaultRegisterSockPath(): string {
  if (process.env.XMSG_REGISTER_SOCK) {
    return process.env.XMSG_REGISTER_SOCK;
  }
  if (process.env.XDG_RUNTIME_DIR) {
    return path.join(process.env.XDG_RUNTIME_DIR, "xmsg", "register.sock");
  }
  const uid = typeof process.getuid === "function" ? process.getuid() : 1000;
  return `/tmp/xmsg-${uid}/register.sock`;
}

export function defaultXmsgUrl(): string {
  return (process.env.XMSG_URL || "http://127.0.0.1:7787").replace(/\/$/, "");
}

export interface ExtensionOptions {
  sockPath?: string;
  xmsgUrl?: string;
  pollWaitSecs?: number;
  reconnectDelayMs?: number;
}

export class XmsgPiBridge {
  private pi: ExtensionAPI;
  private sockPath: string;
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
      execute: async (_toolCallId, params, _signal, _onUpdate, ctx) => {
        const sessionId = ctx?.sessionManager?.getSessionId?.() || this.currentSessionId;
        if (!sessionId) {
          return {
            content: [{ type: "text", text: "Error: session ID unknown" }],
            details: { error: "session_id_unknown" },
          };
        }

        const url = `${this.xmsgUrl}/v1/messages/${encodeURIComponent(params.message_id)}/replies`;
        try {
          const res = await fetch(url, {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
              sessionRef: sessionId,
              text: params.text,
            }),
          });

          if (res.status === 201) {
            const data = await res.json();
            return {
              content: [{ type: "text", text: `Reply sent (seq ${data.seq})` }],
              details: data,
            };
          } else if (res.status === 403) {
            const errBody = await res.text();
            return {
              content: [{ type: "text", text: `Error: not recipient of message ${params.message_id}` }],
              details: { error: "not_recipient", status: 403, detail: errBody },
            };
          } else {
            const errBody = await res.text();
            return {
              content: [{ type: "text", text: `Error sending reply (HTTP ${res.status}): ${errBody}` }],
              details: { error: "http_error", status: res.status, detail: errBody },
            };
          }
        } catch (err: any) {
          return {
            content: [{ type: "text", text: `Error sending reply: ${err.message || String(err)}` }],
            details: { error: "network_error", detail: String(err) },
          };
        }
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
