import { CLIENT_DEFAULTS, RosterStore } from "./projection.ts";
import { DecodeError, decodeServerMessage, utf8ByteLength } from "./protocol.ts";
import { RosterRenderer } from "./render.ts";

const RECONNECT_BASE_MS = CLIENT_DEFAULTS.reconnect_base_ms;
const RECONNECT_CAP_MS = CLIENT_DEFAULTS.reconnect_cap_ms;
const RECONNECT_MAX_ATTEMPTS = CLIENT_DEFAULTS.reconnect_max_attempts;

class MissionControlClient {
  private readonly store = new RosterStore();
  private readonly renderer: RosterRenderer;
  private ws: WebSocket | null = null;
  private nextId = 1;
  private backoffAttempt = 0;
  private reconnectTimer: number | null = null;
  private syncResetTimer: number | null = null;
  private uiTickTimer: number | null = null;
  private openedThisAttempt = false;
  private readmit4401Active = false;
  private readmit4403Active = false;

  constructor(liveRoot: HTMLElement, ssrRoot: HTMLElement | null) {
    this.renderer = new RosterRenderer(liveRoot, ssrRoot);
  }

  start(): void {
    this.renderNow();
    this.connect();
    this.uiTickTimer = window.setInterval(() => {
      this.renderNow();
    }, 1000);
  }

  private renderNow(): void {
    this.renderer.render(this.store, Date.now(), {
      onSelectNode: (nodeName) => this.selectNode(nodeName),
      onReconnect: () => this.manualReconnect(),
    });
  }

  private manualReconnect(): void {
    if (this.store.stoppedAuth || this.store.stoppedIncompatible) return;
    this.backoffAttempt = 0;
    this.store.resetForManualReconnect();
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.connect();
  }

  private selectNode(nodeName: string | null): void {
    if (this.store.selectedDetailSub) {
      const oldSub = this.store.selectedDetailSub;
      this.store.retireSub(oldSub);
      this.store.selectedDetailSub = null;
      this.sendJson({ v: 1, type: "unsubscribe", id: this.nextId++, sub: oldSub });
    }
    this.store.selectedNode = nodeName;
    if (nodeName) {
      const nv = this.store.nodes.get(nodeName);
      if (nv && nv.status !== "removed_retained") {
        const rec = this.store.allocSub("node", nodeName);
        this.store.selectedDetailSub = rec.sub;
        const msg: Record<string, unknown> = {
          v: 1,
          type: "subscribe",
          id: this.nextId++,
          sub: rec.sub,
          scope: { kind: "node", node: nodeName },
        };
        if (rec.cursor) msg.cursor = rec.cursor;
        this.sendJson(msg);
      }
    }
    this.renderNow();
  }

  private sendJson(obj: Record<string, unknown>): void {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(obj));
    }
  }

  private connect(): void {
    if (this.store.stoppedAuth || this.store.stoppedIncompatible) return;
    if (this.reconnectTimer !== null) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    const proto = window.location.protocol === "https:" ? "wss:" : "ws:";
    const url = `${proto}//${window.location.host}/v1/mission-control/session`;
    this.openedThisAttempt = false;
    this.store.noteDialAttempt(Date.now());
    const ws = new WebSocket(url, "xmsg.mission-control.v1");
    this.ws = ws;

    ws.addEventListener("open", () => {
      if (this.ws !== ws) return;
      this.openedThisAttempt = true;
      this.store.wsOpen = true;
      this.store.reconnecting = false;
      this.store.reconnectExhausted = false;
      this.store.defectMessage = null;

      this.sendJson({
        v: 1,
        type: "hello",
        id: this.nextId++,
        protocol: 1,
        capabilities: ["observe", "activity"],
        require: ["observe"],
        client: { name: "mc-web", version: "0.1.0" },
      });

      const fleetSub = this.store.allocSub("fleet");
      const attSub = this.store.allocSub("attention");
      this.sendSubscribe(fleetSub.sub, { kind: "fleet" }, fleetSub.cursor);
      this.sendSubscribe(attSub.sub, { kind: "attention" }, attSub.cursor);

      if (this.store.selectedNode) {
        const nv = this.store.nodes.get(this.store.selectedNode);
        if (nv && nv.status !== "removed_retained") {
          const nodeSub = this.store.allocSub("node", this.store.selectedNode);
          this.store.selectedDetailSub = nodeSub.sub;
          this.sendSubscribe(nodeSub.sub, { kind: "node", node: this.store.selectedNode }, nodeSub.cursor);
        }
      }

      if (this.syncResetTimer !== null) clearTimeout(this.syncResetTimer);
      this.syncResetTimer = window.setTimeout(() => {
        if (this.store.wsOpen) {
          this.backoffAttempt = 0;
          this.readmit4401Active = false;
          this.readmit4403Active = false;
        }
      }, 60_000);

      this.renderNow();
    });

    ws.addEventListener("message", (ev) => {
      if (this.ws !== ws) return;
      if (typeof ev.data !== "string") {
        // Binary frames violate text-only contract -> close 1003/4400.
        this.store.defectMessage = "binary frame received";
        ws.close(4400, "binary frame");
        this.renderNow();
        return;
      }
      try {
        const rawBytes = utf8ByteLength(ev.data);
        const msg = decodeServerMessage(ev.data, this.store.maxServerMessageBytes);
        const changed = this.store.applyMessage(msg, rawBytes, Date.now());
        if (msg.type === "snapshot" && msg.final && msg.sub === "fleet") {
          this.readmit4401Active = false;
          this.readmit4403Active = false;
        }
        if (changed || msg.type === "hello") {
          this.renderNow();
        }
      } catch (err) {
        this.store.defectMessage = err instanceof DecodeError ? err.message : "protocol decode error";
        ws.close(4400, "decode error");
        this.renderNow();
      }
    });

    ws.addEventListener("close", (ev) => {
      if (this.ws !== ws) return;
      this.ws = null;
      this.store.wsOpen = false;
      if (this.syncResetTimer !== null) {
        clearTimeout(this.syncResetTimer);
        this.syncResetTimer = null;
      }

      if (!this.openedThisAttempt) {
        void this.handleFailedUpgrade();
        return;
      }

      this.handleOpenClose(ev.code);
    });
  }

  private sendSubscribe(sub: string, scope: Record<string, unknown>, cursor?: string): void {
    const msg: Record<string, unknown> = { v: 1, type: "subscribe", id: this.nextId++, sub, scope };
    if (cursor) msg.cursor = cursor;
    this.sendJson(msg);
  }

  private async handleFailedUpgrade(): Promise<void> {
    if (this.readmit4401Active || this.readmit4403Active) {
      this.stopForReauth();
      return;
    }
    try {
      const res = await fetch("/v1/mission-control/snapshot/attention", { redirect: "manual" });
      if (res.type === "opaqueredirect" || res.status === 401 || res.status === 403) {
        this.stopForReauth();
        return;
      }
      // Discard any 200 body and resume backoff for transient failures (e.g. 503).
    } catch {
      // Network error -> backoff.
    }
    this.scheduleBackoff(0);
  }

  private handleOpenClose(code: number): void {
    if (code === 4409) {
      this.store.stoppedIncompatible = true;
      this.store.reconnecting = false;
      this.renderNow();
      return;
    }
    if (code === 4401) {
      if (this.readmit4401Active) {
        this.stopForReauth();
        return;
      }
      this.readmit4401Active = true;
      this.store.reconnecting = true;
      this.renderNow();
      this.connect();
      return;
    }
    if (code === 4403) {
      this.store.invalidateOnPolicyOrScope();
      if (this.readmit4403Active) {
        this.stopForReauth();
        return;
      }
      this.readmit4403Active = true;
      this.store.reconnecting = true;
      this.renderNow();
      this.connect();
      return;
    }
    if (code === 1000) {
      this.store.reconnecting = false;
      this.renderNow();
      return;
    }
    const extraJitter = code === 1001 ? Math.floor(Math.random() * 2000) : 0;
    this.scheduleBackoff(extraJitter);
  }

  private stopForReauth(): void {
    this.store.stoppedAuth = true;
    this.store.reconnecting = false;
    this.store.clearAllForReauth();
    this.renderNow();
  }

  private scheduleBackoff(extraMs: number): void {
    if (this.backoffAttempt >= RECONNECT_MAX_ATTEMPTS) {
      this.store.reconnecting = false;
      this.store.reconnectExhausted = true;
      this.renderNow();
      return;
    }
    this.store.reconnecting = true;
    const cap = Math.min(RECONNECT_CAP_MS, RECONNECT_BASE_MS * Math.pow(2, this.backoffAttempt));
    const delay = Math.floor(Math.random() * cap) + extraMs;
    this.backoffAttempt++;
    this.renderNow();
    this.reconnectTimer = window.setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, delay);
  }
}

window.addEventListener("DOMContentLoaded", () => {
  const liveRoot = document.getElementById("mc-live");
  if (!liveRoot) return;
  const ssrRoot = document.getElementById("mc-ssr");
  const client = new MissionControlClient(liveRoot, ssrRoot);
  client.start();
});
