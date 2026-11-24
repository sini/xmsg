import { DecodeError, DEFAULT_SNAPSHOT_MAX_BYTES } from "./protocol.ts";
import type {
  ActivityDescriptor,
  AttentionItem,
  EndpointEntry,
  ExportEvent,
  ExportGap,
  NodeView,
  ServerMessage,
} from "./protocol.ts";

export type ScopeKind = "fleet" | "attention" | "node";

export interface SubRecord {
  sub: string;
  kind: ScopeKind;
  node?: string;
  active: boolean;
  synced: boolean;
  streamEpoch?: string;
  cursor?: string;
  lastSeq?: number;
  pendingParts: Extract<ServerMessage, { type: "snapshot" }>[];
  pendingBytes: number;
  pendingEpoch?: string;
}

export type ConnectionBadge = "Unknown" | "Live" | "Delayed" | "Reconnecting" | "Stale";

const NON_ELIGIBLE_STATUS = new Set([
  "removed_retained",
  "loading",
  "denied",
  "unsupported_outbound_only",
  "unsupported_transport",
]);

export const REASON_PLAIN: Record<string, string> = {
  background: "running in background",
  scheduled_wake: "scheduled wake",
  aged: "activity aged out",
  restarted: "daemon restarted",
  contradictory: "contradictory evidence",
  unverified: "owner unverified",
  evidence_lost: "evidence lost",
  registry_unavailable: "registry unavailable",
  unreported: "not reported",
  incarnation_ended: "session ended",
};

export function plainReason(reason?: string): string {
  if (!reason) return "";
  return REASON_PLAIN[reason] ?? reason;
}

export function activityGlyph(act?: ActivityDescriptor, kind?: string): { glyph: string; label: string } {
  if (kind === "service") return { glyph: "·", label: "service" };
  if (!act) return { glyph: "?", label: "unknown" };
  if (act.state === "blocked") {
    return act.block === "input" ? { glyph: "◆", label: "needs input" } : { glyph: "▲", label: "needs permission" };
  }
  if (act.state === "working") {
    return act.reason === "background" ? { glyph: "▷", label: "working (background)" } : { glyph: "▶", label: "working" };
  }
  if (act.state === "idle") {
    return act.reason === "scheduled_wake" ? { glyph: "◷", label: "idle (scheduled wake)" } : { glyph: "○", label: "idle" };
  }
  return { glyph: "?", label: "unknown" };
}

function sortRank(entry: EndpointEntry, nodeStale: boolean): number {
  if (entry.descriptor.kind === "service") return 5;
  const stale = nodeStale || entry.activity_stale === true;
  const act = entry.activity;
  if (!act) return 4;
  if (act.state === "blocked") {
    if (stale) return 4; // Stale blocked never sorts into needs-you
    return act.block === "input" ? 0 : 1;
  }
  if (act.state === "working") return 2;
  if (act.state === "idle") return 3;
  return 4;
}

export function sortEndpoints(endpoints: EndpointEntry[], nodeStale: boolean): EndpointEntry[] {
  return [...endpoints].sort((a, b) => {
    const ra = sortRank(a, nodeStale);
    const rb = sortRank(b, nodeStale);
    if (ra !== rb) return ra - rb;
    return a.descriptor.id.localeCompare(b.descriptor.id);
  });
}

export function formatAgeMs(deltaMs: number): string {
  const s = Math.max(0, Math.floor(deltaMs / 1000));
  if (s < 60) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 60) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h`;
  return `${Math.floor(h / 24)}d`;
}

export class RosterStore {
  readonly subs = new Map<string, SubRecord>();
  private nextSubSeq = 1;
  nodeOrder: string[] = [];
  nodes = new Map<string, NodeView>();
  attention = new Map<string, AttentionItem>();
  selectedNode: string | null = null;
  selectedDetailSub: string | null = null;
  fleetTruncated = false;

  wsOpen = false;
  reconnecting = false;
  stoppedAuth = false;
  stoppedIncompatible = false;
  defectMessage: string | null = null;

  serverAtMs = 0;
  clientAtServerMs = 0;
  lastServerMessageAtMs = 0;
  lastRealEventAtMs = 0;
  tickIntervalMs = 15_000;
  staleAfterMs = 60_000;
  maxServerMessageBytes = 262_144;
  snapshotMaxBytes = DEFAULT_SNAPSHOT_MAX_BYTES;
  capabilities: string[] = [];

  private initialFleetApplied = false;
  private announcedBlocked = new Set<string>();
  pendingAnnouncements: string[] = [];

  allocSub(kind: ScopeKind, node?: string): SubRecord {
    const sub = kind === "fleet" ? "fleet" : kind === "attention" ? "att" : `n${this.nextSubSeq++}`;
    const existing = this.subs.get(sub);
    const rec: SubRecord = {
      sub,
      kind,
      node,
      active: true,
      synced: false,
      cursor: existing?.cursor,
      streamEpoch: existing?.streamEpoch,
      pendingParts: [],
      pendingBytes: 0,
    };
    this.subs.set(sub, rec);
    return rec;
  }

  retireSub(sub: string): void {
    const rec = this.subs.get(sub);
    if (rec) {
      rec.active = false;
      rec.pendingParts = [];
      rec.pendingBytes = 0;
      rec.pendingEpoch = undefined;
    }
  }

  clearAllForReauth(): void {
    this.nodes.clear();
    this.nodeOrder = [];
    this.attention.clear();
    this.selectedNode = null;
    this.selectedDetailSub = null;
    this.fleetTruncated = false;
    this.initialFleetApplied = false;
    this.announcedBlocked.clear();
    this.pendingAnnouncements = [];
    for (const rec of this.subs.values()) {
      rec.synced = false;
      rec.cursor = undefined;
      rec.streamEpoch = undefined;
      rec.pendingParts = [];
      rec.pendingBytes = 0;
      rec.pendingEpoch = undefined;
    }
  }

  invalidateOnPolicyOrScope(): void {
    this.clearAllForReauth();
  }

  invalidateNode(nodeName: string): void {
    const existing = this.nodes.get(nodeName);
    if (existing) {
      existing.endpoints = [];
      existing.exchanges = [];
      existing.source_gaps = [];
    }
    if (this.selectedNode === nodeName) {
      this.selectedNode = null;
      if (this.selectedDetailSub) {
        this.retireSub(this.selectedDetailSub);
        this.selectedDetailSub = null;
      }
    }
    for (const rec of this.subs.values()) {
      if (rec.kind === "node" && rec.node === nodeName) {
        rec.cursor = undefined;
        rec.synced = false;
        rec.pendingParts = [];
        rec.pendingBytes = 0;
        rec.pendingEpoch = undefined;
      }
    }
  }

  nowServerMs(nowClientMs: number): number {
    if (!this.serverAtMs) return nowClientMs;
    return this.serverAtMs + (nowClientMs - this.clientAtServerMs);
  }

  connectionBadge(nowClientMs: number): ConnectionBadge {
    if (this.stoppedAuth || this.stoppedIncompatible) return "Unknown";
    const fleetSub = this.subs.get("fleet");
    if (this.reconnecting) {
      if (this.lastServerMessageAtMs && nowClientMs - this.lastServerMessageAtMs >= this.staleAfterMs) {
        return "Stale";
      }
      return "Reconnecting";
    }
    if (!this.wsOpen || !fleetSub || !fleetSub.synced) return "Unknown";
    if (this.lastServerMessageAtMs && nowClientMs - this.lastServerMessageAtMs >= this.staleAfterMs) {
      return "Stale";
    }
    const allNodes = this.nodeOrder.map((n) => this.nodes.get(n)).filter((n): n is NodeView => Boolean(n));
    const eligible = allNodes.filter((n) => !NON_ELIGIBLE_STATUS.has(n.status));
    if (eligible.length >= 1) {
      return eligible.some((n) => n.delivery === "delayed") ? "Delayed" : "Live";
    }
    // Zero eligible current nodes: Delayed if any non-removed node in view is delayed, else Unknown.
    if (allNodes.some((n) => n.status !== "removed_retained" && n.delivery === "delayed")) {
      return "Delayed";
    }
    return "Unknown";
  }

  isNodeUnreachable(nodeName: string): boolean {
    for (const item of this.attention.values()) {
      if (item.kind === "node_unreachable" && item.node === nodeName) return true;
    }
    return false;
  }

  applyMessage(msg: ServerMessage, rawBytes: number, nowClientMs: number): boolean {
    this.lastServerMessageAtMs = nowClientMs;

    switch (msg.type) {
      case "hello": {
        this.serverAtMs = msg.server_at;
        this.clientAtServerMs = nowClientMs;
        this.tickIntervalMs = msg.limits.tick_interval_ms;
        this.maxServerMessageBytes = msg.limits.max_server_message_bytes;
        this.capabilities = msg.capabilities;
        return false;
      }
      case "tick": {
        // tick proves transport only; never updates lastRealEventAtMs or node source ages.
        this.serverAtMs = msg.server_at;
        this.clientAtServerMs = nowClientMs;
        return false;
      }
      case "subscribed": {
        const rec = this.subs.get(msg.sub);
        if (!rec || !rec.active) return false;
        rec.streamEpoch = msg.stream_epoch;
        if (msg.mode === "resume") rec.synced = true;
        return false;
      }
      case "unsubscribed": {
        this.retireSub(msg.sub);
        return false;
      }
      case "error": {
        if (msg.code === "not_found_or_denied" && msg.re !== undefined) {
          // If node detail sub failed, close detail.
          if (this.selectedDetailSub) {
            this.retireSub(this.selectedDetailSub);
            this.selectedDetailSub = null;
            this.selectedNode = null;
          }
          return true;
        }
        return false;
      }
      case "gap": {
        const rec = this.subs.get(msg.sub);
        if (!rec || !rec.active) return false;
        if (msg.reset) {
          rec.synced = false;
          rec.cursor = undefined;
          rec.pendingParts = [];
          rec.pendingBytes = 0;
          rec.pendingEpoch = undefined;
          if (msg.reason === "scope_changed") {
            if (rec.kind === "fleet") this.invalidateOnPolicyOrScope();
            else if (rec.kind === "node" && rec.node) this.invalidateNode(rec.node);
          } else if (rec.kind === "fleet") {
            this.nodes.clear();
            this.nodeOrder = [];
          } else if (rec.kind === "attention") {
            this.attention.clear();
          }
          return true;
        }
        return false;
      }
      case "snapshot": {
        const rec = this.subs.get(msg.sub);
        if (!rec || !rec.active) return false; // Ignore late frames for retired sub.
        const expectedPart = rec.pendingParts.length;
        if (msg.part !== expectedPart) {
          throw new DecodeError(`out-of-order snapshot part ${msg.part} (expected ${expectedPart})`);
        }
        if (rec.pendingEpoch === undefined) {
          rec.pendingEpoch = msg.stream_epoch;
        } else if (msg.stream_epoch !== rec.pendingEpoch) {
          throw new DecodeError(`snapshot stream_epoch mismatch`);
        }
        if (rec.pendingBytes + rawBytes > this.snapshotMaxBytes) {
          throw new DecodeError(`multipart snapshot exceeds ${this.snapshotMaxBytes} bytes`);
        }
        rec.pendingParts.push(msg);
        rec.pendingBytes += rawBytes;

        if (!msg.final) return false;

        // Atomic commit at final: true
        const parts = rec.pendingParts;
        rec.pendingParts = [];
        rec.pendingBytes = 0;
        rec.pendingEpoch = undefined;
        rec.streamEpoch = msg.stream_epoch;
        rec.cursor = msg.cursor;
        rec.synced = true;
        this.serverAtMs = msg.server_at;
        this.clientAtServerMs = nowClientMs;
        this.lastRealEventAtMs = nowClientMs;

        if (rec.kind === "fleet") {
          this.fleetTruncated = Boolean(msg.truncated);
          const nextOrder: string[] = [];
          const nextMap = new Map<string, NodeView>();
          for (const p of parts) {
            for (const nv of p.nodes) {
              nextOrder.push(nv.node);
              nextMap.set(nv.node, nv);
            }
          }
          this.nodeOrder = nextOrder;
          this.nodes = nextMap;
          this.initialFleetApplied = true;
        } else if (rec.kind === "attention") {
          const nextAtt = new Map<string, AttentionItem>();
          for (const p of parts) {
            for (const item of p.attention ?? []) {
              nextAtt.set(item.id, item);
            }
          }
          this.attention = nextAtt;
        } else if (rec.kind === "node" && rec.node) {
          for (const p of parts) {
            for (const nv of p.nodes) {
              if (nv.node === rec.node) {
                this.nodes.set(nv.node, nv);
              }
            }
          }
        }
        return true;
      }
      case "event": {
        const rec = this.subs.get(msg.sub);
        if (!rec || !rec.active) return false;
        rec.cursor = msg.cursor;
        rec.lastSeq = msg.seq;
        this.lastRealEventAtMs = nowClientMs;
        const d = msg.delta;
        const kind = d.kind as string;

        if (kind === "node_status") {
          const nodeName = d.node as string;
          const existing = this.nodes.get(nodeName);
          const nextStatus = d.status as string;
          const hidden = d.history_hidden as boolean;
          if (existing) {
            existing.status = nextStatus;
            existing.delivery = d.delivery as "live" | "delayed";
            existing.last_success_at = d.last_success_at as number | undefined;
            existing.last_source_at = d.last_source_at as number | undefined;
            existing.via_hub = d.via_hub as string | undefined;
            existing.history_hidden = hidden;
            if (hidden || nextStatus === "removed_retained") {
              this.invalidateNode(nodeName);
            }
          }
          return true;
        }
        if (kind === "endpoint_upserted") {
          const nodeName = d.node as string;
          const nv = this.nodes.get(nodeName);
          if (nv && !nv.history_hidden && nv.status !== "removed_retained") {
            const entry: EndpointEntry = {
              descriptor: d.descriptor as EndpointEntry["descriptor"],
              activity: d.activity as ActivityDescriptor | undefined,
              activity_stale: d.activity_stale as boolean | undefined,
            };
            const idx = nv.endpoints.findIndex((e) => e.descriptor.id === entry.descriptor.id);
            if (idx >= 0) nv.endpoints[idx] = entry;
            else nv.endpoints.push(entry);
            this.maybeQueueAnnouncement(nodeName, entry, msg.replayed === true);
          }
          return true;
        }
        if (kind === "endpoint_removed") {
          const nodeName = d.node as string;
          const nv = this.nodes.get(nodeName);
          if (nv) {
            nv.endpoints = nv.endpoints.filter((e) => e.descriptor.id !== (d.id as string));
          }
          return true;
        }
        if (kind === "activity_changed") {
          const nodeName = d.node as string;
          const nv = this.nodes.get(nodeName);
          const ev = d.event as ExportEvent;
          if (nv && !nv.history_hidden && nv.status !== "removed_retained" && ev.from && ev.activity) {
            const ep = nv.endpoints.find((e) => e.descriptor.id === ev.from);
            if (ep) {
              ep.activity = ev.activity;
              ep.activity_stale = false;
              this.maybeQueueAnnouncement(nodeName, ep, msg.replayed === true);
            }
          }
          return true;
        }
        if (kind === "exchange") {
          const nodeName = d.node as string;
          const nv = this.nodes.get(nodeName);
          const ev = d.event as ExportEvent;
          if (nv && !nv.history_hidden && nv.status !== "removed_retained") {
            nv.exchanges.push({ event: ev });
            if (nv.exchanges.length > 200) nv.exchanges.shift();
          }
          return true;
        }
        if (kind === "source_gap") {
          const nodeName = d.node as string;
          const nv = this.nodes.get(nodeName);
          if (nv && !nv.history_hidden && nv.status !== "removed_retained") {
            nv.source_gaps.push(d.gap as ExportGap);
          }
          return true;
        }
        if (kind === "attention_upserted") {
          const item = d.item as AttentionItem;
          this.attention.set(item.id, item);
          return true;
        }
        if (kind === "attention_cleared") {
          this.attention.delete(d.id as string);
          return true;
        }
        return false;
      }
    }
  }

  private maybeQueueAnnouncement(nodeName: string, entry: EndpointEntry, replayed: boolean): void {
    if (!this.initialFleetApplied || replayed) return;
    if (entry.activity_stale || entry.activity?.state !== "blocked") return;
    const key = `${nodeName}:${entry.descriptor.id}:${entry.activity.revision}`;
    if (this.announcedBlocked.has(key)) return;
    this.announcedBlocked.add(key);
    const label = entry.descriptor.label ?? entry.descriptor.id;
    const kind = entry.activity.block === "input" ? "needs input" : "needs permission";
    this.pendingAnnouncements.push(`${label} on ${nodeName}: ${kind}`);
  }
}
