// Strict xmsg.mission-control.v1 JSON decoder and §2.5.1 validator.
// Zero external dependencies; enforces depth <= 16, string <= 4096 bytes,
// no duplicate object keys, closed enums (except descriptor.harness), and
// no unknown fields at any level.

export const DEFAULT_MAX_SERVER_MESSAGE_BYTES = 262_144;
export const DEFAULT_SNAPSHOT_MAX_BYTES = 4 * 1024 * 1024;
export const MAX_JSON_DEPTH = 16;
export const MAX_STRING_BYTES = 4096;
export const SUB_RE = /^[a-z0-9_-]{1,32}$/;

const textEncoder = new TextEncoder();

export class DecodeError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "DecodeError";
  }
}

export function utf8ByteLength(s: string): number {
  return textEncoder.encode(s).length;
}

// Strict recursive-descent JSON parser enforcing:
// - depth <= MAX_JSON_DEPTH (16)
// - string UTF-8 length <= MAX_STRING_BYTES (4096)
// - no duplicate object keys
// - finite safe integers for integer fields (checked by schema)
export function parseStrictJson(raw: string): unknown {
  let pos = 0;
  const len = raw.length;

  function skipWs(): void {
    while (pos < len) {
      const c = raw.charCodeAt(pos);
      if (c === 0x20 || c === 0x09 || c === 0x0a || c === 0x0d) {
        pos++;
      } else {
        break;
      }
    }
  }

  function parseValue(depth: number): unknown {
    skipWs();
    if (pos >= len) throw new DecodeError("unexpected end of JSON");
    const c = raw.charCodeAt(pos);
    if (c === 0x7b) return parseObject(depth + 1); // '{'
    if (c === 0x5b) return parseArray(depth + 1); // '['
    if (c === 0x22) return parseString(); // '"'
    if (c === 0x74) return parseLiteral("true", true);
    if (c === 0x66) return parseLiteral("false", false);
    if (c === 0x6e) return parseLiteral("null", null);
    if (c === 0x2d || (c >= 0x30 && c <= 0x39)) return parseNumber();
    throw new DecodeError(`unexpected character at ${pos}`);
  }

  function parseLiteral<T>(lit: string, val: T): T {
    if (raw.startsWith(lit, pos)) {
      pos += lit.length;
      return val;
    }
    throw new DecodeError(`expected ${lit} at ${pos}`);
  }

  function parseString(): string {
    if (raw.charCodeAt(pos) !== 0x22) throw new DecodeError("expected string");
    const start = pos;
    pos++;
    let hasEscape = false;
    while (pos < len) {
      const c = raw.charCodeAt(pos);
      if (c === 0x22) {
        pos++;
        const slice = raw.slice(start, pos);
        const val = hasEscape ? (JSON.parse(slice) as string) : slice.slice(1, -1);
        if (utf8ByteLength(val) > MAX_STRING_BYTES) {
          throw new DecodeError(`string exceeds ${MAX_STRING_BYTES} bytes`);
        }
        return val;
      }
      if (c === 0x5c) {
        hasEscape = true;
        pos += 2;
        continue;
      }
      if (c < 0x20) {
        throw new DecodeError("unescaped control char in string");
      }
      pos++;
    }
    throw new DecodeError("unterminated string");
  }

  function parseNumber(): number {
    const start = pos;
    if (raw.charCodeAt(pos) === 0x2d) pos++;
    if (pos >= len) throw new DecodeError("invalid number");
    if (raw.charCodeAt(pos) === 0x30) {
      pos++;
    } else if (raw.charCodeAt(pos) >= 0x31 && raw.charCodeAt(pos) <= 0x39) {
      while (pos < len && raw.charCodeAt(pos) >= 0x30 && raw.charCodeAt(pos) <= 0x39) pos++;
    } else {
      throw new DecodeError("invalid number");
    }
    if (pos < len && raw.charCodeAt(pos) === 0x2e) {
      pos++;
      if (pos >= len || raw.charCodeAt(pos) < 0x30 || raw.charCodeAt(pos) > 0x39) {
        throw new DecodeError("invalid fraction");
      }
      while (pos < len && raw.charCodeAt(pos) >= 0x30 && raw.charCodeAt(pos) <= 0x39) pos++;
    }
    if (pos < len && (raw.charCodeAt(pos) === 0x65 || raw.charCodeAt(pos) === 0x45)) {
      pos++;
      if (pos < len && (raw.charCodeAt(pos) === 0x2b || raw.charCodeAt(pos) === 0x2d)) pos++;
      if (pos >= len || raw.charCodeAt(pos) < 0x30 || raw.charCodeAt(pos) > 0x39) {
        throw new DecodeError("invalid exponent");
      }
      while (pos < len && raw.charCodeAt(pos) >= 0x30 && raw.charCodeAt(pos) <= 0x39) pos++;
    }
    const num = Number(raw.slice(start, pos));
    if (!Number.isFinite(num)) throw new DecodeError("non-finite number");
    return num;
  }

  function parseArray(depth: number): unknown[] {
    if (depth > MAX_JSON_DEPTH) throw new DecodeError(`JSON depth exceeds ${MAX_JSON_DEPTH}`);
    pos++; // '['
    skipWs();
    const out: unknown[] = [];
    if (pos < len && raw.charCodeAt(pos) === 0x5d) {
      pos++;
      return out;
    }
    while (true) {
      out.push(parseValue(depth));
      skipWs();
      if (pos >= len) throw new DecodeError("unterminated array");
      const c = raw.charCodeAt(pos);
      if (c === 0x5d) {
        pos++;
        return out;
      }
      if (c !== 0x2c) throw new DecodeError("expected ',' or ']'");
      pos++;
    }
  }

  function parseObject(depth: number): Record<string, unknown> {
    if (depth > MAX_JSON_DEPTH) throw new DecodeError(`JSON depth exceeds ${MAX_JSON_DEPTH}`);
    pos++; // '{'
    skipWs();
    const out: Record<string, unknown> = Object.create(null);
    const seen = new Set<string>();
    if (pos < len && raw.charCodeAt(pos) === 0x7d) {
      pos++;
      return out;
    }
    while (true) {
      skipWs();
      const key = parseString();
      if (seen.has(key)) throw new DecodeError(`duplicate object key: ${key}`);
      seen.add(key);
      skipWs();
      if (pos >= len || raw.charCodeAt(pos) !== 0x3a) throw new DecodeError("expected ':'");
      pos++;
      const val = parseValue(depth);
      Object.defineProperty(out, key, { value: val, enumerable: true, configurable: true, writable: true });
      skipWs();
      if (pos >= len) throw new DecodeError("unterminated object");
      const c = raw.charCodeAt(pos);
      if (c === 0x7d) {
        pos++;
        return out;
      }
      if (c !== 0x2c) throw new DecodeError("expected ',' or '}'");
      pos++;
    }
  }

  const root = parseValue(0);
  skipWs();
  if (pos !== len) throw new DecodeError("trailing data after JSON");
  return root;
}

const NODE_STATUS = new Set([
  "loading",
  "pending_revalidation",
  "healthy",
  "stale",
  "denied",
  "unsupported_outbound_only",
  "unsupported_transport",
  "storage_full",
  "removed_retained",
]);
const DELIVERY = new Set(["live", "delayed"]);
const ACTIVITY_AUTHORITY = new Set(["disabled", "complete", "incomplete"]);
const ACTIVITY_STATE = new Set(["idle", "working", "blocked", "unknown"]);
const ACTIVITY_BLOCK = new Set(["input", "permission"]);
const ACTIVITY_REASON = new Set([
  "background",
  "scheduled_wake",
  "aged",
  "restarted",
  "contradictory",
  "unverified",
  "evidence_lost",
  "registry_unavailable",
  "unreported",
  "incarnation_ended",
]);
const ENDPOINT_KIND = new Set(["instance", "service", "subagent"]);
const REG_STATE = new Set(["live", "parked", "closed", "seen"]);
const EVENT_KIND = new Set([
  "send",
  "reply",
  "deliver",
  "ack",
  "expired",
  "register",
  "unregister",
  "activity_changed",
  "unknown",
]);
const AVAILABILITY = new Set(["available", "not_recorded", "masked"]);
const OUTCOME = new Set([
  "delivered",
  "queued",
  "pushed",
  "gone",
  "denied",
  "rate_limited",
  "payload_too_large",
  "push_failed",
  "unknown",
]);
const GAP_REASON = new Set([
  "cursor_invalid",
  "cursor_expired",
  "epoch_changed",
  "scope_changed",
  "slow_consumer",
  "coalesced",
  "writer_restart",
  "retention_evicted",
  "corrupt_tail",
  "unknown",
]);
const STREAM_GAP_REASON = new Set([
  "cursor_invalid",
  "cursor_expired",
  "epoch_changed",
  "scope_changed",
  "slow_consumer",
  "coalesced",
]);
const ATTENTION_KIND = new Set([
  "blocked_input",
  "blocked_permission",
  "node_stale",
  "node_unreachable",
  "node_denied",
  "coverage_gap",
]);
const ERROR_CODE = new Set([
  "bad_message",
  "unsupported_type",
  "unsupported",
  "version_mismatch",
  "capability_unavailable",
  "not_found_or_denied",
  "duplicate_sub",
  "too_many_subscriptions",
  "rate_limited",
  "lease_expired",
  "revoked",
  "policy_changed",
  "unauthenticated",
  "forbidden",
  "unavailable",
  "internal",
]);
const CAPABILITIES = new Set(["observe", "activity", "commands"]);

function asObject(v: unknown, ctx: string, allowed: Set<string>): Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) {
    throw new DecodeError(`${ctx}: expected object`);
  }
  const obj = v as Record<string, unknown>;
  for (const k of Object.keys(obj)) {
    if (!allowed.has(k)) throw new DecodeError(`${ctx}: unknown field '${k}'`);
  }
  return obj;
}

function asString(v: unknown, ctx: string): string {
  if (typeof v !== "string") throw new DecodeError(`${ctx}: expected string`);
  return v;
}

function asBool(v: unknown, ctx: string): boolean {
  if (typeof v !== "boolean") throw new DecodeError(`${ctx}: expected boolean`);
  return v;
}

function asInt(v: unknown, ctx: string, min = Number.MIN_SAFE_INTEGER, max = Number.MAX_SAFE_INTEGER): number {
  if (typeof v !== "number" || !Number.isSafeInteger(v) || v < min || v > max) {
    throw new DecodeError(`${ctx}: invalid integer`);
  }
  return v;
}

function asEnum<T extends string>(v: unknown, set: Set<string>, ctx: string): T {
  const s = asString(v, ctx);
  if (!set.has(s)) throw new DecodeError(`${ctx}: invalid enum '${s}'`);
  return s as T;
}

function asArray(v: unknown, ctx: string): unknown[] {
  if (!Array.isArray(v)) throw new DecodeError(`${ctx}: expected array`);
  return v;
}

export interface SessionContext {
  repo?: string;
  branch?: string;
  worktree?: string;
  task?: string;
  pr?: string;
  updated_at: number;
  generation: number;
  stale: boolean;
}

export interface ActivityDescriptor {
  state: "idle" | "working" | "blocked" | "unknown";
  block?: "input" | "permission";
  reason?: string;
  state_epoch: string;
  incarnation: number;
  revision: number;
  changed_at: number;
  fresh_at: number;
}

export interface EndpointDescriptor {
  id: string;
  node: string;
  kind: "instance" | "service" | "subagent";
  harness: string;
  state: "live" | "parked" | "closed" | "seen";
  source_at?: number;
  label?: string;
  context?: SessionContext;
  activity?: ActivityDescriptor;
}

export interface EndpointEntry {
  descriptor: EndpointDescriptor;
  activity?: ActivityDescriptor;
  activity_stale?: boolean;
}

export interface ExportEvent {
  sequence: number;
  source_at?: number;
  observed_at: number;
  persisted_at: number;
  kind: string;
  from?: string;
  to?: string;
  message_id?: string;
  reply_id?: number;
  thread_id?: string;
  outcome?: string;
  reason?: string;
  available: string;
  activity?: ActivityDescriptor;
}

export interface ExportGap {
  reason: string;
  unknown_loss: boolean;
}

export interface NodeView {
  node: string;
  status: string;
  delivery: "live" | "delayed";
  last_success_at?: number;
  last_source_at?: number;
  via_hub?: string;
  history_hidden: boolean;
  last_activity_at?: number;
  activity_authority?: "disabled" | "complete" | "incomplete";
  endpoints: EndpointEntry[];
  endpoints_truncated: boolean;
  exchanges: { event: ExportEvent }[];
  source_gaps: ExportGap[];
}

export interface AttentionItem {
  id: string;
  kind: "blocked_input" | "blocked_permission" | "node_stale" | "node_unreachable" | "node_denied" | "coverage_gap";
  node: string;
  endpoint?: string;
  since: number;
  detail: { reason?: string; unknown_loss?: boolean; delivery: "live" | "delayed" };
}

export type ServerMessage =
  | {
      v: 1;
      type: "hello";
      re: number;
      protocol: 1;
      capabilities: string[];
      connection: string;
      actor: { principal: string; display: string; class: string };
      lease_expires_at: number;
      server_at: number;
      limits: {
        max_client_message_bytes: number;
        max_server_message_bytes: number;
        max_json_depth: number;
        subscriptions_per_connection: number;
        tick_interval_ms: number;
      };
    }
  | { v: 1; type: "subscribed"; re: number; sub: string; mode: "snapshot" | "resume"; stream_epoch: string }
  | { v: 1; type: "unsubscribed"; re: number; sub: string }
  | {
      v: 1;
      type: "snapshot";
      sub: string;
      part: number;
      final: boolean;
      stream_epoch: string;
      cursor?: string;
      server_at: number;
      truncated?: boolean;
      nodes: NodeView[];
      attention?: AttentionItem[];
    }
  | { v: 1; type: "event"; sub: string; seq: number; cursor: string; replayed?: boolean; at: number; delta: Record<string, unknown> }
  | { v: 1; type: "gap"; sub: string; reason: string; unknown_loss: boolean; reset: boolean }
  | { v: 1; type: "tick"; server_at: number }
  | { v: 1; type: "error"; re?: number; code: string; fatal: boolean };

const SESSION_CTX_KEYS = new Set(["repo", "branch", "worktree", "task", "pr", "updated_at", "generation", "stale"]);
const ACTIVITY_KEYS = new Set(["state", "block", "reason", "state_epoch", "incarnation", "revision", "changed_at", "fresh_at"]);
const DESCRIPTOR_KEYS = new Set(["id", "node", "kind", "harness", "state", "source_at", "label", "context", "activity"]);
const ENDPOINT_ENTRY_KEYS = new Set(["descriptor", "activity", "activity_stale"]);
const EXPORT_EVENT_KEYS = new Set([
  "sequence",
  "source_at",
  "observed_at",
  "persisted_at",
  "kind",
  "from",
  "to",
  "message_id",
  "reply_id",
  "thread_id",
  "outcome",
  "reason",
  "available",
  "activity",
]);
const EXPORT_GAP_KEYS = new Set(["reason", "unknown_loss"]);
const NODE_VIEW_KEYS = new Set([
  "node",
  "status",
  "delivery",
  "last_success_at",
  "last_source_at",
  "via_hub",
  "history_hidden",
  "last_activity_at",
  "activity_authority",
  "endpoints",
  "endpoints_truncated",
  "exchanges",
  "source_gaps",
]);
const ATTENTION_KEYS = new Set(["id", "kind", "node", "endpoint", "since", "detail"]);
const ATTENTION_DETAIL_KEYS = new Set(["reason", "unknown_loss", "delivery"]);

function decodeSessionContext(v: unknown): SessionContext {
  const o = asObject(v, "context", SESSION_CTX_KEYS);
  const out: SessionContext = {
    updated_at: asInt(o.updated_at, "context.updated_at"),
    generation: asInt(o.generation, "context.generation", 0),
    stale: asBool(o.stale, "context.stale"),
  };
  if (o.repo !== undefined) out.repo = asString(o.repo, "context.repo");
  if (o.branch !== undefined) out.branch = asString(o.branch, "context.branch");
  if (o.worktree !== undefined) out.worktree = asString(o.worktree, "context.worktree");
  if (o.task !== undefined) out.task = asString(o.task, "context.task");
  if (o.pr !== undefined) out.pr = asString(o.pr, "context.pr");
  return out;
}

export function decodeActivity(v: unknown): ActivityDescriptor {
  const o = asObject(v, "activity", ACTIVITY_KEYS);
  const state = asEnum<ActivityDescriptor["state"]>(o.state, ACTIVITY_STATE, "activity.state");
  const out: ActivityDescriptor = {
    state,
    state_epoch: asString(o.state_epoch, "activity.state_epoch"),
    incarnation: asInt(o.incarnation, "activity.incarnation", 0),
    revision: asInt(o.revision, "activity.revision", 0),
    changed_at: asInt(o.changed_at, "activity.changed_at", 0),
    fresh_at: asInt(o.fresh_at, "activity.fresh_at", 0),
  };
  if (o.block !== undefined) {
    if (state !== "blocked") throw new DecodeError("activity.block only allowed when state=blocked");
    out.block = asEnum<"input" | "permission">(o.block, ACTIVITY_BLOCK, "activity.block");
  } else if (state === "blocked") {
    throw new DecodeError("activity.block required when state=blocked");
  }
  if (o.reason !== undefined) {
    out.reason = asEnum<string>(o.reason, ACTIVITY_REASON, "activity.reason");
  }
  return out;
}

export function decodeDescriptor(v: unknown): EndpointDescriptor {
  const o = asObject(v, "descriptor", DESCRIPTOR_KEYS);
  const out: EndpointDescriptor = {
    id: asString(o.id, "descriptor.id"),
    node: asString(o.node, "descriptor.node"),
    kind: asEnum(o.kind, ENDPOINT_KIND, "descriptor.kind"),
    // descriptor.harness is an open string, exempt from closed-enum rule.
    harness: asString(o.harness, "descriptor.harness"),
    state: asEnum(o.state, REG_STATE, "descriptor.state"),
  };
  if (o.source_at !== undefined) out.source_at = asInt(o.source_at, "descriptor.source_at", 0);
  if (o.label !== undefined) out.label = asString(o.label, "descriptor.label");
  if (o.context !== undefined) out.context = decodeSessionContext(o.context);
  if (o.activity !== undefined) out.activity = decodeActivity(o.activity);
  return out;
}

function decodeEndpointEntry(v: unknown): EndpointEntry {
  const o = asObject(v, "endpoint", ENDPOINT_ENTRY_KEYS);
  const out: EndpointEntry = { descriptor: decodeDescriptor(o.descriptor) };
  if (o.activity !== undefined) out.activity = decodeActivity(o.activity);
  if (o.activity_stale !== undefined) out.activity_stale = asBool(o.activity_stale, "endpoint.activity_stale");
  return out;
}

export function decodeExportEvent(v: unknown): ExportEvent {
  const o = asObject(v, "event", EXPORT_EVENT_KEYS);
  const out: ExportEvent = {
    sequence: asInt(o.sequence, "event.sequence", 0),
    observed_at: asInt(o.observed_at, "event.observed_at", 0),
    persisted_at: asInt(o.persisted_at, "event.persisted_at", 0),
    kind: asEnum(o.kind, EVENT_KIND, "event.kind"),
    available: asEnum(o.available, AVAILABILITY, "event.available"),
  };
  if (o.source_at !== undefined) out.source_at = asInt(o.source_at, "event.source_at", 0);
  if (o.from !== undefined) out.from = asString(o.from, "event.from");
  if (o.to !== undefined) out.to = asString(o.to, "event.to");
  if (o.message_id !== undefined) out.message_id = asString(o.message_id, "event.message_id");
  if (o.reply_id !== undefined) out.reply_id = asInt(o.reply_id, "event.reply_id");
  if (o.thread_id !== undefined) out.thread_id = asString(o.thread_id, "event.thread_id");
  if (o.outcome !== undefined) out.outcome = asEnum(o.outcome, OUTCOME, "event.outcome");
  if (o.reason !== undefined) out.reason = asEnum(o.reason, GAP_REASON, "event.reason");
  if (o.activity !== undefined) out.activity = decodeActivity(o.activity);
  return out;
}

export function decodeExportGap(v: unknown): ExportGap {
  const o = asObject(v, "gap", EXPORT_GAP_KEYS);
  return {
    reason: asEnum(o.reason, GAP_REASON, "gap.reason"),
    unknown_loss: asBool(o.unknown_loss, "gap.unknown_loss"),
  };
}

function decodeNodeView(v: unknown): NodeView {
  const o = asObject(v, "NodeView", NODE_VIEW_KEYS);
  const endpoints = asArray(o.endpoints, "NodeView.endpoints").map(decodeEndpointEntry);
  const exchangesRaw = asArray(o.exchanges, "NodeView.exchanges");
  const exchanges = exchangesRaw.map((ex) => {
    if (typeof ex === "object" && ex !== null && "event" in ex && Object.keys(ex).length === 1) {
      return { event: decodeExportEvent((ex as { event: unknown }).event) };
    }
    return { event: decodeExportEvent(ex) };
  });
  const source_gaps = asArray(o.source_gaps, "NodeView.source_gaps").map(decodeExportGap);
  const out: NodeView = {
    node: asString(o.node, "NodeView.node"),
    status: asEnum(o.status, NODE_STATUS, "NodeView.status"),
    delivery: asEnum(o.delivery, DELIVERY, "NodeView.delivery"),
    history_hidden: asBool(o.history_hidden, "NodeView.history_hidden"),
    endpoints,
    endpoints_truncated: asBool(o.endpoints_truncated, "NodeView.endpoints_truncated"),
    exchanges,
    source_gaps,
  };
  if (o.last_success_at !== undefined) out.last_success_at = asInt(o.last_success_at, "NodeView.last_success_at", 0);
  if (o.last_source_at !== undefined) out.last_source_at = asInt(o.last_source_at, "NodeView.last_source_at", 0);
  if (o.via_hub !== undefined) out.via_hub = asString(o.via_hub, "NodeView.via_hub");
  if (o.last_activity_at !== undefined) out.last_activity_at = asInt(o.last_activity_at, "NodeView.last_activity_at", 0);
  if (o.activity_authority !== undefined) {
    out.activity_authority = asEnum(o.activity_authority, ACTIVITY_AUTHORITY, "NodeView.activity_authority");
  }
  return out;
}

export function decodeAttentionItem(v: unknown): AttentionItem {
  const o = asObject(v, "AttentionItem", ATTENTION_KEYS);
  const det = asObject(o.detail, "AttentionItem.detail", ATTENTION_DETAIL_KEYS);
  const detail: AttentionItem["detail"] = {
    delivery: asEnum(det.delivery, DELIVERY, "AttentionItem.detail.delivery"),
  };
  if (det.reason !== undefined) detail.reason = asEnum(det.reason, ACTIVITY_REASON, "AttentionItem.detail.reason");
  if (det.unknown_loss !== undefined) detail.unknown_loss = asBool(det.unknown_loss, "AttentionItem.detail.unknown_loss");
  const out: AttentionItem = {
    id: asString(o.id, "AttentionItem.id"),
    kind: asEnum(o.kind, ATTENTION_KIND, "AttentionItem.kind"),
    node: asString(o.node, "AttentionItem.node"),
    since: asInt(o.since, "AttentionItem.since", 0),
    detail,
  };
  if (o.endpoint !== undefined) out.endpoint = asString(o.endpoint, "AttentionItem.endpoint");
  return out;
}

function decodeDelta(v: unknown): Record<string, unknown> {
  if (typeof v !== "object" || v === null || Array.isArray(v)) throw new DecodeError("delta: expected object");
  const d = v as Record<string, unknown>;
  const kind = asString(d.kind, "delta.kind");
  switch (kind) {
    case "node_status": {
      asObject(d, "delta.node_status", new Set(["kind", "node", "status", "delivery", "last_success_at", "last_source_at", "via_hub", "history_hidden"]));
      asString(d.node, "delta.node");
      asEnum(d.status, NODE_STATUS, "delta.status");
      asEnum(d.delivery, DELIVERY, "delta.delivery");
      asBool(d.history_hidden, "delta.history_hidden");
      if (d.last_success_at !== undefined) asInt(d.last_success_at, "delta.last_success_at", 0);
      if (d.last_source_at !== undefined) asInt(d.last_source_at, "delta.last_source_at", 0);
      if (d.via_hub !== undefined) asString(d.via_hub, "delta.via_hub");
      return d;
    }
    case "endpoint_upserted": {
      asObject(d, "delta.endpoint_upserted", new Set(["kind", "node", "descriptor", "activity", "activity_stale"]));
      asString(d.node, "delta.node");
      decodeDescriptor(d.descriptor);
      if (d.activity !== undefined) decodeActivity(d.activity);
      if (d.activity_stale !== undefined) asBool(d.activity_stale, "delta.activity_stale");
      return d;
    }
    case "endpoint_removed": {
      asObject(d, "delta.endpoint_removed", new Set(["kind", "node", "id"]));
      asString(d.node, "delta.node");
      asString(d.id, "delta.id");
      return d;
    }
    case "exchange":
    case "activity_changed": {
      asObject(d, `delta.${kind}`, new Set(["kind", "node", "event"]));
      asString(d.node, "delta.node");
      decodeExportEvent(d.event);
      return d;
    }
    case "source_gap": {
      asObject(d, "delta.source_gap", new Set(["kind", "node", "gap"]));
      asString(d.node, "delta.node");
      decodeExportGap(d.gap);
      return d;
    }
    case "attention_upserted": {
      asObject(d, "delta.attention_upserted", new Set(["kind", "item"]));
      decodeAttentionItem(d.item);
      return d;
    }
    case "attention_cleared": {
      asObject(d, "delta.attention_cleared", new Set(["kind", "id", "cleared_at"]));
      asString(d.id, "delta.id");
      asInt(d.cleared_at, "delta.cleared_at", 0);
      return d;
    }
    default:
      throw new DecodeError(`unknown delta.kind: ${kind}`);
  }
}

export function decodeServerMessage(raw: string, maxBytes = DEFAULT_MAX_SERVER_MESSAGE_BYTES): ServerMessage {
  if (utf8ByteLength(raw) > maxBytes) {
    throw new DecodeError(`server message exceeds ${maxBytes} bytes`);
  }
  const parsed = parseStrictJson(raw);
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new DecodeError("top-level message must be object");
  }
  const o = parsed as Record<string, unknown>;
  const v = asInt(o.v, "v", 1, 1);
  if (v !== 1) throw new DecodeError("unsupported version");
  const type = asString(o.type, "type");

  switch (type) {
    case "hello": {
      asObject(o, "hello", new Set(["v", "type", "re", "protocol", "capabilities", "connection", "actor", "lease_expires_at", "server_at", "limits"]));
      const actor = asObject(o.actor, "hello.actor", new Set(["principal", "display", "class"]));
      const limits = asObject(
        o.limits,
        "hello.limits",
        new Set(["max_client_message_bytes", "max_server_message_bytes", "max_json_depth", "subscriptions_per_connection", "tick_interval_ms"]),
      );
      const caps = asArray(o.capabilities, "hello.capabilities").map((c) => asEnum<string>(c, CAPABILITIES, "hello.capabilities[]"));
      return {
        v: 1,
        type: "hello",
        re: asInt(o.re, "hello.re", 1),
        protocol: asInt(o.protocol, "hello.protocol", 1, 1) as 1,
        capabilities: caps,
        connection: asString(o.connection, "hello.connection"),
        actor: {
          principal: asString(actor.principal, "actor.principal"),
          display: asString(actor.display, "actor.display"),
          class: asString(actor.class, "actor.class"),
        },
        lease_expires_at: asInt(o.lease_expires_at, "hello.lease_expires_at", 0),
        server_at: asInt(o.server_at, "hello.server_at", 0),
        limits: {
          max_client_message_bytes: asInt(limits.max_client_message_bytes, "limits.max_client_message_bytes", 1),
          max_server_message_bytes: asInt(limits.max_server_message_bytes, "limits.max_server_message_bytes", 1),
          max_json_depth: asInt(limits.max_json_depth, "limits.max_json_depth", 1),
          subscriptions_per_connection: asInt(limits.subscriptions_per_connection, "limits.subscriptions_per_connection", 1),
          tick_interval_ms: asInt(limits.tick_interval_ms, "limits.tick_interval_ms", 1),
        },
      };
    }
    case "subscribed": {
      asObject(o, "subscribed", new Set(["v", "type", "re", "sub", "mode", "stream_epoch"]));
      const sub = asString(o.sub, "subscribed.sub");
      if (!SUB_RE.test(sub)) throw new DecodeError("subscribed.sub grammar");
      return {
        v: 1,
        type: "subscribed",
        re: asInt(o.re, "subscribed.re", 1),
        sub,
        mode: asEnum(o.mode, new Set(["snapshot", "resume"]), "subscribed.mode"),
        stream_epoch: asString(o.stream_epoch, "subscribed.stream_epoch"),
      };
    }
    case "unsubscribed": {
      asObject(o, "unsubscribed", new Set(["v", "type", "re", "sub"]));
      const sub = asString(o.sub, "unsubscribed.sub");
      if (!SUB_RE.test(sub)) throw new DecodeError("unsubscribed.sub grammar");
      return { v: 1, type: "unsubscribed", re: asInt(o.re, "unsubscribed.re", 1), sub };
    }
    case "snapshot": {
      asObject(o, "snapshot", new Set(["v", "type", "sub", "part", "final", "stream_epoch", "cursor", "server_at", "truncated", "nodes", "attention"]));
      const sub = asString(o.sub, "snapshot.sub");
      if (!SUB_RE.test(sub)) throw new DecodeError("snapshot.sub grammar");
      const final = asBool(o.final, "snapshot.final");
      if (final && o.cursor === undefined) throw new DecodeError("snapshot.cursor required when final=true");
      if (!final && o.cursor !== undefined) throw new DecodeError("snapshot.cursor forbidden when final=false");
      if (final && o.truncated === undefined) throw new DecodeError("snapshot.truncated required when final=true");
      if (!final && o.truncated !== undefined) throw new DecodeError("snapshot.truncated forbidden when final=false");
      const nodes = asArray(o.nodes, "snapshot.nodes").map(decodeNodeView);
      const out: Extract<ServerMessage, { type: "snapshot" }> = {
        v: 1,
        type: "snapshot",
        sub,
        part: asInt(o.part, "snapshot.part", 0),
        final,
        stream_epoch: asString(o.stream_epoch, "snapshot.stream_epoch"),
        server_at: asInt(o.server_at, "snapshot.server_at", 0),
        nodes,
      };
      if (o.cursor !== undefined) out.cursor = asString(o.cursor, "snapshot.cursor");
      if (o.truncated !== undefined) out.truncated = asBool(o.truncated, "snapshot.truncated");
      if (o.attention !== undefined) out.attention = asArray(o.attention, "snapshot.attention").map(decodeAttentionItem);
      return out;
    }
    case "event": {
      asObject(o, "event", new Set(["v", "type", "sub", "seq", "cursor", "replayed", "at", "delta"]));
      const sub = asString(o.sub, "event.sub");
      if (!SUB_RE.test(sub)) throw new DecodeError("event.sub grammar");
      const out: Extract<ServerMessage, { type: "event" }> = {
        v: 1,
        type: "event",
        sub,
        seq: asInt(o.seq, "event.seq", 0),
        cursor: asString(o.cursor, "event.cursor"),
        at: asInt(o.at, "event.at", 0),
        delta: decodeDelta(o.delta),
      };
      if (o.replayed !== undefined) out.replayed = asBool(o.replayed, "event.replayed");
      return out;
    }
    case "gap": {
      asObject(o, "gap", new Set(["v", "type", "sub", "reason", "unknown_loss", "reset"]));
      const sub = asString(o.sub, "gap.sub");
      if (!SUB_RE.test(sub)) throw new DecodeError("gap.sub grammar");
      return {
        v: 1,
        type: "gap",
        sub,
        reason: asEnum(o.reason, STREAM_GAP_REASON, "gap.reason"),
        unknown_loss: asBool(o.unknown_loss, "gap.unknown_loss"),
        reset: asBool(o.reset, "gap.reset"),
      };
    }
    case "tick": {
      asObject(o, "tick", new Set(["v", "type", "server_at"]));
      return { v: 1, type: "tick", server_at: asInt(o.server_at, "tick.server_at", 0) };
    }
    case "error": {
      asObject(o, "error", new Set(["v", "type", "re", "code", "fatal"]));
      const out: Extract<ServerMessage, { type: "error" }> = {
        v: 1,
        type: "error",
        code: asEnum(o.code, ERROR_CODE, "error.code"),
        fatal: asBool(o.fatal, "error.fatal"),
      };
      if (o.re !== undefined) out.re = asInt(o.re, "error.re", 1);
      return out;
    }
    default:
      // Includes prepare, prepared, commit, receipt, lookup (unsupported/unsolicited in inspect-only v1).
      throw new DecodeError(`unsupported or unsolicited message type: ${type}`);
  }
}
