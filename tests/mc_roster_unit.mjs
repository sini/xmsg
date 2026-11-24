#!/usr/bin/env node
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";

import { RosterStore } from "../web/mc-roster/src/projection.ts";
import { DecodeError, decodeServerMessage, parseStrictJson } from "../web/mc-roster/src/protocol.ts";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(__dirname, "..");
const vecDir = path.join(repoRoot, "tests/vectors/mission-control/v1");

function loadVec(name) {
  return fs.readFileSync(path.join(vecDir, `${name}.json`), "utf8");
}

test("WR-2 static banned-sink check on web/mc-roster/src", () => {
  const srcDir = path.join(repoRoot, "web/mc-roster/src");
  const banned = [
    /\binnerHTML\b/,
    /\bouterHTML\b/,
    /\binsertAdjacentHTML\b/,
    /\bdocument\.write\b/,
    /\beval\s*\(/,
    /\bnew\s+Function\b/,
    /javascript:/i,
    /\bsetAttribute\s*\(\s*["'](?:href|src)["']\s*,\s*(?=\S)(?!["'])/,
    /\.(?:href|src)\s*=\s*(?=\S)(?!["'])/,
  ];
  for (const f of fs.readdirSync(srcDir)) {
    if (!f.endsWith(".ts")) continue;
    const text = fs.readFileSync(path.join(srcDir, f), "utf8");
    for (const pat of banned) {
      assert.equal(pat.test(text), false, `banned sink ${pat} found in ${f}`);
    }
  }
});

test("WR-3 WS-valid S->C vectors decode and apply cleanly", () => {
  const store = new RosterStore();
  store.allocSub("fleet");
  store.allocSub("attention");
  const n1 = store.allocSub("node", "laptop");

  for (const name of ["V-H2", "V-S3", "V-P1", "V-E1", "V-E2", "V-E3", "V-T1", "V-X1"]) {
    const raw = loadVec(name);
    const msg = decodeServerMessage(raw);
    store.applyMessage(msg, Buffer.byteLength(raw), 1000);
  }

  // Legal seq gap causes no reset
  const seqGapEvent = JSON.stringify({
    v: 1,
    type: "event",
    sub: n1.sub,
    seq: 2050,
    cursor: "cur_after_gap",
    at: 1795000002000,
    delta: { kind: "node_status", node: "laptop", status: "healthy", delivery: "live", history_hidden: false },
  });
  store.applyMessage(decodeServerMessage(seqGapEvent), 200, 2000);
  assert.equal(n1.synced, true, "legal seq gap must not reset sub");

  // V-G1 resets sub n1
  const vg1 = loadVec("V-G1");
  store.applyMessage(decodeServerMessage(vg1), Buffer.byteLength(vg1), 2100);
  assert.equal(n1.synced, false, "V-G1 reset=true must reset sub");

  // V-P2+sub and V-E4+sub (WS attention vectors)
  const vp2 = JSON.parse(loadVec("V-P2"));
  vp2.sub = "att";
  const vp2Msg = decodeServerMessage(JSON.stringify(vp2));
  store.applyMessage(vp2Msg, 512, 1000);
  assert.equal(store.attention.size, 1, "V-P2+sub attention item must be applied");

  const ve4 = JSON.parse(loadVec("V-E4"));
  ve4.sub = "att";
  const ve4Msg = decodeServerMessage(JSON.stringify(ve4));
  store.applyMessage(ve4Msg, 256, 1000);
  assert.equal(store.attention.size, 0, "V-E4+sub attention_cleared must clear item");
});

test("WR-3 WS-invalid S->C vectors and synthetic cells throw DecodeError (-> 4400)", () => {
  for (const name of ["V-I13", "V-I14", "V-I24", "V-C2", "V-C4", "V-C5", "V-C6", "V-C7", "V-C8", "V-C9", "V-C10", "V-C11"]) {
    assert.throws(() => decodeServerMessage(loadVec(name)), DecodeError, `${name} must be refused`);
  }

  // Oversize (> max_server_message_bytes)
  const big = JSON.stringify({ v: 1, type: "tick", server_at: 1 }) + " ".repeat(300_000);
  assert.throws(() => decodeServerMessage(big, 262_144), DecodeError, "oversize must throw");

  // Depth 17
  let nested = "1";
  for (let i = 0; i < 17; i++) nested = `[${nested}]`;
  assert.throws(() => parseStrictJson(nested), DecodeError, "depth 17 must throw");

  // Duplicate key
  assert.throws(() => parseStrictJson('{"a":1,"a":2}'), DecodeError, "duplicate key must throw");

  // Unknown enum (hostile activity.reason)
  const hostileEnum = JSON.stringify({
    v: 1,
    type: "snapshot",
    sub: "fleet",
    part: 0,
    final: true,
    stream_epoch: "9f1c0e5a7b3d2c4e8f6a1b0c9d8e7f6a",
    cursor: "c1",
    server_at: 1795000000100,
    truncated: false,
    nodes: [
      {
        node: "laptop",
        status: "healthy",
        delivery: "live",
        history_hidden: false,
        endpoints: [
          {
            descriptor: { id: "a@laptop", node: "laptop", kind: "instance", harness: "claude", state: "seen" },
            activity: {
              state: "unknown",
              reason: "<script>alert(1)</script>",
              state_epoch: "0a1b",
              incarnation: 1,
              revision: 1,
              changed_at: 100,
              fresh_at: 100,
            },
          },
        ],
        endpoints_truncated: false,
        exchanges: [],
        source_gaps: [],
      },
    ],
  });
  assert.throws(() => decodeServerMessage(hostileEnum), DecodeError, "hostile activity.reason must throw");

  // Out-of-order, wrong-epoch, over-snapshot_max_bytes multipart
  const store = new RosterStore();
  store.snapshotMaxBytes = 500;
  store.allocSub("fleet");
  const p0 = decodeServerMessage(
    JSON.stringify({
      v: 1,
      type: "snapshot",
      sub: "fleet",
      part: 0,
      final: false,
      stream_epoch: "e1",
      server_at: 100,
      nodes: [],
    }),
  );
  store.applyMessage(p0, 300, 100);
  // Out-of-order part 2
  assert.throws(
    () =>
      store.applyMessage(
        decodeServerMessage(
          JSON.stringify({
            v: 1,
            type: "snapshot",
            sub: "fleet",
            part: 2,
            final: true,
            stream_epoch: "e1",
            cursor: "c",
            server_at: 100,
            truncated: false,
            nodes: [],
          }),
        ),
        100,
        100,
      ),
    DecodeError,
  );
  // Wrong epoch
  assert.throws(
    () =>
      store.applyMessage(
        decodeServerMessage(
          JSON.stringify({
            v: 1,
            type: "snapshot",
            sub: "fleet",
            part: 1,
            final: true,
            stream_epoch: "e2",
            cursor: "c",
            server_at: 100,
            truncated: false,
            nodes: [],
          }),
        ),
        100,
        100,
      ),
    DecodeError,
  );
  // Over snapshot_max_bytes
  assert.throws(
    () =>
      store.applyMessage(
        decodeServerMessage(
          JSON.stringify({
            v: 1,
            type: "snapshot",
            sub: "fleet",
            part: 1,
            final: true,
            stream_epoch: "e1",
            cursor: "c",
            server_at: 100,
            truncated: false,
            nodes: [],
          }),
        ),
        300,
        100,
      ),
    DecodeError,
  );
});

test("WR-4b / WR-5a / WR-5d projection invariants (removed_retained, retired sub, 4403 cursor clear)", () => {
  const store = new RosterStore();
  store.wsOpen = true;
  store.allocSub("fleet");
  store.applyMessage(
    decodeServerMessage(
      JSON.stringify({
        v: 1,
        type: "snapshot",
        sub: "fleet",
        part: 0,
        final: true,
        stream_epoch: "ep1",
        cursor: "c_fleet_1",
        server_at: 1000,
        truncated: false,
        nodes: [
          {
            node: "old-node",
            status: "removed_retained",
            delivery: "live",
            history_hidden: false,
            endpoints: [],
            endpoints_truncated: false,
            exchanges: [],
            source_gaps: [],
          },
        ],
      }),
    ),
    512,
    1000,
  );
  // m10: fleet of only removed_retained nodes reads Unknown
  assert.equal(store.connectionBadge(1000), "Unknown");

  // m11: late snapshot for a retired n<k> detail sub is ignored
  const n1 = store.allocSub("node", "old-node");
  store.retireSub(n1.sub);
  const applied = store.applyMessage(
    decodeServerMessage(
      JSON.stringify({
        v: 1,
        type: "snapshot",
        sub: n1.sub,
        part: 0,
        final: true,
        stream_epoch: "ep_n1",
        cursor: "c_n1",
        server_at: 1050,
        truncated: false,
        nodes: [
          {
            node: "old-node",
            status: "healthy",
            delivery: "live",
            history_hidden: false,
            endpoints: [],
            endpoints_truncated: false,
            exchanges: [],
            source_gaps: [],
          },
        ],
      }),
    ),
    512,
    1050,
  );
  assert.equal(applied, false, "late snapshot for retired detail sub must be ignored");
  assert.equal(store.nodes.get("old-node")?.status, "removed_retained");

  // m15 / n03: 4403 reauth clears cursors on EVERY sub (fleet, attention, node)
  const attSub = store.allocSub("attention");
  attSub.cursor = "c_att";
  attSub.streamEpoch = "ep_att";
  attSub.synced = true;
  const nodeSub = store.allocSub("node", "old-node");
  nodeSub.cursor = "c_n";
  nodeSub.streamEpoch = "ep_n";
  nodeSub.synced = true;
  store.clearAllForReauth();
  assert.ok(store.subs.size >= 3);
  for (const rec of store.subs.values()) {
    assert.equal(rec.cursor, undefined, `sub ${rec.sub} cursor must be cleared`);
    assert.equal(rec.streamEpoch, undefined, `sub ${rec.sub} streamEpoch must be cleared`);
    assert.equal(rec.synced, false, `sub ${rec.sub} synced must be cleared`);
  }
});
