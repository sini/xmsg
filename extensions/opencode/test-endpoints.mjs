// How the opencode plugin finds the daemon, runnable without opencode: XMSG_REGISTER_SOCK, then a
// cached `xmsg doctor --json`, then the legacy $XDG_RUNTIME_DIR/xmsg/. A fake `xmsg` on PATH plays
// doctor and fake register.sock servers record which one the plugin connected to.
// Run with: node --experimental-transform-types extensions/opencode/test-endpoints.mjs
import assert from "node:assert/strict";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "opencode-endpoints-"));
fs.chmodSync(tmp, 0o700);
const bin = path.join(tmp, "bin");
fs.mkdirSync(bin);
const calls = path.join(tmp, "doctor-calls");
const managed = path.join(tmp, "xmsg-1000-0123456789ab");
for (const d of [managed, path.join(tmp, "xmsg"), path.join(tmp, "pinned")]) fs.mkdirSync(d, { mode: 0o700 });
const report = (fields) => JSON.stringify(fields);
const usable = report({ endpoints_usable: true, register_socket: `${managed}/register.sock`, leaf_register_socket: null, agent_socket: `${managed}/agent.sock` });
const unsupported = "error: unrecognized subcommand 'doctor'\n\nUsage: xmsg <COMMAND>\n\nFor more information, try '--help'.\n";
// Each mode prints doctor's stdout (exit 1, as doctor does with a failed check) or misbehaves.
fs.writeFileSync(
  path.join(bin, "xmsg"),
  `#!/bin/sh
[ "$1 $2" = "doctor --json" ] || exit 9
echo x >> '${calls}'
case "$FAKE_DOCTOR" in
  usable) echo '${usable}'; exit 1 ;;
  unusable) echo '${report({ endpoints_usable: false, register_socket: `${managed}/register.sock` })}'; exit 1 ;;
  malformed) echo '{not json'; exit 1 ;;
  unsupported) printf "${unsupported.replace(/\n/g, "\\n")}" >&2; exit 2 ;;
  timeout) exec sleep 10 ;;
esac
`,
  { mode: 0o755 },
);
const probes = () => (fs.existsSync(calls) ? fs.readFileSync(calls, "utf8").split("\n").filter(Boolean).length : 0);

// A register.sock that answers the hello and every request; it counts hellos.
const servers = {};
for (const [name, sock] of [["managed", `${managed}/register.sock`], ["legacy", path.join(tmp, "xmsg", "register.sock")], ["pinned", path.join(tmp, "pinned", "register.sock")]]) {
  const conns = new Set();
  const server = net.createServer((c) => {
    conns.add(c);
    c.on("close", () => conns.delete(c));
    c.on("error", () => {});
    let buf = "";
    c.on("data", (chunk) => {
      buf += chunk;
      for (let i; (i = buf.indexOf("\n")) >= 0; ) {
        const frame = JSON.parse(buf.slice(0, i));
        buf = buf.slice(i + 1);
        if (frame.harness) {
          servers[name].hellos += 1;
          c.write('{"status":"ok"}\n');
        } else if (frame.action !== "poll") c.write(JSON.stringify({ status: "ok", request_id: frame.request_id }) + "\n");
      }
    });
  });
  await new Promise((r) => server.listen(sock, r));
  servers[name] = { server, hellos: 0, drop: () => conns.forEach((c) => c.destroy()) };
}

const systemPath = process.env.PATH;
const warnings = [];
console.warn = (line) => warnings.push(String(line));
const client = { session: { get: async () => ({ data: {} }) } };
let loads = 0;
// A fresh module per case, so each case starts with an empty doctor cache.
async function load(env) {
  for (const k of ["XMSG_REGISTER_SOCK", "XMSG_AGENT_SOCK", "FAKE_DOCTOR"]) delete process.env[k];
  Object.assign(process.env, { XDG_RUNTIME_DIR: tmp, XDG_STATE_HOME: path.join(tmp, "state"), PATH: `${bin}:${systemPath}` }, env);
  fs.rmSync(calls, { force: true });
  warnings.length = 0;
  for (const s of Object.values(servers)) s.hellos = 0;
  const plugin = (await import(`./xmsg.ts?case=${++loads}`)).default;
  return plugin.server({ client });
}
const list = (hooks) => hooks.tool.xmsg_list.execute({}, { sessionID: "s1" });

try {
  // Precedence: the env pin wins without a probe; else doctor; else the legacy directory.
  let hooks = await load({ FAKE_DOCTOR: "usable", XMSG_REGISTER_SOCK: path.join(tmp, "pinned", "register.sock") });
  await list(hooks);
  assert.equal(servers.pinned.hellos, 1, "env pin connects to the pinned socket");
  assert.equal(servers.managed.hellos + servers.legacy.hellos, 0);
  assert.equal(probes(), 0, "an env pin needs no doctor probe");

  hooks = await load({ FAKE_DOCTOR: "usable" });
  await list(hooks);
  assert.equal(servers.managed.hellos, 1, "doctor's register_socket is used");
  assert.equal(servers.legacy.hellos, 0, "the legacy directory is not used when doctor answers");
  // The probe is cached: more calls on the connection, and its load-time resolution, ran it once.
  await list(hooks);
  await list(hooks);
  assert.equal(probes(), 1, "one probe for load and three tool calls");
  // A disconnect re-runs it at the next connect.
  servers.managed.drop();
  await new Promise((r) => setTimeout(r, 50));
  await list(hooks);
  assert.equal(servers.managed.hellos, 2, "reconnected after the drop");
  assert.equal(probes(), 2, "the disconnect re-ran the probe");

  // A missing xmsg binary, or one without doctor, falls through to the legacy directory with one log line.
  for (const [env, reason] of [[{ PATH: path.join(tmp, "empty") }, /xmsg CLI not found/], [{ FAKE_DOCTOR: "unsupported" }, /xmsg CLI has no doctor/]]) {
    hooks = await load(env);
    await list(hooks);
    await list(hooks);
    assert.equal(servers.legacy.hellos, 1, `legacy fallback (${reason})`);
    const lines = warnings.filter((w) => /legacy socket directory/.test(w));
    assert.equal(lines.length, 1, `one fallback log line: ${warnings}`);
    assert.match(lines[0], reason);
  }

  // Unusable endpoints, malformed output and a timeout refuse: the plugin is off, and nothing
  // connects to the legacy directory.
  for (const [mode, reason] of [["unusable", /unusable/], ["malformed", /invalid JSON/], ["timeout", /time or output bound/]]) {
    hooks = await load({ FAKE_DOCTOR: mode });
    assert.deepEqual(hooks, {}, `${mode}: the plugin is off`);
    assert.ok(warnings.some((w) => reason.test(w) && /plugin is off/.test(w)), `${mode}: ${warnings}`);
    assert.equal(servers.legacy.hellos + servers.managed.hellos, 0, `${mode}: no connection`);
  }
} finally {
  for (const s of Object.values(servers)) s.server.close();
  fs.rmSync(tmp, { recursive: true, force: true });
}
console.log("✔ opencode finds the daemon through XMSG_REGISTER_SOCK, a cached xmsg doctor probe, then the legacy runtime dir; doctor refusals never reroute");
// The plugin's poll loops hold the event loop open.
process.exit(0);
