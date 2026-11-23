// Socket endpoint resolution of the xmsg-pi extension, runnable without pi.
//
// Loads index.ts through Node's built-in type stripping (Node 23.6 or later)
// and stubs `typebox`, which index.ts only uses to describe tool parameters.
// The pi import is type-only and is erased. Run with: node extensions/pi/test-paths.mjs
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import { registerHooks } from "node:module";
import os from "node:os";
import path from "node:path";

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "typebox") {
      const stub = "export const Type = new Proxy({}, { get: () => () => ({}) });";
      return { url: `data:text/javascript,${encodeURIComponent(stub)}`, shortCircuit: true };
    }
    return nextResolve(specifier, context);
  },
});

const { createEndpointResolver, defaultXmsgUrl, XmsgEndpointError, XmsgPiBridge } = await import("./index.ts");

const keys = ["XDG_RUNTIME_DIR", "XMSG_REGISTER_SOCK", "XMSG_AGENT_SOCK", "XMSG_HTTP_SOCK", "XMSG_URL"];
for (const k of keys) delete process.env[k];

const usable = (dir) => ({
  stdout: JSON.stringify({
    endpoints_usable: true,
    register_socket: `${dir}/register.sock`,
    leaf_register_socket: null,
    agent_socket: `${dir}/agent.sock`,
    http_socket: `${dir}/http.sock`,
  }),
  stderr: "",
  error: null,
});
const enoent = { stdout: "", stderr: "", error: Object.assign(new Error("spawn xmsg ENOENT"), { code: "ENOENT" }) };
const counted = (answer) => {
  const probe = async () => {
    probe.calls += 1;
    return answer;
  };
  probe.calls = 0;
  return probe;
};
const refusal = (resolver, name, pattern, label) =>
  assert.rejects(resolver.resolve(name), (err) => err instanceof XmsgEndpointError && pattern.test(err.message), label);

// What the xmsg binary falls back to when XDG_RUNTIME_DIR is unset or blank.
const fallback =
  process.platform === "darwin"
    ? execFileSync("/usr/bin/getconf", ["DARWIN_USER_TEMP_DIR"], { encoding: "utf8" }).trim()
    : undefined;
const fallbackSock = (name) => (fallback ? path.join(fallback, "xmsg", name) : undefined);

// 1. Precedence: an explicit path, then XMSG_*_SOCK, then doctor, then the legacy directory.
{
  process.env.XDG_RUNTIME_DIR = "/run/user/1000";
  const managed = "/run/user/1000/xmsg-1000-0123456789ab";
  const resolver = createEndpointResolver(counted(usable(managed)), () => {});
  assert.equal(await resolver.resolve("register"), `${managed}/register.sock`);
  assert.equal(await resolver.resolve("agent"), `${managed}/agent.sock`);
  assert.equal(await resolver.resolve("http"), `${managed}/http.sock`);
  process.env.XMSG_REGISTER_SOCK = "/custom/register.sock";
  assert.equal(await resolver.resolve("register"), "/custom/register.sock", "env pin before doctor");
  const bridge = new XmsgPiBridge({}, { sockPath: "/explicit/register.sock", endpoints: resolver });
  assert.equal(await bridge.endpoint("register"), "/explicit/register.sock", "explicit before env");
  assert.equal(await bridge.endpoint("agent"), `${managed}/agent.sock`);
  delete process.env.XMSG_REGISTER_SOCK;

  const leaf = {
    stdout: JSON.stringify({ endpoints_usable: true, register_socket: null, leaf_register_socket: "/leaf/register.sock" }),
    stderr: "",
    error: { code: 1 },
  };
  assert.equal(await createEndpointResolver(counted(leaf), () => {}).resolve("register"), "/leaf/register.sock", "leaf register, doctor exit 1");
}

// 2. A missing xmsg binary, or one without doctor, falls through to the legacy directory with one log line.
const noDoctor = {
  stdout: "",
  stderr: "error: unrecognized subcommand 'doctor'\n\nUsage: xmsg <COMMAND>\n\nFor more information, try '--help'.\n",
  error: { code: 2 },
};
for (const [answer, reason] of [[enoent, /not found/], [noDoctor, /has no doctor/]]) {
  for (const blank of [undefined, "", "   "]) {
    if (blank === undefined) delete process.env.XDG_RUNTIME_DIR;
    else process.env.XDG_RUNTIME_DIR = blank;
    const resolver = createEndpointResolver(counted(answer), () => {});
    const label = `XDG_RUNTIME_DIR=${JSON.stringify(blank)}`;
    assert.equal(await resolver.resolve("register"), fallbackSock("register.sock"), label);
    assert.equal(await resolver.resolve("agent"), fallbackSock("agent.sock"), label);
    assert.equal(await resolver.resolve("http"), fallbackSock("http.sock"), label);
  }
  process.env.XDG_RUNTIME_DIR = "/run/user/1000";
  const lines = [];
  const resolver = createEndpointResolver(counted(answer), (line) => lines.push(line));
  assert.equal(await resolver.resolve("register"), "/run/user/1000/xmsg/register.sock");
  assert.equal(await resolver.resolve("agent"), "/run/user/1000/xmsg/agent.sock");
  assert.equal(await resolver.resolve("http"), "/run/user/1000/xmsg/http.sock");
  assert.equal(lines.length, 1, "one fallback log line");
  assert.match(lines[0], reason);
}

// 3. Unusable endpoints, malformed output and a timeout refuse; none reroutes to the legacy directory.
const report = (fields, error = null) => ({ stdout: JSON.stringify(fields), stderr: "", error });
for (const [label, answer, pattern] of [
  ["unusable", report({ endpoints_usable: false, register_socket: "/x/register.sock" }, { code: 1 }), /unusable/],
  ["relative path", report({ endpoints_usable: true, register_socket: "x/register.sock" }), /non-absolute/],
  ["omitted endpoint", report({ endpoints_usable: true, register_socket: null }), /no register socket/],
  ["malformed JSON", { stdout: "{not json", stderr: "", error: null }, /invalid JSON/],
  ["no endpoints_usable", report({ register_socket: "/x/register.sock" }), /invalid endpoint report/],
  ["timeout", { stdout: "", stderr: "", error: { killed: true, signal: "SIGKILL" } }, /time or output bound/],
  ["output bound", { stdout: "", stderr: "", error: { code: "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" } }, /time or output bound/],
]) {
  await refusal(createEndpointResolver(counted(answer), () => {}), "register", pattern, label);
}

// 4. The probe runs once and is cached, a refusal included, until invalidate().
{
  const doctor = counted(usable("/d"));
  const resolver = createEndpointResolver(doctor, () => {});
  for (const name of ["register", "agent", "http", "register", "agent"]) await resolver.resolve(name);
  assert.equal(doctor.calls, 1, "one probe for five resolutions");
  resolver.invalidate();
  await resolver.resolve("register");
  assert.equal(doctor.calls, 2, "invalidate re-probes");
  const refused = counted({ stdout: "nope", stderr: "", error: null });
  const r2 = createEndpointResolver(refused, () => {});
  await refusal(r2, "register", /invalid JSON/, "first");
  await refusal(r2, "agent", /invalid JSON/, "cached");
  assert.equal(refused.calls, 1, "a refusal is cached too");
}

// 5. The real probe: a fake `xmsg` on PATH reaches the managed http.sock; no `xmsg` on PATH falls back.
{
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "pi-endpoints-"));
  fs.chmodSync(tmp, 0o700);
  const managed = path.join(tmp, "xmsg-1000-0123456789ab");
  fs.mkdirSync(managed, { mode: 0o700 });
  const bin = path.join(tmp, "bin");
  fs.mkdirSync(bin);
  fs.writeFileSync(
    path.join(bin, "xmsg"),
    `#!/bin/sh\n[ "$1 $2" = "doctor --json" ] || exit 9\necho '${usable(managed).stdout}'\nexit 1\n`,
    { mode: 0o755 },
  );
  const server = http.createServer((_req, res) => res.end(JSON.stringify([{ sessionId: "managed" }])));
  await new Promise((r) => server.listen(path.join(managed, "http.sock"), r));
  const savedPath = process.env.PATH;
  process.env.XDG_RUNTIME_DIR = tmp;
  try {
    process.env.PATH = bin;
    const tools = [];
    const bridge = new XmsgPiBridge({ registerTool: (t) => tools.push(t) }, { endpoints: createEndpointResolver() });
    bridge.registerListTool();
    const result = await tools[0].execute("call", {});
    assert.equal(result.details?.[0]?.sessionId, "managed", `list reaches the doctor-resolved http.sock: ${JSON.stringify(result)}`);

    process.env.PATH = path.join(tmp, "empty");
    const lines = [];
    const legacy = createEndpointResolver(undefined, (line) => lines.push(line));
    assert.equal(await legacy.resolve("http"), path.join(tmp, "xmsg", "http.sock"));
    assert.equal(lines.length, 1);
  } finally {
    process.env.PATH = savedPath;
    await new Promise((r) => server.close(r));
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

assert.equal(defaultXmsgUrl(), undefined);
process.env.XMSG_URL = "http://127.0.0.1:8888/";
assert.equal(defaultXmsgUrl(), "http://127.0.0.1:8888");
delete process.env.XMSG_URL;

console.log("✔ socket endpoints follow an explicit path, XMSG_*_SOCK, a cached xmsg doctor probe, then the legacy runtime dir; doctor refusals never reroute");
