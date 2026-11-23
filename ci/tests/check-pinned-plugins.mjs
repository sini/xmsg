// The pi and opencode plugin files the Home Manager module renders with
// programs.xmsg.server.sockets.dir set: with XMSG_*_SOCK unset, the prelude sets the pins before
// the plugin's own code runs, so the plugin resolves them and never runs `xmsg doctor`.
// The shipped files are the control: the same fake `xmsg` on PATH is run by pi's resolver.
// Usage: node --experimental-transform-types check-pinned-plugins.mjs <dir> <pi> <opencode> <pi-shipped> <opencode-shipped>
import assert from "node:assert/strict";
import fs from "node:fs";
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

const [dir, pi, opencode, piShipped, opencodeShipped] = process.argv.slice(2);
const VARS = ["XMSG_REGISTER_SOCK", "XMSG_AGENT_SOCK", "XMSG_HTTP_SOCK"];
const MARK = "// programs.xmsg.server.sockets.dir\n";

// A fake `xmsg` that records each run and answers with other endpoints.
const work = fs.mkdtempSync(path.join(os.tmpdir(), "pinned-plugins-"));
const ran = path.join(work, "doctor-ran");
const other = path.join(work, "other");
fs.writeFileSync(
  path.join(work, "xmsg"),
  `#!/bin/sh\necho "$@" >> ${ran}\nprintf '%s' '${JSON.stringify({
    endpoints_usable: true,
    register_socket: `${other}/register.sock`,
    leaf_register_socket: null,
    agent_socket: `${other}/agent.sock`,
    http_socket: `${other}/http.sock`,
  })}'\n`,
  { mode: 0o755 },
);
process.env.PATH = `${work}:${process.env.PATH}`;
const doctorRuns = () => (fs.existsSync(ran) ? fs.readFileSync(ran, "utf8").trim().split("\n").length : 0);

// A copy beside nothing, so each import is a fresh module.
const copy = (src, name) => {
  const p = path.join(work, name);
  fs.copyFileSync(src, p);
  return p;
};
const unset = () => VARS.forEach((k) => delete process.env[k]);

// Each rendered file: the prelude exactly once, first, ahead of every line of the shipped file.
for (const [rendered, shipped] of [[pi, piShipped], [opencode, opencodeShipped]]) {
  const text = fs.readFileSync(rendered, "utf8");
  const ship = fs.readFileSync(shipped, "utf8");
  assert.equal(text.split(MARK).length - 1, 1, `${rendered}: one prelude`);
  assert.ok(text.startsWith(MARK), `${rendered}: the prelude comes first`);
  assert.ok(text.endsWith(ship), `${rendered}: the shipped file follows the prelude unchanged`);
  assert.equal(ship.includes(MARK), false, `${shipped}: the shipped file has no prelude`);
}

// pi, pinned, env unset: the module-level resolver returns the pins; doctor never runs.
unset();
const piPinned = await import(copy(pi, "pi-pinned.ts"));
for (const n of ["register", "agent", "http"]) {
  assert.equal(await piPinned.endpoints.resolve(n), `${dir}/${n}.sock`, `pi ${n}`);
}
assert.equal(doctorRuns(), 0, "the pinned pi file must not run xmsg doctor");

// Control: the shipped pi file, env unset, runs the fake doctor and takes its endpoints.
unset();
const piPlain = await import(copy(piShipped, "pi-shipped.ts"));
assert.equal(await piPlain.endpoints.resolve("agent"), `${other}/agent.sock`);
assert.equal(doctorRuns(), 1, "control: the shipped pi file runs xmsg doctor");

// opencode, pinned, env unset: loading the file sets the pins before its own code.
unset();
await import(copy(opencode, "opencode-pinned.ts"));
for (const n of ["register", "agent", "http"]) {
  assert.equal(process.env[`XMSG_${n.toUpperCase()}_SOCK`], `${dir}/${n}.sock`, `opencode ${n}`);
}
// An explicit pin already in the environment wins over the prelude.
unset();
process.env.XMSG_AGENT_SOCK = "/explicit/agent.sock";
await import(copy(opencode, "opencode-explicit.ts"));
assert.equal(process.env.XMSG_AGENT_SOCK, "/explicit/agent.sock");
// Control: the shipped opencode file sets nothing.
unset();
await import(copy(opencodeShipped, "opencode-shipped.ts"));
assert.deepEqual(VARS.filter((k) => k in process.env), []);
assert.equal(doctorRuns(), 1, "loading opencode runs no doctor");

console.log("pinned-plugins: prelude once and first; pins resolve without doctor; controls pass");
