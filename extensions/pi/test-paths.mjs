// Socket path resolution of the xmsg-pi extension, runnable without pi.
//
// Loads index.ts through Node's built-in type stripping (Node 23.6 or later)
// and stubs `typebox`, which index.ts only uses inside its tool definitions.
// The pi import is type-only and is erased. Run with: node extensions/pi/test-paths.mjs
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { registerHooks } from "node:module";
import path from "node:path";

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "typebox") {
      return { url: "data:text/javascript,export const Type = {};", shortCircuit: true };
    }
    return nextResolve(specifier, context);
  },
});

const { defaultRegisterSockPath, defaultAgentSockPath } = await import("./index.ts");

const keys = ["XDG_RUNTIME_DIR", "XMSG_REGISTER_SOCK", "XMSG_AGENT_SOCK"];
for (const k of keys) delete process.env[k];

// What the xmsg binary falls back to when XDG_RUNTIME_DIR is unset or blank.
const fallback =
  process.platform === "darwin"
    ? execFileSync("/usr/bin/getconf", ["DARWIN_USER_TEMP_DIR"], { encoding: "utf8" }).trim()
    : undefined;
const fallbackSock = (name) => (fallback ? path.join(fallback, "xmsg", name) : undefined);

for (const blank of [undefined, "", "   "]) {
  if (blank === undefined) delete process.env.XDG_RUNTIME_DIR;
  else process.env.XDG_RUNTIME_DIR = blank;
  const label = `XDG_RUNTIME_DIR=${JSON.stringify(blank)}`;
  assert.equal(defaultRegisterSockPath(), fallbackSock("register.sock"), label);
  assert.equal(defaultAgentSockPath(), fallbackSock("agent.sock"), label);
}

process.env.XDG_RUNTIME_DIR = "/run/user/1000";
assert.equal(defaultRegisterSockPath(), "/run/user/1000/xmsg/register.sock");
assert.equal(defaultAgentSockPath(), "/run/user/1000/xmsg/agent.sock");

process.env.XMSG_REGISTER_SOCK = "/custom/register.sock";
process.env.XMSG_AGENT_SOCK = "/custom/agent.sock";
assert.equal(defaultRegisterSockPath(), "/custom/register.sock");
assert.equal(defaultAgentSockPath(), "/custom/agent.sock");

console.log("✔ socket paths follow XMSG_*_SOCK, then a non-blank XDG_RUNTIME_DIR, then the platform runtime dir");
