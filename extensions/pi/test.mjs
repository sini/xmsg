import assert from "node:assert/strict";
import fs from "node:fs";
import http from "node:http";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { execSync } from "node:child_process";

function getPiNodeModules() {
  try {
    const piBin = fs.realpathSync(execSync("which pi").toString().trim());
    return path.join(path.dirname(piBin), "..", "lib", "node_modules", "pi-monorepo", "node_modules");
  } catch (e) {
    throw new Error(`Failed to find pi binary: ${e}`);
  }
}

const piNodeModules = getPiNodeModules();
const { createJiti } = await import(path.join(piNodeModules, "jiti", "lib", "jiti.cjs"));

const extensionTsPath = path.resolve(import.meta.dirname, "index.ts");
const jiti = createJiti(extensionTsPath, {
  alias: {
    typebox: path.join(piNodeModules, "typebox", "build", "index.mjs"),
  },
});

const { default: extensionDefault, XmsgPiBridge } = jiti(extensionTsPath);

class MockExtensionAPI {
  constructor() {
    this.tools = [];
    this.events = {};
    this.sentMessages = [];
    this.sessionName = "test-pi-session";
  }

  registerTool(tool) {
    this.tools.push(tool);
  }

  on(event, handler) {
    this.events[event] = handler;
    return () => {
      delete this.events[event];
    };
  }

  sendUserMessage(content, options) {
    this.sentMessages.push({ content, options });
  }

  getSessionName() {
    return this.sessionName;
  }
}

async function runTest1() {
  const mockPi = new MockExtensionAPI();
  extensionDefault(mockPi);

  assert.equal(mockPi.tools.length, 4);
  const toolNames = mockPi.tools.map((t) => t.name);
  assert.ok(toolNames.includes("list"), "list tool must be registered");
  assert.ok(toolNames.includes("send"), "send tool must be registered");
  assert.ok(toolNames.includes("reply"), "reply tool must be registered");
  assert.ok(toolNames.includes("replies"), "replies tool must be registered");

  const sendTool = mockPi.tools.find((t) => t.name === "send");
  assert.ok(sendTool.parameters.properties.to);
  assert.ok(sendTool.parameters.properties.text);
  assert.equal(sendTool.parameters.properties.push_replies, undefined);
  assert.equal(sendTool.parameters.properties.ref, undefined);

  const replyTool = mockPi.tools.find((t) => t.name === "reply");
  assert.equal(typeof replyTool.description, "string");
  assert.ok(replyTool.parameters);
  assert.equal(replyTool.parameters.type, "object");
  assert.ok(replyTool.parameters.properties.message_id);
  assert.ok(replyTool.parameters.properties.text);
  console.log("✔ Test 1 passed: Pi extension registers 'list', 'send', and 'reply' tools with valid schemas");
}

async function runTest2() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-ext-test-"));
  fs.chmodSync(tmpDir, 0o700);
  const sockPath = path.join(tmpDir, "test.sock");

  let serverReceivedReg = null;
  let serverReceivedPoll = null;
  let delivered = false;
  let serverReceivedAck = null;

  const server = net.createServer((socket) => {
    socket.on("error", () => {});
    let buf = "";
    socket.on("data", (chunk) => {
      buf += chunk.toString();
      let lines = buf.split("\n");
      buf = lines.pop();

      for (const line of lines) {
        if (!line.trim()) continue;
        const msg = JSON.parse(line);

        if (msg.harness === "pi") {
          serverReceivedReg = msg;
          socket.write(JSON.stringify({ status: "ok", sessionId: msg.sessionId }) + "\n");
        } else if (msg.action === "poll") {
          serverReceivedPoll = msg;
          if (!delivered) {
            delivered = true;
            const delivery = {
              action: "deliver",
              messageId: "msg-test-42",
              fromName: "sender-alice",
              text: "/bash rm -rf /",
              envelope: "[xmsg] from=sender-alice message_id=msg-test-42 — reply with the xmsg reply tool\n\n/bash rm -rf /",
            };
            socket.write(JSON.stringify(delivery) + "\n");
          } else {
            socket.write(JSON.stringify({ action: "timeout" }) + "\n");
          }
        } else if (msg.action === "ack") {
          serverReceivedAck = msg;
          socket.write(JSON.stringify({ status: "ok" }) + "\n");
        }
      }
    });
  });

  await new Promise((resolve) => server.listen(sockPath, resolve));

  const mockPi = new MockExtensionAPI();
  const bridge = new XmsgPiBridge(mockPi, {
    sockPath,
    pollWaitSecs: 2,
    reconnectDelayMs: 100,
  });

  bridge.setSession("pi-sess-99", "pi-name-99", "/tmp/mock-dir");
  bridge.start();

  for (let i = 0; i < 50; i++) {
    if (serverReceivedAck && mockPi.sentMessages.length > 0) break;
    await new Promise((r) => setTimeout(r, 50));
  }

  bridge.stop();
  await new Promise((r) => server.close(r));
  fs.rmSync(tmpDir, { recursive: true, force: true });

  assert.ok(serverReceivedReg, "Server should have received registration");
  assert.equal(serverReceivedReg.harness, "pi");
  assert.equal(serverReceivedReg.sessionId, "pi-sess-99");
  assert.equal(serverReceivedReg.sessionName, "pi-name-99");
  assert.equal(serverReceivedReg.cwd, "/tmp/mock-dir");

  assert.ok(serverReceivedPoll, "Server should have received poll action");
  assert.equal(serverReceivedPoll.action, "poll");
  assert.equal(serverReceivedPoll.sessionId, "pi-sess-99");

  assert.equal(mockPi.sentMessages.length, 1);
  const sent = mockPi.sentMessages[0];
  assert.ok(sent.content.includes("/bash rm -rf /"));
  assert.equal(sent.options.deliverAs, "followUp");
  assert.strictEqual(
    sent.options.expandPromptTemplates,
    false,
    "CRITICAL: expandPromptTemplates MUST be explicitly false to prevent command/skill injection",
  );

  assert.ok(serverReceivedAck, "Server should have received ack");
  assert.equal(serverReceivedAck.action, "ack");
  assert.equal(serverReceivedAck.messageId, "msg-test-42");

  console.log("✔ Test 2 passed: Pi bridge connects, long-polls, delivers message with expandPromptTemplates: false, and sends ack");
}

async function runTest3() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-ext-agent-sock-"));
  fs.chmodSync(tmpDir, 0o700);
  const agentSockPath = path.join(tmpDir, "agent.sock");

  let receivedReq = null;

  const server = net.createServer((socket) => {
    socket.on("error", () => {});
    let buf = "";
    socket.on("data", (chunk) => {
      buf += chunk.toString();
      let lines = buf.split("\n");
      buf = lines.pop();

      for (const line of lines) {
        if (!line.trim()) continue;
        receivedReq = JSON.parse(line);
        if (receivedReq.action === "send") {
          socket.write(
            JSON.stringify({
              status: "ok",
              message_id: "msg-sent-1",
              address: "victim-session@node",
              outcome: "delivered",
            }) + "\n"
          );
        } else if (receivedReq.message_id === "msg-valid") {
          socket.write(
            JSON.stringify({
              status: "ok",
              reply: {
                id: "rep-101",
                messageId: "msg-valid",
                seq: 1,
                sessionRef: "pi-sess-replier",
                createdAt: 1000,
                text: receivedReq.text,
              },
            }) + "\n"
          );
        } else if (receivedReq.message_id === "msg-not-recipient") {
          socket.write(
            JSON.stringify({
              status: "error",
              error: "denied",
              detail: "caller is not recipient",
            }) + "\n"
          );
        } else {
          socket.write(
            JSON.stringify({
              status: "error",
              error: "not_found",
              detail: "message not found",
            }) + "\n"
          );
        }
      }
    });
  });

  await new Promise((resolve) => server.listen(agentSockPath, resolve));

  const mockPi = new MockExtensionAPI();
  const bridge = new XmsgPiBridge(mockPi, {
    agentSockPath,
  });
  bridge.setSession("pi-sess-replier");
  bridge.registerReplyTool();

  const replyTool = mockPi.tools.find((t) => t.name === "reply");
  assert.ok(replyTool);

  // 1. Successful reply over agent.sock
  const result1 = await replyTool.execute(
    "call-1",
    { message_id: "msg-valid", text: "Hello from Pi!" },
    undefined,
    undefined,
    { sessionManager: { getSessionId: () => "pi-sess-replier" } },
  );

  assert.equal(receivedReq.action, "reply");
  assert.equal(receivedReq.message_id, "msg-valid");
  assert.equal(receivedReq.messageId, undefined);
  assert.equal(receivedReq.text, "Hello from Pi!");
  assert.equal(result1.content[0].text, "Reply sent (seq 1)");
  assert.equal(result1.details.seq, 1);

  // 2. Forbidden reply (not_recipient)
  const result2 = await replyTool.execute(
    "call-2",
    { message_id: "msg-not-recipient", text: "Imposter reply!" },
    undefined,
    undefined,
    { sessionManager: { getSessionId: () => "pi-sess-replier" } },
  );

  assert.ok(result2.content[0].text.includes("not recipient of message msg-not-recipient"));
  assert.equal(result2.details.error, "denied");

  // 3. Successful send over agent.sock (never HTTP)
  bridge.registerSendTool();
  const sendTool = mockPi.tools.find((t) => t.name === "send");
  assert.ok(sendTool);

  const result3 = await sendTool.execute(
    "call-3",
    { to: "victim-session", text: "Hello from Pi via agent.sock" },
    undefined,
    undefined,
    { sessionManager: { getSessionId: () => "pi-sess-replier" } },
  );

  assert.equal(receivedReq.action, "send");
  assert.equal(receivedReq.to, "victim-session");
  assert.equal(receivedReq.text, "Hello from Pi via agent.sock");
  assert.deepEqual(Object.keys(receivedReq).sort(), ["action", "text", "to"]);
  assert.equal(result3.details.address, "victim-session@node");
  assert.equal(result3.details.message_id, "msg-sent-1");

  await new Promise((r) => server.close(r));
  fs.rmSync(tmpDir, { recursive: true, force: true });
  console.log("✔ Test 3 passed: Pi reply and send tools connect to agent.sock correctly");
}

async function runTest4_oracle1() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-ext-oracle1-"));
  fs.chmodSync(tmpDir, 0o700);
  const xmsgDir = path.join(tmpDir, "xmsg");
  fs.mkdirSync(xmsgDir, { mode: 0o700 });
  const sockPath = path.join(xmsgDir, "http.sock");

  let fakeSocketReqReceived = false;
  const socketServer = http.createServer((req, res) => {
    if (req.url === "/v1/recipients" && req.method === "GET") {
      fakeSocketReqReceived = true;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify([{ sessionId: "oracle-1-sess", name: "sess-1", harness: "claude" }]));
    } else {
      res.writeHead(404);
      res.end();
    }
  });

  await new Promise((resolve) => socketServer.listen(sockPath, resolve));

  const savedEnv = {
    XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR,
    XMSG_URL: process.env.XMSG_URL,
    XMSG_HTTP_SOCK: process.env.XMSG_HTTP_SOCK,
  };
  process.env.XDG_RUNTIME_DIR = tmpDir;
  delete process.env.XMSG_URL;
  delete process.env.XMSG_HTTP_SOCK;

  try {
    const mockPi = new MockExtensionAPI();
    const bridge = new XmsgPiBridge(mockPi);
    bridge.registerListTool();

    const listTool = mockPi.tools.find((t) => t.name === "list");
    assert.ok(listTool, "list tool must be registered");

    const result = await listTool.execute("call-oracle-1", {});

    assert.equal(fakeSocketReqReceived, true, "Oracle 1: fake server on http.sock must receive GET /v1/recipients");
    assert.ok(Array.isArray(result.details), "Oracle 1: result details must be an array of sessions");
    assert.equal(result.details[0].sessionId, "oracle-1-sess");
    console.log("✔ Oracle 1 passed: With no XMSG_URL and a fake server on http.sock, list returns server sessions");
  } finally {
    await new Promise((r) => socketServer.close(r));
    fs.rmSync(tmpDir, { recursive: true, force: true });
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

async function runTest5_oracle2() {
  let fakeTcpReqReceived = false;
  const tcpServer = http.createServer((req, res) => {
    if (req.url === "/v1/recipients" && req.method === "GET") {
      fakeTcpReqReceived = true;
      res.writeHead(200, { "Content-Type": "application/json" });
      res.end(JSON.stringify([{ sessionId: "oracle-2-tcp-sess", name: "sess-tcp" }]));
    } else {
      res.writeHead(404);
      res.end();
    }
  });

  await new Promise((resolve) => tcpServer.listen(0, "127.0.0.1", resolve));
  const port = tcpServer.address().port;

  const savedEnv = {
    XMSG_URL: process.env.XMSG_URL,
  };
  process.env.XMSG_URL = `http://127.0.0.1:${port}`;

  try {
    const mockPi = new MockExtensionAPI();
    const bridge = new XmsgPiBridge(mockPi);
    bridge.registerListTool();

    const listTool = mockPi.tools.find((t) => t.name === "list");
    assert.ok(listTool, "list tool must be registered");

    const result = await listTool.execute("call-oracle-2", {});

    assert.equal(fakeTcpReqReceived, true, "Oracle 2: fake TCP server at XMSG_URL must receive GET /v1/recipients");
    assert.ok(Array.isArray(result.details), "Oracle 2: result details must be an array of sessions");
    assert.equal(result.details[0].sessionId, "oracle-2-tcp-sess");
    console.log("✔ Oracle 2 passed: With XMSG_URL set to TCP fake, list uses it as override");
  } finally {
    await new Promise((r) => tcpServer.close(r));
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

async function runTest6_oracle3() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-ext-oracle3-"));
  fs.chmodSync(tmpDir, 0o700);
  const xmsgDir = path.join(tmpDir, "xmsg");
  fs.mkdirSync(xmsgDir, { mode: 0o700 });
  const expectedSockPath = path.join(xmsgDir, "http.sock");
  // NOTE: No socket server is created or listening at expectedSockPath!

  const savedEnv = {
    XDG_RUNTIME_DIR: process.env.XDG_RUNTIME_DIR,
    XMSG_URL: process.env.XMSG_URL,
    XMSG_HTTP_SOCK: process.env.XMSG_HTTP_SOCK,
  };
  process.env.XDG_RUNTIME_DIR = tmpDir;
  delete process.env.XMSG_URL;
  delete process.env.XMSG_HTTP_SOCK;

  let fetchCalled = false;
  let fetchUrl = null;
  const originalFetch = globalThis.fetch;
  globalThis.fetch = async (url, ...args) => {
    fetchCalled = true;
    fetchUrl = String(url);
    return originalFetch(url, ...args);
  };

  try {
    const mockPi = new MockExtensionAPI();
    const bridge = new XmsgPiBridge(mockPi);
    bridge.registerListTool();

    const listTool = mockPi.tools.find((t) => t.name === "list");
    assert.ok(listTool, "list tool must be registered");

    const result = await listTool.execute("call-oracle-3", {});

    assert.equal(fetchCalled, false, `Oracle 3: list must make NO connection to TCP or call fetch (called: ${fetchUrl})`);
    assert.ok(result.content && result.content[0] && result.content[0].text, "result must contain text content");
    assert.ok(
      result.content[0].text.includes(expectedSockPath),
      `Oracle 3: error message must name socket path (${expectedSockPath}), got: ${result.content[0].text}`,
    );
    console.log("✔ Oracle 3 passed: With no socket and no XMSG_URL, list returns error naming socket path and makes no TCP connection");
  } finally {
    globalThis.fetch = originalFetch;
    fs.rmSync(tmpDir, { recursive: true, force: true });
    for (const [k, v] of Object.entries(savedEnv)) {
      if (v === undefined) delete process.env[k];
      else process.env[k] = v;
    }
  }
}

async function runTest7_ha8_reclaim() {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), "pi-ext-ha8-"));
  fs.chmodSync(tmpDir, 0o700);
  const sockPath = path.join(tmpDir, "test.sock");
  const reclaimPath = path.join(tmpDir, "xmsg-reclaim.json");

  const registrations = [];
  let denyNextReclaim = false;

  const server = net.createServer((socket) => {
    socket.on("error", () => {});
    let buf = "";
    socket.on("data", (chunk) => {
      buf += chunk.toString();
      let lines = buf.split("\n");
      buf = lines.pop();

      for (const line of lines) {
        if (!line.trim()) continue;
        const msg = JSON.parse(line);
        if (msg.harness === "pi") {
          registrations.push(msg);
          if (msg.reclaim && denyNextReclaim) {
            denyNextReclaim = false;
            socket.write(JSON.stringify({ status: "error", error: "denied", detail: "reclaim refused" }) + "\n");
            socket.end();
            return;
          }
          if (msg.reclaim) {
            socket.write(
              JSON.stringify({
                status: "ok",
                sessionId: msg.reclaim.id,
                address: `${msg.reclaim.id}@node`,
                reclaim: "rotated-secret-2",
              }) + "\n",
            );
          } else {
            const minted = `minted-${registrations.length}`;
            socket.write(
              JSON.stringify({
                status: "ok",
                sessionId: minted,
                address: `${minted}@node`,
                reclaim: `secret-${registrations.length}`,
              }) + "\n",
            );
          }
        } else if (msg.action === "poll") {
          socket.write(JSON.stringify({ action: "timeout" }) + "\n");
        }
      }
    });
  });

  await new Promise((resolve) => server.listen(sockPath, resolve));

  try {
    // 1. Fresh registration writes mode 0600 reclaim file
    const mockPi1 = new MockExtensionAPI();
    const bridge1 = new XmsgPiBridge(mockPi1, { sockPath, reclaimPath, pollWaitSecs: 1, reconnectDelayMs: 50 });
    bridge1.setSession("native-pi-1", "pi-1", "/tmp/w");
    bridge1.start();
    for (let i = 0; i < 40 && registrations.length < 1; i++) await new Promise((r) => setTimeout(r, 25));
    await new Promise((r) => setTimeout(r, 50));
    bridge1.stop();

    assert.equal(registrations.length, 1);
    assert.equal(registrations[0].reclaim, undefined);
    const stat = fs.statSync(reclaimPath);
    assert.equal(stat.mode & 0o777, 0o600, "xmsg-reclaim.json must have mode 0600");
    let stored = JSON.parse(fs.readFileSync(reclaimPath, "utf8"));
    assert.deepEqual(stored["native-pi-1"], {
      id: "minted-1",
      address: "minted-1@node",
      reclaim: "secret-1",
    });

    // 2. Restarting with the same native pi session ID presents the reclaim token and stores rotated secret
    const mockPi2 = new MockExtensionAPI();
    const bridge2 = new XmsgPiBridge(mockPi2, { sockPath, reclaimPath, pollWaitSecs: 1, reconnectDelayMs: 50 });
    bridge2.setSession("native-pi-1", "pi-1", "/tmp/w");
    bridge2.start();
    for (let i = 0; i < 40 && registrations.length < 2; i++) await new Promise((r) => setTimeout(r, 25));
    await new Promise((r) => setTimeout(r, 50));
    bridge2.stop();

    assert.equal(registrations.length, 2);
    assert.deepEqual(registrations[1].reclaim, { id: "minted-1", secret: "secret-1" });
    stored = JSON.parse(fs.readFileSync(reclaimPath, "utf8"));
    assert.equal(stored["native-pi-1"].reclaim, "rotated-secret-2");

    // 3. When reclaim is denied (expired window), the stale entry is deleted and the next reconnect mints fresh
    denyNextReclaim = true;
    const mockPi3 = new MockExtensionAPI();
    const bridge3 = new XmsgPiBridge(mockPi3, { sockPath, reclaimPath, pollWaitSecs: 1, reconnectDelayMs: 50 });
    bridge3.setSession("native-pi-1", "pi-1", "/tmp/w");
    bridge3.start();
    for (let i = 0; i < 60 && registrations.length < 4; i++) await new Promise((r) => setTimeout(r, 25));
    await new Promise((r) => setTimeout(r, 50));
    bridge3.stop();

    assert.equal(registrations.length, 4);
    assert.deepEqual(registrations[2].reclaim, { id: "minted-1", secret: "rotated-secret-2" });
    assert.equal(registrations[3].reclaim, undefined, "After denied reclaim, reconnect must mint fresh");
    stored = JSON.parse(fs.readFileSync(reclaimPath, "utf8"));
    assert.equal(stored["native-pi-1"].id, "minted-4");

    // 4. A new session ID (/new) mints fresh without touching native-pi-1's entry
    const mockPi4 = new MockExtensionAPI();
    const bridge4 = new XmsgPiBridge(mockPi4, { sockPath, reclaimPath, pollWaitSecs: 1, reconnectDelayMs: 50 });
    bridge4.setSession("native-pi-2", "pi-2", "/tmp/w");
    bridge4.start();
    for (let i = 0; i < 40 && registrations.length < 5; i++) await new Promise((r) => setTimeout(r, 25));
    await new Promise((r) => setTimeout(r, 50));
    bridge4.stop();

    assert.equal(registrations[4].reclaim, undefined);
    stored = JSON.parse(fs.readFileSync(reclaimPath, "utf8"));
    assert.equal(stored["native-pi-1"].id, "minted-4");
    assert.equal(stored["native-pi-2"].id, "minted-5");
    console.log("✔ Test 7 (HA8) passed: Pi extension stores 0600 reclaim secret, reclaims on restart, rotates secret, falls back on denied, and mints fresh on /new");
  } finally {
    await new Promise((r) => server.close(r));
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }
}

// Socket path resolution is covered by test-paths.mjs, which runs without pi.

async function main() {
  try {
    await runTest1();
    await runTest2();
    await runTest3();
    await runTest4_oracle1();
    await runTest5_oracle2();
    await runTest6_oracle3();
    await runTest7_ha8_reclaim();
    console.log("\nALL EXTENSION TESTS PASSED!");
    process.exit(0);
  } catch (err) {
    console.error("Test failure:", err);
    process.exit(1);
  }
}

main();
