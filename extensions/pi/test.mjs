import assert from "node:assert/strict";
import net from "node:net";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";
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

  assert.equal(mockPi.tools.length, 1);
  const replyTool = mockPi.tools[0];
  assert.equal(replyTool.name, "reply");
  assert.equal(typeof replyTool.description, "string");
  assert.ok(replyTool.parameters);
  assert.equal(replyTool.parameters.type, "object");
  assert.ok(replyTool.parameters.properties.message_id);
  assert.ok(replyTool.parameters.properties.text);
  console.log("✔ Test 1 passed: Pi extension registers 'reply' tool with valid schema");
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
        if (receivedReq.messageId === "msg-valid") {
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
        } else if (receivedReq.messageId === "msg-not-recipient") {
          socket.write(
            JSON.stringify({
              status: "error",
              error: "not_recipient",
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
  assert.equal(receivedReq.messageId, "msg-valid");
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
  assert.equal(result2.details.error, "not_recipient");

  await new Promise((r) => server.close(r));
  fs.rmSync(tmpDir, { recursive: true, force: true });
  console.log("✔ Test 3 passed: Pi reply tool connects to agent.sock and handles reply correctly");
}

async function main() {
  try {
    await runTest1();
    await runTest2();
    await runTest3();
    console.log("\nALL EXTENSION TESTS PASSED!");
    process.exit(0);
  } catch (err) {
    console.error("Test failure:", err);
    process.exit(1);
  }
}

main();
