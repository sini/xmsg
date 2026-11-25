"""Test-only ACP peer: deterministic wire responses, without a provider or tools."""
import fcntl
import shutil
import json
import os
import resource
import socket
import stat
import sys

trace = sys.argv[1]
base = os.path.splitext(trace)[0]
with open(base + ".fd-expected", encoding="utf-8") as source:
    expected = json.load(source)
inherited = []
matching = []
limit = min(resource.getrlimit(resource.RLIMIT_NOFILE)[0], 65536)
if expected["fd"] >= limit:
    sys.exit(3)
for descriptor in range(limit):
    try:
        metadata = os.fstat(descriptor)
    except OSError:
        continue
    if stat.S_ISSOCK(metadata.st_mode):
        identity = {"dev": metadata.st_dev, "ino": metadata.st_ino,
                    "kind": stat.S_IFMT(metadata.st_mode), "fd": descriptor}
        if os.environ.get("XMSG_EXECUTOR_FD_DIAGNOSTICS"):
            identity["flags"] = fcntl.fcntl(descriptor, fcntl.F_GETFD)
            identity["mode"] = metadata.st_mode
            peer = socket.socket(fileno=descriptor)
            try:
                identity["socket_type"] = peer.getsockopt(socket.SOL_SOCKET, socket.SO_TYPE)
                identity["family"] = peer.family
                for key, getter in [("sockname", peer.getsockname), ("peername", peer.getpeername)]:
                    try:
                        identity[key] = repr(getter())
                    except OSError as error:
                        identity[key] = repr(error)
            finally:
                peer.detach()
        inherited.append(identity)
        if all(identity[key] == expected[key] for key in ("dev", "ino", "kind")):
            matching.append(identity)
with open(base + ".fd-proof", "w", encoding="utf-8") as output:
    json.dump({"matching_startup_sockets": matching, "inherited_sockets": inherited,
               "scanned": limit, "expected": expected}, output)
if os.environ.get("XMSG_EXECUTOR_FD_DIAGNOSTICS"):
    destination = os.environ["XMSG_EXECUTOR_FD_DIAGNOSTICS"]
    os.makedirs(destination, exist_ok=True)
    for suffix in [".fd-expected", ".fd-proof"]:
        shutil.copyfile(base + suffix, os.path.join(destination, str(os.getpid()) + suffix))
    with open(os.path.join(destination, str(os.getpid()) + ".child.json"), "w") as output:
        json.dump({"pid": os.getpid(), "pgid": os.getpgid(0), "session": os.getsid(0), "fds": inherited}, output)
session = "fake-native-session"
model = "fake-model"
mode = "default"
fairness = len(sys.argv) > 3 and sys.argv[3] == "fairness"
unsupported = len(sys.argv) > 3 and sys.argv[3] == "unsupported"
prompt_id = None

def configuration():
    return {"configOptions": [
        {"id": "model", "type": "select", "currentValue": model},
        {"id": "mode", "type": "select", "currentValue": mode},
    ]}

for raw in sys.stdin:
    frame = json.loads(raw)
    method = frame.get("method")
    with open(trace, "a", encoding="utf-8") as output:
        output.write(json.dumps(frame) + "\n")
        output.flush()
    if unsupported and frame.get("id") == 900 and "error" in frame:
        with socket.socket(socket.AF_UNIX) as receipt:
            receipt.connect(sys.argv[4])
            receipt.sendall(b"D")
        print(json.dumps({"jsonrpc": "2.0", "id": prompt_id, "result": {"stopReason": "end_turn"}}), flush=True)
        continue
    if method == "initialize":
        result = {"protocolVersion": 1, "agentCapabilities": {}, "_meta": {"steering": {"supported": True}}}
    elif method == "session/new":
        result = {"sessionId": session}
    elif method == "session/set_mode":
        mode = frame["params"]["modeId"]
        print(json.dumps({"jsonrpc": "2.0", "method": "session/update", "params": {
            "sessionId": session, "update": {"sessionUpdate": "config_option_update",
            "configOptions": configuration()["configOptions"]}}}), flush=True)
        result = {}
    elif method == "session/set_config_option":
        model = frame["params"]["value"]
        result = configuration()
    elif method == "session/prompt":
        prompt_id = frame["id"]
        if len(sys.argv) > 2:
            with socket.socket(socket.AF_UNIX) as barrier:
                barrier.connect(sys.argv[2])
                barrier.sendall(b"P")
                if barrier.recv(1) != b"R":
                    sys.exit(2)
        if unsupported:
            print(json.dumps({"jsonrpc": "2.0", "id": 900, "method": "_session/tool_error", "params": {
                "sessionId": session, "toolCall": {"toolCallId": "failed-tool", "status": "failed", "title": "denied"},
                "options": [{"optionId": "once", "name": "untrusted retry", "kind": "allow_once"}]}}), flush=True)
            continue
        if fairness:
            frames = []
            for index in range(8):
                frames.append(json.dumps({"jsonrpc": "2.0", "method": "session/update", "params": {
                    "sessionId": session, "update": {"sessionUpdate": "agent_message_chunk", "content": {
                        "type": "text", "text": "batch-end" if index == 7 else "x" * 80}}}}) + "\n")
            batch = "".join(frames).encode()
            if len(batch) > 4096 or os.write(sys.stdout.fileno(), batch) != len(batch):
                sys.exit(4)
            continue
        result = {"stopReason": "end_turn"}
    elif method == "_session/steering":
        if fairness:
            with socket.socket(socket.AF_UNIX) as receipt:
                receipt.connect(sys.argv[4])
                receipt.sendall(b"S")
        result = {"outcome": "injected"}
    else:
        if "id" in frame:
            print(json.dumps({"jsonrpc": "2.0", "id": frame["id"], "error": {
                "code": -32601, "message": "unsupported fake method"}}), flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": frame["id"], "result": result}), flush=True)
