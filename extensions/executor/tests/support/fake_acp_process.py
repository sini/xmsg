"""Test-only ACP v1 process. No model, tools, network, or shell execution."""
import json
import os
import sys

for raw in sys.stdin:
    frame = json.loads(raw)
    if frame.get("method") == "initialize":
        result = {"protocolVersion": 1, "agentCapabilities": {}}
    elif frame.get("method") == "session/new":
        result = {"sessionId": "fake-native-session"}
    else:
        if "id" in frame:
            print(json.dumps({"jsonrpc": "2.0", "id": frame["id"], "error": {"code": -32601, "message": "unsupported fake method"}}), flush=True)
        continue
    print(json.dumps({"jsonrpc": "2.0", "id": frame["id"], "result": result}), flush=True)
