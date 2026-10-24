"""Runs one MCP session against raijin-mcp and saves each response.

usage: python mcp_session.py <outdir> <raijin-mcp> [flags...] < calls.jsonl

calls.jsonl has one tools/call per line: {"name": "raijin_scan", "arguments": {...}}.
The session is initialize, notifications/initialized, tools/list, then the calls. It writes
initialize.json, tools_list.json (the whole JSON-RPC line), tools.json (only the tools array, what a
client puts in the model's context), and for call N: call-N.rpc.json (the line) and call-N.txt
(the result text the model reads).
"""
import json
import os
import subprocess
import sys

out, argv = sys.argv[1], sys.argv[2:]
calls = [json.loads(l) for l in sys.stdin if l.strip()]
reqs = [
    {"jsonrpc": "2.0", "id": 0, "method": "initialize",
     "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "bench", "version": "0"}}},
    {"jsonrpc": "2.0", "method": "notifications/initialized"},
    {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
]
for i, c in enumerate(calls):
    reqs.append({"jsonrpc": "2.0", "id": 10 + i, "method": "tools/call", "params": c})
stdin = "".join(json.dumps(r) + "\n" for r in reqs)
p = subprocess.run(argv, input=stdin, capture_output=True, text=True, check=True)
os.makedirs(out, exist_ok=True)
lines = {json.loads(l)["id"]: l for l in p.stdout.splitlines() if l.strip()}


def save(name, text):
    with open(os.path.join(out, name), "w", encoding="utf-8") as f:
        f.write(text)


save("initialize.json", lines[0] + "\n")
save("tools_list.json", lines[1] + "\n")
tools = json.loads(lines[1])["result"]["tools"]
save("tools.json", json.dumps(tools, separators=(",", ":")) + "\n")
for i in range(len(calls)):
    line = lines[10 + i]
    res = json.loads(line)["result"]
    save(f"call-{i}.rpc.json", line + "\n")
    save(f"call-{i}.txt", res["content"][0]["text"] + "\n")
    if res.get("isError"):
        print(f"call {i} returned isError: {res['content'][0]['text']}", file=sys.stderr)
print(f"{len(tools)} tools listed, {len(calls)} calls")
