# Benchmark

raijin-mcp does not reduce anything itself: every Raijin tool already returns compact JSON. What an
MCP server adds to an agent's context is **the tool list** (names, descriptions and input schemas),
which the client sends to the model on every turn. So this benchmark measures two things:

1. the size of `tools/list`, the fixed cost of having the tools available;
2. end-to-end calls, to show the result the model reads is exactly what the CLI prints.

Everything below comes from `bench/run.sh` (2026-10-29, Go 1.27, tiktoken `o200k_base` and
`cl100k_base`; Claude's tokenizer is not public, so the Claude column is `n/a` without an API key).
Nothing is sent to the network: each call replays a saved engine output with `--input`.

```bash
PY=<python with tiktoken> bench/run.sh [workdir]
```

`run.sh` builds raijin-mcp and every sibling repo next to it (`../raijin-<verb>`) that builds. On
this run all 14 tools built (the siblings need raijin-core, so the run used a `go.work` outside the
repos). The `tools` array also holds `raijin_update`, which is always listed (80 tokens).

## tools/list

| Output | Lines | Bytes | Tokens (o200k) | Tokens (cl100k) |
|---|---:|---:|---:|---:|
| `tools/list`, 14 installed tools (whole JSON-RPC line) | 1 | 12,699 | 2,989 | 2,837 |
| tools array only, 14 installed tools | 1 | 12,655 | 2,973 | 2,822 |
| tools array only, all 14 tools | 1 | 12,655 | 2,973 | 2,822 |
| tools array only, `--tools scan,probe` | 1 | 2,400 | 556 | 530 |
| `initialize` result (sent once) | 1 | 543 | 133 | 134 |
| for comparison: `-h` of the 14 binaries | 562 | 22,258 | 6,024 | 6,025 |

Per tool (tools array entry, o200k): scan 262, ports 248, params 232, tls 223, crawl 222, xss 215,
probe 212, subs 210, takeover 200, fuzz 198, js 196, cors 195, secrets 189, diff 89, update 80. About
200 tokens a tool, most of it the JSON Schema keywords (`"type"`, `"items"`, `"description"`) that
every MCP tool pays.

How to read it, honestly:

- **The whole arsenal costs about 3.0k tokens of context** while it is available. Clients that
  cache the prompt pay that once per conversation, others once per turn. `--tools` cuts it to what
  the task needs: 556 tokens for scan and probe.
- **It is about half the `-h` text** an agent would read to learn the same 14 CLIs through a shell,
  and the schema is typed, so the model does not have to parse usage text or guess flags. It is not
  free: an agent that already knows one CLI and calls it through a shell pays nothing for the list.
- **Descriptions are terse on purpose.** The shared output format is explained once in the
  `initialize` instructions (133 tokens) instead of in every tool. Params whose flag the installed
  binary does not have are dropped from the schema.

## End-to-end calls

Each sibling repo's `testdata/` fixture, called through MCP (`tools/call` with `scope` and
`input`) and through the CLI (`raijin-<verb> --scope scope.txt --input <fixture>`). raijin-diff takes no
`--input`, so it is not in this table.

| Tool | MCP result text vs CLI stdout | CLI stdout tokens | MCP result text tokens | Whole JSON-RPC response tokens |
|---|---|---:|---:|---:|
| raijin_scan | identical, byte for byte | 270 | 270 | 311 |
| raijin_probe | identical, byte for byte | 395 | 395 | 459 |
| raijin_subs | identical, byte for byte | 603 | 603 | 707 |
| raijin_ports | identical, byte for byte | 813 | 813 | 915 |
| raijin_crawl | identical, byte for byte | 705 | 705 | 815 |
| raijin_js | identical, byte for byte | 898 | 898 | 1,036 |
| raijin_params | identical, byte for byte | 506 | 506 | 636 |
| raijin_fuzz | identical, byte for byte | 514 | 514 | 583 |
| raijin_tls | identical, byte for byte | 1,450 | 1,450 | 1,561 |
| raijin_secrets | identical, byte for byte | 80 | 80 | 108 |
| raijin_xss | identical, byte for byte | 815 | 815 | 878 |
| raijin_cors | identical, byte for byte | 441 | 441 | 503 |
| raijin_takeover | identical, byte for byte | 1,059 | 1,059 | 1,219 |

The result text is the tool's stdout unchanged: no pretty-printing, no wrapping, no
`structuredContent` copy (which would send the same JSON twice). The JSON-RPC envelope and the
escaping of the quotes inside the text string add 10% to 30% on the wire, but clients unwrap the
envelope and decode the string before the model reads it, so the model reads the middle column.
