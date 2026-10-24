# Benchmark

raijin-mcp does not reduce anything itself: every Raijin tool already returns compact JSON. What an
MCP server adds to an agent's context is **the tool list** (names, descriptions and input schemas),
which the client sends to the model on every turn. So this benchmark measures two things:

1. the size of `tools/list`, the fixed cost of having the tools available;
2. end-to-end calls, to show the result the model reads is exactly what the CLI prints.

Everything below comes from `bench/run.sh` (2026-10-24, Go 1.27, tiktoken `o200k_base` and
`cl100k_base`; Claude's tokenizer is not public, so the Claude column is `n/a` without an API key).
Nothing is sent to the network: each call replays a saved engine output with `--input`.

```bash
PY=<python with tiktoken> bench/run.sh [workdir]
```

`run.sh` builds raijin-mcp and every sibling repo next to it (`../raijin-<verb>`) that builds. On
this run 13 of the 14 tools built; raijin-js was still in development, so it is only in the
"all 14 tools" row, through a stand-in binary whose `-h` gives nothing (raijin-mcp then lists it
straight from its static table).

## tools/list

| Output | Lines | Bytes | Tokens (o200k) | Tokens (cl100k) |
|---|---:|---:|---:|---:|
| `tools/list`, 13 installed tools (whole JSON-RPC line) | 1 | 11,182 | 2,636 | 2,496 |
| tools array only, 13 installed tools | 1 | 11,138 | 2,620 | 2,481 |
| tools array only, all 14 tools | 1 | 11,946 | 2,809 | 2,660 |
| tools array only, `--tools scan,probe` | 1 | 1,991 | 462 | 438 |
| `initialize` result (sent once) | 1 | 440 | 112 | 113 |
| for comparison: `-h` of the 13 binaries | 484 | 18,727 | 5,113 | 5,115 |

Per tool (tools array entry, o200k): scan 255, ports 241, params 225, tls 216, crawl 215, xss 208,
probe 205, subs 203, takeover 193, fuzz 191, secrets 189, cors 188, diff 89. About 200 tokens a
tool, most of it the JSON Schema keywords (`"type"`, `"items"`, `"description"`) that every MCP
tool pays.

How to read it, honestly:

- **The whole arsenal costs about 2.6k tokens of context** while it is available. Clients that
  cache the prompt pay that once per conversation, others once per turn. `--tools` cuts it to what
  the task needs: 462 tokens for scan and probe.
- **It is about half the `-h` text** an agent would read to learn the same 13 CLIs through a shell,
  and the schema is typed, so the model does not have to parse usage text or guess flags. It is not
  free: an agent that already knows one CLI and calls it through a shell pays nothing for the list.
- **Descriptions are terse on purpose.** The shared output format is explained once in the
  `initialize` instructions (112 tokens) instead of in every tool. Params whose flag the installed
  binary does not have are dropped from the schema.

## End-to-end calls

Each sibling repo's `testdata/` fixture, called through MCP (`tools/call` with `scope` and
`input`) and through the CLI (`raijin-<verb> --scope scope.txt --input <fixture>`). raijin-xss and
raijin-tls ship no fixture in `testdata/`, and raijin-diff takes no `--input`, so they are not in
this table.

| Tool | MCP result text vs CLI stdout | CLI stdout tokens | MCP result text tokens | Whole JSON-RPC response tokens |
|---|---|---:|---:|---:|
| raijin_scan | identical, byte for byte | 190 | 190 | 228 |
| raijin_probe | identical, byte for byte | 385 | 385 | 449 |
| raijin_subs | identical, byte for byte | 594 | 594 | 698 |
| raijin_ports | identical, byte for byte | 801 | 801 | 903 |
| raijin_crawl | identical, byte for byte | 681 | 681 | 791 |
| raijin_params | identical, byte for byte | 496 | 496 | 626 |
| raijin_fuzz | identical, byte for byte | 506 | 506 | 575 |
| raijin_secrets | identical, byte for byte | 71 | 71 | 97 |
| raijin_cors | identical, byte for byte | 432 | 432 | 494 |
| raijin_takeover | identical, byte for byte | 1,036 | 1,036 | 1,196 |

The result text is the tool's stdout unchanged: no pretty-printing, no wrapping, no
`structuredContent` copy (which would send the same JSON twice). The JSON-RPC envelope and the
escaping of the quotes inside the text string add 10% to 30% on the wire, but clients unwrap the
envelope and decode the string before the model reads it, so the model reads the middle column.
