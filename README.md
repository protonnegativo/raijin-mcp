# ⚡ Raijin MCP

**Every Raijin tool for any MCP client: one server, one typed tool per binary, the same compact JSON.**

`raijin-mcp` is the MCP server of **Raijin**, an arsenal of offensive security tools built for AI agents. It speaks the [Model Context Protocol](https://modelcontextprotocol.io) over stdio and exposes each Raijin binary it finds on `PATH` as a tool: `raijin_scan` (nuclei), `raijin_probe` (httpx), `raijin_subs`, `raijin_ports`, `raijin_crawl`, `raijin_params`, `raijin_fuzz`, `raijin_tls`, `raijin_secrets`, `raijin_xss`, `raijin_cors`, `raijin_takeover`, `raijin_js` and `raijin_diff`. A call runs the binary with `--format json` and returns its stdout, the **Raijin Schema**, as the tool result.

## Why not just run the tools from a shell?

An agent with a shell can run `raijin-scan` directly, and the result is the same JSON. What MCP adds is a typed list of tools, and that list sits in the model's context. So it has to be small. Here is what it costs (tokens, `o200k_base`):

```
What the agent reads to know the tools
  --tools scan,probe     █▊                          462 tokens
  13 tools, tools/list   ██████████▎               2,636 tokens
  -h of the 13 CLIs      ████████████████████      5,113 tokens
```

The bars are drawn to scale against the `-h` text.

- **About 200 tokens a tool.** Descriptions are one line. The shared output format is explained once, in the `initialize` instructions, not in every tool. `--tools` exposes only the tools a task needs.
- **The result is not touched.** The text the model reads is the CLI's stdout, byte for byte: `bench/run.sh` checked 10 tools on their fixtures and all 10 were identical. No pretty-printing, and no `structuredContent` copy that would send the same JSON twice.
- **Scope is enforced before anything runs.** Every tool that sends traffic requires `scope`; without it the call fails with a hint and the binary never starts.
- **Errors are readable.** Bad arguments, a missing scope, a missing engine or a timeout come back as `isError` results shaped like the Raijin Schema (`{"tool":...,"errors":[{"kind":...,"hint":...}]}`), so the model can fix the call and retry.

The list is not free: an agent that already knows one CLI pays nothing to call it through a shell. Full numbers are in [BENCHMARK.md](BENCHMARK.md), and `bench/run.sh` reproduces them.

## Install

```bash
go install github.com/protonnegativo/raijin-mcp/cmd/raijin-mcp@latest
```

`@latest` installs the latest release. Then install the Raijin tools you want on `PATH` (for example `go install github.com/protonnegativo/raijin-scan/cmd/raijin-scan@latest`) and their engines (nuclei, httpx, ...). raijin-mcp exposes only the tools it finds.

**Versions.** Every Raijin repo tags a release automatically on every change, and every engine update that passes the tool's tests is committed and released too. `raijin-<verb> --version` shows the release and the engine versions it was tested with; `raijin-mcp --version` shows its own. `raijin-mcp update` updates every Raijin tool at once (see [Updating](#updating)).

## Updating

`raijin-mcp update` is the `apt update` of the Raijin tools: it finds every installed `raijin-<verb>` the way the server does (`--bin-dir`, then `PATH`), and raijin-mcp itself when it was installed with `go install`.

```bash
raijin-mcp update --check              # what is out of date; installs nothing
raijin-mcp update                      # update every installed raijin-<verb> and its engines
raijin-mcp update --pinned             # engines at the versions each tool was tested with
raijin-mcp update --tools scan,probe   # only these
```

```
NAME         INSTALLED                           LATEST  ACTION
raijin-diff  v0.1.0                              v0.1.0  up to date
raijin-scan  v0.0.0-20261025153622-8f04ba98dd58  v0.1.0  update
nuclei       3.3.9                               3.11.1  update
2 of 3 out of date
```

- **Tools.** The installed version is read from the binary's build info; a local build or an untagged commit is older than any release. The latest comes from the module (the repos are private, so `GOPRIVATE=github.com/protonnegativo/*` is added and git fetches them). An update is `go install .../cmd/raijin-<verb>@latest` into the directory the binary is in.
- **Engines.** The tested versions come from each tool's `engines.json` at its latest release, and the installed one from the same version command the tool runs. Go engines are installed with `go install <module>@latest` (`--pinned`: `@v<tested>`) next to the existing binary when that directory is writable, else into `GOBIN`. trufflehog is installed by its official release script, only with `--allow-scripts`; otherwise the command is printed. arjun goes through `pipx` (`pipx upgrade arjun`, pinned `pipx install --force arjun==<v>`). nmap is a system package: the `apt`/`brew` command is printed, never run. Nothing runs with sudo.
- **Output.** A table by default, `--format json` for a Raijin Schema result (`tool: "raijin-update"`, findings for what is out of date, groups for what is up to date, errors with hints). Exit 0 when everything is up to date or was updated, 1 when a lookup or an install failed or something is left to run by hand.
- **MCP.** The `raijin_update` tool is always listed, even with no other tool installed: `{"apply": false, "pinned": false, "tools": ["scan"]}`. By default it only checks and returns the JSON; `apply: true` runs the update (never install scripts). Restart raijin-mcp afterwards to load the new binaries. Its `tools/list` entry costs about 80 tokens.
- **Startup notice.** At most once a day, the server runs the check in the background (10 seconds at most) and caches the result in the user cache directory (`raijin/update-check.json`). When something is out of date, `initialize` adds one sentence to its instructions: `Updates available for N Raijin tools/engines: call raijin_update.` initialize never waits for the network: until the check is done it uses the cached result. `--update-check=false` turns it off.

## Add it to a client

**Claude Code**

```bash
claude mcp add raijin -- raijin-mcp
claude mcp add raijin -- raijin-mcp --tools scan,probe,crawl   # only some tools
```

**Cursor**: `~/.cursor/mcp.json` (or `.cursor/mcp.json` in a project):

```json
{
  "mcpServers": {
    "raijin": {"command": "raijin-mcp", "args": []}
  }
}
```

**Any other MCP client**: a stdio server, command `raijin-mcp`, no arguments needed. Messages are newline-delimited JSON-RPC 2.0. If the client does not inherit your shell's `PATH`, use the full path of `raijin-mcp` and pass `--bin-dir` with the directory of the Raijin binaries.

To see what a client will get, without a client:

```bash
raijin-mcp --list            # the tools/list result, one JSON line
raijin-mcp --list --list-missing
```

## Usage

A call names the tool and its arguments. The scope is a list of rules, the same rules as a Raijin scope file:

```json
{"name": "raijin_scan", "arguments": {
  "scope": ["*.example.com", "!admin.example.com"],
  "targets": ["https://app.example.com"],
  "severity": "critical,high",
  "max_items": 10
}}
```

Arguments shared by the tools:

| Argument | Flag | |
|---|---|---|
| `scope` | `--scope` | authorized targets, one rule each (`example.com`, `*.example.com`, `10.0.0.0/24`, `!excluded`); written to a temp scope file for the call and removed after it |
| `targets` (or `target`) | `-u`, `-d`, `-host`, `-p` | the tool's target flag; `target` (one string) when the flag takes one value, like raijin-fuzz's URL. Optional: with only `scope`, the tool runs on every host the scope names (the description says so when the binary supports it) |
| `input` | `--input` | replay a saved engine output instead of running the engine |
| `max_items`, `max_bytes` | `--max-items`, `--max-bytes` | the output budget |
| `engine_args` | after `--` | extra engine arguments, filtered (see below) |

Each tool adds its own main flags: `templates`, `tags`, `severity`, `include_info` (scan), `follow` (probe), `no_resolve` (subs), `ports`, `top_ports`, `no_services` (ports), `depth`, `duration` (crawl), `method`, `wordlist` (params), `wordlist` (fuzz), `ports`, `no_enum` (tls), `repos`, `no_context` (secrets), `params`, `delay` (xss), `headers` (cors), `http` (takeover), `rate` and `timeout` where the tool has them, and `files` (diff: the old and new outputs). The full table is in [internal/tools/table.go](internal/tools/table.go).

## Output

The result of a call is the tool's JSON, unchanged. This is a real call of `raijin_scan` on the fixture of the raijin-scan repo (`input`, nothing sent), pretty-printed here; the result text is one line:

```json
{
  "tool": "raijin-scan",
  "version": "0.1.0",
  "target": "testdata/sample.jsonl",
  "summary": "2 findings (1 high, 1 medium), 1 info groups, 8 raw matches",
  "findings": [
    {"id": "exposed-env", "title": "Exposed .env", "severity": "high", "locations": ["https://b.example.com/.env [DB_PASSWORD=x, APP_KEY=y, AWS_KEY=z, EXTRA=w]"]},
    {"id": "git-config", "title": "Git Config - Detect", "severity": "medium", "locations": ["https://a.example.com/.git/config", "https://b.example.com/.git/config"]}
  ],
  "groups": [
    {"id": "tech-detect", "variants": ["nginx"], "locations": ["https://a.example.com", "https://b.example.com", "https://c.example.com"]}
  ],
  "omitted": {"duplicates": 1, "out_of_scope": 1}
}
```

The `target` path is shortened. A call without a scope:

```json
{"tool":"raijin-scan","errors":[{"kind":"missing_scope","hint":"scope is required: pass the authorized targets, e.g. [\"example.com\", \"*.example.com\", \"10.0.0.0/24\"]"}]}
```

## How it works

- **Discovery.** At start, raijin-mcp looks for `raijin-<verb>` in `--bin-dir`, then on `PATH`, for each tool in its static table. It runs each binary's `-h` and keeps only the arguments whose flag the binary really has, so an older or newer binary never gets a flag it does not know. It also learns there whether the target and input flags are repeatable.
- **Missing tools are not listed.** A tool that is not installed does not appear in `tools/list`, so it costs no tokens. With `--list-missing` it is listed as `Unavailable: <install hint>`, and calling it returns that hint as an error. The startup line on stderr names the tools found and the ones missing.
- **Scope.** Tools that send traffic (scan, probe, ports, crawl, js, params, fuzz, tls, xss, cors) always require `scope`, and so do subs, takeover and secrets, whose binaries require it. The check runs in raijin-mcp before the binary starts, whatever the client does with the schema. A tool that should take a scope but whose binary has no `--scope` flag is not exposed. raijin-diff takes none. The binary then drops targets and results outside the scope, as it does on the command line.
- **The call.** Flags are passed as `-flag=value`, so a value that starts with `-` is never read as a flag. raijin-mcp always adds `--format json` and never `--pretty` or `--banner`. Calls run in the background: `ping` and other calls are answered meanwhile, and `notifications/cancelled` kills the process. `--call-timeout` (30 minutes by default) bounds each call.
- **engine_args.** Anything a tool would take after `--`. Flags that would add targets behind the scope check (`-u`, `-l`, `-list`, `-target`, `-host`, `-d`, `-iL`, ...), write files (`-o`, `-output`, `-me`, `-se`, `-sr`, ...), load a config, update the engine or run code (`-code`) are refused. It is a deny list, not a sandbox. raijin-cors and raijin-diff have no engine, and raijin-secrets takes no `engine_args` and no `verify`: verifying sends each secret to its provider, and that is the operator's call.
- **Errors.** Exit 0 returns stdout. Exit 2 (engine missing) returns the tool's own JSON with `isError`, which carries the install hint. Exit 1 (usage) returns the first line of stderr as the hint. An unknown tool name is a JSON-RPC error (`-32602`), like `tools/call` without a `name`; argument problems are tool results with `isError`, so the model sees them.
- **Protocol.** `initialize` (versions `2025-11-25`, `2025-06-18`, `2025-03-26` and `2024-11-05`; a client asking for another gets `2025-11-25`), `notifications/initialized`, `ping`, `tools/list`, `tools/call` and `notifications/cancelled`. The server has no resources or prompts and its tool list does not change while it runs (`listChanged: false`). JSON-RPC batches are not supported.

## Flags

| Flag | Default | |
|---|---|---|
| `--tools` | all found | comma-separated verbs to expose, e.g. `scan,probe` |
| `--bin-dir` | | directory searched for `raijin-<verb>` before `PATH` |
| `--list-missing` | false | list tools that are not installed, with an install hint |
| `--call-timeout` | 30m | limit for one tool call (0 means none) |
| `--list` | false | print the `tools/list` result and exit |
| `--version` | false | print the version |
| `--update-check` | true | check for updates in the background, at most once a day |
| `--banner` | false | print the banner to stderr |

The banner is off by default. `--banner` prints it to **stderr** (stdout carries the protocol), with the version taken from the binary. Colors are disabled when `NO_COLOR` is set or stderr is not a terminal.

## Development

```bash
go test ./...
go vet ./...
PY=<python with tiktoken> bench/run.sh
```

Standard library only. The protocol tests start the server on pipes with fake Raijin binaries (shell scripts) in a temp `PATH`: initialize and version negotiation, `tools/list` with only installed tools and flags read from `-h`, `tools/call` arguments and result, unknown tool, invalid params, missing scope, engine missing, cancellation. The updater's tests replace the machine with a fake (no network, no install): version ordering (tags, pseudo-versions, `(devel)`), build info, each engine's version output, the plan for tools and engines, apply and its failures, the startup cache.

To expose a new Raijin tool, add its entry to `Table` in `internal/tools/table.go`: verb, one-line description, target flags, whether it is active, and its main flags.

## Responsible use

Raijin is for authorized testing only: your own assets, pentests with written scope, and bug bounty programs within their rules. Giving an agent these tools gives it the ability to scan. Pass only the scope you are authorized to test, and keep the human in the loop for approving calls (most MCP clients ask before each tool call by default).
