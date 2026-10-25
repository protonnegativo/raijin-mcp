#!/usr/bin/env bash
# Reproducible benchmark for raijin-mcp: the size of what an MCP client puts in the model's context
# (tools/list), and end-to-end calls on the sibling repos' fixtures, checked byte for byte against
# the CLI. Nothing is sent to the network: every call replays a saved engine output with --input.
#
# usage: bench/run.sh [workdir]
# needs: go, python3; the sibling repos next to this one (../raijin-<verb>)
# env: PY=<python with tiktoken> for the token counts (pip install tiktoken)
set -euo pipefail

W=${1:-$(mktemp -d)}
HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(cd "$HERE/.." && pwd)
SIBLINGS=$(cd "$ROOT/.." && pwd)
PY=${PY:-python3}
VERBS="scan probe subs ports crawl js params fuzz tls secrets xss cors takeover diff"
mkdir -p "$W/bin" "$W/all"
echo "workdir: $W"

(cd "$ROOT" && go build -o "$W/bin/raijin-mcp" ./cmd/raijin-mcp)
installed=()
for v in $VERBS; do
  src="$SIBLINGS/raijin-$v"
  if [ -f "$src/cmd/raijin-$v/main.go" ] && (cd "$src" && go build -o "$W/bin/raijin-$v" "./cmd/raijin-$v" 2> /dev/null); then
    cp "$W/bin/raijin-$v" "$W/all/"
    installed+=("$v")
  else
    # Not built (yet): a stand-in with an unreadable -h, so raijin-mcp lists it straight from its table.
    printf '#!/bin/sh\necho "{}"\n' > "$W/all/raijin-$v"
    chmod +x "$W/all/raijin-$v"
  fi
done
echo "real binaries: ${installed[*]}"

# Calls on the fixtures each sibling repo ships in testdata/ (raijin-diff takes no --input).
SCOPE='["example.com","*.example.com","10.0.0.0/8","192.0.2.0/24","127.0.0.1","localhost"]'
calls() {
  for v in "${installed[@]}"; do
    [ "$v" = diff ] && continue
    f=$(ls "$SIBLINGS/raijin-$v"/testdata/sample* 2>/dev/null | head -1) || true
    [ -n "$f" ] || continue
    printf '{"name":"raijin_%s","arguments":{"scope":%s,"input":"%s"}}\n' "$v" "$SCOPE" "$f"
  done
}
calls > "$W/calls.jsonl"
PATH="$W/bin:/usr/bin:/bin" python3 "$HERE/mcp_session.py" "$W/installed" "$W/bin/raijin-mcp" < "$W/calls.jsonl" 2> "$W/installed.log"
PATH="$W/all:/usr/bin:/bin" python3 "$HERE/mcp_session.py" "$W/every" "$W/bin/raijin-mcp" < /dev/null 2> /dev/null
PATH="$W/bin:/usr/bin:/bin" python3 "$HERE/mcp_session.py" "$W/two" "$W/bin/raijin-mcp" --tools scan,probe < /dev/null 2> /dev/null

echo; echo "## tools/list"; echo
"$PY" "$HERE/count_tokens.py" \
  "tools/list, ${#installed[@]} installed tools (whole JSON-RPC line)=$W/installed/tools_list.json" \
  "tools array only, ${#installed[@]} installed tools=$W/installed/tools.json" \
  "tools array only, all 14 tools=$W/every/tools.json" \
  "tools array only, --tools scan,probe=$W/two/tools.json" \
  "initialize result=$W/installed/initialize.json"
if [ ${#installed[@]} -gt 0 ]; then
  for v in "${installed[@]}"; do "$W/bin/raijin-$v" -h > "$W/help-$v.txt" 2>&1 || true; done
  "$PY" "$HERE/count_tokens.py" "-h of the ${#installed[@]} installed binaries (for comparison)=$(printf "$W/help-%s.txt+" "${installed[@]}" | sed 's/+$//')"
fi

echo; echo "## end-to-end calls"; echo
i=0
while read -r call; do
  v=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["name"][7:])' "$call")
  input=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["arguments"]["input"])' "$call")
  python3 -c 'import json,sys; print("\n".join(json.loads(sys.argv[1])))' "$SCOPE" > "$W/scope.txt"
  "$W/bin/raijin-$v" --scope "$W/scope.txt" --input "$input" > "$W/cli-$v.json"
  # raw paths are per run when the tool saves one; compare everything else byte for byte
  if python3 - "$W/cli-$v.json" "$W/installed/call-$i.txt" <<'PY'
import json, sys
a, b = (json.load(open(p)) for p in sys.argv[1:])
a.pop("raw", None); b.pop("raw", None)
sys.exit(0 if a == b else 1)
PY
  then same="identical"; else same="DIFFERENT"; fi
  if cmp -s "$W/cli-$v.json" "$W/installed/call-$i.txt"; then same="$same, byte for byte"; fi
  echo "raijin_$v: MCP result vs CLI stdout: $same"
  "$PY" "$HERE/count_tokens.py" \
    "raijin-$v CLI stdout=$W/cli-$v.json" \
    "raijin_$v MCP result text=$W/installed/call-$i.txt" \
    "raijin_$v whole JSON-RPC response=$W/installed/call-$i.rpc.json"
  echo
  i=$((i+1))
done < "$W/calls.jsonl"
