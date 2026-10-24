package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// help is what a Raijin binary prints for -h (Go flag format), trimmed to the flags tests use.
const help = `usage: raijin-x --scope scope.txt [flags]

  -format string
    	output format: json or table (default "json")
  -input string
    	read an existing engine JSONL file
  -max-bytes int
    	maximum size of the JSON output (default 16000)
  -max-items int
    	maximum findings in the output (0 keeps all)
  -rate int
    	requests per second
  -scope string
    	scope file (required)
  -severity string
    	severities to run
  -u value
    	target URL or host (repeatable)
`

// fakes are shell scripts named like Raijin binaries. raijin-scan echoes its arguments and the
// scope file; raijin-probe behaves like a tool whose engine is missing; raijin-crawl hangs;
// raijin-ports has no --scope flag, so it must not be exposed.
var fakes = map[string]string{
	"raijin-scan": `case "$1" in -h) echo "$HELP" >&2; exit 0;; esac
scope=""
for a in "$@"; do case "$a" in -scope=*) scope=$(tr '\n' ' ' < "${a#-scope=}");; esac; done
echo "$*" > "$ARGS_OUT"
printf '{"tool":"raijin-scan","summary":"fake","scope":"%s"}\n' "$scope"`,
	"raijin-probe": `case "$1" in -h) echo "$HELP" >&2; exit 0;; esac
echo '{"tool":"raijin-probe","summary":"httpx not found, nothing probed","errors":[{"kind":"missing_engine","hint":"install httpx"}]}'
exit 2`,
	"raijin-crawl": `case "$1" in -h) echo "$HELP" >&2; exit 0;; esac
exec sleep 30`,
	"raijin-ports": `case "$1" in -h) printf '  -host value\n    \thosts\n  -format string\n    \tformat\n' >&2; exit 0;; esac
echo '{}'`,
}

func fakePath(t *testing.T) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake binaries are shell scripts")
	}
	dir := t.TempDir()
	for name, body := range fakes {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("#!/bin/sh\n"+body+"\n"), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+"/usr/bin:/bin")
	t.Setenv("HELP", help)
	args := filepath.Join(dir, "args.txt")
	t.Setenv("ARGS_OUT", args)
	return args
}

type session struct {
	t    *testing.T
	in   *io.PipeWriter
	out  *bufio.Reader
	done chan int
}

func start(t *testing.T, flags ...string) *session {
	t.Helper()
	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	s := &session{t: t, in: inW, out: bufio.NewReader(outR), done: make(chan int, 1)}
	go func() {
		code := run(flags, inR, outW, io.Discard)
		outW.Close()
		s.done <- code
	}()
	t.Cleanup(func() { inW.Close() })
	return s
}

func (s *session) send(msg string) {
	s.t.Helper()
	if _, err := io.WriteString(s.in, msg+"\n"); err != nil {
		s.t.Fatal(err)
	}
}

type reply struct {
	ID     json.RawMessage `json:"id"`
	Result json.RawMessage `json:"result"`
	Error  *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (s *session) recv() reply {
	s.t.Helper()
	type line struct {
		b   []byte
		err error
	}
	ch := make(chan line, 1)
	go func() { b, err := s.out.ReadBytes('\n'); ch <- line{b, err} }()
	select {
	case l := <-ch:
		if l.err != nil {
			s.t.Fatalf("read: %v", l.err)
		}
		var r reply
		if err := json.Unmarshal(l.b, &r); err != nil {
			s.t.Fatalf("response is not JSON: %q", l.b)
		}
		return r
	case <-time.After(10 * time.Second):
		s.t.Fatal("no response")
	}
	return reply{}
}

func (s *session) call(id int, name, args string) (text string, isError bool) {
	s.t.Helper()
	s.send(`{"jsonrpc":"2.0","id":` + itoa(id) + `,"method":"tools/call","params":{"name":"` + name + `","arguments":` + args + `}}`)
	r := s.recv()
	if r.Error != nil {
		s.t.Fatalf("rpc error %d: %s", r.Error.Code, r.Error.Message)
	}
	var res struct {
		Content []struct{ Type, Text string }
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(r.Result, &res); err != nil || len(res.Content) != 1 || res.Content[0].Type != "text" {
		s.t.Fatalf("bad result: %s", r.Result)
	}
	return res.Content[0].Text, res.IsError
}

func itoa(i int) string { b, _ := json.Marshal(i); return string(b) }

func TestInitializeNegotiatesVersion(t *testing.T) {
	fakePath(t)
	s := start(t)
	for _, c := range []struct{ asked, want string }{
		{"2025-06-18", "2025-06-18"},
		{"2024-11-05", "2024-11-05"},
		{"1999-01-01", "2025-11-25"},
	} {
		s.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + c.asked + `","capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`)
		var res struct {
			ProtocolVersion string `json:"protocolVersion"`
			Capabilities    struct {
				Tools map[string]bool `json:"tools"`
			} `json:"capabilities"`
			ServerInfo struct{ Name, Version string } `json:"serverInfo"`
		}
		if err := json.Unmarshal(s.recv().Result, &res); err != nil {
			t.Fatal(err)
		}
		if res.ProtocolVersion != c.want {
			t.Errorf("asked %s, got %s, want %s", c.asked, res.ProtocolVersion, c.want)
		}
		if res.ServerInfo.Name != "raijin-mcp" || res.ServerInfo.Version != version || res.Capabilities.Tools == nil {
			t.Errorf("bad initialize result: %+v", res)
		}
	}
	// a notification gets no answer: the next response is the ping's
	s.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
	s.send(`{"jsonrpc":"2.0","id":"p","method":"ping"}`)
	if r := s.recv(); string(r.ID) != `"p"` || string(r.Result) != "{}" {
		t.Errorf("ping: id %s result %s", r.ID, r.Result)
	}
}

func listTools(t *testing.T, s *session) map[string]map[string]any {
	t.Helper()
	s.send(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`)
	var res struct {
		Tools []struct {
			Name        string         `json:"name"`
			Description string         `json:"description"`
			InputSchema map[string]any `json:"inputSchema"`
		} `json:"tools"`
	}
	if err := json.Unmarshal(s.recv().Result, &res); err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]any{}
	for _, tl := range res.Tools {
		if tl.Description == "" {
			t.Errorf("%s has no description", tl.Name)
		}
		out[tl.Name] = tl.InputSchema
	}
	return out
}

func TestToolsListOnlyInstalled(t *testing.T) {
	fakePath(t)
	got := listTools(t, start(t))
	for _, name := range []string{"raijin_scan", "raijin_probe", "raijin_crawl"} {
		if got[name] == nil {
			t.Errorf("%s not listed", name)
		}
	}
	if got["raijin_ports"] != nil {
		t.Error("raijin_ports has no --scope flag and must not be listed")
	}
	if got["raijin_subs"] != nil || got["raijin_fuzz"] != nil {
		t.Error("tools that are not installed must not be listed")
	}

	scan := got["raijin_scan"]
	props := scan["properties"].(map[string]any)
	for _, p := range []string{"targets", "scope", "input", "severity", "rate", "max_items", "max_bytes", "engine_args"} {
		if props[p] == nil {
			t.Errorf("raijin_scan schema misses %s", p)
		}
	}
	// the fake's -h has no -tags or -t: params for flags the binary lacks are dropped
	if props["tags"] != nil || props["templates"] != nil {
		t.Error("params whose flag is missing from -h must be dropped")
	}
	if req, _ := scan["required"].([]any); len(req) != 1 || req[0] != "scope" {
		t.Errorf("scope must be required, got %v", scan["required"])
	}
}

func TestToolsListMissingWithHint(t *testing.T) {
	fakePath(t)
	got := listTools(t, start(t, "--list-missing"))
	if got["raijin_subs"] == nil || got["raijin_ports"] == nil {
		t.Fatal("--list-missing should list unavailable tools")
	}
	s := start(t, "--list-missing")
	text, isErr := s.call(2, "raijin_subs", `{"scope":["example.com"]}`)
	if !isErr || !strings.Contains(text, `"missing_tool"`) || !strings.Contains(text, "go install") {
		t.Errorf("missing tool call: %v %s", isErr, text)
	}
}

func TestToolsFilter(t *testing.T) {
	fakePath(t)
	got := listTools(t, start(t, "--tools", "scan"))
	if len(got) != 1 || got["raijin_scan"] == nil {
		t.Errorf("--tools scan should expose only raijin_scan, got %d tools", len(got))
	}
}

func TestCallRunsBinaryWithJSONFormat(t *testing.T) {
	argsOut := fakePath(t)
	s := start(t)
	text, isErr := s.call(2, "raijin_scan", `{"scope":["*.example.com","!admin.example.com"],"targets":["a.example.com","-b.example.com"],"severity":"high","rate":10,"max_items":5}`)
	if isErr {
		t.Fatalf("unexpected error: %s", text)
	}
	if text != `{"tool":"raijin-scan","summary":"fake","scope":"*.example.com !admin.example.com "}` {
		t.Errorf("result text should be the tool's stdout, got %s", text)
	}
	b, err := os.ReadFile(argsOut)
	if err != nil {
		t.Fatal(err)
	}
	args := string(b)
	for _, want := range []string{"-format=json", "-u=a.example.com", "-u=-b.example.com", "-severity=high", "-rate=10", "-max-items=5"} {
		if !strings.Contains(args, want) {
			t.Errorf("argv %q misses %s", args, want)
		}
	}
	if strings.Contains(args, "-pretty") || strings.Contains(args, "-banner") {
		t.Errorf("argv must not ask for pretty output or the banner: %q", args)
	}
	// the scope file is removed after the call
	for _, f := range strings.Fields(args) {
		if p, ok := strings.CutPrefix(f, "-scope="); ok {
			if _, err := os.Stat(p); !os.IsNotExist(err) {
				t.Errorf("scope file %s not removed", p)
			}
		}
	}
}

func TestCallMissingScope(t *testing.T) {
	argsOut := fakePath(t)
	s := start(t)
	for _, args := range []string{`{"targets":["a.example.com"]}`, `{"scope":[],"targets":["a.example.com"]}`, `{"scope":"  "}`} {
		text, isErr := s.call(2, "raijin_scan", args)
		if !isErr || !strings.Contains(text, `"kind":"missing_scope"`) {
			t.Errorf("%s: want missing_scope error, got %v %s", args, isErr, text)
		}
	}
	if _, err := os.Stat(argsOut); !os.IsNotExist(err) {
		t.Error("the binary must not run without a scope")
	}
}

func TestCallInvalidArguments(t *testing.T) {
	argsOut := fakePath(t)
	s := start(t)
	for args, want := range map[string]string{
		`{"scope":["a.com"],"bogus":1}`:                           "unknown argument",
		`{"scope":["a.com"],"rate":-1}`:                           "non-negative integer",
		`{"scope":["a.com"],"rate":"fast"}`:                       "non-negative integer",
		`{"scope":["a.com"],"targets":{"x":1}}`:                   "array of strings",
		`{"scope":["a.com"],"engine_args":["-u","evil.com"]}`:     "adds targets",
		`{"scope":["a.com"],"engine_args":["-o=/etc/passwd"]}`:    "writes files",
		`{"scope":["a.com"],"engine_args":["--update"]}`:          "updates the engine",
		`{"scope":["a.com"],"input":"a.jsonl","targets":"a.com"}`: "",
	} {
		text, isErr := s.call(2, "raijin_scan", args)
		if want == "" {
			if isErr {
				t.Errorf("%s: unexpected error %s", args, text)
			}
			continue
		}
		if !isErr || !strings.Contains(text, want) || !strings.Contains(text, `"kind":"invalid_arguments"`) {
			t.Errorf("%s: want %q, got %v %s", args, want, isErr, text)
		}
	}
	b, _ := os.ReadFile(argsOut)
	if !strings.Contains(string(b), "-input=a.jsonl") {
		t.Errorf("valid call did not reach the binary: %q", b)
	}
}

func TestCallEngineMissingIsError(t *testing.T) {
	fakePath(t)
	s := start(t)
	text, isErr := s.call(2, "raijin_probe", `{"scope":["a.com"],"targets":["a.com"]}`)
	if !isErr || !strings.Contains(text, `"hint":"install httpx"`) {
		t.Errorf("exit 2 should be isError with the tool's JSON, got %v %s", isErr, text)
	}
}

func TestProtocolErrors(t *testing.T) {
	fakePath(t)
	s := start(t)
	cases := []struct {
		msg  string
		code int
	}{
		{`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"raijin_nope","arguments":{}}}`, -32602},
		{`{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"arguments":{}}}`, -32602},
		{`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"raijin_scan","arguments":[1]}}`, -32602},
		{`{"jsonrpc":"2.0","id":4,"method":"tools/call","params":"x"}`, -32602},
		{`{"jsonrpc":"2.0","id":5,"method":"resources/list"}`, -32601},
		{`{not json`, -32700},
		{`[1,2]`, -32600},
	}
	for _, c := range cases {
		s.send(c.msg)
		r := s.recv()
		if r.Error == nil || r.Error.Code != c.code {
			t.Errorf("%s: want error %d, got %+v %s", c.msg, c.code, r.Error, r.Result)
		}
	}
}

func TestCancelledCallGetsNoAnswer(t *testing.T) {
	fakePath(t)
	s := start(t)
	s.send(`{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"raijin_crawl","arguments":{"scope":["a.com"],"targets":["a.com"]}}}`)
	time.Sleep(200 * time.Millisecond)
	s.send(`{"jsonrpc":"2.0","method":"notifications/cancelled","params":{"requestId":7}}`)
	s.send(`{"jsonrpc":"2.0","id":8,"method":"ping"}`)
	if r := s.recv(); string(r.ID) != "8" {
		t.Errorf("the cancelled call must not be answered, got id %s", r.ID)
	}
	s.in.Close()
	select {
	case code := <-s.done:
		if code != 0 {
			t.Errorf("exit %d", code)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("server did not exit: the cancelled process is still running")
	}
}

func TestEOFWaitsForRunningCall(t *testing.T) {
	fakePath(t)
	var out bytes.Buffer
	in := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"raijin_scan","arguments":{"scope":["a.com"]}}}` + "\n")
	if code := run(nil, in, &out, io.Discard); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(out.String(), `raijin-scan`) {
		t.Errorf("the call must be answered before exit, got %q", out.String())
	}
}

func TestListFlagAndVersion(t *testing.T) {
	fakePath(t)
	var out, errb bytes.Buffer
	if code := run([]string{"--list"}, strings.NewReader(""), &out, &errb); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if n := strings.Count(out.String(), "\n"); n != 1 {
		t.Errorf("--list should print one compact JSON line, got %d", n)
	}
	if errb.Len() != 0 {
		t.Errorf("no banner by default, stderr: %q", errb.String())
	}
	out.Reset()
	run([]string{"--version"}, strings.NewReader(""), &out, &errb)
	if out.String() != "raijin-mcp "+version+"\n" {
		t.Errorf("version: %q", out.String())
	}
	if code := run([]string{"--tools", "nope"}, strings.NewReader(""), &out, &errb); code != 1 {
		t.Errorf("unknown --tools verb should exit 1, got %d", code)
	}
}

func TestBannerGoesToStderrOnly(t *testing.T) {
	fakePath(t)
	var out, errb bytes.Buffer
	run([]string{"--banner", "--list"}, strings.NewReader(""), &out, &errb)
	if !strings.Contains(errb.String(), "TGT-LOCK") || strings.Contains(out.String(), "TGT-LOCK") {
		t.Error("banner must go to stderr only")
	}
	var v map[string]any
	if err := json.Unmarshal(out.Bytes(), &v); err != nil {
		t.Fatalf("stdout is not JSON with --banner: %v", err)
	}
}
