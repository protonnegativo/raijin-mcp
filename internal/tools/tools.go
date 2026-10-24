// Package tools finds the Raijin binaries on PATH, describes each one as an MCP tool and runs it.
package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/protonnegativo/raijin-mcp/internal/mcp"
)

// Options configures discovery and runs.
type Options struct {
	BinDir      string        // looked up before PATH
	Only        []string      // verbs to expose; empty exposes every tool found
	ListMissing bool          // list tools that are not installed, with a hint, instead of hiding them
	CallTimeout time.Duration // limit for one tools/call; 0 means none
}

// Tool is a Spec resolved against the installed binary.
type Tool struct {
	Spec
	Path    string // binary path; empty when it is not installed
	Missing string // why the tool cannot run; empty when it can

	flags       map[string]string // flag -> type from -h ("" for bools); nil when -h could not be read
	targetFlag  string
	targetMulti bool
	inputMulti  bool
	params      []Param
}

// Name is the MCP tool name: raijin_<verb>.
func (t *Tool) Name() string { return "raijin_" + t.Verb }

// Binary is the executable name: raijin-<verb>.
func (t *Tool) Binary() string { return "raijin-" + t.Verb }

// Provider exposes the discovered tools over MCP.
type Provider struct {
	opt   Options
	tools []*Tool
}

// Discover resolves every tool in Table.
func Discover(opt Options) *Provider {
	p := &Provider{opt: opt}
	for _, s := range Table {
		if len(opt.Only) > 0 && !contains(opt.Only, s.Verb) {
			continue
		}
		p.tools = append(p.tools, resolve(s, opt.BinDir))
	}
	return p
}

// Resolved returns every tool considered, installed or not.
func (p *Provider) Resolved() []*Tool { return p.tools }

func resolve(s Spec, binDir string) *Tool {
	t := &Tool{Spec: s, targetMulti: true}
	if binDir != "" {
		if c := filepath.Join(binDir, t.Binary()); isExec(c) {
			t.Path = c
		}
	}
	if t.Path == "" {
		if c, err := exec.LookPath(t.Binary()); err == nil {
			t.Path = c
		}
	}
	if t.Path == "" {
		t.Missing = "not installed: put " + t.Binary() + " on PATH (go install github.com/protonnegativo/" + t.Binary() + "/cmd/" + t.Binary() + "@latest) and restart raijin-mcp"
	} else {
		t.flags = helpFlags(t.Path)
	}

	has := func(flag string) bool {
		if t.flags == nil {
			return true // -h unreadable: trust the table
		}
		_, ok := t.flags[flag]
		return ok
	}
	for _, f := range s.Targets {
		if has(f) {
			t.targetFlag = f
			if t.flags != nil {
				t.targetMulti = t.flags[f] == "value"
			}
			break
		}
	}
	t.Input = s.Input && has("input")
	t.inputMulti = t.flags != nil && t.flags["input"] == "value"
	for _, prm := range s.Params {
		if has(prm.Flag) {
			t.params = append(t.params, prm)
		}
	}
	for _, f := range []string{"max-items", "max-bytes"} {
		if has(f) {
			t.params = append(t.params, budgetParams[f])
		}
	}
	if t.Missing == "" && t.flags != nil && t.Scope == ScopeRequired && !has("scope") {
		t.Missing = t.Binary() + " has no --scope flag; refusing to expose it"
	}
	return t
}

var budgetParams = map[string]Param{
	"max-items": {"max_items", "max-items", "integer", "max findings, 0=all"},
	"max-bytes": {"max_bytes", "max-bytes", "integer", "max output bytes"},
}

var helpLine = regexp.MustCompile(`^  -([A-Za-z0-9][A-Za-z0-9._-]*)(?: (\S+))?`)

// helpFlags reads the flags a Go binary prints for -h: "  -name type" lines.
func helpFlags(path string) map[string]string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, path, "-h")
	cmd.Stdout, cmd.Stderr = &out, &out
	_ = cmd.Run() // flag.ContinueOnError makes -h exit non-zero
	flags := map[string]string{}
	sc := bufio.NewScanner(&out)
	for sc.Scan() {
		if m := helpLine.FindStringSubmatch(sc.Text()); m != nil {
			flags[m[1]] = m[2]
		}
	}
	if len(flags) == 0 {
		return nil
	}
	return flags
}

// Tools lists the installed tools (and, with ListMissing, the others with their install hint).
func (p *Provider) Tools() []mcp.Tool {
	out := []mcp.Tool{}
	for _, t := range p.tools {
		switch {
		case t.Missing == "":
			out = append(out, mcp.Tool{Name: t.Name(), Description: t.Desc, InputSchema: t.schema()})
		case p.opt.ListMissing:
			out = append(out, mcp.Tool{Name: t.Name(), Description: "Unavailable: " + t.Missing, InputSchema: map[string]string{"type": "object"}})
		}
	}
	return out
}

func (t *Tool) schema() map[string]any {
	props := map[string]any{}
	var required []string
	if t.targetFlag != "" {
		props["targets"] = prop("array", t.TargetDesc)
	}
	if t.Scope != ScopeNone {
		desc := "authorized targets: host, *.domain, IP, CIDR, !excluded"
		if t.ScopeDesc != "" {
			desc = t.ScopeDesc
		}
		props["scope"] = prop("array", desc)
		if t.Scope == ScopeRequired {
			required = append(required, "scope")
		}
	}
	if t.Input {
		typ := "string"
		if t.inputMulti {
			typ = "array"
		}
		props["input"] = prop(typ, "replay saved engine output")
	}
	for _, prm := range t.params {
		props[prm.Name] = prop(prm.Type, prm.Desc)
	}
	if t.Engine != "" {
		props["engine_args"] = prop("array", "extra "+t.Engine+" args")
	}
	if t.Positional != nil {
		props[t.Positional.Name] = prop(t.Positional.Type, t.Positional.Desc)
		required = append(required, t.Positional.Name)
	}
	s := map[string]any{"type": "object", "properties": props}
	if len(required) > 0 {
		s["required"] = required
	}
	return s
}

func prop(typ, desc string) map[string]any {
	p := map[string]any{"type": typ}
	if typ == "array" {
		p["items"] = map[string]string{"type": "string"}
	}
	if desc != "" {
		p["description"] = desc
	}
	return p
}

// Call runs one tool. Every problem a model can fix (bad arguments, no scope, a failed run) comes
// back as an isError result carrying a Raijin-style errors entry with a hint.
func (p *Provider) Call(ctx context.Context, name string, raw json.RawMessage) (mcp.Result, error) {
	var t *Tool
	for _, c := range p.tools {
		if c.Name() == name {
			t = c
		}
	}
	if t == nil || (t.Missing != "" && !p.opt.ListMissing) {
		return mcp.Result{}, mcp.ErrUnknownTool
	}
	if t.Missing != "" {
		return fail(t, "missing_tool", t.Missing), nil
	}

	argv, cleanup, err := t.argv(raw)
	defer cleanup()
	if err != nil {
		var ae *argError
		if errors.As(err, &ae) {
			return fail(t, ae.kind, ae.msg), nil
		}
		return fail(t, "server_error", err.Error()), nil
	}

	if p.opt.CallTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, p.opt.CallTimeout)
		defer cancel()
	}
	var stdout, stderr capped
	stdout.max, stderr.max = 8<<20, 64<<10
	cmd := exec.CommandContext(ctx, t.Path, argv...)
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	cmd.WaitDelay = 5 * time.Second
	runErr := cmd.Run()
	out := strings.TrimSpace(stdout.String())

	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		hint := "the call was cancelled"
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			hint = fmt.Sprintf("no result after %s; narrow the targets or raise raijin-mcp --call-timeout", p.opt.CallTimeout)
		}
		return fail(t, "timeout", hint), nil
	case runErr == nil && out != "":
		return mcp.TextResult(out, false), nil
	case runErr == nil:
		return fail(t, "empty_output", firstLine(stderr.String(), t.Binary()+" printed nothing")), nil
	case errors.As(runErr, &exit) && exit.ExitCode() == 2 && json.Valid([]byte(out)):
		return mcp.TextResult(out, true), nil // engine missing: the tool's own JSON has the hint
	case errors.As(runErr, &exit) && exit.ExitCode() == 1:
		return fail(t, "usage", firstLine(stderr.String(), "invalid arguments")), nil
	default:
		return fail(t, "run_error", firstLine(stderr.String(), runErr.Error())), nil
	}
}

type argError struct{ kind, msg string }

func (e *argError) Error() string { return e.msg }

func badArg(format string, a ...any) error {
	return &argError{"invalid_arguments", fmt.Sprintf(format, a...)}
}

// argv turns MCP arguments into the binary's command line. cleanup removes the scope file.
func (t *Tool) argv(raw json.RawMessage) ([]string, func(), error) {
	cleanup := func() {}
	args := map[string]json.RawMessage{}
	if b := bytes.TrimSpace(raw); len(b) > 0 && string(b) != "null" {
		if err := json.Unmarshal(b, &args); err != nil {
			return nil, cleanup, badArg("arguments must be an object")
		}
	}
	known := t.known()
	for k := range args {
		if _, ok := known[k]; !ok {
			return nil, cleanup, badArg("unknown argument %q; accepted: %s", k, strings.Join(sortedKeys(known), ", "))
		}
	}

	var argv []string
	if t.Scope != ScopeNone {
		rules, err := stringList(args["scope"], "scope")
		if err != nil {
			return nil, cleanup, err
		}
		if len(rules) == 0 && (t.Scope == ScopeRequired || t.Active) {
			return nil, cleanup, &argError{"missing_scope", "scope is required: pass the authorized targets, e.g. [\"example.com\", \"*.example.com\", \"10.0.0.0/24\"]"}
		}
		if len(rules) > 0 {
			dir, err := os.MkdirTemp("", "raijin-mcp-*")
			if err != nil {
				return nil, cleanup, err
			}
			cleanup = func() { os.RemoveAll(dir) }
			path := filepath.Join(dir, "scope.txt")
			if err := os.WriteFile(path, []byte(strings.Join(rules, "\n")+"\n"), 0o600); err != nil {
				return nil, cleanup, err
			}
			argv = append(argv, "-scope="+path)
		}
	}
	if t.flags == nil || t.has("format") {
		argv = append(argv, "-format=json")
	}

	if t.targetFlag != "" {
		targets, err := stringList(args["targets"], "targets")
		if err != nil {
			return nil, cleanup, err
		}
		argv = appendList(argv, t.targetFlag, targets, t.targetMulti)
	}
	if t.Input {
		inputs, err := stringList(args["input"], "input")
		if err != nil {
			return nil, cleanup, err
		}
		if len(inputs) > 1 && !t.inputMulti {
			return nil, cleanup, badArg("input takes one file")
		}
		argv = appendList(argv, "input", inputs, true)
	}
	for _, prm := range t.params {
		v, ok := args[prm.Name]
		if !ok {
			continue
		}
		vals, err := scalar(v, prm)
		if err != nil {
			return nil, cleanup, err
		}
		for _, s := range vals {
			argv = append(argv, "-"+prm.Flag+"="+s)
		}
	}
	if t.Positional != nil {
		files, err := stringList(args[t.Positional.Name], t.Positional.Name)
		if err != nil {
			return nil, cleanup, err
		}
		if len(files) == 0 {
			return nil, cleanup, badArg("%s is required", t.Positional.Name)
		}
		for _, f := range files {
			if strings.HasPrefix(f, "-") {
				return nil, cleanup, badArg("%s: %q looks like a flag", t.Positional.Name, f)
			}
		}
		argv = append(argv, files...)
	}
	if t.Engine != "" {
		extra, err := stringList(args["engine_args"], "engine_args")
		if err != nil {
			return nil, cleanup, err
		}
		for _, a := range extra {
			if f := denied(a); f != "" {
				return nil, cleanup, badArg("engine_args: %s is not allowed (%s); use the tool's own arguments", a, f)
			}
		}
		if len(extra) > 0 {
			argv = append(argv, "--")
			argv = append(argv, extra...)
		}
	}
	return argv, cleanup, nil
}

func (t *Tool) has(flag string) bool {
	_, ok := t.flags[flag]
	return ok
}

func (t *Tool) known() map[string]bool {
	k := map[string]bool{}
	if t.targetFlag != "" {
		k["targets"] = true
	}
	if t.Scope != ScopeNone {
		k["scope"] = true
	}
	if t.Input {
		k["input"] = true
	}
	for _, prm := range t.params {
		k[prm.Name] = true
	}
	if t.Engine != "" {
		k["engine_args"] = true
	}
	if t.Positional != nil {
		k[t.Positional.Name] = true
	}
	return k
}

// appendList writes a list as a repeated flag, or as one comma-separated value when the flag is
// not repeatable. The -flag=value form keeps a value that starts with "-" from being read as a flag.
func appendList(argv []string, flag string, vals []string, multi bool) []string {
	if len(vals) == 0 {
		return argv
	}
	if !multi {
		return append(argv, "-"+flag+"="+strings.Join(vals, ","))
	}
	for _, v := range vals {
		argv = append(argv, "-"+flag+"="+v)
	}
	return argv
}

// stringList accepts a JSON array of strings or a single string (split on newlines and commas,
// since models often send "a.com, b.com").
func stringList(raw json.RawMessage, name string) ([]string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var list []string
	if err := json.Unmarshal(raw, &list); err != nil {
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return nil, badArg("%s must be an array of strings", name)
		}
		list = strings.FieldsFunc(s, func(r rune) bool { return r == '\n' || r == ',' })
	}
	var out []string
	for _, v := range list {
		if v = strings.TrimSpace(v); v != "" {
			out = append(out, v)
		}
	}
	return out, nil
}

func scalar(raw json.RawMessage, prm Param) ([]string, error) {
	switch prm.Type {
	case "integer":
		var f float64
		if json.Unmarshal(raw, &f) != nil || f < 0 || f != float64(int64(f)) {
			return nil, badArg("%s must be a non-negative integer", prm.Name)
		}
		return []string{strconv.FormatInt(int64(f), 10)}, nil
	case "boolean":
		var b bool
		if json.Unmarshal(raw, &b) != nil {
			return nil, badArg("%s must be true or false", prm.Name)
		}
		return []string{strconv.FormatBool(b)}, nil
	case "array":
		return stringList(raw, prm.Name)
	default:
		var s string
		if json.Unmarshal(raw, &s) != nil {
			return nil, badArg("%s must be a string", prm.Name)
		}
		return []string{s}, nil
	}
}

// deniedFlags are engine flags engine_args may not carry: they add targets behind the scope check,
// write files, load configs, update the engine or run code.
var deniedFlags = map[string]string{
	"u": "adds targets", "target": "adds targets", "l": "adds targets", "list": "adds targets",
	"host": "adds targets", "d": "adds targets", "domain": "adds targets", "dl": "adds targets",
	"il": "adds targets", "input": "adds targets", "uri": "adds targets", "url": "adds targets",
	"o": "writes files", "output": "writes files", "oa": "writes files", "on": "writes files",
	"ox": "writes files", "og": "writes files", "od": "writes files", "output-dir": "writes files",
	"me": "writes files", "markdown-export": "writes files", "se": "writes files", "sarif-export": "writes files",
	"je": "writes files", "json-export": "writes files", "jle": "writes files", "jsonl-export": "writes files",
	"sr": "writes files", "store-response": "writes files", "srd": "writes files", "store-response-dir": "writes files",
	"config": "loads a config", "provider-config": "loads a config", "pc": "loads a config",
	"up": "updates the engine", "update": "updates the engine", "ut": "updates the engine", "update-templates": "updates the engine",
	"code": "runs code", "script": "runs code",
}

func denied(arg string) string {
	if !strings.HasPrefix(arg, "-") {
		return ""
	}
	name := strings.ToLower(strings.TrimLeft(arg, "-"))
	if i := strings.IndexByte(name, '='); i >= 0 {
		name = name[:i]
	}
	return deniedFlags[name]
}

type errorEntry struct {
	Kind string `json:"kind"`
	Hint string `json:"hint"`
}

// fail is an isError result shaped like a Raijin Schema result with one error.
func fail(t *Tool, kind, hint string) mcp.Result {
	b, _ := json.Marshal(struct {
		Tool   string       `json:"tool"`
		Errors []errorEntry `json:"errors"`
	}{t.Binary(), []errorEntry{{kind, hint}}})
	return mcp.TextResult(string(b), true)
}

// firstLine is the first meaningful stderr line, or def.
func firstLine(s, def string) string {
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if l == "" || strings.HasPrefix(l, "usage:") {
			continue
		}
		if len(l) > 300 {
			l = l[:300]
		}
		return l
	}
	return def
}

// capped is a buffer that stops growing at max bytes.
type capped struct {
	bytes.Buffer
	max int
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.max - c.Len(); room > 0 {
		if len(p) > room {
			c.Buffer.Write(p[:room])
		} else {
			c.Buffer.Write(p)
		}
	}
	return len(p), nil
}

func isExec(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && !fi.IsDir() && fi.Mode()&0o111 != 0
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func sortedKeys(m map[string]bool) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
