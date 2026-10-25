package update

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/protonnegativo/raijin-mcp/internal/mcp"
)

// ToolName is the MCP tool that checks and applies updates.
const ToolName = "raijin_update"

// Provider adds raijin_update to the tools of another provider. It is listed even when no other
// tool is installed.
type Provider struct {
	mcp.Provider
	Sys     Sys
	Opt     Options // Verbs: every tool the server knows
	Version string  // of raijin-mcp, for the JSON
}

var updateTool = mcp.Tool{
	Name:        ToolName,
	Description: "Check (default) or apply updates for Raijin tools and their engines.",
	InputSchema: map[string]any{"type": "object", "properties": map[string]any{
		"apply":  map[string]string{"type": "boolean"},
		"pinned": map[string]any{"type": "boolean", "description": "engines at tested versions"},
		"tools":  map[string]any{"type": "array", "items": map[string]string{"type": "string"}, "description": "verbs, e.g. scan"},
	}},
}

// Tools implements mcp.Provider.
func (p *Provider) Tools() []mcp.Tool {
	inner := p.Provider.Tools()
	return append(inner[:len(inner):len(inner)], updateTool)
}

// Call implements mcp.Provider.
func (p *Provider) Call(ctx context.Context, name string, raw json.RawMessage) (mcp.Result, error) {
	if name != ToolName {
		return p.Provider.Call(ctx, name, raw)
	}
	var args struct {
		Apply  bool     `json:"apply"`
		Pinned bool     `json:"pinned"`
		Tools  []string `json:"tools"`
	}
	if b := bytes.TrimSpace(raw); len(b) > 0 && string(b) != "null" {
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if err := dec.Decode(&args); err != nil {
			return failResult("invalid_arguments", "arguments are {apply: bool, pinned: bool, tools: [verbs]}"), nil
		}
	}
	opt := p.Opt
	opt.Pinned, opt.AllowScripts = args.Pinned, false // never run install scripts for a model
	if len(args.Tools) > 0 {
		opt.Verbs, opt.Self = nil, ""
		for _, v := range ParseVerbs(strings.Join(args.Tools, ",")) {
			switch {
			case v == "mcp":
				opt.Self = p.Opt.Self
			case contains(p.Opt.Verbs, v):
				opt.Verbs = append(opt.Verbs, v)
			default:
				return failResult("invalid_arguments", "unknown tool: "+v), nil
			}
		}
	}
	r := Check(ctx, p.Sys, opt)
	if args.Apply {
		Apply(ctx, p.Sys, r)
	}
	return mcp.TextResult(string(r.JSON(p.Version, "call raijin_update with apply=true")), r.Failed()), nil
}

func failResult(kind, hint string) mcp.Result {
	b, _ := json.Marshal(struct {
		Tool   string  `json:"tool"`
		Errors []Error `json:"errors"`
	}{"raijin-update", []Error{{Kind: kind, Hint: hint}}})
	return mcp.TextResult(string(b), true)
}

func contains(l []string, s string) bool {
	for _, v := range l {
		if v == s {
			return true
		}
	}
	return false
}

// Notice is the startup check: at most once a day, in the background, so initialize never waits on
// the network.
type Notice struct {
	mu       sync.Mutex
	outdated int
}

type cached struct {
	Checked  time.Time `json:"checked"`
	Outdated int       `json:"outdated"`
}

// CachePath is where the last startup check is kept.
func CachePath() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		return ""
	}
	return filepath.Join(dir, "raijin", "update-check.json")
}

// StartNotice reads the cached result and, when it is older than a day (or missing), checks again in
// the background with a 10 second limit, then caches the new result. A check that does not finish
// in time, or whose lookups failed, is not cached, so the next start tries again.
func StartNotice(sys Sys, opt Options, cache string, now time.Time) *Notice {
	n := &Notice{}
	var c cached
	if b, err := os.ReadFile(cache); err == nil && json.Unmarshal(b, &c) == nil {
		n.outdated = c.Outdated
		if now.Sub(c.Checked) < 24*time.Hour && !c.Checked.After(now) {
			return n
		}
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r := Check(ctx, sys, opt)
		if ctx.Err() != nil {
			return
		}
		n.mu.Lock()
		n.outdated = r.Outdated()
		n.mu.Unlock()
		if cache == "" || len(r.Errors) > 0 {
			return // a failed lookup (offline, no git access) is retried at the next start
		}
		b, _ := json.Marshal(cached{Checked: now, Outdated: r.Outdated()})
		writeAtomic(cache, b) // two servers starting together must not interleave their writes
	}()
	return n
}

func writeAtomic(path string, b []byte) {
	if os.MkdirAll(filepath.Dir(path), 0o755) != nil {
		return
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".update-check-")
	if err != nil {
		return
	}
	_, werr := f.Write(b)
	if cerr := f.Close(); werr != nil || cerr != nil || os.Rename(f.Name(), path) != nil {
		os.Remove(f.Name())
	}
}

// Sentence is appended to the initialize instructions; "" when everything is up to date.
func (n *Notice) Sentence() string {
	if n == nil {
		return ""
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.outdated == 0 {
		return ""
	}
	return fmt.Sprintf("Updates available for %d Raijin tools/engines: call raijin_update.", n.outdated)
}
