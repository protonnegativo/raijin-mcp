// Command raijin-mcp is an MCP server over stdio that exposes every Raijin tool on PATH to AI agents.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/protonnegativo/raijin-mcp/internal/banner"
	"github.com/protonnegativo/raijin-mcp/internal/mcp"
	"github.com/protonnegativo/raijin-mcp/internal/tools"
	"github.com/protonnegativo/raijin-mcp/internal/update"
)

// instructions is sent once at initialize. It explains the shared output so tool descriptions
// do not have to repeat it.
const instructions = "Raijin offensive-security tools, for authorized targets only. Each returns compact Raijin Schema JSON: summary, findings (ranked), groups (collapsed info), omitted (counts of what was cut), errors (with hints), next (follow-ups), raw (engine output file)."

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) > 0 && args[0] == "update" {
		return runUpdate(args[1:], stdout, stderr)
	}
	fs := flag.NewFlagSet("raijin-mcp", flag.ContinueOnError)
	fs.SetOutput(stderr)
	only := fs.String("tools", "", "comma-separated verbs to expose, e.g. scan,probe (default: every Raijin tool found)")
	binDir := fs.String("bin-dir", "", "directory searched for raijin-<verb> binaries before PATH")
	listMissing := fs.Bool("list-missing", false, "also list tools that are not installed, with an install hint")
	callTimeout := fs.Duration("call-timeout", 30*time.Minute, "limit for one tool call (0 means none)")
	list := fs.Bool("list", false, "print the tools/list result as JSON and exit")
	showVersion := fs.Bool("version", false, "print the version")
	updateCheck := fs.Bool("update-check", true, "check for updates in the background, at most once a day")
	showBanner := fs.Bool("banner", false, "print the Raijin banner to stderr (off by default to keep output small)")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: raijin-mcp [flags]   (speaks MCP on stdin/stdout)\n"+
			"       raijin-mcp update [--check] [--force] [--tools scan,probe]   (raijin-mcp update -h)\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if *showBanner {
		banner.Write(stderr, "raijin-mcp", version(), useColor(stderr))
	}
	if *showVersion {
		fmt.Fprintln(stdout, "raijin-mcp", version())
		return 0
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(stderr, "raijin-mcp: unexpected arguments:", strings.Join(fs.Args(), " "))
		return 1
	}

	opt := tools.Options{BinDir: *binDir, ListMissing: *listMissing, CallTimeout: *callTimeout}
	if *only != "" {
		for _, v := range strings.Split(*only, ",") {
			v = strings.TrimPrefix(strings.TrimSpace(v), "raijin-")
			if _, ok := tools.Lookup(v); !ok {
				fmt.Fprintln(stderr, "raijin-mcp: unknown tool:", v)
				return 1
			}
			opt.Only = append(opt.Only, v)
		}
	}
	p := tools.Discover(opt)
	uopt := updateOptions(opt.Only)
	sys := update.System{BinDir: *binDir}
	up := &update.Provider{Provider: p, Sys: sys, Opt: uopt, Version: version()}
	if *list {
		enc := json.NewEncoder(stdout)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(map[string]any{"tools": up.Tools()})
		return 0
	}
	var ready, missing []string
	for _, t := range p.Resolved() {
		if t.Missing == "" {
			ready = append(ready, t.Verb)
		} else {
			missing = append(missing, t.Verb)
		}
	}
	fmt.Fprintf(stderr, "raijin-mcp %s: exposing %d tool(s) [%s]", version(), len(ready), strings.Join(ready, " "))
	if len(missing) > 0 {
		fmt.Fprintf(stderr, "; unavailable [%s], see raijin-mcp --list --list-missing", strings.Join(missing, " "))
	}
	fmt.Fprintln(stderr)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	srv := &mcp.Server{Name: "raijin-mcp", Version: version(), Instructions: instructions, Provider: up}
	if *updateCheck {
		srv.Notice = update.StartNotice(sys, uopt, update.CachePath(), time.Now()).Sentence
	}
	if err := srv.Serve(ctx, stdin, stdout); err != nil {
		fmt.Fprintln(stderr, "raijin-mcp:", err)
		return 1
	}
	return 0
}

// useColor is true when w is a terminal and NO_COLOR is not set.
func useColor(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}
