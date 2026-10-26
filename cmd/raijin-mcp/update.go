package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/protonnegativo/raijin-mcp/internal/tools"
	"github.com/protonnegativo/raijin-mcp/internal/update"
)

// runUpdate is "raijin-mcp update": the apt update of the Raijin tools and their engines.
func runUpdate(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("raijin-mcp update", flag.ContinueOnError)
	fs.SetOutput(stderr)
	check := fs.Bool("check", false, "only show what is out of date; install nothing")
	force := fs.Bool("force", false, "engines at their latest version, even if no Raijin tool was tested with it")
	fs.Bool("pinned", false, "engines at the versions each tool was tested with (now the default)")
	only := fs.String("tools", "", "comma-separated verbs to update, e.g. scan,probe (default: every Raijin tool installed)")
	binDir := fs.String("bin-dir", "", "directory searched for raijin-<verb> binaries and engines before PATH")
	format := fs.String("format", "table", "output format: table or json")
	allowScripts := fs.Bool("allow-scripts", false, "run an engine's official install script (trufflehog) instead of printing it")
	fs.Usage = func() {
		fmt.Fprintf(stderr, "usage: raijin-mcp update [--check] [--force] [--tools scan,probe]\n\n"+
			"Updates every installed raijin-<verb> to its latest release and its engines to the version the\n"+
			"tools were tested with (--force: the latest). Never uses sudo; system packages are printed, not installed.\n\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 1
	}
	if fs.NArg() > 0 {
		fmt.Fprintln(stderr, "raijin-mcp update: unexpected arguments:", strings.Join(fs.Args(), " "))
		return 1
	}
	if *format != "table" && *format != "json" {
		fmt.Fprintln(stderr, "raijin-mcp update: --format must be table or json")
		return 1
	}
	var verbs []string
	for _, v := range update.ParseVerbs(*only) {
		if _, ok := tools.Lookup(v); !ok && v != "mcp" {
			fmt.Fprintln(stderr, "raijin-mcp update: unknown tool:", v)
			return 1
		}
		verbs = append(verbs, v)
	}
	opt := updateOptions(verbs)
	opt.Force, opt.AllowScripts = *force, *allowScripts

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sys := update.System{BinDir: *binDir}
	r := update.Check(ctx, sys, opt)
	if !*check {
		update.Apply(ctx, sys, r)
	}
	if *format == "json" {
		fmt.Fprintln(stdout, string(r.JSON(version(), "run raijin-mcp update")))
	} else {
		r.Table(stdout)
	}
	if r.Failed() {
		return 1
	}
	return 0
}

// updateOptions are the tools to check: the verbs given (every known one when none, "mcp" for
// raijin-mcp itself), and this binary when it was installed with go install.
func updateOptions(only []string) update.Options {
	var opt update.Options
	for _, s := range tools.Table {
		if len(only) == 0 || contains(only, s.Verb) {
			opt.Verbs = append(opt.Verbs, s.Verb)
		}
	}
	if len(only) == 0 || contains(only, "mcp") {
		if self, err := os.Executable(); err == nil {
			opt.Self = self
		}
	}
	return opt
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
