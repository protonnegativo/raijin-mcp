// Package update checks and updates the installed Raijin tools and the engines they run: the tools
// to their latest release, the engines to the version each tool was tested with (its engines.json) or,
// forced, to their latest version.
package update

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
)

// Module is where the Raijin tools live.
const Module = "github.com/protonnegativo"

// Sys is everything the updater does to the machine; tests replace it.
type Sys interface {
	// Locate returns the path of an executable (the --bin-dir first, then PATH), or "".
	Locate(name string) string
	// BuildInfo reads the Go build info of a binary.
	BuildInfo(path string) (*debug.BuildInfo, error)
	// EngineOutput runs an engine's version command and returns what it printed.
	EngineOutput(ctx context.Context, name, path string) string
	// Run runs a command outside any Go module, with env added to the environment.
	Run(ctx context.Context, env []string, name string, args ...string) ([]byte, error)
	// Writable is true when files can be created in dir.
	Writable(dir string) bool
	// DefaultBin is where "go install" puts binaries when GOBIN is not set.
	DefaultBin() string
}

// Engine is one entry of a tool's engines.json.
type Engine struct {
	Version string `json:"version"`
	Go      string `json:"go,omitempty"`      // package to go install
	Pip     string `json:"pip,omitempty"`     // PyPI package, installed with pipx
	System  string `json:"system,omitempty"`  // OS package; never installed here
	Release string `json:"release,omitempty"` // GitHub repo whose install script installs the release
	Below   string `json:"below,omitempty"`   // the tool accepts only versions lower than this (a known-bad range)
}

// Options select what is checked and how.
type Options struct {
	Verbs        []string // tools to look for, raijin-<verb>
	Self         string   // path of the running raijin-mcp, checked too when installed with go install; "" for none
	Force        bool     // engines at their latest version instead of the tested one
	AllowScripts bool     // run install scripts (trufflehog's) instead of printing them
}

// Item is one tool or engine and what to do about it.
type Item struct {
	Kind      string   // "tool" or "engine"
	Name      string   // raijin-scan, nuclei
	Path      string   // installed binary; "" when missing
	Installed string   // installed version; "" when missing or unknown
	Target    string   // version to reach
	Tested    bool     // Target is the tested version, not the latest
	Action    string   // "" (nothing to do), "update", "downgrade", "install" or "manual"
	Command   string   // what runs, or what to run by hand
	Result    string   // after Apply: "updated", "failed" or "run by hand"
	Err       string   // why it failed
	UsedBy    []string // engines: the tools that run it
	Unknown   bool     // installed, but its version could not be read
	SystemOK  bool     // a system package at the tested major: nothing to do, whatever the minor
	Reason    string   // engines with a bound: the tools that set it, and the bound
	TestedBy  string   // engines whose tools tested different versions: which tool set the target
	env       []string
	argv      []string
	installTo string
	exact     bool   // the install must give Target exactly (tested, or below a bound)
	engine    Engine // the merged engines.json entry, to read the version again after Apply
}

// Error is a lookup that failed.
type Error struct {
	Kind   string `json:"kind"`
	Target string `json:"target,omitempty"`
	Hint   string `json:"hint"`
}

// Report is the result of Check, and of Apply after it.
type Report struct {
	Items   []*Item
	Errors  []Error
	Applied bool
	Force   bool // engines were checked against their latest version
}

// Outdated counts the items with something to do.
func (r *Report) Outdated() int {
	n := 0
	for _, it := range r.Items {
		if it.Action != "" {
			n++
		}
	}
	return n
}

// Failed is true when a lookup failed or, after Apply, when something is still out of date.
func (r *Report) Failed() bool {
	if len(r.Errors) > 0 {
		return true
	}
	if r.Applied {
		for _, it := range r.Items {
			if it.Action != "" && it.Result != "updated" {
				return true
			}
		}
	}
	return false
}

// goEnv is added to every go command: the Raijin repos are private, so they are fetched with git
// instead of through the module proxy.
func goEnv() []string {
	priv := Module + "/*"
	if old := os.Getenv("GOPRIVATE"); old != "" {
		priv = old + "," + priv
	}
	return []string{"GOPRIVATE=" + priv}
}

// ModuleVersion is the module version a binary was installed at with go install, or "" for a local
// build: those record vcs.* settings, and since Go 1.24 also a pseudo-version, which says nothing about
// what the checkout holds.
func ModuleVersion(info *debug.BuildInfo) string {
	if info == nil {
		return ""
	}
	for _, s := range info.Settings {
		if s.Key == "vcs.revision" {
			return ""
		}
	}
	if v := info.Main.Version; v != "(devel)" {
		return v
	}
	return ""
}

type tool struct {
	item    *Item
	module  string
	pkg     string
	engines map[string]Engine
}

// Check finds what is out of date. It installs nothing.
func Check(ctx context.Context, sys Sys, opt Options) *Report {
	r := &Report{Force: opt.Force}
	var found []*tool
	for _, verb := range opt.Verbs {
		bin := "raijin-" + verb
		if path := sys.Locate(bin); path != "" {
			found = append(found, newTool(sys, bin, path))
		}
	}
	if opt.Self != "" {
		if t := newTool(sys, "raijin-mcp", opt.Self); t.item.Installed != "" {
			found = append(found, t)
		}
	}

	var mu sync.Mutex
	parallel(len(found), func(i int) {
		t := found[i]
		m, err := download(ctx, sys, t.module)
		mu.Lock()
		defer mu.Unlock()
		if err != nil {
			r.Errors = append(r.Errors, Error{"lookup_failed", t.item.Name, err.Error() +
				"; check that git can fetch " + t.module + " (the repos are private)"})
			return
		}
		t.item.Target = m.Version
		if t.item.Installed == "" || Compare(t.item.Installed, m.Version) < 0 {
			t.item.Action = "update"
			t.item.installTo = filepath.Dir(t.item.Path)
			t.item.env = append(goEnv(), "GOBIN="+t.item.installTo)
			t.item.argv = []string{"go", "install", t.pkg + "@latest"}
			t.item.Command = "GOBIN=" + t.item.installTo + " go install " + t.pkg + "@latest"
		}
		if m.Dir != "" {
			if b, err := readFile(filepath.Join(m.Dir, "engines.json")); err == nil {
				_ = json.Unmarshal(b, &t.engines)
			}
		}
	})
	sort.Slice(r.Errors, func(i, j int) bool { return r.Errors[i].Target < r.Errors[j].Target })

	for _, t := range found {
		r.Items = append(r.Items, t.item)
	}
	sort.SliceStable(r.Items, func(i, j int) bool { return r.Items[i].Name < r.Items[j].Name })

	engines, users := mergeEngines(found)
	names := make([]string, 0, len(engines))
	for n := range engines {
		names = append(names, n)
	}
	sort.Strings(names)
	items := make([]*Item, len(names))
	parallel(len(names), func(i int) {
		items[i] = checkEngine(ctx, sys, opt, names[i], engines[names[i]], users[names[i]])
	})
	r.Items = append(r.Items, items...)
	return r
}

func newTool(sys Sys, bin, path string) *tool {
	it := &Item{Kind: "tool", Name: bin, Path: path}
	if info, err := sys.BuildInfo(path); err == nil {
		it.Installed = ModuleVersion(info)
	}
	return &tool{item: it, module: Module + "/" + bin, pkg: Module + "/" + bin + "/cmd/" + bin}
}

// merged is an engine as every tool that runs it accepts it: Below is the strictest bound, Version the
// highest tested version under it, boundBy the tools that set the bound, and testedBy, when the tools
// tested different versions, the tools that tested Version and the others ("raijin-js 1.1.2").
type merged struct {
	Engine
	boundBy  []string
	testedBy []string
	others   []string
}

// mergeEngines joins the engines of every tool. An engine two tools share keeps the lowest bound and
// the highest tested version under it.
func mergeEngines(found []*tool) (map[string]merged, map[string][]string) {
	engines, users := map[string]merged{}, map[string][]string{}
	for _, t := range found {
		for name, e := range t.engines {
			m := engines[name]
			switch c := Compare(e.Below, m.Below); {
			case e.Below == "":
			case m.Below == "" || c < 0:
				m.Below, m.boundBy = e.Below, []string{t.item.Name}
			case c == 0:
				m.boundBy = append(m.boundBy, t.item.Name)
			}
			engines[name] = m
			users[name] = append(users[name], t.item.Name)
		}
	}
	for name, m := range engines {
		// the highest tested version under the bound; when no tool tested one, the first tool's
		var pick Engine
		has, pickUnder := false, false
		for _, t := range found {
			e, ok := t.engines[name]
			if !ok {
				continue
			}
			under := m.Below == "" || Compare(e.Version, m.Below) < 0
			if !has || under && (!pickUnder || Compare(e.Version, pick.Version) > 0) {
				pick, has, pickUnder = e, true, under
			}
		}
		bound := m.Below
		m.Engine, m.Below = pick, bound
		var by, others []string
		for _, t := range found {
			if e, ok := t.engines[name]; ok && Compare(e.Version, pick.Version) == 0 {
				by = append(by, t.item.Name)
			} else if ok {
				others = append(others, t.item.Name+" "+e.Version)
			}
		}
		if len(others) > 0 {
			m.testedBy, m.others = by, others
			sort.Strings(m.testedBy)
			sort.Strings(m.others)
		}
		sort.Strings(m.boundBy)
		engines[name] = m
	}
	for _, u := range users {
		sort.Strings(u)
	}
	return engines, users
}

func checkEngine(ctx context.Context, sys Sys, opt Options, name string, m merged, usedBy []string) *Item {
	e := m.Engine
	it := &Item{Kind: "engine", Name: name, UsedBy: usedBy, Target: e.Version, Tested: true,
		exact: !opt.Force || e.Below != "", engine: e}
	it.Path = sys.Locate(name)
	if it.Path != "" {
		it.Installed = engineVersion(ctx, sys, name, it.Path, e)
		it.Unknown = it.Installed == ""
	}
	if e.Below != "" {
		verb := "accepts"
		if len(m.boundBy) > 1 {
			verb = "accept"
		}
		it.Reason = fmt.Sprintf("%s %s only %s below %s", strings.Join(m.boundBy, ", "), verb, name, e.Below)
	}
	if !opt.Force && len(m.testedBy) > 0 {
		it.TestedBy = fmt.Sprintf("%s tested by %s (%s)", e.Version, strings.Join(m.testedBy, ", "), strings.Join(m.others, ", "))
	}
	goMod := e.Go
	if e.Release != "" && goMod == "" {
		goMod = "github.com/" + e.Release
	}
	switch {
	case !opt.Force || goMod == "":
	case e.Below != "":
		if v, err := highestBelow(ctx, sys, modulePath(goMod), e.Below); err == nil && Compare(v, e.Version) > 0 {
			it.Target, it.Tested = strings.TrimPrefix(v, "v"), false
		}
	default:
		if v, err := latest(ctx, sys, modulePath(goMod)); err == nil && Compare(v, e.Version) >= 0 {
			it.Target, it.Tested = strings.TrimPrefix(v, "v"), false
		}
	}
	system := e.Go == "" && e.Pip == "" && e.Release == ""

	switch {
	case it.Unknown:
		return it // installed, version unreadable: leave it alone
	case it.Path == "":
		it.Action = "install"
	case e.Below != "" && Compare(it.Installed, e.Below) >= 0:
		it.Action = "downgrade"
	case system:
		// the distro decides the minor (apt has 7.94 where nmap.org has 7.98): only another major needs a hand
		if sameMajor(it.Installed, it.Target) {
			it.SystemOK = true
			return it
		}
		it.Action = "update"
	case Compare(it.Installed, it.Target) < 0:
		it.Action = "update"
	case !opt.Force && Compare(it.Installed, it.Target) > 0:
		it.Action = "downgrade" // newer than tested: back to the tested version
	default:
		return it
	}

	dir := ""
	if it.Path != "" && sys.Writable(filepath.Dir(it.Path)) {
		dir = filepath.Dir(it.Path)
	}
	ver := "latest"
	if it.exact {
		ver = "v" + it.Target
	}
	switch {
	case e.Release != "":
		if dir == "" {
			dir = sys.DefaultBin()
		}
		it.installTo = dir
		it.Command = fmt.Sprintf("curl -sSfL https://raw.githubusercontent.com/%s/main/scripts/install.sh | sh -s -- -b %s v%s",
			e.Release, dir, it.Target)
		if opt.AllowScripts {
			it.argv = []string{"sh", "-c", it.Command}
		} else {
			it.Action = "manual"
			it.Command += "   (or rerun with --allow-scripts)"
		}
	case e.Go != "":
		it.env = goEnv()
		it.Command = "go install " + e.Go + "@" + ver
		if dir != "" {
			it.env = append(it.env, "GOBIN="+dir)
			it.Command = "GOBIN=" + dir + " " + it.Command
			it.installTo = dir
		} else {
			it.installTo = sys.DefaultBin()
		}
		it.argv = []string{"go", "install", e.Go + "@" + ver}
	case e.Pip != "":
		args := []string{"pipx", "upgrade", e.Pip}
		switch {
		case it.exact:
			args = []string{"pipx", "install", "--force", e.Pip + "==" + it.Target}
		case it.Path == "":
			args = []string{"pipx", "install", e.Pip}
		}
		it.Command = strings.Join(args, " ")
		if sys.Locate("pipx") != "" {
			it.argv = args
		} else {
			it.Action = "manual"
			it.Command = "install pipx, then: " + it.Command
		}
	default:
		pkg := e.System
		if pkg == "" {
			pkg = name
		}
		it.Action = "manual"
		it.Command = "apt install " + pkg + " (or brew install " + pkg + ")"
	}
	return it
}

// Apply runs the actions of a Check report: tools first, then engines. Items left for the user
// ("manual") are marked "run by hand".
func Apply(ctx context.Context, sys Sys, r *Report) {
	r.Applied = true
	for _, it := range r.Items {
		switch {
		case it.Action == "":
			continue
		case it.argv == nil:
			it.Result = "run by hand"
			continue
		}
		out, err := sys.Run(ctx, it.env, it.argv[0], it.argv[1:]...)
		if err != nil {
			it.Result, it.Err = "failed", lastLine(string(out), err.Error())
			continue
		}
		it.Result = "updated"
		if it.Kind == "tool" {
			if info, err := sys.BuildInfo(it.Path); err == nil {
				it.Installed = ModuleVersion(info)
			}
			continue
		}
		// an install can succeed and change nothing: a curl that failed into sh, or an older copy of
		// the engine that comes first on PATH
		it.Path = sys.Locate(it.Name)
		if it.Path != "" {
			it.Installed = engineVersion(ctx, sys, it.Name, it.Path, it.engine)
		}
		c := Compare(it.Installed, it.Target)
		if it.Path != "" && (c == 0 || c > 0 && !it.exact) {
			continue
		}
		it.Result = "failed"
		dest := ""
		if it.installTo != "" {
			dest = filepath.Join(it.installTo, it.Name)
		}
		switch {
		case it.Path == "":
			it.Err = fmt.Sprintf("installed, but %s is not on PATH", it.Name)
			if dest != "" {
				it.Err += "; it went to " + dest
			}
		case dest != "" && dest != it.Path:
			it.Err = fmt.Sprintf("installed %s %s, but %s comes first on PATH and is %s",
				dest, orDash(engineVersion(ctx, sys, it.Name, dest, it.engine)), it.Path, orDash(it.Installed))
		default:
			it.Err = fmt.Sprintf("installed, but %s is still %s", it.Path, orDash(it.Installed))
		}
	}
}

// engineVersion is the installed version of an engine. For a Go engine it is the module version in the
// binary's build info, what go install wrote: the version an engine prints can be wrong (ffuf 2.3.0
// prints 2.1.0-dev, tlsx 1.4.3 prints v1.4.0). The printed version is the fallback, for other engines
// and for binaries without a module version (stripped, a local build, another module's binary).
func engineVersion(ctx context.Context, sys Sys, name, path string, e Engine) string {
	if e.Go != "" {
		if info, err := sys.BuildInfo(path); err == nil && info.Main.Path != "" &&
			(e.Go == info.Main.Path || strings.HasPrefix(e.Go, info.Main.Path+"/")) {
			if v := ModuleVersion(info); v != "" {
				return strings.TrimPrefix(v, "v")
			}
		}
	}
	return EngineVersion(sys.EngineOutput(ctx, name, path))
}

// sameMajor is true when both versions parse and have the same major.
func sameMajor(a, b string) bool {
	va, vb := parse(a), parse(b)
	return va.ok && vb.ok && va.num[0] == vb.num[0]
}

// readFile is os.ReadFile; engines.json is read from the downloaded module.
var readFile = os.ReadFile

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// modulePath is the module of a go package path: the part before /cmd/.
func modulePath(pkg string) string {
	if i := strings.Index(pkg, "/cmd/"); i >= 0 {
		return pkg[:i]
	}
	return pkg
}

type moduleInfo struct {
	Version string
	Dir     string
	Error   string
}

// download fetches a module at its latest version: the version, and the directory holding its files.
func download(ctx context.Context, sys Sys, module string) (moduleInfo, error) {
	return goJSON(ctx, sys, "mod", "download", "-json", module+"@latest")
}

// latest is the latest version of a public module (the engines), without downloading it.
func latest(ctx context.Context, sys Sys, module string) (string, error) {
	m, err := goJSON(ctx, sys, "list", "-m", "-json", module+"@latest")
	return m.Version, err
}

// highestBelow is the highest release of a public module lower than bound, from the module proxy.
// Pre-releases and pseudo-versions are skipped.
func highestBelow(ctx context.Context, sys Sys, module, bound string) (string, error) {
	out, err := sys.Run(ctx, goEnv(), "go", "list", "-m", "-versions", "-json", module)
	var m struct{ Versions []string }
	if jerr := json.Unmarshal(out, &m); jerr != nil {
		if err == nil {
			err = jerr
		}
		return "", fmt.Errorf("go list: %s", lastLine(string(out), err.Error()))
	}
	best := ""
	for _, v := range m.Versions {
		if IsRelease(v) && parse(v).pre == "" && Compare(v, bound) < 0 && Compare(v, best) > 0 {
			best = v
		}
	}
	if best == "" {
		return "", fmt.Errorf("no release of %s below %s", module, bound)
	}
	return best, nil
}

func goJSON(ctx context.Context, sys Sys, args ...string) (moduleInfo, error) {
	out, err := sys.Run(ctx, goEnv(), "go", args...)
	var m moduleInfo
	if jerr := json.Unmarshal(out, &m); jerr != nil || m.Version == "" || m.Error != "" {
		switch {
		case m.Error != "":
			return m, fmt.Errorf("%s", lastLine(m.Error, "lookup failed"))
		case err != nil:
			return m, fmt.Errorf("go %s: %s", args[0], lastLine(string(out), err.Error()))
		}
		return m, fmt.Errorf("go %s: no version in the output", args[0])
	}
	return m, nil
}

// lastLine is the last non-empty line of s (go puts the reason last), cut to 300 bytes, or def.
func lastLine(s, def string) string {
	lines := strings.Split(strings.TrimSpace(s), "\n")
	l := strings.TrimSpace(lines[len(lines)-1])
	if l == "" {
		return def
	}
	if len(l) > 300 {
		l = l[:300]
	}
	return l
}

// parallel runs f(0..n-1), at most 6 at a time.
func parallel(n int, f func(int)) {
	sem := make(chan struct{}, 6)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		sem <- struct{}{}
		go func(i int) {
			defer wg.Done()
			defer func() { <-sem }()
			f(i)
		}(i)
	}
	wg.Wait()
}
