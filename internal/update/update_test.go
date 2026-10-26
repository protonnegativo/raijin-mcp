package update

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/protonnegativo/raijin-mcp/internal/mcp"
)

func TestCompare(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"v0.1.0", "v0.1.0", 0},
		{"v0.1.0", "v0.1.1", -1},
		{"v0.2.0", "v0.1.9", 1},
		{"v1.10.0", "v1.9.0", 1},
		{"1.12.0", "v1.12.0", 0},
		{"7.94", "7.94.0", 0},
		{"v1.0.0-rc.1", "v1.0.0", -1},
		{"v1.0.0-alpha", "v1.0.0-alpha.1", -1},
		{"v1.0.0-alpha.2", "v1.0.0-alpha.10", -1},
		{"v1.0.0-1", "v1.0.0-alpha", -1},
		{"v0.1.0+dirty", "v0.1.0", 0},
		// pseudo-versions: older than any tag, ordered by commit time among themselves
		{"v0.0.0-20261024160549-dfc3ef737dc9", "v0.1.0", -1},
		{"v0.1.1-0.20261024160549-dfc3ef737dc9", "v0.1.0", -1},
		{"v0.0.0-20261024160549-dfc3ef737dc9", "v0.0.0-20261025132954-1b5f9d7dd231", -1},
		{"v0.0.0-20261025132954-1b5f9d7dd231", "v0.0.0-20261025132954-1b5f9d7dd231", 0},
		// unknown is older than anything
		{"(devel)", "v0.0.0-20261024160549-dfc3ef737dc9", -1},
		{"", "v0.1.0", -1},
		{"", "(devel)", 0},
	}
	for _, c := range cases {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.a, c.b, got, c.want)
		}
		if got := Compare(c.b, c.a); got != -c.want {
			t.Errorf("Compare(%q, %q) = %d, want %d", c.b, c.a, got, -c.want)
		}
	}
	if IsRelease("v0.0.0-20261024160549-dfc3ef737dc9") || !IsRelease("v0.1.3") || IsRelease("(devel)") {
		t.Error("IsRelease")
	}
}

func TestModuleVersion(t *testing.T) {
	cases := []struct{ info, want string }{
		// go install github.com/protonnegativo/raijin-scan/cmd/raijin-scan@v0.1.2
		{"go\tgo1.27.3\npath\tgithub.com/protonnegativo/raijin-scan/cmd/raijin-scan\nmod\tgithub.com/protonnegativo/raijin-scan\tv0.1.2\th1:abc=\nbuild\t-buildmode=exe\nbuild\tGOOS=linux\n", "v0.1.2"},
		// go install ...@<commit>: a pseudo-version, kept (it compares older than any tag)
		{"go\tgo1.27.3\npath\tgithub.com/protonnegativo/raijin-diff/cmd/raijin-diff\nmod\tgithub.com/protonnegativo/raijin-diff\tv0.0.0-20261025132954-1b5f9d7dd231\th1:abc=\n", "v0.0.0-20261025132954-1b5f9d7dd231"},
		// go build in a checkout: vcs settings, version means nothing
		{"go\tgo1.27.3\npath\tgithub.com/protonnegativo/raijin-scan/cmd/raijin-scan\nmod\tgithub.com/protonnegativo/raijin-scan\tv0.0.0-20261024160549-dfc3ef737dc9+dirty\t\nbuild\tvcs=git\nbuild\tvcs.revision=dfc3ef737dc9aaaa\nbuild\tvcs.modified=true\n", ""},
		{"go\tgo1.21.0\npath\tgithub.com/protonnegativo/raijin-scan/cmd/raijin-scan\nmod\tgithub.com/protonnegativo/raijin-scan\t(devel)\t\n", ""},
	}
	for _, c := range cases {
		info, err := debug.ParseBuildInfo(c.info)
		if err != nil {
			t.Fatal(err)
		}
		if got := ModuleVersion(info); got != c.want {
			t.Errorf("ModuleVersion(%q) = %q, want %q", c.info, got, c.want)
		}
	}
}

func TestEngineVersion(t *testing.T) {
	cases := map[string]string{
		"nuclei":     "[\x1b[34mINF\x1b[0m] Nuclei Engine Version: v3.3.9\n[\x1b[34mINF\x1b[0m] Nuclei Config Directory: /root/.config/nuclei\n",
		"httpx":      "\n    __    __  __       _  __\n   / /_  / /_/ /_____ | |/ /\n             /_/\n\n\t\tprojectdiscovery.io\n\n[\x1b[34mINF\x1b[0m] Current Version: v1.6.10\n",
		"naabu":      "\t\tprojectdiscovery.io\n\n[\x1b[34mINF\x1b[0m] Current Version: 2.6.1\n",
		"tlsx":       "   |_| |____|___/_/\\_\\\tv1.2.2\n\n\t\tprojectdiscovery.io\n[\x1b[34mINF\x1b[0m] Current version: v1.2.2\n",
		"katana":     "/_/\\_\\\\_,_/\\__/\\_,_/_//_/\\_,_/\n\t\tprojectdiscovery.io\n[\x1b[34mINF\x1b[0m] Current version: v1.1.2\n",
		"subfinder":  "[\x1b[34mINF\x1b[0m] Current Version: v2.6.7\n[\x1b[34mINF\x1b[0m] Subfinder Config Directory: /root/.config/subfinder\n",
		"dnsx":       "  \\__,_||_| |_||___//_/\\_\\\n\t\tprojectdiscovery.io\n[\x1b[34mINF\x1b[0m] Current Version: 1.2.1\n",
		"ffuf":       "ffuf version: 2.1.0\n",
		"dalfox":     "\r\n    _..._\n  .' .::::.   __   _   _    ___ _ __ __\n\r🌙🦊 Dalfox is a powerful open-source XSS scanner.\n\r\x1b[93mv2.9.2\x1b[0m\n",
		"trufflehog": "trufflehog 3.99.3\n",
		"nmap":       "Nmap version 7.94SVN ( https://nmap.org )\nPlatform: x86_64-pc-linux-gnu\nCompiled with: liblua-5.4.6 openssl-3.0.13\n",
		"arjun":      "2.2.7\n",
		// nuclei 3.11.1 warns about its JSON library first; go1.17 is not the version
		"nuclei-3.11": "WARNING: sonic/ast only supports (go1.17~1.26 and amd64 CPU) or (go1.20~1.26 and arm64 CPU), but your environment is not suitable and will fallback to encoding/json\n[\x1b[34mINF\x1b[0m] Nuclei Engine Version: v3.11.1\n[\x1b[34mINF\x1b[0m] Nuclei Config Directory: /root/.config/nuclei\n",
	}
	want := map[string]string{"nuclei": "3.3.9", "httpx": "1.6.10", "naabu": "2.6.1", "tlsx": "1.2.2", "katana": "1.1.2",
		"subfinder": "2.6.7", "dnsx": "1.2.1", "ffuf": "2.1.0", "dalfox": "2.9.2", "trufflehog": "3.99.3", "nmap": "7.94", "arjun": "2.2.7",
		"nuclei-3.11": "3.11.1"}
	for name, out := range cases {
		if got := EngineVersion(out); got != want[name] {
			t.Errorf("%s: EngineVersion = %q, want %q", name, got, want[name])
		}
	}
	if EngineVersion("command not found") != "" {
		t.Error("no version in the output must be empty")
	}
}

// fakeSys answers from maps and records the commands it is asked to run.
type fakeSys struct {
	paths    map[string]string // name -> path
	tools    map[string]string // path -> module version
	mods     map[string]string // path -> "module version", for engines with build info
	engines  map[string]string // engine name -> version output
	modules  map[string]string // module -> latest version
	versions map[string]string // module -> its releases, space-separated
	dirs     map[string]string // module -> downloaded dir
	writable bool
	ran      []string
	runErr   map[string]bool // argv prefix -> fail
}

func (f *fakeSys) Locate(name string) string { return f.paths[name] }
func (f *fakeSys) BuildInfo(path string) (*debug.BuildInfo, error) {
	if m, ok := f.mods[path]; ok {
		p, v, _ := strings.Cut(m, " ")
		return &debug.BuildInfo{Main: debug.Module{Path: p, Version: v}}, nil
	}
	v, ok := f.tools[path]
	if !ok {
		return nil, errors.New("not a Go binary")
	}
	return &debug.BuildInfo{Main: debug.Module{Version: v}}, nil
}
func (f *fakeSys) EngineOutput(_ context.Context, name, _ string) string { return f.engines[name] }
func (f *fakeSys) Writable(string) bool                                  { return f.writable }
func (f *fakeSys) DefaultBin() string                                    { return "/home/u/go/bin" }

func (f *fakeSys) Run(_ context.Context, env []string, name string, args ...string) ([]byte, error) {
	cmd := strings.Join(append([]string{name}, args...), " ")
	if name == "go" && len(args) > 2 && args[2] == "-versions" {
		mod := args[len(args)-1]
		v, ok := f.versions[mod]
		if !ok {
			return []byte("go: module lookup disabled"), errors.New("exit status 1")
		}
		b, _ := json.Marshal(map[string]any{"Path": mod, "Versions": strings.Fields(v)})
		return b, nil
	}
	if name == "go" && (args[0] == "mod" || args[0] == "list") {
		mod := strings.TrimSuffix(args[len(args)-1], "@latest")
		v, ok := f.modules[mod]
		if !ok {
			return []byte(`{"Path":"` + mod + `","Error":"module ` + mod + `: git ls-remote: repository not found"}`), errors.New("exit status 1")
		}
		b, _ := json.Marshal(map[string]string{"Path": mod, "Version": v, "Dir": f.dirs[mod]})
		return b, nil
	}
	f.ran = append(f.ran, strings.Join(env, " ")+" | "+cmd)
	for prefix := range f.runErr {
		if strings.HasPrefix(cmd, prefix) {
			return []byte("go: build failed"), errors.New("exit status 1")
		}
	}
	return nil, nil
}

func moduleDir(t *testing.T, engines string) string {
	dir := t.TempDir()
	if engines != "" {
		if err := os.WriteFile(filepath.Join(dir, "engines.json"), []byte(engines), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func newFake(t *testing.T) *fakeSys {
	scan := Module + "/raijin-scan"
	diff := Module + "/raijin-diff"
	ports := Module + "/raijin-ports"
	return &fakeSys{
		paths: map[string]string{
			"raijin-scan": "/opt/bin/raijin-scan", "raijin-diff": "/opt/bin/raijin-diff", "raijin-ports": "/opt/bin/raijin-ports",
			"nuclei": "/usr/local/bin/nuclei", "naabu": "/opt/bin/naabu", "nmap": "/usr/bin/nmap",
		},
		tools: map[string]string{
			"/opt/bin/raijin-scan":  "v0.0.0-20261024160549-dfc3ef737dc9", // an older commit
			"/opt/bin/raijin-diff":  "v0.1.0",
			"/opt/bin/raijin-ports": "v0.1.0",
		},
		engines: map[string]string{
			"nuclei": "[INF] Nuclei Engine Version: v3.3.9",
			"naabu":  "[INF] Current Version: 2.5.0",
			"nmap":   "Nmap version 7.80 ( https://nmap.org )",
		},
		modules: map[string]string{
			scan: "v0.1.0", diff: "v0.1.0", ports: "v0.1.0",
			"github.com/projectdiscovery/nuclei/v3": "v3.4.0",
			"github.com/projectdiscovery/naabu/v2":  "v2.6.1",
		},
		dirs: map[string]string{
			scan:  moduleDir(t, `{"nuclei": {"version": "3.3.9", "go": "github.com/projectdiscovery/nuclei/v3/cmd/nuclei"}}`),
			diff:  moduleDir(t, ""),
			ports: moduleDir(t, `{"naabu": {"version": "2.6.1", "go": "github.com/projectdiscovery/naabu/v2/cmd/naabu"}, "nmap": {"version": "7.94", "system": "nmap"}}`),
		},
		writable: true,
	}
}

func byName(r *Report) map[string]*Item {
	m := map[string]*Item{}
	for _, it := range r.Items {
		m[it.Name] = it
	}
	return m
}

func TestCheckPlansWithoutInstalling(t *testing.T) {
	f := newFake(t)
	r := Check(context.Background(), f, Options{Verbs: []string{"scan", "diff", "ports", "probe"}, Force: true})
	if len(f.ran) != 0 {
		t.Fatalf("Check ran %v", f.ran)
	}
	it := byName(r)
	if len(it) != 6 || it["raijin-probe"] != nil {
		t.Fatalf("items: %v", it) // probe is not installed: not listed
	}
	if s := it["raijin-scan"]; s.Action != "update" || s.Target != "v0.1.0" ||
		s.Command != "GOBIN=/opt/bin go install "+Module+"/raijin-scan/cmd/raijin-scan@latest" {
		t.Errorf("raijin-scan: %+v", s)
	}
	if it["raijin-diff"].Action != "" || it["raijin-ports"].Action != "" {
		t.Error("tools at the latest release need nothing")
	}
	if n := it["nuclei"]; n.Action != "update" || n.Target != "3.4.0" || n.Tested ||
		n.Command != "GOBIN=/usr/local/bin go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" {
		t.Errorf("nuclei: %+v", n)
	}
	if n := it["naabu"]; n.Action != "update" || n.Installed != "2.5.0" {
		t.Errorf("naabu: %+v", n)
	}
	if n := it["nmap"]; n.Action != "" || !n.SystemOK || n.status() != "ok (system)" {
		t.Errorf("nmap 7.80, tested 7.94, is a system package of the same major: %+v", n)
	}
	if r.Outdated() != 3 || r.Failed() {
		t.Errorf("outdated %d failed %v", r.Outdated(), r.Failed())
	}
}

func TestCheckTestedByDefault(t *testing.T) {
	f := newFake(t)
	r := Check(context.Background(), f, Options{Verbs: []string{"scan", "ports"}})
	it := byName(r)
	if n := it["nuclei"]; n.Action != "" || n.Target != "3.3.9" || !n.Tested {
		t.Errorf("nuclei at the tested version, 3.4.0 out: %+v", n)
	}
	if n := it["naabu"]; n.Action != "update" || n.Target != "2.6.1" || !n.Tested ||
		n.Command != "GOBIN=/opt/bin go install github.com/projectdiscovery/naabu/v2/cmd/naabu@v2.6.1" {
		t.Errorf("naabu: %+v", n)
	}
	var b strings.Builder
	r.Table(&b)
	if strings.Contains(b.String(), "--force") {
		t.Errorf("tested versions need no --force line:\n%s", b.String())
	}

	f.engines["nuclei"] = "Nuclei Engine Version: v3.4.0" // newer than tested: back to the tested one
	f.writable = false
	r = Check(context.Background(), f, Options{Verbs: []string{"scan"}})
	n := byName(r)["nuclei"]
	if n.Action != "downgrade" || n.Target != "3.3.9" || !n.Tested ||
		n.Command != "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.3.9" {
		t.Errorf("nuclei 3.4.0: %+v", n)
	}
	b.Reset()
	r.Table(&b)
	if !strings.Contains(b.String(), "nuclei: 3.4.0 is newer than the tested 3.3.9 (--force keeps it)") {
		t.Errorf("table:\n%s", b.String())
	}
	// forced, 3.4.0 is the latest: nothing to do, but it is untested
	r = Check(context.Background(), f, Options{Verbs: []string{"scan"}, Force: true})
	if n := byName(r)["nuclei"]; n.Action != "" || n.Tested {
		t.Errorf("forced nuclei 3.4.0: %+v", n)
	}
	b.Reset()
	r.Table(&b)
	if !strings.HasSuffix(b.String(), "--force: engines at the latest version, not tested with Raijin\n") {
		t.Errorf("table:\n%s", b.String())
	}
}

func TestApply(t *testing.T) {
	f := newFake(t)
	r := Check(context.Background(), f, Options{Verbs: []string{"scan", "diff", "ports"}, Force: true})
	// the installs "work": the fake now reports the new versions
	f.tools["/opt/bin/raijin-scan"] = "v0.1.0"
	f.engines["naabu"] = "Current Version: 2.6.1"
	f.runErr = map[string]bool{"go install github.com/projectdiscovery/nuclei": true}
	Apply(context.Background(), f, r)
	it := byName(r)
	if s := it["raijin-scan"]; s.Result != "updated" || s.Installed != "v0.1.0" {
		t.Errorf("raijin-scan: %+v", s)
	}
	if it["naabu"].Result != "updated" {
		t.Errorf("naabu: %+v", it["naabu"])
	}
	if n := it["nuclei"]; n.Result != "failed" || n.Err != "go: build failed" {
		t.Errorf("nuclei: %+v", n)
	}
	if len(f.ran) != 3 || !strings.Contains(f.ran[0], "GOPRIVATE=github.com/protonnegativo/*") || !strings.Contains(f.ran[0], "GOBIN=/opt/bin") {
		t.Errorf("ran: %q", f.ran)
	}
	if !r.Failed() {
		t.Error("a failed install must fail the run")
	}
}

func TestApplyNoticesAnInstallThatChangedNothing(t *testing.T) {
	f := newFake(t)
	r := Check(context.Background(), f, Options{Verbs: []string{"ports"}})
	Apply(context.Background(), f, r) // naabu still prints 2.5.0
	if n := byName(r)["naabu"]; n.Result != "failed" || !strings.Contains(n.Err, "still 2.5.0") {
		t.Errorf("naabu: %+v", n)
	}
}

func TestEngineVersionFromBuildInfo(t *testing.T) {
	f := newFake(t)
	// what go install wrote wins over what the binary prints: nuclei warns about go1.17 first, ffuf
	// 2.3.0 prints 2.1.0-dev
	f.engines["nuclei"] = "WARNING: sonic/ast only supports (go1.17~1.26 and amd64 CPU)\n[INF] Nuclei Engine Version: v3.3.0"
	f.mods = map[string]string{"/usr/local/bin/nuclei": "github.com/projectdiscovery/nuclei/v3 v3.4.0", "/opt/bin/ffuf": "github.com/ffuf/ffuf/v2 v2.3.0"}
	f.paths["ffuf"], f.engines["ffuf"] = "/opt/bin/ffuf", "ffuf version: 2.1.0-dev"
	f.paths["raijin-fuzz"], f.tools["/opt/bin/raijin-fuzz"] = "/opt/bin/raijin-fuzz", "v0.1.0"
	f.modules[Module+"/raijin-fuzz"], f.modules["github.com/ffuf/ffuf/v2"] = "v0.1.0", "v2.3.0"
	f.dirs[Module+"/raijin-fuzz"] = moduleDir(t, `{"ffuf": {"version": "2.1.0", "go": "github.com/ffuf/ffuf/v2"}}`)
	f.paths["naabu"] = "/opt/bin/naabu"
	f.mods["/opt/bin/naabu"] = "github.com/someone/else v9.0.0" // another module's binary: its output counts
	r := Check(context.Background(), f, Options{Verbs: []string{"scan", "fuzz", "ports"}, Force: true})
	it := byName(r)
	if n := it["nuclei"]; n.Installed != "3.4.0" || n.Action != "" {
		t.Errorf("nuclei: %+v", n)
	}
	if n := it["ffuf"]; n.Installed != "2.3.0" || n.Action != "" {
		t.Errorf("ffuf: %+v", n)
	}
	if n := it["naabu"]; n.Installed != "2.5.0" || n.Action != "update" {
		t.Errorf("naabu: %+v", n)
	}
	f.mods["/usr/local/bin/nuclei"] = "github.com/projectdiscovery/nuclei/v3 (devel)" // a local build
	if n := byName(Check(context.Background(), f, Options{Verbs: []string{"scan"}}))["nuclei"]; n.Installed != "3.3.0" {
		t.Errorf("nuclei (devel): %+v", n)
	}
}

func TestApplyNamesTheCopyFirstOnPath(t *testing.T) {
	f := newFake(t)
	f.paths["nuclei"] = "/root/go/bin/nuclei"
	f.writable = false // goes to the default GOBIN, /home/u/go/bin
	r := Check(context.Background(), f, Options{Verbs: []string{"scan"}, Force: true})
	f.mods = map[string]string{"/home/u/go/bin/nuclei": "github.com/projectdiscovery/nuclei/v3 v3.4.0"}
	Apply(context.Background(), f, r)
	want := "installed /home/u/go/bin/nuclei 3.4.0, but /root/go/bin/nuclei comes first on PATH and is 3.3.9"
	if n := byName(r)["nuclei"]; n.Result != "failed" || n.Err != want {
		t.Errorf("nuclei: %+v", n)
	}

	// the copy on PATH has the new module version, whatever it prints: updated
	f = newFake(t)
	r = Check(context.Background(), f, Options{Verbs: []string{"scan"}, Force: true})
	f.mods = map[string]string{"/usr/local/bin/nuclei": "github.com/projectdiscovery/nuclei/v3 v3.4.0"}
	f.engines["nuclei"] = "WARNING: sonic/ast only supports (go1.17~1.26 and amd64 CPU)"
	Apply(context.Background(), f, r)
	if n := byName(r)["nuclei"]; n.Result != "updated" || n.Installed != "3.4.0" {
		t.Errorf("nuclei: %+v", n)
	}
}

// dnsxFake has raijin-subs and raijin-takeover, which both refuse dnsx 1.3.0 and later, and dnsx 1.3.1
// installed.
func dnsxFake(t *testing.T, subs, takeover string) *fakeSys {
	f := newFake(t)
	for _, verb := range []string{"subs", "takeover"} {
		bin := "/opt/bin/raijin-" + verb
		f.paths["raijin-"+verb], f.tools[bin], f.modules[Module+"/raijin-"+verb] = bin, "v0.1.0", "v0.1.0"
	}
	f.dirs[Module+"/raijin-subs"], f.dirs[Module+"/raijin-takeover"] = moduleDir(t, subs), moduleDir(t, takeover)
	f.paths["dnsx"] = "/usr/local/bin/dnsx"
	f.mods = map[string]string{"/usr/local/bin/dnsx": "github.com/projectdiscovery/dnsx v1.3.1"}
	f.modules["github.com/projectdiscovery/dnsx"] = "v1.3.1"
	f.versions = map[string]string{"github.com/projectdiscovery/dnsx": "v1.2.0 v1.2.1 v1.2.2 v1.2.3 v1.2.4-rc.1 v1.3.0 v1.3.1"}
	return f
}

const dnsxBelow130 = `{"dnsx": {"version": "1.2.1", "go": "github.com/projectdiscovery/dnsx/cmd/dnsx", "below": "1.3.0"}}`

func TestBelowDowngrades(t *testing.T) {
	// forced: the highest release under the bound
	f := dnsxFake(t, dnsxBelow130, dnsxBelow130)
	r := Check(context.Background(), f, Options{Verbs: []string{"subs", "takeover"}, Force: true})
	d := byName(r)["dnsx"]
	if d.Action != "downgrade" || d.Target != "1.2.3" || d.Tested || d.Installed != "1.3.1" ||
		d.Command != "GOBIN=/usr/local/bin go install github.com/projectdiscovery/dnsx/cmd/dnsx@v1.2.3" ||
		d.Reason != "raijin-subs, raijin-takeover accept only dnsx below 1.3.0" {
		t.Errorf("dnsx: %+v", d)
	}
	var b strings.Builder
	r.Table(&b)
	for _, want := range []string{"downgrade", "dnsx: 1.3.1 is not accepted; raijin-subs, raijin-takeover accept only dnsx below 1.3.0", "1 of 3 out of date"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("table misses %q:\n%s", want, b.String())
		}
	}
	if !strings.Contains(string(r.JSON("v0.1.0", "")), `"reason":"raijin-subs, raijin-takeover accept only dnsx below 1.3.0"`) {
		t.Errorf("json: %s", r.JSON("v0.1.0", ""))
	}

	// the install lands at the accepted version: an exact target, so a newer one would fail
	f.mods["/usr/local/bin/dnsx"] = "github.com/projectdiscovery/dnsx v1.2.3"
	Apply(context.Background(), f, r)
	if d.Result != "updated" || r.Failed() {
		t.Errorf("dnsx after apply: %+v", d)
	}

	// an accepted version installed: nothing to do, even if it is older than the highest accepted
	f = dnsxFake(t, dnsxBelow130, dnsxBelow130)
	f.mods["/usr/local/bin/dnsx"] = "github.com/projectdiscovery/dnsx v1.2.3"
	if d := byName(Check(context.Background(), f, Options{Verbs: []string{"subs", "takeover"}, Force: true}))["dnsx"]; d.Action != "" {
		t.Errorf("dnsx 1.2.3: %+v", d)
	}
	// by default the tested version, even under the bound
	if d := byName(Check(context.Background(), f, Options{Verbs: []string{"subs", "takeover"}}))["dnsx"]; d.Action != "downgrade" ||
		d.Target != "1.2.1" || !d.Tested || !strings.HasSuffix(d.Command, "dnsx@v1.2.1") {
		t.Errorf("dnsx 1.2.3 by default: %+v", d)
	}

	// no version list: the tested version
	f = dnsxFake(t, dnsxBelow130, dnsxBelow130)
	f.versions = nil
	if d := byName(Check(context.Background(), f, Options{Verbs: []string{"subs", "takeover"}, Force: true}))["dnsx"]; d.Target != "1.2.1" || !d.Tested || d.Action != "downgrade" {
		t.Errorf("dnsx without a version list: %+v", d)
	}
}

func TestBelowStrictestWins(t *testing.T) {
	// raijin-takeover bounds lower, and raijin-subs tests a version above that bound
	f := dnsxFake(t, `{"dnsx": {"version": "1.2.3", "go": "github.com/projectdiscovery/dnsx/cmd/dnsx", "below": "1.3.0"}}`,
		`{"dnsx": {"version": "1.2.1", "go": "github.com/projectdiscovery/dnsx/cmd/dnsx", "below": "1.2.2"}}`)
	d := byName(Check(context.Background(), f, Options{Verbs: []string{"subs", "takeover"}}))["dnsx"]
	if d.Target != "1.2.1" || d.Action != "downgrade" || d.Reason != "raijin-takeover accepts only dnsx below 1.2.2" {
		t.Errorf("dnsx: %+v", d)
	}

	// a tool without a bound tests 1.3.1: the target is still the version under the other's bound, and
	// the table says which tool tested it
	f = dnsxFake(t, `{"dnsx": {"version": "1.3.1", "go": "github.com/projectdiscovery/dnsx/cmd/dnsx"}}`, dnsxBelow130)
	r := Check(context.Background(), f, Options{Verbs: []string{"subs", "takeover"}})
	d = byName(r)["dnsx"]
	if d.Target != "1.2.1" || !d.Tested || d.Action != "downgrade" || d.Reason != "raijin-takeover accepts only dnsx below 1.3.0" ||
		!strings.HasSuffix(d.Command, "dnsx@v1.2.1") || d.TestedBy != "1.2.1 tested by raijin-takeover (raijin-subs 1.3.1)" {
		t.Errorf("dnsx: %+v", d)
	}
	var b strings.Builder
	r.Table(&b)
	if !strings.Contains(b.String(), "dnsx: 1.2.1 tested by raijin-takeover (raijin-subs 1.3.1)") {
		t.Errorf("table:\n%s", b.String())
	}
}

func TestSystemPackages(t *testing.T) {
	f := newFake(t)
	f.engines["nmap"] = "Nmap version 6.40 ( https://nmap.org )"
	if n := byName(Check(context.Background(), f, Options{Verbs: []string{"ports"}}))["nmap"]; n.Action != "manual" || n.SystemOK ||
		!strings.Contains(n.Command, "apt install nmap") {
		t.Errorf("nmap of another major: %+v", n)
	}
	delete(f.paths, "nmap")
	r := Check(context.Background(), f, Options{Verbs: []string{"ports"}})
	if n := byName(r)["nmap"]; n.Action != "manual" || !strings.Contains(n.Command, "apt install nmap") {
		t.Errorf("missing nmap: %+v", n)
	}
	if r.Outdated() != 2 {
		t.Errorf("outdated %d", r.Outdated())
	}
}

func TestReleaseAndPipEngines(t *testing.T) {
	f := newFake(t)
	sec, par := Module+"/raijin-secrets", Module+"/raijin-params"
	f.paths["raijin-secrets"], f.paths["raijin-params"] = "/opt/bin/raijin-secrets", "/opt/bin/raijin-params"
	f.tools["/opt/bin/raijin-secrets"], f.tools["/opt/bin/raijin-params"] = "v0.1.0", "v0.1.0"
	f.modules[sec], f.modules[par] = "v0.1.0", "v0.1.0"
	f.dirs[sec] = moduleDir(t, `{"trufflehog": {"version": "3.99.7", "go": "github.com/trufflesecurity/trufflehog/v3", "release": "trufflesecurity/trufflehog"}}`)
	f.dirs[par] = moduleDir(t, `{"arjun": {"version": "2.2.7", "pip": "arjun"}}`)
	f.paths["trufflehog"], f.engines["trufflehog"] = "/usr/local/bin/trufflehog", "trufflehog 3.99.3"
	f.paths["arjun"], f.engines["arjun"] = "/usr/local/bin/arjun", "2.2.5"
	f.paths["pipx"] = "/usr/bin/pipx"

	r := Check(context.Background(), f, Options{Verbs: []string{"secrets", "params"}})
	it := byName(r)
	if th := it["trufflehog"]; th.Action != "manual" ||
		!strings.HasPrefix(th.Command, "curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin v3.99.7") {
		t.Errorf("trufflehog without --allow-scripts: %+v", th)
	}
	if a := it["arjun"]; a.Action != "update" || a.Command != "pipx install --force arjun==2.2.7" {
		t.Errorf("arjun: %+v", a)
	}

	r = Check(context.Background(), f, Options{Verbs: []string{"secrets", "params"}, AllowScripts: true, Force: true})
	it = byName(r)
	if th := it["trufflehog"]; th.Action != "update" || len(th.argv) != 3 || th.argv[0] != "sh" {
		t.Errorf("trufflehog with --allow-scripts: %+v", th)
	}
	if a := it["arjun"]; a.Command != "pipx upgrade arjun" {
		t.Errorf("arjun: %+v", a)
	}
}

func TestLookupFailureIsAnError(t *testing.T) {
	f := newFake(t)
	delete(f.modules, Module+"/raijin-scan")
	r := Check(context.Background(), f, Options{Verbs: []string{"scan"}})
	if len(r.Errors) != 1 || r.Errors[0].Target != "raijin-scan" || !strings.Contains(r.Errors[0].Hint, "repository not found") || !r.Failed() {
		t.Errorf("errors: %+v", r.Errors)
	}
}

func TestJSONShape(t *testing.T) {
	f := newFake(t)
	r := Check(context.Background(), f, Options{Verbs: []string{"scan", "diff"}, Force: true})
	var out struct {
		Tool     string `json:"tool"`
		Findings []struct {
			Severity, Kind, Name, Latest, Tested, Action string
		} `json:"findings"`
		Groups []struct {
			Kind  string   `json:"kind"`
			Items []string `json:"items"`
		} `json:"groups"`
		Next []string `json:"next"`
	}
	if err := json.Unmarshal(r.JSON("v0.1.0", "call raijin_update with apply=true"), &out); err != nil {
		t.Fatal(err)
	}
	if out.Tool != "raijin-update" || len(out.Findings) != 2 || out.Findings[0].Severity != "low" || out.Findings[0].Name != "raijin-scan" ||
		out.Findings[1].Name != "nuclei" || out.Findings[1].Latest != "3.4.0" {
		t.Errorf("findings: %+v", out.Findings)
	}
	if len(out.Groups) != 1 || out.Groups[0].Kind != "up_to_date" || out.Groups[0].Items[0] != "raijin-diff v0.1.0" {
		t.Errorf("groups: %+v", out.Groups)
	}
	if len(out.Next) != 1 {
		t.Errorf("next: %v", out.Next)
	}
}

func TestTable(t *testing.T) {
	f := newFake(t)
	r := Check(context.Background(), f, Options{Verbs: []string{"ports"}})
	var b strings.Builder
	r.Table(&b)
	for _, want := range []string{"NAME", "LATEST", "naabu", "2.5.0", "update", "nmap", "7.94 (tested)", "ok (system)", "1 of 3 out of date"} {
		if !strings.Contains(b.String(), want) {
			t.Errorf("table misses %q:\n%s", want, b.String())
		}
	}
}

func TestNoticeUsesFreshCache(t *testing.T) {
	cache := filepath.Join(t.TempDir(), "raijin", "update-check.json")
	f := newFake(t)
	now := time.Date(2026, 10, 25, 12, 0, 0, 0, time.UTC)

	// no cache: checks in the background and caches the result
	n := StartNotice(f, Options{Verbs: []string{"scan"}}, cache, now)
	deadline := time.Now().Add(5 * time.Second)
	for n.Sentence() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n.Sentence() != "Updates available for 1 Raijin tools/engines: call raijin_update." { // raijin-scan; nuclei is at the tested version
		t.Fatalf("sentence: %q", n.Sentence())
	}
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(cache); err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	// a fresh cache is used as is: a Sys that would hang is never called
	n = StartNotice(nil, Options{}, cache, now.Add(time.Hour))
	if n.Sentence() == "" {
		t.Error("the cached result must be used")
	}
	os.WriteFile(cache, []byte(`{"format":2,"checked":"2026-10-25T12:00:00Z","outdated":0}`), 0o644)
	if n := StartNotice(nil, Options{}, cache, now.Add(time.Hour)); n.Sentence() != "" {
		t.Errorf("nothing out of date: %q", n.Sentence())
	}

	// a cache of the old format counted against the latest versions: checked again, not used
	os.WriteFile(cache, []byte(`{"checked":"2026-10-25T12:00:00Z","outdated":5}`), 0o644)
	n = StartNotice(newFake(t), Options{Verbs: []string{"diff"}}, cache, now.Add(time.Hour))
	if n.Sentence() != "" {
		t.Errorf("old cache used: %q", n.Sentence())
	}
	for i := 0; i < 100; i++ { // and rewritten in the new format
		if b, _ := os.ReadFile(cache); strings.Contains(string(b), `"format":2`) {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Error("the old cache was not checked again")
}

type noTools struct{}

func (noTools) Tools() []mcp.Tool { return nil }
func (noTools) Call(context.Context, string, json.RawMessage) (mcp.Result, error) {
	return mcp.Result{}, nil
}

func TestProviderForceArgument(t *testing.T) {
	f := newFake(t)
	p := &Provider{Provider: noTools{}, Sys: f, Opt: Options{Verbs: []string{"scan"}}, Version: "v0.1.0"}
	latestOf := func(args string) string {
		res, err := p.Call(context.Background(), ToolName, json.RawMessage(args))
		if err != nil || len(res.Content) == 0 {
			t.Fatalf("%s: %v %+v", args, err, res)
		}
		var out struct {
			Findings []struct{ Name, Latest, Tested string }
			Errors   []Error
		}
		if err := json.Unmarshal([]byte(res.Content[0].Text), &out); err != nil || len(out.Errors) > 0 {
			t.Fatalf("%s: %v %s", args, err, res.Content[0].Text)
		}
		for _, f := range out.Findings {
			if f.Name == "nuclei" {
				return f.Latest
			}
		}
		return ""
	}
	if v := latestOf(`{}`); v != "" {
		t.Errorf("default: nuclei at the tested version needs nothing, got latest %q", v)
	}
	if v := latestOf(`{"pinned": true}`); v != "" {
		t.Errorf("pinned is the default: got latest %q", v)
	}
	if v := latestOf(`{"force": true}`); v != "3.4.0" {
		t.Errorf("force: nuclei latest %q", v)
	}
	res, _ := p.Call(context.Background(), ToolName, json.RawMessage(`{"forced": true}`))
	if !res.IsError || !strings.Contains(res.Content[0].Text, "{apply: bool, force: bool, tools: [verbs]}") {
		t.Errorf("unknown argument: %+v", res)
	}
	var schema struct{ Properties map[string]any }
	b, _ := json.Marshal(p.Tools()[0].InputSchema)
	if json.Unmarshal(b, &schema); schema.Properties["force"] == nil || schema.Properties["pinned"] != nil {
		t.Errorf("schema: %s", b)
	}
}
