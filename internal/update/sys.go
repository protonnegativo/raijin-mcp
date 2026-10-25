package update

import (
	"bufio"
	"bytes"
	"context"
	"debug/buildinfo"
	"os"
	"os/exec"
	"path/filepath"
	"runtime/debug"
	"strings"
	"time"

	"github.com/protonnegativo/raijin-mcp/internal/tools"
)

// System is the real Sys: it finds binaries like the server does and runs commands in a temporary
// directory, so go never sees a go.mod.
type System struct {
	BinDir string // looked up before PATH
}

// Locate implements Sys.
func (s System) Locate(name string) string { return tools.Locate(name, s.BinDir) }

// BuildInfo implements Sys.
func (System) BuildInfo(path string) (*debug.BuildInfo, error) { return buildinfo.ReadFile(path) }

// versionArgs are the version commands the Raijin tools run; the ProjectDiscovery engines (httpx,
// subfinder, dnsx, naabu, katana, tlsx, nuclei) take the default, -version -duc.
var versionArgs = map[string][]string{
	"ffuf":       {"-V"},
	"dalfox":     {"version"},
	"trufflehog": {"--version"},
	"nmap":       {"--version"},
}

// arjun has no version flag: the Python that runs it (the interpreter on its #! line, the venv's own
// for pipx) reports the installed package's version.
const arjunScript = "import importlib.metadata as m; print(m.version('arjun'))"

// EngineOutput implements Sys. It gives up after 3 seconds and returns what was printed by then.
func (System) EngineOutput(ctx context.Context, name, path string) string {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	argv := append([]string{path}, versionArgs[name]...)
	switch {
	case name == "arjun":
		argv = append(interpreter(path), "-c", arjunScript)
	case len(argv) == 1:
		argv = append(argv, "-version", "-duc")
	}
	var out bytes.Buffer
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	cmd.Stdout, cmd.Stderr = &out, &out
	cmd.WaitDelay = time.Second
	_ = cmd.Run() // the output is enough, whatever the exit status
	return out.String()
}

// interpreter reads the #! line of a Python script; python3 when there is none.
func interpreter(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{"python3"}
	}
	defer f.Close()
	line, _ := bufio.NewReader(f).ReadString('\n')
	fields := strings.Fields(strings.TrimPrefix(line, "#!"))
	if !strings.HasPrefix(line, "#!") || len(fields) == 0 || !strings.Contains(line, "python") {
		return []string{"python3"}
	}
	return fields
}

// Run implements Sys.
func (System) Run(ctx context.Context, env []string, name string, args ...string) ([]byte, error) {
	dir, err := os.MkdirTemp("", "raijin-update-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	cmd.WaitDelay = 5 * time.Second
	return cmd.CombinedOutput()
}

// Writable implements Sys.
func (System) Writable(dir string) bool {
	f, err := os.CreateTemp(dir, ".raijin-w-")
	if err != nil {
		return false
	}
	f.Close()
	os.Remove(f.Name())
	return true
}

// DefaultBin implements Sys: GOBIN, else the first GOPATH's bin.
func (System) DefaultBin() string {
	out, err := exec.Command("go", "env", "GOBIN", "GOPATH").Output()
	if err != nil {
		return filepath.Join(os.Getenv("HOME"), "go", "bin")
	}
	gobin, gopath, _ := strings.Cut(string(out), "\n")
	if gobin = strings.TrimSpace(gobin); gobin != "" {
		return gobin
	}
	return filepath.Join(filepath.SplitList(strings.TrimSpace(gopath) + string(os.PathListSeparator))[0], "bin")
}
