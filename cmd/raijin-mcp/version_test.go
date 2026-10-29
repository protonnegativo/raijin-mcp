package main

import (
	"bytes"
	"regexp"
	"runtime/debug"
	"strings"
	"testing"
)

func TestVersionFrom(t *testing.T) {
	cases := []struct {
		info debug.BuildInfo
		want string
	}{
		{debug.BuildInfo{Main: debug.Module{Version: "v0.1.3"}}, "v0.1.3"},
		{debug.BuildInfo{Main: debug.Module{Version: "(devel)"}}, "dev"},
		{debug.BuildInfo{Main: debug.Module{Version: "v0.0.0-20261025132954-0123456789ab+dirty"}, Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "0123456789abcdef0123"}, {Key: "vcs.modified", Value: "true"}}}, "dev-0123456789ab+dirty"},
		{debug.BuildInfo{Settings: []debug.BuildSetting{
			{Key: "vcs.revision", Value: "abc"}, {Key: "vcs.modified", Value: "false"}}}, "dev-abc"},
	}
	for _, c := range cases {
		if got := versionFrom(&c.info); got != c.want {
			t.Errorf("versionFrom(%+v) = %q, want %q", c.info, got, c.want)
		}
	}
}

func TestVersionLine(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"--version"}, strings.NewReader(""), &out, &bytes.Buffer{}); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !regexp.MustCompile(`^raijin-mcp (v\d+\.\d+\.\d+\S*|dev\S*)\n$`).MatchString(out.String()) {
		t.Errorf("version line: %q", out.String())
	}
}

func TestReleaseVersionWins(t *testing.T) {
	releaseVersion = "v9.9.9"
	defer func() { releaseVersion = "" }()
	if got := version(); got != "v9.9.9" {
		t.Errorf("version() = %q, want the linked release version", got)
	}
}
