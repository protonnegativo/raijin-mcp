package tools

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestHelpLine(t *testing.T) {
	cases := map[string][2]string{
		"  -u value":            {"u", "value"},
		"  -max-bytes int":      {"max-bytes", "int"},
		"  -pretty":             {"pretty", ""},
		"  -x\tshort bool flag": {"x", ""}, // Go puts a one-letter bool's usage after a tab
		"    \tusage text":      {"", ""},
	}
	for line, want := range cases {
		m := helpLine.FindStringSubmatch(line)
		got := [2]string{}
		if m != nil {
			got = [2]string{m[1], m[2]}
		}
		if got != want {
			t.Errorf("%q: got %v, want %v", line, got, want)
		}
	}
}

func TestTableIsConsistent(t *testing.T) {
	seen := map[string]bool{}
	for _, s := range Table {
		if seen[s.Verb] {
			t.Errorf("duplicate verb %s", s.Verb)
		}
		seen[s.Verb] = true
		if s.Desc == "" || len(s.Desc) > 120 {
			t.Errorf("%s: description must be set and terse (%d chars)", s.Verb, len(s.Desc))
		}
		if s.Active && s.Scope != ScopeRequired {
			t.Errorf("%s: active tools must require scope", s.Verb)
		}
		for _, p := range s.Params {
			switch p.Type {
			case "string", "integer", "boolean", "array":
			default:
				t.Errorf("%s.%s: bad type %q", s.Verb, p.Name, p.Type)
			}
		}
	}
}

// With -h unreadable the table is trusted; every tool still gets a valid schema, and active tools
// still demand a scope.
func TestSchemaFromTableAlone(t *testing.T) {
	for _, s := range Table {
		tl := &Tool{Spec: s, Path: "/bin/true", targetMulti: true}
		tl.targetFlag = firstOr(s.Targets)
		tl.params = s.Params
		sc := tl.schema()
		if _, err := json.Marshal(sc); err != nil {
			t.Fatal(err)
		}
		req, _ := sc["required"].([]string)
		hasScope := len(req) > 0 && req[0] == "scope"
		if s.Scope == ScopeRequired && !hasScope {
			t.Errorf("%s: scope not required", s.Verb)
		}
		if s.Active {
			if _, _, err := tl.argv(json.RawMessage(`{"targets":["a.com"]}`)); err == nil || !strings.Contains(err.Error(), "scope") {
				t.Errorf("%s: call without scope must fail, got %v", s.Verb, err)
			}
		}
	}
}

func firstOr(l []string) string {
	if len(l) == 0 {
		return ""
	}
	return l[0]
}

func TestDenied(t *testing.T) {
	for arg, want := range map[string]bool{
		"-o": true, "--output=x": true, "-L": true, "-u": true, "-config": true, "-UP": true,
		"-H": false, "Authorization: x": false, "-rl": false, "-tags": false, "-o-not-a-flag": false,
	} {
		if got := denied(arg) != ""; got != want {
			t.Errorf("denied(%q) = %v, want %v", arg, got, want)
		}
	}
}

func TestStringList(t *testing.T) {
	for in, want := range map[string]string{
		`["a.com"," b.com ",""]`: "a.com|b.com",
		`"a.com, b.com\nc.com"`:  "a.com|b.com|c.com",
		`null`:                   "",
	} {
		got, err := stringList(json.RawMessage(in), "x")
		if err != nil || strings.Join(got, "|") != want {
			t.Errorf("%s: got %v %v, want %s", in, got, err, want)
		}
	}
	if _, err := stringList(json.RawMessage(`[1]`), "x"); err == nil {
		t.Error("numbers are not strings")
	}
}

func TestNonRepeatableTargetsAreJoined(t *testing.T) {
	got := appendList(nil, "d", []string{"a.com", "b.com"}, false)
	if len(got) != 1 || got[0] != "-d=a.com,b.com" {
		t.Errorf("got %v", got)
	}
}

func TestDiffTakesPositionalFiles(t *testing.T) {
	s, _ := Lookup("diff")
	tl := &Tool{Spec: s, Path: "/bin/true"}
	argv, cleanup, err := tl.argv(json.RawMessage(`{"files":["old.json","new.json"]}`))
	defer cleanup()
	if err != nil || strings.Join(argv, " ") != "-format=json old.json new.json" {
		t.Errorf("got %v %v", argv, err)
	}
	if _, _, err := tl.argv(json.RawMessage(`{"files":["-rf"]}`)); err == nil {
		t.Error("a positional that looks like a flag must be refused")
	}
}
