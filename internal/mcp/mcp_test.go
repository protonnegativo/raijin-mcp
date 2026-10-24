package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"
)

type stub struct{}

func (stub) Tools() []Tool {
	return []Tool{{Name: "echo", Description: "echo", InputSchema: map[string]string{"type": "object"}}}
}

func (stub) Call(_ context.Context, name string, args json.RawMessage) (Result, error) {
	if name != "echo" {
		return Result{}, ErrUnknownTool
	}
	return TextResult(string(args), false), nil
}

func serve(t *testing.T, lines ...string) []map[string]any {
	t.Helper()
	var out bytes.Buffer
	s := &Server{Name: "t", Version: "1", Provider: stub{}}
	if err := s.Serve(context.Background(), strings.NewReader(strings.Join(lines, "\n")), &out); err != nil {
		t.Fatal(err)
	}
	var res []map[string]any
	for _, l := range strings.Split(strings.TrimSpace(out.String()), "\n") {
		var m map[string]any
		if err := json.Unmarshal([]byte(l), &m); err != nil {
			t.Fatalf("not JSON: %q", l)
		}
		res = append(res, m)
	}
	return res
}

func TestNegotiate(t *testing.T) {
	for _, v := range Versions {
		if Negotiate(v) != v {
			t.Errorf("supported version %s not echoed", v)
		}
	}
	if Negotiate("") != Versions[0] || Negotiate("2030-01-01") != Versions[0] {
		t.Error("unknown versions get the newest")
	}
}

func TestCallKeepsTextUnescaped(t *testing.T) {
	res := serve(t, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"e":"a -> <b> & c"}}}`)
	b, _ := json.Marshal(res[0]["result"])
	if !strings.Contains(string(b), `a ->`) { // re-marshalled here; check the raw stream instead
	}
	var out bytes.Buffer
	s := &Server{Provider: stub{}}
	_ = s.Serve(context.Background(), strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"e":"<b>&"}}}`), &out)
	if !strings.Contains(out.String(), `<b>&`) {
		t.Errorf("HTML escaping wastes tokens: %s", out.String())
	}
}

func TestResponsesFromClientAreIgnored(t *testing.T) {
	res := serve(t, `{"jsonrpc":"2.0","id":9,"result":{}}`, `{"jsonrpc":"2.0","id":1,"method":"ping"}`)
	if len(res) != 1 || res[0]["id"].(float64) != 1 {
		t.Errorf("got %v", res)
	}
}

func TestStringAndNumberIDsAreEchoed(t *testing.T) {
	res := serve(t, `{"jsonrpc":"2.0","id":"abc","method":"ping"}`, `{"jsonrpc":"2.0","id":0,"method":"tools/list"}`)
	if res[0]["id"] != "abc" || res[1]["id"].(float64) != 0 {
		t.Errorf("ids: %v %v", res[0]["id"], res[1]["id"])
	}
}
