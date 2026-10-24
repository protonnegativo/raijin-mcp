// Package mcp is a small Model Context Protocol server over stdio: JSON-RPC 2.0, one message per
// line. It implements what a tool server needs: initialize, ping, tools/list, tools/call and the
// initialized and cancelled notifications.
package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
)

// Versions are the protocol versions the server speaks, newest first. A client asking for one of
// them gets it back; any other request gets the newest, and the client decides if it can go on.
var Versions = []string{"2025-11-25", "2025-06-18", "2025-03-26", "2024-11-05"}

// JSON-RPC error codes.
const (
	CodeParse          = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603
)

// Tool is one entry of tools/list.
type Tool struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	InputSchema any    `json:"inputSchema"`
}

// Content is one block of a tool result. Only text is used.
type Content struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// Result is the result of tools/call.
type Result struct {
	Content []Content `json:"content"`
	IsError bool      `json:"isError,omitempty"`
}

// TextResult wraps a text in a Result.
func TextResult(text string, isError bool) Result {
	return Result{Content: []Content{{Type: "text", Text: text}}, IsError: isError}
}

// ErrUnknownTool is returned by a Provider for a tool it does not have.
var ErrUnknownTool = errors.New("unknown tool")

// Provider supplies the tools. Call returns ErrUnknownTool for a name it does not know; any other
// problem (bad arguments, a failed run) is a Result with IsError, so the model can read it and retry.
type Provider interface {
	Tools() []Tool
	Call(ctx context.Context, name string, args json.RawMessage) (Result, error)
}

// Server answers MCP requests for a Provider.
type Server struct {
	Name         string
	Version      string
	Instructions string
	Provider     Provider

	mu       sync.Mutex // guards out and inflight
	out      *json.Encoder
	inflight map[string]context.CancelFunc
	wg       sync.WaitGroup
}

type message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *rpcError       `json:"error,omitempty"`
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Serve reads requests from r and writes responses to w until r ends. tools/call runs in the
// background, so a long scan does not block ping or cancellation. When r ends, Serve waits for the
// running calls to answer; cancelling ctx stops them.
func (s *Server) Serve(ctx context.Context, r io.Reader, w io.Writer) error {
	s.out = json.NewEncoder(w)
	s.out.SetEscapeHTML(false)
	s.inflight = map[string]context.CancelFunc{}

	br := bufio.NewReaderSize(r, 1<<16)
	var err error
	for {
		var line []byte
		line, err = br.ReadBytes('\n')
		if line = bytes.TrimSpace(line); len(line) > 0 {
			s.handle(ctx, line)
		}
		if err != nil {
			break
		}
	}
	s.wg.Wait()
	if errors.Is(err, io.EOF) {
		return nil
	}
	return err
}

func (s *Server) handle(ctx context.Context, line []byte) {
	var m message
	if err := json.Unmarshal(line, &m); err != nil {
		code := CodeParse
		if json.Valid(line) {
			code = CodeInvalidRequest // valid JSON, but not a request object (batches included)
		}
		s.reply(nil, nil, &rpcError{code, "invalid message"})
		return
	}
	if m.Method == "" {
		if len(m.ID) == 0 {
			s.reply(nil, nil, &rpcError{CodeInvalidRequest, "missing method"})
		}
		return // a response to us; the server sends no requests, so there is nothing to match
	}
	if len(m.ID) == 0 || string(m.ID) == "null" {
		s.notify(m)
		return
	}

	switch m.Method {
	case "initialize":
		s.reply(m.ID, s.initialize(m.Params), nil)
	case "ping":
		s.reply(m.ID, struct{}{}, nil)
	case "tools/list":
		s.reply(m.ID, map[string]any{"tools": s.Provider.Tools()}, nil)
	case "tools/call":
		var p struct {
			Name      string          `json:"name"`
			Arguments json.RawMessage `json:"arguments"`
		}
		if err := json.Unmarshal(orEmpty(m.Params), &p); err != nil || p.Name == "" {
			s.reply(m.ID, nil, &rpcError{CodeInvalidParams, "params must be {name, arguments}"})
			return
		}
		if a := bytes.TrimSpace(p.Arguments); len(a) > 0 && a[0] != '{' && string(a) != "null" {
			s.reply(m.ID, nil, &rpcError{CodeInvalidParams, "arguments must be an object"})
			return
		}
		cctx, cancel := context.WithCancel(ctx)
		s.mu.Lock()
		s.inflight[string(m.ID)] = cancel
		s.mu.Unlock()
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.forget(m.ID)
			res, err := s.Provider.Call(cctx, p.Name, p.Arguments)
			switch {
			case errors.Is(err, ErrUnknownTool):
				s.reply(m.ID, nil, &rpcError{CodeInvalidParams, "unknown tool: " + p.Name})
			case err != nil:
				s.reply(m.ID, nil, &rpcError{CodeInternal, err.Error()})
			case cctx.Err() != nil && ctx.Err() == nil:
				// cancelled by the client (notifications/cancelled): the spec says not to answer
			default:
				s.reply(m.ID, res, nil)
			}
		}()
	default:
		s.reply(m.ID, nil, &rpcError{CodeMethodNotFound, "method not found: " + m.Method})
	}
}

func (s *Server) initialize(params json.RawMessage) any {
	var p struct {
		ProtocolVersion string `json:"protocolVersion"`
	}
	_ = json.Unmarshal(orEmpty(params), &p)
	return map[string]any{
		"protocolVersion": Negotiate(p.ProtocolVersion),
		"capabilities":    map[string]any{"tools": map[string]bool{"listChanged": false}},
		"serverInfo":      map[string]string{"name": s.Name, "version": s.Version},
		"instructions":    s.Instructions,
	}
}

// Negotiate returns the version the server answers with for the one a client asked for.
func Negotiate(requested string) string {
	for _, v := range Versions {
		if v == requested {
			return v
		}
	}
	return Versions[0]
}

func (s *Server) notify(m message) {
	if m.Method != "notifications/cancelled" {
		return // notifications/initialized and anything unknown need no action
	}
	var p struct {
		RequestID json.RawMessage `json:"requestId"`
	}
	if json.Unmarshal(orEmpty(m.Params), &p) != nil {
		return
	}
	s.mu.Lock()
	cancel := s.inflight[string(p.RequestID)]
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
}

func (s *Server) forget(id json.RawMessage) {
	s.mu.Lock()
	if cancel := s.inflight[string(id)]; cancel != nil {
		cancel()
		delete(s.inflight, string(id))
	}
	s.mu.Unlock()
}

func (s *Server) reply(id json.RawMessage, result any, e *rpcError) {
	if id == nil {
		id = json.RawMessage("null")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_ = s.out.Encode(response{JSONRPC: "2.0", ID: id, Result: result, Error: e})
}

func orEmpty(b json.RawMessage) []byte {
	if len(bytes.TrimSpace(b)) == 0 || string(b) == "null" {
		return []byte("{}")
	}
	return b
}
