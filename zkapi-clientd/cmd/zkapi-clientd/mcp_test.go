package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/delegatemcp"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/server"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const mainArgsEnv = "ZKAPI_CLIENTD_TEST_MAIN_ARGS"

// mcpProcess runs `zkapi-clientd --config-dir DIR mcp` as a real child
// process speaking newline-delimited JSON-RPC over its stdin and stdout.
type mcpProcess struct {
	t      *testing.T
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	lines  *bufio.Scanner
	stderr *bytes.Buffer
}

func startMCP(t *testing.T, dir string) *mcpProcess {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), mainArgsEnv+"="+strings.Join([]string{"--config-dir", dir, "mcp"}, "\x1f"),
		// An environment proxy must never carry local daemon traffic.
		"HTTP_PROXY=http://192.0.2.1:3128", "http_proxy=http://192.0.2.1:3128", "ALL_PROXY=socks5://192.0.2.1:1080", "NO_PROXY=", "no_proxy=")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	p := &mcpProcess{t: t, cmd: cmd, stdin: stdin, lines: bufio.NewScanner(stdout), stderr: &bytes.Buffer{}}
	p.lines.Buffer(make([]byte, 1<<20), 4<<20)
	cmd.Stderr = p.stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })
	return p
}

func (p *mcpProcess) send(frame string) {
	p.t.Helper()
	if _, err := io.WriteString(p.stdin, frame+"\n"); err != nil {
		p.t.Fatal(err)
	}
}

// receive reads the next stdout line, which must be a JSON-RPC frame.
func (p *mcpProcess) receive() map[string]any {
	p.t.Helper()
	if !p.lines.Scan() {
		p.t.Fatalf("no MCP frame; stderr: %s", p.stderr.String())
	}
	var frame map[string]any
	if err := json.Unmarshal(p.lines.Bytes(), &frame); err != nil || frame["jsonrpc"] != "2.0" {
		p.t.Fatalf("stdout carried non-MCP output: %q", p.lines.Text())
	}
	return frame
}

func (p *mcpProcess) initialize(version string) {
	p.t.Helper()
	p.send(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"` + version + `","capabilities":{},"clientInfo":{"name":"stdio-test","version":"0"}}}`)
	result, _ := p.receive()["result"].(map[string]any)
	if result == nil || result["protocolVersion"] != version {
		p.t.Fatalf("initialize result = %v", result)
	}
	p.send(`{"jsonrpc":"2.0","method":"notifications/initialized"}`)
}

func (p *mcpProcess) call(id int, arguments string) (string, bool) {
	p.t.Helper()
	p.send(`{"jsonrpc":"2.0","id":` + string(rune('0'+id)) + `,"method":"tools/call","params":{"name":"zkapi_delegate","arguments":` + arguments + `}}`)
	frame := p.receive()
	var result struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	raw, _ := json.Marshal(frame["result"])
	if json.Unmarshal(raw, &result) != nil || len(result.Content) == 0 {
		p.t.Fatalf("tools/call = %v", frame)
	}
	return result.Content[0].Text, result.IsError
}

// finish closes stdin; the server must then exit cleanly with nothing
// further on stdout.
func (p *mcpProcess) finish() {
	p.t.Helper()
	p.stdin.Close()
	if p.lines.Scan() {
		p.t.Fatalf("unexpected output after EOF: %q", p.lines.Text())
	}
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			p.t.Fatalf("mcp exited with %v; stderr: %s", err, p.stderr.String())
		}
	case <-time.After(10 * time.Second):
		p.t.Fatal("mcp did not exit after stdin closed")
	}
}

func mcpProfile(t *testing.T, listen string, requireKey bool) (string, config.Config) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "profile")
	c, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	c.Listen, c.RequireAPIKey, c.DefaultModel = listen, requireKey, "saved/default"
	if err := config.Init(dir, c); err != nil {
		t.Fatal(err)
	}
	return dir, c
}

func snapshotDir(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		data := ""
		if !info.IsDir() {
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			data = string(raw)
		}
		files[path] = info.Mode().String() + ":" + data
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func TestMCPOverRealStdioFailsClosedWithoutDaemonAndChangesNothing(t *testing.T) {
	// Nothing listens on the discard port; no listener is needed here.
	dir, _ := mcpProfile(t, "127.0.0.1:9", false)
	before := snapshotDir(t, dir)
	p := startMCP(t, dir)
	p.initialize("2025-06-18")
	p.send(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	tools, _ := p.receive()["result"].(map[string]any)["tools"].([]any)
	if len(tools) != 2 {
		t.Fatalf("tools = %v", tools)
	}
	text, isError := p.call(3, `{"task":"Find the bug."}`)
	if !isError || !strings.Contains(text, "at http://127.0.0.1:9 could not be reached") || !strings.Contains(text, "may have been processed and charged") || !strings.Contains(text, "never starts, funds or configures") {
		t.Fatalf("tool result = %q", text)
	}
	p.finish()
	if p.stderr.Len() != 0 {
		t.Fatalf("unexpected diagnostics: %s", p.stderr.String())
	}
	after := snapshotDir(t, dir)
	if len(before) != len(after) {
		t.Fatalf("mcp created or removed profile files: %v -> %v", before, after)
	}
	for path, value := range before {
		if after[path] != value {
			t.Fatalf("mcp changed %s", path)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "management-token")); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("mcp created or read the management credential")
	}
}

// delegatingBackend is a fake protocol engine behind the real local API.
type delegatingBackend struct {
	mu     sync.Mutex
	bodies []string
}

func (b *delegatingBackend) Models(context.Context) (json.RawMessage, error) {
	return json.RawMessage(`{"object":"list","data":[{"id":"saved/default","oa_request_limit_micro_usd":1000000}]}`), nil
}

func (b *delegatingBackend) Complete(context.Context, json.RawMessage) (*http.Response, error) {
	return nil, errors.New("chat path must not be used")
}

func (b *delegatingBackend) Delegate(_ context.Context, body json.RawMessage) (*http.Response, error) {
	b.mu.Lock()
	b.bodies = append(b.bodies, string(body))
	b.mu.Unlock()
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(`{"id":"gen-PRIVATE","choices":[{"message":{"content":"Check the loop bound.","reasoning":"PRIVATE"},"finish_reason":"stop"}],"usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}`))}, nil
}

func TestMCPOverRealStdioDelegatesThroughTheLocalAPI(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if errors.Is(err, syscall.EPERM) {
		t.Skip("local listeners are not permitted in this environment")
	}
	if err != nil {
		t.Fatal(err)
	}
	dir, c := mcpProfile(t, listener.Addr().String(), true)
	backend := &delegatingBackend{}
	api, err := server.New(backend, c.APIKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	api.RequireAPIKey, api.DefaultModel, api.WebSearch = true, c.DefaultModel, true
	daemon := httptest.NewUnstartedServer(api)
	daemon.Listener.Close()
	daemon.Listener = listener
	daemon.Start()
	defer daemon.Close()

	p := startMCP(t, dir)
	p.initialize("2025-11-25")
	text, isError := p.call(2, `{"task":"Find the bug.","context":"for i := 0; i <= n; i++ {}"}`)
	if isError || text != "Check the loop bound." {
		t.Fatalf("tool result = %q error=%t", text, isError)
	}
	// Identical repeated calls are separate paid requests; nothing is cached
	// or merged by the adapter.
	if text, isError := p.call(3, `{"task":"Find the bug.","context":"for i := 0; i <= n; i++ {}"}`); isError || text != "Check the loop bound." {
		t.Fatalf("second result = %q", text)
	}
	p.finish()
	backend.mu.Lock()
	defer backend.mu.Unlock()
	want := `{"max_tokens":4096,"messages":[{"content":"Find the bug.\n\nContext:\nfor i := 0; i \u003c= n; i++ {}","role":"user"}],"model":"saved/default","stream":false}`
	if len(backend.bodies) != 2 || backend.bodies[0] != want || backend.bodies[1] != want {
		t.Fatalf("backend bodies = %v", backend.bodies)
	}
}

func TestDaemonDelegationWithoutTorIsAConfigurationErrorBeforeAnyWalletRequest(t *testing.T) {
	for _, relayURL := range []string{"", "socks5://127.0.0.1:9050", "wss://relay.example/"} {
		t.Run(relayURL, func(t *testing.T) {
			c, err := config.Default()
			if err != nil {
				t.Fatal(err)
			}
			c.RelayURL = relayURL
			var companion int
			transport := inferenceTestTransport(func(r *http.Request) (*http.Response, error) {
				companion++
				return nil, errors.New("unexpected network use")
			})
			zc := zkConfig(c, &http.Client{Transport: transport})
			zc.ClientURL = "http://127.0.0.1:9"
			wallet, err := zkapi.New(zc)
			if err != nil {
				t.Fatal(err)
			}
			api, err := server.New(zkInference{wallet}, c.APIKey, 1)
			if err != nil {
				t.Fatal(err)
			}
			api.DefaultModel = "saved/default"
			r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787"+server.DelegatePath, strings.NewReader(`{"task":"t"}`))
			r.RemoteAddr = "127.0.0.1:1"
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			api.ServeHTTP(w, r)
			if w.Code != http.StatusPreconditionFailed || !strings.Contains(w.Body.String(), "delegation_requires_tor") ||
				!strings.Contains(w.Body.String(), "IsolateSOCKSAuth") || !strings.Contains(w.Body.String(), "nothing was spent") {
				t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
			}
			if companion != 0 {
				t.Fatal("network used before refusing delegation")
			}
		})
	}
}

// walletErrorDelegator fails every delegation with a wallet error, mapped
// through the daemon's real strict-delegation error boundary.
type walletErrorDelegator struct{ delegatingBackend }

func (*walletErrorDelegator) Delegate(ctx context.Context, _ json.RawMessage) (*http.Response, error) {
	return nil, delegateBackendError(ctx, &zkapi.ReceiptJournalMissingError{Status: 409, Nullifier: receiptNullifier})
}

const receiptNullifier = "0x1d3adbeefc0ffee5eed5a1ad0b5e55ed"

// recorderTransport serves adapter requests from the real local API in
// process, so the full daemon-to-MCP error path runs without a listener.
type recorderTransport struct{ api http.Handler }

func (t recorderTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r.RemoteAddr = "127.0.0.1:50000"
	w := httptest.NewRecorder()
	t.api.ServeHTTP(w, r)
	return w.Result(), nil
}

func TestStrictDelegationWithholdsWalletIdentifiersFromAgents(t *testing.T) {
	// Ordinary chat keeps naming the nullifier for the owner's recovery.
	chat := inferenceError(context.Background(), &zkapi.ReceiptJournalMissingError{Status: 409, Nullifier: receiptNullifier})
	if !strings.Contains(chat.Error(), receiptNullifier) {
		t.Fatal("chat recovery message lost the nullifier")
	}
	c, err := config.Default()
	if err != nil {
		t.Fatal(err)
	}
	api, err := server.New(&walletErrorDelegator{}, c.APIKey, 1)
	if err != nil {
		t.Fatal(err)
	}
	api.DefaultModel = "saved/default"
	r := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8787"+server.DelegatePath, strings.NewReader(`{"task":"t"}`))
	r.RemoteAddr = "127.0.0.1:1"
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	api.ServeHTTP(w, r)
	body := w.Body.String()
	if w.Code != 409 || !strings.Contains(body, "receipt_journal_missing") || strings.Contains(body, "1d3adbeef") {
		t.Fatalf("daemon response = %d %s", w.Code, body)
	}

	mcpServer, err := delegatemcp.NewServer(delegatemcp.Options{Listen: "127.0.0.1:8787", APIKey: c.APIKey, Transport: recorderTransport{api}})
	if err != nil {
		t.Fatal(err)
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = mcpServer.Run(ctx, serverTransport) }()
	session, err := mcp.NewClient(&mcp.Implementation{Name: "agent", Version: "1"}, nil).Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	result, err := session.CallTool(ctx, &mcp.CallToolParams{Name: delegatemcp.DelegateTool, Arguments: map[string]any{"task": "t"}})
	if err != nil || !result.IsError {
		t.Fatalf("err=%v result=%+v", err, result)
	}
	raw, _ := json.Marshal(result)
	if strings.Contains(string(raw), "1d3adbeef") || !strings.Contains(string(raw), "receipt_journal_missing") {
		t.Fatalf("MCP result = %s", raw)
	}
}
