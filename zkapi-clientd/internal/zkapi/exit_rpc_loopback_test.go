package zkapi

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// refuseNonHTTPS makes the client's configured transport refuse every URL
// that is not HTTPS, as relay.NewClient's transport does in production.
func refuseNonHTTPS(c *Client) {
	upstream := c.inference.Transport
	c.inference.Transport = withdrawalRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Scheme != "https" {
			return nil, errors.New("upstream transport requires destination HTTPS")
		}
		return upstream.RoundTrip(r)
	})
}

// loopbackHTTPRPC serves target, an HTTPS test RPC, as plain HTTP on
// 127.0.0.1: the owner's own node on this machine. It returns the URL and
// the number of calls it answered.
func loopbackHTTPRPC(t *testing.T, target string) (string, func() int) {
	t.Helper()
	var mu sync.Mutex
	calls := 0
	upstream := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	node := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		calls++
		mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		forwarded, _ := http.NewRequest(http.MethodPost, target, bytes.NewReader(body))
		forwarded.Header.Set("Content-Type", "application/json")
		response, err := upstream.Do(forwarded)
		if err != nil {
			w.WriteHeader(http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		w.WriteHeader(response.StatusCode)
		_, _ = io.Copy(w, response.Body)
	}))
	t.Cleanup(node.Close)
	if !strings.HasPrefix(node.URL, "http://127.0.0.1:") || ValidateExitRPCURL(node.URL) != nil {
		t.Fatalf("not a plain-HTTP exit RPC on this machine: %s", node.URL)
	}
	return node.URL, func() int {
		mu.Lock()
		defer mu.Unlock()
		return calls
	}
}

// Review finding (clientd-fixes 0): an exit RPC at http:// on this machine is
// accepted and documented, but the configured transport is HTTPS-only. Such
// a node is dialed directly, so it can stand in for an indexer that
// withholds a deposit.
func TestLoopbackHTTPExitRPCSavesAWithheldDeposit(t *testing.T) {
	f, _ := minedNativeDeposit(t)
	refuseNonHTTPS(f.h.client)
	exit, calls := loopbackHTTPRPC(t, f.exitRPC)
	f.h.client.config.ExitRPCURL = exit
	f.mu.Lock()
	f.indexerStatus = http.StatusServiceUnavailable
	f.exitFinalized = "0x20"
	f.mu.Unlock()
	status, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || status.Phase != "active" || f.activated != 1 {
		t.Fatalf("the loopback exit RPC did not stand in for the indexer: %+v %v", status, err)
	}
	if binding := f.savedDeposit(t).Binding; binding == nil || !binding.ExitRPC {
		t.Fatalf("the binding does not record the exit RPC's corroboration: %+v", binding)
	}
	f.mu.Lock()
	answered := strings.Join(f.exitCalls, " ")
	f.mu.Unlock()
	if calls() == 0 || !strings.Contains(answered, "eth_getTransactionReceipt") || !strings.Contains(answered, "eth_call") {
		t.Fatalf("the loopback exit RPC was not asked for the receipt and the vault state: %d %s", calls(), answered)
	}
}

// The same node checks a cooperative withdrawal's close, so the withdrawal
// completes instead of waiting on an exit RPC the transport cannot reach.
func TestLoopbackHTTPExitRPCCompletesAWithdrawal(t *testing.T) {
	f := newWithdrawalFixture(t)
	refuseNonHTTPS(f.h.client)
	exit, calls := loopbackHTTPRPC(t, f.exitRPC)
	f.h.client.config.ExitRPCURL = exit
	hash := f.withdraw(t)
	f.mineWithdrawal(t, hash, withdrawalTestDestination, false)
	status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || f.confirmCalls != 1 {
		t.Fatalf("the close the loopback exit RPC shows did not complete: %+v %v", status, err)
	}
	f.mu.Lock()
	answered := strings.Join(f.exitCalls, " ")
	f.mu.Unlock()
	if calls() == 0 || !strings.Contains(answered, "eth_getTransactionReceipt") {
		t.Fatalf("the close was not checked through the loopback exit RPC: %d %s", calls(), answered)
	}
}

// The deployment checks read the same node directly as well.
func TestLoopbackHTTPExitRPCRunsTheDeploymentChecks(t *testing.T) {
	honest := fakeDeploymentRPC(t, "sepolia", nil)
	exit, calls := loopbackHTTPRPC(t, honest.URL)
	client := &Client{config: Config{Network: "sepolia", ExitRPCURL: exit}, inference: honest.Client(), endpoints: &chainEndpoints{RPC: honest.URL}}
	refuseNonHTTPS(client)
	if err := client.CheckDeployment(context.Background()); err != nil || calls() == 0 {
		t.Fatalf("the loopback exit RPC's deployment check failed: %d %v", calls(), err)
	}
}

// The gasless deployment checks read the node directly too, and a bundler on
// this machine, which passes the same URL check, is dialed directly.
func TestLoopbackHTTPExitRPCAndBundlerServeASponsoredWithdrawal(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	refuseNonHTTPS(f.h.client)
	exit, calls := loopbackHTTPRPC(t, f.exitRPC)
	f.h.client.config.ExitRPCURL = exit
	if err := f.h.client.CheckGaslessDeployment(context.Background()); err != nil || calls() == 0 {
		t.Fatalf("the loopback exit RPC's gasless deployment check failed: %d %v", calls(), err)
	}
	if !strings.HasPrefix(g.url, "http://127.0.0.1:") {
		t.Fatalf("the fixture bundler is not plain HTTP on this machine: %s", g.url)
	}
	if hash := f.sponsoredClose(t); len(g.sends) != 1 || g.sends[0] != hash {
		t.Fatalf("the operation did not reach the loopback bundler: %v", g.sends)
	}
}

// Only plain HTTP to a loopback name or IP leaves the configured transport,
// and its direct connection reaches nothing but a loopback IP.
func TestOnlyLoopbackHTTPBypassesTheConfiguredTransport(t *testing.T) {
	c := &Client{inference: &http.Client{}}
	for _, url := range []string{"http://127.0.0.1:8545", "http://127.1.2.3:8545/rpc", "http://localhost:8545", "http://[::1]:8545"} {
		if c.rpcHTTP(url) != loopbackRPCClient {
			t.Errorf("%s did not use the direct loopback client", url)
		}
	}
	for _, url := range []string{"https://127.0.0.1:8545", "https://localhost:8545", "https://rpc.example", "http://rpc.example", "http://10.0.0.1:8545", "http://localhost.rpc.example", "http://user@127.0.0.1:8545", "ws://127.0.0.1:8545", "127.0.0.1:8545"} {
		if c.rpcHTTP(url) != c.inference {
			t.Errorf("%s bypassed the configured transport", url)
		}
	}
	for _, address := range []string{"127.0.0.1:8545", "[::1]:8545"} {
		if err := dialLoopbackOnly("tcp", address, nil); err != nil {
			t.Errorf("refused loopback %s: %v", address, err)
		}
	}
	for _, address := range []string{"192.0.2.1:80", "[2001:db8::1]:80", "localhost:8545", "bad"} {
		if dialLoopbackOnly("tcp", address, nil) == nil {
			t.Errorf("a direct connection to %s was allowed", address)
		}
	}
	if transport := loopbackRPCClient.Transport.(*http.Transport); transport.Proxy != nil || loopbackRPCClient.Jar != nil || loopbackRPCClient.CheckRedirect == nil || loopbackRPCClient.Timeout <= 0 {
		t.Fatal("the direct loopback client may use a proxy, a cookie jar, redirects, or no timeout")
	}
}
