package zkapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/crypto"
)

// The fixture code whose keccak256 the test profiles pin.
var fixtureCode = map[string]string{"vault": "0x600160015b", "adapter": "0x600260025b", "poseidon": "0x600360035b"}

// deploymentCheckAnswer answers the RPC reads of the deployment checks for
// the test profile of network, as an honest node of that deployment does.
// handled is false for any other request.
func deploymentCheckAnswer(network, method string, params []json.RawMessage) (result any, handled bool) {
	d, _, err := pinnedDeployment(network)
	if err != nil || !d.deployed() {
		return nil, false
	}
	switch method {
	case "eth_getCode":
		var address string
		if len(params) == 0 || json.Unmarshal(params[0], &address) != nil {
			return nil, false
		}
		for name, contract := range map[string]string{"vault": d.Contract, "adapter": d.ProofAdapter, "poseidon": d.PoseidonLibrary} {
			if strings.EqualFold(address, contract) {
				return fixtureCode[name], true
			}
		}
	case "eth_call":
		var call struct {
			From string `json:"from"`
			To   string `json:"to"`
			Data string `json:"data"`
		}
		if len(params) == 0 || json.Unmarshal(params[0], &call) != nil || call.From != "" || len(call.Data) != 10 {
			return nil, false
		}
		word := func(value string) string { return "0x" + addressABIWord(strings.ToLower(value)) }
		number := func(value uint64) string { return "0x" + uintWord(value) }
		vault := map[string]string{
			selectorProofAdapter:            word(d.ProofAdapter),
			selectorStateSigningKeyX:        word(d.StateSigningKey.X),
			selectorStateSigningKeyY:        word(d.StateSigningKey.Y),
			selectorClearanceSigningKeyX:    word(d.ClearanceSigning.X),
			selectorClearanceSigningKeyY:    word(d.ClearanceSigning.Y),
			selectorChallengePeriod:         number(d.ChallengePeriod),
			selectorNoteTTL:                 number(d.NoteTTL),
			selectorMaxPauseDuration:        number(d.MaxPauseDuration),
			selectorConcessionEscapeVersion: number(1),
			selectorRootHistoryWindow:       number(86400),
		}
		adapter := map[string]string{
			selectorCircuitIDHash:    crypto.Keccak256Hash([]byte(d.Proof.Circuit)).Hex(),
			selectorRequestVKHash:    word(d.Proof.RequestVKKeccak256),
			selectorWithdrawalVKHash: word(d.Proof.WithdrawalVKKeccak256),
		}
		if strings.EqualFold(call.To, d.Contract) {
			value, ok := vault[call.Data]
			return value, ok
		}
		if strings.EqualFold(call.To, d.ProofAdapter) {
			value, ok := adapter[call.Data]
			return value, ok
		}
	}
	return nil, false
}

// fakeDeploymentRPC serves the deployment checks, with tamper applied to the
// answers (method, data or address → replacement).
func fakeDeploymentRPC(t *testing.T, network string, tamper map[string]any) *httptest.Server {
	t.Helper()
	chain, _ := ChainID(network)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var request struct {
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		_ = json.NewDecoder(r.Body).Decode(&request)
		var result any
		if request.Method == "eth_chainId" {
			result = fmt.Sprintf("0x%x", chain)
		} else if answer, ok := deploymentCheckAnswer(network, request.Method, request.Params); ok {
			result = answer
			var call struct {
				To   string `json:"to"`
				Data string `json:"data"`
			}
			var address string
			if len(request.Params) > 0 {
				_ = json.Unmarshal(request.Params[0], &call)
				_ = json.Unmarshal(request.Params[0], &address)
			}
			for key, replacement := range tamper {
				if strings.EqualFold(key, call.Data) || strings.EqualFold(key, address) {
					result = replacement
				}
			}
		} else {
			t.Errorf("unexpected RPC %s", request.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": 1, "result": result})
	}))
	t.Cleanup(server.Close)
	return server
}

// Design §6.7: the client trusts the deployment only when the runtime code
// of the vault, adapter and Poseidon library, the vault's adapter and every
// pinned getter match, through the pinned RPC and the owner's exit RPC.
func TestDeploymentChecksUseThePinnedAndTheExitRPC(t *testing.T) {
	d, _, err := deployedDeployment("sepolia")
	if err != nil {
		t.Fatal(err)
	}
	honest := fakeDeploymentRPC(t, "sepolia", nil)
	client := &Client{config: Config{Network: "sepolia"}, inference: honest.Client(), endpoints: &chainEndpoints{RPC: honest.URL}}
	if err := client.CheckDeployment(context.Background()); err != nil {
		t.Fatalf("an honest deployment failed: %v", err)
	}
	for name, tamper := range map[string]map[string]any{
		"vault code":               {d.Contract: "0x6001"},
		"adapter code":             {d.ProofAdapter: "0x6002"},
		"poseidon code":            {d.PoseidonLibrary: "0x"},
		"another adapter":          {selectorProofAdapter: "0x" + addressABIWord("0x1111111111111111111111111111111111111111")},
		"another state key":        {selectorStateSigningKeyX: "0x" + uintWord(7)},
		"another clearance key":    {selectorClearanceSigningKeyY: "0x" + uintWord(7)},
		"another challenge period": {selectorChallengePeriod: "0x" + uintWord(60)},
		"another note ttl":         {selectorNoteTTL: "0x" + uintWord(60)},
		"another pause bound":      {selectorMaxPauseDuration: "0x" + uintWord(60)},
		"no concession exit":       {selectorConcessionEscapeVersion: "0x" + uintWord(0)},
		"another root window":      {selectorRootHistoryWindow: "0x" + uintWord(3600)},
		"another circuit":          {selectorCircuitIDHash: crypto.Keccak256Hash([]byte("zkapi-v2-note-bound-v1")).Hex()},
		"another request key":      {selectorRequestVKHash: "0x" + uintWord(1)},
		"another withdrawal key":   {selectorWithdrawalVKHash: "0x" + uintWord(1)},
	} {
		t.Run(name, func(t *testing.T) {
			lying := fakeDeploymentRPC(t, "sepolia", tamper)
			// Through the pinned RPC.
			client := &Client{config: Config{Network: "sepolia"}, inference: lying.Client(), endpoints: &chainEndpoints{RPC: lying.URL}}
			if err := client.CheckDeployment(context.Background()); !errors.Is(err, errDeploymentMismatch) {
				t.Fatalf("accepted: %v", err)
			}
			// Through the exit RPC while the pinned one is honest. Both
			// servers share one TLS test root, so one client trusts both.
			pool := honest.Client()
			pool.Transport.(*http.Transport).TLSClientConfig.RootCAs.AddCert(lying.Certificate())
			client = &Client{config: Config{Network: "sepolia", ExitRPCURL: lying.URL}, inference: pool, endpoints: &chainEndpoints{RPC: honest.URL}}
			err := client.CheckDeployment(context.Background())
			if !errors.Is(err, errDeploymentMismatch) || !strings.Contains(err.Error(), lying.URL) {
				t.Fatalf("the exit RPC's answer was not checked: %v", err)
			}
		})
	}
	for _, url := range []string{"http://rpc.example", "ftp://127.0.0.1", "https://user:pass@rpc.example", "https://rpc.example/?key=1"} {
		if ValidateExitRPCURL(url) == nil {
			t.Fatalf("accepted exit RPC %s", url)
		}
	}
	for _, url := range []string{"https://rpc.example/v1/key", "http://127.0.0.1:8545", "http://localhost:8545", "http://[::1]:8545"} {
		if err := ValidateExitRPCURL(url); err != nil {
			t.Fatalf("refused exit RPC %s: %v", url, err)
		}
	}
}

// Before every deposit (its quote included) the deployment is checked; a
// vault whose code is not the pinned one is never funded, and nothing is
// signed.
func TestDepositsAreRefusedOnADeploymentMismatch(t *testing.T) {
	f := newAddressFixture(t, true)
	f.codeTamper = true
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 1234567); !errors.Is(err, errDeploymentMismatch) {
		t.Fatalf("a deposit into a mismatched deployment was quoted: %v", err)
	}
	if len(f.submitted) != 0 || len(f.accepted) != 0 {
		t.Fatal("something was signed")
	}
	f.codeTamper = false
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 1234567); err != nil {
		t.Fatalf("the matching deployment was refused: %v", err)
	}
}
