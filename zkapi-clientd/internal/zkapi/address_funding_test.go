package zkapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/core/types"
)

const addressTestVault = "0xc0c0000000000000000000000000000000000001"
const addressTestToken = "0x2222222222222222222222222222222222222222"

// addressTestBlock is the hash of the fixture's canonical block 0x20, whose
// header the RPC serves by hash with the time this test binary started.
var addressTestHeader = fixtureHeader(0x20, time.Now().Unix())
var addressTestBlock = addressTestHeader.Hash().Hex()

type addressFixture struct {
	native                                                         bool
	estimateValue                                                  string
	overrideReads                                                  int
	mu                                                             sync.Mutex
	h                                                              *FundingHandler
	chain, decimals, gas, gasPrice, balance, eth, allowance, nonce string
	finalized, canonical                                           string
	accepted                                                       map[string]*types.Transaction
	receipts                                                       map[string]map[string]any
	submitted                                                      []string
	ambiguous                                                      bool
	active                                                         bool
	prepared, activated, paths                                     int
	rpcCalls                                                       []string
	// Independent corroboration sources. The RPC answers vault notes() from
	// vaultNotes; the separate indexer server serves leaves. mine registers
	// a deposit in both, and tests make them disagree deliberately.
	vaultNotes                 map[uint32]fixtureNote
	vaultReadsAt               []string
	leaves                     []*big.Int
	indexer                    *httptest.Server
	indexerBlock               uint64
	indexerHash                string
	indexerStatus              int // >0: HTTP error, <0: inconsistent snapshot
	indexerWithoutBlock        bool
	snapshotReads, rootReads   int
	cachedRoot                 *big.Int
	cachedPath                 []*big.Int
	cachedVersion, leafVersion int
	mined                      map[string]uint32
	minedExpiry                map[uint32]uint64
	// minedRoot is NoteDeposited.newRoot of each mined deposit, by hash.
	minedRoot map[string]*big.Int
	// Block headers served by eth_getBlockByHash, by lowercase hash.
	headers map[string]*types.Header
	// Companion wallet state for activation and rebind.
	walletNote      map[string]any
	walletPending   bool
	withdrawalPhase map[string]any
	confirmBodies   []map[string]any
	resetCalls      int
	// Withdrawal release: a non-empty releaseRefusal answers 409 with that
	// code; companionSteps orders release and reset calls.
	releaseBodies  []map[string]any
	releaseRefusal string
	companionSteps []string
	// escapeCredits answers the vault's escapePayoutCredits(address), by
	// lowercase destination address; a missing destination reads zero.
	escapeCredits map[string]string
	creditReads   int
	// codeTamper makes the RPC serve other runtime code at the vault.
	codeTamper bool
	// pinnedDown makes the pinned RPC refuse every call; exitRPC serves the
	// same chain as the owner's exit RPC (--exit-rpc-url), and exitCalls
	// lists the methods it answered.
	pinnedDown bool
	exitRPC    string
	exitCalls  []string
	// refuseSimulation makes the RPCs refuse the eth_call simulation and the
	// gas estimate of a signed vault call.
	refuseSimulation bool
	// pinnedNonce, when set, is the nonce the pinned RPC alone answers (a
	// lying pinned RPC). pendingNonce and finalizedNonce, when set, answer
	// eth_getTransactionCount at the "pending" and "finalized" tags (a
	// mempool transaction, a nonce taken by another transaction).
	pinnedNonce, pendingNonce, finalizedNonce string
	// latestTime, when set, is the timestamp of every block served.
	latestTime int64
	// hideReceipts makes this many receipt reads answer null first.
	hideReceipts int
	// logs are the vault logs eth_getLogs serves, filtered by topics.
	logs []map[string]any
	// gasless, when enabled (enableGasless), serves the gasless contracts
	// and the bundler of a sponsored withdrawal.
	gasless *gaslessFixture
}

// addressTestFirstNote is the first fixture deposit's note: the indexer
// starts with this many unrelated leaves.
const addressTestFirstNote = 12

func (f *addressFixture) setLeaf(id uint32, leaf *big.Int) {
	for uint32(len(f.leaves)) <= id {
		f.leaves = append(f.leaves, new(big.Int))
	}
	f.leaves[id] = leaf
	f.leafVersion++
}

func (f *addressFixture) registerDeposit(id uint32, commitment string, amount, expiry uint64) {
	f.vaultNotes[id] = fixtureNote{commitment: "0x" + addressABIWord(commitment), amount: amount, expiry: expiry, status: noteActive}
	f.setLeaf(id, noteLeaf(id, fieldValue(commitment), amount, expiry))
}

func (f *addressFixture) closeNote(id uint32) {
	note := f.vaultNotes[id]
	note.status = noteClosed
	f.vaultNotes[id] = note
	f.setLeaf(id, new(big.Int))
}

// tree returns the root and the empty-slot path at next_note_id, cached
// until a leaf changes. Callers hold f.mu.
func (f *addressFixture) tree() (*big.Int, []*big.Int) {
	if f.cachedRoot == nil || f.cachedVersion != f.leafVersion {
		f.cachedRoot, f.cachedPath = testTree(f.leaves, uint32(len(f.leaves)))
		f.cachedVersion = f.leafVersion
	}
	return f.cachedRoot, f.cachedPath
}

func newAddressFixture(t *testing.T, native ...bool) *addressFixture {
	t.Helper()
	f := &addressFixture{chain: "0x1", decimals: "0x6", gas: "0x10000", gasPrice: "0x3b9aca00", balance: "0xf4240", eth: "0xde0b6b3a7640000", allowance: "0x0", nonce: "0x0", finalized: "0x20", canonical: addressTestBlock, accepted: map[string]*types.Transaction{}, receipts: map[string]map[string]any{}}
	f.native = len(native) > 0 && native[0]
	f.vaultNotes, f.mined, f.minedExpiry = map[uint32]fixtureNote{}, map[string]uint32{}, map[uint32]uint64{}
	f.headers = map[string]*types.Header{strings.ToLower(addressTestBlock): addressTestHeader}
	for i := range addressTestFirstNote {
		f.setLeaf(uint32(i), big.NewInt(int64(0x1000+i)))
	}
	f.indexerBlock, f.indexerHash = 0x20, addressTestBlock
	f.walletNote = map[string]any{"note_id": addressTestFirstNote, "current_balance": 99999}
	f.indexer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("identity reached the indexer")
		}
		if r.Method != http.MethodGet || (r.URL.Path != "/v1/tree/snapshot" && r.URL.Path != "/v1/tree/root") {
			t.Errorf("unexpected indexer request %s %s", r.Method, r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		snapshot := r.URL.Path == "/v1/tree/snapshot"
		if snapshot {
			f.snapshotReads++
		} else {
			f.rootReads++
		}
		if f.indexerStatus > 0 {
			w.WriteHeader(f.indexerStatus)
			_, _ = io.WriteString(w, `{"status":"unavailable","error_code":"indexer_unavailable"}`)
			return
		}
		root, _ := f.tree()
		body := map[string]any{"root": fmt.Sprintf("0x%x", root), "next_note_id": len(f.leaves)}
		if snapshot {
			body["leaves"] = fieldHexes(f.leaves)
		}
		if f.indexerStatus < 0 && snapshot { // An internally inconsistent snapshot.
			body["next_note_id"] = len(f.leaves) + 1
		}
		if !f.indexerWithoutBlock {
			body["block_number"], body["block_hash"] = f.indexerBlock, f.indexerHash
		}
		_ = json.NewEncoder(w).Encode(body)
	}))
	t.Cleanup(f.indexer.Close)
	chainRPC := func(w http.ResponseWriter, r *http.Request, exit bool) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if !exit && f.pinnedDown {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Error("identity reached payment RPC")
		}
		if r.Method != http.MethodPost {
			t.Error("unexpected RPC method")
		}
		var request struct {
			ID     int               `json:"id"`
			Method string            `json:"method"`
			Params []json.RawMessage `json:"params"`
		}
		if json.NewDecoder(r.Body).Decode(&request) != nil {
			t.Error("invalid RPC request")
			return
		}
		if exit {
			f.exitCalls = append(f.exitCalls, request.Method)
		} else {
			f.rpcCalls = append(f.rpcCalls, request.Method)
		}
		var result any
		// The gasless fixture (gasless_fixture_test.go) answers the gasless
		// contracts' reads and the dry run of a sponsored operation.
		if f.gasless != nil {
			if result, refused, handled := f.gasless.answer(t, request.Method, request.Params); handled {
				if refused != nil {
					_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "error": refused})
				} else {
					_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
				}
				return
			}
		}
		// The deployment checks before a deposit read the fixture vault's
		// code and getters.
		if answer, ok := deploymentCheckAnswer("mainnet", request.Method, request.Params); ok {
			if f.codeTamper && request.Method == "eth_getCode" && answer == fixtureCode["vault"] {
				answer = "0x60016001"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": answer})
			return
		}
		switch request.Method {
		case "eth_chainId":
			result = f.chain
		case "eth_getBalance":
			result = f.eth
		case "eth_getTransactionCount":
			var tag string
			if len(request.Params) == 2 {
				_ = json.Unmarshal(request.Params[1], &tag)
			}
			result = f.nonce
			switch {
			case !exit && f.pinnedNonce != "":
				result = f.pinnedNonce
			case tag == "pending" && f.pendingNonce != "":
				result = f.pendingNonce
			case tag == "finalized" && f.finalizedNonce != "":
				result = f.finalizedNonce
			}
		case "eth_getCode":
			result = "0x"
		case "eth_feeHistory":
			bases := make([]string, 21)
			rewards := make([][]string, 20)
			ratios := make([]float64, 20)
			for i := range bases {
				bases[i] = f.gasPrice
			}
			for i := range rewards {
				rewards[i] = []string{"0xf4240"}
				ratios[i] = 0.5
			}
			result = map[string]any{"oldestBlock": "0xd", "baseFeePerGas": bases, "reward": rewards, "gasUsedRatio": ratios}
		case "eth_estimateGas":
			if f.refuseSimulation {
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "error": map[string]any{"code": 3, "message": "execution reverted"}})
				return
			}
			if len(request.Params) == 3 {
				f.overrideReads++
			}
			var call map[string]string
			_ = json.Unmarshal(request.Params[0], &call)
			f.estimateValue = call["value"]
			result = f.gas
		case "eth_gasPrice":
			result = f.gasPrice
		case "eth_blockNumber":
			result = "0x20"
		case "eth_getLogs":
			var filter struct {
				Address string   `json:"address"`
				Topics  []string `json:"topics"`
			}
			_ = json.Unmarshal(request.Params[0], &filter)
			found := []map[string]any{}
			for _, log := range f.logs {
				topics, _ := log["topics"].([]string)
				matches := strings.EqualFold(fmt.Sprint(log["address"]), filter.Address)
				for i, topic := range filter.Topics {
					matches = matches && i < len(topics) && strings.EqualFold(topics[i], topic)
				}
				if matches {
					found = append(found, log)
				}
			}
			result = found
		case "eth_call":
			var call struct {
				From string `json:"from"`
				To   string `json:"to"`
				Data string `json:"data"`
			}
			_ = json.Unmarshal(request.Params[0], &call)
			if call.From != "" && f.refuseSimulation && strings.EqualFold(call.To, addressTestVault) {
				_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "error": map[string]any{"code": 3, "message": "execution reverted"}})
				return
			}
			if call.From != "" {
				result = "0x"
				if len(request.Params) == 3 {
					f.overrideReads++
				}
				break
			}
			if strings.EqualFold(call.To, addressTestVault) && strings.HasPrefix(call.Data, "0x"+escapePayoutCreditsSelector) && len(call.Data) == 74 {
				f.creditReads++
				result = "0x0"
				if credit, ok := f.escapeCredits["0x"+strings.ToLower(call.Data[34:])]; ok {
					result = credit
				}
				break
			}
			if strings.EqualFold(call.To, addressTestVault) && strings.HasPrefix(call.Data, notesSelector) {
				var block struct {
					BlockHash        string `json:"blockHash"`
					RequireCanonical bool   `json:"requireCanonical"`
				}
				if len(request.Params) == 2 && json.Unmarshal(request.Params[1], &block) == nil {
					f.vaultReadsAt = append(f.vaultReadsAt, block.BlockHash)
					if !block.RequireCanonical || !strings.EqualFold(block.BlockHash, f.canonical) {
						_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "error": map[string]any{"code": -32000, "message": "header not found"}})
						return
					}
				} else {
					f.vaultReadsAt = append(f.vaultReadsAt, string(request.Params[1]))
				}
				id, _ := new(big.Int).SetString(call.Data[10:], 16)
				result = encodeVaultNote(f.vaultNotes[uint32(id.Uint64())])
				break
			}
			if !strings.EqualFold(call.To, addressTestToken) {
				t.Error("unexpected token contract")
			}
			switch call.Data[:10] {
			case "0x313ce567":
				result = f.decimals
			case "0x70a08231":
				result = f.balance
			case "0xdd62ed3e":
				result = f.allowance
			default:
				t.Errorf("unexpected call %s", call.Data[:10])
			}
		case "eth_getTransactionReceipt":
			var hash string
			_ = json.Unmarshal(request.Params[0], &hash)
			if found, ok := f.receipts[hash]; ok && f.hideReceipts == 0 {
				result = found
			}
			if f.hideReceipts > 0 {
				f.hideReceipts--
			}
		case "eth_getBlockByNumber":
			var number string
			_ = json.Unmarshal(request.Params[0], &number)
			if number == "finalized" {
				number = f.finalized
			}
			if number == "latest" {
				number = "0x20"
			}
			timestamp := time.Now().Unix()
			if f.latestTime != 0 {
				timestamp = f.latestTime
			}
			result = map[string]string{"number": number, "hash": f.canonical, "timestamp": fmt.Sprintf("0x%x", timestamp), "baseFeePerGas": f.gasPrice}
		case "eth_getBlockByHash":
			var hash string
			_ = json.Unmarshal(request.Params[0], &hash)
			if header, ok := f.headers[strings.ToLower(hash)]; ok {
				result = header
			}
		case "eth_sendRawTransaction":
			var raw string
			_ = json.Unmarshal(request.Params[0], &raw)
			encoded, err := hex.DecodeString(strings.TrimPrefix(raw, "0x"))
			var tx types.Transaction
			if err != nil || tx.UnmarshalBinary(encoded) != nil {
				t.Error("invalid signed transaction")
				return
			}
			stored, err := os.ReadFile(f.h.addressStatePath())
			if err != nil {
				t.Error("transaction broadcast before durable journal")
				return
			}
			var journal addressFundingRecord
			_ = json.Unmarshal(stored, &journal)
			journaled := false
			for _, entry := range append(append([]addressTransaction{}, journal.History...), pendingAddressTransaction(journal.Pending)...) {
				if entry.Raw == raw && entry.Hash == tx.Hash().Hex() {
					journaled = true
				}
			}
			if !journaled {
				t.Error("broadcast does not match durable journal")
			}
			from, err := types.Sender(types.LatestSignerForChainID(big.NewInt(1)), &tx)
			if err != nil || !strings.EqualFold(from.Hex(), journal.Address) || (!f.native && tx.Value().Sign() != 0) {
				t.Error("invalid EIP-155 signature or value")
			}
			f.accepted[tx.Hash().Hex()] = &tx
			f.submitted = append(f.submitted, raw)
			if f.ambiguous {
				w.WriteHeader(502)
				_, _ = io.WriteString(w, "do not expose raw signed transaction: "+raw)
				return
			}
			result = tx.Hash().Hex()
		default:
			t.Errorf("unexpected RPC %s", request.Method)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
	}
	rpc := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { chainRPC(w, r, false) }))
	t.Cleanup(rpc.Close)
	exitRPC := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { chainRPC(w, r, true) }))
	t.Cleanup(exitRPC.Close)
	f.exitRPC = exitRPC.URL
	client := newTestClient(t, func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		switch r.URL.Path {
		case "/funding/config":
			config := map[string]any{"chain_id": 1, "contract_address": addressTestVault, "demo_billing_token_address": addressTestToken, "demo_rpc_url": rpc.URL, "indexer_url": f.indexer.URL, "protocol_server_url": testProtocolServerURL(t, "mainnet")}
			if f.native {
				config["demo_billing_token_address"] = nil
				deployment, _, err := pinnedDeployment("mainnet")
				if err != nil {
					t.Fatal(err)
				}
				config["deployment_id"] = deployment.ID
				config["billing_asset"] = "native_eth"
				config["billing_unit"] = "gwei"
				config["native_asset_wei_per_unit"] = "1000000000"
			}
			_ = json.NewEncoder(w).Encode(config)
		case "/wallet/status":
			_ = json.NewEncoder(w).Encode(map[string]any{"has_note": f.active, "pending_request": f.walletPending, "note": f.walletNote})
		case "/funding/api/deposit/prepare":
			f.prepared++
			var input struct {
				Amount uint64 `json:"amount"`
			}
			_ = json.NewDecoder(r.Body).Decode(&input)
			path := make([]string, 32)
			for i := range path {
				path[i] = "0x0"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"amount": input.Amount, "secret": "0xabcdef", "commitment": "0x1234", "zero_path": path})
		case "/oa/v1/deposit/path":
			f.paths++
			_, path := f.tree()
			_ = json.NewEncoder(w).Encode(map[string]any{"zero_path": fieldHexes(path)})
		case "/funding/api/deposit/confirm":
			var body map[string]any
			if json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("invalid deposit confirmation")
			}
			f.confirmBodies = append(f.confirmBodies, body)
			f.activated++
			f.active = true
			f.walletNote = map[string]any{"note_id": body["note_id"], "deposit_amount": body["amount"], "current_balance": body["amount"], "expiry_ts": body["expiry_ts"], "is_genesis": true}
			_, _ = io.WriteString(w, `{}`)
		case "/wallet/reset":
			f.resetCalls++
			f.companionSteps = append(f.companionSteps, "reset")
			f.active = false
			_ = json.NewEncoder(w).Encode(map[string]any{"has_note": false, "pending_request": false})
		case "/oa/v1/withdraw/release":
			var body map[string]any
			if r.Method != http.MethodPost || json.NewDecoder(r.Body).Decode(&body) != nil {
				t.Error("invalid withdrawal release")
			}
			f.releaseBodies = append(f.releaseBodies, body)
			f.companionSteps = append(f.companionSteps, "release")
			if f.releaseRefusal != "" {
				w.WriteHeader(http.StatusConflict)
				_ = json.NewEncoder(w).Encode(map[string]any{"error": map[string]any{"code": f.releaseRefusal, "message": "private reservation detail"}})
				return
			}
			f.withdrawalPhase = nil
			_ = json.NewEncoder(w).Encode(map[string]any{"phase": "none"})
		case "/oa/v1/withdraw/status":
			phase := f.withdrawalPhase
			if phase == nil {
				phase = map[string]any{"phase": "none"}
			}
			_ = json.NewEncoder(w).Encode(phase)
		default:
			t.Errorf("unexpected companion path %s", r.URL.Path)
		}
	}, rpc)
	client.endpoints.Indexer = f.indexer.URL
	var err error
	f.h, err = NewFundingHandler(client, "http://127.0.0.1:8787", t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// setChainTime makes the fixture chain's block 0x20, which the indexer's
// view and the RPC's canonical reads name, carry block time at. Call it
// before anything is mined.
func (f *addressFixture) setChainTime(at int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	header := fixtureHeader(0x20, at)
	hash := header.Hash().Hex()
	f.headers[strings.ToLower(hash)] = header
	f.canonical, f.indexerHash = hash, hash
}

// mine includes a broadcast transaction. A successful deposit lands at the
// indexer's next slot, in both the vault state and the indexer snapshot; a
// re-inclusion of the same transaction keeps its note and expiry.
func (f *addressFixture) mine(t *testing.T, hash string, reverted bool) {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	tx := f.accepted[hash]
	if tx == nil {
		t.Fatal("transaction was not broadcast")
	}
	status := "0x1"
	if reverted {
		status = "0x0"
	}
	receipt := map[string]any{"transactionHash": hash, "status": status, "blockNumber": "0x10", "blockHash": f.canonical, "to": tx.To().Hex()}
	if !reverted {
		data := hex.EncodeToString(tx.Data())
		if strings.HasPrefix(data, "095ea7b3") {
			value, _ := new(big.Int).SetString(data[72:], 16)
			f.allowance = "0x" + value.Text(16)
		} else {
			commitment := "0x" + data[8:72]
			amount, _ := new(big.Int).SetString(data[72:136], 16)
			id, ok := f.mined[hash]
			if !ok {
				id = uint32(len(f.leaves))
				f.mined[hash], f.minedExpiry[id] = id, uint64(time.Now().Unix())+3600
				f.registerDeposit(id, commitment, amount.Uint64(), f.minedExpiry[id])
				if f.minedRoot == nil {
					f.minedRoot = map[string]*big.Int{}
				}
				f.minedRoot[hash], _ = f.tree()
			}
			receipt["logs"] = depositEventReceiptAt(addressTestVault, id, commitment, amount.Uint64(), f.minedExpiry[id], f.minedRoot[hash]).Logs
			f.allowance = "0x0"
		}
	}
	f.nonce = fmt.Sprintf("0x%x", tx.Nonce()+1)
	f.receipts[hash] = receipt
}

func TestAddressFundingPersistsBeforeReturningAndSurvivesRestart(t *testing.T) {
	f := newAddressFixture(t)
	status, err := f.h.Address(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.Phase != "ready" || !isHex(status.Address, 20) || status.TokenBalance != "1000000" || status.ETHBalance != "1000000000000000000" {
		t.Fatalf("invalid public address status: %+v", status)
	}
	info, err := os.Stat(f.h.addressStatePath())
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("funding key was not durably saved privately")
	}
	raw, _ := os.ReadFile(f.h.addressStatePath())
	var saved addressFundingRecord
	_ = json.Unmarshal(raw, &saved)
	public, _ := json.Marshal(status)
	if strings.Contains(string(public), saved.PrivateKey) || strings.Contains(string(public), "private_key") {
		t.Fatal("private key exposed")
	}
	restarted := &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	again, err := restarted.Address(context.Background())
	if err != nil || again.Address != status.Address {
		t.Fatalf("restart changed address: %v", err)
	}
	if len(f.submitted) != 0 {
		t.Fatal("read-only address lookup submitted a transaction")
	}
}

func TestAddressFundingPersistenceFailureExposesNoAddress(t *testing.T) {
	f := newAddressFixture(t)
	if err := os.Mkdir(f.h.addressStatePath(), 0700); err != nil {
		t.Fatal(err)
	}
	status, err := f.h.Address(context.Background())
	if err == nil || status.Address != "" || len(f.submitted) != 0 {
		t.Fatal("address escaped failed storage")
	}
}

func TestAddressFundingRejectsNetworkDecimalsAndDeploymentMismatch(t *testing.T) {
	for _, scenario := range []string{"chain", "decimals", "deployment", "permissions", "damaged key"} {
		t.Run(scenario, func(t *testing.T) {
			f := newAddressFixture(t)
			if _, err := f.h.Address(context.Background()); err != nil {
				t.Fatal(err)
			}
			f.mu.Lock()
			switch scenario {
			case "chain":
				f.chain = "0xaa36a7"
			case "decimals":
				f.decimals = "0x12"
			case "permissions":
				_ = os.Chmod(f.h.addressStatePath(), 0644)
			default:
				raw, _ := os.ReadFile(f.h.addressStatePath())
				var record addressFundingRecord
				_ = json.Unmarshal(raw, &record)
				if scenario == "deployment" {
					record.Token = addressTestVault
				} else {
					record.PrivateKey = "bad"
				}
				if err := f.h.saveAddress(&record); err != nil {
					t.Fatal(err)
				}
			}
			f.mu.Unlock()
			if _, err := f.h.FundAddress(context.Background(), 100000); err == nil {
				t.Fatal("invalid funding context accepted")
			}
			if len(f.submitted) != 0 {
				t.Fatal("invalid context broadcast")
			}
		})
	}
}

func TestAddressFundingWaitingDoesNotPrepareOrSend(t *testing.T) {
	f := newAddressFixture(t)
	f.balance = "0x0"
	status, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || status.Phase != "waiting_funds" || status.Amount != 100000 || f.prepared != 0 || len(f.submitted) != 0 {
		t.Fatalf("bad waiting state: %+v %v", status, err)
	}
	if _, err := f.h.FundAddress(context.Background(), 200000); err == nil {
		t.Fatal("changed an authorized amount")
	}
}

func TestAddressFundingAmbiguousApprovalReplaysExactBytesAcrossRestart(t *testing.T) {
	f := newAddressFixture(t)
	f.ambiguous = true
	first, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || first.Phase != "approval_pending" || !isHex(first.TransactionHash, 32) {
		t.Fatalf("ambiguous submit lost hash: %+v %v", first, err)
	}
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	again, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || again.TransactionHash != first.TransactionHash || len(f.submitted) != 2 || f.submitted[0] != f.submitted[1] || len(f.accepted) != 1 {
		t.Fatalf("ambiguous approval replaced: %v", err)
	}
	if strings.Contains(again.Message, "raw") {
		t.Fatal("raw RPC error exposed")
	}
	before := len(f.submitted)
	if _, err := f.h.Address(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(f.submitted) != before {
		t.Fatal("GET rebroadcast a transaction")
	}
}

func TestAddressFundingApprovesExactAmountRefreshesPathAndDepositsOnce(t *testing.T) {
	f := newAddressFixture(t)
	approval, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	tx := f.accepted[approval.TransactionHash]
	if tx == nil || !strings.EqualFold(tx.To().Hex(), addressTestToken) || hex.EncodeToString(tx.Data()) != "095ea7b3"+addressABIWord(addressTestVault)+fmt.Sprintf("%064x", 100000) {
		t.Fatal("approval is not exact configured vault amount")
	}
	f.mine(t, approval.TransactionHash, false)
	f.finalized = "0x1" // A canonical approval can progress before finality.
	deposit, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	if deposit.Phase != "deposit_pending" || f.paths != 1 || f.prepared != 1 {
		t.Fatalf("deposit did not use refreshed saved note: %+v", deposit)
	}
	tx = f.accepted[deposit.TransactionHash]
	if tx == nil || tx.Nonce() != 1 || !strings.EqualFold(tx.To().Hex(), addressTestVault) {
		t.Fatal("invalid deposit transaction")
	}
	// The prepared "0x0" path was replaced by the refreshed empty-slot path,
	// bound to the indexer slot the deposit targets; the calldata carries
	// only the commitment and the amount (vault revision 3).
	f.mu.Lock()
	_, path := f.tree()
	f.mu.Unlock()
	if data := hex.EncodeToString(tx.Data()); len(data) != 8+64*2 || !strings.HasPrefix(data, depositSelector) {
		t.Fatal("deposit calldata is not deposit(bytes32,uint128)")
	}
	if refreshed := f.savedDeposit(t).ZeroPath; !slices.Equal(refreshed, fieldHexes(path)) || slices.Equal(refreshed, slices.Repeat([]string{"0x0"}, 32)) {
		t.Fatal("deposit witness was not refreshed")
	}
	if saved, err := f.h.readAddressDeposit(fundingConfig{ChainID: 1, Contract: addressTestVault, Token: addressTestToken}); err != nil || saved.Slot == nil || saved.Slot.NoteID != addressTestFirstNote {
		t.Fatalf("deposit slot was not recorded before signing: %+v %v", saved, err)
	}
	f.mine(t, deposit.TransactionHash, false)
	before := len(f.submitted)
	pending, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || pending.Phase != "deposit_pending" || f.activated != 0 {
		t.Fatal("activated non-final deposit")
	}
	if len(f.submitted) != before {
		t.Fatal("mined pending transaction broadcast again")
	}
	f.finalized = "0x20"
	active, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || active.Phase != "active" || f.activated != 1 {
		t.Fatalf("activation failed: %+v %v", active, err)
	}
	for range 3 {
		status, err := f.h.FundAddress(context.Background(), 100000)
		if err != nil || status.Phase != "active" {
			t.Fatal(err)
		}
	}
	if f.activated != 1 || len(f.accepted) != 2 || f.prepared != 1 {
		t.Fatal("retry deposited or initialized twice")
	}
}

func TestAddressFundingResetsInsufficientAllowanceAndDoesNotRepeatUnresolvedReset(t *testing.T) {
	f := newAddressFixture(t)
	f.allowance = "0xc350"
	reset, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	tx := f.accepted[reset.TransactionHash]
	if !strings.HasSuffix(hex.EncodeToString(tx.Data()), strings.Repeat("0", 64)) {
		t.Fatal("excess allowance not reset")
	}
	_, err = f.h.FundAddress(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.accepted) != 1 {
		t.Fatal("unresolved reset generated a replacement")
	}
	f.mine(t, reset.TransactionHash, false)
	approval, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	if approval.Phase != "approval_pending" || f.accepted[approval.TransactionHash].Nonce() != 1 {
		t.Fatal("exact approval did not follow reset")
	}
}

func TestAddressFundingRevertRequiresExplicitRetryAndLegacyRecordIsNotAdopted(t *testing.T) {
	for _, legacy := range []bool{false, true} {
		t.Run(fmt.Sprint(legacy), func(t *testing.T) {
			f := newAddressFixture(t)
			if legacy {
				if err := f.h.save(depositRecord{ChainID: 1, Contract: addressTestVault, Amount: 200000, Secret: "0x1", Commitment: "0x2"}); err != nil {
					t.Fatal(err)
				}
				status, err := f.h.FundAddress(context.Background(), 100000)
				if err != nil || status.Phase != "legacy_recovery" || status.Amount != 200000 || len(f.submitted) != 0 {
					t.Fatalf("legacy note adopted: %+v %v", status, err)
				}
			} else {
				status, err := f.h.FundAddress(context.Background(), 100000)
				if err != nil {
					t.Fatal(err)
				}
				f.mine(t, status.TransactionHash, true)
				status, err = f.h.FundAddress(context.Background(), 100000)
				if err != nil || status.Phase != "reverted" {
					t.Fatalf("revert not preserved: %v", err)
				}
				if len(f.accepted) != 1 {
					t.Fatal("reverted transaction replaced before explicit retry")
				}
				f.finalized = "0x1"
				status, err = f.h.FundAddress(context.Background(), 100000)
				if err != nil || status.Phase != "reverted" || len(f.accepted) != 1 {
					t.Fatal("retry replaced unfinalized revert")
				}
				f.finalized = "0x20"
				status, err = f.h.FundAddress(context.Background(), 100000)
				if err != nil || status.Phase != "approval_pending" || len(f.accepted) != 2 || f.accepted[status.TransactionHash].Nonce() != 1 {
					t.Fatalf("explicit safe retry did not progress: %v", err)
				}
			}
		})
	}
}

func TestAddressFundingBoundsGasFeesAndNonce(t *testing.T) {
	for _, scenario := range []string{"gas", "gas buffer", "fee", "fee budget", "nonce"} {
		t.Run(scenario, func(t *testing.T) {
			f := newAddressFixture(t)
			switch scenario {
			case "gas":
				f.gas = "0x2000000"
			case "gas buffer":
				f.gas = "0x1000000"
			case "fee":
				f.gasPrice = "0x01"
			case "fee budget":
				f.gas = "0x800000"
				f.gasPrice = "0x" + strings.Repeat("f", 64)
			case "nonce":
				f.nonce = "0xffffffffffffffff"
			}
			if _, err := f.h.FundAddress(context.Background(), 100000); err == nil {
				t.Fatal("unsafe transaction was accepted")
			}
			if len(f.submitted) != 0 {
				t.Fatal("unsafe transaction was sent")
			}
		})
	}
}

func TestAddressFundingChangedCanonicalBlockStopsProgress(t *testing.T) {
	f := newAddressFixture(t)
	first, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	f.mine(t, first.TransactionHash, false)
	f.canonical = "0x" + strings.Repeat("b", 64)
	if _, err := f.h.FundAddress(context.Background(), 100000); err == nil {
		t.Fatal("noncanonical receipt progressed")
	}
	if len(f.accepted) != 1 {
		t.Fatal("new transaction after noncanonical receipt")
	}
}

func TestAddressFundingCannotExposeAddressAfterDirectoryLoss(t *testing.T) {
	f := newAddressFixture(t)
	f.h.statePath = filepath.Join(t.TempDir(), "missing", "pending-deposit.json")
	status, err := f.h.Address(context.Background())
	if err == nil || status.Address != "" {
		t.Fatal("unsaved generated key exposed")
	}
}

func TestAddressFundingWaitsForEnoughETHAndReusesSufficientAllowance(t *testing.T) {
	f := newAddressFixture(t)
	f.allowance = "0xf4240"
	f.eth = "0x1"
	waiting, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || waiting.Phase != "waiting_funds" || len(f.submitted) != 0 {
		t.Fatalf("insufficient ETH did not wait: %+v %v", waiting, err)
	}
	f.eth = "0xde0b6b3a7640000"
	deposit, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || deposit.Phase != "deposit_pending" || len(f.accepted) != 1 {
		t.Fatalf("sufficient allowance triggered approval: %+v %v", deposit, err)
	}
}

func TestAddressFundingManualConfirmationCannotBypassFinality(t *testing.T) {
	f := newAddressFixture(t)
	f.allowance = "0xf4240"
	deposit, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	f.mine(t, deposit.TransactionHash, false)
	f.finalized = "0x1"
	if _, err := f.h.confirm(context.Background(), deposit.TransactionHash); err == nil || !strings.Contains(err.Error(), "finality") {
		t.Fatalf("manual recovery bypassed finality: %v", err)
	}
	if f.activated != 0 {
		t.Fatal("unfinalized note activated")
	}
	f.finalized = "0x20"
	if _, err := f.h.confirm(context.Background(), deposit.TransactionHash); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.FundAddress(context.Background(), 100000); err != nil {
		t.Fatal(err)
	}
	if f.activated != 1 || len(f.accepted) != 1 {
		t.Fatal("manual recovery duplicated activation or deposit")
	}
}

func TestAddressFundingMissingActivatedCompanionNoteNeverRefills(t *testing.T) {
	f := newAddressFixture(t)
	f.allowance = "0xf4240"
	deposit, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	f.mine(t, deposit.TransactionHash, false)
	if _, err := f.h.FundAddress(context.Background(), 100000); err != nil {
		t.Fatal(err)
	}
	f.active = false
	for _, readOnly := range []bool{true, false} {
		var status AddressFundingStatus
		if readOnly {
			status, err = f.h.Address(context.Background())
		} else {
			status, err = f.h.FundAddress(context.Background(), 200000)
		}
		if err != nil || status.Phase != "recovery_required" || status.Amount != 100000 {
			t.Fatalf("missing note offered refill: %+v %v", status, err)
		}
	}
	if f.prepared != 1 || f.activated != 1 || len(f.accepted) != 1 {
		t.Fatal("lost state triggered second deposit")
	}
}

func TestAddressFundingAmbiguousDepositNeverChoosesNewNonce(t *testing.T) {
	f := newAddressFixture(t)
	f.allowance = "0xf4240"
	f.ambiguous = true
	first, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		status, err := f.h.FundAddress(context.Background(), 100000)
		if err != nil || status.TransactionHash != first.TransactionHash {
			t.Fatal("ambiguous deposit changed identity")
		}
	}
	if len(f.accepted) != 1 || f.prepared != 1 || f.paths != 1 {
		t.Fatal("ambiguous deposit regenerated note/path/transaction")
	}
	for _, raw := range f.submitted {
		if raw != f.submitted[0] {
			t.Fatal("deposit replay changed signed bytes")
		}
	}
}

func TestAddressFundingRejectsRPCNonceRollbackAfterApproval(t *testing.T) {
	f := newAddressFixture(t)
	first, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	f.mine(t, first.TransactionHash, false)
	f.nonce = "0x0"
	if _, err := f.h.FundAddress(context.Background(), 100000); err == nil || !strings.Contains(err.Error(), "caught up") {
		t.Fatalf("nonce rollback not blocked: %v", err)
	}
	if len(f.accepted) != 1 {
		t.Fatal("signed with consumed nonce")
	}
}

func TestAddressFundingConcurrentCallsShareOneAddressAndTransaction(t *testing.T) {
	f := newAddressFixture(t)
	var group sync.WaitGroup
	for range 4 {
		group.Add(1)
		go func() {
			defer group.Done()
			if _, err := f.h.FundAddress(context.Background(), 100000); err != nil {
				t.Error(err)
			}
		}()
	}
	group.Wait()
	if len(f.accepted) != 1 || f.prepared != 1 {
		t.Fatal("concurrent calls generated conflicting funding state")
	}
}

func TestAddressFundingRevertedDepositRetainsNoteAndRefreshesWitnessOnExplicitRetry(t *testing.T) {
	f := newAddressFixture(t)
	f.allowance = "0xf4240"
	first, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	f.mine(t, first.TransactionHash, true)
	reverted, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || reverted.Phase != "reverted" {
		t.Fatal("reverted deposit not reported")
	}
	second, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	if second.Phase != "deposit_pending" || second.TransactionHash == first.TransactionHash || f.prepared != 1 || f.paths != 2 || len(f.accepted) != 2 {
		t.Fatalf("safe retry did not retain note: %+v", second)
	}
	raw, _ := os.ReadFile(f.h.statePath)
	var note depositRecord
	_ = json.Unmarshal(raw, &note)
	if note.Secret != "0xabcdef" || note.Commitment != "0x1234" {
		t.Fatal("reverted deposit lost note secret")
	}
}

func TestAddressFundingApprovalReorgReplaysPriorSignedBytesBeforeDependentDeposit(t *testing.T) {
	f := newAddressFixture(t)
	approval, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	f.mine(t, approval.TransactionHash, false)
	deposit, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	originalApproval, originalDeposit := f.submitted[0], f.submitted[1]
	f.nonce = "0x0"
	delete(f.receipts, approval.TransactionHash)
	status, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	if status.TransactionHash != deposit.TransactionHash || len(f.submitted) != 4 || f.submitted[2] != originalApproval || f.submitted[3] != originalDeposit || len(f.accepted) != 2 {
		t.Fatal("reorg recovery changed signed approvals/deposit")
	}
}

func TestAddressFundingApprovalReorgAfterArchivalWithoutSignedSuccessor(t *testing.T) {
	f := newAddressFixture(t)
	approval, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil {
		t.Fatal(err)
	}
	original := f.submitted[0]
	f.mine(t, approval.TransactionHash, false)
	f.eth = "0x1" // Interrupt after archiving approval, before signing a successor.
	waiting, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || waiting.Phase != "waiting_funds" {
		t.Fatalf("did not pause between stages: %+v %v", waiting, err)
	}
	raw, _ := os.ReadFile(f.h.addressStatePath())
	var saved addressFundingRecord
	_ = json.Unmarshal(raw, &saved)
	if saved.Pending != nil || len(saved.History) != 1 || len(f.accepted) != 1 {
		t.Fatal("fixture did not isolate archived approval")
	}
	f.eth = "0xde0b6b3a7640000"
	f.allowance = "0x0"
	f.nonce = "0x0"
	delete(f.receipts, approval.TransactionHash)
	retrying, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || retrying.Phase != "approval_pending" || retrying.TransactionHash != approval.TransactionHash || len(f.accepted) != 1 || f.submitted[len(f.submitted)-1] != original {
		t.Fatalf("archived approval recovery stalled or replaced: %+v %v", retrying, err)
	}
	f.mine(t, approval.TransactionHash, false)
	deposit, err := f.h.FundAddress(context.Background(), 100000)
	if err != nil || deposit.Phase != "deposit_pending" || len(f.accepted) != 2 || f.accepted[deposit.TransactionHash].Nonce() != 1 {
		t.Fatalf("replayed approval did not unblock deposit: %+v %v", deposit, err)
	}
}

func TestAddressFundingUnfinalizedFailedApprovalMayDisappearOrBecomeSuccessful(t *testing.T) {
	for _, scenario := range []string{"disappears", "becomes successful"} {
		t.Run(scenario, func(t *testing.T) {
			f := newAddressFixture(t)
			approval, err := f.h.FundAddress(context.Background(), 100000)
			if err != nil {
				t.Fatal(err)
			}
			f.mine(t, approval.TransactionHash, true)
			f.finalized = "0x1"
			pending, err := f.h.FundAddress(context.Background(), 100000)
			if err != nil || pending.Phase != "approval_pending" || len(f.accepted) != 1 {
				t.Fatalf("provisional failure became terminal: %+v %v", pending, err)
			}
			if scenario == "disappears" {
				delete(f.receipts, approval.TransactionHash)
				f.nonce = "0x0"
				pending, err = f.h.FundAddress(context.Background(), 100000)
				if err != nil || pending.TransactionHash != approval.TransactionHash || f.submitted[0] != f.submitted[len(f.submitted)-1] || len(f.accepted) != 1 {
					t.Fatalf("failed receipt disappearance lost replay: %+v %v", pending, err)
				}
			}
			f.mine(t, approval.TransactionHash, false)
			deposit, err := f.h.FundAddress(context.Background(), 100000)
			if err != nil || deposit.Phase != "deposit_pending" || len(f.accepted) != 2 {
				t.Fatalf("formerly failed approval could not succeed: %+v %v", deposit, err)
			}
		})
	}
}

func TestAddressFundingRejectsRetiredTransactionInPendingJournal(t *testing.T) {
	f := newAddressFixture(t)
	if _, err := f.h.FundAddress(context.Background(), 100000); err != nil {
		t.Fatal(err)
	}
	raw, _ := os.ReadFile(f.h.addressStatePath())
	var saved addressFundingRecord
	_ = json.Unmarshal(raw, &saved)
	saved.Pending.FinalizedRevert = true
	if err := f.h.saveAddress(&saved); err != nil {
		t.Fatal(err)
	}
	if _, err := f.h.FundAddress(context.Background(), 100000); err == nil || !strings.Contains(err.Error(), "retired") {
		t.Fatal("inconsistent pending journal accepted")
	}
	if len(f.submitted) != 1 {
		t.Fatal("inconsistent pending journal broadcast")
	}
}

func (f *addressFixture) fundNative(t *testing.T, amount uint64) (AddressFundingStatus, error) {
	t.Helper()
	config, err := f.h.config(context.Background())
	if err != nil {
		return AddressFundingStatus{}, err
	}
	record, err := f.h.loadAddress(config)
	if err != nil {
		return AddressFundingStatus{}, err
	}
	if record.Pending != nil || record.Phase == "active" {
		return f.h.FundAddress(context.Background(), amount)
	}
	quote, err := f.h.QuoteAddressDeposit(context.Background(), amount)
	if err != nil {
		return AddressFundingStatus{}, err
	}
	return f.h.ApproveAddressDeposit(context.Background(), quote.ID)
}
