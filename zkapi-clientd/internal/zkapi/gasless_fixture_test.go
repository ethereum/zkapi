package zkapi

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// gaslessFixture serves, beside the address fixture's chain RPC, the gasless
// contracts of the test profile (the canonical EntryPoint runtime from the
// contract fixtures, fixture code at the paymaster and the factory, the
// paymaster's views and state, the EntryPoint's nonces and hashes, the
// vault's pause and pending-escape views, the dry run of handleOps) and an
// httptest bundler with the scripted shapes of the SDK's fake bundler
// (eth_chainId, eth_supportedEntryPoints, eth_estimateUserOperationGas,
// eth_sendUserOperation asserting the op was journaled first,
// eth_getUserOperationByHash, eth_getUserOperationReceipt). mineUserOp
// includes a sent operation in a bundle transaction with the logs its
// outcome produces.
type gaslessFixture struct {
	f       *addressFixture
	vectors transitVectors
	profile gaslessProfile
	// The gasless contracts of the test profile.
	entryPoint, senderCreator, paymaster, factory, vault common.Address
	// implementation is what the factory's implementation() names.
	implementation common.Address
	codes          map[string]string
	// The paymaster's live state.
	flatFee, minEscapeNet, maxSponsoredCost, maxFeeCeiling, priorityCeiling, deposit *big.Int
	escapesEnabled, sponsorshipPaused, vaultPaused                                   bool
	pausedAt                                                                         uint64
	attempts                                                                         map[string]uint64
	owed, credits, balances                                                          map[string]*big.Int
	stranded                                                                         map[string]bool
	escapeNote                                                                       map[string]uint64
	escapeSponsored                                                                  map[uint32]bool
	sequences                                                                        map[string]uint64
	pending                                                                          map[uint32]fixturePending
	// dryRunRevert, when set, is the revert data every handleOps dry run
	// answers.
	dryRunRevert []byte
	// The bundler.
	url                     string
	down, forgeHash, refuse bool
	// refuseResend refuses an operation the bundler saw already (a bundler
	// that dropped it for its fees and wants higher ones).
	refuseResend  bool
	refuseMessage string
	// sendDown fails only eth_sendUserOperation (a bundler reachable for
	// its reads whose send never answers).
	sendDown              bool
	unsupportedEntryPoint bool
	// accountSeen makes the bundler answer AA10 for an operation with
	// initCode, as one that saw the transit account created between the
	// client's dry run and its send.
	accountSeen              bool
	wrongChain               bool
	forgedReceiptTransaction string
	estimate                 map[string]string
	ops                      map[string]gaslessUserOpJSON
	sends                    []string
	known                    map[string]bool
	bundlerReceipts          map[string]string
	opLogs                   []map[string]any
	bundlerCalls             []string
}

// fixturePending is a vault pendingWithdrawals entry.
type fixturePending struct {
	nullifier    *big.Int
	finalBalance uint64
	destination  common.Address
	deadline     uint64
}

const gaslessFixturePaymasterCode = "0x600460045b"
const gaslessFixtureFactoryCode = "0x600560055b"
const gaslessFixtureImplementationCode = "0x600660065b"

// enableGasless attaches the gasless fixture and points the handler's
// bundler at it.
func (f *addressFixture) enableGasless(t *testing.T) *gaslessFixture {
	t.Helper()
	vectors := loadTransitVectors(t)
	deployment, _, err := deployedDeployment("mainnet")
	if err != nil {
		t.Fatal(err)
	}
	profile, err := deployment.Gasless.validate()
	if err != nil {
		t.Fatal(err)
	}
	readRuntime := func(name string) string {
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "protocol", "contracts", "test", "fixtures", name))
		if err != nil {
			t.Fatal(err)
		}
		return strings.TrimSpace(string(raw))
	}
	g := &gaslessFixture{
		f: f, vectors: vectors, profile: profile,
		entryPoint: common.HexToAddress(profile.EntryPoint), senderCreator: common.HexToAddress(profile.SenderCreator), paymaster: common.HexToAddress(profile.Paymaster), factory: common.HexToAddress(profile.Factory), vault: common.HexToAddress(deployment.Contract), implementation: common.HexToAddress(profile.Implementation),
		flatFee: vectorUint(t, vectors.Policy.FlatFeeWei), minEscapeNet: vectorUint(t, vectors.Policy.MinEscapeNetWei), maxSponsoredCost: vectorUint(t, vectors.Policy.MaxSponsoredCost), maxFeeCeiling: vectorUint(t, vectors.Policy.MaxFeeCeiling), priorityCeiling: vectorUint(t, vectors.Policy.PriorityFeeCeiling),
		deposit: new(big.Int).Mul(big.NewInt(10), big.NewInt(1_000_000_000_000_000_000)), escapesEnabled: true,
		attempts: map[string]uint64{}, owed: map[string]*big.Int{}, credits: map[string]*big.Int{}, balances: map[string]*big.Int{}, stranded: map[string]bool{}, escapeNote: map[string]uint64{}, escapeSponsored: map[uint32]bool{}, sequences: map[string]uint64{}, pending: map[uint32]fixturePending{},
		ops: map[string]gaslessUserOpJSON{}, known: map[string]bool{}, bundlerReceipts: map[string]string{},
	}
	g.codes = map[string]string{
		strings.ToLower(profile.EntryPoint): readRuntime("entrypoint-v0.7.0.runtime.hex"), strings.ToLower(profile.SenderCreator): readRuntime("sender-creator-v0.7.0.runtime.hex"),
		strings.ToLower(profile.Paymaster): gaslessFixturePaymasterCode, strings.ToLower(profile.Factory): gaslessFixtureFactoryCode,
		strings.ToLower(profile.Implementation): gaslessFixtureImplementationCode,
	}
	if crypto.Keccak256Hash(common.FromHex(g.codes[strings.ToLower(profile.EntryPoint)])).Hex() != gaslessEntryPointCodehash {
		t.Fatal("the EntryPoint runtime fixture does not hash to the canonical codehash")
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { g.serveBundler(t, w, r) }))
	t.Cleanup(server.Close)
	g.url = server.URL
	f.mu.Lock()
	f.gasless = g
	f.mu.Unlock()
	f.h.client.config.BundlerURL = server.URL
	return g
}

// transitAccount is the fixture's transit account of (owner, payee).
func (g *gaslessFixture) transitAccount(owner, payee common.Address) common.Address {
	creation := common.FromHex(g.profile.AccountCreationCode)
	return transitAccountAddress(g.factory, creation, g.entryPoint, g.vault, g.paymaster, owner, payee)
}

func wordHex(value *big.Int) string {
	return addressABIWord(value.Text(16))
}

func addressWord(address common.Address) string {
	return addressABIWord(strings.ToLower(address.Hex()))
}

// answer serves a chain RPC method of the gasless path; handled is false
// for anything else. Called with the address fixture's lock held.
func (g *gaslessFixture) answer(t *testing.T, method string, params []json.RawMessage) (result any, refused map[string]any, handled bool) {
	t.Helper()
	switch method {
	case "eth_getCode":
		var address string
		_ = json.Unmarshal(params[0], &address)
		if code, ok := g.codes[strings.ToLower(address)]; ok {
			return code, nil, true
		}
		return nil, nil, false
	case "eth_getBalance", "eth_getTransactionCount":
		var address string
		_ = json.Unmarshal(params[0], &address)
		balance, ok := g.balances[strings.ToLower(address)]
		if !ok {
			return nil, nil, false
		}
		if method == "eth_getTransactionCount" {
			return "0x0", nil, true
		}
		return "0x" + balance.Text(16), nil, true
	case "eth_getLogs":
		var filter struct {
			Address string `json:"address"`
			Topics  []any  `json:"topics"`
		}
		_ = json.Unmarshal(params[0], &filter)
		if !strings.EqualFold(filter.Address, g.entryPoint.Hex()) {
			return nil, nil, false
		}
		found := []map[string]any{}
		for _, log := range g.opLogs {
			topics := log["topics"].([]string)
			matches := true
			for i, topic := range filter.Topics {
				if topic == nil {
					continue
				}
				matches = matches && i < len(topics) && strings.EqualFold(topics[i], fmt.Sprint(topic))
			}
			if matches {
				found = append(found, log)
			}
		}
		return found, nil, true
	case "eth_call":
		var call struct {
			From string `json:"from"`
			To   string `json:"to"`
			Data string `json:"data"`
		}
		_ = json.Unmarshal(params[0], &call)
		if call.From != "" {
			if !strings.EqualFold(call.To, g.entryPoint.Hex()) {
				return nil, nil, false
			}
			if g.dryRunRevert != nil {
				return nil, map[string]any{"code": 3, "message": "execution reverted", "data": "0x" + hex.EncodeToString(g.dryRunRevert)}, true
			}
			// The EntryPoint's sender creation: an initCode for a sender
			// with code fails AA10.
			raw := common.FromHex(call.Data)
			if len(raw) > 4+4*32 {
				if op, err := decodeUserOpTuple(raw[4+4*32:]); err == nil && len(op.InitCode) != 0 {
					if _, exists := g.codes[strings.ToLower(op.Sender.Hex())]; exists {
						return nil, map[string]any{"code": 3, "message": "execution reverted", "data": "0x" + fixtureFailedOp("AA10 sender already constructed")}, true
					}
				}
			}
			return "0x", nil, true
		}
		return g.view(t, call.To, call.Data)
	}
	return nil, nil, false
}

// view answers a contract read of the gasless path.
func (g *gaslessFixture) view(t *testing.T, to, data string) (any, map[string]any, bool) {
	t.Helper()
	if len(data) < 10 {
		return nil, nil, false
	}
	selector, args := data[2:10], data[10:]
	arg := func(i int) *big.Int {
		if len(args) < (i+1)*64 {
			t.Errorf("short call %s", data)
			return new(big.Int)
		}
		return new(big.Int).SetBytes(common.FromHex(args[i*64 : (i+1)*64]))
	}
	word := func(values ...*big.Int) string {
		out := "0x"
		for _, value := range values {
			out += wordHex(value)
		}
		return out
	}
	boolWord := func(value bool) *big.Int {
		if value {
			return big.NewInt(1)
		}
		return new(big.Int)
	}
	switch strings.ToLower(to) {
	case strings.ToLower(g.paymaster.Hex()):
		switch selector {
		case selectorPaymasterPolicy:
			return word(g.maxSponsoredCost, g.flatFee, g.minEscapeNet, boolWord(g.escapesEnabled), boolWord(g.sponsorshipPaused)), nil, true
		case selectorMaxFeeCeiling:
			return word(g.maxFeeCeiling), nil, true
		case selectorPriorityFeeCeiling:
			return word(g.priorityCeiling), nil, true
		case selectorCallCap:
			return word(new(big.Int).SetUint64(g.profile.GasPolicy.CallCap[arg(0).Uint64()-1])), nil, true
		case selectorAttempts:
			return word(new(big.Int).SetUint64(g.attempts[args[:64]])), nil, true
		case selectorOwed:
			return word(g.owedOf(common.BigToAddress(arg(0)))), nil, true
		case selectorStranded:
			return word(boolWord(g.stranded[strings.ToLower(common.BigToAddress(arg(0)).Hex())])), nil, true
		case selectorEscapeNotePlusOne:
			return word(new(big.Int).SetUint64(g.escapeNote[strings.ToLower(common.BigToAddress(arg(0)).Hex())])), nil, true
		case selectorCredits:
			credit := g.credits[strings.ToLower(common.BigToAddress(arg(0)).Hex())]
			if credit == nil {
				credit = new(big.Int)
			}
			return word(credit), nil, true
		case selectorPaymasterQuote:
			kind, sender, noteID, nullifier, maxCost, maxFee := uint8(arg(0).Uint64()), common.BigToAddress(arg(1)), uint32(arg(2).Uint64()), arg(3), arg(4), arg(5)
			owed := g.owedOf(sender)
			required := new(big.Int).Add(new(big.Int).Add(maxCost, g.flatFee), owed)
			reserve := new(big.Int)
			if kind == gaslessKindEscape {
				reserve = new(big.Int).Mul(new(big.Int).SetUint64(g.profile.GasPolicy.FinalizeReserveGas), maxFee)
				required.Add(required, reserve)
				required.Add(required, g.minEscapeNet)
				required.Add(required, g.flatFee)
			}
			key := gaslessKey(kind, nullifier, noteID, sender)
			open := false
			if recorded := g.escapeNote[strings.ToLower(sender.Hex())]; recorded != 0 {
				note := g.f.vaultNotes[uint32(recorded-1)]
				open = note.status == notePendingWithdrawal || (note.status == noteClosed && g.balanceOf(sender).Sign() != 0)
			}
			return word(required, owed, g.flatFee, reserve, boolWord(g.attempts[key.Hex()[2:]] < g.profile.GasPolicy.MaxAttempts), boolWord(g.escapesEnabled && !g.escapeSponsored[noteID] && !open)), nil, true
		case selectorGasPolicy:
			out := "0x"
			for _, value := range g.profile.GasPolicy.words() {
				out += uintWord(value)
			}
			return out, nil, true
		case selectorPaymasterVault:
			return "0x" + addressWord(g.vault), nil, true
		case selectorPaymasterFactory:
			return "0x" + addressWord(g.factory), nil, true
		case selectorPaymasterEntryPoint:
			return "0x" + addressWord(g.entryPoint), nil, true
		case selectorWeiPerUnit:
			return "0x" + uintWord(1_000_000_000), nil, true
		case selectorAccountCreationCodeHash:
			return strings.ToLower(g.profile.AccountCreationCodeHash), nil, true
		}
	case strings.ToLower(g.factory.Hex()):
		switch selector {
		case selectorFactoryPaymaster:
			return "0x" + addressWord(g.paymaster), nil, true
		case selectorFactoryImplementation:
			return "0x" + addressWord(g.implementation), nil, true
		case selectorAccountCreationCodeHash:
			return strings.ToLower(g.profile.AccountCreationCodeHash), nil, true
		case selectorFactoryGetAddress:
			owner, payee := common.BigToAddress(arg(0)), common.BigToAddress(arg(1))
			account := g.transitAccount(owner, payee)
			for _, address := range []common.Address{account, payee} {
				if _, known := g.balances[strings.ToLower(address.Hex())]; !known {
					g.balances[strings.ToLower(address.Hex())] = new(big.Int)
				}
			}
			return "0x" + addressWord(account), nil, true
		}
	case strings.ToLower(g.entryPoint.Hex()):
		switch selector {
		case selectorGetNonce:
			sender, key := common.BigToAddress(arg(0)), arg(1)
			nonce := new(big.Int).Lsh(key, 64)
			nonce.Or(nonce, new(big.Int).SetUint64(g.sequences[strings.ToLower(sender.Hex())+"|"+key.String()]))
			return word(nonce), nil, true
		case selectorGetUserOpHash:
			op, err := decodeUserOpTuple(common.FromHex(args)[32:])
			if err != nil {
				t.Errorf("getUserOpHash calldata: %v", err)
				return nil, map[string]any{"code": 3, "message": "bad calldata"}, true
			}
			return op.hash(g.entryPoint, 1).Hex(), nil, true
		case selectorEntryPointBalance:
			return word(g.deposit), nil, true
		}
	case strings.ToLower(g.vault.Hex()):
		switch selector {
		case selectorVaultPaused:
			return word(boolWord(g.vaultPaused)), nil, true
		case selectorVaultPausedAt:
			return word(new(big.Int).SetUint64(g.pausedAt)), nil, true
		case selectorPendingWithdrawals:
			pending, ok := g.pending[uint32(arg(0).Uint64())]
			if !ok {
				return word(new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int), new(big.Int)), nil, true
			}
			return word(big.NewInt(1), new(big.Int), pending.nullifier, new(big.Int).SetUint64(pending.finalBalance), new(big.Int).SetBytes(pending.destination.Bytes()), new(big.Int).SetUint64(pending.deadline)), nil, true
		}
	}
	return nil, nil, false
}

func (g *gaslessFixture) owedOf(sender common.Address) *big.Int {
	if owed := g.owed[strings.ToLower(sender.Hex())]; owed != nil {
		return owed
	}
	return new(big.Int)
}

func (g *gaslessFixture) balanceOf(address common.Address) *big.Int {
	if balance := g.balances[strings.ToLower(address.Hex())]; balance != nil {
		return balance
	}
	return new(big.Int)
}

// decodeUserOpTuple decodes the ABI tuple of a packed operation (the
// inverse of gaslessUserOp.abiTuple).
func decodeUserOpTuple(tuple []byte) (*gaslessUserOp, error) {
	if len(tuple) < 9*32 {
		return nil, fmt.Errorf("short tuple")
	}
	word := func(i int) []byte { return tuple[i*32 : (i+1)*32] }
	op := &gaslessUserOp{Sender: common.BytesToAddress(word(0)), Nonce: new(big.Int).SetBytes(word(1))}
	var ok bool
	if op.InitCode, ok = abiBytesAt(tuple, 2); !ok {
		return nil, fmt.Errorf("initCode")
	}
	if op.CallData, ok = abiBytesAt(tuple, 3); !ok {
		return nil, fmt.Errorf("callData")
	}
	op.VerificationGasLimit, op.CallGasLimit = new(big.Int).SetBytes(word(4)[:16]).Uint64(), new(big.Int).SetBytes(word(4)[16:]).Uint64()
	op.PreVerificationGas = new(big.Int).SetBytes(word(5)).Uint64()
	op.MaxPriorityFeePerGas, op.MaxFeePerGas = new(big.Int).SetBytes(word(6)[:16]), new(big.Int).SetBytes(word(6)[16:])
	paymasterAndData, ok := abiBytesAt(tuple, 7)
	if !ok || len(paymasterAndData) != 64 {
		return nil, fmt.Errorf("paymasterAndData")
	}
	op.Paymaster = common.BytesToAddress(paymasterAndData[:20])
	op.PaymasterVerificationGasLimit, op.PaymasterPostOpGasLimit = new(big.Int).SetBytes(paymasterAndData[20:36]).Uint64(), new(big.Int).SetBytes(paymasterAndData[36:52]).Uint64()
	op.FeeCapWei = new(big.Int).SetBytes(paymasterAndData[52:64])
	if op.Signature, ok = abiBytesAt(tuple, 8); !ok {
		return nil, fmt.Errorf("signature")
	}
	return op, nil
}

// serveBundler is the httptest bundler.
func (g *gaslessFixture) serveBundler(t *testing.T, w http.ResponseWriter, r *http.Request) {
	t.Helper()
	g.f.mu.Lock()
	defer g.f.mu.Unlock()
	if g.down {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	var request struct {
		ID     int               `json:"id"`
		Method string            `json:"method"`
		Params []json.RawMessage `json:"params"`
	}
	if json.NewDecoder(r.Body).Decode(&request) != nil {
		t.Error("invalid bundler request")
		return
	}
	g.bundlerCalls = append(g.bundlerCalls, request.Method)
	reply := func(result any) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "result": result})
	}
	fail := func(code int, message string) {
		_ = json.NewEncoder(w).Encode(map[string]any{"jsonrpc": "2.0", "id": request.ID, "error": map[string]any{"code": code, "message": message}})
	}
	switch request.Method {
	case "eth_chainId":
		if g.wrongChain {
			reply("0xaa36a7")
			return
		}
		reply(g.f.chain)
	case "eth_supportedEntryPoints":
		if g.unsupportedEntryPoint {
			reply([]string{"0x0000000000000000000000000000000000000001"})
			return
		}
		reply([]string{g.entryPoint.Hex()})
	case "eth_estimateUserOperationGas":
		if g.estimate != nil {
			reply(g.estimate)
			return
		}
		// The estimate of the operation's kind: its call floor.
		var encoded gaslessUserOpJSON
		_ = json.Unmarshal(request.Params[0], &encoded)
		kind := gaslessKindForward
		if op, err := gaslessUserOpFromJSON(encoded); err == nil {
			if vaultCall, err := vaultCallOfTransitCallData(op.CallData); err == nil {
				switch len(vaultCall) {
				case withdrawalCalldataLength:
					kind = gaslessKindClose
					if hex.EncodeToString(vaultCall[:4]) == escapeSelector {
						kind = gaslessKindEscape
					}
				case 36:
					kind = gaslessKindFinalize
				}
			}
		}
		policy := g.profile.GasPolicy
		reply(map[string]string{"preVerificationGas": hexQuantityUint(policy.PVGFloor), "verificationGasLimit": hexQuantityUint(policy.VerificationFloorInit), "callGasLimit": hexQuantityUint(policy.CallFloor[kind-1]), "paymasterVerificationGasLimit": hexQuantityUint(policy.PMVerificationFloor), "paymasterPostOpGasLimit": hexQuantityUint(policy.PostOpFloor)})
	case "eth_sendUserOperation":
		if g.sendDown {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		var encoded gaslessUserOpJSON
		var entryPoint string
		if len(request.Params) != 2 || json.Unmarshal(request.Params[0], &encoded) != nil || json.Unmarshal(request.Params[1], &entryPoint) != nil || !strings.EqualFold(entryPoint, g.entryPoint.Hex()) {
			t.Error("invalid eth_sendUserOperation params")
			fail(-32602, "invalid params")
			return
		}
		op, err := gaslessUserOpFromJSON(encoded)
		if err != nil {
			t.Errorf("the bundler received an invalid operation: %v", err)
			fail(-32602, "invalid operation")
			return
		}
		hash := op.hash(g.entryPoint, 1).Hex()
		// Like the RPC's raw-transaction check: the operation must be in
		// the durable journal before it is sent.
		stored, err := os.ReadFile(g.f.h.addressStatePath())
		if err != nil {
			t.Error("operation sent before the durable journal")
		}
		var journal addressFundingRecord
		_ = json.Unmarshal(stored, &journal)
		if journal.Withdrawal == nil || journal.Withdrawal.UserOp == nil || !strings.EqualFold(journal.Withdrawal.UserOp.Hash, hash) {
			t.Errorf("the sent operation %s is not the journaled one", hash)
		}
		if !strings.EqualFold(op.Paymaster.Hex(), g.paymaster.Hex()) || len(op.Signature) != 65 {
			t.Error("the operation names another paymaster or carries no signature")
		}
		// ERC-7562 LIM-070: preVerificationGas covers the calldata cost of
		// the packed operation plus PRE_VERIFICATION_OVERHEAD_GAS.
		if minimum := calldataCost(op.abiTuple()) + 50_000; op.PreVerificationGas < minimum {
			fail(-32602, fmt.Sprintf("preVerificationGas too low: expected at least %d", minimum))
			return
		}
		if g.refuse || (g.refuseResend && g.ops[hash].Sender != "") {
			message := g.refuseMessage
			if message == "" {
				message = "replacement op must increase maxFeePerGas and maxPriorityFeePerGas"
			}
			fail(-32507, message)
			return
		}
		if _, exists := g.codes[strings.ToLower(op.Sender.Hex())]; len(op.InitCode) != 0 && (exists || g.accountSeen) {
			fail(-32500, "AA10 sender already constructed")
			return
		}
		g.ops[hash] = encoded
		g.sends = append(g.sends, hash)
		g.known[hash] = true
		if g.forgeHash {
			reply("0x" + strings.Repeat("f", 64))
			return
		}
		reply(hash)
	case "eth_getUserOperationByHash":
		var hash string
		_ = json.Unmarshal(request.Params[0], &hash)
		if g.known[strings.ToLower(hash)] || g.known[hash] {
			reply(map[string]any{"userOperation": g.ops[hash], "entryPoint": g.entryPoint.Hex(), "transactionHash": nil})
			return
		}
		reply(nil)
	case "eth_getUserOperationReceipt":
		var hash string
		_ = json.Unmarshal(request.Params[0], &hash)
		if g.forgedReceiptTransaction != "" {
			reply(map[string]any{"userOpHash": hash, "success": true, "receipt": map[string]any{"transactionHash": g.forgedReceiptTransaction}})
			return
		}
		if tx, ok := g.bundlerReceipts[hash]; ok {
			reply(map[string]any{"userOpHash": hash, "success": true, "receipt": map[string]any{"transactionHash": tx}})
			return
		}
		reply(nil)
	default:
		t.Errorf("unexpected bundler method %s", request.Method)
		fail(-32601, "unknown method")
	}
}

// fixtureSettlement is what the paymaster's postOp did for a mined
// operation.
type fixtureSettlement struct {
	Received, Charged, OwedPaid, PaidOut *big.Int
	// Credited, when set, is a PayoutCredited of the payee (the push failed).
	Credited *big.Int
}

// mineUserOp includes the sent operation hash in a bundle transaction: a
// successful one carries the vault's exit log (the proof destination is the
// transit account), the paymaster's Settled (or PayoutCredited) and the
// EntryPoint's UserOperationEvent; a reverted one carries the revert reason
// and SponsorshipFailed, and strands the transit account. The bundle
// transaction's hash is returned.
func (g *gaslessFixture) mineUserOp(t *testing.T, hash string, success bool, settlement fixtureSettlement) string {
	t.Helper()
	g.f.mu.Lock()
	defer g.f.mu.Unlock()
	encoded, ok := g.ops[hash]
	if !ok {
		t.Fatalf("operation %s was not sent", hash)
	}
	op, err := gaslessUserOpFromJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	vaultCall, err := vaultCallOfTransitCallData(op.CallData)
	if err != nil {
		t.Fatal(err)
	}
	kind := gaslessKindForward
	noteID := uint32(0xffffffff)
	nullifier := new(big.Int)
	finalBalance := uint64(0)
	if recorded := g.escapeNote[strings.ToLower(op.Sender.Hex())]; recorded != 0 {
		noteID = uint32(recorded - 1)
	}
	switch len(vaultCall) {
	case withdrawalCalldataLength:
		noteID = uint32(new(big.Int).SetBytes(vaultCall[4+8*32 : 4+9*32]).Uint64())
		finalBalance = new(big.Int).SetBytes(vaultCall[4+9*32 : 4+10*32]).Uint64()
		nullifier.SetBytes(vaultCall[4+11*32 : 4+12*32])
		kind = gaslessKindClose
		if hex.EncodeToString(vaultCall[:4]) == escapeSelector {
			kind = gaslessKindEscape
		}
	case 36:
		noteID = uint32(new(big.Int).SetBytes(vaultCall[4:36]).Uint64())
		kind = gaslessKindFinalize
		nullifier = g.pending[noteID].nullifier
	}
	sender := op.Sender
	payee := common.HexToAddress(withdrawalTestDestination)
	key := gaslessKey(kind, nullifier, noteID, sender)
	g.attempts[key.Hex()[2:]]++
	g.known[hash] = false
	if len(op.InitCode) != 0 {
		g.codes[strings.ToLower(sender.Hex())] = g.vectors.TransitRuntimeCode
	}
	g.sequences[strings.ToLower(sender.Hex())+"|"+new(big.Int).Rsh(op.Nonce, 64).String()]++
	bundle := crypto.Keccak256Hash(common.FromHex(hash)).Hex()
	zero := func(v *big.Int) *big.Int {
		if v == nil {
			return new(big.Int)
		}
		return v
	}
	settlement.Received, settlement.Charged, settlement.OwedPaid, settlement.PaidOut = zero(settlement.Received), zero(settlement.Charged), zero(settlement.OwedPaid), zero(settlement.PaidOut)
	successWord := new(big.Int)
	if success {
		successWord.SetInt64(1)
	}
	event := map[string]any{"address": g.entryPoint.Hex(), "topics": []string{userOperationEventTopic, hash, "0x" + addressWord(sender), "0x" + addressWord(g.paymaster)}, "data": "0x" + wordHex(op.Nonce) + wordHex(successWord) + wordHex(settlement.Charged) + uintWord(400_000), "transactionHash": bundle, "blockNumber": "0x10"}
	logs := []map[string]any{event}
	settled := func() map[string]any {
		return map[string]any{"address": g.paymaster.Hex(), "topics": []string{paymasterSettledTopic, key.Hex(), "0x" + addressWord(sender), "0x" + addressWord(payee)}, "data": "0x" + uintWord(uint64(kind)) + uintWord(uint64(noteID)) + wordHex(settlement.Received) + wordHex(settlement.Charged) + wordHex(settlement.OwedPaid) + wordHex(settlement.PaidOut)}
	}
	if success {
		switch kind {
		case gaslessKindClose:
			logs = append(logs, map[string]any{"address": g.vault.Hex(), "topics": []string{withdrawalEventTopic, fmt.Sprintf("0x%064x", noteID)}, "data": "0x" + wordHex(nullifier) + uintWord(finalBalance) + addressWord(sender)})
			g.f.closeNote(noteID)
		case gaslessKindEscape:
			g.owed[strings.ToLower(sender.Hex())] = new(big.Int).Add(g.owedOf(sender), settlement.Charged)
			g.escapeNote[strings.ToLower(sender.Hex())] = uint64(noteID) + 1
			g.escapeSponsored[noteID] = true
			g.pending[noteID] = fixturePending{nullifier: nullifier, finalBalance: finalBalance, destination: sender}
			note := g.f.vaultNotes[noteID]
			note.status = notePendingWithdrawal
			g.f.vaultNotes[noteID] = note
			logs = append(logs, map[string]any{"address": g.paymaster.Hex(), "topics": []string{paymasterEscapeOwedTopic, "0x" + addressWord(sender), fmt.Sprintf("0x%064x", noteID)}, "data": "0x" + wordHex(settlement.Charged)})
		case gaslessKindFinalize:
			pending := g.pending[noteID]
			logs = append(logs, map[string]any{"address": g.vault.Hex(), "topics": []string{escapeFinalizedEventTopic, fmt.Sprintf("0x%064x", noteID)}, "data": "0x" + wordHex(pending.nullifier) + uintWord(pending.finalBalance) + addressWord(sender)})
			delete(g.pending, noteID)
			delete(g.escapeNote, strings.ToLower(sender.Hex()))
			g.owed[strings.ToLower(sender.Hex())] = new(big.Int).Sub(g.owedOf(sender), settlement.OwedPaid)
			g.f.closeNote(noteID)
		case gaslessKindForward:
			g.balances[strings.ToLower(sender.Hex())] = new(big.Int)
			delete(g.stranded, strings.ToLower(sender.Hex()))
			delete(g.escapeNote, strings.ToLower(sender.Hex()))
			g.owed[strings.ToLower(sender.Hex())] = new(big.Int).Sub(g.owedOf(sender), settlement.OwedPaid)
		}
		if settlement.Credited != nil {
			credit := g.credits[strings.ToLower(payee.Hex())]
			if credit == nil {
				credit = new(big.Int)
			}
			g.credits[strings.ToLower(payee.Hex())] = new(big.Int).Add(credit, settlement.Credited)
			logs = append(logs, map[string]any{"address": g.paymaster.Hex(), "topics": []string{paymasterPayoutCreditedTopic, "0x" + addressWord(payee)}, "data": "0x" + wordHex(settlement.Credited)})
		}
		logs = append(logs, settled())
	} else {
		reason, _ := hex.DecodeString(selectorVaultCallFailed + addressABIWord("20") + addressABIWord("4") + hex.EncodeToString(common.RightPadBytes(common.FromHex(selectorOf("NoteNotActive()")), 32)))
		logs = append(logs, map[string]any{"address": g.entryPoint.Hex(), "topics": []string{userOperationRevertReasonTopic, hash, "0x" + addressWord(sender)}, "data": "0x" + wordHex(op.Nonce) + addressABIWord("40") + uintWord(uint64(len(reason))) + hex.EncodeToString(common.RightPadBytes(reason, (len(reason)+31)/32*32))})
		logs = append(logs, map[string]any{"address": g.paymaster.Hex(), "topics": []string{paymasterSponsorshipFailedTopic, key.Hex(), "0x" + addressWord(sender)}, "data": "0x" + uintWord(uint64(kind)) + uintWord(uint64(noteID)) + wordHex(settlement.Charged)})
		if kind == gaslessKindClose || kind == gaslessKindFinalize {
			g.stranded[strings.ToLower(sender.Hex())] = true
		}
	}
	g.f.receipts[bundle] = map[string]any{"transactionHash": bundle, "status": "0x1", "blockNumber": "0x10", "blockHash": g.f.canonical, "to": g.entryPoint.Hex(), "logs": logs}
	g.opLogs = append(g.opLogs, event)
	g.bundlerReceipts[hash] = bundle
	return bundle
}

// fixtureFailedOp is the hex of FailedOp(0, reason).
func fixtureFailedOp(reason string) string {
	return selectorFailedOp + uintWord(0) + addressABIWord("40") + uintWord(uint64(len(reason))) + hex.EncodeToString(common.RightPadBytes([]byte(reason), (len(reason)+31)/32*32))
}
