package zkapi

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// transitVectors is protocol/contracts/test/fixtures/transit-vectors.json,
// the cross-language vectors of the gasless path: every unsigned integer is
// a decimal string, every address, hash and byte string a 0x hex string.
type transitVectors struct {
	ChainID                 string            `json:"chain_id"`
	EntryPoint              string            `json:"entry_point"`
	EntryPointCodehash      string            `json:"entry_point_codehash"`
	SenderCreator           string            `json:"sender_creator"`
	SenderCreatorCodehash   string            `json:"sender_creator_codehash"`
	Vault                   string            `json:"vault"`
	Paymaster               string            `json:"paymaster"`
	Factory                 string            `json:"factory"`
	Owner                   string            `json:"owner"`
	OwnerPrivateKey         string            `json:"owner_private_key"`
	Payee                   string            `json:"payee"`
	TransitAccount          string            `json:"transit_account"`
	AccountCreationCode     string            `json:"account_creation_code"`
	AccountCreationCodeHash string            `json:"account_creation_code_keccak256"`
	TransitRuntimeCode      string            `json:"transit_runtime_code"`
	ForwardNonceKey         string            `json:"forward_nonce_key"`
	Keys                    map[string]string `json:"keys"`
	Close                   struct {
		NoteID                        string `json:"note_id"`
		FinalBalance                  string `json:"final_balance"`
		Nullifier                     string `json:"nullifier"`
		VaultCalldata                 string `json:"vault_calldata"`
		CallData                      string `json:"call_data"`
		InitCode                      string `json:"init_code"`
		Sender                        string `json:"sender"`
		Nonce                         string `json:"nonce"`
		NonceKey                      string `json:"nonce_key"`
		NonceSequence                 string `json:"nonce_sequence"`
		AccountGasLimits              string `json:"account_gas_limits"`
		VerificationGasLimit          string `json:"verification_gas_limit"`
		CallGasLimit                  string `json:"call_gas_limit"`
		PreVerificationGas            string `json:"pre_verification_gas"`
		GasFees                       string `json:"gas_fees"`
		MaxFeePerGas                  string `json:"max_fee_per_gas"`
		MaxPriorityFeePerGas          string `json:"max_priority_fee_per_gas"`
		PaymasterAndData              string `json:"paymaster_and_data"`
		PaymasterVerificationGasLimit string `json:"paymaster_verification_gas_limit"`
		PaymasterPostOpGasLimit       string `json:"paymaster_post_op_gas_limit"`
		FeeCapWei                     string `json:"fee_cap_wei"`
		MaxCost                       string `json:"max_cost"`
		UserOpHash                    string `json:"user_op_hash"`
		EIP191Digest                  string `json:"eip191_digest"`
		SignatureR                    string `json:"signature_r"`
		SignatureS                    string `json:"signature_s"`
		SignatureV                    string `json:"signature_v"`
		Signature                     string `json:"signature"`
		ValidUntil                    string `json:"valid_until"`
	} `json:"close"`
	ChargeSamples []struct {
		Kind             string `json:"kind"`
		ActualGas        string `json:"actual_gas"`
		ExecutionGasUsed string `json:"execution_gas_used"`
		CallGasLimit     string `json:"call_gas_limit"`
		PostOpGasLimit   string `json:"post_op_gas_limit"`
		PayeeHasCode     bool   `json:"payee_has_code"`
		PayeeIsEmpty     bool   `json:"payee_is_empty"`
		FeePerGas        string `json:"fee_per_gas"`
		ChargeWei        string `json:"charge_wei"`
	} `json:"charge_samples"`
	GasPolicy json.RawMessage `json:"gas_policy"`
	Policy    struct {
		BaseFee            string `json:"base_fee"`
		EscapesEnabled     bool   `json:"escapes_enabled"`
		FlatFeeWei         string `json:"flat_fee_wei"`
		MaxFeeCeiling      string `json:"max_fee_ceiling"`
		MaxSponsoredCost   string `json:"max_sponsored_cost"`
		MinEscapeNetWei    string `json:"min_escape_net_wei"`
		PriorityFeeCeiling string `json:"priority_fee_ceiling"`
	} `json:"policy"`
}

func loadTransitVectors(t *testing.T) transitVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "protocol", "contracts", "test", "fixtures", "transit-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors transitVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

func vectorUint(t *testing.T, value string) *big.Int {
	t.Helper()
	n, ok := new(big.Int).SetString(value, 10)
	if !ok {
		t.Fatalf("not a decimal vector: %q", value)
	}
	return n
}

func vectorBytes(t *testing.T, value string) []byte {
	t.Helper()
	raw, err := hex.DecodeString(strings.TrimPrefix(value, "0x"))
	if err != nil {
		t.Fatalf("not a hex vector: %q", value)
	}
	return raw
}

// vectorOp is the vectors' complete close operation, built from its fields.
func vectorOp(t *testing.T, v transitVectors) *gaslessUserOp {
	t.Helper()
	return &gaslessUserOp{
		Sender: common.HexToAddress(v.Close.Sender), Nonce: vectorUint(t, v.Close.Nonce), InitCode: vectorBytes(t, v.Close.InitCode), CallData: vectorBytes(t, v.Close.CallData),
		CallGasLimit: vectorUint(t, v.Close.CallGasLimit).Uint64(), VerificationGasLimit: vectorUint(t, v.Close.VerificationGasLimit).Uint64(), PreVerificationGas: vectorUint(t, v.Close.PreVerificationGas).Uint64(),
		MaxFeePerGas: vectorUint(t, v.Close.MaxFeePerGas), MaxPriorityFeePerGas: vectorUint(t, v.Close.MaxPriorityFeePerGas), Paymaster: common.HexToAddress(v.Paymaster),
		PaymasterVerificationGasLimit: vectorUint(t, v.Close.PaymasterVerificationGasLimit).Uint64(), PaymasterPostOpGasLimit: vectorUint(t, v.Close.PaymasterPostOpGasLimit).Uint64(),
		FeeCapWei: vectorUint(t, v.Close.FeeCapWei), Signature: vectorBytes(t, v.Close.Signature),
	}
}

// Design 3.1 and 5.3: every derivation of the gasless path, byte-checked
// against the cross-language vectors: the transit account, the init code,
// the calldata, the packed fields, the nonce, the userOpHash from the etched
// EntryPoint, the EIP-191 digest and signature, the attempt keys, the FORWARD
// nonce key, the charge formula and the gas policy.
func TestGaslessDerivationsFollowTheTransitVectors(t *testing.T) {
	v := loadTransitVectors(t)
	creation := vectorBytes(t, v.AccountCreationCode)
	if crypto.Keccak256Hash(creation).Hex() != v.AccountCreationCodeHash {
		t.Fatal("the creation code does not hash to its pin")
	}
	factory, entryPoint, vault, paymaster := common.HexToAddress(v.Factory), common.HexToAddress(v.EntryPoint), common.HexToAddress(v.Vault), common.HexToAddress(v.Paymaster)
	owner, payee := common.HexToAddress(v.Owner), common.HexToAddress(v.Payee)
	if got := transitAccountAddress(factory, creation, entryPoint, vault, paymaster, owner, payee); got != common.HexToAddress(v.TransitAccount) {
		t.Fatalf("transit account %s, want %s", got.Hex(), v.TransitAccount)
	}
	if hex.EncodeToString(transitInitCode(factory, owner, payee)) != strings.TrimPrefix(v.Close.InitCode, "0x") {
		t.Fatal("init code differs from the vector")
	}
	vaultCall := vectorBytes(t, v.Close.VaultCalldata)
	if len(vaultCall) != withdrawalCalldataLength || hex.EncodeToString(vaultCall[:4]) != withdrawalSelector {
		t.Fatal("the vector's vault call is not a mutualClose")
	}
	callData := transitCallData(vaultCall)
	if hex.EncodeToString(callData) != strings.TrimPrefix(v.Close.CallData, "0x") {
		t.Fatal("withdraw(bytes) calldata differs from the vector")
	}
	if inner, err := vaultCallOfTransitCallData(callData); err != nil || hex.EncodeToString(inner) != hex.EncodeToString(vaultCall) {
		t.Fatalf("the vault call was not recovered from the calldata: %v", err)
	}
	for _, mutate := range []func([]byte) []byte{
		func(d []byte) []byte { return d[:len(d)-1] },
		func(d []byte) []byte { return append(d, 0) },
		func(d []byte) []byte { c := append([]byte{}, d...); c[len(c)-1] = 1; return c },
		func(d []byte) []byte { c := append([]byte{}, d...); c[35] = 0x40; return c },
	} {
		if _, err := vaultCallOfTransitCallData(mutate(callData)); err == nil {
			t.Fatal("a malformed withdraw(bytes) layout was accepted")
		}
	}
	// The owner key signs; the vector's owner is its address.
	key, err := crypto.ToECDSA(common.LeftPadBytes(vectorUint(t, v.OwnerPrivateKey).Bytes(), 32))
	if err != nil || crypto.PubkeyToAddress(key.PublicKey) != owner {
		t.Fatalf("the vector's owner key does not give its owner: %v", err)
	}
	op := vectorOp(t, v)
	if hex.EncodeToString(op.accountGasLimits()) != strings.TrimPrefix(v.Close.AccountGasLimits, "0x") {
		t.Fatal("accountGasLimits packing differs")
	}
	if hex.EncodeToString(op.gasFees()) != strings.TrimPrefix(v.Close.GasFees, "0x") {
		t.Fatal("gasFees packing differs")
	}
	if hex.EncodeToString(op.paymasterAndData()) != strings.TrimPrefix(v.Close.PaymasterAndData, "0x") {
		t.Fatal("paymasterAndData packing differs")
	}
	if op.maxCost().String() != v.Close.MaxCost {
		t.Fatalf("maxCost %s, want %s", op.maxCost(), v.Close.MaxCost)
	}
	nullifier := vectorUint(t, v.Close.Nullifier)
	if gaslessNonceKey(gaslessKindClose, nullifier).String() != v.Close.NonceKey {
		t.Fatal("the close nonce key is not the nullifier")
	}
	nonce := new(big.Int).Lsh(gaslessNonceKey(gaslessKindClose, nullifier), 64)
	nonce.Or(nonce, vectorUint(t, v.Close.NonceSequence))
	if nonce.String() != v.Close.Nonce {
		t.Fatalf("nonce %s, want %s", nonce, v.Close.Nonce)
	}
	chainID := vectorUint(t, v.ChainID).Uint64()
	hash := op.hash(entryPoint, chainID)
	if hash.Hex() != v.Close.UserOpHash {
		t.Fatalf("userOpHash %s, want %s", hash.Hex(), v.Close.UserOpHash)
	}
	if eip191Digest(hash).Hex() != v.Close.EIP191Digest {
		t.Fatal("the EIP-191 digest differs")
	}
	signature, err := signUserOpHash(hash, key)
	if err != nil || hex.EncodeToString(signature) != strings.TrimPrefix(v.Close.Signature, "0x") {
		t.Fatalf("signature %x differs from the vector: %v", signature, err)
	}
	if hex.EncodeToString(signature[:32]) != strings.TrimPrefix(v.Close.SignatureR, "0x") || hex.EncodeToString(signature[32:64]) != strings.TrimPrefix(v.Close.SignatureS, "0x") || vectorUint(t, v.Close.SignatureV).Uint64() != uint64(signature[64]) {
		t.Fatal("r, s or v differs from the vector")
	}
	if signer, err := recoverUserOpSigner(hash, signature); err != nil || signer != owner {
		t.Fatalf("recovered %s: %v", signer.Hex(), err)
	}
	if _, err := recoverUserOpSigner(hash, signature[:64]); err == nil {
		t.Fatal("a 64-byte signature recovered")
	}
	// Keys.
	noteID := uint32(vectorUint(t, v.Close.NoteID).Uint64())
	sender := common.HexToAddress(v.TransitAccount)
	for name, want := range map[string]common.Hash{
		"close": gaslessKey(gaslessKindClose, nullifier, 0, common.Address{}), "escape": gaslessKey(gaslessKindEscape, nil, noteID, common.Address{}),
		"finalize": gaslessKey(gaslessKindFinalize, nil, noteID, common.Address{}), "forward": gaslessKey(gaslessKindForward, nil, 0, sender),
	} {
		if want.Hex() != v.Keys[name] {
			t.Errorf("key %s: %s, want %s", name, want.Hex(), v.Keys[name])
		}
	}
	if gaslessForwardNonceKey.String() != v.ForwardNonceKey || gaslessNonceKey(gaslessKindForward, nullifier).String() != v.ForwardNonceKey {
		t.Fatal("the FORWARD nonce key differs")
	}
	// The gas policy and the charge formula.
	var policy gaslessGasPolicy
	if err := json.Unmarshal(v.GasPolicy, &policy); err != nil {
		t.Fatal(err)
	}
	if policy.CallFloor != [4]uint64{540000, 540000, 250000, 80000} || policy.CallCap != [4]uint64{950000, 1100000, 400000, 150000} || policy.PostOpFloor != 250000 || policy.MaxAttempts != 3 || policy.FinalizeReserveGas != 990000 {
		t.Fatalf("gas policy parsed as %+v", policy)
	}
	for i, sample := range v.ChargeSamples {
		got := gaslessChargeFor(policy, uint8(vectorUint(t, sample.Kind).Uint64()), vectorUint(t, sample.ActualGas).Uint64(), vectorUint(t, sample.ExecutionGasUsed).Uint64(), vectorUint(t, sample.CallGasLimit).Uint64(), vectorUint(t, sample.PostOpGasLimit).Uint64(), sample.PayeeHasCode, sample.PayeeIsEmpty, vectorUint(t, sample.FeePerGas))
		if got.String() != sample.ChargeWei {
			t.Errorf("charge sample %d: %s, want %s", i, got, sample.ChargeWei)
		}
	}
	// The defaults derived for a profile without explicit ones are the limits
	// the vectors' operation carries.
	filled, err := policy.withDefaults()
	if err != nil {
		t.Fatal(err)
	}
	if filled.CallDefault[0] != op.CallGasLimit || filled.VerificationDefaultInit != op.VerificationGasLimit || filled.PMVerificationDefault != op.PaymasterVerificationGasLimit || filled.PostOpDefault != op.PaymasterPostOpGasLimit {
		t.Fatalf("derived defaults %+v differ from the vector's limits %+v", filled, op)
	}
	// The policy words are what gasPolicy() returns, in its order.
	if words := filled.words(); len(words) != 30 || words[0] != 540000 || words[8] != 250000 || words[29] != 3 {
		t.Fatalf("policy words %v", words)
	}
}

// The unpacked JSON form carries the v0.7 field names of
// eth_sendUserOperation, and parses back to the same bytes and hash.
func TestGaslessUserOpJSONRoundTripsWithTheBundlerFieldNames(t *testing.T) {
	v := loadTransitVectors(t)
	op := vectorOp(t, v)
	encoded, err := json.Marshal(op.toJSON())
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	if err := json.Unmarshal(encoded, &fields); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sender", "nonce", "factory", "factoryData", "callData", "callGasLimit", "verificationGasLimit", "preVerificationGas", "maxFeePerGas", "maxPriorityFeePerGas", "paymaster", "paymasterVerificationGasLimit", "paymasterPostOpGasLimit", "paymasterData", "signature"} {
		if _, present := fields[name]; !present {
			t.Errorf("field %s missing from %s", name, encoded)
		}
	}
	if len(fields) != 15 || fields["factory"] != common.HexToAddress(v.Factory).Hex() || fields["nonce"] != "0x"+vectorUint(t, v.Close.Nonce).Text(16) || fields["callGasLimit"] != "0x9cdc4" || fields["paymasterData"] != "0x00000000000009184e72a000" {
		t.Fatalf("unexpected encoding %s", encoded)
	}
	var decoded gaslessUserOpJSON
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}
	parsed, err := gaslessUserOpFromJSON(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.hash(common.HexToAddress(v.EntryPoint), vectorUint(t, v.ChainID).Uint64()).Hex() != v.Close.UserOpHash || hex.EncodeToString(parsed.abiTuple()) != hex.EncodeToString(op.abiTuple()) {
		t.Fatal("the parsed operation differs from the original")
	}
	// Without initCode the factory fields are omitted and parse back empty.
	op.InitCode = nil
	encoded, _ = json.Marshal(op.toJSON())
	if strings.Contains(string(encoded), "factory") {
		t.Fatal("an operation without initCode names a factory")
	}
	var bare gaslessUserOpJSON
	_ = json.Unmarshal(encoded, &bare)
	if parsed, err := gaslessUserOpFromJSON(bare); err != nil || len(parsed.InitCode) != 0 {
		t.Fatalf("parsed init code %x: %v", parsed.InitCode, err)
	}
	for name, mutate := range map[string]func(*gaslessUserOpJSON){
		"padded quantity":      func(j *gaslessUserOpJSON) { j.CallGasLimit = "0x0a7d8c" },
		"short paymaster data": func(j *gaslessUserOpJSON) { j.PaymasterData = "0x00" },
		"bad sender":           func(j *gaslessUserOpJSON) { j.Sender = "0x12" },
		"fee over 128 bits":    func(j *gaslessUserOpJSON) { j.MaxFeePerGas = "0x1" + strings.Repeat("0", 32) },
	} {
		bad := decoded
		mutate(&bad)
		if _, err := gaslessUserOpFromJSON(bad); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// The selectors and topics are derived from the committed contracts'
// signatures; a few are checked against their known values.
func TestGaslessSelectorsAndTopicsMatchTheContracts(t *testing.T) {
	for signatureSelector, want := range map[string]string{
		selectorGetUserOpHash: "22cdde4c", selectorHandleOps: "765e827f", selectorGetNonce: "35567e1a", selectorTransitWithdraw: "0968f264", selectorTransitSweep: "35faa416",
		selectorCreateAccount: "133572ba", selectorFactoryGetAddress: "5191620b", selectorAccountCreationCodeHash: "08a1a807", selectorFactoryPaymaster: "16e4cbf9",
		selectorGasPolicy: "3a5dbdc2", selectorPaymasterQuote: "e948303d", selectorClaimCredit: "60e27464", selectorOwed: "df18e047", selectorAttempts: "f6829c37",
		selectorStranded: "97b69f6a", selectorEscapeNotePlusOne: "c72bb484", selectorCredits: "fe5ff468", selectorPaymasterPolicy: "0505c8c9", selectorMaxFeeCeiling: "981df567",
		selectorPriorityFeeCeiling: "c8fcbcdd", selectorCallCap: "6e202337", selectorWeiPerUnit: "a3bea703", selectorPaymasterFactory: "c45a0155", selectorPaymasterVault: "fbfa77cf",
		selectorPaymasterEntryPoint: "b0d691fe", selectorEntryPointBalance: "70a08231", selectorVaultPaused: "5c975abb",
	} {
		if signatureSelector != want {
			t.Errorf("selector %s, want %s", signatureSelector, want)
		}
	}
	for topic, want := range map[string]string{
		paymasterSettledTopic:           "0xd42d05cc535635a5dda37221df3418f706f9917ccea103d9b084ec88c57493d7",
		paymasterPayoutCreditedTopic:    "0xfa0ea8a012f094d1b6f48df9238391dcbfbbda9acf72c5fa9b26c32451e98a61",
		paymasterSponsorshipFailedTopic: "0x96b6440447f40d6d398b5b5c86e4fbe9444a326945cbbd866acd96b8d71f9bde",
		paymasterCollectedTopic:         "0x91b3a0728743b4fa9ade16f0aa193f1e25f6ecd35942b9dfb43a7c6eac383955",
		paymasterCreditClaimedTopic:     "0x87e12c2565042763daa6bf5842ed2b6447f17f7e28f9a4905fe3959581396ead",
		userOperationEventTopic:         "0x49628fd1471006c1482da88028e9ce4dbb080b815c9b0344d39e5a8e6ec1419f",
	} {
		if topic != want {
			t.Errorf("topic %s, want %s", topic, want)
		}
	}
	if gaslessErrorNames[selectorOf("NoteNotActive()")] != "NoteNotActive" || gaslessErrorNames[selectorOf("PayoutBelowCost(uint256,uint256)")] != "PayoutBelowCost" {
		t.Fatal("error names missing")
	}
}

// FailedOp and FailedOpWithRevert of the EntryPoint decode to the AA code
// and the inner error name, with a VaultCallFailed wrapper unwrapped.
func TestGaslessAAFailuresDecode(t *testing.T) {
	word := func(n int) string { return addressABIWord(new(big.Int).SetInt64(int64(n)).Text(16)) }
	text := func(s string) string {
		return word(len(s)) + hex.EncodeToString(common.RightPadBytes([]byte(s), 32))
	}
	plain := selectorFailedOp + word(0) + word(0x40) + text("AA25 invalid account nonce")
	raw, _ := hex.DecodeString(plain)
	failure, ok := decodeAAFailure(raw)
	if !ok || failure.Code != "AA25" || failure.Inner != "" || failure.String() != "AA25 invalid account nonce" {
		t.Fatalf("plain failure: %+v %v", failure, ok)
	}
	inner := selectorOf("PayoutBelowCost(uint256,uint256)") + word(5) + word(3)
	innerBytes, _ := hex.DecodeString(inner)
	withRevert := selectorFailedOpWithRevert + word(0) + word(0x60) + word(0xa0) + text("AA33 reverted") + word(len(innerBytes)) + hex.EncodeToString(common.RightPadBytes(innerBytes, 96))
	raw, _ = hex.DecodeString(withRevert)
	failure, ok = decodeAAFailure(raw)
	if !ok || failure.Code != "AA33" || failure.Inner != "PayoutBelowCost" {
		t.Fatalf("inner failure: %+v %v", failure, ok)
	}
	// A vault revert bubbled through S's VaultCallFailed(bytes).
	vaultError, _ := hex.DecodeString(selectorOf("NoteNotActive()"))
	wrapped, _ := hex.DecodeString(selectorVaultCallFailed + word(0x20) + word(4) + hex.EncodeToString(common.RightPadBytes(vaultError, 32)))
	if name := gaslessErrorName(wrapped); name != "VaultCallFailed:NoteNotActive" {
		t.Fatalf("wrapped error named %q", name)
	}
	if _, ok := decodeAAFailure([]byte{1, 2, 3}); ok {
		t.Fatal("garbage decoded")
	}
	if _, ok := decodeAAFailure(append(raw[:4], 0)); ok {
		t.Fatal("a truncated failure decoded")
	}
}

// The gas policy accepts the profile's snake_case names, the vectors' and
// the manifest's camelCase spellings, numbers as JSON numbers or decimal
// strings, and derives or checks the client defaults.
func TestGaslessGasPolicyParsesEverySpellingAndChecksDefaults(t *testing.T) {
	for name, text := range map[string]string{
		"design":   `{"call_floor":[1,2,3,4],"call_cap":[10,20,30,40],"call_default":[5,6,7,8],"postop_floor":100,"postop_cap":200,"postop_default":150,"verification_floor":1,"verification_floor_init":2,"verification_cap":9,"verification_default":3,"verification_default_init":4,"pvg_floor":1,"pvg_cap":2,"pm_verification_floor":1,"pm_verification_cap":5,"pm_verification_default":2,"postop_base_gas":1,"eoa_push_gas":1,"payout_push_gas":1,"account_call_overhead_gas":1,"margin_gas":1,"finalize_reserve_gas":7,"max_attempts":3}`,
		"vectors":  `{"call_floor":["1","2","3","4"],"call_hard_cap":["10","20","30","40"],"post_op_floor":"100","post_op_cap":"200","verification_floor":"1","verification_floor_init":"2","verification_cap":"9","pvg_floor":"1","pvg_cap":"2","pm_verification_floor":"1","pm_verification_cap":"5","post_op_base_gas":"1","eoa_push_gas":"1","payout_push_gas":"1","account_call_overhead_gas":"1","margin_gas":"1","finalize_reserve_gas":"7","max_attempts":"3"}`,
		"manifest": `{"callFloor":[1,2,3,4],"callHardCap":[10,20,30,40],"postOpFloor":100,"postOpCap":200,"verificationFloor":1,"verificationFloorInit":2,"verificationCap":9,"pvgFloor":1,"pvgCap":2,"pmVerificationFloor":1,"pmVerificationCap":5,"postOpBaseGas":1,"eoaPushGas":1,"payoutPushGas":1,"accountCallOverheadGas":1,"marginGas":1,"finalizeReserveGas":7,"maxAttempts":3}`,
	} {
		var policy gaslessGasPolicy
		if err := json.Unmarshal([]byte(text), &policy); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if policy.CallFloor != [4]uint64{1, 2, 3, 4} || policy.CallCap != [4]uint64{10, 20, 30, 40} || policy.PostOpFloor != 100 || policy.PostOpCap != 200 || policy.FinalizeReserveGas != 7 || policy.MaxAttempts != 3 {
			t.Fatalf("%s parsed as %+v", name, policy)
		}
		filled, err := policy.withDefaults()
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if name == "design" {
			if filled.CallDefault != [4]uint64{5, 6, 7, 8} || filled.PostOpDefault != 150 || filled.VerificationDefault != 3 {
				t.Fatalf("explicit defaults replaced: %+v", filled)
			}
		} else if filled.CallDefault != [4]uint64{3, 6, 9, 13} || filled.PostOpDefault != 200 || filled.VerificationDefault != 9 || filled.VerificationDefaultInit != 9 || filled.PMVerificationDefault != 5 {
			t.Fatalf("derived defaults %+v", filled)
		}
		encoded, err := json.Marshal(filled)
		if err != nil {
			t.Fatal(err)
		}
		var again gaslessGasPolicy
		if err := json.Unmarshal(encoded, &again); err != nil || again != filled {
			t.Fatalf("the policy did not round-trip: %v", err)
		}
	}
	var bad gaslessGasPolicy
	_ = json.Unmarshal([]byte(`{"call_floor":[1,2,3,4],"call_cap":[10,20,30,40],"call_default":[11,6,7,8],"pvg_floor":1,"pvg_cap":2,"finalize_reserve_gas":7,"max_attempts":3}`), &bad)
	if _, err := bad.withDefaults(); err == nil {
		t.Fatal("a default above its cap accepted")
	}
	if err := json.Unmarshal([]byte(`{"call_floor":[1,2,3]}`), &bad); err == nil {
		t.Fatal("a three-entry array accepted")
	}
}

// The bundler URL follows the exit RPC's rules.
func TestValidateBundlerURL(t *testing.T) {
	for _, url := range []string{"http://bundler.example", "ftp://127.0.0.1", "https://user:pass@bundler.example", "https://bundler.example/?key=1", "https://bundler.example/#x", ""} {
		if ValidateBundlerURL(url) == nil {
			t.Errorf("accepted bundler URL %q", url)
		}
	}
	for _, url := range []string{"https://bundler.example/rpc", "http://127.0.0.1:4337", "http://localhost:4337", "http://[::1]:4337"} {
		if err := ValidateBundlerURL(url); err != nil {
			t.Errorf("refused bundler URL %s: %v", url, err)
		}
	}
}

// ----------------------------------------------------------- the close flow

// gaslessTestBalance is the private balance of the gasless fixtures (0.1
// ETH): large enough for the sponsored fee at the fixture's 1 gwei base fee
// to stay under the profile's uneconomic fraction.
const gaslessTestBalance = 100_000_000

func newGaslessWithdrawalFixture(t *testing.T) (*withdrawalFixture, *gaslessFixture) {
	t.Helper()
	f := newWithdrawalFixture(t, true)
	g := f.enableGasless(t)
	f.walletBalance, f.planBalance = gaslessTestBalance, gaslessTestBalance
	return f, g
}

func payoutContext(options addressWithdrawalOptions) context.Context {
	return WithWithdrawalOptions(context.Background(), options)
}

var payoutFees = addressWithdrawalOptions{Fees: "payout"}

// gaslessPayoutWei is the fixture note's payout in wei.
var gaslessPayoutWei = new(big.Int).Mul(big.NewInt(gaslessTestBalance), big.NewInt(1_000_000_000))

// sponsoredClose quotes and approves a gasless close and returns the sent
// operation's hash.
func (f *withdrawalFixture) sponsoredClose(t *testing.T) string {
	t.Helper()
	return f.sponsoredCloseWith(t, payoutFees)
}

// sponsoredCloseWith is sponsoredClose with the quote's options (the
// approval, like the CLI's --approve, carries none).
func (f *withdrawalFixture) sponsoredCloseWith(t *testing.T, options addressWithdrawalOptions) string {
	t.Helper()
	quote, err := f.h.QuoteAddressWithdrawal(payoutContext(options), withdrawalTestDestination, f.noteID, "", false)
	if err != nil {
		t.Fatal(err)
	}
	status, err := f.h.ApproveAddressWithdrawal(payoutContext(payoutFees), quote.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status.Phase != "op_submitted" || status.UserOpHash == "" {
		t.Fatalf("not submitted: %+v", status)
	}
	return status.UserOpHash
}

// Design 3.3 and 5.3: with --fees payout the withdrawal is prepared with the
// transit account as destination, the owner key and the operation are
// journaled (mode 0600) before the operation is sent, the funding address
// needs no ETH and signs nothing, the bundle transaction is confirmed
// through the relayed receipt check with the proof destination, and the
// paymaster's Settled figures are reported.
func TestGaslessWithdrawalClosesTheNoteWithASponsoredOperation(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	f.eth = "0x0"
	ctx := payoutContext(payoutFees)
	quote, err := f.h.QuoteAddressWithdrawal(ctx, withdrawalTestDestination, f.noteID, "", false)
	if err != nil {
		t.Fatal(err)
	}
	record := f.journal(t)
	w := record.Withdrawal
	if w == nil || w.FeePayer != "payout" || w.Transit == nil || w.ProofDestination != w.Transit.Account || !strings.EqualFold(w.Destination, withdrawalTestDestination) || w.Phase != "quoted" {
		t.Fatalf("no gasless reservation: %+v", w)
	}
	key, err := crypto.HexToECDSA(w.Transit.OwnerKey)
	if err != nil || crypto.PubkeyToAddress(key.PublicKey).Hex() != w.Transit.Owner || w.Transit.OwnerKey == record.PrivateKey {
		t.Fatal("the transit owner key is missing, wrong, or the funding key")
	}
	transit := common.HexToAddress(w.Transit.Account)
	if g.transitAccount(common.HexToAddress(w.Transit.Owner), common.HexToAddress(withdrawalTestDestination)) != transit {
		t.Fatal("the transit account is not the CREATE2 of the owner and payee")
	}
	if info, err := os.Lstat(f.h.addressStatePath()); err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("the journal with the owner key is not a private file")
	}
	if len(f.prepareBodies) != 1 || !strings.EqualFold(fmt.Sprint(f.prepareBodies[0]["destination"]), transit.Hex()) || !strings.EqualFold(f.reservedDestination, transit.Hex()) {
		t.Fatalf("the companion was not asked to prepare for the transit account: %+v", f.prepareBodies)
	}
	if quote.FeePolicy != "payout" || quote.Kind != "withdrawal" || quote.UserOpKind != "close" || !strings.EqualFold(quote.TransitAccount, transit.Hex()) || !strings.EqualFold(quote.Destination, withdrawalTestDestination) || quote.BundlerURL != g.url || quote.PayoutWei != gaslessPayoutWei.String() || quote.ShortfallWei != "0" || quote.UserOpGas == nil || !quote.UserOpGas.InitCode {
		t.Fatalf("payout quote: %+v", quote)
	}
	feeCap, _ := new(big.Int).SetString(quote.FeeCapWei, 10)
	minimum, _ := new(big.Int).SetString(quote.MinimumReceivedWei, 10)
	if feeCap.Sign() <= 0 || new(big.Int).Add(minimum, feeCap).Cmp(gaslessPayoutWei) != 0 || quote.OwedWei != "0" || quote.FlatFeeWei != g.flatFee.String() {
		t.Fatalf("payout arithmetic: %+v", quote)
	}
	limits := quote.UserOpGas
	if limits.CallGasLimit != 687500 || limits.PaymasterVerificationGasLimit != 450000 || limits.PaymasterPostOpGasLimit != 270000 || limits.VerificationGasLimit != 180000 || limits.PreVerificationGas < 40000 {
		t.Fatalf("the quoted limits are not the pinned defaults: %+v", limits)
	}
	if len(f.accepted) != 1 || len(g.sends) != 0 {
		t.Fatal("quoting signed or sent something")
	}
	status, err := f.h.ApproveAddressWithdrawal(ctx, quote.ID)
	if err != nil {
		t.Fatal(err)
	}
	if status.Phase != "op_submitted" || status.UserOpHash == "" || status.TransactionHash != "" || status.FeePayer != "payout" || !strings.EqualFold(status.TransitAccount, transit.Hex()) {
		t.Fatalf("approval: %+v", status)
	}
	hash := status.UserOpHash
	record = f.journal(t)
	w = record.Withdrawal
	if w.UserOp == nil || w.UserOp.Hash != hash || w.UserOp.Kind != "close" || !w.UserOp.InitCode || len(w.UserOp.Hashes) != 1 || w.UserOp.SubmittedAt == 0 || w.UserOp.BundlerURL != g.url || w.UserOp.ValidUntil == 0 || record.Pending != nil || record.Quote != nil {
		t.Fatalf("the operation was not journaled: %+v", w.UserOp)
	}
	if len(g.sends) != 1 || g.sends[0] != hash || len(f.accepted) != 1 || len(f.submitted) != 1 {
		t.Fatal("the operation was not sent exactly once, or a wallet transaction was signed")
	}
	sent, _ := gaslessUserOpFromJSON(g.ops[hash])
	vaultCall, _ := vaultCallOfTransitCallData(sent.CallData)
	if sent.Sender != transit || len(sent.InitCode) == 0 || common.BytesToAddress(sent.InitCode[:20]) != g.factory || sent.Paymaster != g.paymaster || len(vaultCall) != withdrawalCalldataLength || hex.EncodeToString(vaultCall[4+10*32+12:4+11*32]) != strings.ToLower(transit.Hex()[2:]) {
		t.Fatalf("the sent operation is not the close bound to the transit account: %+v", sent)
	}
	if sent.MaxFeePerGas.Cmp(g.maxFeeCeiling) > 0 || sent.MaxPriorityFeePerGas.Cmp(g.priorityCeiling) > 0 || sent.FeeCapWei.Cmp(g.flatFee) != 0 || new(big.Int).Rsh(sent.Nonce, 64).Cmp(new(big.Int).SetBytes(common.FromHex(w.Nullifier))) != 0 {
		t.Fatalf("fees or nonce key: %+v", sent)
	}
	if signer, err := recoverUserOpSigner(sent.hash(g.entryPoint, 1), sent.Signature); err != nil || signer.Hex() != w.Transit.Owner {
		t.Fatal("the operation is not signed by the transit owner")
	}
	if err := validateSignedWithdrawal(vaultCall, fundingConfig{ChainID: 1, Contract: addressTestVault}, w, time.Now()); err != nil {
		t.Fatal(err)
	}
	// Polling before inclusion changes nothing; a quote is refused while the
	// operation is live.
	if status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID); err != nil || status.Phase != "op_submitted" {
		t.Fatalf("poll: %+v %v", status, err)
	}
	if _, err := f.h.QuoteAddressWithdrawal(ctx, withdrawalTestDestination, f.noteID, "", false); err == nil {
		t.Fatal("a new quote while the operation is live")
	}
	charged := big.NewInt(2_000_000_000_000_000)
	bundle := g.mineUserOp(t, hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, PaidOut: new(big.Int).Sub(gaslessPayoutWei, charged)})
	f.finalized = "0x1"
	status, err = f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "withdrawal_pending" || status.TransactionHash != bundle || f.confirmCalls != 0 {
		t.Fatalf("before finality: %+v %v", status, err)
	}
	f.finalized = "0x20"
	status, err = f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.TransactionHash != bundle || status.ChargedWei != charged.String() || status.ReceivedWei != new(big.Int).Sub(gaslessPayoutWei, charged).String() || status.FundsWaitingInTransit || status.PayoutCredited {
		t.Fatalf("after finality: %+v %v", status, err)
	}
	if f.confirmCalls != 1 || f.active || !strings.Contains(status.Message, "sponsored network fee") {
		t.Fatalf("the companion was not told the bundle transaction: %d %s", f.confirmCalls, status.Message)
	}
	record = f.journal(t)
	if record.Pending != nil || record.Phase != "ready" || record.Amount != 0 || record.Withdrawal.Phase != "complete" || record.Withdrawal.TransactionHash != bundle || len(f.accepted) != 1 {
		t.Fatalf("completion: %+v", record)
	}
	// Restart: complete stays complete, and the next deposit is allowed.
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	if status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID); err != nil || status.Phase != "complete" {
		t.Fatalf("restart: %+v %v", status, err)
	}
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 1234567); err != nil {
		t.Fatalf("funding after a gasless withdrawal: %v", err)
	}
}

// Design 3.3: the bundler is resolved once, at the quote (flag, then
// configuration, then profile), and the approval binds it: a quote made
// with --bundler-url sends the signed operation to that bundler although
// the approval (like the CLI's --approve) names none and the configuration
// names another, and an approval resolving another bundler is refused.
func TestGaslessApprovalBindsTheQuotedBundler(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	var mu sync.Mutex
	decoyCalls := 0
	decoy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		decoyCalls++
		mu.Unlock()
		http.Error(w, "not this bundler", http.StatusServiceUnavailable)
	}))
	defer decoy.Close()
	f.h.client.config.BundlerURL = decoy.URL
	quote, err := f.h.QuoteAddressWithdrawal(payoutContext(addressWithdrawalOptions{Fees: "payout", BundlerURL: g.url}), withdrawalTestDestination, f.noteID, "", false)
	if err != nil || quote.BundlerURL != g.url {
		t.Fatalf("the quote does not name the requested bundler: %+v %v", quote, err)
	}
	// An approval that resolves another bundler is not this quote's.
	if _, err := f.h.ApproveAddressWithdrawal(payoutContext(addressWithdrawalOptions{Fees: "payout", BundlerURL: decoy.URL}), quote.ID); !errors.Is(err, errAddressQuoteChanged) || len(g.sends) != 0 {
		t.Fatalf("an approval with another bundler: %v", err)
	}
	if f.journal(t).Quote == nil {
		quote, err = f.h.QuoteAddressWithdrawal(payoutContext(addressWithdrawalOptions{Fees: "payout", BundlerURL: g.url}), withdrawalTestDestination, f.noteID, "", false)
		if err != nil {
			t.Fatal(err)
		}
	}
	status, err := f.h.ApproveAddressWithdrawal(payoutContext(payoutFees), quote.ID)
	if err != nil || status.Phase != "op_submitted" {
		t.Fatalf("approval: %+v %v", status, err)
	}
	if u := f.journal(t).Withdrawal.UserOp; u == nil || u.BundlerURL != g.url || len(g.sends) != 1 || g.sends[0] != u.Hash {
		t.Fatalf("the operation did not go to the quoted bundler: %+v %v", u, g.sends)
	}
	// Following it uses the journaled bundler as well.
	g.mineUserOp(t, status.UserOpHash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: big.NewInt(5), PaidOut: new(big.Int).Sub(gaslessPayoutWei, big.NewInt(5))})
	if status, err := f.h.WithdrawAddress(payoutContext(payoutFees), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "complete" {
		t.Fatalf("follow: %+v %v", status, err)
	}
	mu.Lock()
	defer mu.Unlock()
	if decoyCalls != 0 {
		t.Fatalf("the configured bundler was contacted %d times", decoyCalls)
	}
}

// The quote's expected charge is the paymaster's chargeFor at the gas an
// operation of this shape uses (its preVerificationGas, the validation
// floors, the kind's measured execution) and at the fee it would pay now
// (base fee plus tip), not at the operation's fee ceiling and signed
// limits; the maximum stays the signed bound.
func TestGaslessQuoteExpectsTheChargeAtTodaysFee(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	quote, err := f.h.QuoteAddressWithdrawal(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, "", false)
	if err != nil {
		t.Fatal(err)
	}
	policy := g.profile.GasPolicy
	limits := quote.UserOpGas
	maxFee, _ := new(big.Int).SetString(quote.MaxFeePerGas, 10)
	tip, _ := new(big.Int).SetString(quote.MaxPriorityFeePerGas, 10)
	baseFee, _ := new(big.Int).SetString(strings.TrimPrefix(f.gasPrice, "0x"), 16)
	feeNow := new(big.Int).Add(baseFee, tip)
	if feeNow.Cmp(maxFee) >= 0 {
		t.Fatalf("the fixture's fee now %s is not below the ceiling %s", feeNow, maxFee)
	}
	floor, _, _ := policy.callLimits(gaslessKindClose)
	execution := floor - 20_000 - policy.AccountCallOverheadGas
	actual := limits.PreVerificationGas + policy.VerificationFloorInit + policy.PMVerificationFloor + execution + policy.AccountCallOverheadGas
	// The fixture's payout address is a fresh account (no code, balance
	// or nonce): the push pays NEW_ACCOUNT_GAS.
	want := gaslessChargeFor(policy, gaslessKindClose, actual, execution, limits.CallGasLimit, limits.PaymasterPostOpGasLimit, false, true, feeNow)
	want.Add(want, g.flatFee)
	// The figure the quote used to show: the signed limits at the ceiling.
	ceiling := gaslessChargeFor(policy, gaslessKindClose, limits.PreVerificationGas+limits.VerificationGasLimit+limits.PaymasterVerificationGasLimit+limits.CallGasLimit, limits.CallGasLimit, limits.CallGasLimit, limits.PaymasterPostOpGasLimit, false, true, maxFee)
	ceiling.Add(ceiling, g.flatFee)
	expected, _ := new(big.Int).SetString(quote.ExpectedFeeWei, 10)
	feeCap, _ := new(big.Int).SetString(quote.FeeCapWei, 10)
	if expected.Cmp(want) != 0 || expected.Cmp(feeCap) >= 0 || new(big.Int).Mul(expected, big.NewInt(2)).Cmp(ceiling) >= 0 {
		t.Fatalf("expected charge %s, want %s (cap %s, at the ceiling %s)", expected, want, feeCap, ceiling)
	}
}

// Design 3.1: a payout address with code may refuse the 100,000-gas push,
// and the paymaster then credits the payout less a CREDIT_GAS surcharge
// taken beyond the cap. The quote's floor deducts that worst case, the
// quote and the status carry the advisory before anything is signed, and
// an address without code is quoted without it.
func TestGaslessQuoteForAContractPayeeDeductsTheCreditSurcharge(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	f.mu.Lock()
	g.codes[strings.ToLower(withdrawalTestDestination)] = "0x6080604052"
	f.mu.Unlock()
	quote, err := f.h.QuoteAddressWithdrawal(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, "", false)
	if err != nil {
		t.Fatal(err)
	}
	maxFee, _ := new(big.Int).SetString(quote.MaxFeePerGas, 10)
	surcharge := new(big.Int).Mul(new(big.Int).SetUint64(g.profile.GasPolicy.CreditGas), maxFee)
	feeCap, _ := new(big.Int).SetString(quote.FeeCapWei, 10)
	minimum, _ := new(big.Int).SetString(quote.MinimumReceivedWei, 10)
	if !quote.PayeeHasCode || quote.CreditSurchargeWei != surcharge.String() || surcharge.Sign() == 0 || new(big.Int).Add(new(big.Int).Add(minimum, feeCap), surcharge).Cmp(gaslessPayoutWei) != 0 {
		t.Fatalf("the floor does not deduct the credit surcharge %s: %+v", surcharge, quote)
	}
	advised := false
	for _, warning := range quote.Warnings {
		advised = advised || strings.Contains(warning, "100,000 gas")
	}
	status, err := f.h.AddressWithdrawal(context.Background())
	if !advised || err != nil || !status.PayeeHasCode || !strings.Contains(status.GaslessAdvisory, "100,000 gas") || len(g.sends) != 0 {
		t.Fatalf("no advisory before signing: %+v %+v %v", quote.Warnings, status, err)
	}
	// Without code: no surcharge, no advisory.
	f2, _ := newGaslessWithdrawalFixture(t)
	plain, err := f2.h.QuoteAddressWithdrawal(payoutContext(payoutFees), withdrawalTestDestination, f2.noteID, "", false)
	if err != nil || plain.PayeeHasCode || plain.CreditSurchargeWei != "" || len(plain.Warnings) != 0 {
		t.Fatalf("an address without code: %+v %v", plain, err)
	}
}

// The gasless path never signs a wallet transaction nor waits for ETH: with
// an empty funding address the quote carries no top-up and the approval
// sends the operation.
func TestGaslessWithdrawalNeverReportsWaitingFunds(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	f.eth = "0x0"
	hash := f.sponsoredClose(t)
	status, err := f.h.AddressWithdrawal(context.Background())
	if err != nil || status.Phase != "op_submitted" || status.UserOpHash != hash || status.Message == "" || strings.Contains(status.Message, "Send ETH") {
		t.Fatalf("%+v %v", status, err)
	}
	// Only the fixture's deposit was ever signed and broadcast.
	if len(g.sends) != 1 || len(f.accepted) != 1 || len(f.submitted) != 1 {
		t.Fatal("the operation was not sent, or a wallet transaction was signed")
	}
}

// A crash between the journal and the send: the identical operation (same
// hash, same bytes) is re-sent on resume, from a fresh process.
func TestGaslessWithdrawalResendsTheJournaledOperationAfterACrash(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	ctx := payoutContext(payoutFees)
	quote, err := f.h.QuoteAddressWithdrawal(ctx, withdrawalTestDestination, f.noteID, "", false)
	if err != nil {
		t.Fatal(err)
	}
	g.sendDown = true
	status, err := f.h.ApproveAddressWithdrawal(ctx, quote.ID)
	if err != nil || status.Phase != "op_built" || status.UserOpHash == "" {
		t.Fatalf("the operation was not journaled before the failed send: %+v %v", status, err)
	}
	journaled := f.journal(t).Withdrawal.UserOp
	if len(g.sends) != 0 || journaled.SubmittedAt != 0 {
		t.Fatal("a send was recorded")
	}
	g.sendDown = false
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	status, err = f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "op_submitted" || status.UserOpHash != journaled.Hash {
		t.Fatalf("resume did not send: %+v %v", status, err)
	}
	if len(g.sends) != 1 || g.sends[0] != journaled.Hash {
		t.Fatalf("another operation was sent: %v", g.sends)
	}
	resent, _ := json.Marshal(g.ops[journaled.Hash])
	var original gaslessUserOpJSON
	_ = json.Unmarshal(journaled.JSON, &original)
	expected, _ := json.Marshal(original)
	if string(resent) != string(expected) || f.prepareCalls != 2 {
		t.Fatal("the re-sent bytes differ from the journaled operation, or the proof was requested again")
	}
	// A lost answer to a send: the bundler holds it; the resume finds it.
	g.mineUserOp(t, journaled.Hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: big.NewInt(1), PaidOut: new(big.Int).Sub(gaslessPayoutWei, big.NewInt(1))})
	if status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID); err != nil || status.Phase != "complete" {
		t.Fatalf("%+v %v", status, err)
	}
}

// After five minutes without inclusion the bundler is asked; an operation
// it forgot is re-sent, and one it refuses as underpriced is re-signed with
// both fees raised an eighth, every hash journaled; the one included wins.
func TestGaslessWithdrawalResumeBumpsTheFeesAndJournalsEveryHash(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	ctx := payoutContext(payoutFees)
	// The quote is made with a fee cap of 0.004 ETH, above the operation's
	// maximum (about 0.0033 ETH): one raise of an eighth fits under it,
	// a second does not. The approval binds that bound.
	const cap = 4_000_000
	quote, err := f.h.QuoteAddressWithdrawal(payoutContext(addressWithdrawalOptions{Fees: "payout", FeeCapGwei: cap}), withdrawalTestDestination, f.noteID, "", false)
	if err != nil || quote.FeeBumpCapWei != "4000000000000000" || quote.FeeCapGwei != cap || quote.FeeBumpCapWei == quote.FeeCapWei {
		t.Fatalf("the quote does not show the re-sign bound: %+v %v", quote, err)
	}
	status, err := f.h.ApproveAddressWithdrawal(ctx, quote.ID)
	if err != nil || status.Phase != "op_submitted" {
		t.Fatalf("approval: %+v %v", status, err)
	}
	first := status.UserOpHash
	if u := f.journal(t).Withdrawal.UserOp; u.FeeCapWei != "4000000000000000" || u.FeeCapGwei != cap || u.AllowExpensiveGas {
		t.Fatalf("the bound was not journaled with the operation: %+v", u)
	}
	// Not yet: nothing happens within five minutes.
	if _, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID); err != nil || len(g.sends) != 1 {
		t.Fatal("a re-send before the wait")
	}
	f.editJournal(t, func(record *addressFundingRecord) { record.Withdrawal.UserOp.SubmittedAt -= 400 })
	// The bundler forgot it: the identical bytes are re-sent.
	g.known[first] = false
	if status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID); err != nil || status.Phase != "op_submitted" || len(g.sends) != 2 || g.sends[1] != first {
		t.Fatalf("no identical re-send: %+v %v %v", status, err, g.sends)
	}
	// Dropped for its fees: the re-send is refused, so it is re-signed with
	// higher fees.
	f.editJournal(t, func(record *addressFundingRecord) { record.Withdrawal.UserOp.SubmittedAt -= 400 })
	g.known[first], g.refuseResend = false, true
	status, err = f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "op_submitted" || status.UserOpHash == first || len(g.sends) != 3 {
		t.Fatalf("no fee bump: %+v %v %v", status, err, g.sends)
	}
	second := status.UserOpHash
	u := f.journal(t).Withdrawal.UserOp
	if u.Hash != second || len(u.Hashes) != 2 || u.Hashes[0] != first || u.Hashes[1] != second {
		t.Fatalf("hashes not journaled: %+v", u)
	}
	old, _ := gasfromJSON(t, g.ops[first])
	bumped, _ := gasfromJSON(t, g.ops[second])
	raise := func(fee *big.Int) *big.Int {
		return new(big.Int).Add(new(big.Int).Add(fee, new(big.Int).Quo(fee, big.NewInt(8))), big.NewInt(1))
	}
	if bumped.MaxFeePerGas.Cmp(raise(old.MaxFeePerGas)) != 0 || bumped.MaxPriorityFeePerGas.Cmp(raise(old.MaxPriorityFeePerGas)) != 0 || bumped.Nonce.Cmp(old.Nonce) != 0 || hex.EncodeToString(bumped.CallData) != hex.EncodeToString(old.CallData) {
		t.Fatalf("the bumped operation differs beyond its fees: %+v vs %+v", bumped, old)
	}
	if signer, err := recoverUserOpSigner(bumped.hash(g.entryPoint, 1), bumped.Signature); err != nil || signer.Hex() != f.journal(t).Withdrawal.Transit.Owner {
		t.Fatal("the bumped operation is not signed by the owner")
	}
	if new(big.Int).Add(bumped.maxCost(), g.flatFee).Cmp(new(big.Int).SetUint64(cap*1_000_000_000)) > 0 {
		t.Fatal("the bumped operation exceeds the cap")
	}
	// Dropped again, from a fresh process: the next raise would take the
	// fee above the cap, so nothing is signed and the record stops with
	// the reason instead.
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	f.editJournal(t, func(record *addressFundingRecord) { record.Withdrawal.UserOp.SubmittedAt -= 400 })
	g.known[second] = false
	status, err = f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "gasless_refused" || !strings.Contains(status.GaslessRefusal, "fee_bump_needs_quote") || !strings.Contains(status.GaslessRefusal, "--fee-cap-gwei of 4000000 gwei") || len(g.sends) != 3 {
		t.Fatalf("a raise above the cap: %+v %v %v", status, err, g.sends)
	}
	if u := f.journal(t).Withdrawal.UserOp; u == nil || u.Hash != second || len(u.Hashes) != 2 {
		t.Fatalf("the dropped operation was forgotten: %+v", u)
	}
	// The first one landed after all: found by its hash on chain before
	// anything is proved again.
	prepares := len(f.prepareBodies)
	g.refuseResend = false
	g.mineUserOp(t, first, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: big.NewInt(5), PaidOut: new(big.Int).Sub(gaslessPayoutWei, big.NewInt(5))})
	status, err = f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.UserOpHash != first || status.GaslessRefusal != "" {
		t.Fatalf("the included operation was not adopted: %+v %v", status, err)
	}
	if len(f.prepareBodies) != prepares || len(g.sends) != 3 {
		t.Fatal("the close was proved or sent again")
	}
}

// A copy signed before a fee bump may still be included: the journal keeps
// the re-signed operation as JSON and Hash (they always match), records the
// included copy apart, and stays loadable from a fresh process while the
// bundle transaction awaits finality and after the close completes.
func TestGaslessWithdrawalLateInclusionOfAnEarlierCopyKeepsTheJournalLoadable(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	ctx := payoutContext(payoutFees)
	quote, err := f.h.QuoteAddressWithdrawal(payoutContext(addressWithdrawalOptions{Fees: "payout", FeeCapGwei: 4_000_000}), withdrawalTestDestination, f.noteID, "", false)
	if err != nil {
		t.Fatal(err)
	}
	status, err := f.h.ApproveAddressWithdrawal(ctx, quote.ID)
	if err != nil || status.Phase != "op_submitted" {
		t.Fatalf("approval: %+v %v", status, err)
	}
	first := status.UserOpHash
	prepares := len(f.prepareBodies)
	f.editJournal(t, func(record *addressFundingRecord) { record.Withdrawal.UserOp.SubmittedAt -= 400 })
	g.known[first], g.refuseResend = false, true
	status, err = f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "op_submitted" || status.UserOpHash == first {
		t.Fatalf("no fee bump: %+v %v", status, err)
	}
	second := status.UserOpHash
	// The pre-bump copy lands; the bundle transaction is not final yet.
	g.refuseResend = false
	bundle := g.mineUserOp(t, first, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: big.NewInt(5), PaidOut: new(big.Int).Sub(gaslessPayoutWei, big.NewInt(5))})
	f.finalized = "0x1"
	status, err = f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "withdrawal_pending" || status.UserOpHash != first || status.TransactionHash != bundle {
		t.Fatalf("the included copy was not followed: %+v %v", status, err)
	}
	u := f.journal(t).Withdrawal.UserOp
	if u.Hash != second || u.IncludedHash != first || u.TransactionHash != bundle || len(u.Hashes) != 2 {
		t.Fatalf("the journal mixes the included copy with the signed one: %+v", u)
	}
	// A fresh process loads the journal and keeps following.
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	if status, err := f.h.AddressWithdrawal(ctx); err != nil || status.Phase != "withdrawal_pending" || status.UserOpHash != first {
		t.Fatalf("the journal does not load after a late inclusion: %+v %v", status, err)
	}
	f.finalized = "0x20"
	status, err = f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.UserOpHash != first || status.TransactionHash != bundle || f.confirmCalls != 1 {
		t.Fatalf("the late inclusion did not complete: %+v %v", status, err)
	}
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	if status, err := f.h.AddressWithdrawal(ctx); err != nil || status.Phase != "complete" {
		t.Fatalf("the completed journal does not load: %+v %v", status, err)
	}
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 1234567); err != nil {
		t.Fatalf("funding after the late inclusion: %v", err)
	}
	if len(f.prepareBodies) != prepares || len(g.sends) != 2 {
		t.Fatal("the close was proved or sent again")
	}
}

// Without --fee-cap-gwei the approval binds the quoted maximum: a dropped
// operation is never re-signed above it (design 3.3: the approval binds the
// fees), the record stops with the reason, and the next quote is made at
// the current fees.
func TestGaslessWithdrawalWithoutAFeeCapIsNeverResignedAboveTheApprovedMaximum(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	ctx := payoutContext(payoutFees)
	quote, err := f.h.QuoteAddressWithdrawal(ctx, withdrawalTestDestination, f.noteID, "", false)
	if err != nil || quote.FeeBumpCapWei != quote.FeeCapWei || quote.FeeCapGwei != 0 {
		t.Fatalf("the quote does not bind its maximum: %+v %v", quote, err)
	}
	if _, err := f.h.ApproveAddressWithdrawal(ctx, quote.ID); err != nil {
		t.Fatal(err)
	}
	first := f.journal(t).Withdrawal.UserOp
	if first.FeeCapWei != quote.FeeCapWei {
		t.Fatalf("the journaled bound is %s, the approved maximum %s", first.FeeCapWei, quote.FeeCapWei)
	}
	f.editJournal(t, func(record *addressFundingRecord) { record.Withdrawal.UserOp.SubmittedAt -= 400 })
	g.known[first.Hash], g.refuseResend = false, true
	status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "gasless_refused" || !strings.Contains(status.GaslessRefusal, "fee_bump_needs_quote") || !strings.Contains(status.GaslessRefusal, "approved maximum") || len(g.sends) != 1 {
		t.Fatalf("re-signed above the approved maximum: %+v %v %v", status, err, g.sends)
	}
	if u := f.journal(t).Withdrawal.UserOp; u == nil || u.Hash != first.Hash || len(u.Hashes) != 1 {
		t.Fatalf("a re-signed copy was journaled: %+v", u)
	}
	// The way out is a fresh quote at the current fees (the dropped
	// operation was not included).
	g.refuseResend = false
	quote, err = f.h.QuoteAddressWithdrawal(ctx, withdrawalTestDestination, f.noteID, "", false)
	if err != nil || quote.UserOpKind != "close" || quote.FeePolicy != "payout" {
		t.Fatalf("no fresh quote: %+v %v", quote, err)
	}
	if w := f.journal(t).Withdrawal; w.UserOp != nil || w.Phase != "quoted" {
		t.Fatalf("the refused operation was kept: %+v", w)
	}
}

func gasfromJSON(t *testing.T, encoded gaslessUserOpJSON) (*gaslessUserOp, error) {
	t.Helper()
	op, err := gaslessUserOpFromJSON(encoded)
	if err != nil {
		t.Fatal(err)
	}
	return op, nil
}

// A bundler that answers another hash than the local one: the submission is
// ambiguous and recovery continues by the chain's logs under the local hash;
// the bundler's receipt is only a hint, and one naming a transaction without
// the operation's event is ignored.
func TestGaslessWithdrawalIgnoresAForgedHashAndAForgedReceipt(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	ctx := payoutContext(payoutFees)
	g.forgeHash = true
	hash := f.sponsoredClose(t)
	if u := f.journal(t).Withdrawal.UserOp; !u.Ambiguous || u.Hash != hash || g.sends[0] != hash {
		t.Fatalf("the forged hash was adopted: %+v", u)
	}
	// A forged receipt names a transaction that holds no event of ours.
	forged := "0x" + strings.Repeat("e", 64)
	f.mu.Lock()
	f.receipts[forged] = map[string]any{"transactionHash": forged, "status": "0x1", "blockNumber": "0x10", "blockHash": f.canonical, "to": g.entryPoint.Hex(), "logs": []map[string]any{}}
	f.mu.Unlock()
	g.forgedReceiptTransaction = forged
	status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "op_submitted" || status.TransactionHash != "" || f.confirmCalls != 0 {
		t.Fatalf("a forged receipt was adopted: %+v %v", status, err)
	}
	g.forgedReceiptTransaction = ""
	bundle := g.mineUserOp(t, hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: big.NewInt(7), PaidOut: new(big.Int).Sub(gaslessPayoutWei, big.NewInt(7))})
	status, err = f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.TransactionHash != bundle {
		t.Fatalf("the chain's logs did not decide: %+v %v", status, err)
	}
}

// An operation included but reverted (the note was closed first by a direct
// replay of the public calldata): phase op_reverted, with the payout in the
// transit account; --collect adopts the replay as the note's settlement and
// forwards the balance with a sponsored FORWARD operation.
func TestGaslessWithdrawalRevertedByAReplayIsCollected(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	ctx := payoutContext(payoutFees)
	hash := f.sponsoredClose(t)
	w := f.journal(t).Withdrawal
	transit := common.HexToAddress(w.Transit.Account)
	// The replay closed the note and paid the transit account.
	replay := "0x" + strings.Repeat("c", 64)
	closeLog := map[string]any{"address": addressTestVault, "topics": []string{withdrawalEventTopic, fmt.Sprintf("0x%064x", f.reservedNoteID)}, "data": "0x" + addressABIWord(f.reservedNullifier) + fmt.Sprintf("%064x", f.reservedBalance) + addressWord(transit), "transactionHash": replay}
	f.mu.Lock()
	f.logs = append(f.logs, closeLog)
	f.receipts[replay] = map[string]any{"transactionHash": replay, "status": "0x1", "blockNumber": "0x10", "blockHash": f.canonical, "to": addressTestVault, "logs": []map[string]any{closeLog}}
	f.closeNote(uint32(f.reservedNoteID))
	g.balances[strings.ToLower(transit.Hex())] = new(big.Int).Set(gaslessPayoutWei)
	f.mu.Unlock()
	bundle := g.mineUserOp(t, hash, false, fixtureSettlement{Charged: big.NewInt(9)})
	status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "op_reverted" || status.TransactionHash != bundle || !strings.Contains(status.Message, "--collect") || !strings.Contains(status.GaslessRefusal, "NoteNotActive") || f.confirmCalls != 0 {
		t.Fatalf("revert: %+v %v", status, err)
	}
	if !g.stranded[strings.ToLower(transit.Hex())] {
		t.Fatal("the fixture did not strand the account")
	}
	// Polls keep the phase; a retry without the hash does nothing.
	if status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID); err != nil || status.Phase != "op_reverted" {
		t.Fatalf("poll: %+v %v", status, err)
	}
	collect := payoutContext(addressWithdrawalOptions{Collect: true})
	quote, err := f.h.QuoteAddressWithdrawal(collect, withdrawalTestDestination, f.noteID, "", false)
	if err != nil {
		t.Fatal(err)
	}
	record := f.journal(t)
	w = record.Withdrawal
	if w.Phase != "complete" || !w.FundsWaitingInTransit || w.SettlementHash != replay || w.TransactionHash != bundle || f.confirmCalls != 1 || f.active || record.Phase != "ready" {
		t.Fatalf("the replay was not adopted as the settlement: %+v", w)
	}
	if quote.UserOpKind != "forward" || quote.Kind != "withdrawal" || quote.FeePolicy != "payout" || quote.PayoutWei != gaslessPayoutWei.String() || quote.UserOpGas == nil || quote.UserOpGas.InitCode {
		t.Fatalf("forward quote: %+v", quote)
	}
	if quote.UserOpGas.CallGasLimit != g.profile.GasPolicy.CallDefault[3] {
		t.Fatalf("the forward's call limit is %d", quote.UserOpGas.CallGasLimit)
	}
	status, err = f.h.ApproveAddressWithdrawal(collect, quote.ID)
	if err != nil || status.Phase != "forward_op_submitted" || len(g.sends) != 2 {
		t.Fatalf("forward: %+v %v", status, err)
	}
	forward, _ := gasfromJSON(t, g.ops[g.sends[1]])
	if vaultCall, err := vaultCallOfTransitCallData(forward.CallData); err != nil || len(vaultCall) != 0 || new(big.Int).Rsh(forward.Nonce, 64).Cmp(gaslessForwardNonceKey) != 0 || len(forward.InitCode) != 0 {
		t.Fatalf("not a FORWARD operation: %+v", forward)
	}
	charged := big.NewInt(300_000_000_000_000)
	g.mineUserOp(t, g.sends[1], true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, PaidOut: new(big.Int).Sub(gaslessPayoutWei, charged)})
	status, err = f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.FundsWaitingInTransit || status.ReceivedWei != new(big.Int).Sub(gaslessPayoutWei, charged).String() || status.ChargedWei != charged.String() {
		t.Fatalf("forward completion: %+v %v", status, err)
	}
	if record := f.journal(t); len(record.Withdrawal.CollectHashes) != 1 || record.Withdrawal.CollectHashes[0] != g.bundlerReceipts[g.sends[1]] {
		t.Fatalf("collect hashes: %+v", record.Withdrawal.CollectHashes)
	}
	if len(f.accepted) != 1 {
		t.Fatal("a wallet transaction was signed")
	}
}

// A payee that rejected the push: the paymaster credited the payout, nothing
// reached the payout address (received 0), and --claim-credit delivers it
// with a wallet-paid claimCredit on the paymaster.
func TestGaslessWithdrawalCreditedPayoutIsClaimed(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	ctx := payoutContext(payoutFees)
	hash := f.sponsoredClose(t)
	charged := big.NewInt(11)
	credited := new(big.Int).Sub(gaslessPayoutWei, charged)
	g.mineUserOp(t, hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, Credited: credited})
	status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.ReceivedWei != "0" || !status.PayoutCredited || !status.PaymasterCredited || status.PaymasterAddress != g.paymaster.Hex() || status.ClaimCalldata != "0x"+selectorClaimCredit+addressABIWord(strings.ToLower(withdrawalTestDestination)) || !strings.Contains(status.Message, "--claim-credit") || status.FundsWaitingInTransit {
		t.Fatalf("credited: %+v %v", status, err)
	}
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 1234567); !errors.Is(err, errWithdrawalPayoutWaiting) {
		t.Fatalf("a deposit while the credit waits: %v", err)
	}
	claim := payoutContext(addressWithdrawalOptions{ClaimCredit: true})
	quote, err := f.h.QuoteAddressWithdrawal(claim, withdrawalTestDestination, f.noteID, "", false)
	if err != nil || quote.Kind != "gasless_claim" || quote.FeePolicy != "low" || !strings.EqualFold(quote.Destination, withdrawalTestDestination) {
		t.Fatalf("claim quote: %+v %v", quote, err)
	}
	if _, err := f.h.ApproveAddressWithdrawal(claim, quote.ID); err != nil {
		t.Fatal(err)
	}
	record := f.journal(t)
	if record.Pending == nil || record.Pending.Kind != "gasless_claim" {
		t.Fatalf("no claim transaction: %+v", record.Pending)
	}
	tx := f.accepted[record.Pending.Hash]
	if tx == nil || !strings.EqualFold(tx.To().Hex(), g.paymaster.Hex()) || "0x"+hex.EncodeToString(tx.Data()) != status.ClaimCalldata || tx.Value().Sign() != 0 {
		t.Fatal("the claim is not claimCredit(Y) on the paymaster")
	}
	f.mu.Lock()
	f.receipts[record.Pending.Hash] = map[string]any{"transactionHash": record.Pending.Hash, "status": "0x1", "blockNumber": "0x10", "blockHash": f.canonical, "to": g.paymaster.Hex(), "logs": []map[string]any{{"address": g.paymaster.Hex(), "topics": []string{paymasterCreditClaimedTopic, "0x" + addressABIWord(strings.ToLower(withdrawalTestDestination))}, "data": "0x" + wordHex(credited)}}}
	f.nonce = fmt.Sprintf("0x%x", tx.Nonce()+1)
	f.mu.Unlock()
	status, err = f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.ReceivedWei != credited.String() || f.journal(t).Pending != nil || f.journal(t).Withdrawal.ClaimHash != strings.ToLower(record.Pending.Hash) {
		t.Fatalf("claim completion: %+v %v", status, err)
	}
	// Delivered: nothing waits in the paymaster, the status says what
	// arrived, and a new deposit is no longer held back.
	if status.PaymasterCredited || status.PayoutCredited || strings.Contains(status.Message, "nothing has arrived") || !strings.Contains(status.Message, credited.String()) {
		t.Fatalf("the claimed credit still shows as waiting: %+v", status)
	}
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 1234567); err != nil {
		t.Fatalf("a deposit after the claim: %v", err)
	}
	// The deposit retired the withdrawal; the claim stays in the history.
	if record := f.journal(t); record.Withdrawal != nil || len(record.History) == 0 || record.History[len(record.History)-1].Kind != "gasless_claim" {
		t.Fatalf("the withdrawal was not retired for the deposit: %+v", record.Withdrawal)
	}
	// Restart keeps the journal valid.
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	if status, err := f.h.AddressWithdrawal(context.Background()); err != nil || status.PaymasterCredited {
		t.Fatalf("after a restart: %+v %v", status, err)
	}
}

// claimCredit is permissionless: when someone else delivered the credit
// first, --claim-credit finds credits(Y) at zero, signs nothing and stops
// waiting for the credit, so a new deposit can be funded.
func TestGaslessWithdrawalCreditClaimedByAThirdPartyStopsWaiting(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	ctx := payoutContext(payoutFees)
	hash := f.sponsoredClose(t)
	charged := big.NewInt(11)
	credited := new(big.Int).Sub(gaslessPayoutWei, charged)
	g.mineUserOp(t, hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, Credited: credited})
	if status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID); err != nil || !status.PaymasterCredited {
		t.Fatalf("credited: %+v %v", status, err)
	}
	f.mu.Lock()
	g.credits[strings.ToLower(withdrawalTestDestination)] = new(big.Int)
	f.mu.Unlock()
	claim := payoutContext(addressWithdrawalOptions{ClaimCredit: true})
	if _, err := f.h.QuoteAddressWithdrawal(claim, withdrawalTestDestination, f.noteID, "", false); err == nil || !strings.Contains(err.Error(), "claimed already") {
		t.Fatalf("a claim of a delivered credit: %v", err)
	}
	record := f.journal(t)
	if w := record.Withdrawal; record.Pending != nil || w.PaymasterCredited || w.PayoutCredited || w.ReceivedWei != "" || w.Phase != "complete" {
		t.Fatalf("the record still waits for the credit: %+v", w)
	}
	status, err := f.h.AddressWithdrawal(context.Background())
	if err != nil || status.PaymasterCredited || status.PayoutCredited || strings.Contains(status.Message, "nothing has arrived") {
		t.Fatalf("status: %+v %v", status, err)
	}
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 1234567); errors.Is(err, errWithdrawalPayoutWaiting) {
		t.Fatalf("a deposit after the third-party claim: %v", err)
	}
}

// The wallet fallback is reached through the management API exactly as
// the CLI and the guided flow send it: a request naming "fees": "wallet"
// switches a refused sponsored withdrawal to the wallet-paid close bound to
// the transit account, while a request without fees keeps the saved mode.
func TestGaslessWalletFallbackIsNamedThroughTheManagementAPI(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	inner := common.FromHex(selectorOf("PayoutBelowCost(uint256,uint256)") + uintWord(5) + uintWord(3))
	revert := selectorFailedOpWithRevert + uintWord(0) + addressABIWord("60") + addressABIWord("a0") + uintWord(13) + hex.EncodeToString(common.RightPadBytes([]byte("AA33 reverted"), 32)) + uintWord(uint64(len(inner))) + hex.EncodeToString(common.RightPadBytes(inner, 96))
	g.dryRunRevert = common.FromHex(revert)
	post := func(body string) (int, map[string]any) {
		r := httptest.NewRequest("POST", "http://127.0.0.1:8787/admin/withdrawal/quote", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		recorder := httptest.NewRecorder()
		f.h.ServeAdminHTTP(recorder, r)
		var answer map[string]any
		_ = json.Unmarshal(recorder.Body.Bytes(), &answer)
		return recorder.Code, answer
	}
	code, answer := post(fmt.Sprintf(`{"destination":%q,"note_id":%d,"fees":"payout"}`, withdrawalTestDestination, f.noteID))
	if code == http.StatusOK || answer["code"] != "payout_below_gas" {
		t.Fatalf("sponsored refusal: %d %+v", code, answer)
	}
	// No fee mode named: the saved sponsored mode is kept (and refused again).
	code, answer = post(fmt.Sprintf(`{"destination":%q,"note_id":%d}`, withdrawalTestDestination, f.noteID))
	if code == http.StatusOK || answer["code"] != "payout_below_gas" || f.journal(t).Withdrawal.FeePayer != "payout" {
		t.Fatalf("a plain request changed the fee mode: %d %+v", code, answer)
	}
	code, answer = post(fmt.Sprintf(`{"destination":%q,"note_id":%d,"fees":"wallet"}`, withdrawalTestDestination, f.noteID))
	if code != http.StatusOK || answer["fee_policy"] == "payout" || answer["kind"] != "withdrawal" {
		t.Fatalf("the named wallet fallback was not taken: %d %+v", code, answer)
	}
	w := f.journal(t).Withdrawal
	if w.FeePayer != "wallet" || w.Phase != "quoted" || w.UserOp != nil || w.ProofDestination != w.Transit.Account || len(g.sends) != 0 {
		t.Fatalf("the record was not switched to the wallet: %+v", w)
	}
}

// Design 3.1 fallback (b): after a gasless prepare the companion's
// reservation pins the transit account, so --fees wallet signs the
// wallet-paid close to the transit account (byte-for-byte the usual close
// but for the destination word) and --sweep then delivers the payout,
// creating the account first when it has no code.
func TestGaslessWithdrawalFallsBackToTheWalletAndSweeps(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	ctx := payoutContext(payoutFees)
	// The dry run refuses: the gasless path stops with the reason.
	inner := common.FromHex(selectorOf("PayoutBelowCost(uint256,uint256)") + uintWord(5) + uintWord(3))
	revert := selectorFailedOpWithRevert + uintWord(0) + addressABIWord("60") + addressABIWord("a0") + uintWord(13) + hex.EncodeToString(common.RightPadBytes([]byte("AA33 reverted"), 32)) + uintWord(uint64(len(inner))) + hex.EncodeToString(common.RightPadBytes(inner, 96))
	g.dryRunRevert = common.FromHex(revert)
	_, err := f.h.QuoteAddressWithdrawal(ctx, withdrawalTestDestination, f.noteID, "", false)
	if GaslessRefusalCode(err) != "payout_below_gas" {
		t.Fatalf("dry run refusal: %v", err)
	}
	status, err := f.h.AddressWithdrawal(context.Background())
	if err != nil || status.Phase != "gasless_refused" || !strings.Contains(status.GaslessRefusal, "payout_below_gas") || !strings.Contains(status.Message, "--fees wallet") {
		t.Fatalf("refused status: %+v %v", status, err)
	}
	w := f.journal(t).Withdrawal
	transit := common.HexToAddress(w.Transit.Account)
	// Rerunning with payout fees tries again (and is refused again).
	if _, err := f.h.QuoteAddressWithdrawal(ctx, withdrawalTestDestination, f.noteID, "", false); GaslessRefusalCode(err) != "payout_below_gas" || len(g.sends) != 0 {
		t.Fatalf("second try: %v", err)
	}
	wallet := payoutContext(addressWithdrawalOptions{Fees: "wallet"})
	quote, err := f.h.QuoteAddressWithdrawal(wallet, withdrawalTestDestination, f.noteID, "", false)
	if err != nil || quote.FeePolicy != "low" || quote.Kind != "withdrawal" {
		t.Fatalf("wallet quote: %+v %v", quote, err)
	}
	if _, err := f.h.ApproveAddressWithdrawal(wallet, quote.ID); err != nil {
		t.Fatal(err)
	}
	record := f.journal(t)
	if record.Pending == nil || record.Pending.Kind != "withdrawal" || record.Withdrawal.FeePayer != "wallet" || record.Withdrawal.ProofDestination != transit.Hex() {
		t.Fatalf("no wallet-paid close: %+v", record.Withdrawal)
	}
	tx := f.accepted[record.Pending.Hash]
	if hex.EncodeToString(tx.Data()[4+10*32+12:4+11*32]) != strings.ToLower(transit.Hex()[2:]) {
		t.Fatal("the close is not bound to the transit account")
	}
	f.mineWithdrawal(t, record.Pending.Hash, transit.Hex(), false)
	f.mu.Lock()
	g.balances[strings.ToLower(transit.Hex())] = new(big.Int).Set(gaslessPayoutWei)
	f.mu.Unlock()
	status, err = f.h.WithdrawAddress(wallet, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || !status.FundsWaitingInTransit || !strings.Contains(status.Message, "--sweep") {
		t.Fatalf("wallet completion: %+v %v", status, err)
	}
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 1234567); !errors.Is(err, errWithdrawalPayoutWaiting) {
		t.Fatalf("a deposit while the payout waits: %v", err)
	}
	// The refused operation was never included, so the paymaster holds no
	// evidence for a sponsored forward: --collect is refused and names
	// --sweep (CLI_ZKAPI.md, gasless_refused then --fees wallet).
	if _, err := f.h.QuoteAddressWithdrawal(payoutContext(addressWithdrawalOptions{Collect: true}), withdrawalTestDestination, f.noteID, "", false); err == nil || !strings.Contains(err.Error(), "no evidence") || !strings.Contains(err.Error(), "--sweep") {
		t.Fatalf("a sponsored collect after a refused operation: %v", err)
	}
	// The wallet-paid sweep and claim never contact a bundler: they work in
	// a fresh process where none resolves (the bundler was given only on
	// the original quote, and the profile publishes none).
	f.h.client.config.BundlerURL = ""
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	if _, err := f.h.QuoteAddressWithdrawal(payoutContext(addressWithdrawalOptions{ClaimCredit: true}), withdrawalTestDestination, f.noteID, "", false); err == nil || GaslessRefusalCode(err) == "bundler_unavailable" || !strings.Contains(err.Error(), "no credited payout") {
		t.Fatalf("a claim without a bundler: %v", err)
	}
	// --sweep: the account has no code, so its creation comes first.
	sweep := payoutContext(addressWithdrawalOptions{Sweep: true})
	quote, err = f.h.QuoteAddressWithdrawal(sweep, withdrawalTestDestination, f.noteID, "", false)
	if err != nil || quote.Kind != "transit_create" {
		t.Fatalf("create quote: %+v %v", quote, err)
	}
	if _, err := f.h.ApproveAddressWithdrawal(sweep, quote.ID); err != nil {
		t.Fatal(err)
	}
	record = f.journal(t)
	create := f.accepted[record.Pending.Hash]
	if record.Pending.Kind != "transit_create" || !strings.EqualFold(create.To().Hex(), g.factory.Hex()) || hex.EncodeToString(create.Data()) != hex.EncodeToString(transitInitCode(g.factory, common.HexToAddress(w.Transit.Owner), common.HexToAddress(withdrawalTestDestination))[20:]) {
		t.Fatal("the creation is not createAccount(owner, payee) on the factory")
	}
	f.mu.Lock()
	f.receipts[record.Pending.Hash] = map[string]any{"transactionHash": record.Pending.Hash, "status": "0x1", "blockNumber": "0x10", "blockHash": f.canonical, "to": g.factory.Hex(), "logs": []map[string]any{}}
	f.nonce = fmt.Sprintf("0x%x", create.Nonce()+1)
	g.codes[strings.ToLower(transit.Hex())] = g.vectors.TransitRuntimeCode
	f.mu.Unlock()
	// Then the sweep itself.
	quote, err = f.h.QuoteAddressWithdrawal(sweep, withdrawalTestDestination, f.noteID, "", false)
	if err != nil || quote.Kind != "transit_sweep" || f.journal(t).Pending != nil {
		t.Fatalf("sweep quote: %+v %v", quote, err)
	}
	if _, err := f.h.ApproveAddressWithdrawal(sweep, quote.ID); err != nil {
		t.Fatal(err)
	}
	record = f.journal(t)
	sweepTx := f.accepted[record.Pending.Hash]
	if record.Pending.Kind != "transit_sweep" || !strings.EqualFold(sweepTx.To().Hex(), transit.Hex()) || hex.EncodeToString(sweepTx.Data()) != selectorTransitSweep {
		t.Fatal("the sweep is not sweep() on the transit account")
	}
	paidOut := new(big.Int).Sub(gaslessPayoutWei, big.NewInt(21))
	f.mu.Lock()
	f.receipts[record.Pending.Hash] = map[string]any{"transactionHash": record.Pending.Hash, "status": "0x1", "blockNumber": "0x10", "blockHash": f.canonical, "to": transit.Hex(), "logs": []map[string]any{{"address": g.paymaster.Hex(), "topics": []string{paymasterCollectedTopic, "0x" + addressWord(transit), "0x" + addressABIWord(strings.ToLower(withdrawalTestDestination))}, "data": "0x" + wordHex(gaslessPayoutWei) + wordHex(big.NewInt(21)) + wordHex(paidOut)}}}
	f.nonce = fmt.Sprintf("0x%x", sweepTx.Nonce()+1)
	f.mu.Unlock()
	status, err = f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.FundsWaitingInTransit || status.ReceivedWei != paidOut.String() || status.OwedPaidWei != "21" || f.journal(t).Withdrawal.SweepHash != strings.ToLower(record.Pending.Hash) {
		t.Fatalf("sweep completion: %+v %v", status, err)
	}
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 1234567); err != nil {
		t.Fatalf("funding after the sweep: %v", err)
	}
}

// After the --fees wallet fallback the fee payer is the wallet, but the
// transit account's balance is still forwarded by a sponsored operation:
// the forward (and a refusal of it) is journaled under the wallet fee
// payer, the journal loads in the same process and after a restart, and
// the forward completes. The fallback from a reverted operation starts
// clean: the reverted operation's bundle transaction is not kept as the
// wallet-paid close's.
func TestGaslessWalletFallbackCollectsWithASponsoredForwardAcrossARestart(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	ctx := payoutContext(payoutFees)
	hash := f.sponsoredClose(t)
	w := f.journal(t).Withdrawal
	transit := common.HexToAddress(w.Transit.Account)
	// The sponsored close was included but reverted: the transit account is
	// stranded.
	bundle := g.mineUserOp(t, hash, false, fixtureSettlement{Charged: big.NewInt(9)})
	if status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID); err != nil || status.Phase != "op_reverted" || status.TransactionHash != bundle {
		t.Fatalf("revert: %+v %v", status, err)
	}
	wallet := payoutContext(addressWithdrawalOptions{Fees: "wallet"})
	quote, err := f.h.QuoteAddressWithdrawal(wallet, withdrawalTestDestination, f.noteID, "", false)
	if err != nil || quote.FeePolicy != "low" || quote.Kind != "withdrawal" {
		t.Fatalf("wallet quote: %+v %v", quote, err)
	}
	if w = f.journal(t).Withdrawal; w.FeePayer != "wallet" || w.Phase != "quoted" || w.TransactionHash != "" || w.UserOp != nil {
		t.Fatalf("the fallback kept the reverted operation's transaction: %+v", w)
	}
	if _, err := f.h.ApproveAddressWithdrawal(wallet, quote.ID); err != nil {
		t.Fatal(err)
	}
	record := f.journal(t)
	if record.Pending == nil || record.Pending.Kind != "withdrawal" || hex.EncodeToString(f.accepted[record.Pending.Hash].Data()[4+10*32+12:4+11*32]) != strings.ToLower(transit.Hex()[2:]) {
		t.Fatalf("no wallet-paid close bound to the transit account: %+v", record.Pending)
	}
	f.mineWithdrawal(t, record.Pending.Hash, transit.Hex(), false)
	f.mu.Lock()
	g.balances[strings.ToLower(transit.Hex())] = new(big.Int).Set(gaslessPayoutWei)
	f.mu.Unlock()
	status, err := f.h.WithdrawAddress(wallet, withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || !status.FundsWaitingInTransit || status.FeePayer != "wallet" {
		t.Fatalf("wallet completion: %+v %v", status, err)
	}
	// The bundler is down at --collect time: the record stays complete with
	// the payout waiting and the reason shown, and loads after a restart.
	g.down = true
	collect := payoutContext(addressWithdrawalOptions{Collect: true})
	if _, err := f.h.QuoteAddressWithdrawal(collect, withdrawalTestDestination, f.noteID, "", false); GaslessRefusalCode(err) != "bundler_unavailable" {
		t.Fatalf("collect with the bundler down: %v", err)
	}
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	status, err = f.h.AddressWithdrawal(context.Background())
	if err != nil || status.Phase != "complete" || !status.FundsWaitingInTransit || !strings.Contains(status.GaslessRefusal, "bundler_unavailable") || !strings.Contains(status.Message, "The sponsored forward stopped") || !strings.Contains(status.Message, "--sweep") {
		t.Fatalf("status after the refused forward: %+v %v", status, err)
	}
	// The bundler is back: --collect quotes and sends the sponsored forward
	// although the wallet paid the close.
	g.down = false
	quote, err = f.h.QuoteAddressWithdrawal(collect, withdrawalTestDestination, f.noteID, "", false)
	if err != nil || quote.UserOpKind != "forward" || quote.FeePolicy != "payout" {
		t.Fatalf("forward quote: %+v %v", quote, err)
	}
	status, err = f.h.ApproveAddressWithdrawal(collect, quote.ID)
	if err != nil || status.Phase != "forward_op_submitted" || len(g.sends) != 2 {
		t.Fatalf("forward: %+v %v", status, err)
	}
	if w = f.journal(t).Withdrawal; w.FeePayer != "wallet" || w.UserOp == nil || w.UserOp.Kind != "forward" || w.GaslessRefusal != "" {
		t.Fatalf("the forward was not journaled under the wallet fee payer: %+v", w)
	}
	// The journal loads in the same process and in a fresh one, and the
	// forward in flight is followed by either command.
	if status, err := f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID); err != nil || status.Phase != "forward_op_submitted" {
		t.Fatalf("same process: %+v %v", status, err)
	}
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	if status, err := f.h.AddressWithdrawal(context.Background()); err != nil || status.Phase != "forward_op_submitted" || status.UserOpHash != g.sends[1] {
		t.Fatalf("after a restart: %+v %v", status, err)
	}
	charged := big.NewInt(300_000_000_000_000)
	paidOut := new(big.Int).Sub(gaslessPayoutWei, charged)
	g.mineUserOp(t, g.sends[1], true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, PaidOut: paidOut})
	status, err = f.h.WithdrawAddress(context.Background(), withdrawalTestDestination, f.noteID)
	if err != nil || status.Phase != "complete" || status.FundsWaitingInTransit || status.ReceivedWei != paidOut.String() || status.FeePayer != "wallet" {
		t.Fatalf("forward completion: %+v %v", status, err)
	}
	f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 1234567); err != nil {
		t.Fatalf("funding after the forward: %v", err)
	}
}

// Design 3.1 pre-flight: the bundler, the paymaster's policy, the vault's
// pause and the fee against the current balance are checked before any
// proof is requested, so a refusal leaves nothing reserved; a refusal after
// the prepare (the key's attempts) is journaled as gasless_refused.
func TestGaslessWithdrawalPreflightRefusesBeforeReserving(t *testing.T) {
	for name, setup := range map[string]func(*withdrawalFixture, *gaslessFixture) string{
		"bundler down": func(f *withdrawalFixture, g *gaslessFixture) string { g.down = true; return "bundler_unavailable" },
		"bundler on another chain": func(f *withdrawalFixture, g *gaslessFixture) string {
			g.wrongChain = true
			return "bundler_wrong_chain"
		},
		"bundler without the entry point": func(f *withdrawalFixture, g *gaslessFixture) string {
			g.unsupportedEntryPoint = true
			return "bundler_unsupported_entry_point"
		},
		"sponsorship paused": func(f *withdrawalFixture, g *gaslessFixture) string {
			g.sponsorshipPaused = true
			return "sponsorship_paused"
		},
		"vault paused": func(f *withdrawalFixture, g *gaslessFixture) string {
			g.vaultPaused, g.pausedAt = true, 1700000000
			return "exits_paused"
		},
		"uneconomic payout": func(f *withdrawalFixture, g *gaslessFixture) string {
			f.walletBalance, f.planBalance = 8_000_000, 8_000_000
			return "gasless_uneconomic"
		},
		"payout below the fee": func(f *withdrawalFixture, g *gaslessFixture) string {
			f.walletBalance, f.planBalance = 1_000_000, 1_000_000
			return "payout_below_gas"
		},
		"fee above the user's cap": func(f *withdrawalFixture, g *gaslessFixture) string { return "fee_above_cap" },
		"fee spike above the ceiling": func(f *withdrawalFixture, g *gaslessFixture) string {
			g.maxFeeCeiling = big.NewInt(500_000_000)
			return "gas_above_paymaster_ceiling"
		},
		"paymaster underfunded": func(f *withdrawalFixture, g *gaslessFixture) string {
			g.deposit = big.NewInt(1)
			return "paymaster_underfunded"
		},
		"policy mismatch": func(f *withdrawalFixture, g *gaslessFixture) string {
			g.flatFee = big.NewInt(1)
			g.profile.GasPolicy.MarginGas++
			return "gasless_unavailable"
		},
		"no bundler configured": func(f *withdrawalFixture, g *gaslessFixture) string {
			f.h.client.config.BundlerURL = ""
			return "bundler_unavailable"
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, g := newGaslessWithdrawalFixture(t)
			code := setup(f, g)
			options := payoutFees
			if code == "fee_above_cap" {
				options.FeeCapGwei = 1
			}
			_, err := f.h.QuoteAddressWithdrawal(payoutContext(options), withdrawalTestDestination, f.noteID, "", false)
			if GaslessRefusalCode(err) != code {
				t.Fatalf("got %v, want %s", err, code)
			}
			if code == "paymaster_underfunded" {
				// Read after the prepare (the deposit against the exact
				// maximum cost); the reservation is journaled as refused.
				if w := f.journal(t).Withdrawal; w == nil || w.Phase != "gasless_refused" {
					t.Fatalf("not journaled: %+v", w)
				}
				return
			}
			if f.prepareCalls != 0 || f.journal(t).Withdrawal != nil || len(g.sends) != 0 {
				t.Fatalf("something was reserved or sent: %d %+v", f.prepareCalls, f.journal(t).Withdrawal)
			}
			// The wallet path is unaffected.
			if _, err := f.h.QuoteAddressWithdrawal(context.Background(), withdrawalTestDestination, f.noteID, "", false); err != nil && code != "vault paused" {
				t.Fatalf("the wallet path was refused: %v", err)
			}
		})
	}
	// Accepting an expensive fee lifts only the uneconomic refusal.
	f, _ := newGaslessWithdrawalFixture(t)
	f.walletBalance, f.planBalance = 8_000_000, 8_000_000
	if _, err := f.h.QuoteAddressWithdrawal(payoutContext(addressWithdrawalOptions{Fees: "payout", AllowExpensiveGas: true}), withdrawalTestDestination, f.noteID, "", false); err != nil {
		t.Fatalf("an accepted expensive fee was refused: %v", err)
	}
	// The key's attempts are read once the nullifier is known: a refusal
	// after the prepare leaves the reservation as gasless_refused, and the
	// wallet fallback reuses it.
	f, g := newGaslessWithdrawalFixture(t)
	g.attempts[gaslessKey(gaslessKindClose, new(big.Int).SetBytes(common.FromHex(withdrawalTestPlan(withdrawalTestDestination)["public_inputs"].(map[string]any)["withdrawal_nullifier"].(string))), 0, common.Address{}).Hex()[2:]] = 3
	_, err := f.h.QuoteAddressWithdrawal(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, "", false)
	if GaslessRefusalCode(err) != "gasless_attempts_exhausted" || f.journal(t).Withdrawal.Phase != "gasless_refused" {
		t.Fatalf("attempts: %v %+v", err, f.journal(t).Withdrawal)
	}
}

// The transit accounts' implementation is pinned like the other gasless
// contracts: a profile without its address or runtime codehash, or whose
// account creation code embeds another implementation, disables --fees
// payout (gasless_unavailable) before any chain read.
func TestGaslessProfileRequiresTheAccountImplementationPin(t *testing.T) {
	for name, edit := range map[string]func(map[string]any){
		"no implementation address":  func(g map[string]any) { delete(g, "withdrawal_account_implementation_address") },
		"no implementation codehash": func(g map[string]any) { delete(g, "withdrawal_account_implementation_runtime_codehash") },
		"another implementation": func(g map[string]any) {
			g["withdrawal_account_implementation_address"] = "0x" + strings.Repeat("ab", 20)
		},
	} {
		t.Run(name, func(t *testing.T) {
			f, _ := newGaslessWithdrawalFixture(t)
			installGaslessProfile(t, func(gasless map[string]any) any {
				edit(gasless)
				return gasless
			})
			if err := f.h.client.CheckGaslessDeployment(context.Background()); !errors.Is(err, errGaslessUnavailable) || !strings.Contains(err.Error(), "gasless object") {
				t.Fatalf("accepted: %v", err)
			}
		})
	}
}

// Design 4.4: the gasless deployment checks run through the pinned and the
// exit RPC before the first gasless prepare; a mismatch disables --fees
// payout and nothing else.
func TestGaslessDeploymentChecksDisableOnlyThePayoutPath(t *testing.T) {
	for name, tamper := range map[string]func(*gaslessFixture){
		"paymaster code":   func(g *gaslessFixture) { g.codes[strings.ToLower(g.paymaster.Hex())] = "0x6001" },
		"factory code":     func(g *gaslessFixture) { g.codes[strings.ToLower(g.factory.Hex())] = "0x6002" },
		"entry point code": func(g *gaslessFixture) { g.codes[strings.ToLower(g.entryPoint.Hex())] = "0x6003" },
		// Other transit account logic behind honest factory, paymaster and
		// EntryPoint runtimes (a constructor can deploy anything).
		"implementation code":    func(g *gaslessFixture) { g.codes[strings.ToLower(g.profile.Implementation)] = "0x6004" },
		"factory implementation": func(g *gaslessFixture) { g.implementation = common.HexToAddress("0x" + strings.Repeat("ab", 20)) },
		"gas policy":             func(g *gaslessFixture) { g.profile.GasPolicy.MarginGas = 1 },
		"another vault":          func(g *gaslessFixture) { g.vault = common.HexToAddress("0x1234") },
	} {
		t.Run(name, func(t *testing.T) {
			f, g := newGaslessWithdrawalFixture(t)
			tamper(g)
			if err := f.h.client.CheckGaslessDeployment(context.Background()); !errors.Is(err, errGaslessUnavailable) {
				t.Fatalf("accepted: %v", err)
			}
			if _, err := f.h.QuoteAddressWithdrawal(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, "", false); !errors.Is(err, errGaslessUnavailable) {
				t.Fatalf("the payout path was not refused: %v", err)
			}
			if err := f.h.client.CheckDeployment(context.Background()); err != nil {
				t.Fatalf("the vault checks were affected: %v", err)
			}
			if _, err := f.h.QuoteAddressWithdrawal(context.Background(), withdrawalTestDestination, f.noteID, "", false); err != nil {
				t.Fatalf("the wallet path was refused: %v", err)
			}
		})
	}
	f, g := newGaslessWithdrawalFixture(t)
	if err := f.h.client.CheckGaslessDeployment(context.Background()); err != nil {
		t.Fatal(err)
	}
	availability, err := f.h.GaslessAvailability(context.Background())
	if err != nil || !availability.Available || availability.BundlerURL != g.url || availability.FlatFeeWei != g.flatFee.String() {
		t.Fatalf("availability: %+v %v", availability, err)
	}
	g.sponsorshipPaused = true
	if availability, err := f.h.GaslessAvailability(context.Background()); err != nil || availability.Available || availability.Reason != "sponsorship_paused" {
		t.Fatalf("paused availability: %+v %v", availability, err)
	}
}

// The journal's gasless record is validated on every load: a tampered
// operation, hash, key or transit account is refused and nothing is sent.
func TestGaslessJournalTamperingIsRefused(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	f.sponsoredClose(t)
	for name, tamper := range map[string]func(*addressWithdrawalRecord){
		"calldata": func(w *addressWithdrawalRecord) {
			w.UserOp.JSON = json.RawMessage(strings.Replace(string(w.UserOp.JSON), "0968f264", "0968f265", 1))
		},
		"hash":        func(w *addressWithdrawalRecord) { w.UserOp.Hash = "0x" + strings.Repeat("a", 64) },
		"owner":       func(w *addressWithdrawalRecord) { w.Transit.Owner = addressTestToken },
		"proof":       func(w *addressWithdrawalRecord) { w.ProofDestination = addressTestToken },
		"destination": func(w *addressWithdrawalRecord) { w.Destination = addressTestToken },
		"fee payer":   func(w *addressWithdrawalRecord) { w.FeePayer = "" },
		"signature": func(w *addressWithdrawalRecord) {
			w.UserOp.JSON = json.RawMessage(strings.Replace(string(w.UserOp.JSON), `"signature":"0x`, `"signature":"0x00`, 1))
		},
	} {
		t.Run(name, func(t *testing.T) {
			original := f.journal(t)
			record := f.journal(t)
			tamper(record.Withdrawal)
			if err := f.h.saveAddress(&record); err != nil {
				t.Fatal(err)
			}
			f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
			sends := len(g.sends)
			if _, err := f.h.WithdrawAddress(payoutContext(payoutFees), withdrawalTestDestination, f.noteID); err == nil {
				t.Fatal("tampered journal accepted")
			}
			if len(g.sends) != sends {
				t.Fatal("a tampered operation was sent")
			}
			if err := f.h.saveAddress(&original); err != nil {
				t.Fatal(err)
			}
		})
	}
}

// TestGaslessFeeParity asserts the fee rule on the table the SDK's selectFees
// asserts too (testdata/gasless-fee-parity.json): the same inputs give the
// same fee fields or the same refusal in both clients.
func TestGaslessFeeParity(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "gasless-fee-parity.json"))
	if err != nil {
		t.Fatal(err)
	}
	var table struct {
		MaxFeeCeiling      string `json:"maxFeeCeiling"`
		PriorityFeeCeiling string `json:"priorityFeeCeiling"`
		Cases              []struct {
			Name                 string `json:"name"`
			Base                 string `json:"base"`
			Tip                  string `json:"tip"`
			MaxFeeCeiling        string `json:"maxFeeCeiling"`
			PriorityFeeCeiling   string `json:"priorityFeeCeiling"`
			MaxFeePerGas         string `json:"maxFeePerGas"`
			MaxPriorityFeePerGas string `json:"maxPriorityFeePerGas"`
			Refused              string `json:"refused"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(raw, &table); err != nil {
		t.Fatal(err)
	}
	wei := func(value, fallback string) *big.Int {
		if value == "" {
			value = fallback
		}
		n, ok := new(big.Int).SetString(value, 10)
		if !ok {
			t.Fatalf("not a decimal wei amount: %q", value)
		}
		return n
	}
	if len(table.Cases) < 10 {
		t.Fatalf("the parity table has %d cases", len(table.Cases))
	}
	for _, c := range table.Cases {
		t.Run(c.Name, func(t *testing.T) {
			maxCeiling := wei(c.MaxFeeCeiling, table.MaxFeeCeiling)
			priorityCeiling := wei(c.PriorityFeeCeiling, table.PriorityFeeCeiling)
			base, tip := wei(c.Base, ""), wei(c.Tip, "")
			maxFee, priority, err := selectGaslessFees(base, tip, maxCeiling, priorityCeiling)
			if c.Refused != "" {
				if GaslessRefusalCode(err) != c.Refused || maxFee != nil || priority != nil {
					t.Fatalf("got %v %v %v, want refusal %s", maxFee, priority, err, c.Refused)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if maxFee.Cmp(wei(c.MaxFeePerGas, "")) != 0 || priority.Cmp(wei(c.MaxPriorityFeePerGas, "")) != 0 {
				t.Fatalf("got maxFee %s priority %s, want %s %s", maxFee, priority, c.MaxFeePerGas, c.MaxPriorityFeePerGas)
			}
			// The inputs are not aliased into the result.
			if maxFee == maxCeiling || priority == tip || priority == priorityCeiling {
				t.Fatal("the result aliases an input")
			}
		})
	}
}
