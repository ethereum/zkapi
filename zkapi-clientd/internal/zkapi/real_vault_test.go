package zkapi

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
)

// realVaultLayout is the revision-3 vault's selectors and event layouts as
// the compiled protocol/contracts sources produce them
// (crates/zkapi-serverd/tests/fixtures/vault_calldata_golden.json, which
// check-calldata-golden.sh keeps equal to the contracts).
type realVaultLayout struct {
	Selectors map[string]string `json:"selectors"`
	Events    map[string]struct {
		Topic0 string `json:"topic0"`
		Topics string `json:"topics"`
		Data   string `json:"data"`
	} `json:"events"`
}

func loadRealVaultLayout(t *testing.T) realVaultLayout {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "crates", "zkapi-serverd", "tests", "fixtures", "vault_calldata_golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	var layout realVaultLayout
	if err := json.Unmarshal(raw, &layout); err != nil {
		t.Fatal(err)
	}
	return layout
}

func TestEverySelectorAndTopicIsTheRealVaults(t *testing.T) {
	layout := loadRealVaultLayout(t)
	selectors := map[string]string{
		"mutualClose":               withdrawalSelector,
		"initiateEscapeWithdrawal":  escapeSelector,
		"finalizeEscapeWithdrawal":  finalizeEscapeSelector,
		"claimEscapePayout":         claimEscapePayoutSelector,
		"escapePayoutCredits":       escapePayoutCreditsSelector,
		"notes":                     notesSelector,
		"proofAdapter":              selectorProofAdapter,
		"stateSigningKeyX":          selectorStateSigningKeyX,
		"stateSigningKeyY":          selectorStateSigningKeyY,
		"clearanceSigningKeyX":      selectorClearanceSigningKeyX,
		"clearanceSigningKeyY":      selectorClearanceSigningKeyY,
		"challengePeriod":           selectorChallengePeriod,
		"noteTtl":                   selectorNoteTTL,
		"maxPauseDuration":          selectorMaxPauseDuration,
		"CONCESSION_ESCAPE_VERSION": selectorConcessionEscapeVersion,
		"ROOT_HISTORY_WINDOW":       selectorRootHistoryWindow,
		"CIRCUIT_ID_HASH":           selectorCircuitIDHash,
		"REQUEST_VK_HASH":           selectorRequestVKHash,
		"WITHDRAWAL_VK_HASH":        selectorWithdrawalVKHash,
		"deposit":                   depositSelector,
	}
	for name, ours := range selectors {
		real, ok := layout.Selectors[name]
		if !ok {
			t.Fatalf("the real vault layout has no %s", name)
		}
		if "0x"+strings.TrimPrefix(ours, "0x") != real {
			t.Fatalf("%s: clientd uses %s, the real vault %s", name, ours, real)
		}
	}
	topics := map[string]string{
		"MutualClose":               withdrawalEventTopic,
		"EscapeWithdrawalFinalized": escapeFinalizedEventTopic,
		"EscapePayoutDeferred":      escapePayoutDeferredEventTopic,
		"EscapeConcessionRecorded":  escapeConcessionRecordedTopic,
		"EscapeConcessionRaised":    escapeConcessionRaisedTopic,
		"NoteDeposited":             depositEventTopic,
	}
	for name, ours := range topics {
		event, ok := layout.Events[name]
		if !ok {
			t.Fatalf("the real vault layout has no event %s", name)
		}
		if !strings.EqualFold(ours, event.Topic0) {
			t.Fatalf("%s: clientd matches topic %s, the real vault emits %s", name, ours, event.Topic0)
		}
	}
	// The payout matchers read EscapeWithdrawalFinalized as two topics and
	// three data words, and EscapePayoutDeferred as three topics and one word.
	if finalized := layout.Events["EscapeWithdrawalFinalized"]; len(finalized.Topics) != 2+2*64 || !isHex(finalized.Data, 96) {
		t.Fatalf("EscapeWithdrawalFinalized layout changed: %+v", finalized)
	}
	if deferred := layout.Events["EscapePayoutDeferred"]; len(deferred.Topics) != 2+3*64 || !isHex(deferred.Data, 32) {
		t.Fatalf("EscapePayoutDeferred layout changed: %+v", deferred)
	}
}

// The shared withdrawal golden vector (design §11 WP-F): real kind-0 and
// kind-1 proofs whose calldata Forge pins to abi.encodeCall against the real
// vault (protocol/contracts/test/fixtures/withdrawal-golden.json). The escape
// goes through escapeCalldata and the close through withdrawalCalldata, each
// with the owner's confirmation and checks, and must produce exactly the
// golden bytes. With ZKAPI_WITHDRAWAL_GOLDEN_OUT set, the output is written
// there for scripts/check-withdrawal-golden.mjs, which submits it to a vault
// on Anvil.
func TestRealProofsEncodeToTheSharedWithdrawalGoldenVector(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "protocol", "contracts", "test", "fixtures", "withdrawal-golden.json"))
	if err != nil {
		t.Fatal(err)
	}
	type statement struct {
		PublicInputs withdrawalInputs `json:"public_inputs"`
		Proof        string           `json:"proof"`
		StateBalance string           `json:"state_balance"`
		Calldata     string           `json:"calldata"`
	}
	var golden struct {
		ChainID    uint64 `json:"chain_id"`
		Deployment struct {
			Vault string `json:"vault"`
		} `json:"deployment"`
		Escape statement `json:"escape"`
		Close  statement `json:"close"`
	}
	if err := json.Unmarshal(raw, &golden); err != nil {
		t.Fatal(err)
	}
	config := fundingConfig{ChainID: golden.ChainID, Contract: golden.Deployment.Vault}
	// The signing window opens VALIDITY before a proof's valid_until.
	signingTime := func(p withdrawalInputs) time.Time { return time.Unix(int64(p.ValidUntil)-exitProofValidity, 0) }
	destination := func(p withdrawalInputs) string { return common.BytesToAddress(p.Destination).Hex() }

	e := golden.Escape
	var plan escapePlan
	plan.Status, plan.Action, plan.NoteID = "prepared", "escape", e.PublicInputs.NoteID
	plan.StateBalance, plan.Conceded = e.StateBalance, fmt.Sprint(e.PublicInputs.Conceded)
	plan.PublicInputs = e.PublicInputs
	plan.Proof.Backend, plan.Proof.Proof = "groth16_bn254", e.Proof
	stateBalance, _ := parseUnits(e.StateBalance)
	saved := &addressWithdrawalRecord{NoteID: e.PublicInputs.NoteID, Destination: destination(e.PublicInputs), Mode: "escape",
		StateBalance: stateBalance, Conceded: e.PublicInputs.Conceded, Bound: e.PublicInputs.Conceded}
	escape, _, err := escapeCalldata(plan, config, saved, signingTime(e.PublicInputs))
	if err != nil {
		t.Fatal(err)
	}
	if escape != e.Calldata {
		t.Fatalf("escape calldata differs from the golden vector:\n%s\n%s", escape, e.Calldata)
	}

	c := golden.Close
	var closePlan withdrawalPlan
	closePlan.Mode, closePlan.PublicInputs = "mutual", c.PublicInputs
	closePlan.Proof.Backend, closePlan.Proof.Proof = "groth16_bn254", c.Proof
	closeSaved := &addressWithdrawalRecord{NoteID: c.PublicInputs.NoteID, Destination: destination(c.PublicInputs)}
	closeData, _, err := withdrawalCalldata(closePlan, config, closeSaved, c.PublicInputs.FinalBalance, signingTime(c.PublicInputs))
	if err != nil {
		t.Fatal(err)
	}
	if closeData != c.Calldata {
		t.Fatalf("close calldata differs from the golden vector:\n%s\n%s", closeData, c.Calldata)
	}
	if dir := os.Getenv("ZKAPI_WITHDRAWAL_GOLDEN_OUT"); dir != "" {
		output, _ := json.Marshal(map[string]string{"escape": escape, "close": closeData})
		if err := os.WriteFile(filepath.Join(dir, "go-clientd.json"), output, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}
