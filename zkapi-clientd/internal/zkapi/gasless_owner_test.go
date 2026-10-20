package zkapi

import (
	"bytes"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// transitOwnerVectors is testdata/transit-owner-vectors.json, the table the
// SDK's deriveTransitOwnerKey asserts too (sdk/test/zkapi-gasless.test.mjs).
type transitOwnerVectors struct {
	Derivation          string `json:"derivation"`
	AccountCreationCode string `json:"account_creation_code"`
	Cases               []struct {
		Name                string   `json:"name"`
		Seed                string   `json:"seed"`
		ChainID             string   `json:"chain_id"`
		EntryPoint          string   `json:"entry_point"`
		Vault               string   `json:"vault"`
		Factory             string   `json:"factory"`
		Paymaster           string   `json:"paymaster"`
		AccountCreationCode string   `json:"account_creation_code"`
		CreationCodeKeccak  string   `json:"account_creation_code_keccak256"`
		Payee               string   `json:"payee"`
		RejectCounters      []uint32 `json:"reject_counters"`
		Counter             uint32   `json:"counter"`
		OwnerPrivateKey     string   `json:"owner_private_key"`
		Owner               string   `json:"owner"`
		TransitAccount      string   `json:"transit_account"`
	} `json:"cases"`
}

func loadTransitOwnerVectors(t *testing.T) transitOwnerVectors {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "transit-owner-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var vectors transitOwnerVectors
	if err := json.Unmarshal(raw, &vectors); err != nil {
		t.Fatal(err)
	}
	return vectors
}

// secp256k1N is the group order: an expansion equal to it is the smallest
// invalid scalar above the range.
var secp256k1N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

// TestTransitOwnerDerivationFollowsTheSharedVectors derives every vector's
// owner key, owner and transit account. A rejection case replaces the
// expansion at its counters with n, then 0 (the two kinds of invalid
// scalar), so the derivation resamples to the next counter.
func TestTransitOwnerDerivationFollowsTheSharedVectors(t *testing.T) {
	vectors := loadTransitOwnerVectors(t)
	if vectors.Derivation != transitOwnerDerivationV1 || len(vectors.Cases) < 10 {
		t.Fatalf("vectors: %s, %d cases", vectors.Derivation, len(vectors.Cases))
	}
	resampled := false
	seen := map[string]bool{}
	for _, c := range vectors.Cases {
		t.Run(c.Name, func(t *testing.T) {
			creation := common.FromHex(vectors.AccountCreationCode)
			if c.AccountCreationCode != "" {
				creation = common.FromHex(c.AccountCreationCode)
			}
			if crypto.Keccak256Hash(creation).Hex() != c.CreationCodeKeccak {
				t.Fatal("the vector's creation code does not hash to its keccak")
			}
			chainID, ok := new(big.Int).SetString(c.ChainID, 10)
			if !ok || !chainID.IsUint64() {
				t.Fatalf("chain ID %q", c.ChainID)
			}
			scope := transitOwnerScopeOf(chainID.Uint64(), c.Vault, c.EntryPoint, c.Factory, c.Paymaster, c.CreationCodeKeccak, c.Payee)
			if len(scope.info(0)) != 168 || !bytes.Equal(scope.info(7)[164:], []byte{0, 0, 0, 7}) {
				t.Fatal("the info is not 168 bytes ending with the big-endian counter")
			}
			rejections := 0
			expand := func(prk, info []byte) ([]byte, error) {
				counter := uint32(info[164])<<24 | uint32(info[165])<<16 | uint32(info[166])<<8 | uint32(info[167])
				for _, rejected := range c.RejectCounters {
					if rejected == counter {
						rejections++
						if rejections%2 == 1 {
							return common.LeftPadBytes(secp256k1N.Bytes(), 32), nil
						}
						return make([]byte, 32), nil
					}
				}
				return transitOwnerExpand(prk, info)
			}
			key, counter, err := deriveTransitOwnerKeyWith(common.FromHex(c.Seed), scope, expand)
			if err != nil {
				t.Fatal(err)
			}
			if rejections != len(c.RejectCounters) || counter != c.Counter {
				t.Fatalf("counter %d after %d rejections, want %d", counter, rejections, c.Counter)
			}
			resampled = resampled || counter > 0
			if got := "0x" + common.Bytes2Hex(crypto.FromECDSA(key)); got != c.OwnerPrivateKey {
				t.Fatalf("owner key %s, want %s", got, c.OwnerPrivateKey)
			}
			owner := crypto.PubkeyToAddress(key.PublicKey)
			if owner.Hex() != c.Owner {
				t.Fatalf("owner %s, want %s", owner.Hex(), c.Owner)
			}
			account := transitAccountAddress(scope.Factory, creation, scope.EntryPoint, scope.Vault, scope.Paymaster, owner, scope.Payee)
			if account.Hex() != c.TransitAccount {
				t.Fatalf("transit account %s, want %s", account.Hex(), c.TransitAccount)
			}
			if len(c.RejectCounters) == 0 {
				// Without injected rejections the plain derivation agrees.
				plain, plainCounter, err := deriveTransitOwnerKey(common.FromHex(c.Seed), scope)
				if err != nil || plain.D.Cmp(key.D) != 0 || plainCounter != counter {
					t.Fatal("deriveTransitOwnerKey disagrees with its expansion")
				}
				if seen[c.OwnerPrivateKey] {
					t.Fatal("two scopes derived one key")
				}
				seen[c.OwnerPrivateKey] = true
			}
		})
	}
	if !resampled {
		t.Fatal("no vector reaches the resampling")
	}
}

// The derivation refuses a seed shorter than 32 bytes, and gives up (an
// error, not a loop) when every counter is rejected.
func TestTransitOwnerDerivationRefusesAShortSeedAndBoundsTheResampling(t *testing.T) {
	scope := transitOwnerScopeOf(1, addressTestVault, gaslessEntryPointAddressForTest, addressTestToken, addressTestToken, "0x"+strings.Repeat("11", 32), withdrawalTestDestination)
	if _, _, err := deriveTransitOwnerKey(make([]byte, 31), scope); err == nil {
		t.Fatal("a 31-byte seed was accepted")
	}
	calls := 0
	_, _, err := deriveTransitOwnerKeyWith(bytes.Repeat([]byte{1}, 32), scope, func(prk, info []byte) ([]byte, error) {
		calls++
		return make([]byte, 32), nil
	})
	if err == nil || calls != transitOwnerMaxCounter {
		t.Fatalf("every counter rejected: %v after %d expansions", err, calls)
	}
}

const gaslessEntryPointAddressForTest = "0x0000000071727De22E5E9d8BAf0edAc6f37da032"

// expectedTransit is the transit account the fixture wallet derives for
// payee under the test profile: the owner key from the funding key.
func (g *gaslessFixture) expectedTransit(t *testing.T, record addressFundingRecord, payee string) (owner, account common.Address, key string) {
	t.Helper()
	derived, _, err := deriveTransitOwnerKey(common.FromHex(record.PrivateKey), transitOwnerScopeOf(record.ChainID, record.Contract, g.profile.EntryPoint, g.profile.Factory, g.profile.Paymaster, g.profile.AccountCreationCodeHash, payee))
	if err != nil {
		t.Fatal(err)
	}
	owner = crypto.PubkeyToAddress(derived.PublicKey)
	return owner, g.transitAccount(owner, common.HexToAddress(payee)), common.Bytes2Hex(crypto.FromECDSA(derived))
}

// Phase A3: the transit account of a payout address is derived from the
// funding key, journaled with its derivation, and reused: the first
// sponsored close creates it through initCode; once it has code, the next
// withdrawal to the same payout address (here the next note, after the
// first completed) is quoted and sent from the same sender without initCode,
// under the verification limit without initCode, and settles the same way.
func TestGaslessWithdrawalsToOnePayeeReuseTheTransitAccount(t *testing.T) {
	f, g := newGaslessWithdrawalFixture(t)
	ctx := payoutContext(payoutFees)
	owner, account, ownerKey := g.expectedTransit(t, f.journal(t), withdrawalTestDestination)
	first := f.sponsoredClose(t)
	w := f.journal(t).Withdrawal
	if w.Transit.OwnerDerivation != transitOwnerDerivationV1 || w.Transit.OwnerKey != ownerKey || w.Transit.Owner != owner.Hex() || w.Transit.Account != account.Hex() || !w.UserOp.InitCode {
		t.Fatalf("the first withdrawal's transit account is not the derived one, created by initCode: %+v %+v", w.Transit, w.UserOp)
	}
	if sent := g.sentOp(t, first); len(sent.InitCode) == 0 || sent.VerificationGasLimit != g.profile.GasPolicy.VerificationDefaultInit {
		t.Fatalf("the first operation: initCode %d bytes, verification %d", len(sent.InitCode), sent.VerificationGasLimit)
	}
	charged := big.NewInt(2_000_000_000_000_000)
	g.mineUserOp(t, first, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, PaidOut: new(big.Int).Sub(gaslessPayoutWei, charged)})
	f.finalized = "0x20"
	if status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID); err != nil || status.Phase != "complete" {
		t.Fatalf("the first withdrawal: %+v %v", status, err)
	}

	// The next note of this wallet (its deposit is the address fixture's
	// concern): the complete withdrawal is retired as a deposit retires it.
	f.mu.Lock()
	f.vaultNotes[13] = fixtureNote{commitment: f.vaultNotes[12].commitment, amount: f.vaultNotes[12].amount, expiry: f.vaultNotes[12].expiry, status: noteActive}
	f.mu.Unlock()
	f.editJournal(t, func(record *addressFundingRecord) {
		retireWithdrawal(record)
		record.Phase, record.Amount = "active", 100000
	})
	f.noteID, f.active, f.walletBalance, f.planBalance = 13, true, gaslessTestBalance, gaslessTestBalance
	quote, err := f.h.QuoteAddressWithdrawal(ctx, withdrawalTestDestination, f.noteID, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.EqualFold(quote.TransitAccount, account.Hex()) || quote.UserOpGas == nil || quote.UserOpGas.InitCode || quote.UserOpGas.VerificationGasLimit != g.profile.GasPolicy.VerificationDefault {
		t.Fatalf("the second quote does not reuse the transit account without initCode: %+v %+v", quote, quote.UserOpGas)
	}
	status, err := f.h.ApproveAddressWithdrawal(ctx, quote.ID)
	if err != nil || status.Phase != "op_submitted" {
		t.Fatalf("the second approval: %+v %v", status, err)
	}
	second := g.sentOp(t, status.UserOpHash)
	if second.Sender != account || len(second.InitCode) != 0 || second.VerificationGasLimit != g.profile.GasPolicy.VerificationDefault {
		t.Fatalf("the second operation: sender %s, initCode %d bytes, verification %d", second.Sender.Hex(), len(second.InitCode), second.VerificationGasLimit)
	}
	if signer, err := recoverUserOpSigner(second.hash(g.entryPoint, 1), second.Signature); err != nil || signer != owner {
		t.Fatal("the second operation is not signed by the same derived owner")
	}
	if w := f.journal(t).Withdrawal; w.NoteID != 13 || w.UserOp.InitCode || w.Transit.Account != account.Hex() {
		t.Fatalf("the second record: %+v", w)
	}
	g.mineUserOp(t, status.UserOpHash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, PaidOut: new(big.Int).Sub(gaslessPayoutWei, charged)})
	if status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID); err != nil || status.Phase != "complete" {
		t.Fatalf("the second withdrawal: %+v %v", status, err)
	}
	// Another payout address gets another owner and another transit account.
	otherOwner, otherAccount, _ := g.expectedTransit(t, f.journal(t), addressTestToken)
	if otherOwner == owner || otherAccount == account {
		t.Fatal("another payout address shares the transit account")
	}
}

// A record of an earlier build holds a random owner key (no
// owner_derivation) and is still followed and settled with it; a derived
// record whose journaled key is not the derived one is refused, and one
// whose key copy is missing recovers it from the funding key.
func TestGaslessTransitOwnerKeyReadsEarlierRecordsAndRederives(t *testing.T) {
	t.Run("earlier build", func(t *testing.T) {
		// A record as an earlier build journaled it: owner_key without
		// owner_derivation (that build drew the key at random; to the reader
		// the derived key below is just as arbitrary), its operation in
		// flight. It is followed and settled from the journaled key alone.
		f, g := newGaslessWithdrawalFixture(t)
		ctx := payoutContext(payoutFees)
		hash := f.sponsoredClose(t)
		f.editJournal(t, func(record *addressFundingRecord) { record.Withdrawal.Transit.OwnerDerivation = "" })
		raw, _ := os.ReadFile(f.h.addressStatePath())
		if strings.Contains(string(raw), "owner_derivation") {
			t.Fatal("an earlier build's record carries owner_derivation")
		}
		random, _ := crypto.GenerateKey()
		legacy := f.journal(t)
		legacy.PrivateKey = common.Bytes2Hex(crypto.FromECDSA(random))
		if key, err := transitOwnerKey(&legacy); err != nil || common.Bytes2Hex(crypto.FromECDSA(key)) != legacy.Withdrawal.Transit.OwnerKey {
			t.Fatalf("the earlier record's key depends on the funding key: %v", err)
		}
		charged := big.NewInt(2_000_000_000_000_000)
		g.mineUserOp(t, hash, true, fixtureSettlement{Received: gaslessPayoutWei, Charged: charged, PaidOut: new(big.Int).Sub(gaslessPayoutWei, charged)})
		f.finalized = "0x20"
		f.h = &FundingHandler{client: f.h.client, statePath: f.h.statePath}
		if status, err := f.h.WithdrawAddress(ctx, withdrawalTestDestination, f.noteID); err != nil || status.Phase != "complete" {
			t.Fatalf("the earlier record was not settled: %+v %v", status, err)
		}
		if f.journal(t).Withdrawal.Transit.OwnerDerivation != "" {
			t.Fatal("the earlier record was rewritten as a derived one")
		}
	})
	t.Run("derived", func(t *testing.T) {
		f, _ := newGaslessWithdrawalFixture(t)
		f.sponsoredClose(t)
		record := f.journal(t)
		key, err := transitOwnerKey(&record)
		if err != nil || common.Bytes2Hex(crypto.FromECDSA(key)) != record.Withdrawal.Transit.OwnerKey {
			t.Fatalf("the derived record's key: %v", err)
		}
		missing := f.journal(t)
		missing.Withdrawal.Transit.OwnerKey = ""
		if again, err := transitOwnerKey(&missing); err != nil || again.D.Cmp(key.D) != 0 {
			t.Fatalf("a missing key copy is not derived again: %v", err)
		}
		other, _ := crypto.GenerateKey()
		tampered := f.journal(t)
		tampered.Withdrawal.Transit.OwnerKey = common.Bytes2Hex(crypto.FromECDSA(other))
		tampered.Withdrawal.Transit.Owner = crypto.PubkeyToAddress(other.PublicKey).Hex()
		if _, err := transitOwnerKey(&tampered); err == nil || !strings.Contains(err.Error(), "not the one derived") {
			t.Fatalf("a journaled key other than the derived one: %v", err)
		}
		unknown := f.journal(t)
		unknown.Withdrawal.Transit.OwnerDerivation = "hkdf-sha256/zkapi-transit-owner-v9"
		if _, err := transitOwnerKey(&unknown); err == nil {
			t.Fatal("an unknown derivation was accepted")
		}
		// The funding key decides: another wallet's key derives another owner.
		foreign := f.journal(t)
		foreign.PrivateKey = common.Bytes2Hex(crypto.FromECDSA(other))
		foreign.Withdrawal.Transit.OwnerKey = ""
		if _, err := transitOwnerKey(&foreign); err == nil {
			t.Fatal("another funding key recovered this record's owner")
		}
	})
}

// Phase A3: one transit account serves every escape of the wallet to one
// payout address, and the paymaster keeps one open sponsored escape per
// transit account. While its recorded escape is pending, or closed with the
// payout still in S, a sponsored escape from S is refused before anything is
// reserved or proved (transit_escape_pending), naming the wallet-paid escape;
// once S's escape settled, or for a close, nothing is refused.
func TestGaslessEscapeFromATransitAccountWithAnOpenEscapeIsRefused(t *testing.T) {
	for _, c := range []struct {
		name    string
		status  uint8
		balance int64
		refused bool
	}{
		{"pending", notePendingWithdrawal, 0, true},
		{"closed, payout waiting in S", noteClosed, 1, true},
		{"closed, S emptied", noteClosed, 0, false},
		{"active again (defeated)", noteActive, 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, g := newGaslessWithdrawalFixture(t)
			f.escape = &escapeCompanion{conceded: 0, bound: 0, chainPhase: "pending"}
			_, account, _ := g.expectedTransit(t, f.journal(t), withdrawalTestDestination)
			g.createTransitAccount(t, account.Hex())
			f.mu.Lock()
			f.vaultNotes[9] = fixtureNote{commitment: f.vaultNotes[12].commitment, amount: f.vaultNotes[12].amount, expiry: f.vaultNotes[12].expiry, status: c.status}
			g.escapeNote[strings.ToLower(account.Hex())] = 9 + 1
			g.balances[strings.ToLower(account.Hex())] = big.NewInt(c.balance)
			f.mu.Unlock()
			status, err := f.h.EscapeAddress(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, nil, "")
			if !c.refused {
				if err != nil || status.Phase != "escape_decision" || !strings.EqualFold(status.TransitAccount, account.Hex()) {
					t.Fatalf("a settled escape of S refused the next one: %+v %v", status, err)
				}
				// S's recorded escape turns pending again (another client of
				// this wallet escaped meanwhile): the quote's escapeOpen is
				// refused as transit_escape_pending, not as escapes disabled.
				f.mu.Lock()
				note := f.vaultNotes[9]
				note.status = notePendingWithdrawal
				f.vaultNotes[9] = note
				f.mu.Unlock()
				if _, err := f.h.QuoteAddressEscape(payoutContext(payoutFees), withdrawalTestDestination, f.noteID, &[]uint64{0}[0], ""); GaslessRefusalCode(err) != GaslessTransitEscapePending {
					t.Fatalf("the quote: %v", err)
				}
				return
			}
			if GaslessRefusalCode(err) != GaslessTransitEscapePending || !strings.Contains(err.Error(), "--fees wallet") || !strings.Contains(err.Error(), account.Hex()) {
				t.Fatalf("not refused as transit_escape_pending: %v", err)
			}
			if record := f.journal(t); record.Withdrawal != nil || len(f.escape.prepares) != 0 || len(g.sends) != 0 {
				t.Fatalf("something was reserved, prepared or sent: %+v", record.Withdrawal)
			}
			// A close to the same payout address from the same S is sponsored.
			hash := f.sponsoredClose(t)
			if sent := g.sentOp(t, hash); sent.Sender != account || len(sent.InitCode) != 0 {
				t.Fatalf("the close: sender %s, initCode %d bytes", sent.Sender.Hex(), len(sent.InitCode))
			}
		})
	}
}

// The paymaster's own refusal of a second escape (EscapeEvidencePending, in
// a dry run) is reported as transit_escape_pending, not as escapes being
// disabled.
func TestGaslessEscapeEvidencePendingIsATransitRefusal(t *testing.T) {
	inner := common.FromHex(selectorOf("EscapeEvidencePending(uint32)") + uintWord(9))
	data := common.FromHex(selectorFailedOpWithRevert + uintWord(0) + addressABIWord("60") + addressABIWord("a0") + uintWord(13) + common.Bytes2Hex(common.RightPadBytes([]byte("AA33 reverted"), 32)) + uintWord(uint64(len(inner))) + common.Bytes2Hex(common.RightPadBytes(inner, 64)))
	failure, ok := decodeAAFailure(data)
	if !ok || failure.Inner != "EscapeEvidencePending" {
		t.Fatalf("decoded %+v %v", failure, ok)
	}
	if code := GaslessRefusalCode(refusalOfFailure(failure)); code != GaslessTransitEscapePending {
		t.Fatalf("refusal code %s", code)
	}
	for _, name := range []string{"EscapesDisabled()", "EscapeAlreadySponsored(uint32)"} {
		inner := common.FromHex(selectorOf(name) + uintWord(9))
		if strings.HasSuffix(name, "()") {
			inner = common.FromHex(selectorOf(name))
		}
		f := aaFailure{Code: "AA33", Inner: gaslessErrorName(inner)}
		if code := GaslessRefusalCode(refusalOfFailure(f)); code != "escapes_disabled" {
			t.Fatalf("%s: refusal code %s", name, code)
		}
	}
}
