package zkapi

import (
	"bytes"
	"context"
	"errors"
	"io/fs"
	"math/big"
	"net/http"
	"strings"
	"testing"
	"testing/fstest"
)

// Design C.8: a deposit's gas grows with the trailing ones of the note ID it
// lands at, plus a fresh slot at each level's first write, and another
// deposit can move it to a costlier ID. The policy limit covers the next 64
// IDs.
func TestDepositGasPolicyCoversTheNext64NoteIDs(t *testing.T) {
	for _, test := range []struct {
		name                 string
		estimate, next, slot uint64
		want                 uint64
	}{
		// t_now 0, t_max 6 (63), first writes 15, 31 and 63 in (12, 76).
		{"fresh vault, mainnet rules", 65_536, 12, 22_100, (65_536+16_500*6+7_500+17_100)*12/10 + 1},
		// The same window with EIP-8037's fresh slot raises the limit.
		{"fresh vault, Sepolia", 65_536, 12, 110_000, (65_536+16_500*6+7_500+105_000)*12/10 + 1},
		// The first deposit: levels 1 to 6 are first written at 1, 3, 7, 15,
		// 31 and 63.
		{"first deposit", 100_000, 0, 22_100, (100_000 + 16_500*6 + 7_500 + 17_100) * 12 / 10},
		// The reviewer's Sepolia case: t_now 0, t_max 6, no first write
		// in (1152, 1216): ceil(1.2 · (157,500 + 106,500)) = 316,800.
		{"Sepolia window without a first write", 157_500, 1152, 110_000, 316_800},
		// t_now 6 at 63: nothing in [63, 127) has more, and 127 is outside.
		{"at the window's most", 172_200, 63, 22_100, 206_640},
		// A first write in the window (1023 in (1000, 1064)), t_max 10.
		{"first write of level 10", 70_000, 1000, 22_100, (70_000 + 16_500*10 + 7_500 + 17_100) * 12 / 10},
		{"capped", 1_400_000, 12, 110_000, depositGasCap},
		{"estimate above the cap", 2_000_000, 12, 22_100, depositGasCap},
	} {
		if got := depositGasPolicyLimit(test.estimate, test.next, test.slot); got != test.want {
			t.Errorf("%s: limit %d, want %d", test.name, got, test.want)
		}
	}
	for n, want := range map[uint32]int{0: 0, 1: 1, 2: 0, 3: 2, 7: 3, 12: 0, 63: 6, 1023: 10, 0xfffffffe: 0, 0xffffffff: 32} {
		if got := trailingOnes(n); got != want {
			t.Errorf("trailingOnes(%d) = %d, want %d", n, got, want)
		}
	}
}

// withProfileEdit runs the package tests' deployed profiles with one
// replacement in network's profile.
func withProfileEdit(t *testing.T, network, before, after string) {
	t.Helper()
	raw, err := fs.ReadFile(packagedDeployments, "deployments/"+network+".json")
	if err != nil {
		t.Fatal(err)
	}
	changed := bytes.Replace(raw, []byte(before), []byte(after), 1)
	if bytes.Equal(changed, raw) {
		t.Fatalf("the %s profile has no %s", network, before)
	}
	files := fstest.MapFS{}
	for _, name := range []string{"mainnet", "sepolia"} {
		content, err := fs.ReadFile(packagedDeployments, "deployments/"+name+".json")
		if err != nil {
			t.Fatal(err)
		}
		if name == network {
			content = changed
		}
		files["deployments/"+name+".json"] = &fstest.MapFile{Data: content}
	}
	restore := SetPackagedDeploymentsForTesting(files)
	t.Cleanup(restore)
}

// The signed deposit carries the larger of the padded estimate and the
// policy limit at the vault's next note ID (12, a fresh vault, read at the
// latest block), with the profile's fresh_slot_gas.
func TestTheSignedDepositCarriesThePolicyGasLimit(t *testing.T) {
	estimate := uint64(0x10000) // The fixture's eth_estimateGas.
	padded, err := paddedAddressGas(new(big.Int).SetUint64(estimate))
	if err != nil {
		t.Fatal(err)
	}
	for _, slot := range []uint64{22_100, 110_000} {
		t.Run(map[uint64]string{22_100: "mainnet rules", 110_000: "fresh slot of 110,000"}[slot], func(t *testing.T) {
			if slot != 22_100 {
				withProfileEdit(t, "mainnet", `"fresh_slot_gas": 22100`, `"fresh_slot_gas": 110000`)
			}
			f := newAddressFixture(t, true)
			status, err := f.fundNative(t, 100000)
			if err != nil || status.Phase != "deposit_pending" {
				t.Fatalf("deposit not signed: %+v %v", status, err)
			}
			want := depositGasPolicyLimit(estimate, 12, slot)
			if want <= padded {
				t.Fatalf("the fixture's estimate is not below the policy limit: %d, %d", want, padded)
			}
			if tx := f.accepted[status.TransactionHash]; tx == nil || tx.Gas() != want {
				t.Fatalf("deposit gas limit %v, want %d", tx, want)
			}
			if f.nextNoteReads == 0 {
				t.Fatal("the policy did not read the vault's next note ID")
			}
		})
	}
	// Without the vault's next note ID no deposit is quoted or signed.
	f := newAddressFixture(t, true)
	upstream := f.h.client.inference.Transport
	f.h.client.inference.Transport = withdrawalRoundTripper(func(r *http.Request) (*http.Response, error) {
		raw, _ := ioReadAndRestore(r)
		if strings.Contains(string(raw), nextNoteIDSelector) {
			return withdrawalJSONResponse(r, 502, map[string]any{"error": "unavailable"}), nil
		}
		return upstream.RoundTrip(r)
	})
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); err == nil || !strings.Contains(err.Error(), "next note ID") || len(f.accepted) != 0 {
		t.Fatalf("a deposit was quoted without the policy's next note ID: %v", err)
	}
}

// A deposit below the vault's minDeposit() (the profile's min_deposit_units,
// which the deployment checks pin) is refused before anything is prepared.
func TestDepositsBelowTheMinimumAreRefused(t *testing.T) {
	withProfileEdit(t, "mainnet", `"min_deposit_units": 1,`, `"min_deposit_units": 100001,`)
	f := newAddressFixture(t, true)
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 100000); !errors.Is(err, errDepositTooSmall) {
		t.Fatalf("a deposit below the minimum was quoted: %v", err)
	}
	if _, err := f.h.prepare(context.Background(), 100000); !errors.Is(err, errDepositTooSmall) {
		t.Fatalf("a deposit below the minimum was prepared: %v", err)
	}
	if f.prepared != 0 || len(f.accepted) != 0 {
		t.Fatal("a refused deposit reached the companion or was signed")
	}
	if _, err := f.h.QuoteAddressDeposit(context.Background(), 100001); err != nil {
		t.Fatalf("a deposit of the minimum was refused: %v", err)
	}
}
