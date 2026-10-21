package main

import (
	"strings"
	"testing"
)

func TestDepositPaymentCardIsCompact(t *testing.T) {
	q := wizardBalance(wizardQuote(), "0")
	ui := &recordingSetupDisplay{}
	if err := showSetupDeposit(ui, q); err != nil {
		t.Fatal(err)
	}
	if len(ui.payments) != 1 {
		t.Fatal("missing payment card")
	}
	for _, label := range []string{"Funding address:", "Receiving account balance:", "Private deposit:", "Estimated network fee:", "Maximum network fee:"} {
		if strings.Contains(ui.payments[0], label) {
			t.Fatal("redundant breakdown:", label)
		}
	}
	for _, label := range []string{"Network: Ethereum Mainnet", "Send at least:", "To:", "Payment URI:"} {
		if !strings.Contains(ui.payments[0], label) {
			t.Fatal("missing", label)
		}
	}
	changed := q
	changed.BalanceWei = "1"
	changed.RecommendedTopUpWei = "750001000029999"
	if depositPaymentDisplayKey(q) != depositPaymentDisplayKey(changed) {
		t.Fatal("small balance movement refreshes display")
	}
	changed.ShortfallWei = "0"
	if depositPaymentDisplayKey(changed) != "" {
		t.Fatal("funded card not cleared")
	}
	funded := wizardBalance(q, q.RecommendedTotalWei)
	if err := showSetupDepositPayment(ui, funded, true); err != nil {
		t.Fatal(err)
	}
	if len(ui.payments) != 2 || ui.payments[1] != "" {
		t.Fatal("stale funded payment card")
	}
}
