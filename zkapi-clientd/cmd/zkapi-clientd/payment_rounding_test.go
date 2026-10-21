package main

import (
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
	"testing"
)

func TestPaymentSendLineBalanceThreshold(t *testing.T) {
	for _, test := range []struct{ balance, topup, want string }{
		{"0", "6228890429955413", "Send at least: 0.0063 ETH"},
		{"62999999999999", "6228890429955413", "Send at least: 0.0063 ETH"},
		{"63000000000000", "6228890429955413", "Send at least: 0.0063 ETH (account already has 0.000063 ETH)"},
		{"1500000000000000", "4800000000000000", "Send at least: 0.0048 ETH (account already has 0.0015 ETH)"},
		{"1599999999999999", "4700000000000001", "Send at least: 0.0048 ETH (account already has 0.0015 ETH)"},
	} {
		q := zkapi.AddressPaymentQuote{BalanceWei: test.balance, RequiredTotalWei: "6300000000000000", RecommendedTopUpWei: test.topup}
		if got := paymentSendLine(q); got != test.want {
			t.Errorf("balance %s: got %q want %q", test.balance, got, test.want)
		}
	}
}

func TestMinimumETH(t *testing.T) {
	for _, test := range []struct{ wei, want string }{
		{"6228890429955413", "0.0063"},
		{"6300000000000000", "0.0063"},
		{"9990000000000000", "0.010"},
		{"1", "0.0000000000000000010"},
		{"10", "0.000000000000000010"},
		{"1230000000000000000", "1.3"},
		{"999000000000000000000", "1000"},
		{"0", "0"},
	} {
		if got := minimumETH(test.wei); got != test.want {
			t.Errorf("%s: got %s want %s", test.wei, got, test.want)
		}
	}
}
