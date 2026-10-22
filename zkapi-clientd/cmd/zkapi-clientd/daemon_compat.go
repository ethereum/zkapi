package main

import (
	"errors"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

// serve keeps running across an upgrade, so this CLI can attach to a daemon
// an older build started. That daemon names no new-withdrawal fee mode: it
// applies no payout-only policy and keeps no bounded authorization, so a
// quote through it could fall back to a wallet-paid fee and an approval
// could ask again on every fee change. A new withdrawal is refused with a
// restart instruction; a withdrawal it already signed is still followed,
// since following only observes the saved transaction or operation.
var errDaemonPredatesPayoutOnly = errors.New("the running zkapi-clientd daemon was started by an older build, which can pay withdrawal fees from the wallet and asks again when fees change; stop it (Ctrl+C in its terminal, or stop its service), start zkapi-clientd serve again with this build and the same --config-dir, then retry. Nothing was reserved, signed or sent")

func daemonPredatesPayoutOnly(state zkapi.AddressWithdrawalStatus) bool {
	return state.NewWithdrawalFees == ""
}

// followsSignedWithdrawal reports a saved withdrawal whose transaction or
// sponsored operation is already signed (or settled): an older daemon can
// still follow it to completion.
func followsSignedWithdrawal(state zkapi.AddressWithdrawalStatus) bool {
	switch state.Phase {
	case "withdrawal_pending", "confirming", "complete", "no_note":
		return true
	}
	return zkapi.GaslessPendingPhase(state.Phase)
}

// checkWithdrawalDaemon refuses anything but following a signed withdrawal
// through a daemon that predates payout-only withdrawals.
func checkWithdrawalDaemon(state zkapi.AddressWithdrawalStatus) error {
	if daemonPredatesPayoutOnly(state) && !followsSignedWithdrawal(state) {
		return errDaemonPredatesPayoutOnly
	}
	return nil
}
