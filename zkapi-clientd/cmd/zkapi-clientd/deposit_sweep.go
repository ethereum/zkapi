package main

import (
	"context"
	"errors"
	"math/big"
	"strings"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

// Whole gwei are the note's smallest unit. Leave the maximum quoted fee
// allowance public, not just the optimistic estimated fee.
func sweepDepositAmount(q zkapi.AddressPaymentQuote) (uint64, error) {
	balance, ok := new(big.Int).SetString(q.BalanceWei, 10)
	reserve, valid := new(big.Int).SetString(q.FeeReserveWei, 10)
	if !ok || !valid || balance.Sign() < 0 || reserve.Sign() < 0 || balance.BitLen() > 256 || reserve.BitLen() > 256 {
		return 0, errors.New("invalid sweep quote quantities")
	}
	available := new(big.Int).Sub(balance, reserve)
	if available.Sign() <= 0 {
		return 0, nil
	}
	available.Quo(available, big.NewInt(1_000_000_000))
	if !available.IsUint64() || available.Uint64() > 1_000_000_000_000 {
		return 0, errors.New("available deposit exceeds 1000 ETH limit; use an explicit deposit amount")
	}
	return available.Uint64(), nil
}

// Resize only definitely unsigned drafts. The owner endpoint independently
// rejects pending/signed transactions and mismatched wallet state. Every new
// principal is re-simulated because it changes the commitment/calldata and gas.
func maximizeUnsignedDeposit(ctx context.Context, service guidedFundingService, q zkapi.AddressPaymentQuote) (zkapi.AddressPaymentQuote, error) {
	if !sameSetupDeposit(q, q) {
		return q, errors.New("cannot resize a recovery transaction")
	}
	minimum := q.Amount
	target, err := sweepDepositAmount(q)
	if err != nil {
		return q, err
	}
	// Do not reduce the initial minimum. The ordinary flow may already afford
	// the required fee even if the optional maximum allowance is not covered.
	if target <= minimum {
		return q, nil
	}
	original := q
	for attempt := 0; attempt < 4; attempt++ {
		if err := ctx.Err(); err != nil {
			return q, err
		}
		state, err := service.Address(ctx)
		if err != nil {
			return q, err
		}
		if !sameSetupFunding(state, q) || state.TransactionHash != "" || (state.Phase != "ready" && state.Phase != "waiting_funds") {
			return q, errors.New("saved deposit advanced or changed; restart serve to recover it without resizing")
		}
		next, err := service.Quote(ctx, target, 0)
		if err != nil {
			return q, err
		}
		if !sameSetupDeposit(next, next) || next.Amount != target || next.ChainID != original.ChainID || next.DeploymentID != original.DeploymentID || !strings.EqualFold(next.Address, original.Address) || !strings.EqualFold(next.Contract, original.Contract) || next.Nonce != original.Nonce {
			return q, errors.New("resized quote changed the wallet or transaction nonce; stopped without approval")
		}
		if _, err := paymentRequestURI(next); err != nil {
			return q, err
		}
		affordable, err := sweepDepositAmount(next)
		if err != nil {
			return q, err
		}
		if affordable >= target {
			return next, nil
		}
		if affordable < minimum {
			return q, errors.New("balance or fees changed while sizing the deposit; restart serve to review the saved unsigned amount")
		}
		// Only shrink on retries; do not chase falling gas prices indefinitely.
		q = next
		target = affordable
	}
	return q, errors.New("network fees changed repeatedly while sizing deposit; no approval sent; restart serve to recover the unsigned draft")
}
