package main

import (
	"context"
	"errors"
	"math/big"
	"strconv"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/relay"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

type serveModelKey struct{}

// Automatic serve funding sizes an unsigned draft from the available balance,
// then approves only the resulting fixed deposit through the recovery-safe flow.
type automaticDepositUI struct{ setupPrompter }

func (p automaticDepositUI) Continue(ctx context.Context, question string) (bool, error) {
	if question != "Press Enter to continue with this deposit, or type cancel" {
		return false, errors.New("unexpected automatic deposit approval")
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	p.Printf("serve: authorizing the displayed fixed deposit and affordable quoted network fees.\n")
	return true, nil
}

// Return principal in gwei, excluding the additional deposit fee reserve.
func recommendedDeposit(modelUnits uint64, feeWei string) (uint64, error) {
	fee, ok := new(big.Int).SetString(feeWei, 10)
	if !ok || fee.Sign() < 0 || fee.BitLen() > 256 || modelUnits == 0 {
		return 0, errors.New("invalid deposit recommendation inputs")
	}
	gas := new(big.Int).Mul(fee, big.NewInt(10))
	gas.Add(gas, big.NewInt(999999999)).Quo(gas, big.NewInt(1000000000))
	model := new(big.Int).Mul(new(big.Int).SetUint64(modelUnits), big.NewInt(3))
	if model.Cmp(gas) > 0 {
		gas = model
	}
	if !gas.IsUint64() || gas.Sign() == 0 || gas.Uint64() > 1_000_000_000_000 {
		return 0, errors.New("recommended deposit exceeds supported limit; stopped without approval")
	}
	return gas.Uint64(), nil
}

func ensureServeFunding(ctx context.Context, c config.Config, _, _ string, ui setupPrompter) error {
	transport, err := relay.NewClient(c.RelayURL)
	if err != nil {
		return err
	}
	defer transport.CloseIdleConnections()
	wallet, err := zkapi.New(zkConfig(c, transport))
	if err != nil {
		return err
	}
	return serveFunding(ctx, localGuidedFunding{c, wallet}, wallet, ui)
}

type fundingBudgetSource interface {
	ModelRequestBudget(context.Context, string) (uint64, error)
	NativeUSDQuote(context.Context) (zkapi.NativeUSDQuote, error)
}

func serveFunding(ctx context.Context, service guidedFundingService, wallet fundingBudgetSource, ui setupPrompter) error {
	ready, err := waitSetupWallet(ctx, service, ui, waitFundingPoll)
	if err != nil {
		return err
	}
	if ready.WithdrawalPending {
		return errors.New("withdrawal is reserved; run zkapi-clientd withdraw to resume")
	}
	if ready.HasNote {
		return configuredWalletReady(ctx, service, ui)
	}
	state, err := service.Address(ctx)
	if err != nil {
		return err
	}
	if state.BillingAsset != "native_eth" {
		return errors.New("automatic funding requires native ETH")
	}
	ui.Printf("No open private note. Funding address on %s: %s\n", fundingNetwork(state.ChainID), state.Address)
	switch state.Phase {
	case "deposit_pending", "confirming":
		if err := finishGuidedDeposit(ctx, service, state, ui, waitFundingPoll); err != nil {
			return err
		}
		return configuredWalletReady(ctx, service, ui)
	case "ready", "waiting_funds":
		if state.TransactionHash != "" {
			return errors.New("saved deposit transaction requires recovery; no new deposit authorized")
		}
	default:
		return errors.New("saved funding requires recovery; refusing to replace it")
	}
	if err := showSetupEscapePayoutCredits(ctx, service, state, ui); err != nil {
		return err
	}
	var quote zkapi.AddressPaymentQuote
	if state.Amount != 0 {
		ui.Printf("Resuming unsigned deposit threshold: %s ETH; available funds above it will also be deposited.\n", fundingUnits(strconv.FormatUint(state.Amount, 10), 9))
		quote, err = service.Quote(ctx, state.Amount, 0)
	} else {
		model, _ := ctx.Value(serveModelKey{}).(string)
		// No application model exists yet. Use the largest supported reviewed tier.
		budget := uint64(6_000_000)
		if model != "" {
			budget, err = wallet.ModelRequestBudget(ctx, model)
			if err != nil {
				return err
			}
		} else {
			ui.Printf("No --model selected; using conservative $6 per-query cap.\n")
		}
		price, e := wallet.NativeUSDQuote(ctx)
		if e != nil {
			return e
		}
		units, e := price.GweiForUSD(budget)
		if e != nil {
			return e
		}
		// The first unsigned quote supplies the live gas estimate. No signing occurs.
		quote, err = service.Quote(ctx, units, 0)
		if err != nil {
			return err
		}
		amount, e := recommendedDeposit(units, quote.ExpectedFeeWei)
		if e != nil {
			return e
		}
		quote, err = service.Quote(ctx, amount, 0)
		if err == nil && quote.Amount != amount {
			return errors.New("quote changed recommended principal; stopped without approval")
		}
		if err == nil {
			ui.Printf("Recommended minimum: max(3 × $%s query cap converted at the current ETH price, 10 × estimated deposit gas). Minimum spending balance: %s ETH; network fees are extra.\n", setupUSD(budget), fundingUnits(quote.PrincipalWei, 18))
		}
	}
	if err != nil {
		return err
	}
	if quote.Amount == 0 || quote.Address != state.Address || quote.ChainID != state.ChainID || quote.DeploymentID != state.DeploymentID || (state.Amount != 0 && quote.Amount != state.Amount) {
		return errors.New("deposit quote changed wallet or saved amount")
	}
	ui.Printf("serve will deposit the available ETH minus the quoted network fee allowance once funded. Ctrl+C stops waiting and preserves recovery records.\n")
	if err := waitAndDeposit(ctx, service, quote, automaticDepositUI{ui}, waitFundingPoll); err != nil {
		return err
	}
	return configuredWalletReady(ctx, service, ui)
}
