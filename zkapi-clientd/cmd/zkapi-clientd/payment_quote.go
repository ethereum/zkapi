package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/config"
	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
)

func activeFundingConfig(ctx context.Context, c config.Config) (config.Config, error) {
	active, err := resolveActiveConfig(ctx, c)
	if err != nil {
		if ctx.Err() != nil {
			return c, errFundingWaitStopped
		}
		return c, err
	}
	if active.Backend != "zkapi" {
		return c, errors.New("wallet commands require the running daemon to use zkapi; start zkapi-clientd serve")
	}
	return active, nil
}

func validQuoteID(id string) bool {
	if len(id) != 64 {
		return false
	}
	_, err := hex.DecodeString(id)
	return err == nil
}

func fundingNetwork(chain uint64) string {
	if chain == 11155111 {
		return "Ethereum Sepolia (test network)"
	}
	return "Ethereum Mainnet"
}

// managementError is the daemon's message for a failed management request,
// with the machine-readable code it forwards for refusals a guided flow acts
// on (for example unsettled_request_state or quote_changed). scope prefixes
// the message ("wallet" unless set).
type managementError struct{ message, code, scope string }

func (e *managementError) Error() string {
	if e.scope != "" {
		return e.scope + ": " + e.message
	}
	return "wallet: " + e.message
}

func managementErrorCode(err error) string {
	var failed *managementError
	if errors.As(err, &failed) {
		return failed.code
	}
	return ""
}

func requestManagementJSON(ctx context.Context, c config.Config, method, path string, body, result any) error {
	var payload []byte
	var err error
	if body != nil {
		payload, err = json.Marshal(body)
		if err != nil {
			return errors.New("invalid management request")
		}
	}
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 10 * time.Minute, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, err := http.NewRequestWithContext(ctx, method, "http://"+c.Listen+path, bytes.NewReader(payload))
	if err != nil {
		return errors.New("invalid local management endpoint")
	}
	req.Header.Set("Authorization", "Bearer "+c.APIKey)
	req.Header.Set("X-OA-Management-Token", c.ManagementToken)
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		if ctx.Err() != nil {
			return errFundingWaitStopped
		}
		return errors.New("local wallet request did not complete; check saved status before retrying")
	}
	defer response.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(response.Body, (32<<10)+1))
	if err != nil && ctx.Err() != nil {
		return errFundingWaitStopped
	}
	if err != nil || len(raw) > 32<<10 {
		return errors.New("invalid local wallet response")
	}
	if response.StatusCode != http.StatusOK {
		var failed struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		if json.Unmarshal(raw, &failed) == nil && failed.Error != "" {
			return &managementError{message: failed.Error, code: failed.Code}
		}
		return errors.New("local wallet request failed; check saved status before retrying")
	}
	if json.Unmarshal(raw, result) != nil {
		return errors.New("invalid local wallet response")
	}
	return nil
}

func requestPaymentQuote(ctx context.Context, c config.Config, method, path, kind string, body any) (zkapi.AddressPaymentQuote, error) {
	var q zkapi.AddressPaymentQuote
	if err := requestManagementJSON(ctx, c, method, path, body, &q); err != nil {
		return q, err
	}
	chain, err := zkapi.ChainID(c.ZKAPI.Network)
	// A kind of "" accepts the withdrawal route's kinds: the withdrawal and
	// the gasless path's wallet-paid transit transactions.
	kindAccepted := q.Kind == kind || (kind == "" && (q.Kind == "withdrawal" || zkapi.TransitKind(q.Kind)))
	if err != nil || q.ChainID != chain || !kindAccepted || !validQuoteID(q.ID) || !fundingAddress(q.Address) || !fundingAddress(q.Contract) || (q.FeePolicy != "low" && q.FeePolicy != "payout") || q.EstimatedGas == 0 || q.GasLimit < q.EstimatedGas || q.ExpiresAt <= time.Now().UnixMilli() {
		return q, errors.New("invalid payment quote or network")
	}
	if q.FeePolicy == "payout" {
		// A payout quote: its figures are the operation's, not a top-up.
		if q.UserOpGas == nil || q.UserOpKind == "" || !fundingAddress(q.TransitAccount) || q.ShortfallWei != "0" {
			return q, errors.New("invalid payout quote")
		}
		quantities := []string{q.FeeCapWei, q.FlatFeeWei, q.PayoutWei, q.OwedWei, q.FinalizeReserveWei}
		if q.UserOpKind != "escape" {
			// An escape initiation promises no floor (its finalization is
			// quoted later); every other operation does.
			quantities = append(quantities, q.MinimumReceivedWei)
		}
		for _, quantity := range quantities {
			if !fundingBalance(quantity) {
				return q, errors.New("invalid payout quote quantity")
			}
		}
		for _, quantity := range []string{q.FinalizeEstimateWei, q.EstimatedReceivedWei, q.FeeBumpCapWei, q.MaxTotalFeeWei, q.MinNetPayoutWei} {
			if quantity != "" && !fundingBalance(quantity) {
				return q, errors.New("invalid payout quote quantity")
			}
		}
		if !validPayoutAuthorization(q) {
			return q, errors.New("invalid payout quote authorization")
		}
	}
	if !zkapi.MatchesDeployment(c.ZKAPI.Network, q.DeploymentID, q.Contract) {
		return q, errors.New("payment quote does not match the pinned deployment")
	}
	for _, quantity := range []string{q.PrincipalWei, q.BalanceWei, q.ExpectedFeeWei, q.RequiredFeeWei, q.FeeReserveWei, q.FeeBufferWei, q.RequiredTotalWei, q.RecommendedTotalWei, q.ShortfallWei, q.RecommendedTopUpWei, q.MaxFeePerGas, q.MaxPriorityFeePerGas} {
		if !fundingBalance(quantity) {
			return q, errors.New("invalid payment quote quantity")
		}
	}
	if kind == "deposit" && q.Amount == 0 {
		return q, errors.New("invalid deposit principal")
	}
	if kind != "deposit" {
		if _, err := zkapi.NormalizeWithdrawalDestination(q.Destination); err != nil {
			return q, errors.New("invalid quoted destination")
		}
	}
	if kind == "deposit" && q.PrincipalWei != new(big.Int).Mul(new(big.Int).SetUint64(q.Amount), big.NewInt(1_000_000_000)).String() {
		return q, errors.New("deposit quote principal does not match native units")
	}
	return q, nil
}

func printPaymentQuote(out io.Writer, q zkapi.AddressPaymentQuote, command string) {
	if _, guided := out.(setupUIWriter); guided {
		command = ""
	}
	fmt.Fprintf(out, "\n%s %s quote\n", fundingNetwork(q.ChainID), q.Kind)
	if q.InputMicroUSD != 0 {
		fmt.Fprintf(out, "Selected USD value: $%s (converted once to the fixed ETH principal below)\n", fundingUnits(fmt.Sprint(q.InputMicroUSD), 6))
	}
	principal := q.PrincipalWei
	if q.Kind == "withdrawal" || strings.HasPrefix(q.Kind, "escape") {
		principal = new(big.Int).Mul(new(big.Int).SetUint64(q.Amount), big.NewInt(1_000_000_000)).String()
	}
	fmt.Fprintf(out, "Fixed amount: %s ETH\n", fundingUnits(principal, 18))
	if q.Destination != "" {
		fmt.Fprintln(out, "Destination:", q.Destination)
	}
	if q.FeePolicy == "payout" {
		printPayoutQuote(out, q)
		if command == "" {
			fmt.Fprintf(out, "Quote expires: %s\nQuoting does not sign or send.\n", time.UnixMilli(q.ExpiresAt).Format(time.RFC3339))
			return
		}
		if authorizedPayoutQuote(q) {
			fmt.Fprintf(out, "Quote expires: %s (afterwards rerun --to for a new quote)\nTo approve this withdrawal once, within this maximum: %s --approve %s\nKeep the same --config-dir if used. Quoting does not sign or send.\n", time.UnixMilli(q.ExpiresAt).Format(time.RFC3339), command, q.ID)
			return
		}
		fmt.Fprintf(out, "Quote expires: %s\nTo authorize this exact operation: %s --approve %s\nKeep the same --config-dir if used. Quoting does not sign or send.\n", time.UnixMilli(q.ExpiresAt).Format(time.RFC3339), command, q.ID)
		return
	}
	fmt.Fprintf(out, "Local signing address: %s\nAvailable public balance: %s ETH\n", q.Address, fundingUnits(q.BalanceWei, 18))
	fmt.Fprintf(out, "Estimated network fee: %s ETH\nRequired fee allowance: %s ETH\nMaximum approved fee allowance: %s ETH (Low)\n", fundingUnits(q.ExpectedFeeWei, 18), fundingUnits(q.RequiredFeeWei, 18), fundingUnits(q.FeeReserveWei, 18))
	if strings.TrimLeft(q.ShortfallWei, "0") != "" {
		fmt.Fprintf(out, "%s\nSend on %s to %s\nPayment URI: ethereum:%s@%d?value=%s\n", paymentSendLine(q), fundingNetwork(q.ChainID), q.Address, q.Address, q.ChainID, q.RecommendedTopUpWei)
		fmt.Fprintln(out, "After funds arrive, request a fresh quote.")
	} else {
		fmt.Fprintln(out, "The existing balance covers the required amount; no top-up is needed.")
	}
	if command == "" {
		fmt.Fprintf(out, "Quote expires: %s\nQuoting does not sign or broadcast.\n", time.UnixMilli(q.ExpiresAt).Format(time.RFC3339))
		return
	}
	fmt.Fprintf(out, "Quote expires: %s\nTo authorize this exact quote: %s --approve %s\nKeep the same --config-dir if used. Quoting does not sign or broadcast.\n", time.UnixMilli(q.ExpiresAt).Format(time.RFC3339), command, q.ID)
}

// printPayoutQuote prints the figures of a payout quote (design 3.3): the
// fee is taken from the payout by a sponsored operation, so no ETH is needed
// and only "at least this much reaches the payout address" is promised. A
// quote with a bounded authorization (authorize once) prints its terms; a
// legacy quote binds only the operation as built now.
func printPayoutQuote(out io.Writer, q zkapi.AddressPaymentQuote) {
	fmt.Fprintf(out, "Fee paid from the payout by a sponsored %s operation; no ETH is needed from the local signing address.\nTransit account: %s\nBundler: %s\n", q.UserOpKind, q.TransitAccount, q.BundlerURL)
	if authorizedPayoutQuote(q) {
		fmt.Fprintf(out, "Payout: %s ETH\n", fundingUnits(q.PayoutWei, 18))
		printPayoutTerms(out, q)
		if q.UserOpGas != nil {
			fmt.Fprintf(out, "The operation as built now (rebuilt within the maximum when fees change): gas limits call %d, verification %d, pre-verification %d, paymaster verification %d, postOp %d; max fee %s wei/gas, priority %s wei/gas\n", q.UserOpGas.CallGasLimit, q.UserOpGas.VerificationGasLimit, q.UserOpGas.PreVerificationGas, q.UserOpGas.PaymasterVerificationGasLimit, q.UserOpGas.PaymasterPostOpGasLimit, q.MaxFeePerGas, q.MaxPriorityFeePerGas)
		}
		return
	}
	fmt.Fprintf(out, "Payout: %s ETH\nMaximum fee taken from it: %s ETH (expected charge at today's base fee: about %s ETH, an estimate; paymaster flat fee %s ETH)\n", fundingUnits(q.PayoutWei, 18), fundingUnits(q.FeeCapWei, 18), fundingUnits(q.ExpectedFeeWei, 18), fundingUnits(q.FlatFeeWei, 18))
	if strings.TrimLeft(q.OwedWei, "0") != "" {
		fmt.Fprintf(out, "Owed from an earlier sponsored escape, deducted first: %s ETH\n", fundingUnits(q.OwedWei, 18))
	}
	if q.UserOpKind == "escape" {
		fmt.Fprintf(out, "This initiation's charge becomes the transit account's debt, settled from the payout at finalization. The finalization is a later sponsored operation, quoted after the challenge period at its own fees: the paymaster requires a reserve of %s ETH for it now.\n", fundingUnits(q.FinalizeReserveWei, 18))
		if q.FinalizeEstimateWei != "" && q.EstimatedReceivedWei != "" {
			fmt.Fprintf(out, "At today's fees the finalization would take about %s ETH, and the payout address would then receive about %s ETH: estimates, not a floor (the fee at finalization, and any raise by the operator, decide).\n", fundingUnits(q.FinalizeEstimateWei, 18), fundingUnits(q.EstimatedReceivedWei, 18))
		}
	} else {
		fmt.Fprintf(out, "The payout address receives at least: %s ETH\n", fundingUnits(q.MinimumReceivedWei, 18))
	}
	printPayeeHasCode(out, q)
	if q.FeeBumpCapWei != "" && q.FeeBumpCapWei != q.FeeCapWei {
		fmt.Fprintf(out, "If the bundler drops the operation it is re-signed with higher fees, taking at most %s ETH from the payout (your --fee-cap-gwei); the approval binds that bound.\n", fundingUnits(q.FeeBumpCapWei, 18))
	} else {
		fmt.Fprintln(out, "The approval binds this maximum: a dropped operation is not re-signed above it (quote with --fee-cap-gwei to allow higher fees).")
	}
	if q.UserOpGas != nil {
		fmt.Fprintf(out, "Signed gas limits: call %d, verification %d, pre-verification %d, paymaster verification %d, postOp %d; max fee %s wei/gas, priority %s wei/gas\n", q.UserOpGas.CallGasLimit, q.UserOpGas.VerificationGasLimit, q.UserOpGas.PreVerificationGas, q.UserOpGas.PaymasterVerificationGasLimit, q.UserOpGas.PaymasterPostOpGasLimit, q.MaxFeePerGas, q.MaxPriorityFeePerGas)
	}
}

// printPayoutTerms prints what one approval of a payout withdrawal
// authorizes (the CLI quote and the guided withdrawal print the same): the
// fee is an estimate that may change, the bound on what the payout may lose
// and the floor the destination receives hold whatever it becomes, and the
// approval covers only this destination, note and transit account.
func printPayoutTerms(out io.Writer, q zkapi.AddressPaymentQuote) {
	maxFee, minNet := payoutBound(q)
	fmt.Fprintf(out, "Estimated network fee: about %s ETH (an estimate; the actual fee may change)\n", fundingUnits(q.ExpectedFeeWei, 18))
	fmt.Fprintf(out, "At most %s ETH may be taken from the payout (the network fee and the paymaster's fee together)\n", fundingUnits(maxFee, 18))
	if strings.TrimLeft(q.OwedWei, "0") != "" {
		fmt.Fprintf(out, "Owed from an earlier sponsored escape, deducted first: %s ETH\n", fundingUnits(q.OwedWei, 18))
	}
	fmt.Fprintf(out, "%s receives at least %s ETH\n", q.Destination, fundingUnits(minNet, 18))
	printPayeeHasCode(out, q)
	if authorizedPayoutQuote(q) {
		fmt.Fprintln(out, "This one approval covers this destination, note and transit account; fee changes within this maximum are handled without asking again; a new destination or note needs a new approval.")
	}
}

func printPayeeHasCode(out io.Writer, q zkapi.AddressPaymentQuote) {
	if q.PayeeHasCode {
		fmt.Fprintf(out, "The payout address has code: it must accept the ETH within 100,000 gas, or the payout is credited in the paymaster (less a surcharge of up to %s ETH, which the floor above already deducts) for zkapi-clientd withdraw --claim-credit --to %s.\n", fundingUnits(zeroIfEmpty(q.CreditSurchargeWei), 18), q.Destination)
	}
}

// authorizedPayoutQuote reports a payout quote approved once under a
// bounded authorization: the daemon rebuilds, re-signs and re-proves within
// MaxTotalFeeWei without another approval.
func authorizedPayoutQuote(q zkapi.AddressPaymentQuote) bool {
	return q.FeePolicy == "payout" && q.MaxTotalFeeWei != "" && q.MinNetPayoutWei != ""
}

// validPayoutAuthorization checks a payout quote's bounded authorization:
// both figures or neither, a bound no lower than the operation as built now,
// and a floor that is exactly the payout less the bound and the debt.
func validPayoutAuthorization(q zkapi.AddressPaymentQuote) bool {
	if q.MaxTotalFeeWei == "" && q.MinNetPayoutWei == "" {
		return true
	}
	if q.MaxTotalFeeWei == "" || q.MinNetPayoutWei == "" {
		return false
	}
	bound, ok := new(big.Int).SetString(q.MaxTotalFeeWei, 10)
	floor, floorOK := new(big.Int).SetString(q.MinNetPayoutWei, 10)
	payout, payoutOK := new(big.Int).SetString(q.PayoutWei, 10)
	owed, owedOK := new(big.Int).SetString(q.OwedWei, 10)
	if !ok || !floorOK || !payoutOK || !owedOK {
		return false
	}
	if q.FeeCapWei != "" {
		cap, capOK := new(big.Int).SetString(q.FeeCapWei, 10)
		if !capOK || bound.Cmp(cap) < 0 {
			return false
		}
	}
	expected := new(big.Int).Sub(payout, bound)
	expected.Sub(expected, owed)
	return expected.Sign() >= 0 && expected.Cmp(floor) == 0
}

// payoutBound is what a payout approval binds: the most the payout may lose
// and the least the payout address receives. A legacy quote without the
// bounded authorization binds its operation as built now.
func payoutBound(q zkapi.AddressPaymentQuote) (maxFee, minNet string) {
	if authorizedPayoutQuote(q) {
		return q.MaxTotalFeeWei, q.MinNetPayoutWei
	}
	return q.FeeCapWei, q.MinimumReceivedWei
}

// payoutWithinBound reports a payout quote whose bound is no looser than
// the accepted one's: no higher maximum fee and no lower floor, so the
// owner's approval of the accepted terms covers it.
func payoutWithinBound(q, accepted zkapi.AddressPaymentQuote) bool {
	maxFee, minNet := payoutBound(q)
	acceptedFee, acceptedNet := payoutBound(accepted)
	fee, feeOK := new(big.Int).SetString(maxFee, 10)
	net, netOK := new(big.Int).SetString(minNet, 10)
	limit, limitOK := new(big.Int).SetString(acceptedFee, 10)
	floor, floorOK := new(big.Int).SetString(acceptedNet, 10)
	return feeOK && netOK && limitOK && floorOK && fee.Cmp(limit) <= 0 && net.Cmp(floor) >= 0
}
