package main

import (
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"

	"github.com/ethereum/zkapi/zkapi-clientd/internal/zkapi"
	qrcode "github.com/skip2/go-qrcode"
)

const paymentQRColors = "\x1b[38;2;0;0;0;48;2;255;255;255m"
const paymentQRReset = "\x1b[0m"

// paymentRequestURI uses only the public top-up from an authenticated payment
// quote. ERC-681 value is integer wei, including the quoted fee buffer after
// subtracting ETH already at the funding address, never the vault principal.
func paymentRequestURI(q zkapi.AddressPaymentQuote) (string, error) {
	invalid := errors.New("invalid ETH payment request")
	network := ""
	switch q.ChainID {
	case 1:
		network = "mainnet"
	case 11155111:
		network = "sepolia"
	default:
		return "", invalid
	}
	if !fundingAddress(q.Address) || strings.EqualFold(q.Address, q.Contract) || !zkapi.MatchesDeployment(network, q.DeploymentID, q.Contract) {
		return "", invalid
	}
	expectedPrincipal := new(big.Int)
	switch q.Kind {
	case "deposit":
		if q.Amount == 0 || q.Destination != "" {
			return "", invalid
		}
		expectedPrincipal.Mul(new(big.Int).SetUint64(q.Amount), big.NewInt(1_000_000_000))
	case "withdrawal":
		if _, err := zkapi.NormalizeWithdrawalDestination(q.Destination); err != nil || q.NoteID > 0xffffffff || q.Binding == "" {
			return "", invalid
		}
		// The payout comes from the private note. This payment is gas only,
		// sent to the local signing address, never to the payout destination.
	default:
		return "", invalid
	}
	values := make([]*big.Int, 9)
	for i, quantity := range []string{q.PrincipalWei, q.BalanceWei, q.RequiredFeeWei, q.FeeReserveWei, q.FeeBufferWei, q.RequiredTotalWei, q.RecommendedTotalWei, q.ShortfallWei, q.RecommendedTopUpWei} {
		if !fundingBalance(quantity) {
			return "", invalid
		}
		values[i], _ = new(big.Int).SetString(quantity, 10)
		if values[i].BitLen() > 256 {
			return "", invalid
		}
	}
	principal, balance, fee, reserve, buffer := values[0], values[1], values[2], values[3], values[4]
	total, recommended, shortfall, topUp := values[5], values[6], values[7], values[8]
	if principal.Cmp(expectedPrincipal) != 0 ||
		total.Cmp(new(big.Int).Add(principal, fee)) != 0 ||
		recommended.Cmp(new(big.Int).Add(principal, reserve)) != 0 ||
		buffer.Cmp(new(big.Int).Sub(reserve, fee)) != 0 {
		return "", invalid
	}
	for _, pair := range [][2]*big.Int{{total, shortfall}, {recommended, topUp}} {
		want := new(big.Int).Sub(pair[0], balance)
		if want.Sign() < 0 {
			want.SetInt64(0)
		}
		if want.Cmp(pair[1]) != 0 {
			return "", invalid
		}
	}
	// A funded transaction can proceed without the optional fee buffer. Do not
	// invite another payment solely to replenish that buffer.
	if shortfall.Sign() == 0 || topUp.Sign() == 0 {
		return "", nil
	}
	return fmt.Sprintf("ethereum:%s@%d?value=%s", q.Address, q.ChainID, topUp), nil
}

// minimumETH rounds upwards, never below the quoted amount. Integer wei
// arithmetic avoids floating-point errors in funding instructions.
func minimumETH(wei string) string { return significantETH(wei, true) }

func significantETH(wei string, roundUp bool) string {
	amount, ok := new(big.Int).SetString(wei, 10)
	if !ok || amount.Sign() < 0 {
		return "invalid amount"
	}
	if amount.Sign() == 0 {
		return "0"
	}
	digits := len(amount.String())
	if digits > 2 {
		step := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(digits-2)), nil)
		if roundUp {
			amount.Add(amount, new(big.Int).Sub(step, big.NewInt(1)))
		}
		amount.Quo(amount, step).Mul(amount, step)
	}
	text := fundingUnits(amount.String(), 18)
	decimals := max(0, 20-len(amount.String()))
	whole, fraction, _ := strings.Cut(text, ".")
	if decimals == 0 {
		return whole
	}
	fraction += strings.Repeat("0", decimals)
	return whole + "." + fraction[:decimals]
}

func paymentSendLine(q zkapi.AddressPaymentQuote) string {
	line := "Send at least: " + minimumETH(q.RecommendedTopUpWei) + " ETH"
	balance, balanceOK := new(big.Int).SetString(q.BalanceWei, 10)
	required, requiredOK := new(big.Int).SetString(q.RequiredTotalWei, 10)
	if balanceOK && requiredOK && balance.Sign() > 0 && required.Sign() > 0 && new(big.Int).Mul(balance, big.NewInt(100)).Cmp(required) >= 0 {
		// Round the balance down so the display never overstates available ETH.
		line += " (account already has " + significantETH(q.BalanceWei, false) + " ETH)"
	}
	return line
}

func printSetupPaymentQR(out io.Writer, q zkapi.AddressPaymentQuote) error {
	uri, err := paymentRequestURI(q)
	if err != nil || uri == "" {
		return err
	}
	code, err := qrcode.New(uri, qrcode.Medium)
	if err != nil {
		return errors.New("could not encode the ETH payment request")
	}
	// Bitmap includes the standard four-module quiet zone. Half blocks preserve
	// square modules in a normal terminal while keeping the symbol under 80 columns.
	qr := terminalPaymentQR(code.Bitmap())
	_, err = fmt.Fprintf(out, "\nScan with an Ethereum wallet:\n%sNetwork: %s\n%s\nTo: %s\nPayment URI: %s\n", qr, fundingNetwork(q.ChainID), paymentSendLine(q), q.Address, uri)
	return err
}

func terminalPaymentQR(bitmap [][]bool) string {
	var out strings.Builder
	for y := 0; y < len(bitmap); y += 2 {
		out.WriteString(paymentQRColors)
		for x, top := range bitmap[y] {
			bottom := y+1 < len(bitmap) && bitmap[y+1][x]
			switch {
			case top && bottom:
				out.WriteRune('█')
			case top:
				out.WriteRune('▀')
			case bottom:
				out.WriteRune('▄')
			default:
				out.WriteByte(' ')
			}
		}
		out.WriteString(paymentQRReset)
		out.WriteByte('\n')
	}
	return out.String()
}
