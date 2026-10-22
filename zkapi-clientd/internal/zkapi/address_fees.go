package zkapi

import (
	"context"
	"errors"
	"math"
	"math/big"
	"math/bits"
	"sort"
	"strings"
	"time"
)

const addressMaxGas uint64 = 16_777_216

var addressUint256Max = new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 256), big.NewInt(1))
var errAddressFeeData = errors.New("current Ethereum fees could not be read reliably; retry the quote; no transaction was sent")
var errAddressQuoteChanged = errors.New("the network fee quote changed or expired; review a new quote; no transaction was sent")

type addressFeeHistory struct {
	OldestBlock string     `json:"oldestBlock"`
	BaseFees    []string   `json:"baseFeePerGas"`
	GasUsed     []float64  `json:"gasUsedRatio"`
	Rewards     [][]string `json:"reward"`
}
type addressFees struct{ Max, Tip, Minimum, Expected *big.Int }

// Fee inputs are JSON-RPC quantities, not ABI words: reject padding and signs.
func feeQuantity(encoded string) (*big.Int, error) {
	if len(encoded) < 3 || len(encoded) > 66 || !strings.HasPrefix(encoded, "0x") || (len(encoded) > 3 && encoded[2] == '0') {
		return nil, errAddressFeeData
	}
	for _, c := range encoded[2:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return nil, errAddressFeeData
		}
	}
	n, ok := new(big.Int).SetString(encoded[2:], 16)
	if !ok || n.BitLen() > 256 {
		return nil, errAddressFeeData
	}
	return n, nil
}
func lowPriorityFee(history addressFeeHistory, number uint64, base *big.Int) (*big.Int, error) {
	count := uint64(20)
	if number < 19 {
		count = number + 1
	}
	oldest, err := feeQuantity(history.OldestBlock)
	if err != nil || !oldest.IsUint64() || oldest.Uint64() != number-count+1 || len(history.BaseFees) != int(count)+1 || len(history.GasUsed) != int(count) || len(history.Rewards) != int(count) {
		return nil, errAddressFeeData
	}
	for i, s := range history.BaseFees {
		n, e := feeQuantity(s)
		if e != nil || (i == int(count)-1 && n.Cmp(base) != 0) {
			return nil, errAddressFeeData
		}
	}
	rewards := make([]*big.Int, 0, count)
	for i, row := range history.Rewards {
		ratio := history.GasUsed[i]
		if len(row) != 1 || math.IsNaN(ratio) || math.IsInf(ratio, 0) || ratio < 0 || ratio > 1 {
			return nil, errAddressFeeData
		}
		n, e := feeQuantity(row[0])
		if e != nil || (ratio == 0 && n.Sign() != 0) {
			return nil, errAddressFeeData
		}
		if ratio > 0 {
			rewards = append(rewards, n)
		}
	}
	minimum := big.NewInt(1_000_000)
	if len(rewards) == 0 {
		return minimum, nil
	}
	sort.Slice(rewards, func(i, j int) bool { return rewards[i].Cmp(rewards[j]) < 0 })
	middle := len(rewards) / 2
	median := new(big.Int).Set(rewards[middle])
	if len(rewards)%2 == 0 {
		median.Add(median, rewards[middle-1]).Quo(median, big.NewInt(2))
	}
	if median.Cmp(minimum) < 0 {
		return minimum, nil
	}
	return median, nil
}
func (h *FundingHandler) addressLowFees(ctx context.Context, config fundingConfig, gas uint64) (addressFees, error) {
	var out addressFees
	var block struct {
		Number    string `json:"number"`
		Timestamp string `json:"timestamp"`
		Base      string `json:"baseFeePerGas"`
	}
	if gas < 21000 || gas > addressMaxGas || h.addressRPC(ctx, config, "eth_getBlockByNumber", []any{"latest", false}, &block) != nil {
		return out, errAddressFeeData
	}
	number, e1 := feeQuantity(block.Number)
	timestamp, e2 := feeQuantity(block.Timestamp)
	base, e3 := feeQuantity(block.Base)
	if e1 != nil || e2 != nil || e3 != nil || !number.IsUint64() || number.BitLen() > 53 || !timestamp.IsInt64() || timestamp.BitLen() > 53 {
		return out, errAddressFeeData
	}
	var history addressFeeHistory
	if h.addressRPC(ctx, config, "eth_feeHistory", []any{"0x14", block.Number, []int{10}}, &history) != nil {
		return out, errAddressFeeData
	}
	tip, err := lowPriorityFee(history, number.Uint64(), base)
	if err != nil {
		return out, err
	}
	now := time.Now().Unix()
	if timestamp.Int64() < now-120 || timestamp.Int64() > now+30 {
		return out, errAddressFeeData
	}
	increase := new(big.Int).Quo(new(big.Int).Set(base), big.NewInt(8))
	if increase.Sign() == 0 {
		increase.SetInt64(1)
	}
	next := new(big.Int).Add(base, increase)
	low := new(big.Int).Quo(new(big.Int).Add(new(big.Int).Mul(base, big.NewInt(5)), big.NewInt(3)), big.NewInt(4))
	if low.Cmp(next) < 0 {
		low.Set(next)
	}
	out = addressFees{Max: new(big.Int).Add(low, tip), Tip: tip, Minimum: new(big.Int).Add(next, tip), Expected: new(big.Int).Add(base, tip)}
	if new(big.Int).Mul(out.Max, new(big.Int).SetUint64(gas)).BitLen() > 256 {
		return addressFees{}, errAddressFeeData
	}
	return out, nil
}
func paddedAddressGas(gas *big.Int) (uint64, error) {
	if gas == nil || !gas.IsUint64() || gas.Uint64() < 21000 || gas.Uint64() > addressMaxGas {
		return 0, errors.New("invalid payment gas estimate")
	}
	limit := (gas.Uint64()*120+99)/100 + 50_000
	if limit > addressMaxGas {
		return 0, errors.New("payment gas limit exceeds Ethereum's transaction cap")
	}
	return limit, nil
}

// The deposit gas-limit policy of vault revision 4 (design C.8). A deposit at
// note ID n hashes trailing_ones(n) frontier levels, about 16,100 gas each,
// plus about 7,100 when n has any, and the first deposit to reach a level,
// at n = 2^t - 1, writes a fresh storage slot. Another deposit can land
// first and move ours to a costlier ID, so a bare estimate at the current
// next ID is not enough: the limit covers every ID in the next
// depositGasWindow.
const (
	depositGasWindow      = 64
	depositGasPerLevel    = 16_500
	depositGasFirstLevel  = 7_500
	depositGasWrittenSlot = 5_000
	depositGasCap         = 1_500_000
)

// trailingOnes is the number of frontier levels a deposit at note ID n hashes.
func trailingOnes(n uint32) int {
	return bits.TrailingZeros32(^n)
}

// depositGasPolicyLimit is the policy's gas limit for a deposit whose
// estimate at next note ID next is estimate: with t_now = trailingOnes(next)
// and t_max the most over [next, next + 64),
//
//	extra = 16,500·(t_max − t_now) + (t_now = 0 and t_max > 0 ? 7,500 : 0)
//	      + (some 2^j − 1, j ≥ 1, in (next, next + 64) ? freshSlotGas − 5,000 : 0)
//
// and the limit is min(ceil(1.2·(estimate + extra)), 1,500,000). freshSlotGas
// is the network's fresh-slot cost from the deployment profile.
func depositGasPolicyLimit(estimate, next, freshSlotGas uint64) uint64 {
	if next > math.MaxUint32 {
		return depositGasCap
	}
	end := min(next+depositGasWindow, uint64(math.MaxUint32)+1)
	now := trailingOnes(uint32(next))
	most := now
	for k := next; k < end; k++ {
		most = max(most, trailingOnes(uint32(k)))
	}
	extra := uint64(depositGasPerLevel * (most - now))
	if now == 0 && most > 0 {
		extra += depositGasFirstLevel
	}
	for j := 1; j <= 32; j++ {
		if first := uint64(1)<<j - 1; first > next && first < next+depositGasWindow {
			extra += freshSlotGas - min(freshSlotGas, depositGasWrittenSlot)
			break
		}
	}
	if estimate > depositGasCap {
		return depositGasCap
	}
	return min(((estimate+extra)*12+9)/10, depositGasCap)
}

// depositGasLimit is the gas limit of a deposit whose padded estimate is
// padded and raw estimate estimate: the larger of padded and the policy's
// limit at the vault's next note ID, read at the latest block.
func (h *FundingHandler) depositGasLimit(ctx context.Context, config fundingConfig, estimate *big.Int, padded uint64) (uint64, error) {
	deployment, _, err := deployedDeployment(h.client.config.Network)
	if err != nil {
		return 0, err
	}
	next, err := h.addressUintCall(ctx, config, config.Contract, nextNoteIDSelector, "latest")
	if err != nil || !next.IsUint64() || next.Uint64() > math.MaxUint32 {
		return 0, errors.New("the vault's next note ID is unavailable; no deposit was signed")
	}
	if next.Uint64() == math.MaxUint32 {
		return 0, errors.New("the vault's note tree is full; no deposit was signed")
	}
	return max(padded, depositGasPolicyLimit(estimate.Uint64(), next.Uint64(), deployment.FreshSlotGas)), nil
}
