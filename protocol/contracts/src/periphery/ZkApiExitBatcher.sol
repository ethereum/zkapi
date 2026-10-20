// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ZkApiVault} from "../ZkApiVault.sol";
import {Types} from "../libraries/Types.sol";
import {IZkApiBatchProofAdapter} from "../interfaces/IZkApiBatchProofAdapter.sol";
import {IZkApiProofAdapter} from "../interfaces/IZkApiProofAdapter.sol";

/// @title ZkApiExitBatcher
/// @notice Lands many vault exits of one kind in one transaction: it verifies every item's proof at
///         once through the vault's adapter (verify*BatchOnce, all or nothing), then makes each
///         item's ordinary vault call (mutualClose, initiateEscapeWithdrawal,
///         challengeEscapeWithdrawal, raiseEscapeConcession, finalizeEscapeWithdrawal), whose own
///         verification finds the adapter's record of it and costs a lookup. Stateless and
///         permissionless: an operator relaying cooperative closes, the challenger batching defeats
///         and raises, and anyone landing a community's exits use the same contract, and it can be
///         redeployed without touching the vault.
/// @dev Safety:
///      - Payouts stay bound by the proofs: every call is the vault's own, whose checks and payouts
///        are unchanged, so a submitter cannot redirect funds. The batcher holds no ETH (nothing
///        here is payable) and keeps no state.
///      - Validity does not depend on state: every item is verified up front, whatever its state, so
///        a simulation of the exact batch is final for its proofs (eth_call it before sending).
///      - An item whose state no longer allows it (closed or escaped by its owner first, already
///        defeated, finalized or raised) is skipped with ItemSkipped and the batch goes on, as is an
///        item whose call runs out of its kind's gas cap (a destination that burns the payout's gas)
///        or whose payout push fails. Each call gets exactly its kind's cap, set at construction for
///        the chain's gas schedule, so one item can never take another's gas.
///      - The batch itself is never starved into a skip: after verification it requires the
///        worst-case gas of every item up front (n · cap · 64/63 plus overheads) and, before each
///        call, that the call can get its whole cap; otherwise the whole call reverts
///        BatchOutOfGas. eth_estimateGas therefore already covers hostile destinations.
///      - The verifications forward all gas to the BN254 precompiles (gas()), as the single
///        verifier does, so a batch with an invalid point burns what it was given: simulate first.
contract ZkApiExitBatcher {
    // ------------------------------------------------------------------------------------ kinds

    uint8 public constant KIND_CLOSE = 0;
    uint8 public constant KIND_ESCAPE = 1;
    uint8 public constant KIND_DEFEAT = 2;
    uint8 public constant KIND_RAISE = 3;
    uint8 public constant KIND_FINALIZE = 4;

    // --------------------------------------------------------------------------------- gas model

    /// @notice The most items one call takes (the bitmap of applied items has 256 bits; a batch
    ///         this size already needs more gas than most chains allow one transaction for large
    ///         caps: see gasBound).
    uint256 public constant MAX_ITEMS = 64;
    /// @notice An upper bound of verify*BatchOnce's gas for n proofs, VERIFY_BASE_GAS + n ·
    ///         VERIFY_ITEM_GAS, measured on the generated adapter's worst case (every item on the
    ///         generic path, every scalar a full multiplication) with a margin
    ///         (test/batch/BatchGas.t.sol), including the batcher's ABI re-encoding of the call.
    uint256 public constant VERIFY_BASE_GAS = 330_000;
    uint256 public constant VERIFY_ITEM_GAS = 60_000;
    /// @notice Each item's gas besides its vault call: the guard, the call's encoding and its cold
    ///         access, the return-data copy and a skip's event (test/batch/ExitBatcher.t.sol).
    uint256 public constant ITEM_OVERHEAD_GAS = 15_000;
    /// @notice The reserve's slack for the loop's own bookkeeping and the return.
    uint256 public constant RESERVE_MARGIN_GAS = 20_000;
    /// @notice ItemSkipped carries at most this many bytes of a refused call's revert data.
    uint256 public constant MAX_REASON_BYTES = 256;
    /// @notice Bounds of a per-kind cap at construction.
    uint256 public constant MIN_ITEM_GAS = 50_000;
    uint256 public constant MAX_ITEM_GAS = 2_000_000;

    // ---------------------------------------------------------------------------------- immutables

    ZkApiVault public immutable vault;
    IZkApiBatchProofAdapter public immutable adapter;
    /// @notice The gas each kind's vault call gets, set for the chain's gas schedule.
    uint256 public immutable closeGas;
    uint256 public immutable escapeGas;
    uint256 public immutable defeatGas;
    uint256 public immutable raiseGas;
    uint256 public immutable finalizeGas;

    // ---------------------------------------------------------------------------- events and errors

    /// @notice Item `index` was not applied: its vault call reverted with `reason` (truncated to
    ///         MAX_REASON_BYTES; empty when it ran out of its gas cap).
    event ItemSkipped(uint256 indexed index, uint8 indexed kind, uint32 indexed noteId, bytes reason);

    /// @notice The batch cannot give item `index` (0 for the up-front reserve) its whole gas cap:
    ///         send it with more gas (gasBound) rather than let an item be skipped for lack of gas.
    error BatchOutOfGas(uint256 index);
    error EmptyBatch();
    error BatchTooLarge(uint256 items, uint256 max);
    error LengthMismatch();
    /// @notice A kind other than the five above.
    error UnknownKind(uint8 kind);
    /// @notice The vault's adapter does not report IZkApiBatchProofAdapter (constructor).
    error NotABatchAdapter();
    /// @notice A per-kind cap outside [MIN_ITEM_GAS, MAX_ITEM_GAS] (constructor).
    error ItemGasOutOfRange(uint8 kind, uint256 gas);

    /// @param vault_ The vault whose exits this batcher lands; its adapter must report both
    ///        IZkApiProofAdapter and IZkApiBatchProofAdapter through ERC-165.
    /// @param itemGas_ The gas of each kind's vault call, in kind order (close, escape, defeat,
    ///        raise, finalize). Chain-specific: docs/deployment.md lists the measured values for
    ///        mainnet's schedule and for EIP-8037's state-creation pricing.
    constructor(ZkApiVault vault_, uint256[5] memory itemGas_) {
        address adapter_ = address(vault_.proofAdapter());
        if (!_supports(adapter_, type(IZkApiBatchProofAdapter).interfaceId)) revert NotABatchAdapter();
        if (!_supports(adapter_, type(IZkApiProofAdapter).interfaceId)) revert NotABatchAdapter();
        for (uint8 kind = 0; kind < 5; ++kind) {
            if (itemGas_[kind] < MIN_ITEM_GAS || itemGas_[kind] > MAX_ITEM_GAS) {
                revert ItemGasOutOfRange(kind, itemGas_[kind]);
            }
        }
        vault = vault_;
        adapter = IZkApiBatchProofAdapter(adapter_);
        closeGas = itemGas_[KIND_CLOSE];
        escapeGas = itemGas_[KIND_ESCAPE];
        defeatGas = itemGas_[KIND_DEFEAT];
        raiseGas = itemGas_[KIND_RAISE];
        finalizeGas = itemGas_[KIND_FINALIZE];
    }

    // ------------------------------------------------------------------------------------ batches

    /// @notice mutualClose of every item, after one batch verification of all of them.
    /// @return applied Bit i set iff item i's close landed.
    function mutualCloseBatch(Types.WithdrawalPublicInputs[] calldata inputs, bytes calldata proofs)
        external
        returns (uint256 applied)
    {
        uint256 n = _size(inputs.length);
        adapter.verifyWithdrawalBatchOnce(inputs, proofs);
        uint256 cap = closeGas;
        _reserve(n * _itemReserve(cap));
        for (uint256 i = 0; i < n; ++i) {
            _guard(i, cap);
            (bool ok, bytes memory reason) =
                _call(cap, abi.encodeCall(ZkApiVault.mutualClose, (inputs[i], proofs[i * 0x100:(i + 1) * 0x100])));
            if (ok) applied |= 1 << i;
            else emit ItemSkipped(i, KIND_CLOSE, inputs[i].noteId, reason);
        }
    }

    /// @notice initiateEscapeWithdrawal of every item, after one batch verification of all of them.
    /// @return applied Bit i set iff item i's escape started.
    function initiateEscapeBatch(Types.WithdrawalPublicInputs[] calldata inputs, bytes calldata proofs)
        external
        returns (uint256 applied)
    {
        uint256 n = _size(inputs.length);
        adapter.verifyWithdrawalBatchOnce(inputs, proofs);
        uint256 cap = escapeGas;
        _reserve(n * _itemReserve(cap));
        for (uint256 i = 0; i < n; ++i) {
            _guard(i, cap);
            (bool ok, bytes memory reason) = _call(
                cap, abi.encodeCall(ZkApiVault.initiateEscapeWithdrawal, (inputs[i], proofs[i * 0x100:(i + 1) * 0x100]))
            );
            if (ok) applied |= 1 << i;
            else emit ItemSkipped(i, KIND_ESCAPE, inputs[i].noteId, reason);
        }
    }

    /// @notice Defeats and raises of pending escapes with request proofs, after one batch
    ///         verification of all of them: amounts[i] == 0 defeats noteIds[i]'s escape
    ///         (challengeEscapeWithdrawal), any other amount raises its concession to it
    ///         (raiseEscapeConcession).
    /// @return applied Bit i set iff item i's defeat or raise landed.
    function challengeBatch(
        uint32[] calldata noteIds,
        uint128[] calldata amounts,
        Types.RequestPublicInputs[] calldata inputs,
        bytes calldata proofs
    ) external returns (uint256 applied) {
        uint256 n = _size(inputs.length);
        if (noteIds.length != n || amounts.length != n) revert LengthMismatch();
        adapter.verifyRequestBatchOnce(inputs, proofs);
        (uint256 defeatCap, uint256 raiseCap) = (defeatGas, raiseGas);
        uint256 reserve;
        for (uint256 i = 0; i < n; ++i) {
            reserve += _itemReserve(amounts[i] == 0 ? defeatCap : raiseCap);
        }
        _reserve(reserve);
        for (uint256 i = 0; i < n; ++i) {
            bool defeat = amounts[i] == 0;
            uint256 cap = defeat ? defeatCap : raiseCap;
            _guard(i, cap);
            bytes calldata proof = proofs[i * 0x100:(i + 1) * 0x100];
            (bool ok, bytes memory reason) = _call(
                cap,
                defeat
                    ? abi.encodeCall(ZkApiVault.challengeEscapeWithdrawal, (noteIds[i], inputs[i], proof))
                    : abi.encodeCall(ZkApiVault.raiseEscapeConcession, (noteIds[i], inputs[i], proof, amounts[i]))
            );
            if (ok) applied |= 1 << i;
            else emit ItemSkipped(i, defeat ? KIND_DEFEAT : KIND_RAISE, noteIds[i], reason);
        }
    }

    /// @notice finalizeEscapeWithdrawal of every note (no proof to verify).
    /// @return applied Bit i set iff note i's escape was paid out.
    function finalizeBatch(uint32[] calldata noteIds) external returns (uint256 applied) {
        uint256 n = _size(noteIds.length);
        uint256 cap = finalizeGas;
        _reserve(n * _itemReserve(cap));
        for (uint256 i = 0; i < n; ++i) {
            _guard(i, cap);
            (bool ok, bytes memory reason) =
                _call(cap, abi.encodeCall(ZkApiVault.finalizeEscapeWithdrawal, (noteIds[i])));
            if (ok) applied |= 1 << i;
            else emit ItemSkipped(i, KIND_FINALIZE, noteIds[i], reason);
        }
    }

    // ---------------------------------------------------------------------------------- the gas model

    /// @notice The gas each call of `kind` gets.
    function itemGas(uint8 kind) public view returns (uint256) {
        if (kind == KIND_CLOSE) return closeGas;
        if (kind == KIND_ESCAPE) return escapeGas;
        if (kind == KIND_DEFEAT) return defeatGas;
        if (kind == KIND_RAISE) return raiseGas;
        if (kind == KIND_FINALIZE) return finalizeGas;
        revert UnknownKind(kind);
    }

    /// @notice An upper bound of a batch call's execution gas (without the transaction's 21,000
    ///         and its calldata) for items of these kinds, kinds[i] item i's: the verification bound
    ///         (none for finalizations) plus the reserve the call requires. A relayer sends at
    ///         least this, and never less than eth_estimateGas of the exact batch.
    function gasBound(uint8[] calldata kinds) external view returns (uint256 gas) {
        uint256 proofs;
        for (uint256 i = 0; i < kinds.length; ++i) {
            gas += _itemReserve(itemGas(kinds[i]));
            if (kinds[i] != KIND_FINALIZE) ++proofs;
        }
        gas += RESERVE_MARGIN_GAS;
        if (proofs != 0) gas += VERIFY_BASE_GAS + proofs * VERIFY_ITEM_GAS;
    }

    // ------------------------------------------------------------------------------------ internals

    function _size(uint256 n) private pure returns (uint256) {
        if (n == 0) revert EmptyBatch();
        if (n > MAX_ITEMS) revert BatchTooLarge(n, MAX_ITEMS);
        return n;
    }

    /// @dev The gas one item may take from the batch: its whole cap through the 63/64 rule, and its
    ///      overhead.
    function _itemReserve(uint256 cap) private pure returns (uint256) {
        return (cap * 64) / 63 + ITEM_OVERHEAD_GAS;
    }

    /// @dev After verification, the worst case of every item up front, so that no item can be
    ///      starved into a skip and a simulation's gas estimate covers hostile destinations.
    function _reserve(uint256 itemsReserve) private view {
        if (gasleft() < itemsReserve + RESERVE_MARGIN_GAS) revert BatchOutOfGas(0);
    }

    /// @dev Before each call: the call can get its whole cap (EIP-150 forwards at most 63/64 of
    ///      what is left after the call's own cost, which the overhead covers).
    function _guard(uint256 index, uint256 cap) private view {
        if (gasleft() < _itemReserve(cap)) revert BatchOutOfGas(index);
    }

    /// @dev The vault call with exactly `cap` gas; on a revert, at most MAX_REASON_BYTES of its data.
    function _call(uint256 cap, bytes memory data) private returns (bool ok, bytes memory reason) {
        address target = address(vault);
        assembly ("memory-safe") {
            ok := call(cap, target, 0, add(data, 0x20), mload(data), 0, 0)
        }
        if (!ok) {
            uint256 size = MAX_REASON_BYTES;
            assembly ("memory-safe") {
                if lt(returndatasize(), size) { size := returndatasize() }
                reason := mload(0x40)
                mstore(reason, size)
                returndatacopy(add(reason, 0x20), 0, size)
                mstore(0x40, add(add(reason, 0x20), and(add(size, 0x1f), not(0x1f))))
            }
        }
    }

    /// @dev ERC-165 through a bounded static call: a missing or reverting supportsInterface, or any
    ///      answer but true, is false.
    function _supports(address target, bytes4 interfaceId) private view returns (bool) {
        if (target.code.length == 0) return false;
        (bool ok, bytes memory answer) =
            target.staticcall{gas: 30_000}(abi.encodeCall(IZkApiProofAdapter.supportsInterface, (interfaceId)));
        return ok && answer.length == 32 && uint256(bytes32(answer)) == 1;
    }
}
