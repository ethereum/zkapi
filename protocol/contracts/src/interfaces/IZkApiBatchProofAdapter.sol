// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Types} from "../libraries/Types.sol";

/// @title IZkApiBatchProofAdapter – Batch proof verification boundary
/// @notice Verifies n proofs of one statement kind in one check, all or nothing, and optionally
///         remembers every verified statement for the rest of the transaction, so that the vault's
///         ordinary single-item calls that follow (ZkApiExitBatcher) find each one verified. An
///         adapter that implements it reports both this interface and IZkApiProofAdapter through
///         ERC-165.
/// @dev `proofs` is the n 256-byte proofs concatenated, in the order of `inputs`: 256 · n bytes,
///      each eight words A.x, A.y, B.x.c0, B.x.c1, B.y.c0, B.y.c1, C.x, C.y. A batch must revert
///      exactly when one of its items, verified alone by IZkApiProofAdapter's assertValid* (never
///      through a record), would revert, up to a soundness error of about 2^-128 per batch, and
///      also for an empty batch or a proofs length other than 256 · n. It must refuse what a single
///      verification refuses, in particular any public input at or above the BN254 scalar field
///      order (the vault keys nullifiers on raw words, so an input must never verify in a
///      non-canonical form, value + r) and any coordinate at or above the base field order.
interface IZkApiBatchProofAdapter {
    /// @notice Asserts that every withdrawal proof is valid for its public inputs. Never consults
    ///         or writes a record.
    function verifyWithdrawalBatch(Types.WithdrawalPublicInputs[] calldata inputs, bytes calldata proofs) external view;

    /// @notice Asserts that every request proof is valid for its public inputs. Never consults or
    ///         writes a record.
    function verifyRequestBatch(Types.RequestPublicInputs[] calldata inputs, bytes calldata proofs) external view;

    /// @notice verifyWithdrawalBatch, then, for every item, the record IZkApiProofAdapter's
    ///         verifyWithdrawalOnce writes (transient, EIP-1153, at a slot associated with the
    ///         item's destination), so that assertValidWithdrawal of exactly that item's inputs and
    ///         proof later in the transaction returns without verifying. Records are written only
    ///         after the whole batch verified and are never erased.
    function verifyWithdrawalBatchOnce(Types.WithdrawalPublicInputs[] calldata inputs, bytes calldata proofs) external;

    /// @notice verifyRequestBatch, then a transient record per item, so that assertValidRequest of
    ///         exactly that item's inputs and proof later in the transaction (the vault's defeat or
    ///         raise of an escape) returns without verifying. Records are written only after the
    ///         whole batch verified, are never erased, and live in a namespace no withdrawal record
    ///         can reach.
    function verifyRequestBatchOnce(Types.RequestPublicInputs[] calldata inputs, bytes calldata proofs) external;
}
