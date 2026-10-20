// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Types} from "../libraries/Types.sol";

/// @title IZkApiProofAdapter – Proof verification boundary
/// @notice The vault delegates Groth16 verification to this boundary.
interface IZkApiProofAdapter {
    /// @notice keccak256 of the circuit ID ("zkapi-v2-concession-v1"): the statement verified.
    function CIRCUIT_ID_HASH() external view returns (bytes32);

    /// @notice keccak256 of the request verifying key (request.vk without its header). Identifies
    ///         the setup, so it tells development keys from ceremony keys.
    function REQUEST_VK_HASH() external view returns (bytes32);

    /// @notice keccak256 of the withdrawal verifying key (withdrawal.vk without its header).
    function WITHDRAWAL_VK_HASH() external view returns (bytes32);

    /// @notice Assert that a request proof is valid for the given public inputs.
    /// @dev Must revert if the proof is invalid, and for any public input at or above the BN254
    ///      scalar field order: the vault matches nullifiers by their raw words, so an input must
    ///      never verify in a non-canonical form (value + r).
    function assertValidRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proofEnvelope) external view;

    /// @notice Assert that a withdrawal proof is valid for the given public inputs.
    /// @dev Must revert if the proof is invalid, and for any public input at or above the BN254
    ///      scalar field order. Must return without verifying again, at the cost of a lookup, when
    ///      verifyWithdrawalOnce verified exactly these inputs and proof earlier in the same
    ///      transaction, and only then.
    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proofEnvelope)
        external
        view;

    /// @notice Assert a withdrawal proof exactly as assertValidWithdrawal does, always verifying it
    ///         in full, and remember for the rest of the transaction that these inputs and proof
    ///         verified. The gasless paymaster calls it in validation, so that the vault's
    ///         assertValidWithdrawal of the same operation in the execution phase need not verify
    ///         the proof a second time.
    /// @dev Part of the interface's contract, not an optimisation an adapter may leave out: the
    ///      paymaster's callGasLimit floors of a CLOSE and an ESCAPE cover the vault's verification
    ///      as that lookup, so an adapter that verifies again in execution makes a sponsored exit
    ///      near its floor run out of gas after validation passed. What it remembers must be
    ///      transient (EIP-1153), written only after a full verification and never erased, and kept
    ///      at slots associated with inputs.destination in the ERC-7562 sense
    ///      (keccak256(destination ‖ x)): the paymaster calls it in validation for an operation
    ///      whose sender is the destination (STO-021). An adapter whose assertValidWithdrawal
    ///      already costs no more than that lookup (a test double that accepts every proof) has
    ///      nothing to remember.
    function verifyWithdrawalOnce(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proofEnvelope) external;

    /// @notice ERC-165: true for 0x01ffc9a7 and for type(IZkApiProofAdapter).interfaceId, which the
    ///         gasless paymaster requires of the vault's adapter before it relies on
    ///         verifyWithdrawalOnce.
    function supportsInterface(bytes4 interfaceId) external view returns (bool);
}
