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
    ///      scalar field order.
    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proofEnvelope)
        external
        view;
}
