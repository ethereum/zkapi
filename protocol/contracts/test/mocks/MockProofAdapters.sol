// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IZkApiProofAdapter} from "../../src/interfaces/IZkApiProofAdapter.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Errors} from "../../src/libraries/Errors.sol";

/// @dev The adapter identity constants every mock reports: the real circuit ID hash and
///      placeholder VK hashes that no setup has.
abstract contract MockAdapterIdentity is IZkApiProofAdapter {
    bytes32 public constant CIRCUIT_ID_HASH = keccak256("zkapi-v2-concession-v1");
    bytes32 public constant REQUEST_VK_HASH = keccak256("mock request vk");
    bytes32 public constant WITHDRAWAL_VK_HASH = keccak256("mock withdrawal vk");
}

/// @dev Isolates vault checks; the real adapter has separate Groth16 fixture tests. Accepts every
///      withdrawal and only the request proofs registered through acceptRequest.
contract MockProofAdapter is MockAdapterIdentity {
    mapping(bytes32 => bool) private acceptedRequests;

    function acceptRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof) external {
        acceptedRequests[keccak256(abi.encode(inputs, proof))] = true;
    }

    function assertValidRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof) external view {
        if (!acceptedRequests[keccak256(abi.encode(inputs, proof))]) revert Errors.InvalidProof();
    }

    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata, bytes calldata) external pure {}
}

/// @dev Accepts every proof.
contract AcceptAllProofs is MockAdapterIdentity {
    function assertValidRequest(Types.RequestPublicInputs calldata, bytes calldata) external pure {}
    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata, bytes calldata) external pure {}
}
