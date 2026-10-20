// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IZkApiProofAdapter} from "../../src/interfaces/IZkApiProofAdapter.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Errors} from "../../src/libraries/Errors.sol";

/// @dev The adapter identity constants every mock reports: the real circuit ID hash and
///      placeholder VK hashes that no setup has, and the ERC-165 answer the paymaster requires.
abstract contract MockAdapterIdentity is IZkApiProofAdapter {
    bytes32 public constant CIRCUIT_ID_HASH = keccak256("zkapi-v2-concession-v1");
    bytes32 public constant REQUEST_VK_HASH = keccak256("mock request vk");
    bytes32 public constant WITHDRAWAL_VK_HASH = keccak256("mock withdrawal vk");

    function supportsInterface(bytes4 interfaceId) external pure returns (bool) {
        return interfaceId == type(IZkApiProofAdapter).interfaceId || interfaceId == 0x01ffc9a7;
    }
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

    /// @dev Accepts every withdrawal, so nothing reads the record; it is written anyway, as the real
    ///      adapter writes it (one TSTORE at keccak256(destination ‖ h) after hashing that preimage
    ///      in this frame), so that the paymaster's validation with this mock makes the same
    ///      sender-associated access the opcode audit checks, first uses (initCode) included.
    function verifyWithdrawalOnce(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof) external {
        bytes32 h = keccak256(abi.encode(inputs, proof));
        address destination = inputs.destination;
        assembly ("memory-safe") {
            mstore(0x00, destination)
            mstore(0x20, h)
            tstore(keccak256(0x00, 0x40), 1)
        }
    }
}

/// @dev Accepts every proof, so its assertValidWithdrawal costs less than a record's lookup and
///      verifyWithdrawalOnce has nothing to remember.
contract AcceptAllProofs is MockAdapterIdentity {
    function assertValidRequest(Types.RequestPublicInputs calldata, bytes calldata) external pure {}
    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata, bytes calldata) external pure {}
    function verifyWithdrawalOnce(Types.WithdrawalPublicInputs calldata, bytes calldata) external pure {}
}
