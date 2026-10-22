// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {IZkApiProofAdapter} from "../../src/interfaces/IZkApiProofAdapter.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Errors} from "../../src/libraries/Errors.sol";
import {ReferenceHashes} from "../helpers/PoseidonRuntime.sol";

/// @dev The adapter identity constants every mock reports: the real circuit ID hash and
///      placeholder VK hashes that no setup has, and the ERC-165 answer the paymaster requires.
abstract contract MockAdapterIdentity is IZkApiProofAdapter {
    bytes32 public constant CIRCUIT_ID_HASH = keccak256("zkapi-v2-concession-v2");
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

    /// @dev Tests register each deposit's commitment; this mock ignores it.
    function register(uint32, bytes32) external virtual {}

    function acceptRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof) external {
        acceptedRequests[keccak256(abi.encode(inputs, proof))] = true;
    }

    function assertValidRequest(Types.RequestPublicInputs calldata inputs, bytes calldata proof) external view {
        if (!acceptedRequests[keccak256(abi.encode(inputs, proof))]) revert Errors.InvalidProof();
    }

    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata, bytes calldata) external view virtual {}

    /// @dev Accepts every withdrawal, so nothing reads the record; it is written anyway, as the real
    ///      adapter writes it (one TSTORE at keccak256(destination ‖ h) after hashing that preimage
    ///      in this frame), so that the paymaster's validation with this mock makes the same
    ///      sender-associated access the opcode audit checks, first uses (initCode) included.
    function verifyWithdrawalOnce(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof) external virtual {
        _record(inputs, proof);
    }

    function _record(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof) internal {
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

/// @dev The circuit's leaf binding without the rest of the proof: accepts a withdrawal only when
///      its noteLeaf is the leaf of the registration commitment registered for the note ID in its
///      noteFields over exactly those noteFields (W5: L = P(d_leaf', R(s), F)[1]), computed with the
///      reference Poseidon. A real proof proves this for the prover's secret; the vault must then
///      refuse every statement whose leaf is not the stored one, which this mock lets the vault
///      tests, the invariant and the mutation suites exercise: an exit that would take D or e from
///      fields the leaf does not bind cannot pass here. Requests verify once registered, as with
///      MockProofAdapter.
contract LeafBindingMockAdapter is MockProofAdapter {
    /// @notice The registration commitment a test deposited under each note ID.
    mapping(uint32 => bytes32) public registrationOf;

    function register(uint32 noteId, bytes32 commitment) external override {
        registrationOf[noteId] = commitment;
    }

    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata inputs, bytes calldata)
        external
        view
        override
    {
        _bind(inputs);
    }

    /// @dev As MockProofAdapter's: checks the binding, then writes the record the real adapter writes.
    function verifyWithdrawalOnce(Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof)
        external
        override
    {
        _bind(inputs);
        _record(inputs, proof);
    }

    function _bind(Types.WithdrawalPublicInputs calldata inputs) private view {
        uint256 fields = inputs.noteFields;
        // The circuit's range checks: F packs a u32, a u128 and a u64.
        if (fields >> 224 != 0) revert Errors.InvalidProof();
        bytes32 registration = registrationOf[uint32(fields >> 192)];
        if (registration == bytes32(0)) revert Errors.InvalidProof();
        if (inputs.noteLeaf != ReferenceHashes.leafOfFields(registration, fields)) revert Errors.InvalidProof();
    }
}
