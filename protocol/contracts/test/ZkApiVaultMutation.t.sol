// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Groth16ProofAdapter} from "../src/adapters/Groth16ProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";

/// @dev Generated mutation test: for every real fixture proof (both fixture files), every one of
///      its public inputs (12 request, 16 withdrawal) is changed in turn to another value of its
///      Solidity type and inside the scalar field, and the real adapter must revert InvalidProof.
///      So does every one of the 8 proof words. The inputs are mutated as ABI words, in
///      public-input order, so an adapter that skipped, reordered or misencoded an input fails
///      here even if the Rust side is right.
///      Each field-element input (the 256-bit words) is also given its non-canonical form
///      value + r, which the ecMul precompile would reduce to the same scalar, and each proof word
///      value + q. The adapter must refuse both: the vault keys usedNullifiers,
///      challengedNullifiers and pendingConcessions on the raw words, so an adapter that reduced
///      N + r or N_{k+1} + r to a valid proof would let an escape slip past ChallengedNullifier,
///      SupersededState and ReplayedNullifier, or name a successor no defeat can match.
contract ZkApiVaultMutationTest is Test {
    uint256 constant SCALAR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant BASE_MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    /// Gas for each verification. A proof word off the curve makes a precompile fail, which burns
    /// all the gas the adapter forwards to it; the cap keeps the loop from running dry.
    uint256 constant VERIFY_GAS = 1_000_000;

    Groth16ProofAdapter adapter;

    /// Bit widths of the request inputs in order (256: a field element).
    uint16[12] REQUEST_BITS = [16, 64, 160, 256, 256, 256, 64, 128, 256, 256, 256, 256];
    /// Bit widths of the withdrawal inputs in order.
    uint16[16] WITHDRAWAL_BITS = [16, 64, 160, 256, 256, 256, 256, 256, 32, 128, 160, 256, 8, 256, 128, 64];

    function setUp() public {
        adapter = new Groth16ProofAdapter();
    }

    function test_everyRequestInputIsBound() public {
        string[2] memory solidity = ["request", "request_signed"];
        for (uint256 i = 0; i < solidity.length; ++i) {
            _mutateRequest("test/fixtures/solidity-fixture.json", solidity[i]);
        }
        string[5] memory vault = ["request_a0", "request_a1", "request_a2", "request_a3", "request_b0"];
        for (uint256 i = 0; i < vault.length; ++i) {
            _mutateRequest("test/fixtures/vault-challenge.json", vault[i]);
        }
    }

    function test_everyWithdrawalInputIsBound() public {
        string[6] memory solidity =
            ["withdrawal", "escape_c0", "escape_genesis_concession", "close", "ownership", "escape_full_destination"];
        for (uint256 i = 0; i < solidity.length; ++i) {
            _mutateWithdrawal("test/fixtures/solidity-fixture.json", solidity[i]);
        }
        string[6] memory vault = [
            "escape_a2",
            "escape_a2_concede",
            "escape_a2_expired",
            "escape_b0_genesis_concede",
            "close_a2",
            "ownership_a2"
        ];
        for (uint256 i = 0; i < vault.length; ++i) {
            _mutateWithdrawal("test/fixtures/vault-challenge.json", vault[i]);
        }
    }

    function _mutateRequest(string memory file, string memory name) private {
        (bytes memory words, bytes memory proof) = _fixture(file, name);
        assertEq(words.length, 12 * 32, name);
        adapter.assertValidRequest{gas: VERIFY_GAS}(abi.decode(words, (Types.RequestPublicInputs)), proof);
        for (uint256 i = 0; i < 12; ++i) {
            bytes memory mutated = _mutateWord(words, i, REQUEST_BITS[i]);
            Types.RequestPublicInputs memory inputs = abi.decode(mutated, (Types.RequestPublicInputs));
            vm.expectRevert(Errors.InvalidProof.selector);
            adapter.assertValidRequest{gas: VERIFY_GAS}(inputs, proof);
            if (REQUEST_BITS[i] != 256) continue;
            inputs = abi.decode(_addToWord(words, i, SCALAR_MODULUS), (Types.RequestPublicInputs));
            vm.expectRevert(Errors.InvalidProof.selector);
            adapter.assertValidRequest{gas: VERIFY_GAS}(inputs, proof);
        }
        Types.RequestPublicInputs memory original = abi.decode(words, (Types.RequestPublicInputs));
        for (uint256 i = 0; i < 8; ++i) {
            bytes memory mutatedProof = _mutateWord(proof, i, 256);
            vm.expectRevert(Errors.InvalidProof.selector);
            adapter.assertValidRequest{gas: VERIFY_GAS}(original, mutatedProof);
            vm.expectRevert(Errors.InvalidProof.selector);
            adapter.assertValidRequest{gas: VERIFY_GAS}(original, _addToWord(proof, i, BASE_MODULUS));
        }
    }

    function _mutateWithdrawal(string memory file, string memory name) private {
        (bytes memory words, bytes memory proof) = _fixture(file, name);
        assertEq(words.length, 16 * 32, name);
        adapter.assertValidWithdrawal{gas: VERIFY_GAS}(abi.decode(words, (Types.WithdrawalPublicInputs)), proof);
        for (uint256 i = 0; i < 16; ++i) {
            bytes memory mutated = _mutateWord(words, i, WITHDRAWAL_BITS[i]);
            Types.WithdrawalPublicInputs memory inputs = abi.decode(mutated, (Types.WithdrawalPublicInputs));
            vm.expectRevert(Errors.InvalidProof.selector);
            adapter.assertValidWithdrawal{gas: VERIFY_GAS}(inputs, proof);
            if (WITHDRAWAL_BITS[i] != 256) continue;
            inputs = abi.decode(_addToWord(words, i, SCALAR_MODULUS), (Types.WithdrawalPublicInputs));
            vm.expectRevert(Errors.InvalidProof.selector);
            adapter.assertValidWithdrawal{gas: VERIFY_GAS}(inputs, proof);
        }
        Types.WithdrawalPublicInputs memory original = abi.decode(words, (Types.WithdrawalPublicInputs));
        for (uint256 i = 0; i < 8; ++i) {
            bytes memory mutatedProof = _mutateWord(proof, i, 256);
            vm.expectRevert(Errors.InvalidProof.selector);
            adapter.assertValidWithdrawal{gas: VERIFY_GAS}(original, mutatedProof);
            vm.expectRevert(Errors.InvalidProof.selector);
            adapter.assertValidWithdrawal{gas: VERIFY_GAS}(original, _addToWord(proof, i, BASE_MODULUS));
        }
    }

    /// A copy of `data` whose word `index` is changed by one, staying below 2^bits and below the
    /// scalar field order.
    function _mutateWord(bytes memory data, uint256 index, uint16 bits) private pure returns (bytes memory out) {
        out = bytes.concat(data);
        uint256 value;
        assembly ("memory-safe") {
            value := mload(add(add(out, 0x20), mul(index, 0x20)))
        }
        uint256 limit = bits == 256 ? SCALAR_MODULUS - 1 : (uint256(1) << bits) - 1;
        uint256 next = value < limit ? value + 1 : value - 1;
        assembly ("memory-safe") {
            mstore(add(add(out, 0x20), mul(index, 0x20)), next)
        }
    }

    /// A copy of `data` whose word `index` is increased by `modulus`: the same residue, written
    /// non-canonically. Every fixture word is below the modulus, so the sum cannot overflow.
    function _addToWord(bytes memory data, uint256 index, uint256 modulus) private pure returns (bytes memory out) {
        out = bytes.concat(data);
        uint256 value;
        assembly ("memory-safe") {
            value := mload(add(add(out, 0x20), mul(index, 0x20)))
        }
        require(value < modulus, "fixture word is not canonical");
        assembly ("memory-safe") {
            mstore(add(add(out, 0x20), mul(index, 0x20)), add(value, modulus))
        }
    }

    function _fixture(string memory file, string memory name) private view returns (bytes memory, bytes memory) {
        string memory json = vm.readFile(file);
        return (
            vm.parseJsonBytes(json, string.concat(".", name, ".inputs_abi")),
            vm.parseJsonBytes(json, string.concat(".", name, ".proof_hex"))
        );
    }
}
