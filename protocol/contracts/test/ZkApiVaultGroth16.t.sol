// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
import {Groth16ProofAdapter} from "../src/adapters/Groth16ProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {Events} from "../src/libraries/Events.sol";
import {Bn254PoseidonReference} from "./reference/Bn254PoseidonReference.sol";
import {NoteLeafLib} from "../src/libraries/NoteLeafLib.sol";
import {PoseidonRuntime, ReferenceHashes} from "./helpers/PoseidonRuntime.sol";

/// @dev Rust-generated proofs (CircomReduction prover, committed setup), the generated verifier and
///      a normally deployed vault. Regenerate test/fixtures/vault-challenge.json with
///        cargo run --release -p zkapi-proof --example vault_challenge_fixture -- \
///          ../setup/v2-concession-dev > ../contracts/test/fixtures/vault-challenge.json
///      Note A (id 0) has the honest chain a0 -R0-> a1 -R1-> a2 -R2-> a3 (charges 60,000, 150,000
///      and 40,000; R2's bound is 100,000), so B2 = 790,000. Note B (id 1) shares A's secret and is
///      at genesis. Every proof is at the root holding A and B unless named otherwise, and is valid
///      until the fixture's valid_until (7 days after the deposits).
contract ZkApiVaultGroth16Test is Test {
    uint256 constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465;
    uint128 constant DEPOSIT = 1_000_000;
    uint128 constant B2 = 790_000;
    uint128 constant SB2 = 100_000;
    uint128 constant CHARGE2 = 40_000;
    uint256 constant SCALAR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    address constant DEPLOYER = address(0xf00d);
    address constant USER = 0x1111111111111111111111111111111111111111;
    address constant TREASURY = address(0xbeef);
    address constant OPERATOR = address(0x0D0D);

    Groth16ProofAdapter adapter;
    ZkApiVault vault;
    string fixtures;
    uint256[32] emptySiblings;
    mapping(uint32 => bool) retired;

    function setUp() public {
        vm.chainId(31_337);
        fixtures = vm.readFile("test/fixtures/vault-challenge.json");
        assertEq(vm.parseJsonString(fixtures, ".circuit_id"), "zkapi-v2-concession-v2");
        vm.warp(vm.parseJsonUint(fixtures, ".timestamp"));
        uint256 zero;
        for (uint256 level = 0; level < 32; ++level) {
            emptySiblings[level] = zero;
            zero = Bn254PoseidonReference.compress(DOMAIN_NODE, zero, zero);
        }
        (Types.WithdrawalPublicInputs memory parameters,) = _withdrawal("escape_a2");
        // Folded for the vault DEPLOYER creates at nonce 0, the address the proofs bind.
        adapter = new Groth16ProofAdapter(
            vm.computeCreateAddress(DEPLOYER, 0),
            parameters.stateSigningKeyX,
            parameters.stateSigningKeyY,
            parameters.clearanceSigningKeyX,
            parameters.clearanceSigningKeyY
        );
        vm.setNonce(DEPLOYER, 0);
        vm.prank(DEPLOYER);
        vault = new ZkApiVault(
            TREASURY,
            30 days,
            24 hours,
            100_000,
            address(adapter),
            parameters.stateSigningKeyX,
            parameters.stateSigningKeyY,
            parameters.clearanceSigningKeyX,
            parameters.clearanceSigningKeyY,
            address(this),
            7 days,
            PoseidonRuntime.etch(),
            1
        );
        assertEq(address(vault), parameters.contractAddress);
        vm.deal(USER, 10 * uint256(DEPOSIT) * 1 gwei);
    }

    // ======================================================== withholding operator

    /// The operator withheld a3 after R2 and refuses clearance. The owner escapes from a2
    /// conceding R2's bound. The operator's evidence (R2 at N2, and every older request) neither
    /// defeats nor raises it, and the treasury gains exactly D - (B2 - sb2).
    function test_realWithholdingConcessionExits() public {
        _depositAB();
        (Types.WithdrawalPublicInputs memory escape, bytes memory escapeProof) = _withdrawal("escape_a2_concede");
        assertEq(escape.conceded, SB2);
        assertEq(escape.finalBalance, B2 - SB2);
        vm.prank(USER);
        vault.initiateEscapeWithdrawal(escape, escapeProof);

        vm.startPrank(OPERATOR);
        string[3] memory archived = ["request_a0", "request_a1", "request_a2"];
        for (uint256 i = 0; i < archived.length; ++i) {
            (Types.RequestPublicInputs memory request, bytes memory proof) = _request(archived[i]);
            vm.expectRevert(Errors.NotSuccessorEvidence.selector);
            vault.challengeEscapeWithdrawal(0, request, proof);
        }
        (Types.RequestPublicInputs memory r2, bytes memory r2Proof) = _request("request_a2");
        vm.expectRevert(Errors.NotARaise.selector);
        vault.raiseEscapeConcession(0, r2, r2Proof, type(uint128).max);
        vm.stopPrank();

        uint256 treasuryBefore = TREASURY.balance;
        vm.warp(_deadline(0));
        vault.finalizeEscapeWithdrawal(0);
        assertEq(USER.balance, 8 * uint256(DEPOSIT) * 1 gwei + uint256(B2 - SB2) * 1 gwei);
        assertEq(TREASURY.balance - treasuryBefore, uint256(DEPOSIT - (B2 - SB2)) * 1 gwei);
        assertEq(address(vault).balance, uint256(DEPOSIT) * 1 gwei);
    }

    /// A forced early exit concedes nothing; the honest challenger raises it with R2 to the
    /// settled charge, and a later raise is capped at R2's bound.
    function test_realRaiseToTheChargeThenToTheBound() public {
        _depositAB();
        _initiate("escape_a2");
        (Types.RequestPublicInputs memory r2, bytes memory r2Proof) = _request("request_a2");
        vm.prank(OPERATOR);
        vault.raiseEscapeConcession(0, r2, r2Proof, CHARGE2);
        assertEq(_finalBalance(0), B2 - CHARGE2);
        vm.prank(OPERATOR);
        vault.raiseEscapeConcession(0, r2, r2Proof, type(uint128).max);
        assertEq(_finalBalance(0), B2 - SB2);
        (, uint128 stateBalance, uint128 conceded) = vault.pendingConcessions(0);
        assertEq(stateBalance, B2);
        assertEq(conceded, SB2);
        vm.warp(_deadline(0));
        vault.finalizeEscapeWithdrawal(0);
        assertEq(TREASURY.balance, uint256(DEPOSIT - (B2 - SB2)) * 1 gwei);
    }

    // ======================================================================= defeat

    /// R3, spent from the successor a3, defeats the escape from a2; R2 (at a2 itself) does not.
    function test_realSuccessorRequestDefeatsAndStateRequestDoesNot() public {
        _depositAB();
        (Types.WithdrawalPublicInputs memory escape,) = _initiate("escape_a2");
        (Types.RequestPublicInputs memory r2, bytes memory r2Proof) = _request("request_a2");
        (Types.RequestPublicInputs memory r3, bytes memory r3Proof) = _request("request_a3");
        assertEq(r2.requestNullifier, escape.withdrawalNullifier);
        assertEq(r3.requestNullifier, escape.nextNullifier);
        vm.prank(OPERATOR);
        vm.expectRevert(Errors.NotSuccessorEvidence.selector);
        vault.challengeEscapeWithdrawal(0, r2, r2Proof);
        // A tampered successor statement does not verify.
        (Types.RequestPublicInputs memory forged,) = _request("request_a3");
        forged.solvencyBound += 1;
        vm.prank(OPERATOR);
        vm.expectRevert(Errors.InvalidProof.selector);
        vault.challengeEscapeWithdrawal(0, forged, r3Proof);

        vm.warp(_deadline(0) - 1);
        vm.prank(OPERATOR);
        vault.challengeEscapeWithdrawal(0, r3, r3Proof);
        assertEq(uint256(_status(0)), uint256(Types.NoteStatus.Active));
        assertTrue(vault.challengedNullifiers(escape.withdrawalNullifier));
        assertFalse(vault.usedNullifiers(escape.withdrawalNullifier));
        assertFalse(vault.usedNullifiers(escape.nextNullifier));
        assertEq(address(vault).balance, 2 * uint256(DEPOSIT) * 1 gwei);
        vm.warp(_deadline(0));
        vm.expectRevert(Errors.NotPendingWithdrawal.selector);
        vault.finalizeEscapeWithdrawal(0);
    }

    /// After the defeat: a2 again (to any destination) reverts ChallengedNullifier and a1
    /// SupersededState, cheaply; a0 is verified and recorded, and R1 defeats it. The operator's
    /// clearance still closes a2.
    function test_realReEscapesAfterADefeat() public {
        _depositAB();
        _initiate("escape_a2");
        _defeat("request_a3");
        _escapeReverts("escape_a2", Errors.ChallengedNullifier.selector);
        _escapeReverts("escape_a2_concede", Errors.ChallengedNullifier.selector);
        _escapeReverts("escape_a2_other_destination", Errors.ChallengedNullifier.selector);
        _escapeReverts("escape_a1", Errors.SupersededState.selector);

        _initiate("escape_a0");
        (Types.RequestPublicInputs memory r0, bytes memory r0Proof) = _request("request_a0");
        vm.prank(OPERATOR);
        vm.expectRevert(Errors.NotSuccessorEvidence.selector);
        vault.challengeEscapeWithdrawal(0, r0, r0Proof);
        _defeat("request_a1");
        _escapeReverts("escape_a0", Errors.ChallengedNullifier.selector);

        (Types.WithdrawalPublicInputs memory close, bytes memory closeProof) = _withdrawal("close_a2");
        vault.mutualClose(close, closeProof);
        assertEq(USER.balance, 8 * uint256(DEPOSIT) * 1 gwei + uint256(B2) * 1 gwei);
        assertEq(TREASURY.balance, uint256(DEPOSIT - B2) * 1 gwei);
    }

    // ========================================================== kinds and expiry

    function test_realOwnershipProofIsRejected() public {
        _depositAB();
        (Types.WithdrawalPublicInputs memory ownership, bytes memory proof) = _withdrawal("ownership_a2");
        adapter.assertValidWithdrawal(ownership, proof);
        vm.expectRevert(Errors.WrongWithdrawalKind.selector);
        vault.initiateEscapeWithdrawal(ownership, proof);
        vm.expectRevert(Errors.WrongWithdrawalKind.selector);
        vault.mutualClose(ownership, proof);
        // A close proof is not an escape, and an escape proof is not a close.
        _escapeReverts("close_a2", Errors.WrongWithdrawalKind.selector);
        (Types.WithdrawalPublicInputs memory escape, bytes memory escapeProof) = _withdrawal("escape_a2");
        vm.expectRevert(Errors.WrongWithdrawalKind.selector);
        vault.mutualClose(escape, escapeProof);
    }

    function test_realMutualCloses() public {
        _depositAB();
        (Types.WithdrawalPublicInputs memory closeA, bytes memory proofA) = _withdrawal("close_a2");
        (Types.WithdrawalPublicInputs memory closeB, bytes memory proofB) = _withdrawal("close_b0");
        uint256 root = vault.currentRoot();
        vault.mutualClose(closeA, proofA);
        vault.mutualClose(closeB, proofB);
        assertEq(USER.balance, 8 * uint256(DEPOSIT) * 1 gwei + uint256(B2 + DEPOSIT) * 1 gwei);
        assertEq(TREASURY.balance, uint256(DEPOSIT - B2) * 1 gwei);
        assertEq(vault.currentRoot(), root);
        assertEq(address(vault).balance, 0);
    }

    function test_realExpiredProofIsRejected() public {
        _depositAB();
        _escapeReverts("escape_a2_expired", Errors.ProofExpired.selector);
        (Types.WithdrawalPublicInputs memory escape, bytes memory proof) = _withdrawal("escape_a2");
        vm.warp(uint256(escape.validUntil) + 1);
        vm.expectRevert(Errors.ProofExpired.selector);
        vault.initiateEscapeWithdrawal(escape, proof);
        (Types.WithdrawalPublicInputs memory close, bytes memory closeProof) = _withdrawal("close_a2");
        vm.expectRevert(Errors.ProofExpired.selector);
        vault.mutualClose(close, closeProof);
        vm.warp(escape.validUntil);
        vault.initiateEscapeWithdrawal(escape, proof);
    }

    // ============================================================ genesis and notes

    /// A genesis escape may concede part of the deposit; B's own request (bound 100,000) cannot
    /// raise a 250,000 concession, and A's requests never touch B's escape.
    function test_realGenesisConcession() public {
        _depositAB();
        (Types.WithdrawalPublicInputs memory escape,) = _initiate("escape_b0_genesis_concede");
        assertEq(escape.noteFields >> 192, 1);
        assertEq(escape.conceded, 250_000);
        (Types.RequestPublicInputs memory rb, bytes memory rbProof) = _request("request_b0");
        assertEq(rb.requestNullifier, escape.withdrawalNullifier);
        vm.prank(OPERATOR);
        vm.expectRevert(Errors.NotARaise.selector);
        vault.raiseEscapeConcession(1, rb, rbProof, type(uint128).max);
        (Types.RequestPublicInputs memory ra1, bytes memory ra1Proof) = _request("request_a1");
        vm.prank(OPERATOR);
        vm.expectRevert(Errors.NotSuccessorEvidence.selector);
        vault.challengeEscapeWithdrawal(1, ra1, ra1Proof);
        vm.warp(_deadline(1));
        vault.finalizeEscapeWithdrawal(1);
        assertEq(USER.balance, 8 * uint256(DEPOSIT) * 1 gwei + 750_000 gwei);
        assertEq(TREASURY.balance, 250_000 gwei);
    }

    /// A and B share a secret, but their nullifiers are disjoint: a defeat of A's escape leaves
    /// B's escape pending, and B finalizes.
    function test_realSameSecretNotesAreIndependent() public {
        _depositAB();
        assertEq(
            vm.parseJsonBytes32(fixtures, ".note_a_registration"), vm.parseJsonBytes32(fixtures, ".note_b_registration")
        );
        (Types.RequestPublicInputs memory ra0,) = _request("request_a0");
        (Types.RequestPublicInputs memory rb0,) = _request("request_b0");
        assertNotEq(ra0.requestNullifier, rb0.requestNullifier);
        (Types.WithdrawalPublicInputs memory escapeA,) = _initiate("escape_a2");
        (Types.WithdrawalPublicInputs memory escapeB,) = _initiate("escape_b0_genesis_concede");
        assertNotEq(escapeA.nextNullifier, escapeB.nextNullifier);
        _defeat("request_a3");
        assertEq(uint256(_status(1)), uint256(Types.NoteStatus.PendingWithdrawal));
        vm.warp(_deadline(1));
        vault.finalizeEscapeWithdrawal(1);
        assertEq(uint256(_status(0)), uint256(Types.NoteStatus.Active));
        assertEq(uint256(_status(1)), uint256(Types.NoteStatus.Closed));
    }

    // ================================================= non-canonical public inputs

    /// Each field-element word of an escape and a close, written as value + r (the same scalar to
    /// the ecMul precompile), is refused. The nullifiers reach the real adapter, which must revert
    /// InvalidProof: the vault keys its nullifier bookkeeping on the raw words, so an escape naming
    /// N_{k+1} + r could not be defeated by the real successor request (NotSuccessorEvidence), and
    /// one naming N_k + r would slip past ChallengedNullifier after a defeat, or N_{k+1} + r past
    /// SupersededState. The leaf, the fields and the keys are refused by the vault's own checks
    /// first: leaf + r is not the stored leaf, and fields + r is above 2^224.
    function test_realWithdrawalsRefuseNonCanonicalFieldInputs() public {
        _depositAB();
        string[2] memory names = ["escape_a2", "close_a2"];
        for (uint256 n = 0; n < names.length; ++n) {
            _withdrawalWordReverts(names[n], 3, Errors.NoteLeafMismatch.selector);
            _withdrawalWordReverts(names[n], 8, Errors.InvalidNoteFields.selector);
            for (uint256 key = 4; key < 8; ++key) {
                _withdrawalWordReverts(names[n], key, Errors.InvalidDeploymentBinding.selector);
            }
            _withdrawalWordReverts(names[n], 11, Errors.InvalidProof.selector);
            _withdrawalWordReverts(names[n], 13, Errors.InvalidProof.selector);
        }
        assertEq(uint256(_status(0)), uint256(Types.NoteStatus.Active));

        // After R3 defeats the escape from a2, renaming a2's nullifier, or a1's successor
        // nullifier (a2's), does not get around ChallengedNullifier or SupersededState.
        _initiate("escape_a2");
        _defeat("request_a3");
        _withdrawalWordReverts("escape_a2", 11, Errors.InvalidProof.selector);
        _withdrawalWordReverts("escape_a1", 13, Errors.InvalidProof.selector);
        _escapeReverts("escape_a2", Errors.ChallengedNullifier.selector);
        _escapeReverts("escape_a1", Errors.SupersededState.selector);
        assertEq(uint256(_status(0)), uint256(Types.NoteStatus.Active));
    }

    /// Each field-element word of the defeat and raise evidence, written as value + r, is refused:
    /// the request nullifier by the vault's match against the stored canonical nullifiers, the keys
    /// by the binding check, and the root, tag and anonymous commitment by the real adapter.
    function test_realEvidenceRefusesNonCanonicalFieldInputs() public {
        _depositAB();
        _initiate("escape_a2");
        uint256[4] memory adapterChecked = [uint256(3), 9, 10, 11];
        for (uint256 i = 0; i < adapterChecked.length; ++i) {
            _evidenceWordReverts(false, "request_a3", adapterChecked[i], Errors.InvalidProof.selector);
            _evidenceWordReverts(true, "request_a2", adapterChecked[i], Errors.InvalidProof.selector);
        }
        for (uint256 key = 4; key < 6; ++key) {
            _evidenceWordReverts(false, "request_a3", key, Errors.InvalidDeploymentBinding.selector);
            _evidenceWordReverts(true, "request_a2", key, Errors.InvalidDeploymentBinding.selector);
        }
        _evidenceWordReverts(false, "request_a3", 8, Errors.NotSuccessorEvidence.selector);
        _evidenceWordReverts(true, "request_a2", 8, Errors.NotStateEvidence.selector);
        assertEq(_finalBalance(0), B2);
        _defeat("request_a3");
    }

    /// Initiates (or closes with) fixture `name` with ABI word `index` increased by r, as the user,
    /// expecting `err`.
    function _withdrawalWordReverts(string memory name, uint256 index, bytes4 err) private {
        bytes memory words = vm.parseJsonBytes(fixtures, string.concat(".", name, ".inputs_abi"));
        _addScalarModulus(words, index);
        Types.WithdrawalPublicInputs memory inputs = abi.decode(words, (Types.WithdrawalPublicInputs));
        bytes memory proof = vm.parseJsonBytes(fixtures, string.concat(".", name, ".proof_hex"));
        vm.prank(USER);
        vm.expectRevert(err);
        if (inputs.kind == 1) vault.mutualClose(inputs, proof);
        else vault.initiateEscapeWithdrawal(inputs, proof);
    }

    /// Defeats (or raises, to the request's bound) note 0's escape with fixture `name`, ABI word
    /// `index` increased by r, as the operator, expecting `err`.
    function _evidenceWordReverts(bool raise, string memory name, uint256 index, bytes4 err) private {
        bytes memory words = vm.parseJsonBytes(fixtures, string.concat(".", name, ".inputs_abi"));
        _addScalarModulus(words, index);
        Types.RequestPublicInputs memory inputs = abi.decode(words, (Types.RequestPublicInputs));
        bytes memory proof = vm.parseJsonBytes(fixtures, string.concat(".", name, ".proof_hex"));
        vm.prank(OPERATOR);
        vm.expectRevert(err);
        if (raise) vault.raiseEscapeConcession(0, inputs, proof, inputs.solvencyBound);
        else vault.challengeEscapeWithdrawal(0, inputs, proof);
    }

    function _addScalarModulus(bytes memory words, uint256 index) private pure {
        uint256 value = _word(words, index);
        require(value < SCALAR_MODULUS, "fixture word is not canonical");
        _setWord(words, index, value + SCALAR_MODULUS);
    }

    function _word(bytes memory words, uint256 index) private pure returns (uint256 value) {
        require(words.length >= 32 * (index + 1), "word index");
        assembly ("memory-safe") {
            value := mload(add(add(words, 0x20), mul(index, 0x20)))
        }
    }

    function _setWord(bytes memory words, uint256 index, uint256 value) private pure {
        require(words.length >= 32 * (index + 1), "word index");
        assembly ("memory-safe") {
            mstore(add(add(words, 0x20), mul(index, 0x20)), value)
        }
    }

    // ============================================== tampered withdrawal statements

    /// The vault relies on the withdrawal proof for every word of an escape or a close that it
    /// does not check itself. Each such word of escape_a2 and close_a2, changed to another
    /// canonical value that passes every check made before verification, reverts InvalidProof:
    /// the note's fields (its expiry +1, its deposit +1 and the note ID moved to B together with
    /// B's stored leaf), the payout, the destination, the nullifier, the successor nullifier, the
    /// concession and validUntil, each increased by one. A leaf that is not the stored one never
    /// reaches the adapter (NoteLeafMismatch). The note stays Active and neither nullifier is
    /// consumed. Without verification, each would pay out or record an escape; the fields would
    /// pay a deposit the note never had.
    function test_realWithdrawalsRefuseTamperedStatements() public {
        _depositAB();
        string[2] memory names = ["escape_a2", "close_a2"];
        // noteFields (expiry), finalBalance, destination, withdrawalNullifier, nextNullifier,
        // conceded, validUntil
        uint256[7] memory proofOnly = [uint256(8), 9, 10, 11, 13, 14, 15];
        (uint256 leafB,) = vault.noteRecord(1);
        for (uint256 n = 0; n < names.length; ++n) {
            bytes memory words = vm.parseJsonBytes(fixtures, string.concat(".", names[n], ".inputs_abi"));
            for (uint256 i = 0; i < proofOnly.length; ++i) {
                _tamperedWithdrawalReverts(names[n], proofOnly[i], _word(words, proofOnly[i]) + 1);
            }
            // The deposit one unit higher.
            _tamperedWithdrawalReverts(names[n], 8, _word(words, 8) + (1 << 64));
            // Another note's leaf and fields: both checks pass, the proof does not.
            bytes memory moved = vm.parseJsonBytes(fixtures, string.concat(".", names[n], ".inputs_abi"));
            _setWord(moved, 3, leafB);
            _setWord(moved, 8, _word(moved, 8) + (1 << 192));
            Types.WithdrawalPublicInputs memory inputs = abi.decode(moved, (Types.WithdrawalPublicInputs));
            bytes memory proof = vm.parseJsonBytes(fixtures, string.concat(".", names[n], ".proof_hex"));
            vm.prank(USER);
            vm.expectRevert(Errors.InvalidProof.selector);
            if (inputs.kind == 1) vault.mutualClose(inputs, proof);
            else vault.initiateEscapeWithdrawal(inputs, proof);
            // A's statement with B's leaf: the vault's own check.
            _withdrawalWordSet(names[n], 3, leafB, Errors.NoteLeafMismatch.selector);
        }
        (Types.WithdrawalPublicInputs memory escape,) = _withdrawal("escape_a2");
        for (uint32 id = 0; id < 2; ++id) {
            assertEq(uint256(_status(id)), uint256(Types.NoteStatus.Active));
        }
        assertFalse(vault.usedNullifiers(escape.withdrawalNullifier));
        assertFalse(vault.usedNullifiers(escape.nextNullifier));
        assertFalse(vault.usedNullifiers(escape.withdrawalNullifier + 1));
        assertFalse(vault.usedNullifiers(escape.nextNullifier + 1));
        assertEq(address(vault).balance, 2 * uint256(DEPOSIT) * 1 gwei);
        // The untampered statements go through.
        _initiate("escape_a2");
    }

    /// Submits fixture `name` (an escape or a close, by its kind) with ABI word `index` set to the
    /// canonical `value`, as the user, expecting InvalidProof.
    function _tamperedWithdrawalReverts(string memory name, uint256 index, uint256 value) private {
        bytes memory words = vm.parseJsonBytes(fixtures, string.concat(".", name, ".inputs_abi"));
        require(value < SCALAR_MODULUS && value != _word(words, index), "not a canonical change");
        _setWord(words, index, value);
        Types.WithdrawalPublicInputs memory inputs = abi.decode(words, (Types.WithdrawalPublicInputs));
        bytes memory proof = vm.parseJsonBytes(fixtures, string.concat(".", name, ".proof_hex"));
        vm.prank(USER);
        vm.expectRevert(Errors.InvalidProof.selector);
        if (inputs.kind == 1) vault.mutualClose(inputs, proof);
        else vault.initiateEscapeWithdrawal(inputs, proof);
    }

    /// Submits fixture `name` with ABI word `index` set to `value`, expecting `err`.
    function _withdrawalWordSet(string memory name, uint256 index, uint256 value, bytes4 err) private {
        bytes memory words = vm.parseJsonBytes(fixtures, string.concat(".", name, ".inputs_abi"));
        _setWord(words, index, value);
        Types.WithdrawalPublicInputs memory inputs = abi.decode(words, (Types.WithdrawalPublicInputs));
        bytes memory proof = vm.parseJsonBytes(fixtures, string.concat(".", name, ".proof_hex"));
        vm.prank(USER);
        vm.expectRevert(err);
        if (inputs.kind == 1) vault.mutualClose(inputs, proof);
        else vault.initiateEscapeWithdrawal(inputs, proof);
    }

    // ========================================= closed notes stay closed (Amendment A3)

    /// A closed note's leaf stays in its word until it is retired, and an exit proof needs nothing
    /// else, so the Active check is the only barrier to a second payout. After close_a2, and after
    /// a finalized escape_a2, every exit proof of A reverts NoteNotActive, before and after A's
    /// leaf is retired: escapes from the older states a0 and a1 (a0's nullifiers are unconsumed),
    /// from a2, and close_a2.
    function test_realClosedNoteNeverExitsAgain() public {
        for (uint256 route = 0; route < 2; ++route) {
            uint256 snapshot = vm.snapshotState();
            _depositAB();
            if (route == 0) {
                (Types.WithdrawalPublicInputs memory close, bytes memory closeProof) = _withdrawal("close_a2");
                vault.mutualClose(close, closeProof);
            } else {
                _initiate("escape_a2");
                vm.warp(_deadline(0));
                vault.finalizeEscapeWithdrawal(0);
            }
            assertEq(uint256(_status(0)), uint256(Types.NoteStatus.Closed));
            uint256 held = address(vault).balance;
            _assertRealNeverExitsAgain();
            _retire(0);
            _assertRealNeverExitsAgain();
            assertEq(uint256(_status(0)), uint256(Types.NoteStatus.Closed));
            assertEq(address(vault).balance, held);
            (Types.WithdrawalPublicInputs memory a0,) = _withdrawal("escape_a0");
            assertFalse(vault.usedNullifiers(a0.withdrawalNullifier));
            assertFalse(vault.usedNullifiers(a0.nextNullifier));
            vm.revertToState(snapshot);
        }
    }

    function _assertRealNeverExitsAgain() private {
        string[5] memory names = ["escape_a0", "escape_a1", "escape_a2", "escape_a2_concede", "close_a2"];
        for (uint256 i = 0; i < names.length; ++i) {
            (Types.WithdrawalPublicInputs memory inputs, bytes memory proof) = _withdrawal(names[i]);
            vm.prank(USER);
            vm.expectRevert(Errors.NoteNotActive.selector);
            if (inputs.kind == 1) vault.mutualClose(inputs, proof);
            else vault.initiateEscapeWithdrawal(inputs, proof);
        }
    }

    // ============================================== leaf-bound exits (Amendment A3)

    /// A's escape and B's close need no root: they land after other deposits, a close, a
    /// retirement and two days, with the statements proven before any of it. The events carry no
    /// root.
    function test_realExitsAfterDepositsAndARetirement() public {
        _depositAB();
        _depositOther(2, 0x1234);
        _depositOther(3, 0x5678);
        (Types.WithdrawalPublicInputs memory closeB, bytes memory closeProof) = _withdrawal("close_b0");
        vault.mutualClose(closeB, closeProof);
        _retire(1);
        _depositOther(4, 0x9abc);
        vm.warp(vm.getBlockTimestamp() + 2 days);

        (Types.WithdrawalPublicInputs memory escape,) = _withdrawal("escape_a2");
        vm.expectEmit(address(vault));
        emit Events.EscapeWithdrawalInitiated(
            0,
            escape.withdrawalNullifier,
            escape.finalBalance,
            escape.destination,
            uint64(vm.getBlockTimestamp()) + vault.challengePeriod()
        );
        _initiate("escape_a2");
        (bool pending, uint256 pendingRoot,,,,) = vault.pendingWithdrawals(0);
        assertTrue(pending);
        assertEq(pendingRoot, 0, "no root is stored");
        _depositOther(5, 0xdef0);
        vm.expectEmit(address(vault));
        emit Events.EscapeWithdrawalChallenged(0, escape.withdrawalNullifier);
        _defeat("request_a3");
        assertEq(USER.balance, 4 * uint256(DEPOSIT) * 1 gwei + uint256(DEPOSIT) * 1 gwei);
    }

    /// The leaf binding with real proofs: valid proofs of genesis escapes for note B's ID and
    /// secret over another deposit (2,000,000, twice B's) or another expiry are self-consistent
    /// statements the adapter accepts, and only the vault's stored leaf refuses them. Without that
    /// check the forged deposit would pay out twice B's deposit.
    function test_realForgedDepositOrExpiryIsRefusedByTheStoredLeaf() public {
        _depositAB();
        string[2] memory forged = ["escape_b0_forged_deposit", "escape_b0_forged_expiry"];
        for (uint256 i = 0; i < forged.length; ++i) {
            (Types.WithdrawalPublicInputs memory inputs, bytes memory proof) = _withdrawal(forged[i]);
            assertEq(inputs.noteFields >> 192, 1);
            adapter.assertValidWithdrawal(inputs, proof);
            _escapeReverts(forged[i], Errors.NoteLeafMismatch.selector);
        }
        (Types.WithdrawalPublicInputs memory deposit,) = _withdrawal("escape_b0_forged_deposit");
        assertEq(uint128(deposit.noteFields >> 64), 2 * DEPOSIT);
        assertEq(deposit.finalBalance, 2 * DEPOSIT);
        assertEq(uint256(_status(1)), uint256(Types.NoteStatus.Active));
        assertEq(address(vault).balance, 2 * uint256(DEPOSIT) * 1 gwei);
        // B's honest escape still goes through.
        _initiate("escape_b0_genesis_concede");
    }

    // ================================================================ gas snapshot

    /// Transaction gas (21,000 + calldata + execution with cold vault and adapter, refunds
    /// ignored) of each exit entry point with real proofs, under the design's ceilings, and
    /// pinned in snapshots/concession-exit-gas.json (checked in CI with FORGE_SNAPSHOT_CHECK).
    function test_realExitGasSnapshot() public {
        _depositAB();
        uint256 snapshot = vm.snapshotState();

        (Types.WithdrawalPublicInputs memory escape, bytes memory escapeProof) = _withdrawal("escape_a2");
        uint256 escapeGas =
            _txGas(abi.encodeCall(vault.initiateEscapeWithdrawal, (escape, escapeProof)), "initiateEscapeWithdrawal");
        (Types.RequestPublicInputs memory r2, bytes memory r2Proof) = _request("request_a2");
        uint256 raiseGas =
            _txGas(abi.encodeCall(vault.raiseEscapeConcession, (0, r2, r2Proof, SB2)), "raiseEscapeConcession");
        (Types.RequestPublicInputs memory r3, bytes memory r3Proof) = _request("request_a3");
        uint256 defeatGas =
            _txGas(abi.encodeCall(vault.challengeEscapeWithdrawal, (0, r3, r3Proof)), "challengeEscapeWithdrawal");
        vm.revertToState(snapshot);

        _initiate("escape_a2");
        vm.warp(_deadline(0));
        uint256 finalizeGas = _txGas(abi.encodeCall(vault.finalizeEscapeWithdrawal, (0)), "finalizeEscapeWithdrawal");
        vm.revertToState(snapshot);

        (Types.WithdrawalPublicInputs memory close, bytes memory closeProof) = _withdrawal("close_a2");
        uint256 closeGas = _txGas(abi.encodeCall(vault.mutualClose, (close, closeProof)), "mutualClose");
        vm.revertToState(snapshot);

        bytes32 registration = vm.parseJsonBytes32(fixtures, ".note_a_registration");
        // casting to 'uint64' is safe because the fixture's expiry is a bucketed uint64 time
        // forge-lint: disable-next-line(unsafe-typecast)
        uint64 expiry = uint64(vm.parseJsonUint(fixtures, ".expiry"));
        vm.warp(vault.effectiveExpiry(0, registration, DEPOSIT, expiry));
        uint256 claimGas =
            _txGas(abi.encodeCall(vault.claimExpired, (0, registration, DEPOSIT, expiry)), "claimExpired");

        assertLe(escapeGas, 700_000, "escape");
        assertLe(defeatGas, 500_000, "defeat");
        assertLe(raiseGas, 400_000, "raise");
        assertLe(closeGas, 550_000, "close");
        assertLe(claimGas, 200_000, "claim");
        assertLe(finalizeGas, 250_000, "finalize");
        vm.snapshotValue("concession-exit-gas", "initiateEscapeWithdrawal", escapeGas);
        vm.snapshotValue("concession-exit-gas", "challengeEscapeWithdrawal", defeatGas);
        vm.snapshotValue("concession-exit-gas", "raiseEscapeConcession", raiseGas);
        vm.snapshotValue("concession-exit-gas", "mutualClose", closeGas);
        vm.snapshotValue("concession-exit-gas", "finalizeEscapeWithdrawal", finalizeGas);
        vm.snapshotValue("concession-exit-gas", "claimExpired", claimGas);
    }

    /// Runs `data` against the vault (it must succeed) and returns its transaction gas.
    function _txGas(bytes memory data, string memory label) private returns (uint256 txGas) {
        vm.cool(address(vault));
        vm.cool(address(adapter));
        vm.prank(OPERATOR);
        (bool ok,) = address(vault).call(data);
        assertTrue(ok, label);
        uint256 execution = vm.lastCallGas().gasTotalUsed;
        uint256 calldataGas;
        for (uint256 i = 0; i < data.length; ++i) {
            calldataGas += data[i] == 0 ? 4 : 16;
        }
        txGas = 21_000 + calldataGas + execution;
        emit log_named_uint(string.concat(label, " calldata bytes"), data.length);
        emit log_named_uint(string.concat(label, " transaction gas"), txGas);
    }

    // ===================================================================== helpers

    function _depositA() private {
        bytes32 registration = vm.parseJsonBytes32(fixtures, ".note_a_registration");
        vm.prank(USER);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(registration, DEPOSIT);
        assertEq(_leafOf(0), vm.parseJsonUint(fixtures, ".note_a_leaf"));
    }

    function _depositB() private {
        bytes32 registration = vm.parseJsonBytes32(fixtures, ".note_b_registration");
        vm.prank(USER);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(registration, DEPOSIT);
        assertEq(_leafOf(1), vm.parseJsonUint(fixtures, ".note_b_leaf"));
    }

    function _depositAB() private {
        _depositA();
        _depositB();
        assertEq(vault.currentRoot(), vm.parseJsonUint(fixtures, ".root_ab"));
    }

    function _depositOther(uint32 expectedId, uint256 commitment) private {
        assertEq(vault.nextNoteId(), expectedId);
        vm.prank(USER);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(commitment), DEPOSIT);
    }

    function _retire(uint32 noteId) private {
        uint256[32] memory path = _path(noteId);
        vm.prank(OPERATOR);
        vault.retireClosedLeaf(noteId, path);
        retired[noteId] = true;
    }

    /// The vault's stored leaf (zero once retired).
    function _leafOf(uint32 noteId) private view returns (uint256 leaf) {
        (leaf,) = vault.noteRecord(noteId);
    }

    function _treeLeaf(uint32 index) private view returns (uint256) {
        if (index >= vault.nextNoteId() || retired[index]) return 0;
        return _leafOf(index);
    }

    /// Live-tree siblings for slots 0..3; later slots are empty.
    function _path(uint32 index) private view returns (uint256[32] memory siblings) {
        require(index < 4, "test tree");
        siblings = emptySiblings;
        siblings[0] = _treeLeaf(index ^ 1);
        uint32 pair = (index >> 1) ^ 1;
        siblings[1] = Bn254PoseidonReference.compress(DOMAIN_NODE, _treeLeaf(pair * 2), _treeLeaf(pair * 2 + 1));
    }

    function _initiate(string memory name) private returns (Types.WithdrawalPublicInputs memory, bytes memory) {
        (Types.WithdrawalPublicInputs memory inputs, bytes memory proof) = _withdrawal(name);
        vm.prank(USER);
        vault.initiateEscapeWithdrawal(inputs, proof);
        // casting to 'uint32' is safe because the fixtures' fields are below 2^224
        // forge-lint: disable-next-line(unsafe-typecast)
        assertEq(uint256(_status(uint32(inputs.noteFields >> 192))), uint256(Types.NoteStatus.PendingWithdrawal));
        assertTrue(vault.usedNullifiers(inputs.withdrawalNullifier));
        assertTrue(vault.usedNullifiers(inputs.nextNullifier));
        return (inputs, proof);
    }

    function _escapeReverts(string memory name, bytes4 err) private {
        (Types.WithdrawalPublicInputs memory inputs, bytes memory proof) = _withdrawal(name);
        vm.prank(USER);
        vm.expectRevert(err);
        vault.initiateEscapeWithdrawal(inputs, proof);
    }

    function _defeat(string memory name) private {
        (Types.RequestPublicInputs memory request, bytes memory proof) = _request(name);
        vm.prank(OPERATOR);
        vault.challengeEscapeWithdrawal(0, request, proof);
        assertEq(uint256(_status(0)), uint256(Types.NoteStatus.Active));
    }

    function _status(uint32 noteId) private view returns (Types.NoteStatus status) {
        (, status) = vault.noteRecord(noteId);
    }

    function _deadline(uint32 noteId) private view returns (uint64 deadline) {
        (,,,,, deadline) = vault.pendingWithdrawals(noteId);
    }

    function _finalBalance(uint32 noteId) private view returns (uint128 finalBalance) {
        (,,, finalBalance,,) = vault.pendingWithdrawals(noteId);
    }

    function _request(string memory name) private view returns (Types.RequestPublicInputs memory, bytes memory) {
        return (
            abi.decode(
                vm.parseJsonBytes(fixtures, string.concat(".", name, ".inputs_abi")), (Types.RequestPublicInputs)
            ),
            vm.parseJsonBytes(fixtures, string.concat(".", name, ".proof_hex"))
        );
    }

    function _withdrawal(string memory name) private view returns (Types.WithdrawalPublicInputs memory, bytes memory) {
        return (
            abi.decode(
                vm.parseJsonBytes(fixtures, string.concat(".", name, ".inputs_abi")), (Types.WithdrawalPublicInputs)
            ),
            vm.parseJsonBytes(fixtures, string.concat(".", name, ".proof_hex"))
        );
    }
}
