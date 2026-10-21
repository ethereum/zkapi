// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test, console} from "forge-std/Test.sol";
import {ZkApiVault} from "../src/ZkApiVault.sol";
import {Groth16ProofAdapter} from "../src/adapters/Groth16ProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Bn254Poseidon} from "../src/libraries/Bn254Poseidon.sol";
import {NoteLeafLib} from "../src/libraries/NoteLeafLib.sol";

/// @dev The shared withdrawal golden vector (design §11 WP-F): a real kind-0 escape and a real
///      kind-1 close (vault-challenge.json's escape_a2_concede and close_b0) with their exact
///      calldata, and the deposits and deployment they land on. The Rust (zkapi-serverd watcher,
///      zkapi-companion chain), JS (sdk/wallet.js) and Go (zkapi-clientd) encoders assert byte
///      equality with test/fixtures/withdrawal-golden.json, and scripts/check-withdrawal-golden.mjs
///      submits each encoder's output to a vault on Anvil. This test pins the JSON to Solidity's
///      abi.encodeCall against the real vault, and lands every call on a normally deployed vault.
///      Regenerate the JSON with: node scripts/check-withdrawal-golden.mjs --update
///      (ZKAPI_PRINT_WITHDRAWAL_GOLDEN=1 makes this test print it instead of checking it).
contract WithdrawalGoldenTest is Test {
    uint256 constant DOMAIN_NODE = 0x7a6b6170692e76322e6e6f6465;
    uint128 constant DEPOSIT = 1_000_000;
    address constant DEPLOYER = address(0xf00d);
    address constant USER = 0x1111111111111111111111111111111111111111;
    address constant TREASURY = address(0xbeef);
    address constant OWNER = address(0x0D0D);
    uint64 constant NOTE_TTL = 30 days;
    uint64 constant CHALLENGE_PERIOD = 24 hours;
    uint128 constant REQUEST_CHARGE_CAP = 100_000;
    uint64 constant MAX_PAUSE_DURATION = 7 days;
    string constant ESCAPE = "escape_a2_concede";
    string constant CLOSE = "close_b0";

    Groth16ProofAdapter adapter;
    ZkApiVault vault;
    string fixtures;
    string golden;
    bool printing;
    uint256[32] emptySiblings;

    function setUp() public {
        vm.chainId(31_337);
        fixtures = vm.readFile("test/fixtures/vault-challenge.json");
        printing = vm.envOr("ZKAPI_PRINT_WITHDRAWAL_GOLDEN", false);
        if (!printing) golden = vm.readFile("test/fixtures/withdrawal-golden.json");
        vm.warp(vm.parseJsonUint(fixtures, ".timestamp"));
        uint256 zero;
        for (uint256 level = 0; level < 32; ++level) {
            emptySiblings[level] = zero;
            zero = Bn254Poseidon.compress(DOMAIN_NODE, zero, zero);
        }
        adapter = new Groth16ProofAdapter();
        (Types.WithdrawalPublicInputs memory escape,) = _withdrawal(ESCAPE);
        vm.setNonce(DEPLOYER, 0);
        vm.prank(DEPLOYER);
        vault = new ZkApiVault(
            TREASURY,
            NOTE_TTL,
            CHALLENGE_PERIOD,
            REQUEST_CHARGE_CAP,
            address(adapter),
            escape.stateSigningKeyX,
            escape.stateSigningKeyY,
            escape.clearanceSigningKeyX,
            escape.clearanceSigningKeyY,
            OWNER,
            MAX_PAUSE_DURATION
        );
        assertEq(address(vault), escape.contractAddress);
        vm.deal(USER, 10 * uint256(DEPOSIT) * 1 gwei);
    }

    /// The golden calldata is Solidity's encoding of the proven statements against the real vault,
    /// and every golden call lands: two deposits, the escape (conceding 100,000) and the close.
    function test_goldenWithdrawalCalldataLandsOnTheVault() public {
        (Types.WithdrawalPublicInputs memory escape, bytes memory escapeProof) = _withdrawal(ESCAPE);
        (Types.WithdrawalPublicInputs memory close, bytes memory closeProof) = _withdrawal(CLOSE);
        assertEq(escape.kind, 0);
        assertEq(escape.conceded, 100_000);
        assertEq(close.kind, 1);
        bytes memory escapeCalldata = abi.encodeCall(ZkApiVault.initiateEscapeWithdrawal, (escape, escapeProof));
        bytes memory closeCalldata = abi.encodeCall(ZkApiVault.mutualClose, (close, closeProof));
        assertEq(escapeCalldata.length, 836);
        assertEq(closeCalldata.length, 836);

        bytes memory depositA =
            abi.encodeCall(ZkApiVault.deposit, (vm.parseJsonBytes32(fixtures, ".note_a_registration"), DEPOSIT));
        _call(depositA, uint256(DEPOSIT) * 1 gwei);
        bytes memory depositB =
            abi.encodeCall(ZkApiVault.deposit, (vm.parseJsonBytes32(fixtures, ".note_b_registration"), DEPOSIT));
        _call(depositB, uint256(DEPOSIT) * 1 gwei);
        assertEq(vault.currentRoot(), vm.parseJsonUint(fixtures, ".root_ab"));
        assertEq(vault.currentRoot(), escape.activeRoot);

        if (printing) {
            _print("deposit_a", depositA);
            _print("deposit_b", depositB);
            _print("escape", escapeCalldata);
            _print("close", closeCalldata);
            console.log(string.concat("active_root=", vm.toString(bytes32(vault.currentRoot()))));
        } else {
            assertEq(vm.parseJsonBytes(golden, ".deposits[0].calldata"), depositA, "deposit A");
            assertEq(vm.parseJsonBytes(golden, ".deposits[1].calldata"), depositB, "deposit B");
            assertEq(vm.parseJsonBytes(golden, ".escape.calldata"), escapeCalldata, "escape");
            assertEq(vm.parseJsonBytes(golden, ".close.calldata"), closeCalldata, "close");
            assertEq(vm.parseJsonBytes(golden, ".escape.proof_hex"), escapeProof, "escape proof");
            assertEq(vm.parseJsonBytes(golden, ".close.proof_hex"), closeProof, "close proof");
            assertEq(vm.parseJsonUint(golden, ".active_root"), vault.currentRoot(), "root");
            assertEq(vm.parseJsonAddress(golden, ".deployment.vault"), address(vault), "vault");
        }

        uint256 destinationBefore = USER.balance;
        _call(escapeCalldata, 0);
        assertEq(uint256(_status(0)), uint256(Types.NoteStatus.PendingWithdrawal));
        (uint256 nextNullifier, uint128 stateBalance, uint128 conceded) = vault.pendingConcessions(0);
        assertEq(nextNullifier, escape.nextNullifier);
        assertEq(stateBalance, escape.finalBalance + escape.conceded);
        assertEq(conceded, 100_000);
        _call(closeCalldata, 0);
        assertEq(uint256(_status(1)), uint256(Types.NoteStatus.Closed));
        assertEq(USER.balance - destinationBefore, uint256(close.finalBalance) * 1 gwei);
    }

    function _call(bytes memory data, uint256 value) private {
        vm.prank(USER);
        (bool ok, bytes memory reason) = address(vault).call{value: value}(data);
        if (!ok) {
            assembly {
                revert(add(reason, 32), mload(reason))
            }
        }
    }

    function _print(string memory name, bytes memory data) private pure {
        console.log(string.concat(name, "=", vm.toString(data)));
    }

    function _status(uint32 noteId) private view returns (Types.NoteStatus status) {
        (,,, status) = vault.notes(noteId);
    }

    function _leafOf(uint32 noteId) private view returns (uint256) {
        if (noteId >= vault.nextNoteId()) return 0;
        (bytes32 commitment, uint128 amount, uint64 expiry,) = vault.notes(noteId);
        return NoteLeafLib.computeLeaf(noteId, commitment, amount, expiry);
    }

    /// Siblings of slot `index` (0 or 1) in a tree holding only notes 0 and 1.
    function _path(uint32 index) private view returns (uint256[32] memory siblings) {
        require(index < 2, "golden tree");
        siblings = emptySiblings;
        siblings[0] = _leafOf(index ^ 1);
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
