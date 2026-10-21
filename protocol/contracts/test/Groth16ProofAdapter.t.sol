// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Groth16ProofAdapter} from "../src/adapters/Groth16ProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";

/// @dev Real proofs from zkapi-proof/examples/solidity_fixture.rs (test/fixtures/solidity-fixture.json),
///      proved with the shipping CircomReduction prover against the committed setup, verified by
///      the generated adapter. Regenerate with
///        cargo run --release -p zkapi-proof --example solidity_fixture -- ../setup/v2-concession-dev \
///          > ../contracts/test/fixtures/solidity-fixture.json
contract Groth16ProofAdapterTest is Test {
    string constant CIRCUIT_ID = "zkapi-v2-concession-v1";

    Groth16ProofAdapter adapter;
    string fixtures;

    function setUp() public {
        adapter = new Groth16ProofAdapter();
        fixtures = vm.readFile("test/fixtures/solidity-fixture.json");
        assertEq(vm.parseJsonString(fixtures, ".circuit_id"), CIRCUIT_ID);
    }

    /// The identity constants equal the committed setup's manifest.json: the circuit ID hash and
    /// the keccak256 of each verifying key without its header. ZKAPI_SETUP_DIR selects the setup
    /// as WP-A's proof tests read it (absolute, or relative to protocol/rust, where the setup
    /// READMEs run their commands: ZKAPI_SETUP_DIR=../setup/v2-concession); the default is the
    /// development setup. The directory must lie under protocol/setup (fs_permissions).
    function test_identityConstantsEqualTheSetupManifest() public view {
        string memory manifest = _readSetupManifest(setupDir());
        assertEq(vm.parseJsonString(manifest, ".circuit_id"), CIRCUIT_ID);
        assertEq(vm.parseJsonString(manifest, ".setup_id"), vm.parseJsonString(fixtures, ".setup_id"));
        assertEq(adapter.CIRCUIT_ID_HASH(), keccak256(bytes(CIRCUIT_ID)));
        assertEq(adapter.CIRCUIT_ID_HASH(), 0xf464f910d858a070b2f88db1049aab19d8fabeed1e527920be90dc0c950b0687);
        assertEq(adapter.REQUEST_VK_HASH(), vm.parseJsonBytes32(manifest, ".vk_keccak256.request"));
        assertEq(adapter.WITHDRAWAL_VK_HASH(), vm.parseJsonBytes32(manifest, ".vk_keccak256.withdrawal"));
        assertEq(vm.parseJsonUint(manifest, ".circuits.request.public_inputs"), 12);
        assertEq(vm.parseJsonUint(manifest, ".circuits.withdrawal.public_inputs"), 16);
    }

    function test_verifiesRustRequestProofs() public view {
        string[2] memory names = ["request", "request_signed"];
        for (uint256 i = 0; i < names.length; ++i) {
            (Types.RequestPublicInputs memory inputs, bytes memory proof) = _request(names[i]);
            adapter.assertValidRequest(inputs, proof);
        }
    }

    /// Escapes with c = 0 and c > 0 (signed and genesis), a close, an ownership proof and an
    /// escape to a full 160-bit destination.
    function test_verifiesRustWithdrawalProofsOfEveryKind() public view {
        string[6] memory names =
            ["withdrawal", "escape_c0", "escape_genesis_concession", "close", "ownership", "escape_full_destination"];
        for (uint256 i = 0; i < names.length; ++i) {
            (Types.WithdrawalPublicInputs memory inputs, bytes memory proof) = _withdrawal(names[i]);
            adapter.assertValidWithdrawal(inputs, proof);
        }
        (Types.WithdrawalPublicInputs memory concession,) = _withdrawal("withdrawal");
        assertEq(concession.kind, 0);
        assertGt(concession.conceded, 0);
        assertNotEq(concession.nextNullifier, 0);
        (Types.WithdrawalPublicInputs memory ownership,) = _withdrawal("ownership");
        assertEq(ownership.kind, 2);
        assertEq(ownership.destination, address(0));
        assertEq(ownership.nextNullifier, 0);
        (Types.WithdrawalPublicInputs memory full,) = _withdrawal("escape_full_destination");
        assertEq(full.destination, address(type(uint160).max));
    }

    /// The escape's successor nullifier is the nullifier of the request from the signed
    /// successor state (the fixture's s1 follows s0's request).
    function test_escapeNamesTheSuccessorsRequestNullifier() public view {
        (Types.RequestPublicInputs memory genesisRequest,) = _request("request");
        (Types.RequestPublicInputs memory successorRequest,) = _request("request_signed");
        (Types.WithdrawalPublicInputs memory escape,) = _withdrawal("escape_c0");
        assertEq(escape.withdrawalNullifier, successorRequest.requestNullifier);
        assertNotEq(escape.withdrawalNullifier, genesisRequest.requestNullifier);
        (Types.WithdrawalPublicInputs memory genesisEscape,) = _withdrawal("escape_genesis_concession");
        assertEq(genesisEscape.withdrawalNullifier, genesisRequest.requestNullifier);
        assertEq(genesisEscape.nextNullifier, successorRequest.requestNullifier);
    }

    function test_rejectsTamperedRequestInput() public {
        (Types.RequestPublicInputs memory inputs, bytes memory proof) = _request("request");
        inputs.solvencyBound += 1;
        vm.expectRevert(Errors.InvalidProof.selector);
        adapter.assertValidRequest(inputs, proof);
    }

    function test_rejectsTamperedWithdrawalInputs() public {
        (Types.WithdrawalPublicInputs memory inputs, bytes memory proof) = _withdrawal("withdrawal");
        // Shifting value from the payout to the concession keeps finalBalance + conceded.
        inputs.finalBalance += 1;
        inputs.conceded -= 1;
        vm.expectRevert(Errors.InvalidProof.selector);
        adapter.assertValidWithdrawal(inputs, proof);
        (inputs, proof) = _withdrawal("ownership");
        inputs.kind = 1;
        vm.expectRevert(Errors.InvalidProof.selector);
        adapter.assertValidWithdrawal(inputs, proof);
        (inputs, proof) = _withdrawal("escape_c0");
        inputs.validUntil += 1;
        vm.expectRevert(Errors.InvalidProof.selector);
        adapter.assertValidWithdrawal(inputs, proof);
    }

    function test_rejectsMalformedProofs() public {
        (Types.WithdrawalPublicInputs memory inputs, bytes memory proof) = _withdrawal("close");
        vm.expectRevert(Errors.InvalidProof.selector);
        adapter.assertValidWithdrawal(inputs, bytes.concat(proof, hex"00"));
        vm.expectRevert(Errors.InvalidProof.selector);
        adapter.assertValidWithdrawal(inputs, new bytes(256));
        bytes memory outOfField = proof;
        for (uint256 i = 0; i < 32; ++i) {
            outOfField[i] = 0xff;
        }
        vm.expectRevert(Errors.InvalidProof.selector);
        adapter.assertValidWithdrawal(inputs, outOfField);
    }

    /// ZKAPI_SETUP_DIR resolved by setupPath.
    function setupDir() public view returns (string memory) {
        return setupPath(vm.envOr("ZKAPI_SETUP_DIR", string("")));
    }

    function _readSetupManifest(string memory dir) private view returns (string memory) {
        string memory path = string.concat(dir, "/manifest.json");
        try vm.readFile(path) returns (string memory manifest) {
            return manifest;
        } catch {
            revert(
                string.concat(
                    "cannot read ",
                    path,
                    ": ZKAPI_SETUP_DIR is absolute or relative to protocol/rust (../setup/<name>), under protocol/setup"
                )
            );
        }
    }

    /// A setup directory named as zkapi-proof's tests/common/mod.rs reads ZKAPI_SETUP_DIR: an
    /// absolute path as is, a relative one against protocol/rust (a sibling of this project, so
    /// ../setup/... names the same directory from either); empty, the development setup.
    function setupPath(string memory dir) public view returns (string memory) {
        if (bytes(dir).length == 0) return string.concat(vm.projectRoot(), "/../setup/v2-concession-dev");
        if (bytes(dir)[0] == "/") return dir;
        return string.concat(vm.projectRoot(), "/../rust/", dir);
    }

    /// The path rules, for the forms WP-A's runbooks use and the absolute form CI uses; each reads
    /// the same manifest.
    function test_setupPathFollowsTheProofTestsPathRules() public view {
        string memory root = vm.projectRoot();
        string memory dev = string.concat(root, "/../setup/v2-concession-dev");
        string memory expected = vm.readFile(string.concat(dev, "/manifest.json"));
        assertEq(setupPath(""), dev);
        assertEq(setupPath(dev), dev);
        assertEq(setupPath("../setup/v2-concession-dev"), string.concat(root, "/../rust/../setup/v2-concession-dev"));
        assertEq(setupPath("../setup/v2-concession"), string.concat(root, "/../rust/../setup/v2-concession"));
        assertEq(vm.readFile(string.concat(setupPath("../setup/v2-concession-dev"), "/manifest.json")), expected);
        assertEq(vm.readFile(string.concat(setupPath(dev), "/manifest.json")), expected);
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
