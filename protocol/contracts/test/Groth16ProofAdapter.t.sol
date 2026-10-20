// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {Groth16ProofAdapter} from "../src/adapters/Groth16ProofAdapter.sol";
import {IZkApiProofAdapter} from "../src/interfaces/IZkApiProofAdapter.sol";
import {Types} from "../src/libraries/Types.sol";
import {Errors} from "../src/libraries/Errors.sol";

/// @dev verifyWithdrawalOnce and assertValidWithdrawal in one call tree, as the paymaster's
///      validation and the vault's execution run in one transaction; returns the gas of the
///      second call.
contract VerifyOnceCaller {
    function verifyThenAssert(
        IZkApiProofAdapter adapter,
        Types.WithdrawalPublicInputs calldata verified,
        bytes calldata verifiedProof,
        Types.WithdrawalPublicInputs calldata asserted,
        bytes calldata assertedProof
    ) external returns (uint256 gasUsed) {
        adapter.verifyWithdrawalOnce(verified, verifiedProof);
        uint256 g0 = gasleft();
        adapter.assertValidWithdrawal(asserted, assertedProof);
        gasUsed = g0 - gasleft();
    }

    /// verifyWithdrawalOnce, then the same statement through assertValidWithdrawal (expected to
    /// revert InvalidProof() unless the bytes are the verified ones).
    function verifyThenTry(
        IZkApiProofAdapter adapter,
        Types.WithdrawalPublicInputs calldata verified,
        bytes calldata verifiedProof,
        Types.WithdrawalPublicInputs calldata asserted,
        bytes calldata assertedProof
    ) external returns (bool ok, bytes memory reason) {
        adapter.verifyWithdrawalOnce(verified, verifiedProof);
        (ok, reason) = address(adapter)
            .staticcall(abi.encodeCall(IZkApiProofAdapter.assertValidWithdrawal, (asserted, assertedProof)));
    }

    /// verifyWithdrawalOnce, then assertValidWithdrawal as raw calldata (`assertCall`, whose words
    /// need not decode), with at most `gasCap`: a failing precompile burns what it is given.
    function verifyThenTryRaw(
        IZkApiProofAdapter adapter,
        Types.WithdrawalPublicInputs calldata verified,
        bytes calldata verifiedProof,
        bytes calldata assertCall,
        uint256 gasCap
    ) external returns (bool ok) {
        adapter.verifyWithdrawalOnce(verified, verifiedProof);
        (ok,) = address(adapter).staticcall{gas: gasCap}(assertCall);
    }
}

/// @dev Real proofs from zkapi-proof/examples/solidity_fixture.rs (test/fixtures/solidity-fixture.json),
///      proved with the shipping CircomReduction prover against the committed setup, verified by
///      the generated adapter. Regenerate with
///        cargo run --release -p zkapi-proof --example solidity_fixture -- ../setup/v2-concession-dev \
///          > ../contracts/test/fixtures/solidity-fixture.json
///      Every check runs on two deployments of the adapter: `folded`, folded for the fixture's
///      binding (chain 31337, contract 0x1234 and its signing keys), so its proofs take the folded
///      path, and `generic`, folded for another vault, so they take the path over every input.
contract Groth16ProofAdapterTest is Test {
    string constant CIRCUIT_ID = "zkapi-v2-concession-v1";
    uint256 constant SCALAR_MODULUS = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
    uint256 constant BASE_MODULUS = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
    address constant OTHER_VAULT = address(0xdead);

    Groth16ProofAdapter folded;
    Groth16ProofAdapter generic;
    VerifyOnceCaller caller;
    string fixtures;
    Types.WithdrawalPublicInputs binding;

    function setUp() public {
        vm.chainId(31_337);
        fixtures = vm.readFile("test/fixtures/solidity-fixture.json");
        assertEq(vm.parseJsonString(fixtures, ".circuit_id"), CIRCUIT_ID);
        (binding,) = _withdrawal("withdrawal");
        assertEq(binding.chainId, 31_337);
        folded = _deploy(binding.contractAddress);
        generic = _deploy(OTHER_VAULT);
        caller = new VerifyOnceCaller();
    }

    function _deploy(address vault) private returns (Groth16ProofAdapter) {
        return new Groth16ProofAdapter(
            vault,
            binding.stateSigningKeyX,
            binding.stateSigningKeyY,
            binding.clearanceSigningKeyX,
            binding.clearanceSigningKeyY
        );
    }

    function _adapters() private view returns (Groth16ProofAdapter[2] memory) {
        return [folded, generic];
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
        assertEq(folded.CIRCUIT_ID_HASH(), keccak256(bytes(CIRCUIT_ID)));
        assertEq(folded.CIRCUIT_ID_HASH(), 0xf464f910d858a070b2f88db1049aab19d8fabeed1e527920be90dc0c950b0687);
        assertEq(folded.REQUEST_VK_HASH(), vm.parseJsonBytes32(manifest, ".vk_keccak256.request"));
        assertEq(folded.WITHDRAWAL_VK_HASH(), vm.parseJsonBytes32(manifest, ".vk_keccak256.withdrawal"));
        assertEq(vm.parseJsonUint(manifest, ".circuits.request.public_inputs"), 12);
        assertEq(vm.parseJsonUint(manifest, ".circuits.withdrawal.public_inputs"), 16);
    }

    /// The constructor's arguments and the chain are public, for the deployment script's checks.
    function test_foldedConstantsAreTheConstructorArguments() public view {
        assertEq(folded.foldedChainId(), 31_337);
        assertEq(folded.foldedVault(), binding.contractAddress);
        assertEq(generic.foldedVault(), OTHER_VAULT);
        assertEq(folded.foldedStateSigningKeyX(), binding.stateSigningKeyX);
        assertEq(folded.foldedStateSigningKeyY(), binding.stateSigningKeyY);
        assertEq(folded.foldedClearanceSigningKeyX(), binding.clearanceSigningKeyX);
        assertEq(folded.foldedClearanceSigningKeyY(), binding.clearanceSigningKeyY);
    }

    /// The folded points are IC0 + Σ c · IC with the IC points of the setup's manifest.json (the
    /// setup ZKAPI_SETUP_DIR selects), summed here through the precompiles: the adapter's verifying
    /// key constants and its constructor agree with the setup.
    function test_foldedPointsAreTheManifestsSums() public view {
        string memory manifest = _readSetupManifest(setupDir());
        uint256[] memory request = new uint256[](5);
        request[0] = 2;
        request[1] = block.chainid;
        request[2] = uint160(binding.contractAddress);
        request[3] = binding.stateSigningKeyX;
        request[4] = binding.stateSigningKeyY;
        uint256[5] memory requestIndices = [uint256(1), 2, 3, 5, 6];
        (uint256 x, uint256 y) = _manifestSum(manifest, ".request.ic", request, _list(requestIndices));
        assertEq(folded.foldedRequestIc0X(), x, "request x");
        assertEq(folded.foldedRequestIc0Y(), y, "request y");
        uint256[] memory withdrawal = new uint256[](7);
        for (uint256 i = 0; i < 5; ++i) {
            withdrawal[i] = request[i];
        }
        withdrawal[5] = binding.clearanceSigningKeyX;
        withdrawal[6] = binding.clearanceSigningKeyY;
        uint256[7] memory withdrawalIndices = [uint256(1), 2, 3, 5, 6, 7, 8];
        uint256[] memory indices = new uint256[](7);
        for (uint256 i = 0; i < 7; ++i) {
            indices[i] = withdrawalIndices[i];
        }
        (x, y) = _manifestSum(manifest, ".withdrawal.ic", withdrawal, indices);
        assertEq(folded.foldedWithdrawalIc0X(), x, "withdrawal x");
        assertEq(folded.foldedWithdrawalIc0Y(), y, "withdrawal y");
        // Another vault folds to another point.
        assertNotEq(generic.foldedWithdrawalIc0X(), x);
    }

    /// A key coordinate no proof can carry (at or above the scalar field order) is refused.
    function test_constructorRefusesNonCanonicalKeys() public {
        vm.expectRevert(Errors.InvalidProof.selector);
        new Groth16ProofAdapter(OTHER_VAULT, SCALAR_MODULUS, 1, 2, 3);
        vm.expectRevert(Errors.InvalidProof.selector);
        new Groth16ProofAdapter(OTHER_VAULT, 1, 2, 3, binding.clearanceSigningKeyY + SCALAR_MODULUS);
    }

    function test_supportsTheAdapterInterface() public view {
        assertTrue(folded.supportsInterface(type(IZkApiProofAdapter).interfaceId));
        assertTrue(folded.supportsInterface(0x01ffc9a7));
        assertFalse(folded.supportsInterface(0xffffffff));
        assertFalse(folded.supportsInterface(IZkApiProofAdapter.assertValidWithdrawal.selector));
    }

    function test_verifiesRustRequestProofs() public view {
        string[2] memory names = ["request", "request_signed"];
        for (uint256 a = 0; a < 2; ++a) {
            for (uint256 i = 0; i < names.length; ++i) {
                (Types.RequestPublicInputs memory inputs, bytes memory proof) = _request(names[i]);
                _adapters()[a].assertValidRequest(inputs, proof);
            }
        }
    }

    /// Escapes with c = 0 and c > 0 (signed and genesis), a close, an ownership proof and an
    /// escape to a full 160-bit destination, through assertValidWithdrawal and
    /// verifyWithdrawalOnce.
    function test_verifiesRustWithdrawalProofsOfEveryKind() public {
        string[6] memory names =
            ["withdrawal", "escape_c0", "escape_genesis_concession", "close", "ownership", "escape_full_destination"];
        for (uint256 a = 0; a < 2; ++a) {
            for (uint256 i = 0; i < names.length; ++i) {
                (Types.WithdrawalPublicInputs memory inputs, bytes memory proof) = _withdrawal(names[i]);
                _adapters()[a].assertValidWithdrawal(inputs, proof);
                _adapters()[a].verifyWithdrawalOnce(inputs, proof);
            }
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
        for (uint256 a = 0; a < 2; ++a) {
            (Types.RequestPublicInputs memory inputs, bytes memory proof) = _request("request");
            inputs.solvencyBound += 1;
            vm.expectRevert(Errors.InvalidProof.selector);
            _adapters()[a].assertValidRequest(inputs, proof);
        }
    }

    function test_rejectsTamperedWithdrawalInputs() public {
        for (uint256 a = 0; a < 2; ++a) {
            Groth16ProofAdapter adapter = _adapters()[a];
            (Types.WithdrawalPublicInputs memory inputs, bytes memory proof) = _withdrawal("withdrawal");
            // Shifting value from the payout to the concession keeps finalBalance + conceded.
            inputs.finalBalance += 1;
            inputs.conceded -= 1;
            vm.expectRevert(Errors.InvalidProof.selector);
            adapter.assertValidWithdrawal(inputs, proof);
            vm.expectRevert(Errors.InvalidProof.selector);
            adapter.verifyWithdrawalOnce(inputs, proof);
            (inputs, proof) = _withdrawal("ownership");
            inputs.kind = 1;
            vm.expectRevert(Errors.InvalidProof.selector);
            adapter.assertValidWithdrawal(inputs, proof);
            (inputs, proof) = _withdrawal("escape_c0");
            inputs.validUntil += 1;
            vm.expectRevert(Errors.InvalidProof.selector);
            adapter.assertValidWithdrawal(inputs, proof);
        }
    }

    /// The folded path is taken only when every folded word matches: a statement of the folded
    /// vault with another protocol version, chain, contract or key verifies over every input, so
    /// its proof (made for the fixture's words) fails.
    function test_aChangedFoldedWordLeavesTheFoldedPath() public {
        (Types.WithdrawalPublicInputs memory inputs, bytes memory proof) = _withdrawal("close");
        bytes memory words = abi.encode(inputs);
        uint256[7] memory foldedWords = [uint256(0), 1, 2, 4, 5, 6, 7];
        for (uint256 i = 0; i < foldedWords.length; ++i) {
            uint256 index = foldedWords[i];
            bytes memory changed = bytes.concat(words);
            uint256 value;
            assembly ("memory-safe") {
                value := mload(add(add(changed, 0x20), mul(index, 0x20)))
            }
            assembly ("memory-safe") {
                mstore(add(add(changed, 0x20), mul(index, 0x20)), add(value, 1))
            }
            Types.WithdrawalPublicInputs memory mutated = abi.decode(changed, (Types.WithdrawalPublicInputs));
            vm.expectRevert(Errors.InvalidProof.selector);
            folded.assertValidWithdrawal(mutated, proof);
        }
    }

    function test_rejectsMalformedProofs() public {
        for (uint256 a = 0; a < 2; ++a) {
            Groth16ProofAdapter adapter = _adapters()[a];
            (Types.WithdrawalPublicInputs memory inputs, bytes memory proof) = _withdrawal("close");
            vm.expectRevert(Errors.InvalidProof.selector);
            adapter.assertValidWithdrawal(inputs, bytes.concat(proof, hex"00"));
            vm.expectRevert(Errors.InvalidProof.selector);
            adapter.assertValidWithdrawal(inputs, new bytes(255));
            vm.expectRevert(Errors.InvalidProof.selector);
            adapter.assertValidWithdrawal(inputs, new bytes(256));
            bytes memory outOfField = bytes.concat(proof);
            for (uint256 i = 0; i < 32; ++i) {
                outOfField[i] = 0xff;
            }
            vm.expectRevert(Errors.InvalidProof.selector);
            adapter.assertValidWithdrawal(inputs, outOfField);
            vm.expectRevert(Errors.InvalidProof.selector);
            adapter.verifyWithdrawalOnce(inputs, outOfField);
        }
    }

    /// A word that does not fit its narrow field is refused as Solidity's ABI decoder refuses it,
    /// with an empty revert, on both paths and before the proof is looked at.
    function test_rejectsDirtyNarrowFieldsAsTheAbiDecoder() public view {
        (Types.WithdrawalPublicInputs memory inputs, bytes memory proof) = _withdrawal("close");
        uint256[9] memory narrow = [uint256(0), 1, 2, 8, 9, 10, 12, 14, 15];
        uint16[9] memory bits = [uint16(16), 64, 160, 32, 128, 160, 8, 128, 64];
        for (uint256 a = 0; a < 2; ++a) {
            for (uint256 i = 0; i < narrow.length; ++i) {
                bytes memory words = abi.encode(inputs);
                uint256 index = narrow[i];
                uint256 dirty = uint256(1) << bits[i];
                assembly ("memory-safe") {
                    let at := add(add(words, 0x20), mul(index, 0x20))
                    mstore(at, or(mload(at), dirty))
                }
                bytes memory data = abi.encodePacked(
                    IZkApiProofAdapter.assertValidWithdrawal.selector,
                    words,
                    uint256(0x220),
                    uint256(proof.length),
                    proof
                );
                (bool ok, bytes memory reason) = address(_adapters()[a]).staticcall(data);
                assertFalse(ok, "dirty word accepted");
                assertEq(reason.length, 0, "an empty revert, as the ABI decoder's");
            }
        }
    }

    // ------------------------------------------------------------------ verify once

    /// After verifyWithdrawalOnce, assertValidWithdrawal of the same bytes in the same transaction
    /// returns without verifying (a few thousand gas instead of a verification). A Forge test is
    /// one transaction, so the call without a record comes first.
    function test_verifyOnceThenAssertIsCheap() public {
        (Types.WithdrawalPublicInputs memory inputs, bytes memory proof) = _withdrawal("close");
        for (uint256 a = 0; a < 2; ++a) {
            uint256 g0 = gasleft();
            _adapters()[a].assertValidWithdrawal(inputs, proof);
            assertGt(g0 - gasleft(), 150_000, "a verification");
            uint256 hit = caller.verifyThenAssert(_adapters()[a], inputs, proof, inputs, proof);
            assertLt(hit, 5_000, "a recorded verification");
        }
    }

    /// Only the exact verified bytes skip the verification. The same statement with another
    /// valid proof of it ((-A, -B, C), which also verifies and shares A.x) is verified in full; a
    /// changed input with the verified proof fails. Recording the other proof does not evict the
    /// first: every verified pair has a slot of its own.
    function test_onlyTheVerifiedBytesSkipTheVerification() public {
        (Types.WithdrawalPublicInputs memory inputs, bytes memory proof) = _withdrawal("close");
        bytes memory twin = _negatedTwin(proof);
        assertNotEq(keccak256(twin), keccak256(proof));
        folded.assertValidWithdrawal(inputs, twin);
        uint256 other = caller.verifyThenAssert(folded, inputs, proof, inputs, twin);
        assertGt(other, 150_000, "another proof is verified in full");
        for (uint256 field = 0; field < 16; ++field) {
            bytes memory words = abi.encode(inputs);
            if (field == 0 || field == 12) {
                // protocolVersion and kind: another value of the type.
                assembly ("memory-safe") {
                    let at := add(add(words, 0x20), mul(field, 0x20))
                    mstore(at, xor(mload(at), 1))
                }
            } else {
                assembly ("memory-safe") {
                    let at := add(add(words, 0x20), mul(field, 0x20))
                    mstore(at, add(mload(at), 1))
                }
            }
            Types.WithdrawalPublicInputs memory changed = abi.decode(words, (Types.WithdrawalPublicInputs));
            (bool ok, bytes memory reason) = caller.verifyThenTry(folded, inputs, proof, changed, proof);
            assertFalse(ok, "a changed input is not covered by the record");
            assertEq(bytes4(reason), Errors.InvalidProof.selector);
        }
        // Two records of one destination coexist: after the twin's, the first still holds.
        uint256 both = new VerifyOnceTwice().run(folded, inputs, proof, twin);
        assertLt(both, 10_000, "both proofs recorded");
    }

    /// The record covers every byte the verification reads: after a fixture's record, the same
    /// call with one bit flipped anywhere in its 16 input words or its 256 proof bytes is refused
    /// (InvalidProof(), or the ABI decoder's empty revert for a dirty narrow field) by either
    /// deployment, while the unchanged call hits. Samples the 6,144 bits of a statement and proof;
    /// each assertion is capped at 1,500,000 gas.
    function testFuzz_aFlippedBitMissesTheRecord(uint256 seed) public {
        string[3] memory names = ["close", "withdrawal", "escape_full_destination"];
        (Types.WithdrawalPublicInputs memory inputs, bytes memory proof) = _withdrawal(names[seed % 3]);
        Groth16ProofAdapter adapter = _adapters()[(seed >> 8) % 2];
        bytes memory call = abi.encodeCall(IZkApiProofAdapter.assertValidWithdrawal, (inputs, proof));
        assertEq(call.length, 4 + 0x200 + 0x40 + 0x100, "selector, inputs, proof offset and length, proof");
        assertTrue(caller.verifyThenTryRaw(adapter, inputs, proof, call, 1_500_000), "the recorded bytes hit");
        uint256 bit = (seed >> 16) % (0x300 * 8);
        uint256 recordedByte = bit / 8;
        // the 512 input bytes after the selector, then the proof's 256 after its offset and length
        // words (recorded byte 0x200 is call byte 4 + 0x240)
        uint256 at = recordedByte < 0x200 ? 4 + recordedByte : 4 + 0x40 + recordedByte;
        call[at] = bytes1(uint8(call[at]) ^ uint8(1 << (bit % 8)));
        assertFalse(caller.verifyThenTryRaw(adapter, inputs, proof, call, 1_500_000), "a flipped bit misses the record");
    }

    /// The record lasts one transaction (EIP-1153): a later transaction verifies again.
    /// forge-config: default.isolate = true
    function test_theRecordLastsOneTransaction() public {
        (Types.WithdrawalPublicInputs memory inputs, bytes memory proof) = _withdrawal("close");
        folded.verifyWithdrawalOnce(inputs, proof);
        folded.assertValidWithdrawal(inputs, proof);
        assertGt(vm.lastCallGas().gasTotalUsed, 150_000, "verified again in a new transaction");
    }

    // ------------------------------------------------------------------ setup paths

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

    // ------------------------------------------------------------------ helpers

    /// IC[0] + Σ scalars[k] · IC[indices[k]] of a manifest's IC list, through ecMul and ecAdd.
    function _manifestSum(string memory manifest, string memory key, uint256[] memory scalars, uint256[] memory indices)
        private
        view
        returns (uint256 x, uint256 y)
    {
        (x, y) = _manifestPoint(manifest, key, 0);
        for (uint256 k = 0; k < scalars.length; ++k) {
            (uint256 px, uint256 py) = _manifestPoint(manifest, key, indices[k]);
            (bool ok, bytes memory product) = address(7).staticcall(abi.encode(px, py, scalars[k]));
            assertTrue(ok, "ecMul");
            (px, py) = abi.decode(product, (uint256, uint256));
            bytes memory sum;
            (ok, sum) = address(6).staticcall(abi.encode(x, y, px, py));
            assertTrue(ok, "ecAdd");
            (x, y) = abi.decode(sum, (uint256, uint256));
        }
    }

    function _manifestPoint(string memory manifest, string memory key, uint256 index)
        private
        pure
        returns (uint256, uint256)
    {
        string memory at = string.concat(key, "[", vm.toString(index), "]");
        return
            (vm.parseJsonUint(manifest, string.concat(at, "[0]")), vm.parseJsonUint(manifest, string.concat(at, "[1]")));
    }

    function _list(uint256[5] memory values) private pure returns (uint256[] memory list) {
        list = new uint256[](5);
        for (uint256 i = 0; i < 5; ++i) {
            list[i] = values[i];
        }
    }

    /// (-A, -B, C): a different proof of the same statement, since e(-A, -B) = e(A, B). The proof
    /// words are A.x, A.y, B.x.c0, B.x.c1, B.y.c0, B.y.c1, C.x, C.y; negating a point negates y.
    function _negatedTwin(bytes memory proof) private pure returns (bytes memory twin) {
        twin = bytes.concat(proof);
        uint256[3] memory ys = [uint256(1), 4, 5];
        for (uint256 i = 0; i < 3; ++i) {
            uint256 at = ys[i];
            assembly ("memory-safe") {
                let p := add(add(twin, 0x20), mul(at, 0x20))
                let v := mload(p)
                mstore(p, mod(sub(BASE_MODULUS, v), BASE_MODULUS))
            }
        }
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

/// @dev Records two proofs of one statement in one transaction, the second after the first, then
///      asserts both: neither record evicts the other. Returns the gas of the two assertions.
contract VerifyOnceTwice {
    function run(
        IZkApiProofAdapter adapter,
        Types.WithdrawalPublicInputs calldata inputs,
        bytes calldata first,
        bytes calldata second
    ) external returns (uint256 gasUsed) {
        adapter.verifyWithdrawalOnce(inputs, first);
        adapter.verifyWithdrawalOnce(inputs, second);
        uint256 g0 = gasleft();
        adapter.assertValidWithdrawal(inputs, first);
        adapter.assertValidWithdrawal(inputs, second);
        gasUsed = g0 - gasleft();
    }
}
