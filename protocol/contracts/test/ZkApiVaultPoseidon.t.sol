// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {ZkApiVault} from "../src/ZkApiVault.sol";
import {Errors} from "../src/libraries/Errors.sol";
import {MerkleUpdateLib} from "../src/libraries/MerkleUpdateLib.sol";
import {VaultTestBase} from "./helpers/VaultTestBase.sol";
import {PoseidonRuntime} from "./helpers/PoseidonRuntime.sol";

/// @dev Answers compress with a value that is not the tree's first zero hash.
contract WrongHasher {
    function compress(uint256, uint256, uint256) external pure returns (uint256) {
        return 1;
    }
}

/// @dev Reverts every call with a reason.
contract RevertingHasher {
    fallback() external {
        revert("hasher down");
    }
}

/// @dev Tries to write its own storage in every entry point the vault uses: under the vault's
///      STATICCALL the write fails, so the vault's call reverts.
contract WritingHasher {
    uint256 internal calls;

    /// @dev The only entry point the revision-4 vault calls.
    function compress(uint256, uint256, uint256) external returns (uint256) {
        ++calls;
        return 1;
    }

    function hash5(uint256, uint256, uint256, uint256, uint256) external returns (uint256) {
        ++calls;
        return 1;
    }

    function insertPath32(uint256, uint32, uint256, uint256[32] calldata) external returns (uint256, uint256) {
        ++calls;
        return (2, 3);
    }

    function compressPairPath32(uint256, uint32, uint256, uint256, uint256[32] calldata, uint256)
        external
        returns (uint256, uint256, uint256)
    {
        ++calls;
        return (4, 5, 6);
    }
}

/// @dev The vault's binding to its Poseidon runtime: the constructor argument and its check, the
///      immutable getter, and that the vault reaches the runtime only by STATICCALL and reverts
///      with it.
contract ZkApiVaultPoseidonTest is VaultTestBase {
    function setUp() public {
        _setUpVault();
    }

    function test_poseidonIsTheConstructorArgument() public view {
        assertEq(address(vault.poseidon()), PoseidonRuntime.ADDRESS);
        assertEq(PoseidonRuntime.ADDRESS.codehash, keccak256(vm.getDeployedCode(PoseidonRuntime.ARTIFACT)));
    }

    function test_constructorRefusesAPoseidonWithoutCodeOrWithWrongAnswers() public {
        address[3] memory noCode = [address(0), address(0x1234), address(0xdead)];
        for (uint256 i = 0; i < noCode.length; ++i) {
            vm.expectRevert(Errors.InvalidDeploymentBinding.selector);
            _vaultWith(noCode[i]);
        }
        // The hashers exist before expectRevert, which applies to the next call.
        address wrong = address(new WrongHasher());
        address reverting = address(new RevertingHasher());
        vm.expectRevert(Errors.InvalidDeploymentBinding.selector);
        _vaultWith(wrong);
        // A contract without compress (here the proof adapter) fails the call itself.
        vm.expectRevert();
        _vaultWith(address(adapter));
        vm.expectRevert(bytes("hasher down"));
        _vaultWith(reverting);
        // A second vault may share the deployed runtime.
        assertEq(address(_vaultWith(PoseidonRuntime.ADDRESS).poseidon()), PoseidonRuntime.ADDRESS);
    }

    function test_aFailedHasherCallRevertsTheVaultCall() public {
        uint32 id = _deposit(42);
        bytes32 root = bytes32(vault.currentRoot());
        vm.etch(PoseidonRuntime.ADDRESS, address(new RevertingHasher()).code);
        vm.prank(user);
        vm.expectRevert(bytes("hasher down"));
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(bytes32(uint256(43)), DEPOSIT);
        assertEq(vault.nextNoteId(), id + 1);
        // The computed root is the hasher's too: it fails with it, and is unchanged once it is back.
        vm.expectRevert(bytes("hasher down"));
        vault.currentRoot();
        vm.etch(PoseidonRuntime.ADDRESS, vm.getDeployedCode(PoseidonRuntime.ARTIFACT));
        assertEq(bytes32(vault.currentRoot()), root);
    }

    /// A write under STATICCALL is an exceptional halt that burns the gas the vault forwarded, so the
    /// deposit runs with an explicit gas cap (five times a deposit's cost) rather than the test's
    /// whole gas limit. The same capped call succeeds once the real runtime is back, so the
    /// failure is the hasher's write and not the cap.
    function test_theHasherCannotWriteState() public {
        _deposit(42);
        uint256 nextId = vault.nextNoteId();
        bytes32 root = bytes32(vault.currentRoot());
        bytes memory code = PoseidonRuntime.ADDRESS.code;
        vm.etch(PoseidonRuntime.ADDRESS, address(new WritingHasher()).code);
        assertFalse(_cappedDeposit(43), "deposit with a writing hasher");
        assertEq(vault.nextNoteId(), nextId);
        assertEq(vm.load(PoseidonRuntime.ADDRESS, 0), 0, "nothing written");
        vm.etch(PoseidonRuntime.ADDRESS, code);
        assertEq(bytes32(vault.currentRoot()), root);
        assertTrue(_cappedDeposit(43), "the same deposit with the runtime");
        assertEq(vault.nextNoteId(), nextId + 1);
    }

    function _cappedDeposit(uint256 commitment) internal returns (bool ok) {
        vm.prank(user);
        (ok,) = address(vault).call{value: uint256(DEPOSIT) * 1 gwei, gas: 3_000_000}(
            abi.encodeCall(vault.deposit, (bytes32(commitment), DEPOSIT))
        );
    }

    function _vaultWith(address poseidon) internal returns (ZkApiVault) {
        return new ZkApiVault(
            treasury,
            30 days,
            CHALLENGE_PERIOD,
            100_000,
            address(adapter),
            STATE_X,
            STATE_Y,
            CLEAR_X,
            CLEAR_Y,
            address(this),
            MAX_PAUSE,
            poseidon,
            1
        );
    }

    /// The constructor's check value: the first zero hash, compress(DOMAIN_NODE, 0, 0).
    function test_theCheckValueIsTheFirstZeroHash() public view {
        assertEq(vault.poseidon().compress(DOMAIN_NODE, 0, 0), MerkleUpdateLib.zeroHash(1));
    }
}
