// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

// Golden calldata, getter selectors and layouts, and event layouts of the
// revision-4 vault (leaf-bound exits), taken from the real contracts (protocol/contracts/src:
// ZkApiVault, Types, Events and IZkApiProofAdapter), never from a copy of
// their declarations: vault_calldata_golden.json is this test's output.
// check-calldata-golden.sh runs it with forge and compares (CI), or rewrites
// the JSON with --update. zkapi-serverd's watcher and native_billing tests and
// zkapi-indexerd's poller tests pin their encoders, selectors and decoders
// against the JSON.

import {Test, Vm, console} from "forge-std/Test.sol";
import {ZkApiVault} from "zkapi/ZkApiVault.sol";
import {Types} from "zkapi/libraries/Types.sol";
import {Events} from "zkapi/libraries/Events.sol";
import {IZkApiProofAdapter} from "zkapi/interfaces/IZkApiProofAdapter.sol";

/// Emits the vault's own event declarations, so their topics and data
/// layouts are the compiler's.
contract VaultEvents is Events {
    function emitAll() external {
        emit NoteDeposited(7, bytes32(uint256(0x0c0c)), 1_000_000, 2_000_000_000);
        emit MutualClose(7, 0x0101, 900_000, address(0x1111111111111111111111111111111111111111));
        emit EscapeWithdrawalInitiated(
            7, 0x0101, 900_000, address(0x1111111111111111111111111111111111111111), 2_000_086_400
        );
        emit EscapeConcessionRecorded(7, 0x0202, 1_000_000, 100_000);
        emit EscapeConcessionRaised(7, 0x0101, 150_000, 850_000);
        emit EscapeWithdrawalChallenged(7, 0x0101);
        emit EscapeWithdrawalFinalized(7, 0x0101, 850_000, address(0x1111111111111111111111111111111111111111));
        emit ExpiredClaimed(7, 1_000_000);
        emit ClosedLeafRetired(7);
        emit EscapePayoutDeferred(7, address(0x1111111111111111111111111111111111111111), 850_000);
        emit EscapePayoutClaimed(address(0x1111111111111111111111111111111111111111), 850_000);
        emit RootRecorded(0x0a0a, 8, 123_456);
    }
}

contract GoldenTest is Test {
    function proof() internal pure returns (bytes memory out) {
        out = new bytes(256);
        for (uint256 i = 0; i < 256; i++) {
            out[i] = bytes1(uint8(i + 1));
        }
    }

    function request() internal pure returns (Types.RequestPublicInputs memory r) {
        r.protocolVersion = 2;
        r.chainId = 11155111;
        r.contractAddress = 0x00112233445566778899AABbCCdDeeFf00112233;
        r.activeRoot = 0x0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9;
        r.stateSigningKeyX = 0x1111111111111111111111111111111111111111111111111111111111111111;
        r.stateSigningKeyY = 0x2222222222222222222222222222222222222222222222222222222222222222;
        r.requestTime = 1767225600;
        r.solvencyBound = type(uint128).max;
        r.requestNullifier = 0x0102030405060708091011121314151617181920212223242526272829303132;
        r.authorizationTag = 0x2a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40414243444546474849;
        r.anonymousCommitmentX = 0x0333333333333333333333333333333333333333333333333333333333333333;
        r.anonymousCommitmentY = 0x0444444444444444444444444444444444444444444444444444444444444444;
    }

    function withdrawal(uint8 kind) internal pure returns (Types.WithdrawalPublicInputs memory w) {
        w.protocolVersion = 2;
        w.chainId = 1;
        w.contractAddress = 0x00112233445566778899AABbCCdDeeFf00112233;
        w.noteLeaf = 0x0a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f9;
        w.stateSigningKeyX = 0x1111111111111111111111111111111111111111111111111111111111111111;
        w.stateSigningKeyY = 0x2222222222222222222222222222222222222222222222222222222222222222;
        w.clearanceSigningKeyX = 0x0555555555555555555555555555555555555555555555555555555555555555;
        w.clearanceSigningKeyY = 0x0666666666666666666666666666666666666666666666666666666666666666;
        // noteId 2^32 - 1, deposit 2^53 - 1, expiry 2^64 - 1: every field at its top bit.
        w.noteFields = (uint256(type(uint32).max) << 192) | (uint256(9_007_199_254_740_991) << 64) | type(uint64).max;
        w.finalBalance = 1_000_000_000_000_000_000;
        w.destination = 0xFFfFfFffFFfffFFfFFfFFFFFffFFFffffFfFFFfF;
        w.withdrawalNullifier = 0x0102030405060708091011121314151617181920212223242526272829303132;
        w.kind = kind;
        if (kind == 0) {
            w.nextNullifier = 0x2122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f40;
            w.conceded = 123456789;
        }
        w.validUntil = type(uint64).max;
    }

    function line(string memory key, bytes memory value) internal pure {
        console.log(string.concat(key, "=", vm.toString(value)));
    }

    function selector(string memory key, bytes4 value) internal pure {
        line(string.concat("selector.", key), abi.encodePacked(value));
    }

    /// The ABI words a getter of a deployed vault returns for id 0.
    function getterWords(address vault, string memory key, bytes memory call) internal view {
        (bool ok, bytes memory data) = vault.staticcall(call);
        require(ok, key);
        console.log(string.concat("getter_words.", key, "=", vm.toString(data.length / 32)));
    }

    function test_print_golden_vectors() public {
        line(
            "calldata.defeat",
            abi.encodeCall(ZkApiVault.challengeEscapeWithdrawal, (type(uint32).max, request(), proof()))
        );
        line(
            "calldata.raise",
            abi.encodeCall(ZkApiVault.raiseEscapeConcession, (7, request(), proof(), 123456789012345678901234567890))
        );
        line("calldata.escape", abi.encodeCall(ZkApiVault.initiateEscapeWithdrawal, (withdrawal(0), proof())));
        line("calldata.close", abi.encodeCall(ZkApiVault.mutualClose, (withdrawal(1), proof())));
        uint256[32] memory siblings;
        for (uint256 i = 0; i < 32; i++) {
            siblings[i] = (i + 1) * 0x0101010101010101;
        }
        line("calldata.retire", abi.encodeCall(ZkApiVault.retireClosedLeaf, (9, siblings)));

        // Every vault and adapter function the server, challenger, indexer,
        // signer and clients call or decode. Public getters have selectors
        // only on an instance, so a vault is deployed (with the real Poseidon
        // runtime, which its constructor checks).
        address poseidon = deployCode("out/Bn254PoseidonRuntime.sol/Bn254PoseidonRuntime.json");
        ZkApiVault vault = new ZkApiVault(
            address(0xbeef), 30 days, 1 days, 100_000, address(0xada), 11, 12, 13, 14, address(this), 2 days, poseidon, 1
        );
        IZkApiProofAdapter adapter = IZkApiProofAdapter(address(0xada));
        selector("challengeEscapeWithdrawal", vault.challengeEscapeWithdrawal.selector);
        selector("raiseEscapeConcession", vault.raiseEscapeConcession.selector);
        selector("retireClosedLeaf", vault.retireClosedLeaf.selector);
        selector("initiateEscapeWithdrawal", vault.initiateEscapeWithdrawal.selector);
        selector("mutualClose", vault.mutualClose.selector);
        selector("deposit", vault.deposit.selector);
        selector("finalizeEscapeWithdrawal", vault.finalizeEscapeWithdrawal.selector);
        selector("claimEscapePayout", vault.claimEscapePayout.selector);
        selector("claimExpired", vault.claimExpired.selector);
        selector("currentRoot", vault.currentRoot.selector);
        selector("noteRecord", vault.noteRecord.selector);
        selector("noteLeaves", vault.noteLeaves.selector);
        selector("frontier", vault.frontier.selector);
        selector("minDeposit", vault.minDeposit.selector);
        selector("pausedBefore", vault.pausedBefore.selector);
        selector("graceUntil", vault.graceUntil.selector);
        selector("pauseEpochCount", vault.pauseEpochCount.selector);
        selector("recordRoot", vault.recordRoot.selector);
        selector("recordedRoot", vault.recordedRoot.selector);
        selector("usedNullifiers", vault.usedNullifiers.selector);
        selector("challengedNullifiers", vault.challengedNullifiers.selector);
        selector("pendingWithdrawals", vault.pendingWithdrawals.selector);
        selector("pendingConcessions", vault.pendingConcessions.selector);
        selector("escapePayoutCredits", vault.escapePayoutCredits.selector);
        selector("effectiveExpiry", vault.effectiveExpiry.selector);
        selector("CONCESSION_ESCAPE_VERSION", vault.CONCESSION_ESCAPE_VERSION.selector);
        selector("LEAF_BOUND_EXIT_VERSION", vault.LEAF_BOUND_EXIT_VERSION.selector);
        selector("proofAdapter", vault.proofAdapter.selector);
        selector("challengePeriod", vault.challengePeriod.selector);
        selector("noteTtl", vault.noteTtl.selector);
        selector("maxPauseDuration", vault.maxPauseDuration.selector);
        selector("nextNoteId", vault.nextNoteId.selector);
        selector("stateSigningKeyX", vault.stateSigningKeyX.selector);
        selector("stateSigningKeyY", vault.stateSigningKeyY.selector);
        selector("clearanceSigningKeyX", vault.clearanceSigningKeyX.selector);
        selector("clearanceSigningKeyY", vault.clearanceSigningKeyY.selector);
        selector("CIRCUIT_ID_HASH", adapter.CIRCUIT_ID_HASH.selector);
        selector("REQUEST_VK_HASH", adapter.REQUEST_VK_HASH.selector);
        selector("WITHDRAWAL_VK_HASH", adapter.WITHDRAWAL_VK_HASH.selector);
        selector("assertValidWithdrawal", adapter.assertValidWithdrawal.selector);
        selector("verifyWithdrawalOnce", adapter.verifyWithdrawalOnce.selector);
        selector("assertValidRequest", adapter.assertValidRequest.selector);

        // The words each struct getter returns (the adapter is never called
        // by these reads).
        getterWords(address(vault), "pendingWithdrawals", abi.encodeCall(vault.pendingWithdrawals, (0)));
        getterWords(address(vault), "pendingConcessions", abi.encodeCall(vault.pendingConcessions, (0)));
        getterWords(address(vault), "noteRecord", abi.encodeCall(vault.noteRecord, (0)));
        getterWords(address(vault), "recordedRoot", abi.encodeCall(vault.recordedRoot, (0)));
        getterWords(address(vault), "frontier", abi.encodeCall(vault.frontier, ()));

        // topic0, every topic (32-byte words, topic0 first) and the data of
        // each event as the vault emits it.
        VaultEvents events = new VaultEvents();
        string[12] memory names = [
            "NoteDeposited",
            "MutualClose",
            "EscapeWithdrawalInitiated",
            "EscapeConcessionRecorded",
            "EscapeConcessionRaised",
            "EscapeWithdrawalChallenged",
            "EscapeWithdrawalFinalized",
            "ExpiredClaimed",
            "ClosedLeafRetired",
            "EscapePayoutDeferred",
            "EscapePayoutClaimed",
            "RootRecorded"
        ];
        vm.recordLogs();
        events.emitAll();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        require(logs.length == names.length, "one log per event");
        for (uint256 i = 0; i < logs.length; i++) {
            line(string.concat("event.", names[i], ".topic0"), abi.encodePacked(logs[i].topics[0]));
            line(string.concat("event.", names[i], ".topics"), abi.encodePacked(logs[i].topics));
            line(string.concat("event.", names[i], ".data"), logs[i].data);
        }
    }
}
