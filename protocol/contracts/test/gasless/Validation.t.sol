// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {ZkApiVault} from "../../src/ZkApiVault.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Errors} from "../../src/libraries/Errors.sol";
import {MerkleUpdateLib} from "../../src/libraries/MerkleUpdateLib.sol";
import {IEntryPoint, IPaymaster, PackedUserOperation} from "../../src/gasless/IERC4337.sol";
import {ZkApiWithdrawalAccount} from "../../src/gasless/ZkApiWithdrawalAccount.sol";
import {ZkApiWithdrawalPaymaster} from "../../src/gasless/ZkApiWithdrawalPaymaster.sol";
import {MockAdapterIdentity} from "../mocks/MockProofAdapters.sol";
import {GaslessTestBase} from "./GaslessTestBase.sol";

/// @dev An account with code that is not a transit account: validates every operation.
contract ForeignAccount {
    address public owner;
    address public payee;

    constructor(address owner_, address payee_) {
        owner = owner_;
        payee = payee_;
    }

    function validateUserOp(PackedUserOperation calldata, bytes32, uint256) external pure returns (uint256) {
        return 0;
    }
}

/// @dev Refuses every withdrawal proof: shows which checks run before the adapter.
contract RejectingWithdrawals is MockAdapterIdentity {
    function assertValidRequest(Types.RequestPublicInputs calldata, bytes calldata) external pure {}

    function assertValidWithdrawal(Types.WithdrawalPublicInputs calldata, bytes calldata) external pure {
        revert Errors.InvalidProof();
    }
}

/// @dev A vault whose versions and adapter the paymaster's constructor checks: only the getters
///      the constructor reads, so a refusal is attributable to one check.
contract VersionedVault {
    uint16 public immutable PROTOCOL_VERSION;
    uint16 public immutable CONCESSION_ESCAPE_VERSION;
    address public immutable proofAdapter;
    uint256 public constant nativeAssetWeiPerUnit = 1 gwei;
    uint256 public constant stateSigningKeyX = 11;
    uint256 public constant stateSigningKeyY = 12;
    uint256 public constant clearanceSigningKeyX = 13;
    uint256 public constant clearanceSigningKeyY = 14;
    uint64 public constant maxPauseDuration = 7 days;

    constructor(uint16 protocolVersion, uint16 concessionVersion, address adapter_) {
        PROTOCOL_VERSION = protocolVersion;
        CONCESSION_ESCAPE_VERSION = concessionVersion;
        proofAdapter = adapter_;
    }
}

/// @dev Every refusal of validatePaymasterUserOp, one test per error selector, each shown to be
///      uncharged and uncounted; the constructor's refusals; the estimation convention; the
///      adapter last; the validity window packing; what validation reads and writes; the ERC-7562
///      opcode audit over a recorded trace.
contract ValidationTest is GaslessTestBase {
    uint256 constant ATTEMPTS_SLOT = 8;
    uint256 constant ESCAPE_NOTE_SLOT = 11;
    uint256 constant STRANDED_SLOT = 12;

    function setUp() public {
        _setUpGasless();
    }

    function _closeReady()
        internal
        returns (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs, uint32 id)
    {
        id = _bigNote(42);
        (op, inputs) = _closeOp(id, 1001, BIG - 1_000_000);
    }

    /// Re-signs an operation after its fields changed.
    function _resign(PackedUserOperation memory op) internal view returns (PackedUserOperation memory) {
        return _sign(op, OWNER_KEY);
    }

    function _withGas(PackedUserOperation memory op, OpGas memory g)
        internal
        view
        returns (PackedUserOperation memory)
    {
        op.accountGasLimits = bytes32((g.verification << 128) | g.call);
        op.preVerificationGas = g.pvg;
        op.gasFees = bytes32((g.priority << 128) | g.maxFee);
        op.paymasterAndData = _paymasterAndData(g);
        return _resign(op);
    }

    function _withInputs(PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs, bool escape)
        internal
        view
        returns (PackedUserOperation memory)
    {
        op.callData = _callData(escape ? _escapeCall(inputs) : _closeCall(inputs));
        return _resign(op);
    }

    function _refusedUncounted(PackedUserOperation memory op, bytes4 selector, bytes32 key)
        internal
        returns (bytes memory inner)
    {
        uint256 before = paymaster.attempts(key);
        inner = _refused(op, selector);
        assertEq(paymaster.attempts(key), before, "uncounted");
    }

    // ------------------------------------------------------------------------ constructor

    function _deploy(address entryPoint_, address vault_) internal returns (ZkApiWithdrawalPaymaster) {
        return new ZkApiWithdrawalPaymaster(
            IEntryPoint(entryPoint_),
            ZkApiVault(vault_),
            address(this),
            _defaultPolicy(),
            MAX_FEE_CEILING,
            PRIORITY_CEILING
        );
    }

    /// The EntryPoint is pinned by runtime codehash: an address without code or with other code is
    /// refused, so a deployment against the wrong EntryPoint (or a wrong chain) cannot happen.
    function test_constructorRefusesABadEntryPoint() public {
        vm.expectRevert(ZkApiWithdrawalPaymaster.BadEntryPoint.selector);
        _deploy(address(0xdead), address(vault));
        vm.expectRevert(ZkApiWithdrawalPaymaster.BadEntryPoint.selector);
        _deploy(address(vault), address(vault));
        vm.expectRevert(ZkApiWithdrawalPaymaster.BadEntryPoint.selector);
        _deploy(SENDER_CREATOR, address(vault));
        assertEq(address(_deploy(ENTRY_POINT, address(vault)).entryPoint()), ENTRY_POINT, "the pinned runtime");
    }

    /// The vault must speak protocol version 2 with concession escapes version 1 and name an
    /// adapter with code, since validation re-runs the vault's checks and the adapter's proof.
    function test_constructorRefusesABadVault() public {
        VersionedVault wrongProtocol = new VersionedVault(3, 1, address(adapter));
        vm.expectRevert(ZkApiWithdrawalPaymaster.BadVault.selector);
        _deploy(ENTRY_POINT, address(wrongProtocol));
        VersionedVault wrongConcession = new VersionedVault(2, 2, address(adapter));
        vm.expectRevert(ZkApiWithdrawalPaymaster.BadVault.selector);
        _deploy(ENTRY_POINT, address(wrongConcession));
        VersionedVault codelessAdapter = new VersionedVault(2, 1, address(0x1234));
        vm.expectRevert(ZkApiWithdrawalPaymaster.BadVault.selector);
        _deploy(ENTRY_POINT, address(codelessAdapter));
        // the same mock with the right versions and an adapter with code is accepted
        VersionedVault right = new VersionedVault(2, 1, address(adapter));
        ZkApiWithdrawalPaymaster p = _deploy(ENTRY_POINT, address(right));
        assertEq(address(p.adapter()), address(adapter));
        assertEq(p.WEI_PER_UNIT(), 1 gwei);
        assertEq(p.MAX_PAUSE_DURATION(), 7 days);
    }

    // ------------------------------------------------------------------- paymaster policy

    function test_notEntryPoint() public {
        (PackedUserOperation memory op,,) = _closeReady();
        vm.expectRevert(ZkApiWithdrawalPaymaster.NotEntryPoint.selector);
        paymaster.validatePaymasterUserOp(op, bytes32(0), 0);
        vm.prank(bundler);
        vm.expectRevert(ZkApiWithdrawalPaymaster.NotEntryPoint.selector);
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, "", 0, 0);
    }

    function test_sponsorshipPaused() public {
        (PackedUserOperation memory op,,) = _closeReady();
        ZkApiWithdrawalPaymaster.Policy memory p = _defaultPolicy();
        p.sponsorshipPaused = true;
        paymaster.setPolicy(p);
        _refusedUncounted(op, ZkApiWithdrawalPaymaster.SponsorshipPaused.selector, _closeKey(1001));
        p.sponsorshipPaused = false;
        paymaster.setPolicy(p);
        (bool ok,) = _tryHandle(op);
        assertTrue(ok, "sponsorship resumes");
    }

    function test_badPaymasterData() public {
        (PackedUserOperation memory op,,) = _closeReady();
        bytes memory pmd = op.paymasterAndData;
        op.paymasterAndData = abi.encodePacked(pmd, uint8(0));
        _refused(_resign(op), ZkApiWithdrawalPaymaster.BadPaymasterData.selector);
        op.paymasterAndData = new bytes(63);
        for (uint256 i = 0; i < 63; ++i) {
            op.paymasterAndData[i] = pmd[i];
        }
        _refused(_resign(op), ZkApiWithdrawalPaymaster.BadPaymasterData.selector);
        op.paymasterAndData = new bytes(52);
        for (uint256 i = 0; i < 52; ++i) {
            op.paymasterAndData[i] = pmd[i];
        }
        _refused(_resign(op), ZkApiWithdrawalPaymaster.BadPaymasterData.selector);
    }

    function test_feeAboveCap() public {
        (PackedUserOperation memory op,,) = _closeReady();
        OpGas memory g = _gas(CLOSE, true);
        g.feeCap = FLAT_FEE - 1;
        bytes memory inner = _refused(_withGas(op, g), ZkApiWithdrawalPaymaster.FeeAboveCap.selector);
        assertEq(inner, abi.encodeWithSelector(ZkApiWithdrawalPaymaster.FeeAboveCap.selector, FLAT_FEE, FLAT_FEE - 1));
        g.feeCap = FLAT_FEE;
        (bool ok,) = _tryHandle(_withGas(op, g));
        assertTrue(ok, "the exact fee is accepted");
    }

    function test_feeAboveCeiling() public {
        (PackedUserOperation memory op,,) = _closeReady();
        OpGas memory g = _gas(CLOSE, true);
        g.maxFee = MAX_FEE_CEILING + 1;
        _refused(_withGas(op, g), ZkApiWithdrawalPaymaster.FeeAboveCeiling.selector);
        g = _gas(CLOSE, true);
        g.priority = PRIORITY_CEILING + 1;
        _refused(_withGas(op, g), ZkApiWithdrawalPaymaster.FeeAboveCeiling.selector);
    }

    function _gasField(uint8 field, uint256 floor, uint256 cap, bool withInit) internal {
        (PackedUserOperation memory op,,) = _closeReady();
        if (!withInit) {
            factory.createAccount(ownerAddr, payee);
            op.initCode = "";
        }
        OpGas memory g = _gas(CLOSE, withInit);
        uint256[2] memory values = [floor - 1, cap + 1];
        for (uint256 i = 0; i < 2; ++i) {
            if (field == 0) g.pvg = values[i];
            if (field == 1) g.verification = values[i];
            if (field == 2) g.call = values[i];
            if (field == 3) g.pmVerification = values[i];
            if (field == 4) g.postOp = values[i];
            bytes memory inner = _refused(_withGas(op, g), ZkApiWithdrawalPaymaster.GasLimitOutOfRange.selector);
            assertEq(
                inner,
                abi.encodeWithSelector(
                    ZkApiWithdrawalPaymaster.GasLimitOutOfRange.selector, field, values[i], floor, cap
                )
            );
        }
    }

    function test_gasLimitOutOfRange_preVerificationGas() public {
        _gasField(0, gp.pvgFloor, gp.pvgCap, true);
    }

    function test_gasLimitOutOfRange_verificationGasLimit() public {
        _gasField(1, gp.verificationFloorInit, gp.verificationCap, true);
        _gasField(1, gp.verificationFloor, gp.verificationCap, false);
    }

    function test_gasLimitOutOfRange_callGasLimit() public {
        _gasField(2, gp.callFloor[0], gp.callHardCap[0], true);
        // the owner's cap lowers the accepted range
        paymaster.setCallCap(CLOSE, gp.callFloor[0] + 10_000);
        _gasField(2, gp.callFloor[0], gp.callFloor[0] + 10_000, false);
        vm.expectRevert(ZkApiWithdrawalPaymaster.CallCapOutOfRange.selector);
        paymaster.setCallCap(CLOSE, gp.callHardCap[0] + 1);
        vm.expectRevert(ZkApiWithdrawalPaymaster.CallCapOutOfRange.selector);
        paymaster.setCallCap(CLOSE, gp.callFloor[0] - 1);
        vm.expectRevert(ZkApiWithdrawalPaymaster.InvalidKind.selector);
        paymaster.setCallCap(5, 1);
    }

    function test_gasLimitOutOfRange_paymasterVerificationGasLimit() public {
        _gasField(3, gp.pmVerificationFloor, gp.pmVerificationCap, true);
    }

    function test_gasLimitOutOfRange_paymasterPostOpGasLimit() public {
        _gasField(4, gp.postOpFloor, gp.postOpCap, true);
    }

    function test_gasLimitOutOfRange_forwardCallGasLimit() public {
        address s = factory.createAccount(ownerAddr, payee);
        vm.deal(s, 0.05 ether);
        paymaster.allowForward(s);
        PackedUserOperation memory op = _forwardOp();
        OpGas memory g = _gas(FORWARD, false);
        g.call = gp.callFloor[3] - 1;
        _refused(_withGas(op, g), ZkApiWithdrawalPaymaster.GasLimitOutOfRange.selector);
        g.call = gp.callHardCap[3] + 1;
        _refused(_withGas(op, g), ZkApiWithdrawalPaymaster.GasLimitOutOfRange.selector);
    }

    function test_maxCostAbovePolicy() public {
        (PackedUserOperation memory op,,) = _closeReady();
        ZkApiWithdrawalPaymaster.Policy memory p = _defaultPolicy();
        p.maxSponsoredCost = uint128(_maxCost(_gas(CLOSE, true)) - 1);
        paymaster.setPolicy(p);
        bytes memory inner = _refused(op, ZkApiWithdrawalPaymaster.MaxCostAbovePolicy.selector);
        assertEq(
            inner,
            abi.encodeWithSelector(
                ZkApiWithdrawalPaymaster.MaxCostAbovePolicy.selector, _maxCost(_gas(CLOSE, true)), p.maxSponsoredCost
            )
        );
    }

    function test_notTransitAccount() public {
        ForeignAccount foreign = new ForeignAccount(ownerAddr, payee);
        uint32 id = _bigNote(42);
        Types.WithdrawalPublicInputs memory inputs = _closeTo(id, 1001, BIG - 1_000_000, address(foreign));
        PackedUserOperation memory op = _op(
            address(foreign), _nonce(address(foreign), 1001), "", _callData(_closeCall(inputs)), _gas(CLOSE, false)
        );
        _refused(op, ZkApiWithdrawalPaymaster.NotTransitAccount.selector);
    }

    // -------------------------------------------------------------------------- callData

    function test_unsupportedCall() public {
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs,) = _closeReady();
        bytes memory vaultCall = _closeCall(inputs);
        bytes4 unsupported = ZkApiWithdrawalPaymaster.UnsupportedCall.selector;
        // another selector on the account
        op.callData = abi.encodeWithSelector(ZkApiWithdrawalAccount.sweep.selector);
        _refused(_resign(op), unsupported);
        // a non-canonical offset word
        bytes memory callData = _callData(vaultCall);
        callData[35] = 0x40;
        op.callData = callData;
        _refused(_resign(op), unsupported);
        // a length the paymaster does not accept (835, 837, 1)
        op.callData = _callData(_slice(vaultCall, 0, 835));
        _refused(_resign(op), unsupported);
        op.callData = _callData(abi.encodePacked(vaultCall, uint8(0)));
        _refused(_resign(op), unsupported);
        op.callData = _callData(hex"00");
        _refused(_resign(op), unsupported);
        // the right length word but trailing calldata beyond the padded argument
        op.callData = abi.encodePacked(_callData(vaultCall), uint8(0));
        _refused(_resign(op), unsupported);
        // nonzero padding after the argument
        callData = _callData(vaultCall);
        callData[callData.length - 1] = 0x01;
        op.callData = callData;
        _refused(_resign(op), unsupported);
        // a vault selector that is not an exit
        bytes memory other = _closeCall(inputs);
        other[0] = 0xff;
        op.callData = _callData(other);
        _refused(_resign(op), unsupported);
        // the proof's offset or length word is not canonical
        other = _closeCall(inputs);
        other[547] = 0x40;
        op.callData = _callData(other);
        _refused(_resign(op), unsupported);
        other = _closeCall(inputs);
        other[579] = 0xff;
        op.callData = _callData(other);
        _refused(_resign(op), unsupported);
        // a finalize with upper bits in the note id
        bytes memory finalize = abi.encodePacked(ZkApiVault.finalizeEscapeWithdrawal.selector, uint256(1) << 32);
        op.callData = _callData(finalize);
        _refused(_resign(op), unsupported);
        // a 36-byte call with another selector
        finalize = abi.encodePacked(ZkApiVault.claimExpired.selector, uint256(0));
        op.callData = _callData(finalize);
        _refused(_resign(op), unsupported);
        // the untouched call is accepted
        op.callData = _callData(vaultCall);
        (bool ok,) = _tryHandle(_resign(op));
        assertTrue(ok);
    }

    function _slice(bytes memory data, uint256 start, uint256 end) internal pure returns (bytes memory out) {
        out = new bytes(end - start);
        for (uint256 i = start; i < end; ++i) {
            out[i - start] = data[i];
        }
    }

    function test_wrongNonceKeyPerShape() public {
        (PackedUserOperation memory op,,) = _closeReady();
        address s = op.sender;
        op.nonce = _nonce(s, 1002);
        _refusedUncounted(_resign(op), ZkApiWithdrawalPaymaster.WrongNonceKey.selector, _closeKey(1001));
        // escape
        uint32 id2 = _bigNote(43);
        (op,) = _escapeOp(id2, 2001, 2002, BIG - 2_000_000, 1_000_000);
        op.nonce = _nonce(s, 2002);
        _refused(_resign(op), ZkApiWithdrawalPaymaster.WrongNonceKey.selector);
        // finalize: the pending escape's nullifier keys it
        factory.createAccount(ownerAddr, payee);
        vm.prank(user);
        vault.initiateEscapeWithdrawal(_escapeTo(id2, 2001, 2002, BIG - 2_000_000, 1_000_000, s), PROOF);
        vm.warp(_deadline(id2));
        op = _finalizeOp(id2);
        op.nonce = _nonce(s, 2002);
        _refused(_resign(op), ZkApiWithdrawalPaymaster.WrongNonceKey.selector);
        // forward: the fixed key
        paymaster.allowForward(s);
        vm.deal(s, 0.05 ether);
        op = _forwardOp();
        op.nonce = _nonce(s, 7);
        _refused(_resign(op), ZkApiWithdrawalPaymaster.WrongNonceKey.selector);
        assertEq(paymaster.FORWARD_NONCE_KEY(), uint192(uint256(keccak256("zkapi.gasless.forward"))));
    }

    /// Three sponsorships of one key, whatever their outcome, exhaust it; the owner releases it.
    function test_attemptsExhaustedAfterThreeSponsorships() public {
        address s = factory.createAccount(ownerAddr, payee);
        bytes32 key = _forwardKey(s);
        for (uint256 i = 0; i < 3; ++i) {
            vm.deal(s, 0.05 ether);
            paymaster.allowForward(s);
            Vm.Log[] memory logs = _handle(_forwardOp());
            (bool success,,) = _userOpEvent(logs);
            assertTrue(success);
            assertEq(paymaster.attempts(key), i + 1);
        }
        vm.deal(s, 0.05 ether);
        paymaster.allowForward(s);
        PackedUserOperation memory op = _forwardOp();
        bytes memory inner = _refused(op, ZkApiWithdrawalPaymaster.AttemptsExhausted.selector);
        assertEq(inner, abi.encodeWithSelector(ZkApiWithdrawalPaymaster.AttemptsExhausted.selector, key));
        assertTrue(paymaster.stranded(s), "the evidence is not consumed by a refusal");
        // a reverted execution counts too
        uint32 id = _bigNote(42);
        (PackedUserOperation memory close, Types.WithdrawalPublicInputs memory inputs) =
            _closeOp(id, 1001, BIG - 1_000_000);
        Vm.Log[] memory bundle = _bundledWithReplay(close, abi.encodeCall(ZkApiVault.mutualClose, (inputs, proof256)));
        (bool ok,,) = _userOpEventOf(bundle, s);
        assertFalse(ok, "reverted in execution");
        assertEq(paymaster.attempts(_closeKey(1001)), 1, "counted");
        // the owner releases the forward key
        bytes32[] memory keys = new bytes32[](1);
        keys[0] = key;
        vm.prank(user);
        vm.expectRevert();
        paymaster.release(keys);
        vm.recordLogs();
        paymaster.release(keys);
        assertTrue(_has(vm.getRecordedLogs(), address(paymaster), ZkApiWithdrawalPaymaster.Released.selector));
        assertEq(paymaster.attempts(key), 0);
        (ok,) = _tryHandle(_forwardOp());
        assertTrue(ok, "sponsored again");
    }

    // ------------------------------------------------------------------- exit statements

    function test_destinationNotSender() public {
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs,) = _closeReady();
        inputs.destination = payee;
        _refusedUncounted(
            _withInputs(op, inputs, false), ZkApiWithdrawalPaymaster.DestinationNotSender.selector, _closeKey(1001)
        );
    }

    function test_bindingMismatch() public {
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory base,) = _closeReady();
        for (uint256 field = 0; field < 7; ++field) {
            Types.WithdrawalPublicInputs memory inputs = base;
            if (field == 0) inputs.protocolVersion = 3;
            if (field == 1) inputs.chainId += 1;
            if (field == 2) inputs.contractAddress = address(0xdead);
            if (field == 3) inputs.stateSigningKeyX += 1;
            if (field == 4) inputs.stateSigningKeyY += 1;
            if (field == 5) inputs.clearanceSigningKeyX += 1;
            if (field == 6) inputs.clearanceSigningKeyY += 1;
            _refused(_withInputs(op, inputs, false), ZkApiWithdrawalPaymaster.BindingMismatch.selector);
        }
    }

    function test_invalidValidUntil() public {
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs,) = _closeReady();
        inputs.validUntil = 0;
        _refused(_withInputs(op, inputs, false), ZkApiWithdrawalPaymaster.InvalidValidUntil.selector);
        inputs.validUntil = uint64(1) << 48;
        _refused(_withInputs(op, inputs, false), ZkApiWithdrawalPaymaster.InvalidValidUntil.selector);
        inputs.validUntil = type(uint48).max;
        (bool ok,) = _tryHandle(_withInputs(op, inputs, false));
        assertTrue(ok, "the largest window the EntryPoint can carry");
    }

    function test_exitsPausedWhilePaused() public {
        (PackedUserOperation memory op,,) = _closeReady();
        uint32 id2 = _bigNote(43);
        uint32 id3 = _bigNote(44);
        address s = factory.createAccount(ownerAddr, payee);
        vm.prank(user);
        vault.initiateEscapeWithdrawal(_escapeTo(id3, 3001, 3002, BIG - 2_000_000, 1_000_000, s), PROOF);
        op.initCode = "";
        op = _resign(op);
        vault.pause();
        uint64 reopenAt = vault.pausedAt() + MAX_PAUSE;
        bytes memory inner = _refusedUncounted(op, ZkApiWithdrawalPaymaster.ExitsPaused.selector, _closeKey(1001));
        assertEq(inner, abi.encodeWithSelector(ZkApiWithdrawalPaymaster.ExitsPaused.selector, reopenAt));
        // escapes too
        (PackedUserOperation memory escape,) = _escapeOp(id2, 2001, 2002, BIG - 2_000_000, 1_000_000);
        _refused(escape, ZkApiWithdrawalPaymaster.ExitsPaused.selector);
        // finalization is never gated by the pause
        uint256 snap = vm.snapshotState();
        vm.warp(_deadline(id3));
        Vm.Log[] memory logs = _handle(_finalizeOp(id3));
        (bool success,,) = _userOpEvent(logs);
        assertTrue(success, "finalized while paused");
        vm.revertToState(snap);
        vault.unpause();
        (bool ok,) = _tryHandle(op);
        assertTrue(ok, "closes resume");
    }

    function test_unknownRoot() public {
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs,) = _closeReady();
        inputs.activeRoot += 1;
        _refused(_withInputs(op, inputs, false), ZkApiWithdrawalPaymaster.UnknownRoot.selector);
    }

    function test_noteNotActive() public {
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs,) = _closeReady();
        vm.prank(user);
        vault.mutualClose(_close(inputs.noteId, 9, BIG), PROOF);
        _refused(op, ZkApiWithdrawalPaymaster.NoteNotActive.selector);
        // a note that was never deposited
        inputs.noteId = 7;
        _refused(_withInputs(op, inputs, false), ZkApiWithdrawalPaymaster.NoteNotActive.selector);
    }

    function test_nullifierUsed() public {
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs,) = _closeReady();
        // the nullifier was consumed by an escape of another note
        uint32 id2 = _bigNote(43);
        vm.prank(user);
        vault.initiateEscapeWithdrawal(_escape(id2, 1001, 1002, BIG, 0), PROOF);
        _refused(_withInputs(op, inputs, false), ZkApiWithdrawalPaymaster.NullifierUsed.selector);
        // an escape whose successor was consumed
        uint32 id3 = _bigNote(44);
        (PackedUserOperation memory escape,) = _escapeOp(id3, 3001, 1002, BIG - 2_000_000, 1_000_000);
        _refused(escape, ZkApiWithdrawalPaymaster.NullifierUsed.selector);
    }

    function test_invalidFelt() public {
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs,) = _closeReady();
        inputs.withdrawalNullifier = MerkleUpdateLib.FIELD_MODULUS;
        op.nonce = _nonce(op.sender, uint192(MerkleUpdateLib.FIELD_MODULUS));
        _refused(_withInputs(op, inputs, false), ZkApiWithdrawalPaymaster.InvalidFelt.selector);
        uint32 id2 = _bigNote(43);
        (PackedUserOperation memory escape,) =
            _escapeOp(id2, 2001, MerkleUpdateLib.FIELD_MODULUS + 5, BIG - 2_000_000, 1_000_000);
        _refused(escape, ZkApiWithdrawalPaymaster.InvalidFelt.selector);
    }

    function test_wrongKind() public {
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs,) = _closeReady();
        inputs.kind = KIND_ESCAPE;
        _refused(_withInputs(op, inputs, false), ZkApiWithdrawalPaymaster.WrongKind.selector);
        inputs.kind = KIND_OWNERSHIP;
        _refused(_withInputs(op, inputs, false), ZkApiWithdrawalPaymaster.WrongKind.selector);
        uint32 id2 = _bigNote(43);
        (PackedUserOperation memory escape, Types.WithdrawalPublicInputs memory escapeInputs) =
            _escapeOp(id2, 2001, 2002, BIG - 2_000_000, 1_000_000);
        escapeInputs.kind = KIND_CLOSE;
        _refused(_withInputs(escape, escapeInputs, true), ZkApiWithdrawalPaymaster.WrongKind.selector);
    }

    function test_invalidBalance() public {
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs,) = _closeReady();
        inputs.finalBalance = BIG + 1;
        _refused(_withInputs(op, inputs, false), ZkApiWithdrawalPaymaster.InvalidBalance.selector);
        uint32 id2 = _bigNote(43);
        (PackedUserOperation memory escape, Types.WithdrawalPublicInputs memory escapeInputs) =
            _escapeOp(id2, 2001, 2002, BIG - 1_000_000, 1_000_001);
        _refused(_withInputs(escape, escapeInputs, true), ZkApiWithdrawalPaymaster.InvalidBalance.selector);
    }

    function test_badSuccessor() public {
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs) =
            _escapeOp(id, 2001, 0, BIG - 2_000_000, 1_000_000);
        _refused(op, ZkApiWithdrawalPaymaster.BadSuccessor.selector);
        inputs.nextNullifier = 2001;
        _refused(_withInputs(op, inputs, true), ZkApiWithdrawalPaymaster.BadSuccessor.selector);
    }

    function test_challengedNullifierAndSupersededState() public {
        uint32 id = _bigNote(42);
        address s = factory.createAccount(ownerAddr, payee);
        vm.prank(user);
        vault.initiateEscapeWithdrawal(_escapeTo(id, 2001, 2002, BIG - 2_000_000, 1_000_000, s), PROOF);
        Types.RequestPublicInputs memory request = _evidence(2002, 100_000);
        vm.prank(challenger);
        vault.challengeEscapeWithdrawal(id, request, PROOF);
        (PackedUserOperation memory op,) = _escapeOp(id, 2001, 2002, BIG - 2_000_000, 1_000_000);
        _refused(op, ZkApiWithdrawalPaymaster.ChallengedNullifier.selector);
        // the state below the defeated one names it as successor
        (op,) = _escapeOp(id, 2000, 2001, BIG - 2_000_000, 1_000_000);
        _refused(op, ZkApiWithdrawalPaymaster.SupersededState.selector);
    }

    function test_escapesDisabledAndAlreadySponsored() public {
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op,) = _escapeOp(id, 2001, 2002, BIG - 2_000_000, 1_000_000);
        ZkApiWithdrawalPaymaster.Policy memory p = _defaultPolicy();
        p.escapesEnabled = false;
        paymaster.setPolicy(p);
        _refusedUncounted(op, ZkApiWithdrawalPaymaster.EscapesDisabled.selector, _escapeKey(id));
        p.escapesEnabled = true;
        paymaster.setPolicy(p);
        _handle(op);
        assertTrue(paymaster.escapeSponsored(id));
        // defeated, then a second sponsored initiation of the same note
        Types.RequestPublicInputs memory request = _evidence(2002, 100_000);
        vm.prank(challenger);
        vault.challengeEscapeWithdrawal(id, request, PROOF);
        (op,) = _escapeOp(id, 2003, 2004, BIG - 2_000_000, 1_000_000);
        bytes memory inner = _refused(op, ZkApiWithdrawalPaymaster.EscapeAlreadySponsored.selector);
        assertEq(inner, abi.encodeWithSelector(ZkApiWithdrawalPaymaster.EscapeAlreadySponsored.selector, id));
    }

    function test_payoutBelowCostPerShape() public {
        // close: the payout must cover maxCost + flat fee + debt
        uint32 id = _bigNote(42);
        OpGas memory g = _gas(CLOSE, true);
        uint256 required = _maxCost(g) + FLAT_FEE;
        uint128 justBelow = uint128((required - 1) / 1 gwei);
        (PackedUserOperation memory op,) = _closeOp(id, 1001, justBelow);
        bytes memory inner = _refusedUncounted(op, ZkApiWithdrawalPaymaster.PayoutBelowCost.selector, _closeKey(1001));
        assertEq(
            inner,
            abi.encodeWithSelector(
                ZkApiWithdrawalPaymaster.PayoutBelowCost.selector, required, uint256(justBelow) * 1 gwei
            )
        );
        (op,) = _closeOp(id, 1001, uint128((required + 1 gwei - 1) / 1 gwei));
        (bool ok,) = _tryHandle(op);
        assertTrue(ok, "exactly enough");
        // escape: plus the finalization reserve, the minimum net and the second flat fee
        uint32 id2 = _bigNote(43);
        OpGas memory e = _gas(ESCAPE, false);
        uint256 needed = _maxCost(e) + FLAT_FEE + gp.finalizeReserveGas * e.maxFee + MIN_ESCAPE_NET + FLAT_FEE;
        uint128 belowEscape = uint128((needed - 1) / 1 gwei);
        (op,) = _escapeOp(id2, 2001, 2002, belowEscape, 0);
        inner = _refused(op, ZkApiWithdrawalPaymaster.PayoutBelowCost.selector);
        assertEq(
            inner,
            abi.encodeWithSelector(
                ZkApiWithdrawalPaymaster.PayoutBelowCost.selector, needed, uint256(belowEscape) * 1 gwei
            )
        );
        (uint256 requiredWei,, uint256 flatFeeWei, uint256 reserveWei, bool attemptsLeft, bool escapeOpen) =
            paymaster.quote(ESCAPE, op.sender, id2, 0, _maxCost(e), e.maxFee);
        assertEq(requiredWei, needed, "quote agrees");
        assertEq(flatFeeWei, FLAT_FEE);
        assertEq(reserveWei, gp.finalizeReserveGas * e.maxFee);
        assertTrue(attemptsLeft);
        assertTrue(escapeOpen);
        // finalize: a tiny pending payout
        uint32 id3 = _bigNote(44);
        vm.prank(user);
        vault.initiateEscapeWithdrawal(_escapeTo(id3, 3001, 3002, 1_000, BIG - 1_000, op.sender), PROOF);
        vm.warp(_deadline(id3));
        op = _finalizeOp(id3);
        _refused(op, ZkApiWithdrawalPaymaster.PayoutBelowCost.selector);
        // forward: a tiny balance
        paymaster.allowForward(op.sender);
        vm.deal(op.sender, 1_000);
        op = _forwardOp();
        _refused(op, ZkApiWithdrawalPaymaster.PayoutBelowCost.selector);
    }

    function test_notPendingEscape() public {
        uint32 id = _bigNote(42);
        address s = factory.createAccount(ownerAddr, payee);
        PackedUserOperation memory op = _op(s, _nonce(s, 5), "", _callData(_finalizeCall(id)), _gas(FINALIZE, false));
        _refused(_resign(op), ZkApiWithdrawalPaymaster.NotPendingEscape.selector);
        // a pending escape of another destination
        vm.prank(user);
        vault.initiateEscapeWithdrawal(_escape(id, 2001, 2002, BIG - 2_000_000, 1_000_000), PROOF);
        vm.warp(_deadline(id));
        op = _finalizeOp(id);
        _refused(op, ZkApiWithdrawalPaymaster.DestinationNotSender.selector);
        // finalized by a third party
        vault.finalizeEscapeWithdrawal(id);
        op = _finalizeOp(id);
        _refused(op, ZkApiWithdrawalPaymaster.NotPendingEscape.selector);
    }

    function test_notStranded() public {
        address s = factory.createAccount(ownerAddr, payee);
        vm.deal(s, 0.05 ether);
        PackedUserOperation memory op = _forwardOp();
        _refusedUncounted(op, ZkApiWithdrawalPaymaster.NotStranded.selector, _forwardKey(s));
        paymaster.allowForward(s);
        (bool ok,) = _tryHandle(op);
        assertTrue(ok);
    }

    // ------------------------------------------------------------------ conventions and order

    /// maxFeePerGas == 0 skips the checks that depend on maxCost (ceilings, policy cap, payout) but
    /// none of the state checks.
    function test_estimationConvention() public {
        uint32 id = _bigNote(42);
        OpGas memory g = _gas(CLOSE, true);
        g.maxFee = 0;
        g.priority = 0;
        ZkApiWithdrawalPaymaster.Policy memory p = _defaultPolicy();
        p.maxSponsoredCost = 1;
        paymaster.setPolicy(p);
        factory.createAccount(ownerAddr, payee);
        (PackedUserOperation memory op,) = _closeOp(id, 1001, 1); // a payout of 1 gwei
        op = _withGas(op, g);
        (, bytes memory context,) = _validateDirect(op);
        assertEq(context.length, 288, "accepted in estimation");
        // state checks still apply
        vm.prank(user);
        vault.mutualClose(_close(id, 9, BIG), PROOF);
        (op,) = _closeOp(id, 1001, 1);
        op = _withGas(op, g);
        _refused(op, ZkApiWithdrawalPaymaster.NoteNotActive.selector);
    }

    /// The adapter is consulted last: a refused proof is reported only when every cheap check passed.
    function test_adapterIsCalledLast() public {
        vm.etch(address(adapter), address(new RejectingWithdrawals()).code);
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs,) = _closeReady();
        _refused(op, Errors.InvalidProof.selector);
        inputs.kind = KIND_ESCAPE;
        _refused(_withInputs(op, inputs, false), ZkApiWithdrawalPaymaster.WrongKind.selector);
        inputs = _closeTo(inputs.noteId, 1001, BIG + 1, op.sender);
        _refused(_withInputs(op, inputs, false), ZkApiWithdrawalPaymaster.InvalidBalance.selector);
    }

    function test_validationDataPacking() public {
        address s = factory.createAccount(ownerAddr, payee);
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs,) = _closeReady();
        (, bytes memory context, uint256 data) = _validateDirect(op);
        assertEq(context.length, 288, "fixed-size context (EREP-055)");
        assertEq(uint48(data >> 160), inputs.validUntil, "validUntil");
        assertEq(data >> 208, 0, "no validAfter");
        assertEq(uint160(data), 0, "no aggregator, no failure");
        // finalize: valid from the deadline on
        uint32 id2 = _bigNote(43);
        vm.prank(user);
        vault.initiateEscapeWithdrawal(_escapeTo(id2, 2001, 2002, BIG - 2_000_000, 1_000_000, s), PROOF);
        uint64 deadline = _deadline(id2);
        (,, data) = _validateDirect(_finalizeOp(id2));
        assertEq(uint48(data >> 160), 0, "finalize has no validUntil");
        assertEq(uint48(data >> 208), deadline, "validAfter = challengeDeadline");
        // forward: no window
        vm.deal(s, 0.05 ether);
        paymaster.allowForward(s);
        (,, data) = _validateDirect(_forwardOp());
        assertEq(data, 0);
    }

    /// Validation reads only the paymaster's and the vault's storage and writes only attempts (and,
    /// for a forward, the evidence it consumes).
    function test_validationStorageAccess() public {
        (PackedUserOperation memory op,,) = _closeReady();
        address s = factory.createAccount(ownerAddr, payee);
        op.initCode = "";
        op = _resign(op);
        vm.record();
        _validateDirect(op);
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(paymaster));
        assertGt(reads.length, 0);
        assertEq(writes.length, 1, "one write");
        assertEq(writes[0], keccak256(abi.encode(_closeKey(1001), ATTEMPTS_SLOT)), "attempts[key]");
        (, writes) = vm.accesses(address(vault));
        assertEq(writes.length, 0, "the vault is read only");
        (reads, writes) = vm.accesses(s);
        assertEq(reads.length + writes.length, 0, "the account has no storage");
        (reads, writes) = vm.accesses(address(factory));
        assertEq(reads.length + writes.length, 0, "the factory reads no storage");
        (reads, writes) = vm.accesses(address(adapter));
        assertEq(reads.length + writes.length, 0, "the adapter reads no storage");
        // a forward consumes the evidence
        vm.deal(s, 0.05 ether);
        paymaster.allowForward(s);
        vm.record();
        _validateDirect(_forwardOp());
        (, writes) = vm.accesses(address(paymaster));
        assertEq(writes.length, 2, "evidence and attempts");
        assertEq(writes[0], keccak256(abi.encode(s, STRANDED_SLOT)), "stranded[S] consumed");
        assertEq(writes[1], keccak256(abi.encode(_forwardKey(s), ATTEMPTS_SLOT)), "attempts[key]");
    }

    /// The clock never changes a validation outcome.
    function test_validationIsTimeIndependent() public {
        (PackedUserOperation memory op,,) = _closeReady();
        factory.createAccount(ownerAddr, payee);
        op.initCode = "";
        op = _resign(op);
        uint256[3] memory times = [uint256(1), 1_700_000_000, type(uint48).max];
        bytes32 expected;
        for (uint256 i = 0; i < 3; ++i) {
            uint256 snap = vm.snapshotState();
            vm.warp(times[i]);
            (, bytes memory context, uint256 data) = _validateDirect(op);
            bytes32 outcome = keccak256(abi.encode(context, data));
            if (i == 0) expected = outcome;
            else assertEq(outcome, expected, "same outcome");
            vm.revertToState(snap);
        }
    }

    // ------------------------------------------------------------------ ERC-7562 opcode audit
    // The audit itself (GaslessTestBase._audit) traces handleOps and checks every validation frame
    // but the EntryPoint's and the SenderCreator's; RealAdapter.t.sol runs it with the real adapter.

    function test_opcodeAudit_firstUseClose() public {
        (PackedUserOperation memory op,,) = _closeReady();
        _audit(op, true, false);
    }

    function test_opcodeAudit_escape() public {
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op,) = _escapeOp(id, 2001, 2002, BIG - 2_000_000, 1_000_000);
        _audit(op, true, false);
    }

    function test_opcodeAudit_finalize() public {
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op,) = _escapeOp(id, 2001, 2002, BIG - 2_000_000, 1_000_000);
        _handle(op);
        vm.warp(_deadline(id));
        _audit(_finalizeOp(id), false, false);
    }

    function test_opcodeAudit_forward() public {
        address s = factory.createAccount(ownerAddr, payee);
        vm.deal(s, 0.05 ether);
        paymaster.allowForward(s);
        _audit(_forwardOp(), false, true);
    }
}
