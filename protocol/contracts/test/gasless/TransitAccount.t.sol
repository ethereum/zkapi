// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {ZkApiVault} from "../../src/ZkApiVault.sol";
import {Types} from "../../src/libraries/Types.sol";
import {PackedUserOperation} from "../../src/gasless/IERC4337.sol";
import {ZkApiWithdrawalAccount} from "../../src/gasless/ZkApiWithdrawalAccount.sol";
import {ZkApiWithdrawalAccountFactory} from "../../src/gasless/ZkApiWithdrawalAccountFactory.sol";
import {ZkApiWithdrawalPaymaster} from "../../src/gasless/ZkApiWithdrawalPaymaster.sol";
import {ToggleableDestination} from "../NativeEthVault.t.sol";
import {GaslessTestBase} from "./GaslessTestBase.sol";

/// @dev A contract that answers owner()/payee() like a transit account but is not one.
contract FakeAccount {
    address public owner;
    address public payee;

    constructor(address owner_, address payee_) {
        owner = owner_;
        payee = payee_;
    }

    function repay(ZkApiWithdrawalPaymaster paymaster, uint256 gasUsed) external payable {
        paymaster.repay{value: msg.value}(gasUsed);
    }

    function collect(ZkApiWithdrawalPaymaster paymaster) external payable {
        paymaster.collect{value: msg.value}();
    }

    receive() external payable {}
}

/// @dev The transit account: factory refusals and determinism, the proxy's argument plumbing, the
///      owner-only signature check that never reverts, the EntryPoint-only entry points, repay and
///      collect provenance, and sweep.
contract TransitAccountTest is GaslessTestBase {
    ZkApiWithdrawalAccount impl;

    function setUp() public {
        _setUpGasless();
        impl = factory.implementation();
    }

    // ------------------------------------------------------------------------------ creation

    function test_createAccountRefusesAnUnusablePayeeOrOwner() public {
        address[5] memory bad = [address(0), address(vault), address(paymaster), ENTRY_POINT, address(factory)];
        for (uint256 i = 0; i < bad.length; ++i) {
            vm.expectRevert(ZkApiWithdrawalAccountFactory.InvalidPayee.selector);
            factory.createAccount(ownerAddr, bad[i]);
        }
        vm.expectRevert(ZkApiWithdrawalAccountFactory.InvalidPayee.selector);
        factory.createAccount(address(0), payee);
    }

    function test_createAccountIsDeterministicAndIdempotent() public {
        address predicted = factory.getAddress(ownerAddr, payee);
        bytes memory creationCode = factory.accountCreationCode();
        assertEq(creationCode.length, 74, "creation code bytes");
        assertEq(keccak256(creationCode), factory.accountCreationCodeHash(), "creation code hash");
        assertEq(factory.accountCreationCodeHash(), paymaster.accountCreationCodeHash(), "paymaster pin");
        bytes memory initCode = abi.encodePacked(
            creationCode, abi.encode(ENTRY_POINT, address(vault), address(paymaster), ownerAddr, payee)
        );
        assertEq(predicted, vm.computeCreate2Address(bytes32(0), keccak256(initCode), address(factory)), "CREATE2");
        assertEq(predicted.code.length, 0);

        vm.recordLogs();
        address created = factory.createAccount(ownerAddr, payee);
        assertEq(created, predicted);
        assertEq(created.code.length, 221, "proxy bytes");
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertEq(_count(logs, address(factory), ZkApiWithdrawalAccountFactory.AccountCreated.selector), 1);
        // the proxy's code is the logic (61 bytes, with the implementation address) then the arguments
        bytes memory code = created.code;
        bytes memory args = new bytes(160);
        for (uint256 i = 0; i < 160; ++i) {
            args[i] = code[61 + i];
        }
        assertEq(args, abi.encode(ENTRY_POINT, address(vault), address(paymaster), ownerAddr, payee), "embedded args");
        assertEq(creationCode.length - 13, 61, "stub then logic");
        for (uint256 i = 0; i < 61; ++i) {
            assertEq(code[i], creationCode[13 + i], "logic bytes");
        }

        vm.recordLogs();
        assertEq(factory.createAccount(ownerAddr, payee), created, "idempotent");
        assertEq(vm.getRecordedLogs().length, 0, "no second creation");
        assertEq(paymaster.transitAccount(ownerAddr, payee), created);
    }

    function test_argumentsAreReadThroughTheProxy() public {
        ZkApiWithdrawalAccount s = ZkApiWithdrawalAccount(payable(factory.createAccount(ownerAddr, payee)));
        assertEq(s.entryPoint(), ENTRY_POINT);
        assertEq(s.vault(), address(vault));
        assertEq(s.paymaster(), address(paymaster));
        assertEq(s.owner(), ownerAddr);
        assertEq(s.payee(), payee);
        assertEq(s.SELECTOR_WITHDRAW(), ZkApiWithdrawalAccount.withdraw.selector);
        assertEq(s.ARGS_LENGTH(), 160);
        // the logic contract itself has no arguments
        vm.expectRevert(ZkApiWithdrawalAccount.NotProxy.selector);
        impl.owner();
        vm.expectRevert(ZkApiWithdrawalAccount.NotProxy.selector);
        impl.sweep();
        (bool ok,) = address(impl).call{value: 1}("");
        assertFalse(ok, "the logic contract refuses ETH");
        // and a direct call whose calldata ends in a crafted argument tail is refused all the same:
        // the logic never relays a call or sends a balance of its own
        vm.deal(address(impl), 1 ether);
        bytes memory crafted = abi.encodePacked(
            abi.encodeCall(
                ZkApiWithdrawalAccount.withdraw, (abi.encodeCall(ZkApiVault.mutualClose, (_close(0, 1, 1), PROOF)))
            ),
            abi.encode(address(this), address(vault), address(this), address(0), address(0))
        );
        bytes memory ret;
        (ok, ret) = address(impl).call(crafted);
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(ZkApiWithdrawalAccount.NotProxy.selector), "withdraw with a tail");
        (ok, ret) = address(impl)
            .call(
                abi.encodePacked(
                    abi.encodeCall(ZkApiWithdrawalAccount.sweep, ()), abi.encode(0, 0, address(this), 0, 0)
                )
            );
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(ZkApiWithdrawalAccount.NotProxy.selector), "sweep with a tail");
        (ok, ret) = address(impl).call{value: 1}(new bytes(160));
        assertFalse(ok);
        assertEq(ret, abi.encodeWithSelector(ZkApiWithdrawalAccount.NotProxy.selector), "the fallback with a tail");
        assertEq(address(impl).balance, 1 ether, "nothing left the logic contract");
        // an unknown selector through the proxy is refused; a bare transfer is accepted
        (ok,) = address(s).call(abi.encodeWithSelector(bytes4(0x12345678)));
        assertFalse(ok, "unknown call");
        (ok,) = address(s).call{value: 1 ether}("");
        assertTrue(ok, "receive");
        assertEq(address(s).balance, 1 ether);
    }

    // ---------------------------------------------------------------------------- validation

    function _unsigned() internal returns (ZkApiWithdrawalAccount s, PackedUserOperation memory op, bytes32 hash) {
        s = ZkApiWithdrawalAccount(payable(factory.createAccount(ownerAddr, payee)));
        uint32 id = _bigNote(42);
        (op,) = _closeOp(id, 1001, BIG - 1_000_000);
        hash = entryPoint.getUserOpHash(op);
    }

    function _validate(ZkApiWithdrawalAccount s, PackedUserOperation memory op, bytes memory signature)
        internal
        returns (uint256)
    {
        op.signature = signature;
        bytes32 hash = entryPoint.getUserOpHash(op);
        vm.prank(ENTRY_POINT);
        return s.validateUserOp(op, hash, 0);
    }

    function test_validateUserOpAcceptsOnlyTheOwnersSignature() public {
        (ZkApiWithdrawalAccount s, PackedUserOperation memory op, bytes32 hash) = _unsigned();
        bytes32 digest = keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", hash));
        (uint8 v, bytes32 r, bytes32 sv) = vm.sign(OWNER_KEY, digest);
        assertEq(_validate(s, op, abi.encodePacked(r, sv, v)), 0, "owner");
        assertEq(_validate(s, op, abi.encodePacked(r, sv, v - 27)), 0, "owner, v as 0/1");
        (uint8 v2, bytes32 r2, bytes32 s2) = vm.sign(OTHER_KEY, digest);
        assertEq(_validate(s, op, abi.encodePacked(r2, s2, v2)), 1, "another signer");
        assertEq(_validate(s, op, abi.encodePacked(r, sv)), 1, "64 bytes");
        assertEq(_validate(s, op, abi.encodePacked(r, sv, v, uint8(0))), 1, "66 bytes");
        assertEq(_validate(s, op, ""), 1, "empty");
        assertEq(_validate(s, op, abi.encodePacked(r, sv, uint8(29))), 1, "bad v");
        // the malleable twin (n - s, flipped v) recovers the same signer but is refused
        uint256 n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
        bytes32 highS = bytes32(n - uint256(sv));
        uint8 flipped = v == 27 ? 28 : 27;
        assertEq(ecrecover(digest, flipped, r, highS), ownerAddr, "twin recovers");
        assertEq(_validate(s, op, abi.encodePacked(r, highS, flipped)), 1, "high s");
        // a signature over a different hash
        (v, r, sv) = vm.sign(OWNER_KEY, keccak256("other"));
        assertEq(_validate(s, op, abi.encodePacked(r, sv, v)), 1, "wrong digest");
        // only the EntryPoint may ask
        op.signature = abi.encodePacked(r, sv, v);
        vm.expectRevert(ZkApiWithdrawalAccount.NotEntryPoint.selector);
        s.validateUserOp(op, hash, 0);
    }

    // ------------------------------------------------------------------------ entry points

    function test_withdrawOnlyFromTheEntryPointAndOnlyInsideASponsoredOperation() public {
        ZkApiWithdrawalAccount s = ZkApiWithdrawalAccount(payable(factory.createAccount(ownerAddr, payee)));
        vm.expectRevert(ZkApiWithdrawalAccount.NotEntryPoint.selector);
        s.withdraw("");
        vm.prank(address(paymaster));
        vm.expectRevert(ZkApiWithdrawalAccount.NotEntryPoint.selector);
        s.withdraw("");
        // the EntryPoint outside a sponsored operation: repay refuses, nothing moves
        vm.deal(address(s), 1 ether);
        vm.prank(ENTRY_POINT);
        vm.expectRevert(ZkApiWithdrawalPaymaster.NotRepayable.selector);
        s.withdraw("");
        assertEq(address(s).balance, 1 ether);
        // a vault call that reverts bubbles the vault's error bytes
        uint32 id = _bigNote(42);
        Types.WithdrawalPublicInputs memory inputs = _closeTo(id, 1001, BIG, address(s));
        inputs.kind = KIND_ESCAPE;
        vm.prank(ENTRY_POINT);
        vm.expectRevert(
            abi.encodeWithSelector(
                ZkApiWithdrawalAccount.VaultCallFailed.selector,
                abi.encodeWithSelector(bytes4(keccak256("WrongWithdrawalKind()")))
            )
        );
        s.withdraw(_closeCall(inputs));
    }

    function test_repayAndCollectOnlyFromAFactoryCreatedAccount() public {
        address s = factory.createAccount(ownerAddr, payee);
        // an EOA
        vm.deal(user, 1 ether);
        vm.prank(user);
        vm.expectRevert(ZkApiWithdrawalPaymaster.NotRepayable.selector);
        paymaster.repay{value: 1}(1);
        vm.prank(user);
        vm.expectRevert(ZkApiWithdrawalPaymaster.NotRepayable.selector);
        paymaster.collect{value: 1}();
        // a contract answering owner()/payee() like S
        FakeAccount fake = new FakeAccount(ownerAddr, payee);
        vm.deal(address(fake), 1 ether);
        vm.expectRevert(ZkApiWithdrawalPaymaster.NotRepayable.selector);
        fake.repay{value: 1}(paymaster, 1);
        vm.expectRevert(ZkApiWithdrawalPaymaster.NotRepayable.selector);
        fake.collect{value: 1}(paymaster);
        // the same proxy code and arguments deployed by another deployer
        bytes memory initCode = abi.encodePacked(
            factory.accountCreationCode(), abi.encode(ENTRY_POINT, address(vault), address(paymaster), ownerAddr, payee)
        );
        address clone;
        assembly ("memory-safe") {
            clone := create2(0, add(initCode, 0x20), mload(initCode), 0)
        }
        assertTrue(clone != address(0) && clone != s, "clone elsewhere");
        assertEq(ZkApiWithdrawalAccount(payable(clone)).payee(), payee);
        vm.deal(clone, 1 ether);
        vm.prank(ENTRY_POINT);
        vm.expectRevert(ZkApiWithdrawalPaymaster.NotRepayable.selector);
        ZkApiWithdrawalAccount(payable(clone)).withdraw("");
        vm.expectRevert(ZkApiWithdrawalPaymaster.NotRepayable.selector);
        ZkApiWithdrawalAccount(payable(clone)).sweep();
        // the real account: collect accepts (repay needs the sponsorship in flight)
        vm.deal(s, 1 ether);
        ZkApiWithdrawalAccount(payable(s)).sweep();
        assertEq(payee.balance, 1 ether);
    }

    // ------------------------------------------------------------------------------- sweep

    function test_sweepRoutesThroughCollectAndPaysTheDebtFirst() public {
        // a sponsored escape leaves a debt on S
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op,) = _escapeOp(id, 2001, 2002, BIG - 2_000_000, 1_000_000);
        _handle(op);
        address s = op.sender;
        uint256 debt = paymaster.owed(s);
        assertGt(debt, 0);
        ZkApiWithdrawalAccount account = ZkApiWithdrawalAccount(payable(s));
        vm.expectRevert(ZkApiWithdrawalAccount.NothingToSweep.selector);
        account.sweep();
        // a balance smaller than the debt: all of it repays
        vm.deal(s, debt / 2);
        uint256 depositBefore = entryPoint.balanceOf(address(paymaster));
        vm.recordLogs();
        vm.prank(user);
        account.sweep();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        (bool found, Vm.Log memory log) = _find(logs, address(paymaster), ZkApiWithdrawalPaymaster.Collected.selector);
        assertTrue(found);
        (uint256 received, uint256 owedPaid, uint256 paidOut) = abi.decode(log.data, (uint256, uint256, uint256));
        assertEq(received, debt / 2);
        assertEq(owedPaid, debt / 2);
        assertEq(paidOut, 0);
        assertEq(paymaster.owed(s), debt - debt / 2);
        assertEq(entryPoint.balanceOf(address(paymaster)) - depositBefore, debt / 2);
        assertEq(payee.balance, 0);
        assertEq(s.balance, 0);
        // a larger balance: the rest of the debt, then the payee
        vm.deal(s, 1 ether);
        account.sweep();
        assertEq(paymaster.owed(s), 0);
        assertEq(payee.balance, 1 ether - (debt - debt / 2));
        assertEq(s.balance, 0);
        assertEq(address(paymaster).balance, 0);
    }

    function test_sweepCreditsARejectingPayee() public {
        ToggleableDestination wallet = new ToggleableDestination();
        address s = factory.createAccount(ownerAddr, address(wallet));
        vm.deal(s, 1 ether);
        vm.recordLogs();
        ZkApiWithdrawalAccount(payable(s)).sweep();
        Vm.Log[] memory logs = vm.getRecordedLogs();
        assertTrue(_has(logs, address(paymaster), ZkApiWithdrawalPaymaster.PayoutCredited.selector));
        assertEq(paymaster.credits(address(wallet)), 1 ether);
        assertEq(paymaster.totalCredits(), 1 ether);
        assertEq(address(paymaster).balance, 1 ether);
        vm.expectRevert(ZkApiWithdrawalPaymaster.NativeTransferFailed.selector);
        paymaster.claimCredit(address(wallet));
        wallet.setAccepting(true);
        vm.prank(user);
        paymaster.claimCredit(address(wallet));
        assertEq(address(wallet).balance, 1 ether);
        assertEq(paymaster.credits(address(wallet)), 0);
        assertEq(paymaster.totalCredits(), 0);
        vm.expectRevert(ZkApiWithdrawalPaymaster.ZeroAmount.selector);
        paymaster.claimCredit(address(wallet));
    }

    // ----------------------------------------------------------------------------- receive

    function test_receiveWithinTheVaultsPushes() public {
        address s = factory.createAccount(ownerAddr, payee);
        uint32 id = _bigNote(42);
        vm.prank(user);
        vault.initiateEscapeWithdrawal(_escapeTo(id, 2001, 2002, BIG - 2_000_000, 1_000_000, s), PROOF);
        vm.warp(_deadline(id));
        vault.finalizeEscapeWithdrawal(id);
        assertEq(s.balance, uint256(BIG - 2_000_000) * 1 gwei, "the 100k push landed");
        assertEq(vault.escapePayoutCredits(s), 0);
        uint32 id2 = _bigNote(43);
        vm.prank(user);
        vault.mutualClose(_closeTo(id2, 3001, BIG, s), PROOF);
        assertEq(s.balance, uint256(BIG - 2_000_000) * 1 gwei + uint256(BIG) * 1 gwei, "the full-gas push landed");
    }
}
