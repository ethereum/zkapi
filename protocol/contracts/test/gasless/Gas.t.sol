// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Groth16ProofAdapter} from "../../src/adapters/Groth16ProofAdapter.sol";
import {IEntryPoint, PackedUserOperation} from "../../src/gasless/IERC4337.sol";
import {GaslessTestBase, GasBurner, Rejecter, Acceptor, EntryPointDriver} from "./GaslessTestBase.sol";

/// @dev The measurements behind the paymaster's gas constants, pinned in snapshots/gasless-gas.json
///      (FORGE_SNAPSHOT_CHECK compares them in CI). Direct calls from the driver replay the
///      EntryPoint's sequence and isolate what S measures, what its call costs around that window,
///      and what postOp costs on each path; the least verificationGasLimit the EntryPoint accepts is
///      searched through handleOps; end-to-end runs give each shape's real gas and show the pinned
///      constants land the charge within MARGIN_GAS of the real cost. The constants are checked
///      against the measurements: every floor exceeds its need by the stated slack.
///
///      Every number is a transaction with every account and slot cold, from a deployment in its
///      steady state (a funded treasury and payee), with the mock adapter unless stated. Forge
///      keeps the EIP-2929 warm set for the whole test function (every account and slot a test
///      touches, through a call or a cheatcode, stays warm; vm.cool cools an account's slots but
///      not its address), so the cold discipline is: setUp prepares every scenario (notes, transit
///      accounts, prior operations, the clock, the signed operations themselves), each test's first
///      EntryPoint or paymaster interaction is the measured one, and a second measurement in the
///      same test comes after vm.revertToState to the state at the test's start, which restores
///      the cold set as well as the state.
///
///      Forge rewrites snapshots/gasless-gas.json with the values of the run only: a targeted run
///      (--match-path, --match-test) leaves a truncated file. Regenerate it with a full `forge test`
///      from protocol/contracts before committing; CI checks it with FORGE_SNAPSHOT_CHECK=true.
contract GasTest is GaslessTestBase {
    string constant GROUP = "gasless-gas";
    uint256 constant FEE = 11 gwei;
    uint256 constant PRE_GAS = 280_000;
    uint256 constant VALIDATION_GAS_SLACK = 4_000;
    uint256 constant CALL_STIPEND = 2_300;

    // The scenarios setUp prepares, one transit account each so that none disturbs another.
    uint8 constant SC_CLOSE_EOA = 1; // a close from an existing S to a funded EOA
    uint8 constant SC_CLOSE_EMPTY = 2; // ... to a never-used address
    uint8 constant SC_CLOSE_DRAINED = 3; // ... to a used, drained EOA
    uint8 constant SC_CLOSE_BURNER = 4; // ... to a payee that burns the push
    uint8 constant SC_CLOSE_REJECTER = 5; // ... to a payee that refuses the push
    uint8 constant SC_CLOSE_ACCEPTOR = 6; // ... to a payee with code that accepts
    uint8 constant SC_ESCAPE = 7; // an escape initiation from an existing S
    uint8 constant SC_ESCAPE_WITH_BALANCE = 8; // ... from an S that holds a direct payout
    uint8 constant SC_FINALIZE = 9; // the finalization of a sponsored escape (a debt to deduct)
    uint8 constant SC_FINALIZE_NO_DEBT = 10; // the finalization of a direct escape paid to S
    uint8 constant SC_FORWARD = 11; // a forward of a balance the owner allowed
    uint8 constant SC_REVERTED = 12; // the postOp context of a validated close (nothing arrived)
    uint8 constant SC_REVERTED_WITH_DEBT = 13; // ... of a finalization whose payout arrived, with a debt
    uint8 constant SC_REVERTED_NO_DEBT = 14; // ... the same with the debt written off
    uint8 constant SC_CLOSE_FIRST = 15; // a first-use close (initCode) to a funded EOA
    uint8 constant SC_CLOSE_REPEAT = 16; // a second close from an S a sponsored close created
    uint8 constant SC_CLOSE_EMPTY_FIRST = 17; // a first-use close to a never-used address
    uint8 constant SC_CLOSE_DRAINED_FIRST = 18; // ... to a drained EOA
    uint8 constant SC_CLOSE_BURNER_FIRST = 19; // ... to a burning payee
    uint8 constant SC_ESCAPE_FIRST = 20; // a first-use escape initiation
    uint8 constant SC_MIN_VERIFICATION_INIT = 21; // the verificationGasLimit search with initCode
    uint8 constant SC_MIN_VERIFICATION = 22; // ... without
    uint8 constant SC_COLLECT = 23; // a sweep of an S with a balance

    address constant EMPTY_PAYEE = address(0xE3A7);
    address constant EMPTY_PAYEE_FIRST = address(0xE3A6);
    address constant DRAINED_PAYEE = address(0xD4A1);
    address constant DRAINED_PAYEE_FIRST = address(0xD4A2);

    struct Prepared {
        address sender;
        address payee;
        uint32 noteId;
        uint256 nonce;
        bytes initCode;
        bytes callData;
        bytes op;
        bytes32 hash;
        bytes vaultCall;
        bytes context;
    }

    mapping(uint8 => Prepared) prepared;
    Groth16ProofAdapter realAdapter;
    /// The test tree holds eight notes: the operations setUp only prepares all exit this one
    /// (each test starts from setUp's state, and a second measurement follows a revert to it),
    /// the operations setUp executes get a note each.
    uint32 sharedNote;
    uint256 nextNullifier = 1001;
    uint256 nextCommitment = 42;

    function setUp() public {
        _setUpGasless();
        realAdapter = new Groth16ProofAdapter();
        // a funded treasury: the vault's push to it is never a new-account transfer
        vm.prank(user);
        vault.mutualClose(_close(_bigNote(nextCommitment++), nextNullifier++, BIG - 1_000_000), PROOF);
        vm.deal(payee, 1 ether);
        vm.setNonce(DRAINED_PAYEE, 3);
        vm.setNonce(DRAINED_PAYEE_FIRST, 3);
        // the escapes executed here first: their finalizations share one deadline the clock is
        // then moved to
        uint32 deadlineNote = _prepSponsoredEscape(SC_FINALIZE);
        _prepSponsoredEscape(SC_REVERTED_WITH_DEBT);
        _prepSponsoredEscape(SC_REVERTED_NO_DEBT);
        _prepDirectEscape(SC_FINALIZE_NO_DEBT);
        vm.warp(_deadline(deadlineNote));
        _prepFinalize(SC_FINALIZE);
        _prepFinalize(SC_FINALIZE_NO_DEBT);
        _prepRevertedFinalize(SC_REVERTED_WITH_DEBT, false);
        _prepRevertedFinalize(SC_REVERTED_NO_DEBT, true);
        // the other operations executed here, then the note every prepared exit names
        _prepRepeatClose(SC_CLOSE_REPEAT);
        _prepEscapeWithBalance(SC_ESCAPE_WITH_BALANCE);
        sharedNote = _bigNote(nextCommitment++);
        assertEq(sharedNote, 7, "the test tree's last slot");
        // the closes
        _prepClose(SC_CLOSE_EOA, _fundedPayee(SC_CLOSE_EOA), true);
        _prepClose(SC_CLOSE_EMPTY, EMPTY_PAYEE, true);
        _prepClose(SC_CLOSE_DRAINED, DRAINED_PAYEE, true);
        _prepClose(SC_CLOSE_BURNER, address(new GasBurner()), true);
        _prepClose(SC_CLOSE_REJECTER, address(new Rejecter()), true);
        _prepClose(SC_CLOSE_ACCEPTOR, address(new Acceptor()), true);
        _prepClose(SC_CLOSE_FIRST, payee, false);
        _prepClose(SC_CLOSE_EMPTY_FIRST, EMPTY_PAYEE_FIRST, false);
        _prepClose(SC_CLOSE_DRAINED_FIRST, DRAINED_PAYEE_FIRST, false);
        _prepClose(SC_CLOSE_BURNER_FIRST, address(new GasBurner()), false);
        _prepClose(SC_CLOSE_REPEAT, prepared[SC_CLOSE_REPEAT].payee, false);
        _prepRevertedClose(SC_REVERTED);
        // the escapes measured from an existing S, the first-use one, the one with a balance
        _prepEscape(SC_ESCAPE, _fundedPayee(SC_ESCAPE), true, sharedNote);
        _prepEscape(SC_ESCAPE_FIRST, _fundedPayee(SC_ESCAPE_FIRST), false, sharedNote);
        _prepEscape(SC_ESCAPE_WITH_BALANCE, prepared[SC_ESCAPE_WITH_BALANCE].payee, false, sharedNote);
        // the forward, the sweep and the verification search
        _prepForward(SC_FORWARD);
        _prepCollect(SC_COLLECT);
        _prepMinVerification(SC_MIN_VERIFICATION_INIT, false);
        _prepMinVerification(SC_MIN_VERIFICATION, true);
    }

    // ----------------------------------------------------------------------------- preparation

    /// A funded EOA payee of its own for scenario `id`.
    function _fundedPayee(uint8 id) internal returns (address p) {
        p = address(uint160(0x9A7E00 + id));
        vm.deal(p, 1 ether);
    }

    function _store(uint8 id, PackedUserOperation memory op, bytes memory vaultCall) internal {
        Prepared storage p = prepared[id];
        p.sender = op.sender;
        p.op = abi.encode(op);
        p.hash = entryPoint.getUserOpHash(op);
        p.vaultCall = vaultCall;
    }

    /// A close of the shared note from the transit account of `payee_`, created first or left to
    /// the operation's initCode.
    function _prepClose(uint8 id, address payee_, bool create) internal {
        if (create) _createdTransit(ownerAddr, payee_);
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs) =
            _closeOpFor(payee_, sharedNote, nextNullifier++, BIG - 1_000_000);
        _store(id, op, _closeCall(inputs));
        prepared[id].payee = payee_;
        prepared[id].noteId = sharedNote;
    }

    /// A first close sponsored through handleOps (the second one, of the shared note, follows).
    function _prepRepeatClose(uint8 id) internal {
        address payee_ = _fundedPayee(id);
        (PackedUserOperation memory first,) = _closeOpFor(payee_, _bigNote(nextCommitment++), nextNullifier++, BIG);
        _handle(first);
        prepared[id].payee = payee_;
    }

    /// A close validated from the driver: its postOp context, for the reverted-execution path.
    function _prepRevertedClose(uint8 id) internal {
        _prepClose(id, _fundedPayee(id), true);
        (, bytes memory context,) = _validateDirect(abi.decode(prepared[id].op, (PackedUserOperation)));
        prepared[id].context = context;
    }

    function _prepEscape(uint8 id, address payee_, bool create, uint32 note) internal {
        if (create) _createdTransit(ownerAddr, payee_);
        uint256 nullifier = nextNullifier;
        nextNullifier += 2;
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs) =
            _escapeOpFor(payee_, note, nullifier, nullifier + 1, BIG - 2_000_000, 1_000_000);
        _store(id, op, _escapeCall(inputs));
        prepared[id].payee = payee_;
        prepared[id].noteId = note;
    }

    /// An S that holds a direct payout (a close paid to it outside any sponsorship); its escape of
    /// the shared note follows.
    function _prepEscapeWithBalance(uint8 id) internal {
        address payee_ = _fundedPayee(id);
        address s = _createdTransit(ownerAddr, payee_);
        vm.prank(user);
        vault.mutualClose(_closeTo(_bigNote(nextCommitment++), nextNullifier++, BIG - 1_000_000, s), PROOF);
        prepared[id].payee = payee_;
    }

    /// A sponsored escape initiation of a note of its own through handleOps (a first use: S is
    /// created by it).
    function _prepSponsoredEscape(uint8 id) internal returns (uint32 note) {
        note = _bigNote(nextCommitment++);
        _prepEscape(id, _fundedPayee(id), false, note);
        _handle(abi.decode(prepared[id].op, (PackedUserOperation)));
    }

    /// A direct escape paid to an existing S (no debt).
    function _prepDirectEscape(uint8 id) internal {
        address payee_ = _fundedPayee(id);
        address s = _createdTransit(ownerAddr, payee_);
        uint32 note = _bigNote(nextCommitment++);
        uint256 nullifier = nextNullifier;
        nextNullifier += 2;
        vm.prank(user);
        vault.initiateEscapeWithdrawal(_escapeTo(note, nullifier, nullifier + 1, BIG - 2_000_000, 1_000_000, s), PROOF);
        prepared[id].payee = payee_;
        prepared[id].noteId = note;
    }

    /// The finalization of the scenario's pending escape, after its deadline.
    function _prepFinalize(uint8 id) internal {
        Prepared storage p = prepared[id];
        _store(id, _finalizeOpFor(p.payee, p.noteId), _finalizeCall(p.noteId));
    }

    /// The finalization executed from the driver without its postOp: the payout reached S and P,
    /// and the context is what a reverted execution's postOp would then receive.
    function _prepRevertedFinalize(uint8 id, bool writeOff) internal {
        _prepFinalize(id);
        if (writeOff) paymaster.writeOffDebt(prepared[id].sender);
        prepared[id].context = _runPrepared(id, 0, 0).context;
    }

    function _prepForward(uint8 id) internal {
        address payee_ = _fundedPayee(id);
        address s = _createdTransit(ownerAddr, payee_);
        vm.deal(s, 0.05 ether);
        paymaster.allowForward(s);
        _store(id, _forwardOpFor(payee_), "");
        prepared[id].payee = payee_;
    }

    function _prepCollect(uint8 id) internal {
        address s = _createdTransit(ownerAddr, _fundedPayee(id));
        vm.deal(s, 0.05 ether);
        prepared[id].sender = s;
    }

    /// The parts of a close the verification search assembles per probe (a probe may touch
    /// nothing before handleOps): the sender, its nonce, the initCode and the callData.
    function _prepMinVerification(uint8 id, bool create) internal {
        address payee_ = _fundedPayee(id);
        if (create) _createdTransit(ownerAddr, payee_);
        address s = _transit(ownerAddr, payee_);
        uint32 note = sharedNote;
        uint256 nullifier = nextNullifier++;
        Prepared storage p = prepared[id];
        p.sender = s;
        p.nonce = _nonce(s, uint192(nullifier));
        p.initCode = create ? bytes("") : _initCode(ownerAddr, payee_);
        p.callData = _callData(_closeCall(_closeTo(note, nullifier, BIG - 1_000_000, s)));
    }

    // ------------------------------------------------------------------------------ measuring

    function _snap(string memory name, uint256 value) internal {
        vm.snapshotValue(GROUP, name, value);
    }

    function _op(uint8 id) internal view returns (PackedUserOperation memory) {
        return abi.decode(prepared[id].op, (PackedUserOperation));
    }

    /// Validation, withdraw and (with a nonzero actualGasCost) postOp of a prepared operation from
    /// the driver.
    function _runPrepared(uint8 id, uint256 actualGasCost, uint256 feePerGas)
        internal
        returns (EntryPointDriver.Run memory)
    {
        PackedUserOperation memory op = _op(id);
        Prepared storage p = prepared[id];
        return driver.run(paymaster, op, p.hash, _maxCostOf(op), p.vaultCall, actualGasCost, feePerGas);
    }

    function _closeRun(uint8 id) internal returns (EntryPointDriver.Run memory) {
        return _runPrepared(id, PRE_GAS * FEE, FEE);
    }

    // ------------------------------------------------------------------------ direct measurements

    /// CLOSE: S's window, the call around it, the validation and postOp with a funded EOA payee.
    function test_measure_close() public {
        EntryPointDriver.Run memory r = _closeRun(SC_CLOSE_EOA);
        _snap("validationCloseMockCold", r.validationGas);
        _snap("accountCallClose", r.withdrawGas);
        _snap("accountMeasuredClose", r.measuredGas);
        _snap("postOpEoa", r.postOpGas);
        uint256 overhead = r.withdrawGas - r.measuredGas;
        assertGe(gp.accountCallOverheadGas, overhead, "the overhead constant covers the measured overhead");
        assertLe(gp.accountCallOverheadGas, overhead + 4_000, "and little more (innerHandleOp's own work)");
        assertLe(gp.postOpBaseGas + gp.eoaPushGas, r.postOpGas, "postOp base + push pinned at or under the measurement");
        assertGe(gp.postOpBaseGas + gp.eoaPushGas + 10_000, r.postOpGas, "and not far under");
    }

    function test_measure_closeEmptyPayee() public {
        uint256 cold = vm.snapshotState();
        uint256 eoa = _closeRun(SC_CLOSE_EOA).postOpGas;
        vm.revertToState(cold);
        EntryPointDriver.Run memory r = _closeRun(SC_CLOSE_EMPTY);
        _snap("postOpEmptyEoa", r.postOpGas);
        assertGe(gp.newAccountGas + 100, r.postOpGas - eoa, "the EIP-161 surcharge");
        assertLe(gp.newAccountGas, r.postOpGas - eoa);
    }

    /// A used and drained EOA (nonce > 0, zero balance) is not empty under EIP-161: the push costs
    /// what a funded one costs and no new-account surcharge is charged.
    function test_measure_closeDrainedPayee() public {
        uint256 cold = vm.snapshotState();
        uint256 eoa = _closeRun(SC_CLOSE_EOA).postOpGas;
        vm.revertToState(cold);
        EntryPointDriver.Run memory r = _closeRun(SC_CLOSE_DRAINED);
        _snap("postOpDrainedEoa", r.postOpGas);
        assertLe(r.postOpGas, eoa + 200, "no surcharge");
        assertGe(r.postOpGas + 200, eoa);
    }

    function test_measure_closeBurner() public {
        uint256 cold = vm.snapshotState();
        uint256 eoa = _closeRun(SC_CLOSE_EOA).postOpGas;
        vm.revertToState(cold);
        EntryPointDriver.Run memory r = _closeRun(SC_CLOSE_BURNER);
        _snap("postOpWorst", r.postOpGas);
        uint256 extra = r.postOpGas - eoa;
        assertLe(
            extra,
            gp.payoutPushGas + CALL_STIPEND + gp.creditGas + 500,
            "the burn, the stipend and the credit bookkeeping"
        );
        assertGe(extra, gp.payoutPushGas + gp.creditGas - 2_000);
        assertGe(
            gp.postOpFloor,
            r.postOpGas + gp.postOpFinalizeExtraGas + 30_000 + 30_000,
            "the floor leaves the worst path 30k headroom"
        );
    }

    function test_measure_closeRejecter() public {
        uint256 cold = vm.snapshotState();
        uint256 eoa = _closeRun(SC_CLOSE_EOA).postOpGas;
        vm.revertToState(cold);
        EntryPointDriver.Run memory r = _closeRun(SC_CLOSE_REJECTER);
        _snap("postOpRejecter", r.postOpGas);
        uint256 extra = r.postOpGas - eoa;
        assertLe(extra, gp.creditGas + 500, "the credit bookkeeping of a refused push");
        assertGe(extra, gp.creditGas - 2_000);
    }

    function test_measure_closeAcceptor() public {
        EntryPointDriver.Run memory r = _closeRun(SC_CLOSE_ACCEPTOR);
        _snap("postOpAcceptor", r.postOpGas);
    }

    function test_measure_escape() public {
        EntryPointDriver.Run memory r = _closeRun(SC_ESCAPE);
        _snap("validationEscapeMockCold", r.validationGas);
        _snap("accountCallEscape", r.withdrawGas);
        _snap("accountMeasuredEscape", r.measuredGas);
        _snap("postOpEscape", r.postOpGas);
        uint256 overhead = r.withdrawGas - r.measuredGas;
        assertGe(gp.accountCallOverheadEscapeGas, overhead);
        assertLe(gp.accountCallOverheadEscapeGas, overhead + 4_000);
        assertLe(gp.postOpEscapeGas, r.postOpGas);
        assertGe(gp.postOpEscapeGas + 10_000, r.postOpGas);
    }

    /// An escape initiation from an S that holds a direct payout: the balance settles the debt
    /// (deposited) and the rest is credited, which the forward constant covers.
    function test_measure_escapeWithBalance() public {
        EntryPointDriver.Run memory r = _closeRun(SC_ESCAPE_WITH_BALANCE);
        _snap("accountCallEscapeWithBalance", r.withdrawGas);
        _snap("postOpEscapeWithBalance", r.postOpGas);
        Prepared storage p = prepared[SC_ESCAPE_WITH_BALANCE];
        assertEq(p.sender.balance, 0, "forwarded");
        assertGt(paymaster.credits(p.payee), 0, "the rest was credited");
        assertEq(paymaster.owed(p.sender), 0, "the debt was settled");
        assertLe(gp.postOpEscapeGas + gp.postOpEscapeForwardGas, r.postOpGas, "pinned under the measurement");
    }

    /// The same path end to end: the charge sits above the real cost and within the margin plus the
    /// credit bookkeeping of it (the end-to-end accounting is what the constant is pinned from).
    function test_endToEndEscapeWithBalance() public {
        Vm.Log[] memory logs = _handle(_op(SC_ESCAPE_WITH_BALANCE));
        (bool success, uint256 actualGasCost, uint256 actualGasUsed) = _userOpEvent(logs);
        assertTrue(success);
        SettledEvent memory e = _settled(logs);
        assertEq(e.received, uint256(BIG - 1_000_000) * 1 gwei);
        assertEq(actualGasCost, actualGasUsed * FEE);
        uint256 chargedGas = (e.charged - FLAT_FEE) / FEE;
        assertGe(chargedGas, actualGasUsed, "never under the real cost");
        assertLe(chargedGas - actualGasUsed, gp.marginGas + gp.creditGas, "the margin and the credit over it");
        _snap("handleOpsEscapeWithBalance", actualGasUsed);
        _snap("overchargeEscapeWithBalance", chargedGas - actualGasUsed);
    }

    /// SC_FINALIZE with and without a debt to deduct, against the plain close's postOp: what a
    /// finalization adds to the settling path sits between the two differences.
    function test_measure_finalize() public {
        uint256 cold = vm.snapshotState();
        uint256 eoa = _closeRun(SC_CLOSE_EOA).postOpGas;
        vm.revertToState(cold);
        EntryPointDriver.Run memory r = _closeRun(SC_FINALIZE);
        _snap("validationFinalizeMockCold", r.validationGas);
        _snap("accountCallFinalize", r.withdrawGas);
        _snap("accountMeasuredFinalize", r.measuredGas);
        _snap("postOpFinalize", r.postOpGas);
        uint256 overhead = r.withdrawGas - r.measuredGas;
        assertGe(gp.accountCallOverheadGas, overhead);
        assertLe(gp.accountCallOverheadGas, overhead + 4_000);
        assertEq(paymaster.owed(prepared[SC_FINALIZE].sender), 0, "the debt was deducted");
        vm.revertToState(cold);
        uint256 noDebt = _closeRun(SC_FINALIZE_NO_DEBT).postOpGas;
        _snap("postOpFinalizeNoDebt", noDebt);
        assertGe(gp.postOpFinalizeExtraGas + eoa, noDebt, "the finalize extra covers a finalization without a debt");
        assertLe(gp.postOpFinalizeExtraGas + eoa, r.postOpGas, "and sits under one with a debt");
    }

    /// The reverted-execution path as the in-bundle replay of a close leaves it: nothing arrived,
    /// S is stranded, the loss is recorded. FAILURE_POSTOP_GAS bounds it in the lostWei metric.
    function test_measure_postOpReverted() public {
        Prepared storage p = prepared[SC_REVERTED];
        uint256 plain = driver.postOpReverted(paymaster, p.context, PRE_GAS * FEE, FEE);
        _snap("postOpReverted", plain);
        assertLe(plain, 70_000, "within FAILURE_POSTOP_GAS");
        assertEq(paymaster.received(p.sender), 0);
        assertTrue(paymaster.stranded(p.sender));
    }

    /// The reverted-execution path with a balance to settle: an unsponsored finalization of S ran
    /// earlier in the bundle, so postOp deducts the escape's debt (deposited) and credits the rest.
    /// Pins what the debt settlement adds to that path (FAILURE_DEBT_DEPOSIT_GAS bounds it in the
    /// lostWei metric) and that the floor leaves it 30k headroom.
    function test_measure_postOpRevertedWithDebt() public {
        uint256 cold = vm.snapshotState();
        Prepared storage p = prepared[SC_REVERTED_WITH_DEBT];
        assertEq(paymaster.received(p.sender), uint256(BIG - 2_000_000) * 1 gwei, "the finalization reached S and P");
        assertGt(paymaster.owed(p.sender), 0);
        uint256 withDebt = driver.postOpReverted(paymaster, p.context, PRE_GAS * FEE, FEE);
        _snap("postOpRevertedWithDebt", withDebt);
        assertEq(paymaster.owed(p.sender), 0, "the debt is settled on the reverted path too");
        vm.revertToState(cold);
        p = prepared[SC_REVERTED_NO_DEBT];
        assertEq(paymaster.owed(p.sender), 0, "written off");
        uint256 noDebt = driver.postOpReverted(paymaster, p.context, PRE_GAS * FEE, FEE);
        _snap("postOpRevertedNoDebt", noDebt);
        // FAILURE_POSTOP_GAS (70,000) + FAILURE_DEBT_DEPOSIT_GAS (20,000) + CREDIT_GAS bound the path.
        assertLe(withDebt - noDebt, 20_000, "the debt settlement within FAILURE_DEBT_DEPOSIT_GAS");
        assertLe(noDebt, 70_000 + gp.creditGas, "the rest within FAILURE_POSTOP_GAS + CREDIT_GAS");
        assertGe(gp.postOpFloor, withDebt + 30_000, "the floor leaves the reverted path 30k headroom");
    }

    function test_measure_forward() public {
        EntryPointDriver.Run memory r = _closeRun(SC_FORWARD);
        _snap("validationForwardMockCold", r.validationGas);
        _snap("accountCallForward", r.withdrawGas);
        _snap("accountMeasuredForward", r.measuredGas);
        _snap("postOpForward", r.postOpGas);
        uint256 overhead = r.withdrawGas - r.measuredGas;
        assertGe(gp.accountCallOverheadGas, overhead);
        assertLe(gp.accountCallOverheadGas, overhead + 4_000);
    }

    // ---------------------------------------------------------------------------- the floors

    /// The least verificationGasLimit the EntryPoint accepts (AA26 or AA13 below it), with and
    /// without initCode; the paymaster's floor check runs only after the EntryPoint's own.
    function test_measure_minVerificationGas() public {
        uint256 withInit = _searchMinVerification(SC_MIN_VERIFICATION_INIT);
        _snap("minVerificationGasWithInitCode", withInit);
        uint256 without = _searchMinVerification(SC_MIN_VERIFICATION);
        _snap("minVerificationGasWithoutInitCode", without);
        assertGe(
            gp.verificationFloorInit,
            withInit + VALIDATION_GAS_SLACK,
            "floor with initCode above the need plus the slack"
        );
        assertLe(gp.verificationFloorInit, withInit + VALIDATION_GAS_SLACK + 10_000, "rounded up to 10k");
        assertGe(gp.verificationFloor, without + VALIDATION_GAS_SLACK, "floor above the need plus the slack");
        assertLe(gp.verificationFloor, without + VALIDATION_GAS_SLACK + 10_000, "rounded up to 10k");
    }

    /// Every probe runs from the state at the test's start (cold), restored after it.
    function _searchMinVerification(uint8 id) internal returns (uint256 lo) {
        lo = 20_000;
        uint256 hi = 400_000;
        while (lo < hi) {
            uint256 mid = (lo + hi) / 2;
            if (_verificationFits(id, mid)) hi = mid;
            else lo = mid + 1;
        }
    }

    function _verificationFits(uint8 id, uint256 limit) internal returns (bool fits) {
        uint256 snap = vm.snapshotState();
        Prepared storage p = prepared[id];
        bool init = p.initCode.length != 0;
        OpGas memory g = _gas(CLOSE, init);
        g.verification = limit;
        PackedUserOperation memory op = _op(p.sender, p.nonce, p.initCode, p.callData, g);
        op = _sign(op, OWNER_KEY);
        (bool ok, bytes memory data) = _tryHandle(op);
        // success, or the paymaster's floor refusal (which comes after the EntryPoint's AA26/AA13)
        fits = ok || bytes4(data) == IEntryPoint.FailedOpWithRevert.selector;
        vm.revertToState(snap);
    }

    /// The call floors cover the measured execution through S with the real adapter, a treasury
    /// that uses its whole 100,000-gas push, a never-used account (25,000), the 63/64 rule and a
    /// margin; the vault's own exits with real proofs sit well under them.
    function test_callFloorsCoverTheRealExecution() public {
        string memory fixtures = vm.readFile("test/fixtures/vault-challenge.json");
        Types.WithdrawalPublicInputs memory inputs =
            abi.decode(vm.parseJsonBytes(fixtures, ".close_b0.inputs_abi"), (Types.WithdrawalPublicInputs));
        bytes memory proof = vm.parseJsonBytes(fixtures, ".close_b0.proof_hex");
        uint256 cold = vm.snapshotState();
        uint256 adapterGas = driver.verify(realAdapter, inputs, proof);
        vm.revertToState(cold);
        uint256 closeCall = _runPrepared(SC_CLOSE_EOA, 0, 0).withdrawGas;
        uint256 vaultExtras = 100_000 + 25_000;
        assertGe(gp.callFloor[0], (closeCall + adapterGas + vaultExtras) * 64 / 63 + 20_000, "close floor");
        vm.revertToState(cold);
        uint256 escapeCall = _runPrepared(SC_ESCAPE, 0, 0).withdrawGas;
        assertGe(gp.callFloor[1], (escapeCall + adapterGas + 25_000) * 64 / 63 + 20_000, "escape floor");
        vm.revertToState(cold);
        uint256 finalizeCall = _runPrepared(SC_FINALIZE, 0, 0).withdrawGas;
        assertGe(gp.callFloor[2], (finalizeCall + vaultExtras) * 64 / 63 + 20_000, "finalize floor");
        vm.revertToState(cold);
        uint256 forwardCall = _runPrepared(SC_FORWARD, 0, 0).withdrawGas;
        assertGe(gp.callFloor[3], forwardCall * 64 / 63 + 20_000, "forward floor");
        assertLt(gp.callFloor[0], gp.callHardCap[0]);
        assertLt(gp.callFloor[1], gp.callHardCap[1]);
        assertLt(gp.callFloor[2], gp.callHardCap[2]);
        assertLt(gp.callFloor[3], gp.callHardCap[3]);
    }

    // -------------------------------------------------------------------------- end to end

    /// The real charge against the real cost of one operation through handleOps, both pinned
    /// (handleOps<name>, overcharge<name>): the overcharge in gas units must sit in [0, MARGIN_GAS]
    /// for an EOA payee (a credited payout adds the CREDIT_GAS surcharge).
    function _overcharge(uint8 id, bool eoaPayee, string memory name) internal {
        Vm.Log[] memory logs = _handle(_op(id));
        (bool success,, uint256 actualGasUsed) = _userOpEvent(logs);
        assertTrue(success);
        SettledEvent memory e = _settled(logs);
        assertTrue(e.found);
        uint256 chargedGas = (e.charged - FLAT_FEE) / FEE;
        assertGe(chargedGas, actualGasUsed, "never under the real cost");
        if (eoaPayee) assertLe(chargedGas - actualGasUsed, gp.marginGas, "at most the margin over it");
        else assertLe(chargedGas - actualGasUsed, gp.marginGas + gp.creditGas, "the margin and the credit over it");
        _snap(string.concat("handleOps", name), actualGasUsed);
        _snap(string.concat("overcharge", name), chargedGas - actualGasUsed);
    }

    function test_endToEndCloseFirstUse() public {
        assertEq(_op(SC_CLOSE_FIRST).initCode.length, 88, "first use");
        _overcharge(SC_CLOSE_FIRST, true, "CloseFirstUse");
    }

    function test_endToEndCloseRepeat() public {
        assertEq(_op(SC_CLOSE_REPEAT).initCode.length, 0, "an S a sponsored close created");
        _overcharge(SC_CLOSE_REPEAT, true, "CloseRepeat");
    }

    function test_endToEndCloseEmptyPayee() public {
        _overcharge(SC_CLOSE_EMPTY_FIRST, true, "CloseEmptyPayee");
    }

    function test_endToEndCloseDrainedPayee() public {
        _overcharge(SC_CLOSE_DRAINED_FIRST, true, "CloseDrainedPayee");
    }

    function test_endToEndCloseBurner() public {
        _overcharge(SC_CLOSE_BURNER_FIRST, false, "CloseBurner");
    }

    /// Each shape of the escape path, cold: the initiation (a first use), the finalization of a
    /// sponsored escape, the forward of an allowed balance and the finalization of a direct escape.
    function test_endToEndEscapeFinalizeForward() public {
        uint256 cold = vm.snapshotState();
        _overcharge(SC_ESCAPE_FIRST, true, "Escape");
        vm.revertToState(cold);
        _overcharge(SC_FINALIZE, true, "Finalize");
        vm.revertToState(cold);
        _overcharge(SC_FORWARD, true, "Forward");
        vm.revertToState(cold);
        _overcharge(SC_FINALIZE_NO_DEBT, true, "FinalizeNoDebt");
    }

    /// The sweep by a transit account outside an operation.
    function test_collect() public {
        _snap("sweepCollect", driver.sweep(prepared[SC_COLLECT].sender));
    }
}
