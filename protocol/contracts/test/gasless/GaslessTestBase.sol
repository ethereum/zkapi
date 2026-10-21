// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {console} from "forge-std/console.sol";
import {ZkApiVault} from "../../src/ZkApiVault.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Bn254Poseidon} from "../../src/libraries/Bn254Poseidon.sol";
import {IAccount, IEntryPoint, IPaymaster, PackedUserOperation} from "../../src/gasless/IERC4337.sol";
import {IZkApiProofAdapter} from "../../src/interfaces/IZkApiProofAdapter.sol";
import {ZkApiWithdrawalAccount} from "../../src/gasless/ZkApiWithdrawalAccount.sol";
import {ZkApiWithdrawalAccountFactory} from "../../src/gasless/ZkApiWithdrawalAccountFactory.sol";
import {ZkApiWithdrawalPaymaster} from "../../src/gasless/ZkApiWithdrawalPaymaster.sol";
import {MockProofAdapter} from "../mocks/MockProofAdapters.sol";
import {VaultTestBase} from "../helpers/VaultTestBase.sol";

/// @dev A payee that burns every unit of gas it is given.
contract GasBurner {
    receive() external payable {
        while (true) {}
    }
}

/// @dev A payee that refuses ETH.
contract Rejecter {
    receive() external payable {
        revert("no");
    }
}

/// @dev A payee with code that accepts ETH cheaply.
contract Acceptor {
    receive() external payable {}
}

/// @dev An ordinary self-funded ERC-4337 account (no signature check) that executes one call: the
///      other party of a bundle in the griefing scenarios.
contract SelfFundedAccount is IAccount {
    address private immutable entryPoint;

    constructor(address entryPoint_) {
        entryPoint = entryPoint_;
    }

    receive() external payable {}

    function validateUserOp(PackedUserOperation calldata, bytes32, uint256 missingAccountFunds)
        external
        returns (uint256)
    {
        require(msg.sender == entryPoint, "not entrypoint");
        if (missingAccountFunds != 0) {
            (bool ok,) = entryPoint.call{value: missingAccountFunds}("");
            require(ok, "prefund");
        }
        return 0;
    }

    function execute(address target, bytes calldata data) external {
        require(msg.sender == entryPoint, "not entrypoint");
        (bool ok, bytes memory ret) = target.call(data);
        if (!ok) {
            assembly ("memory-safe") {
                revert(add(ret, 32), mload(ret))
            }
        }
    }
}

/// @dev Replays the EntryPoint's sequence for one operation (paymaster validation, the account's
///      withdraw, the paymaster's postOp) from one call tree at depth 1: Forge clears transient
///      storage between the test contract's own calls, and the paymaster's in-flight flag must
///      survive from validation to repay. Measuring from here rather than from the test contract
///      keeps the test contract's memory-expansion cost out of the numbers.
contract EntryPointDriver {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    address private constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;

    struct Run {
        uint256 validationGas;
        bytes context;
        uint256 validationData;
        uint256 withdrawGas;
        uint256 measuredGas;
        uint256 postOpGas;
    }

    function validate(
        ZkApiWithdrawalPaymaster paymaster,
        PackedUserOperation calldata op,
        bytes32 hash,
        uint256 maxCost
    ) external returns (uint256 gasUsed, bytes memory context, uint256 validationData) {
        vm.prank(ENTRY_POINT);
        uint256 g0 = gasleft();
        (context, validationData) = paymaster.validatePaymasterUserOp(op, hash, maxCost);
        gasUsed = g0 - gasleft();
    }

    /// Two validations of the same operation in one call tree: the first with every slot and
    /// contract cold, the second warm. A reverted-mode postOp between them releases the key lock
    /// the first validation took, as the EntryPoint would once the operation's outcome is state; it
    /// writes nothing a CLOSE or ESCAPE validation reads.
    function validateTwice(
        ZkApiWithdrawalPaymaster paymaster,
        PackedUserOperation calldata op,
        bytes32 hash,
        uint256 maxCost
    ) external returns (uint256 cold, uint256 warm) {
        vm.prank(ENTRY_POINT);
        uint256 g0 = gasleft();
        (bytes memory context,) = paymaster.validatePaymasterUserOp(op, hash, maxCost);
        cold = g0 - gasleft();
        vm.prank(ENTRY_POINT);
        paymaster.postOp(IPaymaster.PostOpMode.opReverted, context, 0, 0);
        vm.prank(ENTRY_POINT);
        g0 = gasleft();
        paymaster.validatePaymasterUserOp(op, hash, maxCost);
        warm = g0 - gasleft();
    }

    /// Validation then withdraw; `actualGasCost` of 0 skips postOp.
    function run(
        ZkApiWithdrawalPaymaster paymaster,
        PackedUserOperation calldata op,
        bytes32 hash,
        uint256 maxCost,
        bytes calldata vaultCall,
        uint256 actualGasCost,
        uint256 feePerGas
    ) external returns (Run memory r) {
        vm.prank(ENTRY_POINT);
        uint256 g0 = gasleft();
        (r.context, r.validationData) = paymaster.validatePaymasterUserOp(op, hash, maxCost);
        r.validationGas = g0 - gasleft();
        vm.prank(ENTRY_POINT);
        g0 = gasleft();
        ZkApiWithdrawalAccount(payable(op.sender)).withdraw(vaultCall);
        r.withdrawGas = g0 - gasleft();
        r.measuredGas = paymaster.receivedGas(op.sender);
        if (actualGasCost == 0) return r;
        bytes memory context = r.context;
        vm.prank(ENTRY_POINT);
        g0 = gasleft();
        paymaster.postOp(IPaymaster.PostOpMode.opSucceeded, context, actualGasCost, feePerGas);
        r.postOpGas = g0 - gasleft();
    }

    /// A reverted execution's postOp (nothing was received).
    function postOpReverted(
        ZkApiWithdrawalPaymaster paymaster,
        bytes calldata context,
        uint256 actualGasCost,
        uint256 feePerGas
    ) external returns (uint256 gasUsed) {
        vm.prank(ENTRY_POINT);
        uint256 g0 = gasleft();
        paymaster.postOp(IPaymaster.PostOpMode.opReverted, context, actualGasCost, feePerGas);
        gasUsed = g0 - gasleft();
    }

    /// A sweep of `s` outside an operation, measured from depth 1.
    function sweep(address s) external returns (uint256 gasUsed) {
        uint256 g0 = gasleft();
        ZkApiWithdrawalAccount(payable(s)).sweep();
        gasUsed = g0 - gasleft();
    }

    /// The real adapter's verification alone, as the paymaster calls it.
    function verify(IZkApiProofAdapter adapter, Types.WithdrawalPublicInputs calldata inputs, bytes calldata proof)
        external
        view
        returns (uint256 gasUsed)
    {
        uint256 g0 = gasleft();
        adapter.assertValidWithdrawal(inputs, proof);
        gasUsed = g0 - gasleft();
    }
}

/// @dev The canonical EntryPoint v0.7.0 and its SenderCreator etched at their mainnet addresses
///      (fixtures pinned by keccak256), a mock-adapter vault, the paymaster (which deploys the
///      factory) and the builders every gasless test uses: operations with the profile's default
///      gas fields, EIP-191 signatures from a fixed owner key, handleOps from a bundler, and the
///      decoding of the EntryPoint's and the paymaster's events. Deployment runs from a fixed
///      deployer with a reset nonce, so every address is the same in every test (Golden.t.sol pins
///      them). Notes deposited here are 0.1 ETH so a payout covers a sponsorship's maxCost.
abstract contract GaslessTestBase is VaultTestBase {
    address internal constant ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    address internal constant SENDER_CREATOR = 0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C;
    bytes32 internal constant ENTRY_POINT_CODEHASH = 0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58;
    bytes32 internal constant SENDER_CREATOR_CODEHASH =
        0x283c9d14378f5f4c4e24045b87d621d48443fa5b4af7dd7180a599b3756a7689;
    address internal constant DEPLOYER = address(0xDE91);
    uint256 internal constant OWNER_KEY = 0xA11CE;
    uint256 internal constant OTHER_KEY = 0xB0B;
    uint32 internal constant UNSTAKE_DELAY = 86_400;
    uint8 internal constant CLOSE = 1;
    uint8 internal constant ESCAPE = 2;
    uint8 internal constant FINALIZE = 3;
    uint8 internal constant FORWARD = 4;
    uint128 internal constant BIG = 100_000_000; // 0.1 ether in gwei units
    uint256 internal constant BASEFEE = 10 gwei;
    uint256 internal constant MAX_FEE = 20 gwei;
    uint256 internal constant PRIORITY = 1 gwei;
    uint256 internal constant FLAT_FEE = 1e13;
    uint256 internal constant MIN_ESCAPE_NET = 1e14;
    uint256 internal constant MAX_FEE_CEILING = 100 gwei;
    uint256 internal constant PRIORITY_CEILING = 5 gwei;
    uint256 internal constant INITIAL_DEPOSIT = 10 ether;

    IEntryPoint internal entryPoint = IEntryPoint(ENTRY_POINT);
    EntryPointDriver internal driver;
    ZkApiWithdrawalPaymaster internal paymaster;
    ZkApiWithdrawalAccountFactory internal factory;
    ZkApiWithdrawalPaymaster.GasPolicy internal gp;
    address internal ownerAddr = vm.addr(OWNER_KEY);
    address internal payee = address(0x9A7EE);
    address internal bundler = address(0xB0DD1E);
    address payable internal beneficiary = payable(address(0xBE9EF));
    bytes internal proof256;

    struct OpGas {
        uint256 pvg;
        uint256 verification;
        uint256 call;
        uint256 pmVerification;
        uint256 postOp;
        uint256 maxFee;
        uint256 priority;
        uint256 feeCap;
    }

    struct SettledEvent {
        bool found;
        bytes32 key;
        address sender;
        address payee;
        uint8 kind;
        uint32 noteId;
        uint256 received;
        uint256 charged;
        uint256 owedPaid;
        uint256 paidOut;
    }

    // ------------------------------------------------------------------------------------ setup

    function _etchEntryPoint() internal {
        vm.etch(ENTRY_POINT, vm.parseBytes(vm.trim(vm.readFile("test/fixtures/entrypoint-v0.7.0.runtime.hex"))));
        vm.etch(SENDER_CREATOR, vm.parseBytes(vm.trim(vm.readFile("test/fixtures/sender-creator-v0.7.0.runtime.hex"))));
        assertEq(ENTRY_POINT.code.length, 16_035, "entrypoint bytes");
        assertEq(SENDER_CREATOR.code.length, 451, "sender creator bytes");
        assertEq(ENTRY_POINT.codehash, ENTRY_POINT_CODEHASH, "entrypoint keccak");
        assertEq(SENDER_CREATOR.codehash, SENDER_CREATOR_CODEHASH, "sender creator keccak");
    }

    function _defaultPolicy() internal pure returns (ZkApiWithdrawalPaymaster.Policy memory) {
        return ZkApiWithdrawalPaymaster.Policy({
            maxSponsoredCost: 0.25 ether,
            flatFeeWei: uint64(FLAT_FEE),
            minEscapeNetWei: uint64(MIN_ESCAPE_NET),
            escapesEnabled: true,
            sponsorshipPaused: false
        });
    }

    /// Etches the EntryPoint, deploys adapter, vault and paymaster from DEPLOYER (nonces 0, 1, 2; the
    /// factory is the paymaster's nonce 1 and the account logic the factory's nonce 1), funds and
    /// stakes the paymaster and the factory.
    function _setUpGasless() internal {
        vm.warp(1_700_000_000);
        vm.fee(BASEFEE);
        _etchEntryPoint();
        uint256 zero;
        for (uint256 level = 0; level < 32; ++level) {
            emptySiblings[level] = zero;
            zero = Bn254Poseidon.compress(DOMAIN_NODE, zero, zero);
        }
        vm.setNonce(DEPLOYER, 0);
        vm.startPrank(DEPLOYER);
        adapter = new MockProofAdapter();
        vault = _newVault(CHALLENGE_PERIOD, MAX_PAUSE);
        paymaster = new ZkApiWithdrawalPaymaster(
            entryPoint, vault, address(this), _defaultPolicy(), MAX_FEE_CEILING, PRIORITY_CEILING
        );
        vm.stopPrank();
        factory = paymaster.factory();
        gp = paymaster.gasPolicy();
        driver = new EntryPointDriver();
        vm.deal(user, 100 ether);
        vm.deal(bundler, 10 ether);
        vm.deal(address(this), 100 ether);
        paymaster.deposit{value: INITIAL_DEPOSIT}();
        paymaster.addStake{value: 1 ether}(UNSTAKE_DELAY);
        factory.addStake{value: 1 ether}(UNSTAKE_DELAY);
        proof256 = new bytes(256);
        for (uint256 i = 0; i < 256; ++i) {
            proof256[i] = bytes1(uint8(i + 1));
        }
    }

    /// Deposits a note of `amount` gwei units at the next slot.
    function _depositUnits(uint256 commitment, uint128 amount) internal returns (uint32 id) {
        id = vault.nextNoteId();
        vm.prank(user);
        vault.deposit{value: uint256(amount) * 1 gwei}(bytes32(commitment), amount);
    }

    function _bigNote(uint256 commitment) internal returns (uint32 id) {
        return _depositUnits(commitment, BIG);
    }

    // --------------------------------------------------------------------------------- accounts

    function _transit(address owner_, address payee_) internal view returns (address) {
        return factory.getAddress(owner_, payee_);
    }

    function _initCode(address owner_, address payee_) internal view returns (bytes memory) {
        return abi.encodePacked(address(factory), abi.encodeCall(factory.createAccount, (owner_, payee_)));
    }

    function _createdTransit(address owner_, address payee_) internal returns (address) {
        return factory.createAccount(owner_, payee_);
    }

    // ------------------------------------------------------------------------------- statements

    /// A close of `noteId` at `nullifier` paying `finalBalance` to the transit account `sender`.
    function _closeTo(uint32 noteId, uint256 nullifier, uint128 finalBalance, address sender)
        internal
        view
        returns (Types.WithdrawalPublicInputs memory inputs)
    {
        inputs = _close(noteId, nullifier, finalBalance);
        inputs.destination = sender;
    }

    function _escapeTo(
        uint32 noteId,
        uint256 nullifier,
        uint256 next,
        uint128 finalBalance,
        uint128 conceded,
        address sender
    ) internal view returns (Types.WithdrawalPublicInputs memory inputs) {
        inputs = _escape(noteId, nullifier, next, finalBalance, conceded);
        inputs.destination = sender;
    }

    function _closeCall(Types.WithdrawalPublicInputs memory inputs) internal view returns (bytes memory) {
        return abi.encodeCall(ZkApiVault.mutualClose, (inputs, proof256));
    }

    function _escapeCall(Types.WithdrawalPublicInputs memory inputs) internal view returns (bytes memory) {
        return abi.encodeCall(ZkApiVault.initiateEscapeWithdrawal, (inputs, proof256));
    }

    function _finalizeCall(uint32 noteId) internal pure returns (bytes memory) {
        return abi.encodeCall(ZkApiVault.finalizeEscapeWithdrawal, (noteId));
    }

    function _callData(bytes memory vaultCall) internal pure returns (bytes memory) {
        return abi.encodeCall(ZkApiWithdrawalAccount.withdraw, (vaultCall));
    }

    // ------------------------------------------------------------------------------- operations

    /// The profile's default gas fields: every limit sits above its floor and under its cap.
    function _gas(uint8 kind, bool withInit) internal view returns (OpGas memory g) {
        g.pvg = gp.pvgFloor + 10_000;
        g.verification = withInit ? gp.verificationFloorInit + 40_000 : gp.verificationFloor + 20_000;
        g.call = gp.callFloor[kind - 1] + (gp.callHardCap[kind - 1] - gp.callFloor[kind - 1]) / 4;
        g.pmVerification = gp.pmVerificationFloor + 30_000;
        g.postOp = gp.postOpFloor + 20_000;
        g.maxFee = MAX_FEE;
        g.priority = PRIORITY;
        g.feeCap = FLAT_FEE;
    }

    function _paymasterAndData(OpGas memory g) internal view returns (bytes memory) {
        return abi.encodePacked(address(paymaster), uint128(g.pmVerification), uint128(g.postOp), uint96(g.feeCap));
    }

    function _op(address sender, uint256 nonce, bytes memory initCode, bytes memory callData, OpGas memory g)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op.sender = sender;
        op.nonce = nonce;
        op.initCode = initCode;
        op.callData = callData;
        op.accountGasLimits = bytes32((g.verification << 128) | g.call);
        op.preVerificationGas = g.pvg;
        op.gasFees = bytes32((g.priority << 128) | g.maxFee);
        op.paymasterAndData = _paymasterAndData(g);
    }

    /// The nonce of `sender` under `key` as the EntryPoint reports it (key << 64 | sequence).
    function _nonce(address sender, uint256 key) internal view returns (uint256) {
        return entryPoint.getNonce(sender, uint192(key));
    }

    /// The prefund the EntryPoint computes for `op`: the sum of its five gas limits times maxFeePerGas.
    function _maxCostOf(PackedUserOperation memory op) internal pure returns (uint256) {
        uint256 verification = uint256(op.accountGasLimits) >> 128;
        uint256 callGas = uint128(uint256(op.accountGasLimits));
        uint256 maxFee = uint128(uint256(op.gasFees));
        bytes memory pmd = op.paymasterAndData;
        uint256 pmVerification;
        uint256 postOp;
        assembly ("memory-safe") {
            pmVerification := shr(128, mload(add(pmd, 52)))
            postOp := shr(128, mload(add(pmd, 68)))
        }
        return (op.preVerificationGas + verification + callGas + pmVerification + postOp) * maxFee;
    }

    /// The paymaster's validation of `op` as the EntryPoint runs it, from the driver (one call tree).
    function _validateDirect(PackedUserOperation memory op)
        internal
        returns (uint256 gasUsed, bytes memory context, uint256 validationData)
    {
        return driver.validate(paymaster, op, entryPoint.getUserOpHash(op), _maxCostOf(op));
    }

    /// Validation, withdraw and (with a nonzero actualGasCost) postOp of `op` from the driver.
    function _run(PackedUserOperation memory op, bytes memory vaultCall, uint256 actualGasCost, uint256 feePerGas)
        internal
        returns (EntryPointDriver.Run memory)
    {
        return
            driver.run(paymaster, op, entryPoint.getUserOpHash(op), _maxCostOf(op), vaultCall, actualGasCost, feePerGas);
    }

    function _maxCost(OpGas memory g) internal pure returns (uint256) {
        return (g.pvg + g.verification + g.call + g.pmVerification + g.postOp) * g.maxFee;
    }

    function _gasPrice(OpGas memory g) internal pure returns (uint256) {
        if (g.maxFee == g.priority) return g.maxFee;
        uint256 withTip = g.priority + BASEFEE;
        return withTip < g.maxFee ? withTip : g.maxFee;
    }

    function _digest(PackedUserOperation memory op) internal view returns (bytes32) {
        return keccak256(abi.encodePacked("\x19Ethereum Signed Message:\n32", entryPoint.getUserOpHash(op)));
    }

    function _sign(PackedUserOperation memory op, uint256 key) internal view returns (PackedUserOperation memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, _digest(op));
        op.signature = abi.encodePacked(r, s, v);
        return op;
    }

    /// A signed close of `noteId` from the transit account of (ownerAddr, payee), with initCode when
    /// the account has no code yet.
    function _closeOp(uint32 noteId, uint256 nullifier, uint128 finalBalance)
        internal
        view
        returns (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs)
    {
        return _closeOpFor(payee, noteId, nullifier, finalBalance);
    }

    function _closeOpFor(address payee_, uint32 noteId, uint256 nullifier, uint128 finalBalance)
        internal
        view
        returns (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs)
    {
        address sender = _transit(ownerAddr, payee_);
        bool fresh = sender.code.length == 0;
        inputs = _closeTo(noteId, nullifier, finalBalance, sender);
        op = _op(
            sender,
            _nonce(sender, uint192(nullifier)),
            fresh ? _initCode(ownerAddr, payee_) : bytes(""),
            _callData(_closeCall(inputs)),
            _gas(CLOSE, fresh)
        );
        op = _sign(op, OWNER_KEY);
    }

    function _escapeOp(uint32 noteId, uint256 nullifier, uint256 next, uint128 finalBalance, uint128 conceded)
        internal
        view
        returns (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs)
    {
        return _escapeOpFor(payee, noteId, nullifier, next, finalBalance, conceded);
    }

    function _escapeOpFor(
        address payee_,
        uint32 noteId,
        uint256 nullifier,
        uint256 next,
        uint128 finalBalance,
        uint128 conceded
    ) internal view returns (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs) {
        address sender = _transit(ownerAddr, payee_);
        bool fresh = sender.code.length == 0;
        inputs = _escapeTo(noteId, nullifier, next, finalBalance, conceded, sender);
        op = _op(
            sender,
            _nonce(sender, uint192(nullifier)),
            fresh ? _initCode(ownerAddr, payee_) : bytes(""),
            _callData(_escapeCall(inputs)),
            _gas(ESCAPE, fresh)
        );
        op = _sign(op, OWNER_KEY);
    }

    function _finalizeOp(uint32 noteId) internal view returns (PackedUserOperation memory op) {
        return _finalizeOpFor(payee, noteId);
    }

    function _finalizeOpFor(address payee_, uint32 noteId) internal view returns (PackedUserOperation memory op) {
        address sender = _transit(ownerAddr, payee_);
        bool fresh = sender.code.length == 0;
        (,, uint256 nullifier,,,) = vault.pendingWithdrawals(noteId);
        op = _op(
            sender,
            _nonce(sender, uint192(nullifier)),
            fresh ? _initCode(ownerAddr, payee_) : bytes(""),
            _callData(_finalizeCall(noteId)),
            _gas(FINALIZE, fresh)
        );
        op = _sign(op, OWNER_KEY);
    }

    function _forwardOp() internal view returns (PackedUserOperation memory op) {
        return _forwardOpFor(payee);
    }

    function _forwardOpFor(address payee_) internal view returns (PackedUserOperation memory op) {
        address sender = _transit(ownerAddr, payee_);
        bool fresh = sender.code.length == 0;
        op = _op(
            sender,
            _nonce(sender, paymaster.FORWARD_NONCE_KEY()),
            fresh ? _initCode(ownerAddr, payee_) : bytes(""),
            _callData(""),
            _gas(FORWARD, fresh)
        );
        op = _sign(op, OWNER_KEY);
    }

    /// An operation of a self-funded account that executes `data` on `target` (no paymaster).
    function _selfFundedOp(SelfFundedAccount account, address target, bytes memory data)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op.sender = address(account);
        op.nonce = _nonce(address(account), 0);
        op.callData = abi.encodeCall(SelfFundedAccount.execute, (target, data));
        op.accountGasLimits = bytes32((uint256(100_000) << 128) | 900_000);
        op.preVerificationGas = 50_000;
        op.gasFees = bytes32((PRIORITY << 128) | MAX_FEE);
    }

    /// handleOps([replay, op]): a self-funded account executes `vaultCalldata` on the vault in the
    /// operation before `op`, so `op` passes validation and reverts in execution (the in-bundle
    /// front-run of section 2.6). Returns every log of the call.
    function _bundledWithReplay(PackedUserOperation memory op, bytes memory vaultCalldata)
        internal
        returns (Vm.Log[] memory logs)
    {
        SelfFundedAccount replayer = new SelfFundedAccount(ENTRY_POINT);
        vm.deal(address(replayer), 1 ether);
        PackedUserOperation[] memory ops = new PackedUserOperation[](2);
        ops[0] = _selfFundedOp(replayer, address(vault), vaultCalldata);
        ops[1] = op;
        logs = _handleOps(ops);
    }

    /// The UserOperationEvent of `sender` among a bundle's logs.
    function _userOpEventOf(Vm.Log[] memory logs, address sender)
        internal
        pure
        returns (bool success, uint256 actualGasCost, uint256 actualGasUsed)
    {
        for (uint256 i = 0; i < logs.length; ++i) {
            if (
                logs[i].emitter == ENTRY_POINT && logs[i].topics[0] == IEntryPoint.UserOperationEvent.selector
                    && address(uint160(uint256(logs[i].topics[2]))) == sender
            ) {
                (, success, actualGasCost, actualGasUsed) = abi.decode(logs[i].data, (uint256, bool, uint256, uint256));
                return (success, actualGasCost, actualGasUsed);
            }
        }
        revert("no UserOperationEvent for sender");
    }

    // --------------------------------------------------------------------------------- handling

    function _single(PackedUserOperation memory op) internal pure returns (PackedUserOperation[] memory ops) {
        ops = new PackedUserOperation[](1);
        ops[0] = op;
    }

    /// handleOps([op]) from the bundler; returns every log of the call.
    function _handle(PackedUserOperation memory op) internal returns (Vm.Log[] memory logs) {
        return _handleOps(_single(op));
    }

    function _handleOps(PackedUserOperation[] memory ops) internal returns (Vm.Log[] memory logs) {
        vm.recordLogs();
        vm.prank(bundler);
        entryPoint.handleOps(ops, beneficiary);
        logs = vm.getRecordedLogs();
    }

    /// handleOps([op]) that may revert; returns the revert data when it does.
    function _tryHandle(PackedUserOperation memory op) internal returns (bool ok, bytes memory data) {
        return _tryHandleOps(_single(op));
    }

    function _tryHandleOps(PackedUserOperation[] memory ops) internal returns (bool ok, bytes memory data) {
        vm.prank(bundler);
        (ok, data) = ENTRY_POINT.call(abi.encodeCall(IEntryPoint.handleOps, (ops, beneficiary)));
    }

    /// An unsponsored operation of a transit account (empty paymasterAndData, the account's own
    /// EntryPoint deposit pays) under nonce key `key`, signed by the owner.
    function _unsponsoredOp(address sender, uint192 key, bytes memory callData)
        internal
        view
        returns (PackedUserOperation memory op)
    {
        op = _op(sender, _nonce(sender, key), "", callData, _gas(CLOSE, false));
        op.paymasterAndData = "";
        op = _sign(op, OWNER_KEY);
    }

    /// Asserts that handleOps([op]) fails in the paymaster's validation with `selector` (AA33 with
    /// the paymaster's revert bytes), and that nothing was charged or counted.
    function _refused(PackedUserOperation memory op, bytes4 selector) internal returns (bytes memory inner) {
        uint256 depositBefore = entryPoint.balanceOf(address(paymaster));
        (bool ok, bytes memory data) = _tryHandle(op);
        assertFalse(ok, "handleOps should revert");
        string memory reason;
        (reason, inner) = _failedOpWithRevert(data);
        assertEq(reason, "AA33 reverted", "reason");
        assertEq(bytes4(inner), selector, "paymaster error");
        assertEq(entryPoint.balanceOf(address(paymaster)), depositBefore, "uncharged");
    }

    /// Decodes a FailedOpWithRevert(opIndex, reason, inner) revert.
    function _failedOpWithRevert(bytes memory data) internal pure returns (string memory reason, bytes memory inner) {
        assertEq(bytes4(data), IEntryPoint.FailedOpWithRevert.selector, "FailedOpWithRevert");
        (, reason, inner) = abi.decode(_body(data), (uint256, string, bytes));
    }

    /// Decodes a FailedOp(opIndex, reason) revert.
    function _failedOp(bytes memory data) internal pure returns (string memory reason) {
        assertEq(bytes4(data), IEntryPoint.FailedOp.selector, "FailedOp");
        (, reason) = abi.decode(_body(data), (uint256, string));
    }

    function _body(bytes memory data) internal pure returns (bytes memory body) {
        body = new bytes(data.length - 4);
        for (uint256 i = 0; i < body.length; ++i) {
            body[i] = data[i + 4];
        }
    }

    // ------------------------------------------------------------------------------------- logs

    function _find(Vm.Log[] memory logs, address emitter, bytes32 topic0)
        internal
        pure
        returns (bool found, Vm.Log memory log)
    {
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter == emitter && logs[i].topics[0] == topic0) return (true, logs[i]);
        }
    }

    function _count(Vm.Log[] memory logs, address emitter, bytes32 topic0) internal pure returns (uint256 n) {
        for (uint256 i = 0; i < logs.length; ++i) {
            if (logs[i].emitter == emitter && logs[i].topics[0] == topic0) ++n;
        }
    }

    /// The UserOperationEvent of the (single) operation: success, actualGasCost, actualGasUsed.
    function _userOpEvent(Vm.Log[] memory logs)
        internal
        pure
        returns (bool success, uint256 actualGasCost, uint256 actualGasUsed)
    {
        (bool found, Vm.Log memory log) = _find(logs, ENTRY_POINT, IEntryPoint.UserOperationEvent.selector);
        assertTrue(found, "UserOperationEvent");
        (, success, actualGasCost, actualGasUsed) = abi.decode(log.data, (uint256, bool, uint256, uint256));
    }

    function _settled(Vm.Log[] memory logs) internal view returns (SettledEvent memory e) {
        (bool found, Vm.Log memory log) = _find(logs, address(paymaster), ZkApiWithdrawalPaymaster.Settled.selector);
        if (!found) return e;
        e.found = true;
        e.key = log.topics[1];
        e.sender = address(uint160(uint256(log.topics[2])));
        e.payee = address(uint160(uint256(log.topics[3])));
        (e.kind, e.noteId, e.received, e.charged, e.owedPaid, e.paidOut) =
            abi.decode(log.data, (uint8, uint32, uint256, uint256, uint256, uint256));
    }

    function _has(Vm.Log[] memory logs, address emitter, bytes32 topic0) internal pure returns (bool found) {
        (found,) = _find(logs, emitter, topic0);
    }

    // ------------------------------------------------------------------------------------ keys

    function _closeKey(uint256 nullifier) internal view returns (bytes32) {
        return paymaster.keyFor(CLOSE, nullifier, 0, address(0));
    }

    function _escapeKey(uint32 noteId) internal view returns (bytes32) {
        return paymaster.keyFor(ESCAPE, 0, noteId, address(0));
    }

    function _finalizeKey(uint32 noteId) internal view returns (bytes32) {
        return paymaster.keyFor(FINALIZE, 0, noteId, address(0));
    }

    function _forwardKey(address sender) internal view returns (bytes32) {
        return paymaster.keyFor(FORWARD, 0, 0, sender);
    }

    // ------------------------------------------------------------------ ERC-7562 opcode audit

    uint8 internal constant OP_BALANCE = 0x31;
    uint8 internal constant OP_ORIGIN = 0x32;
    uint8 internal constant OP_GASPRICE = 0x3a;
    uint8 internal constant OP_EXTCODESIZE = 0x3b;
    uint8 internal constant OP_EXTCODECOPY = 0x3c;
    uint8 internal constant OP_EXTCODEHASH = 0x3f;
    uint8 internal constant OP_BLOCKHASH = 0x40;
    uint8 internal constant OP_COINBASE = 0x41;
    uint8 internal constant OP_TIMESTAMP = 0x42;
    uint8 internal constant OP_NUMBER = 0x43;
    uint8 internal constant OP_PREVRANDAO = 0x44;
    uint8 internal constant OP_GASLIMIT = 0x45;
    uint8 internal constant OP_SELFBALANCE = 0x47;
    uint8 internal constant OP_BASEFEE = 0x48;
    uint8 internal constant OP_BLOBHASH = 0x49;
    uint8 internal constant OP_BLOBBASEFEE = 0x4a;
    uint8 internal constant OP_SLOAD = 0x54;
    uint8 internal constant OP_SSTORE = 0x55;
    uint8 internal constant OP_GAS = 0x5a;
    uint8 internal constant OP_TLOAD = 0x5c;
    uint8 internal constant OP_TSTORE = 0x5d;
    uint8 internal constant OP_CREATE = 0xf0;
    uint8 internal constant OP_CALL = 0xf1;
    uint8 internal constant OP_CALLCODE = 0xf2;
    uint8 internal constant OP_DELEGATECALL = 0xf4;
    uint8 internal constant OP_CREATE2 = 0xf5;
    uint8 internal constant OP_STATICCALL = 0xfa;
    uint8 internal constant OP_INVALID = 0xfe;
    uint8 internal constant OP_SELFDESTRUCT = 0xff;

    /// ERC-7562 OP-011: the opcodes no validation frame may execute.
    function _forbidden(uint8 o) internal pure returns (bool) {
        return o == OP_TIMESTAMP || o == OP_NUMBER || o == OP_BASEFEE || o == OP_GASPRICE || o == OP_ORIGIN
            || o == OP_COINBASE || o == OP_BLOCKHASH || o == OP_PREVRANDAO || o == OP_GASLIMIT || o == OP_BLOBHASH
            || o == OP_BLOBBASEFEE || o == OP_SELFDESTRUCT || o == OP_CREATE || o == OP_CALLCODE || o == OP_INVALID;
    }

    /// Records handleOps([op]) and audits every frame of the validation phase (from the EntryPoint
    /// call to its innerHandleOp) except the EntryPoint's own and the SenderCreator's against
    /// ERC-7562: OP-011 (no forbidden opcode), OP-061 (no CALL with value), OP-012 (GAS only right
    /// before a call), OP-041/042/062 (every call and EXTCODE* target has code, or is a core
    /// precompile, or is the sender inside the factory frame) in every frame, and the storage rules
    /// as the design states them: SSTORE, TLOAD and TSTORE only in the paymaster, SLOAD only in the
    /// paymaster and the vault, BALANCE only in the staked paymaster (OP-080), CREATE2 only in the
    /// factory (OP-031). Needs the tracer (forge test -vvv, as CI runs it); without it the test is
    /// reported as skipped, never as passed. An operation whose validUntil has passed is accepted
    /// too: the EntryPoint applies the window after the paymaster's validation (AA32), so the
    /// whole validation phase is traced and the execution phase, which the audit does not cover,
    /// is not (the real Groth16 verification run twice would not fit in the trace).
    function _audit(PackedUserOperation memory op, bool expectCreate2, bool expectBalance) internal {
        bool tracer;
        try vm.startDebugTraceRecording() {
            tracer = true;
        } catch {}
        if (!tracer) {
            console.log("opcode audit needs the tracer: run forge test -vvv");
            vm.skip(true);
        }
        (bool ok, bytes memory data) = _tryHandle(op);
        Vm.DebugStep[] memory steps = vm.stopAndReturnDebugTraceRecording();
        // the trace starts in this contract; the audit covers the EntryPoint call, and the validation
        // phase ends when the EntryPoint calls innerHandleOp on itself
        uint256 start = steps.length;
        for (uint256 i = 0; i < steps.length; ++i) {
            if (steps[i].contractAddr == ENTRY_POINT) {
                start = i;
                break;
            }
        }
        uint256 end = steps.length;
        if (ok) {
            for (uint256 i = start; i < steps.length; ++i) {
                if (
                    steps[i].opcode == OP_CALL && steps[i].contractAddr == ENTRY_POINT
                        && steps[i].memoryInput.length >= 4 && bytes4(steps[i].memoryInput) == bytes4(0x0042dc53)
                ) {
                    end = i;
                    break;
                }
            }
            assertLt(end, steps.length, "innerHandleOp found");
        } else {
            assertEq(_failedOp(data), "AA32 paymaster expired or not due", "only the window cut the operation short");
        }
        uint256 create2s;
        uint256 balances;
        uint256 audited;
        uint256 paymasterSteps;
        for (uint256 i = start; i < end; ++i) {
            Vm.DebugStep memory st = steps[i];
            address frame = st.contractAddr;
            if (frame == ENTRY_POINT || frame == SENDER_CREATOR) continue;
            ++audited;
            if (frame == address(paymaster)) ++paymasterSteps;
            uint8 o = st.opcode;
            assertFalse(_forbidden(o), "OP-011: forbidden opcode");
            if (o == OP_CREATE2) {
                assertEq(frame, address(factory), "OP-031: CREATE2 only in the factory frame");
                ++create2s;
            }
            if (o == OP_GAS) {
                uint8 next = steps[i + 1].opcode;
                assertEq(steps[i + 1].contractAddr, frame, "GAS then a call in the same frame");
                assertTrue(
                    next == OP_CALL || next == OP_CALLCODE || next == OP_DELEGATECALL || next == OP_STATICCALL,
                    "OP-012: GAS only before a call"
                );
            }
            if (o == OP_CALL) {
                assertEq(st.stack[2], 0, "OP-061: no CALL with value in validation");
                assertTrue(address(uint160(st.stack[1])).code.length != 0, "OP-041: CALL target has code");
            }
            if (o == OP_STATICCALL || o == OP_DELEGATECALL) {
                address target = address(uint160(st.stack[1]));
                assertTrue(
                    target.code.length != 0 || uint160(target) <= 9,
                    "OP-041/062: target has code or is a core precompile"
                );
            }
            if (o == OP_EXTCODESIZE || o == OP_EXTCODEHASH || o == OP_EXTCODECOPY) {
                address target = address(uint160(st.stack[0]));
                assertTrue(
                    target.code.length != 0 || (frame == address(factory) && target == op.sender),
                    "OP-041/042: EXTCODE* on an address with code (the sender in the factory frame excepted)"
                );
            }
            if (o == OP_SSTORE || o == OP_TLOAD || o == OP_TSTORE) {
                assertEq(frame, address(paymaster), "STO-031: only the paymaster writes storage here");
            }
            if (o == OP_SLOAD) {
                assertTrue(
                    frame == address(paymaster) || frame == address(vault),
                    "STO-031: only the paymaster and the vault read storage here"
                );
            }
            if (o == OP_BALANCE || o == OP_SELFBALANCE) {
                assertEq(frame, address(paymaster), "OP-080: BALANCE only from the staked paymaster");
                ++balances;
            }
        }
        assertGt(audited, 100, "frames audited");
        assertGt(paymasterSteps, 100, "the paymaster's validation was traced");
        assertEq(create2s, expectCreate2 ? 1 : 0, "one CREATE2 in the deployment frame");
        assertEq(balances > 0, expectBalance, "BALANCE only in a forward");
    }

    receive() external payable {}
}
