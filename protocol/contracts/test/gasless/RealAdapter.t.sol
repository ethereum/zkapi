// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Vm} from "forge-std/Vm.sol";
import {console} from "forge-std/console.sol";
import {ZkApiVault} from "../../src/ZkApiVault.sol";
import {Groth16ProofAdapter} from "../../src/adapters/Groth16ProofAdapter.sol";
import {Types} from "../../src/libraries/Types.sol";
import {Errors} from "../../src/libraries/Errors.sol";
import {Bn254Poseidon} from "../../src/libraries/Bn254Poseidon.sol";
import {NoteLeafLib} from "../../src/libraries/NoteLeafLib.sol";
import {PackedUserOperation} from "../../src/gasless/IERC4337.sol";
import {ZkApiWithdrawalAccountFactory} from "../../src/gasless/ZkApiWithdrawalAccountFactory.sol";
import {ZkApiWithdrawalPaymaster} from "../../src/gasless/ZkApiWithdrawalPaymaster.sol";
import {GaslessTestBase, EntryPointDriver} from "./GaslessTestBase.sol";

/// @dev Etched over the real factory: the real CREATE2 computation (same creation code, same gas),
///      except that one (owner, payee) pair maps to the golden close's destination, so a transit
///      account placed there by vm.etch passes the paymaster's provenance check.
contract ProvenanceOverrideFactory {
    bytes32 private immutable c0;
    bytes32 private immutable c1;
    bytes10 private immutable c2;
    address private immutable entryPoint;
    address private immutable vault;
    address private immutable paymaster;
    address private immutable ownerX;
    address private immutable payeeX;
    address private immutable target;

    constructor(
        bytes memory creationCode,
        address entryPoint_,
        address vault_,
        address paymaster_,
        address ownerX_,
        address payeeX_,
        address target_
    ) {
        require(creationCode.length == 74, "creation code");
        bytes32 a;
        bytes32 b;
        bytes32 c;
        assembly {
            a := mload(add(creationCode, 32))
            b := mload(add(creationCode, 64))
            c := mload(add(creationCode, 96))
        }
        c0 = a;
        c1 = b;
        c2 = bytes10(c);
        entryPoint = entryPoint_;
        vault = vault_;
        paymaster = paymaster_;
        ownerX = ownerX_;
        payeeX = payeeX_;
        target = target_;
    }

    function getAddress(address owner, address payee) external view returns (address) {
        bytes32 initCodeHash =
            keccak256(abi.encodePacked(c0, c1, c2, abi.encode(entryPoint, vault, paymaster, owner, payee)));
        address computed = address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(this), bytes32(0), initCodeHash))))
        );
        if (owner == ownerX && payee == payeeX) return target;
        return computed;
    }
}

/// @dev The golden deployment RealAdapterTest and RealAdapterWorstCaseTest share: the vault the
///      golden proofs bind (test/fixtures/vault-challenge.json), its real Groth16ProofAdapter folded
///      for it, the paymaster, and a real transit account placed at the golden destination.
abstract contract RealAdapterBase is GaslessTestBase {
    address constant GOLDEN_DEPLOYER = address(0xf00d);
    address constant GOLDEN_USER = 0x1111111111111111111111111111111111111111;
    address constant GOLDEN_TREASURY = address(0xbeef);
    address constant GOLDEN_OWNER = address(0x0D0D);
    address constant OTHER_PAYEE = address(0x1ABCD);

    Groth16ProofAdapter real;
    string fixtures;
    Types.WithdrawalPublicInputs closeInputs;
    bytes closeProof;
    Types.WithdrawalPublicInputs escapeInputs;
    bytes escapeProof;
    uint256[32] goldenEmptySiblings;
    /// A real transit account of another payee, created before the factory override: its
    /// provenance still checks out, and the golden close names another destination than it.
    address otherS;
    bytes goldenClose;
    bytes goldenEscape;

    function _setUpGolden() internal {
        vm.chainId(31_337);
        fixtures = vm.readFile("test/fixtures/vault-challenge.json");
        vm.warp(vm.parseJsonUint(fixtures, ".timestamp"));
        vm.fee(BASEFEE);
        _etchEntryPoint();
        uint256 zero;
        for (uint256 level = 0; level < 32; ++level) {
            goldenEmptySiblings[level] = zero;
            zero = Bn254Poseidon.compress(DOMAIN_NODE, zero, zero);
        }
        (escapeInputs, escapeProof) = _golden("escape_a2_concede");
        Types.WithdrawalPublicInputs memory escape = escapeInputs;
        // Folded for the vault GOLDEN_DEPLOYER creates at nonce 0, the address the proofs bind.
        real = new Groth16ProofAdapter(
            vm.computeCreateAddress(GOLDEN_DEPLOYER, 0),
            escape.stateSigningKeyX,
            escape.stateSigningKeyY,
            escape.clearanceSigningKeyX,
            escape.clearanceSigningKeyY
        );
        (closeInputs, closeProof) = _golden("close_b0");
        vm.setNonce(GOLDEN_DEPLOYER, 0);
        vm.prank(GOLDEN_DEPLOYER);
        vault = new ZkApiVault(
            GOLDEN_TREASURY,
            30 days,
            24 hours,
            100_000,
            address(real),
            escape.stateSigningKeyX,
            escape.stateSigningKeyY,
            escape.clearanceSigningKeyX,
            escape.clearanceSigningKeyY,
            GOLDEN_OWNER,
            7 days
        );
        assertEq(address(vault), escape.contractAddress, "golden vault");
        vm.deal(GOLDEN_USER, 10 ether);
        vm.startPrank(GOLDEN_USER);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(vm.parseJsonBytes32(fixtures, ".note_a_registration"), DEPOSIT);
        vault.deposit{value: uint256(DEPOSIT) * 1 gwei}(vm.parseJsonBytes32(fixtures, ".note_b_registration"), DEPOSIT);
        vm.stopPrank();
        assertEq(vault.currentRoot(), closeInputs.activeRoot, "golden root");
        paymaster = new ZkApiWithdrawalPaymaster(
            entryPoint, vault, address(this), _defaultPolicy(), MAX_FEE_CEILING, PRIORITY_CEILING
        );
        factory = paymaster.factory();
        gp = paymaster.gasPolicy();
        driver = new EntryPointDriver();
        vm.deal(address(this), 100 ether);
        paymaster.deposit{value: INITIAL_DEPOSIT}();
        paymaster.addStake{value: 1 ether}(UNSTAKE_DELAY);
        vm.deal(bundler, 10 ether);
        // The steady state of a deployment: a funded treasury, payee and beneficiary, and S (at the
        // golden destination) holding nothing before its exit.
        vm.deal(GOLDEN_TREASURY, 1 ether);
        vm.deal(payee, 1 ether);
        vm.deal(beneficiary, 1 ether);
        vm.deal(GOLDEN_USER, 0);
        otherS = factory.createAccount(ownerAddr, OTHER_PAYEE);
        _placeTransitAtGoldenDestination();
        goldenClose = abi.encode(_goldenOp(GOLDEN_USER, "", closeInputs, closeProof));
        goldenEscape = abi.encode(_goldenEscapeOp());
    }

    function _op(bytes storage encoded) internal pure returns (PackedUserOperation memory) {
        return abi.decode(encoded, (PackedUserOperation));
    }

    /// The golden close's gas fields: a payout of 0.001 ETH only covers a small maxFeePerGas.
    function _goldenGas(bool withInit) internal view returns (OpGas memory g) {
        g = _gas(CLOSE, withInit);
        g.maxFee = 0.5 gwei;
        g.priority = 0.1 gwei;
    }

    function _goldenOp(
        address sender,
        bytes memory initCode,
        Types.WithdrawalPublicInputs memory inputs,
        bytes memory proof
    ) internal view returns (PackedUserOperation memory op) {
        bytes memory vaultCall = abi.encodeCall(ZkApiVault.mutualClose, (inputs, proof));
        op = _op(
            sender,
            _nonce(sender, uint192(inputs.withdrawalNullifier)),
            initCode,
            _callData(vaultCall),
            _goldenGas(initCode.length != 0)
        );
        op = _sign(op, OWNER_KEY);
    }

    /// The golden escape (note A, 0.00069 ETH) from the transit account at its destination: its
    /// payout must cover the initiation, the finalization reserve, the minimum net and both flat
    /// fees, which holds at a small maxFeePerGas.
    function _goldenEscapeOp() internal view returns (PackedUserOperation memory op) {
        OpGas memory g = _gas(ESCAPE, false);
        g.maxFee = 0.15 gwei;
        g.priority = 0.1 gwei;
        bytes memory vaultCall = abi.encodeCall(ZkApiVault.initiateEscapeWithdrawal, (escapeInputs, escapeProof));
        op = _op(
            GOLDEN_USER, _nonce(GOLDEN_USER, uint192(escapeInputs.withdrawalNullifier)), "", _callData(vaultCall), g
        );
        op = _sign(op, OWNER_KEY);
    }

    /// Puts a real transit account's code at the golden destination and makes the factory vouch for it.
    function _placeTransitAtGoldenDestination() internal {
        address realS = factory.createAccount(ownerAddr, payee);
        vm.etch(GOLDEN_USER, realS.code);
        ProvenanceOverrideFactory mock = new ProvenanceOverrideFactory(
            factory.accountCreationCode(),
            ENTRY_POINT,
            address(vault),
            address(paymaster),
            ownerAddr,
            payee,
            GOLDEN_USER
        );
        vm.etch(address(factory), address(mock).code);
        assertEq(factory.getAddress(ownerAddr, payee), GOLDEN_USER, "override");
        assertEq(
            factory.getAddress(ownerAddr, OTHER_PAYEE),
            ZkApiWithdrawalAccountFactory(address(factory)).getAddress(ownerAddr, OTHER_PAYEE)
        );
    }

    // ------------------------------------------------------------------------------ fixtures

    function _golden(string memory name) internal view returns (Types.WithdrawalPublicInputs memory, bytes memory) {
        return (
            abi.decode(
                vm.parseJsonBytes(fixtures, string.concat(".", name, ".inputs_abi")), (Types.WithdrawalPublicInputs)
            ),
            vm.parseJsonBytes(fixtures, string.concat(".", name, ".proof_hex"))
        );
    }

    function _goldenLeaf(uint32 noteId) internal view returns (uint256) {
        if (noteId >= vault.nextNoteId()) return 0;
        (bytes32 commitment, uint128 amount, uint64 expiry,) = vault.notes(noteId);
        return NoteLeafLib.computeLeaf(noteId, commitment, amount, expiry);
    }

    function _goldenPath(uint32 index) internal view returns (uint256[32] memory siblings) {
        siblings = goldenEmptySiblings;
        siblings[0] = _goldenLeaf(index ^ 1);
    }
}

/// @dev The paymaster's validation against the real Groth16ProofAdapter and the golden close and
///      escape (test/fixtures/vault-challenge.json's close_b0 and escape_a2_concede, destination
///      0x1111…1111): the gas of the whole validatePaymasterUserOp for both shapes, cold and warm,
///      pinned in snapshots/gasless-gas.json and asserted under PM_VERIFICATION_CAP − 20,000
///      (release gate 1) and under PM_VERIFICATION_FLOOR with the slack; the ERC-7562
///      opcode audit of both shapes with the adapter's frames traced; the refusal of the golden
///      destination from a real transit account; a tampered proof refused last; and both shapes
///      end to end through handleOps, where the vault's verification in execution finds the record
///      the validation left (handleOpsReal*, overchargeReal*).
///      The cold measurements follow Gas.t.sol's discipline: setUp places the transit account at
///      the golden destination and builds the operations, so each test's first paymaster call runs
///      cold, and a second measurement follows vm.revertToState. The snapshot file is regenerated
///      only by a full `forge test` from protocol/contracts (a targeted run truncates it to the
///      values it recorded).
contract RealAdapterTest is RealAdapterBase {
    function setUp() public {
        _setUpGolden();
    }

    /// Release gate 1: the whole paymaster validation with the real adapter fits under the cap with
    /// 20,000 to spare for both proof shapes, cold and warm; the floor sits above the larger cold
    /// measurement (the ESCAPE shape, which reads the most vault state) plus the slack, and so
    /// above the CLOSE shape's need by more. RealAdapterWorstCaseTest pins it from the dearest
    /// inputs.
    function test_realValidationGasFitsUnderTheCap() public {
        uint256 fresh = vm.snapshotState();
        PackedUserOperation memory op = _op(goldenClose);
        (uint256 cold, uint256 warm) = driver.validateTwice(paymaster, op, entryPoint.getUserOpHash(op), _maxCostOf(op));
        console.log("real validation close cold", cold, "warm", warm);
        vm.revertToState(fresh);
        op = _op(goldenEscape);
        (uint256 escapeCold, uint256 escapeWarm) =
            driver.validateTwice(paymaster, op, entryPoint.getUserOpHash(op), _maxCostOf(op));
        console.log("real validation escape cold", escapeCold, "warm", escapeWarm);
        assertLt(cold, gp.pmVerificationCap - 20_000, "close cold under the cap with 20k to spare");
        assertLt(escapeCold, gp.pmVerificationCap - 20_000, "escape cold under the cap with 20k to spare");
        assertLt(warm, cold, "warm cheaper");
        assertLt(escapeWarm, escapeCold, "warm cheaper");
        uint256 need = escapeCold > cold ? escapeCold : cold;
        assertGe(gp.pmVerificationFloor, need + 4_000, "floor above the larger cold need plus VALIDATION_GAS_SLACK");
        // The cold/warm gap is the ~25 cold storage and account accesses of the checks (about 15%);
        // a bundler's simulations and the inclusion all run cold, so it never changes an outcome.
        assertLt(cold - warm, 70_000, "cold/warm gap");
        assertLt(escapeCold - escapeWarm, 70_000, "cold/warm gap");
        vm.snapshotValue("gasless-gas", "paymasterValidationCold", cold);
        vm.snapshotValue("gasless-gas", "paymasterValidationWarm", warm);
        vm.snapshotValue("gasless-gas", "paymasterValidationEscapeCold", escapeCold);
        vm.snapshotValue("gasless-gas", "paymasterValidationEscapeWarm", escapeWarm);
    }

    /// The real adapter's verification on its own, cold, for the call floors.
    function test_realAdapterVerificationGas() public {
        uint256 gasUsed = driver.verify(real, closeInputs, closeProof);
        console.log("real adapter verify", gasUsed);
        vm.snapshotValue("gasless-gas", "adapterVerifyCold", gasUsed);
    }

    /// From a real transit account, the golden close names another destination.
    function test_goldenDestinationIsNotTheSender() public {
        assertEq(factory.getAddress(ownerAddr, OTHER_PAYEE), otherS, "provenance");
        PackedUserOperation memory op = _goldenOp(otherS, "", closeInputs, closeProof);
        _refused(op, ZkApiWithdrawalPaymaster.DestinationNotSender.selector);
    }

    /// The ERC-7562 audit of every validation frame with the real adapter: the Groth16 pairing
    /// through the core precompiles, with no forbidden opcode, value call or foreign storage. The
    /// clock sits past the proof's validUntil so that only the validation phase is traced.
    function test_opcodeAudit_realAdapterClose() public {
        vm.warp(closeInputs.validUntil + 1);
        _audit(_op(goldenClose), false, false, true);
    }

    function test_opcodeAudit_realAdapterEscape() public {
        vm.warp(escapeInputs.validUntil + 1);
        _audit(_op(goldenEscape), false, false, true);
    }

    /// Every cheap check passes before the proof is verified, and a tampered proof is refused.
    function test_tamperedProofIsRefusedLast() public {
        bytes memory bad = closeProof;
        bad[7] = bytes1(uint8(bad[7]) ^ 0x01);
        PackedUserOperation memory op = _goldenOp(GOLDEN_USER, "", closeInputs, bad);
        _refused(op, Errors.InvalidProof.selector);
        // the untampered proof is accepted by the same validation
        op = _goldenOp(GOLDEN_USER, "", closeInputs, closeProof);
        (, bytes memory context, uint256 validationData) = _validateDirect(op);
        assertEq(context.length, 288, "fixed-size context");
        assertEq(uint48(validationData >> 160), closeInputs.validUntil, "validUntil from the proof");
        assertEq(validationData >> 208, 0, "no validAfter");
        assertEq(uint160(validationData), 0, "no aggregator");
    }

    /// The golden close through handleOps with the real adapter, from an existing S: what the
    /// float pays (UserOperationEvent.actualGasUsed) and the charge over it, within MARGIN_GAS.
    function test_endToEndRealClose() public {
        _endToEndReal(_op(goldenClose), "Close", uint256(closeInputs.finalBalance) * 1 gwei);
    }

    /// The golden escape initiation, the same way: S forwards nothing and its debt is the charge.
    function test_endToEndRealEscape() public {
        _endToEndReal(_op(goldenEscape), "Escape", 0);
    }

    function _endToEndReal(PackedUserOperation memory op, string memory name, uint256 received) internal {
        Vm.Log[] memory logs = _handle(op);
        (bool success, uint256 actualGasCost, uint256 actualGasUsed) = _userOpEvent(logs);
        assertTrue(success, "executed");
        SettledEvent memory e = _settled(logs);
        assertTrue(e.found);
        assertEq(e.received, received);
        uint256 price = actualGasCost / actualGasUsed;
        assertEq(actualGasCost, actualGasUsed * price);
        uint256 chargedGas = (e.charged - FLAT_FEE) / price;
        assertGe(chargedGas, actualGasUsed, "never under the real cost");
        assertLe(chargedGas - actualGasUsed, gp.marginGas, "at most the margin over it");
        vm.snapshotValue("gasless-gas", string.concat("handleOpsReal", name), actualGasUsed);
        vm.snapshotValue("gasless-gas", string.concat("overchargeReal", name), chargedGas - actualGasUsed);
    }

    /// The vault verifies the exit in the execution phase as well, and finds the record the
    /// validation left: both golden exits execute through S with callGasLimit at the kind's floor,
    /// below what the same exit costs on its own with its verification (a direct vault call).
    function test_realExitsExecuteAtTheCallFloor() public {
        uint256 cold = vm.snapshotState();
        vm.prank(GOLDEN_USER);
        uint256 g0 = gasleft();
        vault.mutualClose(closeInputs, closeProof);
        assertLt(gp.callFloor[0], g0 - gasleft(), "the close floor cannot fit the close with its verification");
        vm.revertToState(cold);
        vm.prank(GOLDEN_USER);
        g0 = gasleft();
        vault.initiateEscapeWithdrawal(escapeInputs, escapeProof);
        assertLt(gp.callFloor[1], g0 - gasleft(), "the escape floor cannot fit the escape with its verification");
        vm.revertToState(cold);
        PackedUserOperation memory op = _op(goldenClose);
        op.accountGasLimits = bytes32((uint256(op.accountGasLimits) >> 128 << 128) | gp.callFloor[0]);
        (bool success,,) = _userOpEvent(_handle(_sign(op, OWNER_KEY)));
        assertTrue(success, "the close executed at its floor");
        assertTrue(vault.usedNullifiers(closeInputs.withdrawalNullifier));
        vm.revertToState(cold);
        op = _op(goldenEscape);
        op.accountGasLimits = bytes32((uint256(op.accountGasLimits) >> 128 << 128) | gp.callFloor[1]);
        (success,,) = _userOpEvent(_handle(_sign(op, OWNER_KEY)));
        assertTrue(success, "the escape executed at its floor");
        (bool pending,,,,,) = vault.pendingWithdrawals(escapeInputs.noteId);
        assertTrue(pending);
    }
}

/// @dev The paymaster's validation on the dearest inputs an exit can carry, which sets
///      PM_VERIFICATION_FLOOR: the golden escape from an S that carries a settled sponsored-escape
///      record (its earlier sponsored escape of note B was defeated, so note B is active again and
///      validation reads it to see that the record is settled), and the scalar multiplication the
///      golden proof's noteId 0 skips. Every other input that can skip one skips it in every exit
///      (protocolVersion 2, kind, a close's zero nextNullifier and conceded) or does not skip it in
///      the golden escape (the root, the nullifiers, the destination, validUntil, the final balance
///      and the concession). No valid proof with noteId 3 or more exists among the fixtures, so the
///      multiplication is the adapter's gas for the golden statement with noteId 3 (it reaches the
///      pairing and fails there) less its gas for the golden one. setUp writes the record, so the
///      test's measurement runs cold.
contract RealAdapterWorstCaseTest is RealAdapterBase {
    uint32 constant DEFEATED_NOTE = 1;
    /// The paymaster's storage slot of escapeNotePlusOne (forge inspect ... storageLayout); setUp
    /// checks the write through the getter.
    uint256 constant ESCAPE_NOTE_PLUS_ONE_SLOT = 11;

    function setUp() public {
        _setUpGolden();
        assertEq(escapeInputs.noteId, 0, "the golden escape skips the noteId multiplication");
        (,,, Types.NoteStatus status) = vault.notes(DEFEATED_NOTE);
        assertEq(uint8(status), uint8(Types.NoteStatus.Active), "the defeated escape's note is active again");
        // escapeNotePlusOne[GOLDEN_USER] = DEFEATED_NOTE + 1
        bytes32 slot = keccak256(abi.encode(GOLDEN_USER, uint256(ESCAPE_NOTE_PLUS_ONE_SLOT)));
        vm.store(address(paymaster), slot, bytes32(uint256(DEFEATED_NOTE) + 1));
        assertEq(paymaster.escapeNotePlusOne(GOLDEN_USER), uint256(DEFEATED_NOTE) + 1, "the record");
    }

    function test_worstCaseValidationSetsTheFloor() public {
        uint256 fresh = vm.snapshotState();
        PackedUserOperation memory op = _op(goldenEscape);
        (uint256 recorded,) = driver.validateTwice(paymaster, op, entryPoint.getUserOpHash(op), _maxCostOf(op));
        vm.revertToState(fresh);
        (bool ok,, uint256 golden) = driver.tryVerify(real, escapeInputs, escapeProof);
        assertTrue(ok, "the golden escape verifies");
        vm.revertToState(fresh);
        Types.WithdrawalPublicInputs memory worst = escapeInputs;
        worst.noteId = 3;
        (bool worstOk, bytes memory reason, uint256 worstGas) = driver.tryVerify(real, worst, escapeProof);
        assertFalse(worstOk);
        assertEq(reason, abi.encodeWithSelector(Errors.InvalidProof.selector), "refused at the pairing");
        uint256 multiplication = worstGas - golden;
        assertGt(multiplication, 6_000, "an ecMul (6,000) and an ecAdd (150)");
        assertLt(multiplication, 7_000);
        uint256 need = recorded + multiplication;
        console.log("worst-case escape validation", need, "recorded", recorded);
        assertLt(need, gp.pmVerificationCap - 20_000, "under the cap with 20k to spare");
        assertGe(gp.pmVerificationFloor, need + 4_000, "floor above the worst cold need plus VALIDATION_GAS_SLACK");
        assertLt(gp.pmVerificationFloor, need + 14_000, "floor is that need rounded up to 10k");
        vm.snapshotValue("gasless-gas", "paymasterValidationEscapeWorstCold", need);
    }
}
