// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {console} from "forge-std/console.sol";
import {Types} from "../../src/libraries/Types.sol";
import {PackedUserOperation} from "../../src/gasless/IERC4337.sol";
import {ZkApiWithdrawalPaymaster} from "../../src/gasless/ZkApiWithdrawalPaymaster.sol";
import {GaslessTestBase} from "./GaslessTestBase.sol";

/// @dev The transit vectors the JS (sdk/services/zkapiGasless.mjs) and Go (internal/zkapi/gasless.go)
///      clients are checked against: a fixed deployment (deployer 0xDE91 at nonces 0, 1, 2 on chain
///      31337), the transit account of a fixed owner key and payee, the 74-byte creation code, a
///      complete first-use CLOSE operation of a mock-adapter close with every field packed and
///      unpacked, its userOpHash from the etched EntryPoint, the EIP-191 digest and signature, the
///      nonce keys, the attempt keys, chargeFor samples and every gas constant. The test checks the
///      committed test/fixtures/transit-vectors.json field by field. foundry.toml allows no writes,
///      so regenerate with:
///        ZKAPI_PRINT_TRANSIT_VECTORS=1 forge test --match-contract TransitVectorsTest -vv \
///          | sed -n 's/^  transit_vectors=//p' | python3 -m json.tool > test/fixtures/transit-vectors.json
///      Encoding (the file's "_encoding" field states it): every unsigned integer, wei amounts and
///      gas figures included, is a decimal string (never a bare JSON number), so the JS (BigInt)
///      and Go (big.Int) readers parse every field the same way and no reader rounds a wei amount
///      through a double; addresses, hashes and byte strings are 0x-prefixed hex strings; booleans
///      are JSON booleans. The check path parses the strings back (_u) before comparing.
contract TransitVectorsTest is GaslessTestBase {
    string constant ENCODING = "unsigned integers are decimal strings; addresses, hashes and bytes are 0x hex strings";
    string constant PATH = "test/fixtures/transit-vectors.json";
    uint256 constant NULLIFIER = 1001;
    uint128 constant FINAL_BALANCE = BIG - 1_000_000;

    bool printing;

    function setUp() public {
        vm.chainId(31_337);
        _setUpGasless();
        printing = vm.envOr("ZKAPI_PRINT_TRANSIT_VECTORS", false);
    }

    struct Sample {
        uint8 kind;
        uint256 actualGas;
        uint256 executionGasUsed;
        uint256 callGasLimit;
        uint256 postOpGasLimit;
        bool payeeHasCode;
        bool payeeIsEmpty;
        uint256 feePerGas;
    }

    function _samples() internal pure returns (Sample[6] memory samples) {
        samples[0] = Sample(1, 392_400, 53_751, 687_500, 275_000, false, false, 11 gwei);
        samples[1] = Sample(1, 480_580, 53_751, 687_500, 275_000, false, true, 11 gwei);
        samples[2] = Sample(1, 480_515, 53_751, 950_000, 350_000, true, false, 30 gwei);
        samples[3] = Sample(2, 579_828, 218_541, 762_500, 275_000, false, false, 11 gwei);
        samples[4] = Sample(3, 342_354, 57_190, 295_000, 275_000, false, false, 11 gwei);
        samples[5] = Sample(4, 273_528, 380, 97_500, 275_000, false, false, 1 gwei);
    }

    function test_transitVectors() public {
        uint32 id = _bigNote(42);
        (PackedUserOperation memory op, Types.WithdrawalPublicInputs memory inputs) =
            _closeOp(id, NULLIFIER, FINAL_BALANCE);
        address s = op.sender;
        assertEq(op.initCode.length, 20 + 4 + 64, "first use");
        bytes32 hash = entryPoint.getUserOpHash(op);
        bytes32 digest = _digest(op);
        (uint8 v, bytes32 r, bytes32 sv) = vm.sign(OWNER_KEY, digest);
        assertEq(op.signature, abi.encodePacked(r, sv, v));
        OpGas memory g = _gas(CLOSE, true);
        // validation of the operation, with the account in place
        factory.createAccount(ownerAddr, payee);
        (, bytes memory context, uint256 validationData) = _validateDirect(op);
        bytes memory runtime = s.code;

        if (printing) {
            _print(op, inputs, g, hash, digest, v, r, sv, context, validationData, runtime, id);
            return;
        }
        string memory j = vm.readFile(PATH);
        assertEq(vm.parseJsonString(j, "._encoding"), ENCODING, "the stated encoding");
        assertEq(_u(j, ".chain_id"), 31_337);
        assertEq(vm.parseJsonAddress(j, ".entry_point"), ENTRY_POINT);
        assertEq(vm.parseJsonBytes32(j, ".entry_point_codehash"), ENTRY_POINT_CODEHASH);
        assertEq(vm.parseJsonAddress(j, ".sender_creator"), SENDER_CREATOR);
        assertEq(vm.parseJsonBytes32(j, ".sender_creator_codehash"), SENDER_CREATOR_CODEHASH);
        assertEq(vm.parseJsonAddress(j, ".deployer"), DEPLOYER);
        assertEq(vm.parseJsonAddress(j, ".adapter"), address(adapter));
        assertEq(vm.parseJsonAddress(j, ".vault"), address(vault));
        assertEq(vm.parseJsonAddress(j, ".paymaster"), address(paymaster));
        assertEq(vm.parseJsonAddress(j, ".factory"), address(factory));
        assertEq(vm.parseJsonAddress(j, ".implementation"), address(factory.implementation()));
        assertEq(vm.parseJsonAddress(j, ".owner"), ownerAddr);
        assertEq(_u(j, ".owner_private_key"), OWNER_KEY);
        assertEq(vm.parseJsonAddress(j, ".payee"), payee);
        assertEq(vm.parseJsonAddress(j, ".transit_account"), s);
        assertEq(vm.parseJsonBytes(j, ".account_creation_code"), factory.accountCreationCode());
        assertEq(vm.parseJsonBytes32(j, ".account_creation_code_keccak256"), factory.accountCreationCodeHash());
        assertEq(vm.parseJsonBytes(j, ".transit_runtime_code"), runtime);
        assertEq(_u(j, ".forward_nonce_key"), paymaster.FORWARD_NONCE_KEY());
        // the close
        assertEq(_u(j, ".close.note_id"), id);
        assertEq(_u(j, ".close.commitment"), 42);
        assertEq(_u(j, ".close.deposit_units"), BIG);
        assertEq(_u(j, ".close.final_balance"), FINAL_BALANCE);
        assertEq(_u(j, ".close.nullifier"), NULLIFIER);
        assertEq(vm.parseJsonBytes(j, ".close.inputs_abi"), abi.encode(inputs));
        assertEq(vm.parseJsonBytes(j, ".close.proof"), proof256);
        assertEq(vm.parseJsonBytes(j, ".close.vault_calldata"), _closeCall(inputs));
        assertEq(vm.parseJsonBytes(j, ".close.call_data"), op.callData);
        assertEq(vm.parseJsonBytes(j, ".close.init_code"), op.initCode);
        assertEq(vm.parseJsonAddress(j, ".close.sender"), s);
        assertEq(_u(j, ".close.nonce"), op.nonce);
        assertEq(_u(j, ".close.nonce_key"), uint192(NULLIFIER));
        assertEq(_u(j, ".close.nonce_sequence"), 0);
        assertEq(vm.parseJsonBytes32(j, ".close.account_gas_limits"), op.accountGasLimits);
        assertEq(_u(j, ".close.verification_gas_limit"), g.verification);
        assertEq(_u(j, ".close.call_gas_limit"), g.call);
        assertEq(_u(j, ".close.pre_verification_gas"), op.preVerificationGas);
        assertEq(vm.parseJsonBytes32(j, ".close.gas_fees"), op.gasFees);
        assertEq(_u(j, ".close.max_fee_per_gas"), g.maxFee);
        assertEq(_u(j, ".close.max_priority_fee_per_gas"), g.priority);
        assertEq(vm.parseJsonBytes(j, ".close.paymaster_and_data"), op.paymasterAndData);
        assertEq(_u(j, ".close.paymaster_verification_gas_limit"), g.pmVerification);
        assertEq(_u(j, ".close.paymaster_post_op_gas_limit"), g.postOp);
        assertEq(_u(j, ".close.fee_cap_wei"), g.feeCap);
        assertEq(_u(j, ".close.max_cost"), _maxCost(g));
        assertEq(vm.parseJsonBytes32(j, ".close.user_op_hash"), hash);
        assertEq(vm.parseJsonBytes32(j, ".close.eip191_digest"), digest);
        assertEq(vm.parseJsonBytes32(j, ".close.signature_r"), r);
        assertEq(vm.parseJsonBytes32(j, ".close.signature_s"), sv);
        assertEq(_u(j, ".close.signature_v"), v);
        assertEq(vm.parseJsonBytes(j, ".close.signature"), op.signature);
        assertEq(vm.parseJsonBytes(j, ".close.context"), context);
        assertEq(_u(j, ".close.validation_data"), validationData);
        assertEq(_u(j, ".close.valid_until"), inputs.validUntil);
        // keys
        assertEq(vm.parseJsonBytes32(j, ".keys.close"), _closeKey(NULLIFIER));
        assertEq(vm.parseJsonBytes32(j, ".keys.escape"), _escapeKey(id));
        assertEq(vm.parseJsonBytes32(j, ".keys.finalize"), _finalizeKey(id));
        assertEq(vm.parseJsonBytes32(j, ".keys.forward"), _forwardKey(s));
        // charge samples
        Sample[6] memory samples = _samples();
        for (uint256 i = 0; i < samples.length; ++i) {
            string memory prefix = string.concat(".charge_samples[", vm.toString(i), "]");
            Sample memory x = samples[i];
            assertEq(_u(j, string.concat(prefix, ".kind")), x.kind);
            assertEq(_u(j, string.concat(prefix, ".actual_gas")), x.actualGas);
            assertEq(_u(j, string.concat(prefix, ".execution_gas_used")), x.executionGasUsed);
            assertEq(_u(j, string.concat(prefix, ".call_gas_limit")), x.callGasLimit);
            assertEq(_u(j, string.concat(prefix, ".post_op_gas_limit")), x.postOpGasLimit);
            assertEq(vm.parseJsonBool(j, string.concat(prefix, ".payee_has_code")), x.payeeHasCode);
            assertEq(vm.parseJsonBool(j, string.concat(prefix, ".payee_is_empty")), x.payeeIsEmpty);
            assertEq(_u(j, string.concat(prefix, ".fee_per_gas")), x.feePerGas);
            assertEq(
                _u(j, string.concat(prefix, ".charge_wei")),
                paymaster.chargeFor(
                    x.kind,
                    x.actualGas,
                    x.executionGasUsed,
                    x.callGasLimit,
                    x.postOpGasLimit,
                    x.payeeHasCode,
                    x.payeeIsEmpty,
                    x.feePerGas
                )
            );
        }
        // the gas policy
        for (uint256 k = 0; k < 4; ++k) {
            assertEq(_u(j, string.concat(".gas_policy.call_floor[", vm.toString(k), "]")), gp.callFloor[k]);
            assertEq(_u(j, string.concat(".gas_policy.call_hard_cap[", vm.toString(k), "]")), gp.callHardCap[k]);
        }
        assertEq(_u(j, ".gas_policy.post_op_floor"), gp.postOpFloor);
        assertEq(_u(j, ".gas_policy.post_op_cap"), gp.postOpCap);
        assertEq(_u(j, ".gas_policy.verification_floor"), gp.verificationFloor);
        assertEq(_u(j, ".gas_policy.verification_floor_init"), gp.verificationFloorInit);
        assertEq(_u(j, ".gas_policy.verification_cap"), gp.verificationCap);
        assertEq(_u(j, ".gas_policy.pvg_floor"), gp.pvgFloor);
        assertEq(_u(j, ".gas_policy.pvg_cap"), gp.pvgCap);
        assertEq(_u(j, ".gas_policy.pm_verification_floor"), gp.pmVerificationFloor);
        assertEq(_u(j, ".gas_policy.pm_verification_cap"), gp.pmVerificationCap);
        assertEq(_u(j, ".gas_policy.post_op_base_gas"), gp.postOpBaseGas);
        assertEq(_u(j, ".gas_policy.post_op_escape_gas"), gp.postOpEscapeGas);
        assertEq(_u(j, ".gas_policy.post_op_finalize_extra_gas"), gp.postOpFinalizeExtraGas);
        assertEq(_u(j, ".gas_policy.post_op_escape_forward_gas"), gp.postOpEscapeForwardGas);
        assertEq(_u(j, ".gas_policy.eoa_push_gas"), gp.eoaPushGas);
        assertEq(_u(j, ".gas_policy.new_account_gas"), gp.newAccountGas);
        assertEq(_u(j, ".gas_policy.payout_push_gas"), gp.payoutPushGas);
        assertEq(_u(j, ".gas_policy.credit_gas"), gp.creditGas);
        assertEq(_u(j, ".gas_policy.account_call_overhead_gas"), gp.accountCallOverheadGas);
        assertEq(_u(j, ".gas_policy.account_call_overhead_escape_gas"), gp.accountCallOverheadEscapeGas);
        assertEq(_u(j, ".gas_policy.margin_gas"), gp.marginGas);
        assertEq(_u(j, ".gas_policy.finalize_reserve_gas"), gp.finalizeReserveGas);
        assertEq(_u(j, ".gas_policy.max_attempts"), gp.maxAttempts);
        // the test policy and ceilings the vectors were made with
        assertEq(_u(j, ".policy.max_sponsored_cost"), 0.25 ether);
        assertEq(_u(j, ".policy.flat_fee_wei"), FLAT_FEE);
        assertEq(_u(j, ".policy.min_escape_net_wei"), MIN_ESCAPE_NET);
        assertEq(_u(j, ".policy.max_fee_ceiling"), MAX_FEE_CEILING);
        assertEq(_u(j, ".policy.priority_fee_ceiling"), PRIORITY_CEILING);
        assertEq(_u(j, ".policy.base_fee"), BASEFEE);
    }

    /// An unsigned integer field: a decimal string in the file.
    function _u(string memory j, string memory key) internal pure returns (uint256) {
        return vm.parseUint(vm.parseJsonString(j, key));
    }

    function _su(string memory obj, string memory key, uint256 value) internal returns (string memory) {
        return vm.serializeString(obj, key, vm.toString(value));
    }

    function _print(
        PackedUserOperation memory op,
        Types.WithdrawalPublicInputs memory inputs,
        OpGas memory g,
        bytes32 hash,
        bytes32 digest,
        uint8 v,
        bytes32 r,
        bytes32 sv,
        bytes memory context,
        uint256 validationData,
        bytes memory runtime,
        uint32 id
    ) internal {
        string memory root = "root";
        vm.serializeString(root, "_encoding", ENCODING);
        _su(root, "chain_id", block.chainid);
        vm.serializeAddress(root, "entry_point", ENTRY_POINT);
        vm.serializeBytes32(root, "entry_point_codehash", ENTRY_POINT_CODEHASH);
        vm.serializeAddress(root, "sender_creator", SENDER_CREATOR);
        vm.serializeBytes32(root, "sender_creator_codehash", SENDER_CREATOR_CODEHASH);
        vm.serializeAddress(root, "deployer", DEPLOYER);
        vm.serializeAddress(root, "adapter", address(adapter));
        vm.serializeAddress(root, "vault", address(vault));
        vm.serializeAddress(root, "paymaster", address(paymaster));
        vm.serializeAddress(root, "factory", address(factory));
        vm.serializeAddress(root, "implementation", address(factory.implementation()));
        vm.serializeAddress(root, "owner", ownerAddr);
        _su(root, "owner_private_key", OWNER_KEY);
        vm.serializeAddress(root, "payee", payee);
        vm.serializeAddress(root, "transit_account", op.sender);
        vm.serializeBytes(root, "account_creation_code", factory.accountCreationCode());
        vm.serializeBytes32(root, "account_creation_code_keccak256", factory.accountCreationCodeHash());
        vm.serializeBytes(root, "transit_runtime_code", runtime);
        _su(root, "forward_nonce_key", paymaster.FORWARD_NONCE_KEY());

        string memory close = "close";
        _su(close, "note_id", id);
        _su(close, "commitment", 42);
        _su(close, "deposit_units", BIG);
        _su(close, "final_balance", FINAL_BALANCE);
        _su(close, "nullifier", NULLIFIER);
        vm.serializeBytes(close, "inputs_abi", abi.encode(inputs));
        vm.serializeBytes(close, "proof", proof256);
        vm.serializeBytes(close, "vault_calldata", _closeCall(inputs));
        vm.serializeBytes(close, "call_data", op.callData);
        vm.serializeBytes(close, "init_code", op.initCode);
        vm.serializeAddress(close, "sender", op.sender);
        _su(close, "nonce", op.nonce);
        _su(close, "nonce_key", uint192(NULLIFIER));
        _su(close, "nonce_sequence", 0);
        vm.serializeBytes32(close, "account_gas_limits", op.accountGasLimits);
        _su(close, "verification_gas_limit", g.verification);
        _su(close, "call_gas_limit", g.call);
        _su(close, "pre_verification_gas", op.preVerificationGas);
        vm.serializeBytes32(close, "gas_fees", op.gasFees);
        _su(close, "max_fee_per_gas", g.maxFee);
        _su(close, "max_priority_fee_per_gas", g.priority);
        vm.serializeBytes(close, "paymaster_and_data", op.paymasterAndData);
        _su(close, "paymaster_verification_gas_limit", g.pmVerification);
        _su(close, "paymaster_post_op_gas_limit", g.postOp);
        _su(close, "fee_cap_wei", g.feeCap);
        _su(close, "max_cost", _maxCost(g));
        vm.serializeBytes32(close, "user_op_hash", hash);
        vm.serializeBytes32(close, "eip191_digest", digest);
        vm.serializeBytes32(close, "signature_r", r);
        vm.serializeBytes32(close, "signature_s", sv);
        _su(close, "signature_v", v);
        vm.serializeBytes(close, "signature", op.signature);
        vm.serializeBytes(close, "context", context);
        _su(close, "validation_data", validationData);
        string memory closeJson = _su(close, "valid_until", inputs.validUntil);
        vm.serializeString(root, "close", closeJson);

        string memory keys = "keys";
        vm.serializeBytes32(keys, "close", _closeKey(NULLIFIER));
        vm.serializeBytes32(keys, "escape", _escapeKey(id));
        vm.serializeBytes32(keys, "finalize", _finalizeKey(id));
        string memory keysJson = vm.serializeBytes32(keys, "forward", _forwardKey(op.sender));
        vm.serializeString(root, "keys", keysJson);

        Sample[6] memory samples = _samples();
        string[] memory sampleJsons = new string[](samples.length);
        for (uint256 i = 0; i < samples.length; ++i) {
            string memory key = string.concat("sample", vm.toString(i));
            Sample memory x = samples[i];
            _su(key, "kind", x.kind);
            _su(key, "actual_gas", x.actualGas);
            _su(key, "execution_gas_used", x.executionGasUsed);
            _su(key, "call_gas_limit", x.callGasLimit);
            _su(key, "post_op_gas_limit", x.postOpGasLimit);
            vm.serializeBool(key, "payee_has_code", x.payeeHasCode);
            vm.serializeBool(key, "payee_is_empty", x.payeeIsEmpty);
            _su(key, "fee_per_gas", x.feePerGas);
            sampleJsons[i] = _su(
                key,
                "charge_wei",
                paymaster.chargeFor(
                    x.kind,
                    x.actualGas,
                    x.executionGasUsed,
                    x.callGasLimit,
                    x.postOpGasLimit,
                    x.payeeHasCode,
                    x.payeeIsEmpty,
                    x.feePerGas
                )
            );
        }
        vm.serializeString(root, "charge_samples", sampleJsons);

        string memory policy = "gas_policy";
        string[] memory floors = new string[](4);
        string[] memory caps = new string[](4);
        for (uint256 k = 0; k < 4; ++k) {
            floors[k] = vm.toString(gp.callFloor[k]);
            caps[k] = vm.toString(gp.callHardCap[k]);
        }
        vm.serializeString(policy, "call_floor", floors);
        vm.serializeString(policy, "call_hard_cap", caps);
        _su(policy, "post_op_floor", gp.postOpFloor);
        _su(policy, "post_op_cap", gp.postOpCap);
        _su(policy, "verification_floor", gp.verificationFloor);
        _su(policy, "verification_floor_init", gp.verificationFloorInit);
        _su(policy, "verification_cap", gp.verificationCap);
        _su(policy, "pvg_floor", gp.pvgFloor);
        _su(policy, "pvg_cap", gp.pvgCap);
        _su(policy, "pm_verification_floor", gp.pmVerificationFloor);
        _su(policy, "pm_verification_cap", gp.pmVerificationCap);
        _su(policy, "post_op_base_gas", gp.postOpBaseGas);
        _su(policy, "post_op_escape_gas", gp.postOpEscapeGas);
        _su(policy, "post_op_finalize_extra_gas", gp.postOpFinalizeExtraGas);
        _su(policy, "post_op_escape_forward_gas", gp.postOpEscapeForwardGas);
        _su(policy, "eoa_push_gas", gp.eoaPushGas);
        _su(policy, "new_account_gas", gp.newAccountGas);
        _su(policy, "payout_push_gas", gp.payoutPushGas);
        _su(policy, "credit_gas", gp.creditGas);
        _su(policy, "account_call_overhead_gas", gp.accountCallOverheadGas);
        _su(policy, "account_call_overhead_escape_gas", gp.accountCallOverheadEscapeGas);
        _su(policy, "margin_gas", gp.marginGas);
        _su(policy, "finalize_reserve_gas", gp.finalizeReserveGas);
        string memory policyJson = _su(policy, "max_attempts", gp.maxAttempts);
        vm.serializeString(root, "gas_policy", policyJson);

        string memory test = "policy";
        _su(test, "max_sponsored_cost", 0.25 ether);
        _su(test, "flat_fee_wei", FLAT_FEE);
        _su(test, "min_escape_net_wei", MIN_ESCAPE_NET);
        vm.serializeBool(test, "escapes_enabled", true);
        _su(test, "max_fee_ceiling", MAX_FEE_CEILING);
        _su(test, "priority_fee_ceiling", PRIORITY_CEILING);
        string memory testJson = _su(test, "base_fee", BASEFEE);
        string memory json = vm.serializeString(root, "policy", testJson);
        console.log(string.concat("transit_vectors=", json));
    }
}
