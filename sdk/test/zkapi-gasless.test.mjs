// The shared gasless logic (design §3.1) against the cross-language vectors
// in protocol/contracts/test/fixtures/transit-vectors.json: every derivation
// (S, the init code, the call data, the packing, the hash, the EIP-191
// digest and its signature, the keys, the nonce), the amounts and the
// chargeFor parity, the AA / paymaster error mapping, the bundler client,
// the receipt parsers, the availability verdicts and the 25% rule.
import assert from 'node:assert/strict';
import test from 'node:test';
import { readFileSync } from 'node:fs';
import {
    VECTORS, assertUserOperationShape, attemptsKeyOf, create2TransitAccount, decodeGetUserOpHash, decodeHandleOps, failedOpData,
    gaslessProfileFromVectors, hashPacked, logs, revertError, userOperationHashFromJson
} from './helpers/fake-bundler.mjs';
import { recover, sign } from './helpers/secp256k1.mjs';
import { keccak256Hex, selectorOf } from './helpers/request-archive-harness.mjs';
import { GASLESS_ABI, encodeFinalizeEscape, encodeTransitWithdraw, parseWithdrawalReceipt } from '../wallet.js';
import { codehash } from '../services/zkapiKeccak.mjs';
import { ENTRY_POINT_ERRORS, decodeContractRevert, decodeEntryPointRevert, entryPointError } from '../services/zkapiContractError.mjs';
import {
    CANONICAL_ENTRY_POINT, CANONICAL_SENDER_CREATOR, ENTRY_POINT_V070_CODEHASH, FORWARD_NONCE_KEY, GASLESS_MESSAGES, KIND, MAX_ATTEMPTS,
    SENDER_CREATOR_V070_CODEHASH, UNECONOMIC_FRACTION_PERCENT, attemptsKey, availabilityVerdict, buildUserOperation, bumpFees, bundlerClient,
    bundlerUrl, chargeFor, checkEstimate, decodeGasPolicy, decodePolicy, decodeQuote, dryRunError, eip191Digest, encodeGetNonce,
    encodeGetUserOpHash, encodeHandleOps, gasFields, gaslessAmounts, gaslessPins, handleOpsCalldataBytes, lim070PreVerificationGas, maxCostWei, nonceKeyFor,
    normalizeGasPolicy, packNonce, packUserOperation, parsePayoutCredited, parseSettled, parseSponsorshipFailed, parseStranded,
    parseUserOperationEvent, parseUserOperationRevertReason, preVerificationGasFor, referencePreVerificationGas, sameGasPolicy, selectFees, settlementOf,
    transitAccountAddress, transitInitCode, unpackNonce, userOpHash, userOperationFromJson, userOperationJson,
    userOperationReceiptTransactionHash
} from '../services/zkapiGasless.mjs';

const V = VECTORS;
const C = V.close;
const low = value => String(value).toLowerCase();
const gasPolicy = normalizeGasPolicy(V.gas_policy);

/** The vector's close operation as the SDK builds it (signed). */
function vectorOperation({ signature = C.signature } = {}) {
    return buildUserOperation({
        sender: C.sender, nonce: C.nonce, initCode: C.init_code, callData: C.call_data,
        gas: {
            callGasLimit: C.call_gas_limit, verificationGasLimit: C.verification_gas_limit, preVerificationGas: C.pre_verification_gas,
            paymasterVerificationGasLimit: C.paymaster_verification_gas_limit, paymasterPostOpGasLimit: C.paymaster_post_op_gas_limit
        },
        fees: { maxFeePerGas: C.max_fee_per_gas, maxPriorityFeePerGas: C.max_priority_fee_per_gas },
        paymaster: V.paymaster, feeCapWei: C.fee_cap_wei, signature
    });
}

test('the pinned EntryPoint, SenderCreator and FORWARD_NONCE_KEY are the vectors’', () => {
    assert.equal(low(CANONICAL_ENTRY_POINT), low(V.entry_point));
    assert.equal(low(CANONICAL_SENDER_CREATOR), low(V.sender_creator));
    assert.equal(ENTRY_POINT_V070_CODEHASH, low(V.entry_point_codehash));
    assert.equal(SENDER_CREATOR_V070_CODEHASH, low(V.sender_creator_codehash));
    assert.equal(FORWARD_NONCE_KEY.toString(), V.forward_nonce_key);
    assert.equal(FORWARD_NONCE_KEY, BigInt(keccak256Hex('zkapi.gasless.forward')) & ((1n << 192n) - 1n));
    assert.equal(MAX_ATTEMPTS.toString(), V.gas_policy.max_attempts);
    assert.equal(UNECONOMIC_FRACTION_PERCENT, 25n);
});

test('the transit account is the CREATE2 of the pinned creation code and the five arguments', () => {
    const args = { factory: V.factory, creationCodeHex: V.account_creation_code, entryPoint: V.entry_point, vault: V.vault,
        paymaster: V.paymaster, owner: V.owner, payee: V.payee };
    assert.equal(transitAccountAddress(args), low(V.transit_account));
    assert.equal(create2TransitAccount({ ...args, creationCode: V.account_creation_code }), low(V.transit_account), 'the independent CREATE2');
    assert.equal(codehash(V.account_creation_code), low(V.account_creation_code_keccak256));
    // The proxy's runtime is the creation code after its 13-byte stub, then the arguments.
    assert.equal(`0x${V.account_creation_code.slice(2 + 26)}${[V.entry_point, V.vault, V.paymaster, V.owner, V.payee]
        .map(address => BigInt(address).toString(16).padStart(64, '0')).join('')}`, low(V.transit_runtime_code));
    // Another payee or owner is another account; a bad argument is refused.
    assert.notEqual(transitAccountAddress({ ...args, payee: V.owner }), low(V.transit_account));
    assert.notEqual(transitAccountAddress({ ...args, owner: V.payee }), low(V.transit_account));
    assert.throws(() => transitAccountAddress({ ...args, payee: '0x1234' }), /payee/);
    assert.equal(transitInitCode({ factory: V.factory, owner: V.owner, payee: V.payee }), low(C.init_code));
    assert.equal(transitInitCode({ factory: V.factory, owner: V.owner, payee: V.payee }).slice(42, 50), GASLESS_ABI.createAccount);
});

test('the sponsored call data, the packing, the nonce and the hash are the vectors’ bytes', () => {
    assert.equal(encodeTransitWithdraw(C.vault_calldata), low(C.call_data));
    assert.equal(encodeTransitWithdraw('0x').length, 2 + (4 + 64) * 2, 'a forward is the selector, offset and a zero length');
    assert.equal(encodeTransitWithdraw(`0xff8f5585${'0'.repeat(64)}`).length, 2 + (4 + 64 + 64) * 2, 'a finalization pads to a word');
    assert.throws(() => encodeTransitWithdraw('0x1234'), /empty, a finalization/);
    const op = vectorOperation();
    const packed = packUserOperation(op);
    assert.equal(packed.accountGasLimits, C.account_gas_limits);
    assert.equal(packed.gasFees, C.gas_fees);
    assert.equal(packed.paymasterAndData, low(C.paymaster_and_data));
    assert.equal(packed.paymasterAndData.length, 2 + 64 * 2, '20 + 16 + 16 + 12 bytes');
    assert.equal(packNonce(C.nonce_key, C.nonce_sequence).toString(), C.nonce);
    assert.deepEqual(unpackNonce(C.nonce), { key: BigInt(C.nonce_key), sequence: BigInt(C.nonce_sequence) });
    assert.equal(nonceKeyFor(KIND.close, { nullifier: C.nullifier }).toString(), C.nonce_key);
    assert.equal(nonceKeyFor(KIND.forward), FORWARD_NONCE_KEY);
    assert.equal(userOpHash(op, V.entry_point, V.chain_id), low(C.user_op_hash));
    assert.equal(hashPacked(packed, V.entry_point, V.chain_id), low(C.user_op_hash), 'the independent hash');
    assert.equal(userOperationHashFromJson(userOperationJson(op), V.entry_point, V.chain_id), low(C.user_op_hash));
    assert.equal(maxCostWei(op, op.maxFeePerGas).toString(), C.max_cost);
    assert.equal((BigInt(C.valid_until) << 160n).toString(), C.validation_data, 'validationData = validUntil << 160');
});

test('the EIP-191 digest of the hash is what the owner signs, and the vector signature recovers the owner', () => {
    const digest = eip191Digest(C.user_op_hash);
    assert.equal(digest, low(C.eip191_digest));
    assert.equal(sign(digest, V.owner_private_key), low(C.signature), 'RFC 6979 reproduces the Forge signature');
    assert.equal(recover(digest, C.signature), low(V.owner));
    assert.equal(`0x${C.signature.slice(2, 66)}`, low(C.signature_r));
    assert.equal(`0x${C.signature.slice(66, 130)}`, low(C.signature_s));
    assert.equal(Number.parseInt(C.signature.slice(130), 16), Number(C.signature_v));
    const otherV = Number(C.signature_v) === 27 ? '1c' : '1b';
    assert.notEqual(recover(digest, `0x${C.signature.slice(2, 130)}${otherV}`), low(V.owner), 'the other v recovers another key');
    assert.throws(() => eip191Digest('0x1234'), /32 bytes/);
});

test('the attempt keys are keccak256(abi.encode(name, value))', () => {
    assert.equal(attemptsKey(KIND.close, { nullifier: C.nullifier }), low(V.keys.close));
    assert.equal(attemptsKey(KIND.escape, { noteId: C.note_id }), low(V.keys.escape));
    assert.equal(attemptsKey(KIND.finalize, { noteId: C.note_id }), low(V.keys.finalize));
    assert.equal(attemptsKey(KIND.forward, { sender: V.transit_account }), low(V.keys.forward));
    assert.equal(attemptsKeyOf(1, { nullifier: C.nullifier }), low(V.keys.close), 'the independent key');
    assert.equal(attemptsKeyOf(4, { sender: V.transit_account }), low(V.keys.forward));
    // The paymaster's context word 1 is the close key.
    assert.equal(`0x${C.context.slice(2 + 64, 2 + 128)}`, low(V.keys.close));
});

test('the user operation JSON is the unpacked v0.7 shape and round-trips', () => {
    const op = vectorOperation();
    const json = userOperationJson(op);
    assertUserOperationShape(json);
    assert.equal(json.factory, low(V.factory));
    assert.equal(json.factoryData, `0x${C.init_code.slice(42)}`.toLowerCase());
    assert.equal(json.nonce, `0x${BigInt(C.nonce).toString(16)}`);
    assert.equal(json.callGasLimit, `0x${BigInt(C.call_gas_limit).toString(16)}`);
    assert.equal(json.paymasterData, `0x${BigInt(C.fee_cap_wei).toString(16).padStart(24, '0')}`);
    const back = userOperationFromJson(json);
    assert.equal(userOpHash(back, V.entry_point, V.chain_id), low(C.user_op_hash));
    assert.equal(back.feeCapWei.toString(), C.fee_cap_wei);
    assert.equal(back.initCode, low(C.init_code));
    // Without initCode the factory fields are absent.
    const existing = userOperationJson({ ...op, initCode: '0x' });
    assert.equal('factory' in existing, false);
    assert.equal('factoryData' in existing, false);
    assertUserOperationShape(existing);
});

test('handleOps and getUserOpHash calldata decode back to the same packed operation', () => {
    const op = vectorOperation();
    const packed = packUserOperation(op);
    const { beneficiary, ops } = decodeHandleOps(encodeHandleOps([op], V.deployer));
    assert.equal(beneficiary, low(V.deployer));
    assert.equal(ops.length, 1);
    assert.equal(ops[0].sender, packed.sender);
    assert.equal(`0x${ops[0].nonce}`, packed.nonce);
    assert.equal(`0x${ops[0].initCode}`, packed.initCode);
    assert.equal(`0x${ops[0].callData}`, packed.callData);
    assert.equal(`0x${ops[0].accountGasLimits}`, packed.accountGasLimits);
    assert.equal(`0x${ops[0].preVerificationGas}`, packed.preVerificationGas);
    assert.equal(`0x${ops[0].gasFees}`, packed.gasFees);
    assert.equal(`0x${ops[0].paymasterAndData}`, packed.paymasterAndData);
    assert.equal(`0x${ops[0].signature}`, packed.signature);
    assert.equal(hashPacked(ops[0], V.entry_point, V.chain_id), low(C.user_op_hash));
    assert.equal(hashPacked(decodeGetUserOpHash(encodeGetUserOpHash(op)), V.entry_point, V.chain_id), low(C.user_op_hash));
    assert.equal(encodeGetNonce(V.transit_account, C.nonce_key), `0x${GASLESS_ABI.getNonce}${BigInt(V.transit_account).toString(16).padStart(64, '0')}${BigInt(C.nonce_key).toString(16).padStart(64, '0')}`);
    assert.ok(handleOpsCalldataBytes(op, V.deployer) > 836 + 65 + 9 * 32);
});

test('chargeFor is the paymaster’s formula on every sample', () => {
    for (const sample of V.charge_samples) {
        const charge = chargeFor({
            gasPolicy, kind: Number(sample.kind), actualGas: sample.actual_gas, executionGasUsed: sample.execution_gas_used,
            callGasLimit: sample.call_gas_limit, postOpGasLimit: sample.post_op_gas_limit, payeeHasCode: sample.payee_has_code,
            payeeIsEmpty: sample.payee_is_empty, feePerGas: sample.fee_per_gas
        });
        assert.equal(charge.toString(), sample.charge_wei, JSON.stringify(sample));
    }
    // Execution gas above the call limit is clamped; a zero fee charges nothing.
    assert.equal(chargeFor({ gasPolicy, kind: KIND.close, actualGas: 1n, executionGasUsed: 10n ** 9n, callGasLimit: 600_000n,
        postOpGasLimit: 250_000n, feePerGas: 1n }), chargeFor({ gasPolicy, kind: KIND.close, actualGas: 1n, executionGasUsed: 600_000n,
        callGasLimit: 600_000n, postOpGasLimit: 250_000n, feePerGas: 1n }));
    assert.equal(chargeFor({ gasPolicy, kind: KIND.forward, actualGas: 1n, executionGasUsed: 1n, callGasLimit: 80_000n, postOpGasLimit: 250_000n, feePerGas: 0n }), 0n);
});

test('the gas policy normalizes from both spellings, compares with the contract’s view and refuses a broken one', () => {
    const vectors = normalizeGasPolicy(V.gas_policy);
    const profile = normalizeGasPolicy(gaslessProfileFromVectors({ spelling: 'profile' }).gas_policy);
    assert.ok(sameGasPolicy(vectors, profile), 'postop_* / call_cap and post_op_* / call_hard_cap pin the same constants');
    assert.deepEqual(profile.defaults.callDefault.map(String), ['642500', '680000', '287500', '97500']);
    assert.equal(profile.defaults.postOpDefault, 270_000n);
    assert.equal(vectors.finalizeReserveGas, vectors.pvgFloor + vectors.verificationFloor + vectors.callFloor[2] + vectors.pmVerificationFloor + vectors.postOpFloor);
    assert.equal(vectors.finalizeReserveGas.toString(), V.gas_policy.finalize_reserve_gas);
    // gasPolicy() is two uint256[4] then 22 scalars (30 words).
    const words = [...vectors.callFloor, ...vectors.callHardCap, vectors.postOpFloor, vectors.postOpCap, vectors.verificationFloor,
        vectors.verificationFloorInit, vectors.verificationCap, vectors.pvgFloor, vectors.pvgCap, vectors.pmVerificationFloor,
        vectors.pmVerificationCap, vectors.postOpBaseGas, vectors.postOpEscapeGas, vectors.postOpFinalizeExtraGas, vectors.postOpEscapeForwardGas,
        vectors.eoaPushGas, vectors.newAccountGas, vectors.payoutPushGas, vectors.creditGas, vectors.accountCallOverheadGas,
        vectors.accountCallOverheadEscapeGas, vectors.marginGas, vectors.finalizeReserveGas, vectors.maxAttempts];
    const encoded = `0x${words.map(value => value.toString(16).padStart(64, '0')).join('')}`;
    assert.ok(sameGasPolicy(decodeGasPolicy(encoded), vectors));
    assert.equal(sameGasPolicy(decodeGasPolicy(encoded.replace(/.{64}$/, '0'.repeat(63) + '4')), vectors), false, 'another MAX_ATTEMPTS');
    assert.throws(() => decodeGasPolicy(`0x${'0'.repeat(64 * 29)}`), /exactly 30/);
    assert.throws(() => normalizeGasPolicy({ ...V.gas_policy, margin_gas: undefined }), { code: 'gasless_profile_invalid' });
    assert.throws(() => normalizeGasPolicy({ ...V.gas_policy, call_floor: ['1', '2', '3'] }), { code: 'gasless_profile_invalid' });
    assert.throws(() => normalizeGasPolicy({ ...V.gas_policy, pvg_floor: '999999' }), /above its cap/);
});

test('the profile pins are read, validated and absent when the deployment has none', () => {
    const gasless = gaslessProfileFromVectors({ spelling: 'profile' });
    const pins = gaslessPins({ deployment_status: 'deployed', gasless });
    assert.equal(pins.paymaster, V.paymaster);
    assert.equal(pins.factory, V.factory);
    assert.equal(pins.entryPoint, V.entry_point);
    assert.equal(pins.bundlerUrl, 'https://bundler.example/rpc');
    assert.equal(pins.policy.flatFeeWei.toString(), V.policy.flat_fee_wei);
    assert.equal(pins.policy.escapesEnabled, true);
    assert.equal(pins.feeCeilings.maxFeeWei.toString(), V.policy.max_fee_ceiling);
    assert.equal(pins.uneconomicFractionPercent, 25n);
    assert.equal(pins.accountCreationCodeKeccak256, low(V.account_creation_code_keccak256));
    assert.equal(gaslessPins({ gasless: null }), null);
    assert.equal(gaslessPins({}), null);
    assert.equal(gaslessPins({ deployment_status: 'not_deployed', gasless }), null, 'a placeholder deployment pins nothing');
    assert.equal(gaslessPins({ gasless: { ...gasless, deployment_status: 'not_deployed' } }), null);
    assert.throws(() => gaslessPins({ gasless: { ...gasless, account_creation_code_keccak256: `0x${'11'.repeat(32)}` } }),
        { code: 'gasless_profile_invalid' });
    assert.throws(() => gaslessPins({ gasless: { ...gasless, withdrawal_paymaster_address: '0x12' } }), { code: 'gasless_profile_invalid' });
    assert.throws(() => gaslessPins({ gasless: { ...gasless, uneconomic_fraction_percent: 101 } }), { code: 'gasless_profile_invalid' });
});

test('gas fields come from the pinned policy within every floor and cap, never from an estimate', () => {
    const fields = gasFields({ gasPolicy, kind: KIND.close, withInitCode: true, calldataBytes: 1_764 });
    assert.deepEqual(fields, {
        callGasLimit: 642_500n, verificationGasLimit: 300_000n, preVerificationGas: 21_000n + 16n * 1_764n + 10_000n,
        paymasterVerificationGasLimit: 430_000n, paymasterPostOpGasLimit: 275_000n
    });
    assert.equal(gasFields({ gasPolicy, kind: KIND.close, withInitCode: false, calldataBytes: 0 }).verificationGasLimit, 80_000n);
    assert.equal(gasFields({ gasPolicy, kind: KIND.forward, calldataBytes: 0 }).callGasLimit, 97_500n);
    assert.equal(gasFields({ gasPolicy, kind: KIND.escape, calldataBytes: 0 }).callGasLimit, 680_000n);
    assert.equal(gasFields({ gasPolicy, kind: KIND.finalize, calldataBytes: 0 }).callGasLimit, 287_500n);
    // Profile defaults win; the live callCap bounds the call limit; the pvg clamps to the floor and the cap.
    const profile = normalizeGasPolicy(gaslessProfileFromVectors({ spelling: 'profile' }).gas_policy);
    assert.equal(gasFields({ gasPolicy: profile, kind: KIND.close, calldataBytes: 0 }).paymasterPostOpGasLimit, 270_000n);
    assert.equal(gasFields({ gasPolicy, kind: KIND.close, calldataBytes: 0, callCap: 600_000n }).callGasLimit, 600_000n);
    assert.equal(preVerificationGasFor(gasPolicy, 0), gasPolicy.pvgFloor);
    assert.equal(preVerificationGasFor(gasPolicy, 100_000), gasPolicy.pvgCap);
    // An override outside the range is refused with the field index of GasLimitOutOfRange.
    assert.throws(() => gasFields({ gasPolicy, kind: KIND.close, calldataBytes: 0, overrides: { callGasLimit: 539_999n } }),
        error => error.code === 'gas_limit_out_of_range' && error.data.field === 2);
    assert.throws(() => gasFields({ gasPolicy, kind: KIND.close, calldataBytes: 0, overrides: { paymasterPostOpGasLimit: 350_001n } }),
        error => error.code === 'gas_limit_out_of_range' && error.data.field === 4);
    assert.throws(() => gasFields({ gasPolicy, kind: KIND.close, withInitCode: true, calldataBytes: 0, overrides: { verificationGasLimit: 100_000n } }),
        error => error.code === 'gas_limit_out_of_range' && error.data.field === 1);
    assert.throws(() => gasFields({ gasPolicy, kind: 5, calldataBytes: 0 }), /Unknown/);
    // A bundler estimate above a cap is refused; below the defaults it is ignored.
    assert.throws(() => checkEstimate({ callGasLimit: '0xf4240' }, { gasPolicy, kind: KIND.close }), { code: 'gasless_estimate_above_cap' });
    assert.deepEqual(checkEstimate({ callGasLimit: '0x1', preVerificationGas: 'junk' }, { gasPolicy, kind: KIND.close }), []);
});

test('preVerificationGas covers the reference bundler’s per-op minimum, the smallest shape (a forward from an existing S) included', () => {
    // eth-infinitism bundler calcPreVerificationGas (v0.7 DefaultGasOverheads), written out independently:
    // 21,000 + 18,300 + 4 per word + 4 / 16 per zero / non-zero byte of abi.encode of the nine packed fields.
    const reference = op => {
        const packed = packUserOperation(op);
        const tail = hex => {
            const data = hex.slice(2);
            return `${(data.length / 2).toString(16).padStart(64, '0')}${data.padEnd(Math.ceil(data.length / 64) * 64, '0')}`;
        };
        const tails = [packed.initCode, packed.callData, packed.paymasterAndData, packed.signature].map(tail);
        const offsets = [];
        let offset = 9 * 32;
        for (const item of tails) {
            offsets.push(offset.toString(16).padStart(64, '0'));
            offset += item.length / 2;
        }
        const encoded = Buffer.from(`${packed.sender.slice(2).padStart(64, '0')}${packed.nonce.slice(2)}${offsets[0]}${offsets[1]}`
            + `${packed.accountGasLimits.slice(2)}${packed.preVerificationGas.slice(2)}${packed.gasFees.slice(2)}${offsets[2]}${offsets[3]}${tails.join('')}`, 'hex');
        let gas = 21_000 + 18_300 + 4 * Math.ceil(encoded.length / 32);
        for (const byte of encoded) gas += byte === 0 ? 4 : 16;
        return BigInt(gas);
    };
    const signature = C.signature;
    for (const [label, kind, initCode, callData, nonce] of [
        ['forward', KIND.forward, '0x', encodeTransitWithdraw('0x'), packNonce(FORWARD_NONCE_KEY, 0n)],
        ['forward, later sequence', KIND.forward, '0x', encodeTransitWithdraw('0x'), packNonce(FORWARD_NONCE_KEY, 3n)],
        ['close with initCode', KIND.close, C.init_code, C.call_data, C.nonce]
    ]) {
        for (const gwei of [2n, 20n, 200n]) {
            const fees = { maxFeePerGas: gwei * 1_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n };
            const draft = gas => buildUserOperation({ sender: V.transit_account, nonce, initCode, callData, gas, fees, paymaster: V.paymaster,
                feeCapWei: BigInt(V.policy.flat_fee_wei) });
            const sized = gasFields({ gasPolicy, kind, withInitCode: initCode !== '0x', calldataBytes: 0 });
            const calldataBytes = handleOpsCalldataBytes(draft(sized), V.owner);
            const gas = gasFields({ gasPolicy, kind, withInitCode: initCode !== '0x', calldataBytes, op: draft(sized) });
            const signed = { ...draft(gas), signature };
            const minimum = reference(signed);
            assert.ok(gas.preVerificationGas >= minimum, `${label} at ${gwei} gwei: ${gas.preVerificationGas} covers the reference ${minimum}`);
            assert.ok(gas.preVerificationGas <= gasPolicy.pvgCap);
            assert.equal(referencePreVerificationGas(signed), minimum, 'the SDK’s reference formula is the bundler’s');
            if (label === 'forward') {
                // The calldata-only reserve alone is below the bundler's minimum for this shape (the refusal this guards against).
                assert.ok(preVerificationGasFor(gasPolicy, calldataBytes) < minimum, `the calldata-only reserve is below ${minimum}`);
            }
        }
    }
});

// The preVerificationGas rule zkapi-clientd shares, PVG = clamp(max(A,
// ceil(1.1 × B), C), pvg_floor, pvg_cap), on the vectors' close operation
// (unsigned, as built) with and without its initCode, a FORWARD of the same
// sender and a FINALIZE. The expected numbers were computed independently
// (not by either client) and are asserted, the same, by
// TestGaslessPreVerificationGasParity in zkapi-clientd/internal/zkapi.
test('preVerificationGas follows the rule zkapi-clientd shares, to the gas, on the close, forward and finalize vectors', () => {
    const operation = ({ initCode = C.init_code, callData = C.call_data, nonce = C.nonce, callGasLimit = C.call_gas_limit } = {}) => buildUserOperation({
        sender: C.sender, nonce, initCode, callData,
        gas: {
            callGasLimit, verificationGasLimit: C.verification_gas_limit, preVerificationGas: C.pre_verification_gas,
            paymasterVerificationGasLimit: C.paymaster_verification_gas_limit, paymasterPostOpGasLimit: C.paymaster_post_op_gas_limit
        },
        fees: { maxFeePerGas: C.max_fee_per_gas, maxPriorityFeePerGas: C.max_priority_fee_per_gas },
        paymaster: V.paymaster, feeCapWei: C.fee_cap_wei
    });
    const cases = [
        // label, op, A (LIM-070 term), B (reference minimum), handleOps bytes (C = 21,000 + 16 × bytes + 10,000), PVG
        ['close with initCode', operation(), 66_316n, 52_668n, 1_764, 66_316n],
        ['close without initCode', operation({ initCode: '0x' }), 65_356n, 51_696n, 1_668, 65_356n],
        ['forward', operation({ initCode: '0x', callData: encodeTransitWithdraw('0x'), nonce: packNonce(FORWARD_NONCE_KEY, 0n), callGasLimit: 97_500n }),
            57_904n, 44_136n, 804, 57_904n],
        ['finalize', operation({ initCode: '0x', callData: encodeTransitWithdraw(encodeFinalizeEscape(C.note_id)), nonce: packNonce(C.nonce_key, 1n),
            callGasLimit: 295_000n }), 57_956n, 44_196n, 868, 57_956n]
    ];
    for (const [label, op, lim070, reference, calldataBytes, expected] of cases) {
        assert.equal(lim070PreVerificationGas(gasPolicy, op), lim070, `${label}: A`);
        assert.equal(referencePreVerificationGas({ ...op, preVerificationGas: gasPolicy.pvgCap }), reference, `${label}: B`);
        assert.equal(handleOpsCalldataBytes(op, V.owner), calldataBytes, `${label}: handleOps bytes`);
        assert.equal(preVerificationGasFor(gasPolicy, calldataBytes, op), expected, `${label}: the rule`);
        // The op's own preVerificationGas and its beneficiary do not move the figure.
        assert.equal(preVerificationGasFor(gasPolicy, handleOpsCalldataBytes(op, V.deployer), { ...op, preVerificationGas: 1n }), expected);
    }
    // The clamp: a floor above every term, a cap below them.
    const [, close, , , closeBytes] = cases[0];
    assert.equal(preVerificationGasFor({ ...gasPolicy, pvgFloor: 70_000n }, closeBytes, close), 70_000n);
    assert.equal(preVerificationGasFor({ ...gasPolicy, pvgCap: 60_000n }, closeBytes, close), 60_000n);
});

test('fees sit within the paymaster’s ceilings, a spike is refused, and a bump adds 12.5% up to the ceilings', () => {
    const ceilings = { maxFeeCeiling: 100_000_000_000n, priorityFeeCeiling: 5_000_000_000n };
    assert.deepEqual(selectFees({ baseFeePerGas: 10_000_000_000n, priorityFeePerGas: 2_000_000_000n, ...ceilings }),
        { maxFeePerGas: 22_000_000_000n, maxPriorityFeePerGas: 2_000_000_000n });
    assert.deepEqual(selectFees({ baseFeePerGas: 10_000_000_000n, priorityFeePerGas: 9_000_000_000n, ...ceilings }),
        { maxFeePerGas: 25_000_000_000n, maxPriorityFeePerGas: 5_000_000_000n }, 'the tip is capped by its ceiling');
    assert.equal(selectFees({ baseFeePerGas: 1n, ...ceilings }).maxPriorityFeePerGas, 1_000_000_000n, 'no suggestion: 1 gwei');
    assert.deepEqual(selectFees({ baseFeePerGas: 60_000_000_000n, priorityFeePerGas: 1n, ...ceilings }),
        { maxFeePerGas: 100_000_000_000n, maxPriorityFeePerGas: 1n }, '2 × base + tip above the ceiling: capped, not refused');
    assert.throws(() => selectFees({ baseFeePerGas: 100_000_000_000n, priorityFeePerGas: 1n, ...ceilings }),
        error => error.code === 'gas_above_paymaster_ceiling' && error.data.neededMaxFeePerGas === 100_000_000_001n
            && error.data.maxFeeCeiling === 100_000_000_000n && error.data.baseFeePerGas === 100_000_000_000n
            && error.data.maxPriorityFeePerGas === 1n && error.data.wantedMaxFeePerGas === 200_000_000_001n,
        'the refusal data: base + tip compared, and wantedMaxFeePerGas (2 × base + tip) kept for hosts that read it');
    assert.deepEqual(bumpFees({ maxFeePerGas: 20_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n }, ceilings),
        { maxFeePerGas: 22_500_000_000n, maxPriorityFeePerGas: 1_125_000_000n });
    assert.deepEqual(bumpFees({ maxFeePerGas: 90_000_000_000n, maxPriorityFeePerGas: 4_400_000_000n }, ceilings),
        { maxFeePerGas: 100_000_000_000n, maxPriorityFeePerGas: 4_950_000_000n }, 'clamped at the ceiling, still at least 10% higher');
    assert.equal(bumpFees({ maxFeePerGas: 100_000_000_000n, maxPriorityFeePerGas: 5_000_000_000n }, ceilings), null, 'nothing left to raise');
    // A bundler's replacement rule needs both fields at least 10% higher: a
    // raise the ceiling cuts below that is no replacement, so it is exhausted.
    assert.equal(bumpFees({ maxFeePerGas: 99_000_000_000n, maxPriorityFeePerGas: 4_900_000_000n }, ceilings), null, 'a 1% raise is refused by bundlers');
    assert.equal(bumpFees({ maxFeePerGas: 100_000_000_000n, maxPriorityFeePerGas: 1_000_000_000n }, ceilings), null,
        'maxFeePerGas at the ceiling: a priority-only bump is no replacement');
    assert.equal(bumpFees({ maxFeePerGas: 20_000_000_000n, maxPriorityFeePerGas: 5_000_000_000n }, ceilings), null,
        'maxPriorityFeePerGas at the ceiling: no replacement either');
});

test('selectFees: both thresholds, below, at and above (2 × base + tip caps, base + tip refuses)', () => {
    const gwei = 1_000_000_000n;
    const ceilings = { maxFeeCeiling: 100n * gwei, priorityFeeCeiling: 5n * gwei };
    const fees = (base, tip) => selectFees({ baseFeePerGas: base, priorityFeePerGas: tip, ...ceilings });
    const refused = (base, tip) => assert.throws(() => fees(base, tip), error => error.code === 'gas_above_paymaster_ceiling'
        && error.data.neededMaxFeePerGas === base + (tip < ceilings.priorityFeeCeiling ? tip : ceilings.priorityFeeCeiling));
    const tip = gwei;
    // 2 × base + tip against the ceiling: below is taken as is, at is the
    // ceiling, above is capped at the ceiling (the op still lands).
    assert.deepEqual(fees(49_500_000_000n, tip - 1n), { maxFeePerGas: 100n * gwei - 1n, maxPriorityFeePerGas: tip - 1n });
    assert.deepEqual(fees(49_500_000_000n, tip), { maxFeePerGas: 100n * gwei, maxPriorityFeePerGas: tip });
    assert.deepEqual(fees(49_500_000_000n, tip + 1n), { maxFeePerGas: 100n * gwei, maxPriorityFeePerGas: tip + 1n });
    // base + tip against the ceiling: below and at are sponsored at the
    // ceiling, one wei above is refused.
    assert.deepEqual(fees(99n * gwei - 1n, tip), { maxFeePerGas: 100n * gwei, maxPriorityFeePerGas: tip });
    assert.deepEqual(fees(99n * gwei, tip), { maxFeePerGas: 100n * gwei, maxPriorityFeePerGas: tip });
    refused(99n * gwei + 1n, tip);
    // The capped tip is the one that counts.
    assert.deepEqual(fees(95n * gwei, 9n * gwei), { maxFeePerGas: 100n * gwei, maxPriorityFeePerGas: 5n * gwei });
    refused(95n * gwei + 1n, 9n * gwei);
    // A fee pair at the ceiling has nothing left to bump: the stop before
    // valid_until takes over (the bump never leaves the ceilings).
    assert.equal(bumpFees(fees(60n * gwei, tip), ceilings), null);
});

test('selectFees asserts the fee parity table clientd asserts (same inputs, same fees or the same refusal)', () => {
    const table = JSON.parse(readFileSync(new URL('../../zkapi-clientd/internal/zkapi/testdata/gasless-fee-parity.json', import.meta.url), 'utf8'));
    assert.ok(table.cases.length >= 10);
    for (const c of table.cases) {
        const input = {
            baseFeePerGas: BigInt(c.base), priorityFeePerGas: BigInt(c.tip),
            maxFeeCeiling: BigInt(c.maxFeeCeiling ?? table.maxFeeCeiling),
            priorityFeeCeiling: BigInt(c.priorityFeeCeiling ?? table.priorityFeeCeiling)
        };
        if (c.refused) {
            assert.throws(() => selectFees(input), error => error.code === c.refused, c.name);
        } else {
            assert.deepEqual(selectFees(input), {
                maxFeePerGas: BigInt(c.maxFeePerGas), maxPriorityFeePerGas: BigInt(c.maxPriorityFeePerGas)
            }, c.name);
        }
    }
});

test('the amounts of each kind, payout_below_gas and the 25% rule with allowExpensiveGas', () => {
    const eth = value => BigInt(value) * 10n ** 18n / 1000n; // milli-ETH
    const close = gaslessAmounts({ kind: KIND.close, payoutWei: eth(500), maxCost: eth(38), flatFee: eth(1), owed: eth(2) });
    assert.equal(close.requiredWei, eth(41));
    assert.equal(close.minimumReceived, eth(459));
    assert.equal(close.uneconomic, false);
    assert.equal(close.initiationDebtMax, 0n);
    const forward = gaslessAmounts({ kind: KIND.forward, payoutWei: eth(100), maxCost: eth(2), flatFee: 0n, owed: eth(10) });
    assert.equal(forward.minimumReceived, eth(88));
    const finalize = gaslessAmounts({ kind: KIND.finalize, payoutWei: eth(100), maxCost: eth(5), flatFee: eth(1), owed: eth(10) });
    assert.equal(finalize.minimumReceived, eth(84));
    // An escape initiation pays nothing now: it must cover itself, a finalization at the same fee, the minimum net and both flat fees.
    const escape = gaslessAmounts({ kind: KIND.escape, payoutWei: eth(500), maxCost: eth(40), flatFee: eth(1), owed: 0n, finalizeReserveWei: eth(20), minEscapeNetWei: eth(5) });
    assert.equal(escape.requiredWei, eth(40 + 1 + 20 + 5 + 1));
    assert.equal(escape.initiationDebtMax, eth(41));
    assert.equal(escape.minimumReceived, null, 'an escape has no floor: its finalization is charged later at its own fees');
    assert.equal(escape.estimatedReceived, eth(500 - 40 - 1 - 20 - 1));
    assert.equal(close.estimatedReceived, null);
    assert.throws(() => gaslessAmounts({ kind: KIND.close, payoutWei: eth(40), maxCost: eth(38), flatFee: eth(1), owed: eth(2) }),
        error => error.code === 'payout_below_gas' && error.data.requiredWei === eth(41));
    assert.throws(() => gaslessAmounts({ kind: KIND.escape, payoutWei: eth(60), maxCost: eth(40), flatFee: eth(1), finalizeReserveWei: eth(20), minEscapeNetWei: eth(5) }),
        { code: 'payout_below_gas' });
    // 25%: at 30 gwei a 0.07 ETH maxCost refuses payouts under 0.28 ETH unless the host allows it.
    const cost = 70n * 10n ** 15n;
    assert.throws(() => gaslessAmounts({ kind: KIND.close, payoutWei: eth(279), maxCost: cost, flatFee: 0n }), { code: 'gasless_uneconomic' });
    assert.equal(gaslessAmounts({ kind: KIND.close, payoutWei: eth(280), maxCost: cost, flatFee: 0n }).uneconomic, false);
    const allowed = gaslessAmounts({ kind: KIND.close, payoutWei: eth(100), maxCost: cost, flatFee: 0n, allowExpensiveGas: true });
    assert.equal(allowed.uneconomic, true);
    assert.equal(allowed.minimumReceived, eth(30));
    assert.equal(gaslessAmounts({ kind: KIND.close, payoutWei: eth(100), maxCost: cost, flatFee: 0n, uneconomicFractionPercent: 70n }).uneconomic, false);
    assert.equal(GASLESS_MESSAGES.gasless_uneconomic.includes('quarter'), true);
});

test('AA codes and the paymaster’s errors decode from FailedOp / FailedOpWithRevert, with the silent ones marked', () => {
    const paused = selectorOf('SponsorshipPaused()');
    const decoded = decodeEntryPointRevert({ data: failedOpData('AA33 reverted', paused) });
    assert.equal(decoded.aa, 'AA33');
    assert.equal(decoded.opIndex, 0);
    assert.equal(decoded.inner, paused);
    assert.equal(decoded.innerError.code, 'sponsorship_paused');
    const error = entryPointError({ message: 'execution reverted', data: failedOpData('AA33 reverted', paused) });
    assert.equal(error.code, 'sponsorship_paused');
    assert.equal(error.aa, 'AA33');
    assert.equal(error.silent, false);
    // Nested provider envelopes and JSON strings are searched too.
    assert.equal(entryPointError({ code: -32603, data: { originalError: { data: failedOpData('AA31 paymaster deposit too low') } } }).code, 'paymaster_underfunded');
    assert.equal(entryPointError(JSON.stringify({ error: { data: failedOpData('AA25 invalid account nonce') } })).code, 'nonce_rejected');
    for (const [reason, code, silent] of [['AA10 sender already constructed', 'sender_already_constructed', true], ['AA25 invalid account nonce', 'nonce_rejected', true],
        ['AA24 signature error', 'signature_rejected', false], ['AA31 paymaster deposit too low', 'paymaster_underfunded', false],
        ['AA32 paymaster expired or not due', 'paymaster_time_window', false], ['AA13 initCode failed or OOG', 'init_code_failed', false],
        ['AA50 postOp reverted', 'post_op_reverted', false], ['AA51 prefund below actualGasCost', 'prefund_too_low', false]]) {
        const mapped = entryPointError({ data: failedOpData(reason) });
        assert.equal(mapped.code, code, reason);
        assert.equal(mapped.silent, silent, reason);
        assert.equal(mapped.reason, reason);
        assert.equal(ENTRY_POINT_ERRORS[reason.slice(0, 4)].code, code);
    }
    // Every paymaster, account and factory error selector maps to a code, with its arguments.
    const word = value => BigInt(value).toString(16).padStart(64, '0');
    const cases = [
        ['ExitsPaused(uint64)', 'exits_paused', word(1_700_000_000), { reopenAt: 1_700_000_000n }],
        ['AttemptsExhausted(bytes32)', 'gasless_attempts_exhausted', V.keys.close.slice(2), { key: low(V.keys.close) }],
        ['GasLimitOutOfRange(uint8,uint256,uint256,uint256)', 'gas_limit_out_of_range', `${word(2)}${word(1)}${word(600_000)}${word(950_000)}`, { field: 2n, value: 1n, floor: 600_000n, cap: 950_000n }],
        ['PayoutBelowCost(uint256,uint256)', 'payout_below_gas', `${word(5)}${word(3)}`, { required: 5n, available: 3n }],
        ['FeeAboveCap(uint256,uint256)', 'gasless_fee_above_cap', `${word(2)}${word(1)}`, { fee: 2n, cap: 1n }],
        ['MaxCostAbovePolicy(uint256,uint256)', 'max_cost_above_policy', `${word(9)}${word(8)}`, { maxCost: 9n, cap: 8n }],
        ['EscapeAlreadySponsored(uint32)', 'escape_already_sponsored', word(7), { noteId: 7n }],
        ['EscapeEvidencePending(uint32)', 'escape_evidence_pending', word(7), { noteId: 7n }],
        ['NotTransitAccount()', 'not_transit_account', '', {}], ['UnsupportedCall()', 'unsupported_call', '', {}],
        ['WrongNonceKey()', 'wrong_nonce_key', '', {}], ['BindingMismatch()', 'binding_mismatch', '', {}],
        ['DestinationNotSender()', 'destination_not_sender', '', {}], ['InvalidValidUntil()', 'invalid_valid_until', '', {}],
        ['NullifierUsed()', 'nullifier_used', '', {}], ['EscapesDisabled()', 'escapes_disabled', '', {}],
        ['NotPendingEscape()', 'not_pending_escape', '', {}], ['NotStranded()', 'not_stranded', '', {}],
        ['NotRepayable()', 'not_repayable', '', {}], ['NothingToSweep()', 'nothing_to_sweep', '', {}],
        ['InvalidPayee()', 'invalid_payee', '', {}], ['FeeAboveCeiling()', 'gas_above_paymaster_ceiling', '', {}],
        ['UnknownRoot()', 'unknown_root', '', {}], ['NoteNotActive()', 'note_not_active', '', {}],
        ['ChallengedNullifier()', 'challenged_nullifier', '', {}], ['SupersededState()', 'superseded_state', '', {}],
        ['InvalidProof()', 'invalid_proof', '', {}], ['SponsorshipInFlight(bytes32)', 'sponsorship_in_flight', word(1), { key: `0x${word(1)}` }]
    ];
    for (const [signature, code, args, expected] of cases) {
        const inner = `${selectorOf(signature)}${args}`;
        const mapped = entryPointError({ data: failedOpData('AA33 reverted', inner) });
        assert.equal(mapped.code, code, signature);
        assert.equal(mapped.selector, selectorOf(signature), signature);
        for (const [name, value] of Object.entries(expected)) assert.equal(mapped.data[name], value, `${signature} ${name}`);
        assert.equal(decodeContractRevert(inner).code, code, signature);
    }
    // VaultCallFailed(bytes) carries the vault's own error, decoded one level down.
    const vaultFailed = `${selectorOf('VaultCallFailed(bytes)')}${word(0x20)}${word(4)}${selectorOf('NoteNotActive()').slice(2).padEnd(64, '0')}`;
    assert.equal(decodeContractRevert(vaultFailed).args.reason, selectorOf('NoteNotActive()'));
    assert.equal(entryPointError({ data: 'not a revert' }), null);
    assert.equal(dryRunError({ message: 'network down' }), null);
    assert.equal(entryPointError({ data: failedOpData('something else') }).code, 'entry_point_rejected');
});

test('the receipt parsers read the EntryPoint’s and the paymaster’s events for one operation', () => {
    const entryPoint = low(V.entry_point);
    const paymaster = low(V.paymaster);
    const S = low(V.transit_account);
    const payee = low(V.payee);
    const hash = low(C.user_op_hash);
    const receipt = { transactionHash: `0x${'ab'.repeat(32)}`, blockNumber: '0x10', status: '0x1', logs: [
        logs.settled(paymaster, { key: V.keys.close, sender: S, payee, kind: 1n, noteId: 0n, received: 99n * 10n ** 15n, charged: 5n * 10n ** 15n, owedPaid: 0n, paidOut: 94n * 10n ** 15n }),
        logs.userOperationEvent(entryPoint, { hash, sender: S, paymaster, nonce: BigInt(C.nonce), success: true, actualGasCost: 4n * 10n ** 15n, actualGasUsed: 400_000n }),
        logs.userOperationEvent(entryPoint, { hash: `0x${'cd'.repeat(32)}`, sender: `0x${'11'.repeat(20)}`, paymaster, nonce: 1n, success: false })
    ].map((entry, index) => ({ ...entry, logIndex: `0x${index.toString(16)}` })) };
    const event = parseUserOperationEvent(receipt, { entryPoint, hash });
    assert.deepEqual(event, { userOpHash: hash, sender: S, paymaster, nonce: BigInt(C.nonce), success: true, actualGasCost: 4n * 10n ** 15n, actualGasUsed: 400_000n, logIndex: 1 });
    assert.equal(parseUserOperationEvent(receipt, { entryPoint, sender: S }).userOpHash, hash);
    assert.equal(parseUserOperationEvent(receipt, { entryPoint: paymaster, hash }), null, 'another contract');
    assert.equal(parseUserOperationEvent({ logs: [{ ...receipt.logs[1], removed: true }] }, { entryPoint, hash }), null, 'a removed log');
    const settled = parseSettled(receipt, paymaster, S);
    assert.equal(settled.key, low(V.keys.close));
    assert.equal(settled.paidOut, 94n * 10n ** 15n);
    assert.equal(settled.payee, payee);
    assert.equal(parseSettled(receipt, paymaster, S, { key: V.keys.escape }), null);
    assert.equal(parsePayoutCredited(receipt, paymaster, payee), null);
    const settlement = settlementOf(receipt, { entryPoint, paymaster, hash, sender: S, payee });
    assert.equal(settlement.success, true);
    assert.equal(settlement.settled.charged, 5n * 10n ** 15n);
    assert.equal(settlement.credited, null);
    assert.equal(settlement.transactionHash, `0x${'ab'.repeat(32)}`);
    assert.equal(settlement.blockNumber, 16);
    // A reverted execution: the revert reason, the paymaster's failure and the stranded mark.
    const vaultFailed = `0x${selectorOf('VaultCallFailed(bytes)').slice(2)}${'20'.padStart(64, '0')}${'4'.padStart(64, '0')}${selectorOf('NoteNotActive()').slice(2).padEnd(64, '0')}`;
    const reverted = { transactionHash: `0x${'ef'.repeat(32)}`, blockNumber: '0x11', logs: [
        logs.userOperationEvent(entryPoint, { hash, sender: S, paymaster, nonce: BigInt(C.nonce), success: false, actualGasCost: 3n }),
        logs.userOperationRevertReason(entryPoint, { hash, sender: S, nonce: BigInt(C.nonce), reason: vaultFailed }),
        logs.sponsorshipFailed(paymaster, { key: V.keys.close, sender: S, kind: 1n, noteId: 0n, actualGasCost: 3n }),
        logs.stranded(paymaster, S),
        logs.payoutCredited(paymaster, payee, 7n)
    ] };
    const failed = settlementOf(reverted, { entryPoint, paymaster, hash, sender: S, payee });
    assert.equal(failed.success, false);
    assert.equal(failed.revert.decoded.code, 'note_not_active', 'the vault error inside VaultCallFailed');
    assert.equal(parseUserOperationRevertReason(reverted, { entryPoint, hash }).revertReason, vaultFailed);
    assert.deepEqual(parseSponsorshipFailed(reverted, paymaster, S), { key: low(V.keys.close), sender: S, kind: 1, noteId: 0n, actualGasCost: 3n });
    assert.equal(parseStranded(reverted, paymaster, S), true);
    assert.deepEqual(parsePayoutCredited(reverted, paymaster, payee), { payee, amount: 7n });
    assert.equal(userOperationReceiptTransactionHash({ receipt: { transactionHash: `0x${'ab'.repeat(32)}` } }), `0x${'ab'.repeat(32)}`);
    assert.equal(userOperationReceiptTransactionHash(null), null);
    assert.equal(userOperationReceiptTransactionHash({ receipt: { transactionHash: '0x12' } }), null);
});

test('the noteId filter picks this note’s vault log out of a bundle receipt', () => {
    const vault = `0x${'22'.repeat(20)}`;
    const other = logs.mutualClose(vault, { noteId: 9n, finalBalance: 1n, destination: `0x${'33'.repeat(20)}` });
    const mine = logs.mutualClose(vault, { noteId: 7n, finalBalance: 500_000_000n, destination: V.transit_account });
    const receipt = { logs: [other, mine] };
    assert.equal(parseWithdrawalReceipt(receipt, vault, 'mutual').noteId, 9n, 'without the filter the first log wins, as before');
    const filtered = parseWithdrawalReceipt(receipt, vault, 'mutual', { noteId: 7 });
    assert.equal(filtered.noteId, 7n);
    assert.equal(filtered.destination, low(V.transit_account));
    assert.equal(parseWithdrawalReceipt(receipt, vault, 'mutual', { noteId: 8 }), null);
    assert.equal(parseWithdrawalReceipt(receipt, vault, 'finalize', { noteId: 7 }), null);
});

test('the availability verdict follows the pre-flight order of §3.1', () => {
    const policy = { sponsorshipPaused: false, escapesEnabled: false };
    assert.equal(availabilityVerdict({ bundler: { reachable: false }, policy }).reason, 'bundler_unavailable');
    assert.equal(availabilityVerdict({ bundler: { reachable: true, wrongChain: true }, policy }).reason, 'bundler_wrong_chain');
    assert.equal(availabilityVerdict({ bundler: { reachable: true, supportsEntryPoint: false }, policy }).reason, 'bundler_unsupported_entry_point');
    assert.equal(availabilityVerdict({ policy: { ...policy, sponsorshipPaused: true } }).reason, 'sponsorship_paused');
    assert.equal(availabilityVerdict({ policy, kind: KIND.escape }).reason, 'escapes_disabled');
    assert.equal(availabilityVerdict({ policy, policyMatches: false }).reason, 'gasless_policy_mismatch');
    assert.equal(availabilityVerdict({ policy, depositWei: 1n, maxCost: 2n }).reason, 'paymaster_underfunded');
    assert.equal(availabilityVerdict({ policy, vaultPaused: true, reopenAt: 5 }).reason, 'exits_paused');
    assert.equal(availabilityVerdict({ policy, vaultPaused: true, kind: KIND.finalize }).available, true, 'finalization is never gated by the pause');
    assert.equal(availabilityVerdict({ policy, attempts: 3n }).reason, 'gasless_attempts_exhausted');
    assert.equal(availabilityVerdict({ policy, attempts: 2n, depositWei: 5n, maxCost: 5n }).available, true);
    const verdict = availabilityVerdict({ policy, attempts: 3n });
    assert.equal(verdict.message, GASLESS_MESSAGES.gasless_attempts_exhausted);
});

test('the bundler client speaks JSON-RPC over fetch without credentials, refines refusals and reports outages', async () => {
    const calls = [];
    const answers = [];
    const fetchImpl = async (url, init) => {
        calls.push({ url, init });
        const body = JSON.parse(init.body);
        const next = answers.shift();
        if (next instanceof Error) throw next;
        return { ok: true, status: 200, json: async () => ({ jsonrpc: '2.0', id: body.id, ...next }) };
    };
    const client = bundlerClient('https://bundler.example/rpc', { fetchImpl });
    answers.push({ result: '0xaa36a7' }, { result: [low(V.entry_point)] }, { result: low(C.user_op_hash) });
    assert.equal(await client.chainId(), 11155111n);
    assert.deepEqual(await client.supportedEntryPoints(), [low(V.entry_point)]);
    assert.equal(await client.sendUserOperation(userOperationJson(vectorOperation()), V.entry_point), low(C.user_op_hash));
    assert.equal(calls[2].init.credentials, 'omit');
    assert.equal(JSON.parse(calls[2].init.body).method, 'eth_sendUserOperation');
    assert.equal(JSON.parse(calls[2].init.body).params[1], V.entry_point);
    answers.push({ error: { code: -32507, message: 'AA31 paymaster deposit too low' } });
    await assert.rejects(client.sendUserOperation({}, V.entry_point), error => error.code === 'paymaster_underfunded' && error.aa === 'AA31' && error.rpcCode === -32507);
    // ERC-7769's codes without an AA code: -32508 the paymaster's balance (EREP-010), -32507 the signature; never a fee refusal.
    answers.push({ error: { code: -32508, message: 'paymaster balance too low to cover all pending UserOperations' } });
    await assert.rejects(client.sendUserOperation({}, V.entry_point), error => error.code === 'paymaster_underfunded' && error.aa === null && error.rpcCode === -32508);
    answers.push({ error: { code: -32507, message: 'Invalid UserOp signature or paymaster signature' } });
    await assert.rejects(client.sendUserOperation({}, V.entry_point), error => error.code === 'signature_rejected' && error.rpcCode === -32507);
    answers.push({ error: { code: -32602, message: 'maxPriorityFeePerGas must be at least 1000000000' } });
    await assert.rejects(client.sendUserOperation({}, V.entry_point), error => error.code === 'bundler_rejected' && error.rpcCode === -32602);
    answers.push({ error: { code: -32500, message: 'validation reverted', data: failedOpData('AA33 reverted', selectorOf('AttemptsExhausted(bytes32)') + V.keys.close.slice(2)) } });
    await assert.rejects(client.sendUserOperation({}, V.entry_point), error => error.code === 'gasless_attempts_exhausted');
    answers.push({ error: { code: -32601, message: 'Method not found' } });
    await assert.rejects(client.chainId(), { code: 'bundler_rejected' });
    answers.push(new TypeError('fetch failed'));
    await assert.rejects(client.getUserOperationReceipt(C.user_op_hash), { code: 'bundler_unavailable' });
    answers.push({ result: '0x12' });
    await assert.rejects(client.sendUserOperation({}, V.entry_point), { code: 'bundler_rejected' });
    answers.push({ result: null });
    assert.equal(await client.getUserOperationByHash(C.user_op_hash), null);
    // A host transport on the provider (duck typing) and URL validation.
    const host = bundlerClient({ sendUserOperation: async () => low(C.user_op_hash), getUserOperationReceipt: async () => null });
    assert.equal(host.kind, 'host');
    assert.equal(await host.sendUserOperation({}, V.entry_point), low(C.user_op_hash));
    assert.equal(await host.chainId(), null);
    assert.equal(await host.supportedEntryPoints(), null);
    assert.equal(bundlerUrl('https://bundler.example/rpc/'), 'https://bundler.example/rpc/');
    assert.equal(bundlerUrl('http://localhost:4337'), 'http://localhost:4337/');
    for (const bad of ['http://bundler.example/rpc', 'https://user:pw@bundler.example/', 'ftp://x', 'nope']) {
        assert.throws(() => bundlerUrl(bad), { code: 'bundler_url_invalid' }, bad);
    }
    assert.throws(() => bundlerClient(null), { code: 'bundler_unavailable' });
    assert.throws(() => bundlerClient({}), TypeError);
    await assert.rejects(bundlerClient({ request: async () => { throw revertError(failedOpData('AA10 sender already constructed')); } })
        .sendUserOperation({}, V.entry_point), error => error.code === 'sender_already_constructed' && error.silent === true);
    assert.equal(decodePolicy(`0x${[1n, 2n, 3n, 1n, 0n].map(v => v.toString(16).padStart(64, '0')).join('')}`).escapesEnabled, true);
    assert.equal(decodeQuote(`0x${[1n, 2n, 3n, 4n, 1n, 0n].map(v => v.toString(16).padStart(64, '0')).join('')}`).attemptsLeft, true);
});

test('every sponsored-withdrawal error code the SDK throws is listed in the README error table', () => {
    const source = ['../services/zkapiClient.js', '../services/zkapiGasless.mjs']
        .map(path => readFileSync(new URL(path, import.meta.url), 'utf8')).join('\n');
    const thrown = new Set([...source.matchAll(/gaslessError\('([a-z0-9_]+)'/g)].map(match => match[1]));
    assert.ok(thrown.has('user_op_pending') && thrown.has('gasless_record_not_pinned'));
    const table = readFileSync(new URL('../README.md', import.meta.url), 'utf8').split('\n')
        .filter(line => line.startsWith('| Sponsored withdrawals')).join('\n');
    assert.ok(table, 'the README has the sponsored-withdrawal rows');
    assert.deepEqual([...thrown].filter(code => !table.includes(`\`${code}\``)), []);
});
