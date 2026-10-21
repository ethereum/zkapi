// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Ownable} from "@openzeppelin/contracts/access/Ownable.sol";
import {Ownable2Step} from "@openzeppelin/contracts/access/Ownable2Step.sol";

import {ZkApiVault} from "../ZkApiVault.sol";
import {Types} from "../libraries/Types.sol";
import {MerkleUpdateLib} from "../libraries/MerkleUpdateLib.sol";
import {ReentrancyGuardTransient} from "../libraries/ReentrancyGuardTransient.sol";
import {IZkApiProofAdapter} from "../interfaces/IZkApiProofAdapter.sol";
import {IEntryPoint, IPaymaster, PackedUserOperation, UserOpGas} from "./IERC4337.sol";
import {ZkApiWithdrawalAccount} from "./ZkApiWithdrawalAccount.sol";
import {ZkApiWithdrawalAccountFactory} from "./ZkApiWithdrawalAccountFactory.sol";

/// @title ZkApiWithdrawalPaymaster
/// @notice Sponsors the gas of vault exits whose destination is a transit account S, so that the
///         payout address needs no ETH. In validation it re-runs every deterministic vault check and
///         the Groth16 verification, maps the vault's time checks to the operation's validity window,
///         and bounds every gas field, fee and cost; in postOp it keeps a measured charge out of what
///         S forwarded, re-deposits it, and pushes the rest to S's payee. The operator's float (its
///         EntryPoint deposit) is the only asset at risk: user funds enter P only from S and leave
///         only to S's payee, the deposit, or a credit the payee can claim.
/// @dev One contract holds every rule: validation-time refusals (uncharged: the bundler drops the
///      operation in simulation, or pays itself if the state changed before inclusion), per-key
///      attempt counting written in validation so it survives any execution outcome, one
///      sponsorship per key per transaction (a transient lock, since a bundle is validated whole
///      before any of it executes), and a postOp
///      that never reverts within its gas floor (no loops, no bubbling external call, guarded
///      arithmetic). Validation never reads block time, number or gas price, calls only contracts
///      with code, reads only its own and the vault's storage and writes only its own.
contract ZkApiWithdrawalPaymaster is Ownable2Step, ReentrancyGuardTransient, IPaymaster {
    using UserOpGas for PackedUserOperation;

    // ------------------------------------------------------------------------------ kinds and keys

    uint8 internal constant KIND_CLOSE = 1;
    uint8 internal constant KIND_ESCAPE = 2;
    uint8 internal constant KIND_FINALIZE = 3;
    uint8 internal constant KIND_FORWARD = 4;
    /// @notice The nonce key of a FORWARD operation (CLOSE/ESCAPE use uint192(withdrawalNullifier),
    ///         FINALIZE uint192(pending.withdrawalNullifier)).
    uint192 public constant FORWARD_NONCE_KEY = uint192(uint256(keccak256("zkapi.gasless.forward")));

    // -------------------------------------------------------------------------- pinned EntryPoint

    /// @notice keccak256 of the canonical EntryPoint v0.7.0 runtime (identical on every chain).
    bytes32 public constant ENTRY_POINT_V070_CODEHASH =
        0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58;
    /// @dev P (20) ‖ paymasterVerificationGasLimit (16) ‖ paymasterPostOpGasLimit (16) ‖ feeCapWei (12).
    uint256 private constant PAYMASTER_DATA_LENGTH = 64;
    /// @dev withdraw(bytes) with a 0-, 36- or 836-byte argument: selector + offset word + length word.
    uint256 private constant CALLDATA_HEAD = 68;
    uint256 private constant EXIT_CALL_LENGTH = 836;
    uint256 private constant FINALIZE_CALL_LENGTH = 36;
    uint256 private constant PROOF_OFFSET_WORD = 0x220;
    uint256 private constant PROOF_LENGTH = 0x100;

    // ------------------------------------------------------------------------------ gas constants
    // Measured by test/gasless/Gas.t.sol and RealAdapter.t.sol with every account and slot cold (a
    // bundler's simulation and the inclusion both run cold) and pinned in snapshots/gasless-gas.json,
    // whose entry names the comments below quote; every floor exceeds the measured need by at least
    // ERC-7562's VALIDATION_GAS_SLACK (4,000), and every cap stays below MAX_VERIFICATION_GAS where
    // the rules apply. The tests assert each rule, so a figure that drifts fails CI instead of
    // going stale here.

    /// @notice callGasLimit floors per kind: the measured execution through S (accountCall*) with
    ///         the real Groth16 adapter (adapterVerifyCold), a treasury that uses its whole
    ///         100,000-gas push and a never-used treasury or destination (25,000, EIP-161), under
    ///         the 63/64 rule, plus 20,000.
    uint256 internal constant CALL_FLOOR_CLOSE = 540_000;
    uint256 internal constant CALL_FLOOR_ESCAPE = 540_000;
    uint256 internal constant CALL_FLOOR_FINALIZE = 250_000;
    uint256 internal constant CALL_FLOOR_FORWARD = 80_000;
    /// @notice Upper bounds of callGasLimit per kind; the owner's callCap may only sit at or below.
    uint256 internal constant CALL_HARD_CAP_CLOSE = 950_000;
    uint256 internal constant CALL_HARD_CAP_ESCAPE = 1_100_000;
    uint256 internal constant CALL_HARD_CAP_FINALIZE = 400_000;
    uint256 internal constant CALL_HARD_CAP_FORWARD = 150_000;
    /// @notice paymasterPostOpGasLimit bounds: the worst postOp path is a 100,000-gas push that
    ///         burns everything, then the credit bookkeeping (postOpWorst), and a finalization with
    ///         a debt adds POSTOP_FINALIZE_EXTRA_GAS; Gas.t.sol asserts the floor at least 60,000
    ///         above their sum, and at least 30,000 above the reverted path with a debt to settle
    ///         (postOpRevertedWithDebt).
    uint256 internal constant POSTOP_FLOOR = 250_000;
    uint256 internal constant POSTOP_CAP = 350_000;
    /// @notice verificationGasLimit bounds without and with initCode (the CREATE2 of the 221-byte
    ///         proxy): the least limit the EntryPoint accepts (minVerificationGasWithoutInitCode /
    ///         minVerificationGasWithInitCode) plus VALIDATION_GAS_SLACK, rounded up to 10,000.
    uint256 internal constant VERIFICATION_FLOOR = 50_000;
    uint256 internal constant VERIFICATION_FLOOR_INIT = 140_000;
    uint256 internal constant VERIFICATION_CAP = 400_000;
    /// @notice preVerificationGas bounds.
    uint256 internal constant PVG_FLOOR = 40_000;
    uint256 internal constant PVG_CAP = 150_000;
    /// @notice paymasterVerificationGasLimit bounds: the floor is the larger cold measurement with the
    ///         real Groth16 adapter (paymasterValidationEscapeCold, the shape that reads the most
    ///         vault state, or paymasterValidationCold) plus VALIDATION_GAS_SLACK, rounded up to
    ///         10,000; both measurements fit under the cap with 20,000 to spare; the cap is
    ///         MAX_VERIFICATION_GAS minus VALIDATION_GAS_SLACK.
    uint256 internal constant PM_VERIFICATION_FLOOR = 400_000;
    uint256 internal constant PM_VERIFICATION_CAP = 496_000;
    /// @notice postOp's own gas on a CLOSE or FORWARD settling path with a plain transfer to a
    ///         funded EOA (postOpEoa): POSTOP_BASE_GAS + EOA_PUSH_GAS is pinned at or under the
    ///         measurement and within 10,000 of it, like POSTOP_ESCAPE_GAS under postOpEscape, so
    ///         that the end-to-end charge sits under MARGIN_GAS over the real cost and the margin,
    ///         not the estimate, absorbs cold/warm variance in both directions.
    uint256 internal constant POSTOP_BASE_GAS = 17_000;
    /// @notice postOp's whole gas on an ESCAPE initiation (the debt and the two escape records).
    uint256 internal constant POSTOP_ESCAPE_GAS = 71_200;
    /// @notice What a FINALIZE adds to the settling path: the debt deduction and the escape record.
    ///         Pinned between the two measured differences, postOpFinalizeNoDebt − postOpEoa and
    ///         postOpFinalize − postOpEoa.
    uint256 internal constant POSTOP_FINALIZE_EXTRA_GAS = 5_000;
    /// @notice What a balance S forwards adds to an ESCAPE initiation's charge: the deposit of the
    ///         debt it settles and the credit of the rest (CREDIT_GAS of it). In isolation the path
    ///         costs postOpEscapeWithBalance − postOpEscape more than a plain initiation, but end to
    ///         end the penalty on the unused limits and the margin absorb part of it: pinned under
    ///         that difference so that the charge sits within MARGIN_GAS + CREDIT_GAS of the real
    ///         cost on the dearest variant (the first escape of S, every slot cold and zero;
    ///         overchargeEscapeWithBalance), as on the credit path of a close.
    uint256 internal constant POSTOP_ESCAPE_FORWARD_GAS = 30_000;
    /// @notice The push to a payee: a plain transfer (EOA_PUSH_GAS), the EIP-161 surcharge of a
    ///         never-used address (NEW_ACCOUNT_GAS, postOpEmptyEoa − postOpEoa), the gas forwarded
    ///         to a payee with code (PAYOUT_PUSH_GAS, charged in full because the push cannot measure
    ///         what it used) and, only when the push fails, the credit bookkeeping (CREDIT_GAS,
    ///         postOpRejecter − postOpEoa).
    uint256 internal constant EOA_PUSH_GAS = 9_100;
    uint256 internal constant NEW_ACCOUNT_GAS = 25_000;
    uint256 internal constant PAYOUT_PUSH_GAS = 100_000;
    uint256 internal constant CREDIT_GAS = 46_000;
    /// @notice The EntryPoint's call into S, the proxy, S's dispatch and its repay call: execution gas
    ///         outside the window S measures (accountCall* − accountMeasured*, with and without a
    ///         value to forward), pinned at or above the measurement and within 4,000 of it.
    uint256 internal constant ACCOUNT_CALL_OVERHEAD_GAS = 55_500;
    uint256 internal constant ACCOUNT_CALL_OVERHEAD_ESCAPE_GAS = 28_900;
    /// @notice Covers cold/warm variance; the measured charge exceeds the real cost by at most this
    ///         on every settling path with an EOA payee (the handleOps* entries), and by at most
    ///         this plus CREDIT_GAS when a payout is credited.
    uint256 internal constant MARGIN_GAS = 15_000;
    /// @dev Upper bounds for the lostWei metric of a reverted execution: postOp's own gas on that
    ///      path (the EntryPoint adds it and the 10% penalty on the unused limits after this call),
    ///      and what settling a debt out of a balance an earlier operation forwarded adds to it (the
    ///      debt's slot and the deposit); Gas.t.sol measures both paths (postOpReverted*).
    uint256 internal constant FAILURE_POSTOP_GAS = 70_000;
    uint256 internal constant FAILURE_DEBT_DEPOSIT_GAS = 20_000;
    /// @notice The finalization reserve an escape initiation must leave: the finalize shape's minimum
    ///         limits, charged at the initiation's maxFeePerGas.
    uint256 internal constant FINALIZE_RESERVE_GAS =
        PVG_FLOOR + VERIFICATION_FLOOR + CALL_FLOOR_FINALIZE + PM_VERIFICATION_FLOOR + POSTOP_FLOOR;
    /// @notice Sponsorships per key, success or failure, before the owner must release the key.
    uint8 internal constant MAX_ATTEMPTS = 3;

    // ------------------------------------------------------------------------------ policy bounds

    uint256 internal constant FLAT_FEE_HARD_CAP = 0.001 ether;
    uint256 internal constant MAX_FEE_HARD_CAP = 500 gwei;
    uint256 internal constant PRIORITY_FEE_HARD_CAP = 20 gwei;
    uint256 internal constant MAX_SPONSORED_COST_HARD_CAP = 0.25 ether;

    // ---------------------------------------------------------------------------------- immutables

    IEntryPoint public immutable entryPoint;
    ZkApiVault public immutable vault;
    IZkApiProofAdapter public immutable adapter;
    ZkApiWithdrawalAccountFactory public immutable factory;
    /// @notice Wei per vault unit, read from the vault (never hard-coded).
    uint256 public immutable WEI_PER_UNIT;
    uint256 public immutable STATE_X;
    uint256 public immutable STATE_Y;
    uint256 public immutable CLEAR_X;
    uint256 public immutable CLEAR_Y;
    uint64 public immutable MAX_PAUSE_DURATION;
    bytes32 public immutable accountCreationCodeHash;

    // ------------------------------------------------------------------------------------- storage
    // Slot order is fixed; add only at the end.

    struct Policy {
        uint128 maxSponsoredCost;
        uint64 flatFeeWei;
        uint64 minEscapeNetWei;
        bool escapesEnabled;
        bool sponsorshipPaused;
    }

    Policy public policy;
    /// @notice Fee ceilings in wei per gas; the owner or feeKeeper sets them under the hard caps.
    uint256 public maxFeeCeiling;
    uint256 public priorityFeeCeiling;
    /// @notice May call setFeeCeilings only.
    address public feeKeeper;
    /// @notice The current callGasLimit cap per kind (floor ≤ cap ≤ hard cap; default = hard cap).
    mapping(uint8 => uint256) public callCap;
    /// @notice Sponsorships per key, written in validation.
    mapping(bytes32 => uint8) public attempts;
    /// @notice Wei a transit account owes (its sponsored escape initiation), keyed by S.
    mapping(address => uint256) public owed;
    /// @notice One sponsored initiation per note, ever.
    mapping(uint32 => bool) public escapeSponsored;
    /// @notice S → noteId + 1 of its open sponsored escape (0 = none): the FORWARD evidence that a
    ///         third party's finalization paid that note's escape into S. One open record per S:
    ///         a second sponsored ESCAPE from S is refused (EscapeEvidencePending) while the
    ///         recorded note is pending, or closed with S's balance nonzero (the first escape's
    ///         payout sits in S and FORWARD must settle it first); it may replace the record once
    ///         the note is active again (the first escape was defeated) or closed with S empty.
    ///         Every settling shape of the recorded note clears it: a sponsored FINALIZE or CLOSE
    ///         of that note in postOp, FORWARD in validation when it consumes the evidence.
    mapping(address => uint256) public escapeNotePlusOne;
    /// @notice S whose sponsored CLOSE or FINALIZE reverted: the payout may sit in S.
    mapping(address => bool) public stranded;
    /// @notice Wei S forwarded during the current operation.
    mapping(address => uint256) public received;
    /// @notice The execution gas S reported during the current operation.
    mapping(address => uint256) public receivedGas;
    /// @notice Payouts whose push failed, claimable by anyone for the payee.
    mapping(address => uint256) public credits;
    uint256 public totalCredits;
    /// @notice An upper bound of the gas cost of sponsored operations whose execution reverted
    ///         (metric): what the EntryPoint reported to postOp plus the most it adds afterwards.
    uint256 public lostWei;
    /// @notice Charges a payout could not cover (metric).
    uint256 public shortfallWei;

    // -------------------------------------------------------------------------------------- events

    event Sponsored(
        bytes32 indexed key, address indexed sender, address indexed payee, uint8 kind, uint32 noteId, uint256 maxCost
    );
    event Settled(
        bytes32 indexed key,
        address indexed sender,
        address indexed payee,
        uint8 kind,
        uint32 noteId,
        uint256 received,
        uint256 charged,
        uint256 owedPaid,
        uint256 paidOut
    );
    event SponsorshipFailed(
        bytes32 indexed key, address indexed sender, uint8 kind, uint32 noteId, uint256 actualGasCost
    );
    event EscapeInitiationOwed(address indexed sender, uint32 indexed noteId, uint256 owedWei);
    event Shortfall(address indexed sender, uint32 noteId, uint256 shortfallWei);
    event PayoutCredited(address indexed payee, uint256 amount);
    event CreditClaimed(address indexed payee, uint256 amount);
    event Collected(address indexed sender, address indexed payee, uint256 received, uint256 owedPaid, uint256 paidOut);
    event Stranded(address indexed sender);
    event ForwardAllowed(address indexed sender);
    event PolicySet(Policy policy);
    event FeeCeilingsSet(uint256 maxFee, uint256 priority);
    event FeeKeeperSet(address indexed keeper);
    event CallCapSet(uint8 kind, uint256 cap);
    event Released(bytes32 indexed key);
    event DebtWrittenOff(address indexed sender, uint256 amount);
    event Rescued(address indexed to, uint256 amount);

    // -------------------------------------------------------------------------------------- errors
    // Each is a distinct selector so clients can map the inner bytes of an AA33 FailedOpWithRevert.

    error NotEntryPoint();
    error SponsorshipPaused();
    /// @notice A sponsorship of this key, or of this note, is already in flight in this transaction:
    ///         the EntryPoint validates a whole bundle before it executes any of it, so a second
    ///         operation that the first would make fail is refused in validation rather than
    ///         reverted in execution at the float's expense. Two locks, both transient:
    ///         - the attempts key (the same close replayed at the next nonce). An ERC-4337 bundler
    ///           never includes two operations of one sender in a bundle, so this one fires only
    ///           against a non-compliant or malicious bundler. Clients therefore replace a pending
    ///           operation only at the same nonce (a fee bump) and never build a new operation for
    ///           a key while an older one may still be in a mempool.
    ///         - the note of a CLOSE, ESCAPE or FINALIZE, key = keccak256(abi.encode(bytes32("note"),
    ///           uint256(noteId))): an escape and a close of one note, or closes at two of its
    ///           nullifiers, have different keys and, from different transit accounts, may be
    ///           bundled by a compliant bundler, yet at most one of them can execute.
    ///         Either way the whole bundle fails on-chain validation (the bundler pays, nothing is
    ///         counted). A bundler's pre-send simulation returns the FailedOp at its index, so it
    ///         drops that operation and resubmits the rest; ERC-7562 GREP-040 lets it throttle or
    ///         ban the paymaster for it.
    error SponsorshipInFlight(bytes32 key);
    error BadPaymasterData();
    error FeeAboveCap(uint256 fee, uint256 cap);
    error FeeAboveCeiling();
    /// @notice field: 0 preVerificationGas, 1 verificationGasLimit, 2 callGasLimit,
    ///         3 paymasterVerificationGasLimit, 4 paymasterPostOpGasLimit.
    error GasLimitOutOfRange(uint8 field, uint256 value, uint256 floor, uint256 cap);
    error MaxCostAbovePolicy(uint256 maxCost, uint256 cap);
    error NotTransitAccount();
    error UnsupportedCall();
    error WrongNonceKey();
    error AttemptsExhausted(bytes32 key);
    error BindingMismatch();
    error DestinationNotSender();
    error InvalidValidUntil();
    error UnknownRoot();
    error NoteNotActive();
    error NullifierUsed();
    error InvalidFelt();
    error WrongKind();
    error InvalidBalance();
    error BadSuccessor();
    error ChallengedNullifier();
    error SupersededState();
    error EscapesDisabled();
    error EscapeAlreadySponsored(uint32 noteId);
    /// @notice S's recorded sponsored escape of `noteId` is still open (pending, or closed with its
    ///         payout in S): a second sponsored escape would overwrite the FORWARD evidence.
    error EscapeEvidencePending(uint32 noteId);
    error PayoutBelowCost(uint256 required, uint256 available);
    error ExitsPaused(uint64 reopenAt);
    error NotPendingEscape();
    error NotStranded();
    error NotRepayable();
    error ZeroAmount();
    error NativeTransferFailed();
    error CreditsReserved();
    error BadEntryPoint();
    error BadVault();
    error PolicyOutOfBounds();
    error CeilingOutOfRange();
    error CallCapOutOfRange();
    error InvalidKind();
    error NotFeeKeeper();
    /// @notice Only the owner may set the stake's terms: a first stake, a longer unstake delay or
    ///         a re-lock after unlockStake.
    error StakeTermsLocked();

    // --------------------------------------------------------------------------------- structures

    /// @dev The fixed-size postOp context (ERC-7562 EREP-055), encoded by validation.
    struct Ctx {
        uint8 kind;
        bytes32 key;
        address sender;
        address payee;
        uint32 noteId;
        uint256 maxCost;
        uint256 callGasLimit;
        uint256 postOpGasLimit;
        uint256 flatFee;
    }

    /// @dev What a shape's validation hands back.
    struct Outcome {
        uint48 validUntil;
        uint48 validAfter;
        uint32 noteId;
        bytes32 key;
    }

    /// @dev The operation-wide figures a shape's validation needs.
    struct Figures {
        address sender;
        uint256 nonce;
        uint256 maxCost;
        uint256 maxFee;
        uint256 required;
        bool estimating;
    }

    /// @notice The immutable gas policy the clients mirror; the live callGasLimit cap is callCap(kind).
    struct GasPolicy {
        uint256[4] callFloor;
        uint256[4] callHardCap;
        uint256 postOpFloor;
        uint256 postOpCap;
        uint256 verificationFloor;
        uint256 verificationFloorInit;
        uint256 verificationCap;
        uint256 pvgFloor;
        uint256 pvgCap;
        uint256 pmVerificationFloor;
        uint256 pmVerificationCap;
        uint256 postOpBaseGas;
        uint256 postOpEscapeGas;
        uint256 postOpFinalizeExtraGas;
        uint256 postOpEscapeForwardGas;
        uint256 eoaPushGas;
        uint256 newAccountGas;
        uint256 payoutPushGas;
        uint256 creditGas;
        uint256 accountCallOverheadGas;
        uint256 accountCallOverheadEscapeGas;
        uint256 marginGas;
        uint256 finalizeReserveGas;
        uint256 maxAttempts;
    }

    // -------------------------------------------------------------------------------- constructor

    /// @dev Pins the EntryPoint by runtime codehash, checks the vault's protocol and concession
    ///      versions, reads the adapter, both key pairs, the pause bound and the unit size from the
    ///      vault, and deploys the factory. Every call cap starts at its hard cap.
    constructor(
        IEntryPoint entryPoint_,
        ZkApiVault vault_,
        address owner_,
        Policy memory policy_,
        uint256 maxFeeCeiling_,
        uint256 priorityFeeCeiling_
    ) Ownable(owner_) {
        if (address(entryPoint_).codehash != ENTRY_POINT_V070_CODEHASH) revert BadEntryPoint();
        if (vault_.PROTOCOL_VERSION() != 2 || vault_.CONCESSION_ESCAPE_VERSION() != 1) revert BadVault();
        IZkApiProofAdapter adapter_ = vault_.proofAdapter();
        if (address(adapter_).code.length == 0) revert BadVault();
        entryPoint = entryPoint_;
        vault = vault_;
        adapter = adapter_;
        WEI_PER_UNIT = vault_.nativeAssetWeiPerUnit();
        STATE_X = vault_.stateSigningKeyX();
        STATE_Y = vault_.stateSigningKeyY();
        CLEAR_X = vault_.clearanceSigningKeyX();
        CLEAR_Y = vault_.clearanceSigningKeyY();
        MAX_PAUSE_DURATION = vault_.maxPauseDuration();
        ZkApiWithdrawalAccountFactory factory_ =
            new ZkApiWithdrawalAccountFactory(address(entryPoint_), address(vault_));
        factory = factory_;
        accountCreationCodeHash = factory_.accountCreationCodeHash();
        _setPolicy(policy_);
        _setFeeCeilings(maxFeeCeiling_, priorityFeeCeiling_);
        callCap[KIND_CLOSE] = CALL_HARD_CAP_CLOSE;
        callCap[KIND_ESCAPE] = CALL_HARD_CAP_ESCAPE;
        callCap[KIND_FINALIZE] = CALL_HARD_CAP_FINALIZE;
        callCap[KIND_FORWARD] = CALL_HARD_CAP_FORWARD;
    }

    // ---------------------------------------------------------------------------------- validation

    /// @inheritdoc IPaymaster
    /// @dev Every refusal is one of the custom errors above, so a client maps the AA33 inner bytes.
    ///      The order is: the paymaster's own policy, the gas fields, the sender's provenance, the
    ///      callData shape, then the shape's vault checks, with the proof verified last. With
    ///      maxFeePerGas == 0 (the bundler's estimation convention) the checks that depend on maxCost
    ///      are skipped; state checks never are.
    function validatePaymasterUserOp(PackedUserOperation calldata op, bytes32, uint256 maxCost)
        external
        returns (bytes memory context, uint256 validationData)
    {
        if (msg.sender != address(entryPoint)) revert NotEntryPoint();
        Policy memory pol = policy;
        if (pol.sponsorshipPaused) revert SponsorshipPaused();
        if (op.paymasterAndData.length != PAYMASTER_DATA_LENGTH) revert BadPaymasterData();
        uint256 feeCap = uint96(bytes12(op.paymasterAndData[52:64]));
        if (pol.flatFeeWei > feeCap) revert FeeAboveCap(pol.flatFeeWei, feeCap);
        Figures memory f;
        f.sender = op.sender;
        f.nonce = op.nonce;
        f.maxCost = maxCost;
        f.maxFee = op.maxFeePerGas();
        f.estimating = f.maxFee == 0;
        if (!f.estimating && (f.maxFee > maxFeeCeiling || op.maxPriorityFeePerGas() > priorityFeeCeiling)) {
            revert FeeAboveCeiling();
        }
        _checkRange(0, op.preVerificationGas, PVG_FLOOR, PVG_CAP);
        _checkRange(
            1,
            op.verificationGasLimit(),
            op.initCode.length != 0 ? VERIFICATION_FLOOR_INIT : VERIFICATION_FLOOR,
            VERIFICATION_CAP
        );
        _checkRange(3, op.paymasterVerificationGasLimit(), PM_VERIFICATION_FLOOR, PM_VERIFICATION_CAP);
        uint256 postOpGas = op.paymasterPostOpGasLimit();
        _checkRange(4, postOpGas, POSTOP_FLOOR, POSTOP_CAP);
        if (!f.estimating && maxCost > pol.maxSponsoredCost) revert MaxCostAbovePolicy(maxCost, pol.maxSponsoredCost);
        (bool transit, address payee) = _transitPayee(f.sender);
        if (!transit) revert NotTransitAccount();
        (uint8 kind, bytes calldata vaultCall) = _parseCallData(op.callData);
        uint256 callGas = op.callGasLimit();
        _checkRange(2, callGas, _callFloor(kind), callCap[kind]);
        // Every settling shape deducts what S owes, so the payout must cover it too.
        f.required = maxCost + pol.flatFeeWei + owed[f.sender];

        Outcome memory o;
        if (kind == KIND_FINALIZE) o = _validateFinalize(f, vaultCall);
        else if (kind == KIND_FORWARD) o = _validateForward(f);
        else o = _validateExit(kind, f, vaultCall, pol);

        bytes32 key = o.key;
        uint8 used = attempts[key];
        if (used >= MAX_ATTEMPTS) revert AttemptsExhausted(key);
        // The EntryPoint validates every operation of a bundle before it executes any, so a second
        // operation for the same key (the same close replayed at the next nonce) would pass the
        // state checks above and revert in execution at the float's expense, burning the key's
        // attempts for free. One sponsorship per key per transaction: the lock is transient (an
        // own slot, ERC-7562 OP-070), so the second operation fails the bundle's validation instead
        // (the bundler pays, nothing is counted), and postOp releases it once the outcome is state.
        // A compliant bundler never bundles two operations of one sender, so the lock only ever
        // fires against a non-compliant or malicious one (see SponsorshipInFlight); clients replace
        // a pending operation only at the same nonce and never build a new operation for a key
        // while an older one may still be in a mempool.
        uint256 locked;
        assembly ("memory-safe") {
            locked := tload(key)
        }
        if (locked != 0) revert SponsorshipInFlight(key);
        // The same holds across keys of one note: an ESCAPE and a CLOSE of a note, or CLOSEs at two
        // of its nullifiers, have different keys, and when their senders differ a compliant bundler
        // bundles them. Every one passes the note's state checks, at most one executes, and the
        // rest revert after the full verification at the float's expense, with nothing reaching
        // their senders for a FORWARD to recover. One sponsorship per note per transaction too.
        bytes32 noteLock;
        if (kind != KIND_FORWARD) {
            noteLock = _noteLock(o.noteId);
            assembly ("memory-safe") {
                locked := tload(noteLock)
            }
            if (locked != 0) revert SponsorshipInFlight(noteLock);
        }
        // Own storage, in the outer frame: the count persists for every included operation
        // whatever its execution and postOp do.
        attempts[key] = used + 1;
        // The sender's sponsorships in flight, for repay(): counted here and decremented by each
        // postOp, so two notes of one S may be closed in one bundle. Transient, so a withdraw()
        // reached through any other route cannot park funds in this contract. A key is a hash and a
        // sender an address, so the two slots never coincide.
        address sender = f.sender;
        assembly ("memory-safe") {
            tstore(key, 1)
            if noteLock { tstore(noteLock, 1) }
            tstore(sender, add(tload(sender), 1))
        }
        emit Sponsored(key, sender, payee, kind, o.noteId, maxCost);
        context = abi.encode(
            Ctx({
                kind: kind,
                key: key,
                sender: sender,
                payee: payee,
                noteId: o.noteId,
                maxCost: maxCost,
                callGasLimit: callGas,
                postOpGasLimit: postOpGas,
                flatFee: pol.flatFeeWei
            })
        );
        validationData = (uint256(o.validUntil) << 160) | (uint256(o.validAfter) << 208);
    }

    /// @dev CLOSE and ESCAPE: the proof's binding, time bound, root, note, nullifier and nonce key,
    ///      then the kind's own rules, the payout against the required cost, and the proof last.
    function _validateExit(uint8 kind, Figures memory f, bytes calldata vaultCall, Policy memory pol)
        private
        view
        returns (Outcome memory o)
    {
        Types.WithdrawalPublicInputs memory inputs = abi.decode(vaultCall[4:516], (Types.WithdrawalPublicInputs));
        if (inputs.destination != f.sender) revert DestinationNotSender();
        if (
            inputs.protocolVersion != 2 || inputs.chainId != block.chainid || inputs.contractAddress != address(vault)
                || inputs.stateSigningKeyX != STATE_X || inputs.stateSigningKeyY != STATE_Y
                || inputs.clearanceSigningKeyX != CLEAR_X || inputs.clearanceSigningKeyY != CLEAR_Y
        ) revert BindingMismatch();
        // Zero would mean "no expiry" to the EntryPoint; the vault refuses after validUntil.
        if (inputs.validUntil == 0 || inputs.validUntil > type(uint48).max) revert InvalidValidUntil();
        o.validUntil = uint48(inputs.validUntil);
        // Validation cannot compare with the clock: while paused the vault refuses exits until
        // pausedAt + maxPauseDuration, so refuse here and tell the client when exits reopen.
        if (vault.paused()) revert ExitsPaused(vault.pausedAt() + MAX_PAUSE_DURATION);
        if (!vault.isKnownRoot(inputs.activeRoot)) revert UnknownRoot();
        (, uint128 depositAmount,, Types.NoteStatus status) = vault.notes(inputs.noteId);
        if (status != Types.NoteStatus.Active) revert NoteNotActive();
        uint256 n = inputs.withdrawalNullifier;
        if (n >= MerkleUpdateLib.FIELD_MODULUS) revert InvalidFelt();
        if (vault.usedNullifiers(n)) revert NullifierUsed();
        if (f.nonce >> 64 != uint256(uint192(n))) revert WrongNonceKey();
        o.noteId = inputs.noteId;
        if (kind == KIND_CLOSE) {
            if (inputs.kind != 1) revert WrongKind();
            if (inputs.finalBalance > depositAmount) revert InvalidBalance();
            uint256 expected = uint256(inputs.finalBalance) * WEI_PER_UNIT;
            if (!f.estimating && expected < f.required) revert PayoutBelowCost(f.required, expected);
            o.key = keyFor(KIND_CLOSE, n, 0, address(0));
        } else {
            if (inputs.kind != 0) revert WrongKind();
            if (!pol.escapesEnabled) revert EscapesDisabled();
            if (escapeSponsored[inputs.noteId]) revert EscapeAlreadySponsored(inputs.noteId);
            // One open sponsored escape per S: the record is the FORWARD evidence of the first
            // escape and must not be overwritten before that escape settles (see escapeNotePlusOne).
            (bool open, uint32 openNote) = _openEscape(f.sender);
            if (open) revert EscapeEvidencePending(openNote);
            uint256 nn = inputs.nextNullifier;
            if (nn == 0 || nn == n) revert BadSuccessor();
            if (nn >= MerkleUpdateLib.FIELD_MODULUS) revert InvalidFelt();
            if (vault.challengedNullifiers(n)) revert ChallengedNullifier();
            if (vault.challengedNullifiers(nn)) revert SupersededState();
            if (vault.usedNullifiers(nn)) revert NullifierUsed();
            if (uint256(inputs.finalBalance) + inputs.conceded > depositAmount) revert InvalidBalance();
            // Nothing is paid at initiation: the payout must cover this operation, a gasless
            // finalization at the same fee, the policy's minimum net and both flat fees.
            uint256 payout = uint256(inputs.finalBalance) * WEI_PER_UNIT;
            uint256 needed = f.required + FINALIZE_RESERVE_GAS * f.maxFee + pol.minEscapeNetWei + pol.flatFeeWei;
            if (!f.estimating && payout < needed) revert PayoutBelowCost(needed, payout);
            o.key = keyFor(KIND_ESCAPE, 0, inputs.noteId, address(0));
        }
        // Last, after every cheap refusal: the Groth16 verification dominates the gas.
        adapter.assertValidWithdrawal(inputs, vaultCall[580:836]);
    }

    /// @dev Whether S's recorded sponsored escape is still open: the note is pending, or closed with
    ///      S's balance nonzero (BALANCE is allowed in validation: P is staked, ERC-7562 OP-080).
    ///      An active note (the escape was defeated) or a closed one with S empty is settled.
    function _openEscape(address s) private view returns (bool open, uint32 noteId) {
        uint256 recorded = escapeNotePlusOne[s];
        if (recorded == 0) return (false, 0);
        noteId = uint32(recorded - 1);
        (,,, Types.NoteStatus status) = vault.notes(noteId);
        open = status == Types.NoteStatus.PendingWithdrawal || (status == Types.NoteStatus.Closed && s.balance != 0);
    }

    /// @dev FINALIZE: the pending escape must pay S, and the operation is valid from its deadline on
    ///      (the EntryPoint accepts timestamp >= validAfter, exactly the vault's rule). Not gated by
    ///      the pause: finalization stays open while paused.
    function _validateFinalize(Figures memory f, bytes calldata vaultCall) private view returns (Outcome memory o) {
        uint32 noteId = uint32(uint256(bytes32(vaultCall[4:36])));
        (bool exists,, uint256 nullifier, uint128 finalBalance, address destination, uint64 deadline) =
            vault.pendingWithdrawals(noteId);
        (,,, Types.NoteStatus status) = vault.notes(noteId);
        if (!exists || status != Types.NoteStatus.PendingWithdrawal) revert NotPendingEscape();
        if (destination != f.sender) revert DestinationNotSender();
        if (f.nonce >> 64 != uint256(uint192(nullifier))) revert WrongNonceKey();
        o.validAfter = uint48(deadline);
        uint256 expected = uint256(finalBalance) * WEI_PER_UNIT;
        if (!f.estimating && expected < f.required) revert PayoutBelowCost(f.required, expected);
        o.noteId = noteId;
        o.key = keyFor(KIND_FINALIZE, 0, noteId, address(0));
    }

    /// @dev FORWARD: only with paymaster-recorded evidence that a payout may sit in S (a sponsored
    ///      CLOSE/FINALIZE that reverted, or the note of S's sponsored escape closed by a third
    ///      party's finalization), consumed here so each piece of evidence sponsors one forward.
    function _validateForward(Figures memory f) private returns (Outcome memory o) {
        bool strandedHere = stranded[f.sender];
        uint256 notePlusOne = escapeNotePlusOne[f.sender];
        bool escapeClosed;
        if (notePlusOne != 0) {
            (,,, Types.NoteStatus status) = vault.notes(uint32(notePlusOne - 1));
            escapeClosed = status == Types.NoteStatus.Closed;
        }
        if (!strandedHere && !escapeClosed) revert NotStranded();
        if (f.nonce >> 64 != uint256(FORWARD_NONCE_KEY)) revert WrongNonceKey();
        // BALANCE is allowed here: the paymaster is staked (ERC-7562 OP-080). Only what S holds
        // counts: a forward delivers S's balance and nothing else (a vault escape-payout credit, if
        // one ever existed, is claimed through the vault first and then forwarded or swept).
        uint256 bal = f.sender.balance;
        if (!f.estimating && bal < f.required) revert PayoutBelowCost(f.required, bal);
        if (strandedHere) delete stranded[f.sender];
        if (escapeClosed) delete escapeNotePlusOne[f.sender];
        o.noteId = escapeClosed ? uint32(notePlusOne - 1) : type(uint32).max;
        o.key = keyFor(KIND_FORWARD, 0, 0, f.sender);
    }

    /// @dev The exact callData shapes: withdraw(bytes) with a strict ABI layout and a vault call of
    ///      0 (FORWARD), 36 (FINALIZE) or 836 bytes (CLOSE or ESCAPE by the vault selector).
    function _parseCallData(bytes calldata callData) private pure returns (uint8 kind, bytes calldata vaultCall) {
        if (callData.length < CALLDATA_HEAD) revert UnsupportedCall();
        if (bytes4(callData[0:4]) != ZkApiWithdrawalAccount.withdraw.selector) revert UnsupportedCall();
        if (uint256(bytes32(callData[4:36])) != 0x20) revert UnsupportedCall();
        uint256 len = uint256(bytes32(callData[36:68]));
        if (len != 0 && len != FINALIZE_CALL_LENGTH && len != EXIT_CALL_LENGTH) revert UnsupportedCall();
        uint256 padded = ((len + 31) / 32) * 32;
        if (callData.length != CALLDATA_HEAD + padded) revert UnsupportedCall();
        if (uint256(bytes32(callData[CALLDATA_HEAD + len:])) != 0) revert UnsupportedCall();
        vaultCall = callData[CALLDATA_HEAD:CALLDATA_HEAD + len];
        if (len == 0) return (KIND_FORWARD, vaultCall);
        bytes4 selector = bytes4(vaultCall[0:4]);
        if (len == FINALIZE_CALL_LENGTH) {
            if (selector != ZkApiVault.finalizeEscapeWithdrawal.selector) revert UnsupportedCall();
            if (uint256(bytes32(vaultCall[4:36])) > type(uint32).max) revert UnsupportedCall();
            return (KIND_FINALIZE, vaultCall);
        }
        if (
            uint256(bytes32(vaultCall[516:548])) != PROOF_OFFSET_WORD
                || uint256(bytes32(vaultCall[548:580])) != PROOF_LENGTH
        ) revert UnsupportedCall();
        if (selector == ZkApiVault.mutualClose.selector) return (KIND_CLOSE, vaultCall);
        if (selector == ZkApiVault.initiateEscapeWithdrawal.selector) return (KIND_ESCAPE, vaultCall);
        revert UnsupportedCall();
    }

    function _checkRange(uint8 field, uint256 value, uint256 floor, uint256 cap) private pure {
        if (value < floor || value > cap) revert GasLimitOutOfRange(field, value, floor, cap);
    }

    /// @dev A factory-created transit account: its immutables reproduce its CREATE2 address.
    function _transitPayee(address account) private view returns (bool ok, address payee) {
        if (account.code.length == 0) return (false, address(0));
        ZkApiWithdrawalAccount s = ZkApiWithdrawalAccount(payable(account));
        address owner_ = s.owner();
        payee = s.payee();
        ok = factory.getAddress(owner_, payee) == account;
    }

    // ------------------------------------------------------------------- execution-phase entries

    /// @notice Called by S inside withdraw(): forwards S's balance with the execution gas S measured.
    ///         Accepted only from a sender with a sponsored operation in flight: validation counts
    ///         that sender after recomputing its provenance, and the count lives only inside the
    ///         EntryPoint transaction, so no other contract and no other route can park funds here.
    ///         What arrives is settled by the sponsored operation's postOp, whatever route it took.
    function repay(uint256 executionGasUsed) external payable {
        address s = msg.sender;
        uint256 inFlight;
        assembly ("memory-safe") {
            inFlight := tload(s)
        }
        if (inFlight == 0) revert NotRepayable();
        received[s] += msg.value;
        receivedGas[s] = executionGasUsed;
    }

    /// @notice Called by S.sweep() outside an operation: deducts what S owes first, pushes the rest to
    ///         S's payee and credits it when the push fails. Never reverts on the payee.
    function collect() external payable nonReentrant {
        address s = msg.sender;
        (bool ok, address payee) = _transitPayee(s);
        if (!ok) revert NotRepayable();
        uint256 due = owed[s];
        uint256 take = msg.value < due ? msg.value : due;
        if (take != 0) {
            owed[s] = due - take;
            entryPoint.depositTo{value: take}(address(this));
        }
        uint256 payout = msg.value - take;
        if (payout != 0 && !_push(payee, payout)) _credit(payee, payout);
        emit Collected(s, payee, msg.value, take, payout);
    }

    // ------------------------------------------------------------------------------------- postOp

    /// @inheritdoc IPaymaster
    /// @dev Never reverts within POSTOP_FLOOR: the only external calls are the EntryPoint's depositTo
    ///      (cannot fail) and one bounded low-level push; no loops; guarded arithmetic; a context
    ///      this contract encoded. The EntryPoint adds postOp's own gas and the 10% penalty on the
    ///      unused limits after this call, so the charge estimates them from pinned constants and
    ///      the gas S reported, plus a margin, and caps at the prefund.
    function postOp(PostOpMode mode, bytes calldata context, uint256 actualGasCost, uint256 feePerGas) external {
        if (msg.sender != address(entryPoint)) revert NotEntryPoint();
        Ctx memory c = abi.decode(context, (Ctx));
        address sender = c.sender;
        bytes32 key = c.key;
        // The outcome is state now: release the key and the note, and count this sponsorship of
        // the sender out.
        bytes32 noteLock = c.kind == KIND_FORWARD ? bytes32(0) : _noteLock(c.noteId);
        assembly ("memory-safe") {
            tstore(key, 0)
            if noteLock { tstore(noteLock, 0) }
            let inFlight := tload(sender)
            if inFlight { tstore(sender, sub(inFlight, 1)) }
        }
        uint256 got = received[sender];
        uint256 execUsed = receivedGas[sender];
        if (got != 0) delete received[sender];
        if (execUsed != 0) delete receivedGas[sender];
        uint256 debt = owed[sender];
        if (mode != PostOpMode.opSucceeded) {
            // The vault call reverted and its state rolled back, so this operation forwarded
            // nothing. Only an unsponsored operation of S executed earlier in the bundle, while this
            // sponsorship was in flight, can have forwarded a balance (a finalization or a replayed
            // close paid to S). That balance is settled like every other arrival: the debt of S is
            // deducted first and deposited (an escape's debt cannot be dodged by pairing the
            // sponsored finalization with an unsponsored one), and only the rest is credited to the
            // payee, so user funds never sit here outside the accounting.
            uint256 take;
            if (got != 0) {
                take = got < debt ? got : debt;
                if (take != 0) {
                    owed[sender] = debt - take;
                    entryPoint.depositTo{value: take}(address(this));
                }
                if (got != take) _credit(c.payee, got - take);
            }
            // The payout may sit in S (a replayed close, a third-party finalization): FORWARD may
            // collect it.
            if (c.kind == KIND_CLOSE || c.kind == KIND_FINALIZE) {
                stranded[sender] = true;
                emit Stranded(sender);
            }
            // The metric records an upper bound of the final cost: the EntryPoint still adds this
            // call's gas and up to 10% of the call and postOp limits as the unused-gas penalty.
            uint256 thisCall = FAILURE_POSTOP_GAS;
            if (take != 0) thisCall += FAILURE_DEBT_DEPOSIT_GAS;
            if (got != take) thisCall += CREDIT_GAS;
            lostWei += actualGasCost + ((c.callGasLimit + c.postOpGasLimit) / 10 + thisCall) * feePerGas;
            emit SponsorshipFailed(key, sender, c.kind, c.noteId, actualGasCost);
            return;
        }
        // Exact: actualGasCost = actualGas * gasPrice. feePerGas is 0 only in estimation.
        uint256 actualGas = feePerGas == 0 ? 0 : actualGasCost / feePerGas;
        bool payeeHasCode = c.payee.code.length != 0;
        // EXTCODEHASH is zero exactly for an account the EVM holds empty (EIP-161: no code, zero
        // nonce, zero balance), the one case the push pays the new-account surcharge for; a drained
        // account that has sent a transaction has keccak256("") and costs no more than a funded one.
        bool payeeIsEmpty = c.payee.codehash == bytes32(0);
        uint256 chargeWei = chargeFor(
            c.kind, actualGas, execUsed, c.callGasLimit, c.postOpGasLimit, payeeHasCode, payeeIsEmpty, feePerGas
        ) + c.flatFee;
        // The EntryPoint never charges more than the prefund.
        if (chargeWei > c.maxCost + c.flatFee) chargeWei = c.maxCost + c.flatFee;
        if (c.kind == KIND_ESCAPE) {
            // Nothing is paid at initiation: the charge joins S's debt, collected on every later
            // path. A balance S happened to hold (a direct payout that reached it earlier) settles
            // the debt first, like every other path; what is left is credited to the payee (the
            // escape's postOp has no push). The deposit and the credit bookkeeping are charged to
            // the balance as well; when nothing is left to credit, half of that covers the deposit.
            uint256 escapeDebt = debt + chargeWei;
            uint256 taken;
            if (got != 0) {
                taken = got < escapeDebt ? got : escapeDebt;
                uint256 rest = got - taken;
                uint256 extra = (rest != 0 ? POSTOP_ESCAPE_FORWARD_GAS : POSTOP_ESCAPE_FORWARD_GAS / 2) * feePerGas;
                chargeWei += extra;
                escapeDebt += extra;
                if (rest != 0) {
                    uint256 more = extra < rest ? extra : rest;
                    taken += more;
                    rest -= more;
                    if (rest != 0) _credit(c.payee, rest);
                }
                entryPoint.depositTo{value: taken}(address(this));
            }
            owed[sender] = escapeDebt - taken;
            escapeSponsored[c.noteId] = true;
            escapeNotePlusOne[sender] = uint256(c.noteId) + 1;
            emit EscapeInitiationOwed(sender, c.noteId, chargeWei);
            emit Settled(key, sender, c.payee, c.kind, c.noteId, got, chargeWei, taken, got - taken);
            return;
        }
        uint256 due = chargeWei + debt;
        uint256 keep = got < due ? got : due;
        // The operation's own charge is covered first, then the debt.
        uint256 owedPaid = keep > chargeWei ? keep - chargeWei : 0;
        if (owedPaid != 0) owed[sender] = debt - owedPaid;
        // A sponsored FINALIZE or CLOSE of the recorded note settles S's open escape (a CLOSE of it
        // follows a defeat): the record is stale now and a later sponsored escape may replace it.
        if (c.kind != KIND_FORWARD && escapeNotePlusOne[sender] == uint256(c.noteId) + 1) {
            delete escapeNotePlusOne[sender];
        }
        if (got < due) {
            // Only a raise after a reserve-checked initiation can lower a payout below its debt.
            uint256 short = due - got;
            shortfallWei += short;
            emit Shortfall(sender, c.noteId, short);
        }
        uint256 payout = got - keep;
        if (payout != 0 && !_push(c.payee, payout)) {
            // A payee that refused or burned the push pays for the credit bookkeeping too.
            uint256 surcharge = CREDIT_GAS * feePerGas;
            if (surcharge > payout) surcharge = payout;
            chargeWei += surcharge;
            keep += surcharge;
            _credit(c.payee, payout - surcharge);
        }
        // The float replenishes itself; the flat fee stays in the deposit as revenue.
        if (keep != 0) entryPoint.depositTo{value: keep}(address(this));
        emit Settled(c.key, sender, c.payee, c.kind, c.noteId, got, chargeWei, owedPaid, got - keep);
    }

    /// @dev Sends `amount` with at most PAYOUT_PUSH_GAS and copies no return data.
    function _push(address payee, uint256 amount) private returns (bool success) {
        assembly ("memory-safe") {
            success := call(PAYOUT_PUSH_GAS, payee, amount, 0, 0, 0, 0)
        }
    }

    function _credit(address payee, uint256 amount) private {
        credits[payee] += amount;
        totalCredits += amount;
        emit PayoutCredited(payee, amount);
    }

    /// @notice Pays `payee` its credited payouts with all available gas; anyone may call it, only the
    ///         payee is paid, and a failed transfer reverts and keeps the credit.
    function claimCredit(address payee) external nonReentrant {
        uint256 amount = credits[payee];
        if (amount == 0) revert ZeroAmount();
        delete credits[payee];
        totalCredits -= amount;
        emit CreditClaimed(payee, amount);
        (bool success,) = payable(payee).call{value: amount}("");
        if (!success) revert NativeTransferFailed();
    }

    // -------------------------------------------------------------------------------------- views

    /// @notice The charge formula postOp applies, in wei, before the flat fee, the cap at
    ///         maxCost + flatFee and the CREDIT_GAS surcharge of a failed push: the EntryPoint's gas
    ///         so far, the pinned postOp and push gas of the kind and payee, the 10% penalty on the
    ///         unused call and postOp limits, and the margin.
    function chargeFor(
        uint8 kind,
        uint256 actualGas,
        uint256 executionGasUsed,
        uint256 callGasLimit,
        uint256 postOpGasLimit,
        bool payeeHasCode,
        bool payeeIsEmpty,
        uint256 feePerGas
    ) public pure returns (uint256 chargeWei) {
        uint256 postOpGas;
        uint256 overhead;
        if (kind == KIND_ESCAPE) {
            postOpGas = POSTOP_ESCAPE_GAS;
            overhead = ACCOUNT_CALL_OVERHEAD_ESCAPE_GAS;
        } else {
            postOpGas = POSTOP_BASE_GAS + EOA_PUSH_GAS;
            if (payeeHasCode) postOpGas += PAYOUT_PUSH_GAS;
            else if (payeeIsEmpty) postOpGas += NEW_ACCOUNT_GAS;
            if (kind == KIND_FINALIZE) postOpGas += POSTOP_FINALIZE_EXTRA_GAS;
            overhead = ACCOUNT_CALL_OVERHEAD_GAS;
        }
        if (executionGasUsed > callGasLimit) executionGasUsed = callGasLimit;
        uint256 usedOfLimit = executionGasUsed + overhead + postOpGas;
        uint256 limit = callGasLimit + postOpGasLimit;
        uint256 penalty = limit > usedOfLimit ? (limit - usedOfLimit) / 10 : 0;
        chargeWei = (actualGas + postOpGas + penalty + MARGIN_GAS) * feePerGas;
    }

    /// @notice What a sponsorship of `kind` for `sender` needs: the payout it must bring (this
    ///         operation's maxCost, the flat fee, the debt and, for an escape, the finalization
    ///         reserve, the minimum net and the second flat fee), the debt and fee on their own,
    ///         whether the key has attempts left and whether an escape of the note from `sender`
    ///         can still be sponsored (escapes enabled, the note never sponsored, no open sponsored
    ///         escape recorded for `sender`). `nullifier` keys a CLOSE; the other kinds key by
    ///         `noteId` or `sender`.
    function quote(uint8 kind, address sender, uint32 noteId, uint256 nullifier, uint256 maxCost, uint256 maxFeePerGas)
        external
        view
        returns (
            uint256 requiredWei,
            uint256 owedWei,
            uint256 flatFeeWei,
            uint256 finalizeReserveWei,
            bool attemptsLeft,
            bool escapeOpen
        )
    {
        Policy memory pol = policy;
        owedWei = owed[sender];
        flatFeeWei = pol.flatFeeWei;
        requiredWei = maxCost + flatFeeWei + owedWei;
        if (kind == KIND_ESCAPE) {
            finalizeReserveWei = FINALIZE_RESERVE_GAS * maxFeePerGas;
            requiredWei += finalizeReserveWei + pol.minEscapeNetWei + flatFeeWei;
        }
        attemptsLeft = attempts[keyFor(kind, nullifier, noteId, sender)] < MAX_ATTEMPTS;
        (bool open,) = _openEscape(sender);
        escapeOpen = pol.escapesEnabled && !escapeSponsored[noteId] && !open;
    }

    /// @notice The key the attempts of a sponsorship are counted under.
    function keyFor(uint8 kind, uint256 nullifier, uint32 noteId, address sender) public pure returns (bytes32) {
        if (kind == KIND_CLOSE) return keccak256(abi.encode("close", nullifier));
        if (kind == KIND_ESCAPE) return keccak256(abi.encode("escape", noteId));
        if (kind == KIND_FINALIZE) return keccak256(abi.encode("finalize", noteId));
        if (kind == KIND_FORWARD) return keccak256(abi.encode("forward", sender));
        revert InvalidKind();
    }

    /// @dev The transient slot of a note's in-flight lock (see SponsorshipInFlight). A hash, so it
    ///      coincides neither with an attempts key (other tags) nor with a sender's slot (an address).
    function _noteLock(uint32 noteId) private pure returns (bytes32 slot) {
        assembly ("memory-safe") {
            mstore(0x00, "note")
            mstore(0x20, noteId)
            slot := keccak256(0x00, 0x40)
        }
    }

    /// @notice The pinned gas policy, for the profile and the clients' cross-check.
    function gasPolicy() external pure returns (GasPolicy memory g) {
        g.callFloor = [CALL_FLOOR_CLOSE, CALL_FLOOR_ESCAPE, CALL_FLOOR_FINALIZE, CALL_FLOOR_FORWARD];
        g.callHardCap = [CALL_HARD_CAP_CLOSE, CALL_HARD_CAP_ESCAPE, CALL_HARD_CAP_FINALIZE, CALL_HARD_CAP_FORWARD];
        g.postOpFloor = POSTOP_FLOOR;
        g.postOpCap = POSTOP_CAP;
        g.verificationFloor = VERIFICATION_FLOOR;
        g.verificationFloorInit = VERIFICATION_FLOOR_INIT;
        g.verificationCap = VERIFICATION_CAP;
        g.pvgFloor = PVG_FLOOR;
        g.pvgCap = PVG_CAP;
        g.pmVerificationFloor = PM_VERIFICATION_FLOOR;
        g.pmVerificationCap = PM_VERIFICATION_CAP;
        g.postOpBaseGas = POSTOP_BASE_GAS;
        g.postOpEscapeGas = POSTOP_ESCAPE_GAS;
        g.postOpFinalizeExtraGas = POSTOP_FINALIZE_EXTRA_GAS;
        g.postOpEscapeForwardGas = POSTOP_ESCAPE_FORWARD_GAS;
        g.eoaPushGas = EOA_PUSH_GAS;
        g.newAccountGas = NEW_ACCOUNT_GAS;
        g.payoutPushGas = PAYOUT_PUSH_GAS;
        g.creditGas = CREDIT_GAS;
        g.accountCallOverheadGas = ACCOUNT_CALL_OVERHEAD_GAS;
        g.accountCallOverheadEscapeGas = ACCOUNT_CALL_OVERHEAD_ESCAPE_GAS;
        g.marginGas = MARGIN_GAS;
        g.finalizeReserveGas = FINALIZE_RESERVE_GAS;
        g.maxAttempts = MAX_ATTEMPTS;
    }

    /// @dev The callGasLimit floor of a kind.
    function _callFloor(uint8 kind) private pure returns (uint256) {
        if (kind == KIND_CLOSE) return CALL_FLOOR_CLOSE;
        if (kind == KIND_ESCAPE) return CALL_FLOOR_ESCAPE;
        if (kind == KIND_FINALIZE) return CALL_FLOOR_FINALIZE;
        if (kind == KIND_FORWARD) return CALL_FLOOR_FORWARD;
        revert InvalidKind();
    }

    /// @dev The callGasLimit hard cap of a kind.
    function _callHardCap(uint8 kind) private pure returns (uint256) {
        if (kind == KIND_CLOSE) return CALL_HARD_CAP_CLOSE;
        if (kind == KIND_ESCAPE) return CALL_HARD_CAP_ESCAPE;
        if (kind == KIND_FINALIZE) return CALL_HARD_CAP_FINALIZE;
        if (kind == KIND_FORWARD) return CALL_HARD_CAP_FORWARD;
        revert InvalidKind();
    }

    /// @notice The transit account of (owner, payee): factory.getAddress.
    function transitAccount(address owner_, address payee) external view returns (address) {
        return factory.getAddress(owner_, payee);
    }

    // ----------------------------------------------------------------------------- owner and keeper

    function setPolicy(Policy calldata policy_) external onlyOwner {
        _setPolicy(policy_);
    }

    function _setPolicy(Policy memory policy_) private {
        if (policy_.maxSponsoredCost > MAX_SPONSORED_COST_HARD_CAP || policy_.flatFeeWei > FLAT_FEE_HARD_CAP) {
            revert PolicyOutOfBounds();
        }
        policy = policy_;
        emit PolicySet(policy_);
    }

    /// @notice Lowers (or restores up to the hard cap) the callGasLimit a kind accepts.
    function setCallCap(uint8 kind, uint256 cap) external onlyOwner {
        if (cap < _callFloor(kind) || cap > _callHardCap(kind)) revert CallCapOutOfRange();
        callCap[kind] = cap;
        emit CallCapSet(kind, cap);
    }

    function setFeeKeeper(address keeper) external onlyOwner {
        feeKeeper = keeper;
        emit FeeKeeperSet(keeper);
    }

    /// @notice The owner or the fee keeper sets the ceilings, both nonzero and under the hard caps.
    function setFeeCeilings(uint256 maxFee, uint256 priority) external {
        if (msg.sender != owner() && msg.sender != feeKeeper) revert NotFeeKeeper();
        _setFeeCeilings(maxFee, priority);
    }

    function _setFeeCeilings(uint256 maxFee, uint256 priority) private {
        if (maxFee == 0 || priority == 0 || maxFee > MAX_FEE_HARD_CAP || priority > PRIORITY_FEE_HARD_CAP) {
            revert CeilingOutOfRange();
        }
        maxFeeCeiling = maxFee;
        priorityFeeCeiling = priority;
        emit FeeCeilingsSet(maxFee, priority);
    }

    /// @notice Resets the attempts of `keys`: widens only the owner's own exposure.
    function release(bytes32[] calldata keys) external onlyOwner {
        for (uint256 i = 0; i < keys.length; ++i) {
            delete attempts[keys[i]];
            emit Released(keys[i]);
        }
    }

    /// @notice Lets `sender` forward a balance that reached it without paymaster-recorded evidence.
    function allowForward(address sender) external onlyOwner {
        stranded[sender] = true;
        emit ForwardAllowed(sender);
    }

    /// @notice Accounting only: clears what `sender` owes.
    function writeOffDebt(address sender) external onlyOwner {
        uint256 amount = owed[sender];
        delete owed[sender];
        emit DebtWrittenOff(sender, amount);
    }

    /// @notice Adds to the paymaster's EntryPoint deposit. Anyone may fund the float.
    function deposit() external payable {
        entryPoint.depositTo{value: msg.value}(address(this));
    }

    /// @notice Withdraws from the EntryPoint deposit.
    function withdrawTo(address payable to, uint256 amount) external onlyOwner {
        entryPoint.withdrawTo(to, amount);
    }

    /// @notice Stakes the paymaster with the EntryPoint. The owner sets the terms: the first stake, a
    ///         longer unstake delay and a re-lock after unlockStake come only from it. Anyone else may
    ///         add to a locked stake at its current delay, which changes nothing but the amount. The
    ///         EntryPoint rewrites the terms on every addStake (the delay can only grow and a pending
    ///         unlock is cancelled), so an open call would let a stranger freeze the stake for 1 wei.
    function addStake(uint32 unstakeDelaySec) external payable {
        if (msg.sender != owner()) {
            IEntryPoint.DepositInfo memory info = entryPoint.getDepositInfo(address(this));
            if (!info.staked || info.unstakeDelaySec != unstakeDelaySec) revert StakeTermsLocked();
        }
        entryPoint.addStake{value: msg.value}(unstakeDelaySec);
    }

    function unlockStake() external onlyOwner {
        entryPoint.unlockStake();
    }

    function withdrawStake(address payable to) external onlyOwner {
        entryPoint.withdrawStake(to);
    }

    /// @notice Moves ETH that reached this contract outside the accounting (a forced transfer); the
    ///         credited payouts are reserved for their payees and no owner function can touch them.
    function rescueUnaccounted(uint256 amount, address to) external onlyOwner {
        if (amount == 0) revert ZeroAmount();
        if (amount > address(this).balance - totalCredits) revert CreditsReserved();
        emit Rescued(to, amount);
        (bool success,) = payable(to).call{value: amount}("");
        if (!success) revert NativeTransferFailed();
    }
}
