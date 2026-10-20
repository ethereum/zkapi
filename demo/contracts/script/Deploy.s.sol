// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Script} from "forge-std/Script.sol";
import {VmSafe} from "forge-std/Vm.sol";
import {console2} from "forge-std/console2.sol";

import {ZkApiVault} from "zkapi-contracts/ZkApiVault.sol";
import {Groth16ProofAdapter} from "zkapi-contracts/adapters/Groth16ProofAdapter.sol";
import {IEntryPoint} from "zkapi-contracts/gasless/IERC4337.sol";
import {ZkApiWithdrawalAccountFactory} from "zkapi-contracts/gasless/ZkApiWithdrawalAccountFactory.sol";
import {ZkApiWithdrawalPaymaster} from "zkapi-contracts/gasless/ZkApiWithdrawalPaymaster.sol";
import {ZkApiExitBatcher} from "zkapi-contracts/periphery/ZkApiExitBatcher.sol";
import {SigningKeyChecks} from "./SigningKeyChecks.sol";
import {SetupPolicy} from "./SetupPolicy.sol";

/// @title DeployScript – zkAPI vault deployment (circuit zkapi-v2-concession-v1, vault revision 3).
/// @notice Deploys (or reuses) the vault's Poseidon, Bn254PoseidonRuntime, after checking its
///         runtime codehash against the setup's poseidon-runtime.json, deploys the circuit-specific
///         Groth16 verifier folded for the vault (the address the vault gets next, the chain and the
///         signing keys) and the native ETH ZkApiVault with its 12 constructor arguments, checks the
///         adapter's circuit and verifying-key hashes against the setup manifest, its folded
///         constants against the vault's and its folded points against the manifest's verifying
///         keys, and the vault's getters against the inputs, then (unless GASLESS=0) deploys the
///         gasless-withdrawal paymaster against the canonical ERC-4337 EntryPoint v0.7.0 in the same
///         broadcast, stakes it and its transit-account factory, funds its deposit and checks its
///         getters, deploys the ZkApiExitBatcher of the vault (batched exits through the adapter's
///         batch verification; stateless, permissionless and redeployable) with per-kind item gas
///         caps for the chain's gas schedule, and writes the provisional deployment manifest,
///         including the Poseidon address and every runtime codehash, to $OUTPUT_PATH.pending.
/// @dev    forge runs run() locally before it sends any transaction, so every check here and the
///         provisional manifest describe the simulated deployment: its addresses assume the
///         deployer's nonces at simulation time, and deployBlockLowerBound is the chain head the
///         simulation ran on, which precedes every creation. Nothing here proves the broadcast
///         landed. After --broadcast, finalize the manifest against the chain:
///           node scripts/expected-codehashes.mjs --deployment $OUTPUT_PATH.pending \
///             --rpc $RPC_URL --finalize $OUTPUT_PATH
///         It reads the creation receipts from forge's broadcast log, requires each creation to
///         have succeeded at the manifest's address and the runtime codehashes, owner and treasury
///         on chain to be the expected ones (and, with the paymaster, its deposit, both stakes, its
///         policy and gas policy), and only then writes $OUTPUT_PATH with deployBlock (the block
///         that created the vault) and deploymentStatus "deployed". Profiles take their pins and
///         deploy_block from $OUTPUT_PATH only. A dry run (no --broadcast) writes deploymentStatus
///         "simulated", which finalize refuses.
///         The vault links no library: it takes the Poseidon runtime's address as its last
///         constructor argument (an immutable, called with STATICCALL). The runtime is compiled
///         with the legacy pipeline (foundry.toml compilation_restrictions; script/PoseidonRuntime
///         Artifact.sol pulls it into out/) and deployed from its artifact.
///         The gasless block needs the canonical EntryPoint v0.7.0 runtime at ENTRY_POINT and the
///         SenderCreator runtime at 0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C, both pinned by
///         keccak256 (the paymaster's constructor pins the EntryPoint the same way): on a public
///         chain they are deployed already; on Anvil etch them first with anvil_setCode from
///         protocol/contracts/test/fixtures/*.runtime.hex (CI shows the commands); a forge dry run
///         without an RPC has neither, so pass GASLESS=0 there. "Local" is decided by chain ID alone
///         (31337, 1337): an Anvil started with a public chain ID needs the etched runtimes and the
///         explicit stake and deposit amounts (PAYMASTER_STAKE_WEI, FACTORY_STAKE_WEI,
///         PAYMASTER_DEPOSIT_WEI), or GASLESS=0.
///         Reads these environment variables:
///           PRIVATE_KEY – deployer key (also the vault owner on local chains
///                         unless OWNER is set).
///           OWNER       – vault owner (bounded pause, timelocked treasury changes).
///                         Required except on local chains (31337/1337); use a
///                         multisig or timelock contract. The constructor sets it
///                         directly; later transfers are two-step (transferOwnership
///                         nominates, the new owner calls acceptOwnership).
///           TREASURY    – operator payout address.
///           OUTPUT_PATH – absolute path of the final deployment manifest JSON; the
///                         script writes the provisional one to OUTPUT_PATH.pending.
///           STATE_SIGNING_KEY_X/Y – deployment-pinned Baby-JubJub key (`zkapi signing-keys`).
///           CLEARANCE_SIGNING_KEY_X/Y – deployment-pinned Baby-JubJub key.
///                         Both keys must be points of Baby-JubJub's prime-order subgroup
///                         (ark-ed-on-bn254, the circuits' curve) other than the identity, and
///                         distinct; off local chains neither may be a published development key
///                         (seeds 0x1 and 0x2). The vault's keys are immutable, so the script checks
///                         them before it deploys anything.
///           CHALLENGE_PERIOD_SECONDS – escape delay; defaults to 24 hours.
///           NOTE_TTL_SECONDS – note lifetime; defaults to 30 days.
///           MAX_PAUSE_DURATION_SECONDS – longest a pause blocks exits; at least twice the
///                         challenge period. Required except on local chains (default 7 days).
///           REQUEST_CHARGE_CAP – positive per-request gwei limit; defaults to 1,000,000.
///           SETUP_MANIFEST – the setup's manifest.json; the adapter's CIRCUIT_ID_HASH and VK hashes
///                         must match it. Required except on local chains (default
///                         protocol/setup/v2-concession-dev). SetupPolicy decides which setups
///                         may deploy: off local chains the single-party dev and rehearsal
///                         setups need ALLOW_DEV_SETUP=1, and an mpc-1 setup must have the
///                         verifying keys of the committed
///                         protocol/setup/v2-concession/manifest.json.
///           ALLOW_DEV_SETUP – 1 deploys a dev or rehearsal setup off local chains, mainnet
///                         included (the Sepolia drill vault, or a vault that trusts its
///                         setup's generator not to forge proofs); recorded in the manifest
///                         as allowDevSetup. Default 0.
///           POSEIDON_ADDRESS – an already deployed Bn254PoseidonRuntime to reuse; its runtime
///                         codehash must equal runtime_codehash of poseidon-runtime.json in the
///                         directory of SETUP_MANIFEST (as must the compiled runtime's). Unset
///                         deploys a fresh one.
///           CHAIN_ID – optional expected chain ID; mismatches abort deployment.
///         Gasless withdrawals (ERC-4337):
///           GASLESS     – 1 (default) deploys ZkApiWithdrawalPaymaster after the vault; 0 skips
///                         the block and writes withdrawalPaymaster: null. The paymaster's gas
///                         policy holds only where a fresh storage slot costs at most
///                         FRESH_SLOT_GAS_BOUND (25,000): before anything is broadcast, GASLESS=1
///                         measures one on the RPC and refuses a chain that prices state creation
///                         as EIP-8037 does (Sepolia since 2026: about 110,000).
///           ENTRY_POINT – the EntryPoint v0.7.0; defaults to the canonical
///                         0x0000000071727De22E5E9d8BAf0edAc6f37da032 and must carry its runtime.
///           PAYMASTER_OWNER – owner of the paymaster (policy, fee ceilings, call caps, key
///                         release, stake and deposit withdrawals); defaults to OWNER. The first
///                         stake may only be set by the owner, so when it is not the deployer the
///                         paymaster is deployed with the deployer as owner, staked and funded, and
///                         PAYMASTER_OWNER is nominated (transferOwnership): it must call
///                         acceptOwnership() on the paymaster, as the manifest's
///                         paymasterOwnershipTransferPending records.
///           PAYMASTER_STAKE_WEI, FACTORY_STAKE_WEI – the EntryPoint stakes of the paymaster and
///                         the factory (positive, at most 2^112 - 1). Local chains default to
///                         0.1 ether each; public chains require them (plan 1 ether on mainnet,
///                         0.1 ether on Sepolia).
///           PAYMASTER_UNSTAKE_DELAY_SECONDS – the stakes' unstake delay; default 86,400.
///           PAYMASTER_DEPOSIT_WEI – the paymaster's initial EntryPoint deposit, the float that
///                         pays sponsored gas (positive). Local default 1 ether; required off
///                         local chains.
///           PAYMASTER_MAX_SPONSORED_COST_WEI – the most one operation may cost the float
///                         (maxCost); default 0.05 ether, at most 0.25 ether.
///           PAYMASTER_FLAT_FEE_WEI – flat fee kept per sponsored operation; default 0, at most
///                         0.001 ether.
///           PAYMASTER_MIN_ESCAPE_NET_WEI – least net payout of a sponsored escape; default
///                         0.01 ether, at most 2^64 - 1.
///           PAYMASTER_ESCAPES – 1 sponsors escape initiations; default 0 (finalizations are
///                         always sponsored).
///           PAYMASTER_MAX_FEE_CEILING_WEI, PAYMASTER_PRIORITY_FEE_CEILING_WEI – the fee
///                         ceilings per gas (defaults 100 gwei and 3 gwei; at most 500 gwei and
///                         20 gwei, and the priority ceiling must not exceed the max ceiling).
///           PAYMASTER_FEE_KEEPER – optional key that may re-set the fee ceilings.
///         Batched exits (ZkApiExitBatcher, always deployed after the vault and the gasless block):
///           EXIT_BATCHER_CLOSE_GAS, EXIT_BATCHER_ESCAPE_GAS, EXIT_BATCHER_DEFEAT_GAS,
///           EXIT_BATCHER_RAISE_GAS, EXIT_BATCHER_FINALIZE_GAS – the gas of each kind's vault
///                         call in a batch (50,000 to 2,000,000). Defaults follow the chain's gas
///                         schedule, measured with FRESH_SLOT_PROBE (through the RPC when there is
///                         one, else on forge's own EVM): under EIP-2929 storage pricing (a fresh
///                         slot at most FRESH_SLOT_GAS_BOUND, mainnet today) 250,000, 250,000,
///                         150,000, 150,000 and 300,000; under EIP-8037 state-creation pricing
///                         (Sepolia today) 500,000, 600,000, 150,000, 150,000 and 400,000
///                         (docs/deployment.md#batched-exits). The manifest records the caps and
///                         the schedule (exitBatcherItemGas, exitBatcherGasSchedule).
///         Every JSON number in the manifest is a safe integer (at most 2^53 - 1, so JavaScript
///         reads it exactly); the four signing-key coordinates and every wei amount of the
///         paymaster block are decimal strings.
contract DeployScript is Script, SigningKeyChecks, SetupPolicy {
    uint64 internal constant DEFAULT_NOTE_TTL = 30 days;
    uint64 internal constant LOCAL_MAX_PAUSE_DURATION = 7 days;
    uint256 internal constant VAULT_REVISION = 3;
    string internal constant DEFAULT_SETUP_MANIFEST = "../../protocol/setup/v2-concession-dev/manifest.json";
    /// The vault's Poseidon, legacy-compiled, by its artifact path (a name lookup does not find
    /// artifacts of the additional compiler profile).
    string internal constant POSEIDON_ARTIFACT = "out/Bn254PoseidonRuntime.sol/Bn254PoseidonRuntime.json";
    /// The setup file that pins the runtime (zkapi-proof poseidon_runtime.rs), next to SETUP_MANIFEST.
    string internal constant POSEIDON_RUNTIME_MANIFEST = "poseidon-runtime.json";
    /// Largest integer a JSON number carries exactly in JavaScript (Number.MAX_SAFE_INTEGER).
    uint256 internal constant MAX_SAFE_INTEGER = 9_007_199_254_740_991;

    /// The canonical ERC-4337 EntryPoint v0.7.0 and the SenderCreator it created (its nonce 1,
    /// an immutable of its runtime), pinned by the keccak256 of their runtime code on every chain.
    address internal constant CANONICAL_ENTRY_POINT = 0x0000000071727De22E5E9d8BAf0edAc6f37da032;
    bytes32 internal constant ENTRY_POINT_V070_CODEHASH =
        0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58;
    address internal constant SENDER_CREATOR = 0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C;
    bytes32 internal constant SENDER_CREATOR_V070_CODEHASH =
        0x283c9d14378f5f4c4e24045b87d621d48443fa5b4af7dd7180a599b3756a7689;
    /// The paymaster's policy and ceiling bounds (its private constants; the constructor reverts
    /// PolicyOutOfBounds / CeilingOutOfRange above them, these checks say which variable).
    uint256 internal constant MAX_SPONSORED_COST_HARD_CAP = 0.25 ether;
    uint256 internal constant FLAT_FEE_HARD_CAP = 0.001 ether;
    uint256 internal constant MAX_FEE_HARD_CAP = 500 gwei;
    uint256 internal constant PRIORITY_FEE_HARD_CAP = 20 gwei;
    /// The paymaster's FRESH_SLOT_GAS_BOUND (_checkGasless compares the deployed getter), and a
    /// creation whose constructor returns what GAS reads around one fresh SSTORE (slot 0, cleared
    /// again): gas, push1 1, push0, sstore, gas, swap1, sub, push0, push0, sstore, then
    /// mstore(0, used) and return(0, 32). It measures 22,107 under EIP-2929 storage pricing.
    uint256 internal constant FRESH_SLOT_GAS_BOUND = 25_000;
    bytes internal constant FRESH_SLOT_PROBE = hex"5a60015f555a90035f5f555f5260205ff3";
    /// The exit batcher's default item gas caps per gas schedule (kind order close, escape, defeat,
    /// raise, finalize): test/batch/BatcherGas.t.sol measures each kind's vault call (about 61k,
    /// 114k, 42k, 18k and 36k cold under EIP-2929 pricing) and the caps add what the call may hand on
    /// (a treasury push of up to 100,000, a destination's payout, a finalization's two pushes) and
    /// the fresh slots and account EIP-8037 reprices (an escape writes four, a close one plus a
    /// never-used destination's account).
    uint256[5] internal BATCHER_GAS_MAINNET = [uint256(250_000), 250_000, 150_000, 150_000, 300_000];
    uint256[5] internal BATCHER_GAS_EIP8037 = [uint256(500_000), 600_000, 150_000, 150_000, 400_000];

    /// Placeholder the manifest serializer writes for withdrawalPaymaster with GASLESS=0; it is
    /// replaced by a JSON null before the file is written (vm.serialize* has no null).
    string internal constant NULL_PLACEHOLDER = "__null__";

    struct Params {
        address deployer;
        address owner;
        address treasury;
        uint64 noteTtl;
        uint64 challengePeriod;
        uint64 maxPauseDuration;
        uint128 requestChargeCap;
        uint256 stateKeyX;
        uint256 stateKeyY;
        uint256 clearanceKeyX;
        uint256 clearanceKeyY;
    }

    struct Setup {
        string circuitId;
        string setupId;
        bytes32 requestVkHash;
        bytes32 withdrawalVkHash;
        bool allowDevSetup;
        /// The manifest itself, whose verifying keys' IC points the adapter's fold is checked against.
        string manifest;
        /// runtime_codehash of the setup's poseidon-runtime.json: the only Poseidon code deployed.
        bytes32 poseidonCodehash;
    }

    /// The gasless block's inputs (GASLESS and the PAYMASTER_* variables).
    struct Gasless {
        bool enabled;
        IEntryPoint entryPoint;
        address owner;
        address feeKeeper;
        uint256 stakeWei;
        uint256 factoryStakeWei;
        uint32 unstakeDelay;
        uint256 depositWei;
        ZkApiWithdrawalPaymaster.Policy policy;
        uint256 maxFeeCeiling;
        uint256 priorityFeeCeiling;
    }

    struct Deployed {
        address poseidon;
        bool poseidonReused;
        Groth16ProofAdapter adapter;
        ZkApiVault vault;
        ZkApiWithdrawalPaymaster paymaster;
        ZkApiWithdrawalAccountFactory factory;
        /// The transit-account logic the factory deployed (its nonce 1).
        address implementation;
        /// The deployer still owns the paymaster and PAYMASTER_OWNER must accept the transfer.
        bool paymasterOwnershipPending;
        ZkApiExitBatcher batcher;
    }

    /// The exit batcher's inputs: its item gas caps and the schedule that chose their defaults.
    struct Batcher {
        uint256[5] itemGas;
        uint256 freshSlotGas;
        string schedule;
    }

    function run() external {
        require(block.chainid == vm.envOr("CHAIN_ID", block.chainid), "CHAIN_ID does not match RPC");
        require(
            block.chainid <= MAX_SAFE_INTEGER && block.number <= MAX_SAFE_INTEGER, "chain ID or block above 2^53 - 1"
        );
        bool local = block.chainid == 31337 || block.chainid == 1337;
        uint256 deployerKey = vm.envUint("PRIVATE_KEY");
        string memory outputPath = vm.envString("OUTPUT_PATH");
        Params memory p = _params(vm.addr(deployerKey), local);
        Setup memory setup = _setup(local);
        Gasless memory g = _gasless(p, local);
        if (g.enabled) _requireSponsorableGasSchedule();
        Batcher memory b = _batcher();

        address poseidonIn = vm.envOr("POSEIDON_ADDRESS", address(0));
        require(
            keccak256(vm.getDeployedCode(POSEIDON_ARTIFACT)) == setup.poseidonCodehash,
            "the compiled Bn254PoseidonRuntime is not the runtime poseidon-runtime.json pins"
        );
        if (poseidonIn != address(0)) {
            require(
                poseidonIn.codehash == setup.poseidonCodehash,
                "POSEIDON_ADDRESS runtime code is not the pinned Bn254PoseidonRuntime"
            );
        }

        vm.startBroadcast(deployerKey);
        Deployed memory d;
        d.poseidonReused = poseidonIn != address(0);
        d.poseidon = d.poseidonReused ? poseidonIn : _create(vm.getCode(POSEIDON_ARTIFACT));
        // The adapter folds the vault's address into its verifying keys: the vault is the deployer's
        // next creation after the adapter. Checked against the deployed vault below (_checkAdapter).
        address predictedVault = vm.computeCreateAddress(p.deployer, vm.getNonce(p.deployer) + 1);
        d.adapter = new Groth16ProofAdapter(predictedVault, p.stateKeyX, p.stateKeyY, p.clearanceKeyX, p.clearanceKeyY);
        d.vault = new ZkApiVault(
            p.treasury,
            p.noteTtl,
            p.challengePeriod,
            p.requestChargeCap,
            address(d.adapter),
            p.stateKeyX,
            p.stateKeyY,
            p.clearanceKeyX,
            p.clearanceKeyY,
            p.owner,
            p.maxPauseDuration,
            d.poseidon
        );
        if (g.enabled) _deployGasless(d, p, g);
        d.batcher = new ZkApiExitBatcher(d.vault, b.itemGas);
        vm.stopBroadcast();

        // Before anything is written: the vault's Poseidon is the pinned runtime.
        require(d.poseidon.codehash == setup.poseidonCodehash, "Bn254PoseidonRuntime codehash");
        _checkAdapter(d, setup);
        _checkVault(d, p);
        if (g.enabled) _checkGasless(d, p, g);
        _checkBatcher(d, b);
        bool broadcast =
            vm.isContext(VmSafe.ForgeContext.ScriptBroadcast) || vm.isContext(VmSafe.ForgeContext.ScriptResume);
        string memory pendingPath = string.concat(outputPath, ".pending");
        _writeManifest(pendingPath, d, p, setup, g, b, broadcast ? "pending" : "simulated");

        console2.log("vault        ", address(d.vault));
        console2.log("treasury     ", p.treasury);
        console2.log("owner        ", p.owner);
        if (block.chainid == 1 && p.owner.code.length == 0) {
            console2.log("WARNING: OWNER has no code; use a multisig or timelock contract on mainnet");
        }
        console2.log("proofAdapter ", address(d.adapter));
        console2.log("poseidon     ", d.poseidon, d.poseidonReused ? "(reused)" : "(deployed)");
        console2.log("setup        ", setup.circuitId, setup.setupId);
        if (setup.allowDevSetup && !local && !_eq(setup.setupId, CEREMONY_SETUP_ID)) {
            console2.log(
                "WARNING: single-party setup deployed under ALLOW_DEV_SETUP=1: whoever generated its keys can forge every proof"
            );
        }
        console2.log("vault codehash");
        console2.logBytes32(address(d.vault).codehash);
        console2.log("adapter codehash");
        console2.logBytes32(address(d.adapter).codehash);
        console2.log("poseidon codehash");
        console2.logBytes32(d.poseidon.codehash);
        if (g.enabled) _logGasless(d, g);
        else console2.log("gasless      none (GASLESS=0): withdrawalPaymaster is null");
        console2.log("exitBatcher  ", address(d.batcher), b.schedule);
        console2.log("exitBatcher codehash");
        console2.logBytes32(address(d.batcher).codehash);
        console2.log("provisional manifest", pendingPath);
        if (broadcast) {
            console2.log("Not final until checked on chain. After the broadcast, run from the repository root:");
            console2.log(
                string.concat(
                    "  node scripts/expected-codehashes.mjs --deployment ",
                    pendingPath,
                    " --rpc <RPC_URL> --finalize ",
                    outputPath
                )
            );
        }
    }

    function _params(address deployer, bool local) internal view returns (Params memory p) {
        p.deployer = deployer;
        // The owner can pause exits (for at most maxPauseDuration) and schedule treasury changes,
        // so public deployments must name it explicitly instead of defaulting to the deployer.
        p.owner = local ? vm.envOr("OWNER", deployer) : vm.envAddress("OWNER");
        require(p.owner != address(0), "OWNER must be nonzero");
        // Treasury receives the operator's consumed amount on settlement. Keep
        // it separate from the depositor so consumption is visible in the demo.
        p.treasury = local
            ? vm.envOr("TREASURY", address(0x70997970C51812dc3A010C7d01b50e0d17dc79C8))
            : vm.envAddress("TREASURY");
        require(p.treasury != address(0), "TREASURY must be nonzero");
        p.stateKeyX = vm.envUint("STATE_SIGNING_KEY_X");
        p.stateKeyY = vm.envUint("STATE_SIGNING_KEY_Y");
        p.clearanceKeyX = vm.envUint("CLEARANCE_SIGNING_KEY_X");
        p.clearanceKeyY = vm.envUint("CLEARANCE_SIGNING_KEY_Y");
        _checkSigningKeys(p.stateKeyX, p.stateKeyY, p.clearanceKeyX, p.clearanceKeyY, local);
        p.challengePeriod =
            _positiveSafeInteger(vm.envOr("CHALLENGE_PERIOD_SECONDS", uint256(24 hours)), "CHALLENGE_PERIOD_SECONDS");
        p.noteTtl = _positiveSafeInteger(vm.envOr("NOTE_TTL_SECONDS", uint256(DEFAULT_NOTE_TTL)), "NOTE_TTL_SECONDS");
        uint256 maxPause = local
            ? vm.envOr("MAX_PAUSE_DURATION_SECONDS", uint256(LOCAL_MAX_PAUSE_DURATION))
            : vm.envUint("MAX_PAUSE_DURATION_SECONDS");
        p.maxPauseDuration = _positiveSafeInteger(maxPause, "MAX_PAUSE_DURATION_SECONDS");
        require(
            uint256(p.maxPauseDuration) >= 2 * uint256(p.challengePeriod),
            "MAX_PAUSE_DURATION_SECONDS must be at least twice CHALLENGE_PERIOD_SECONDS"
        );
        uint256 cap = vm.envOr("REQUEST_CHARGE_CAP", uint256(1_000_000));
        require(cap > 0 && cap <= MAX_SAFE_INTEGER, "REQUEST_CHARGE_CAP must be positive safe gwei units");
        // casting to 'uint128' is safe because cap is at most MAX_SAFE_INTEGER
        // forge-lint: disable-next-line(unsafe-typecast)
        p.requestChargeCap = uint128(cap);
    }

    function _setup(bool local) internal view returns (Setup memory setup) {
        string memory path = local ? vm.envOr("SETUP_MANIFEST", DEFAULT_SETUP_MANIFEST) : vm.envString("SETUP_MANIFEST");
        string memory manifest = vm.readFile(path);
        setup.manifest = manifest;
        setup.circuitId = vm.parseJsonString(manifest, ".circuit_id");
        setup.setupId = vm.parseJsonString(manifest, ".setup_id");
        setup.requestVkHash = vm.parseJsonBytes32(manifest, ".vk_keccak256.request");
        setup.withdrawalVkHash = vm.parseJsonBytes32(manifest, ".vk_keccak256.withdrawal");
        uint256 allowDev = vm.envOr("ALLOW_DEV_SETUP", uint256(0));
        require(allowDev <= 1, "ALLOW_DEV_SETUP must be 0 or 1");
        setup.allowDevSetup = allowDev == 1;

        SetupFacts memory facts;
        facts.circuitId = setup.circuitId;
        facts.setupId = setup.setupId;
        facts.requestVkHash = setup.requestVkHash;
        facts.withdrawalVkHash = setup.withdrawalVkHash;
        facts.ceremonyPinned = vm.exists(CEREMONY_MANIFEST);
        if (facts.ceremonyPinned) {
            string memory ceremony = vm.readFile(CEREMONY_MANIFEST);
            require(
                _eq(vm.parseJsonString(ceremony, ".circuit_id"), CIRCUIT_ID)
                    && _eq(vm.parseJsonString(ceremony, ".setup_id"), CEREMONY_SETUP_ID),
                "protocol/setup/v2-concession/manifest.json is not the zkapi-v2-concession-v1 mpc-1 setup"
            );
            facts.ceremonyRequestVkHash = vm.parseJsonBytes32(ceremony, ".vk_keccak256.request");
            facts.ceremonyWithdrawalVkHash = vm.parseJsonBytes32(ceremony, ".vk_keccak256.withdrawal");
        }
        _checkSetupPolicy(facts, local, setup.allowDevSetup);

        // The Poseidon runtime the setup pins (generated with its sources), read once the setup
        // may deploy at all.
        string memory runtimeManifest = string.concat(_directory(path), POSEIDON_RUNTIME_MANIFEST);
        require(vm.exists(runtimeManifest), string.concat("no ", runtimeManifest, " next to SETUP_MANIFEST"));
        string memory runtime = vm.readFile(runtimeManifest);
        require(
            _eq(vm.parseJsonString(runtime, ".contract"), "Bn254PoseidonRuntime"),
            "poseidon-runtime.json does not describe Bn254PoseidonRuntime"
        );
        setup.poseidonCodehash = vm.parseJsonBytes32(runtime, ".runtime_codehash");
    }

    /// The gasless block's inputs. The variables are read and bounded before the EntryPoint is
    /// looked at, so a public-chain run that lacks a required amount says so whether or not the
    /// chain is reachable; the EntryPoint and SenderCreator runtimes are then required to be the
    /// canonical v0.7.0 ones, before anything is deployed.
    function _gasless(Params memory p, bool local) internal view returns (Gasless memory g) {
        uint256 flag = vm.envOr("GASLESS", uint256(1));
        require(flag <= 1, "GASLESS must be 0 or 1");
        g.enabled = flag == 1;
        if (!g.enabled) return g;
        g.entryPoint = IEntryPoint(vm.envOr("ENTRY_POINT", CANONICAL_ENTRY_POINT));
        g.owner = vm.envOr("PAYMASTER_OWNER", p.owner);
        require(g.owner != address(0), "PAYMASTER_OWNER must be nonzero");
        g.feeKeeper = vm.envOr("PAYMASTER_FEE_KEEPER", address(0));
        g.stakeWei = local ? vm.envOr("PAYMASTER_STAKE_WEI", uint256(0.1 ether)) : vm.envUint("PAYMASTER_STAKE_WEI");
        g.factoryStakeWei = local ? vm.envOr("FACTORY_STAKE_WEI", uint256(0.1 ether)) : vm.envUint("FACTORY_STAKE_WEI");
        g.depositWei = local ? vm.envOr("PAYMASTER_DEPOSIT_WEI", uint256(1 ether)) : vm.envUint("PAYMASTER_DEPOSIT_WEI");
        require(
            g.stakeWei > 0 && g.stakeWei <= type(uint112).max,
            "PAYMASTER_STAKE_WEI must be positive (at most 2^112 - 1)"
        );
        require(
            g.factoryStakeWei > 0 && g.factoryStakeWei <= type(uint112).max,
            "FACTORY_STAKE_WEI must be positive (at most 2^112 - 1)"
        );
        require(g.depositWei > 0, "PAYMASTER_DEPOSIT_WEI must be positive");
        uint256 delay = vm.envOr("PAYMASTER_UNSTAKE_DELAY_SECONDS", uint256(1 days));
        require(
            delay > 0 && delay <= type(uint32).max,
            "PAYMASTER_UNSTAKE_DELAY_SECONDS must be positive (at most 2^32 - 1)"
        );
        // casting to 'uint32' is safe because delay is at most type(uint32).max
        // forge-lint: disable-next-line(unsafe-typecast)
        g.unstakeDelay = uint32(delay);

        uint256 maxCost = vm.envOr("PAYMASTER_MAX_SPONSORED_COST_WEI", uint256(0.05 ether));
        require(
            maxCost > 0 && maxCost <= MAX_SPONSORED_COST_HARD_CAP,
            "PAYMASTER_MAX_SPONSORED_COST_WEI must be positive and at most 0.25 ether"
        );
        uint256 flatFee = vm.envOr("PAYMASTER_FLAT_FEE_WEI", uint256(0));
        require(flatFee <= FLAT_FEE_HARD_CAP, "PAYMASTER_FLAT_FEE_WEI must be at most 0.001 ether");
        uint256 minEscapeNet = vm.envOr("PAYMASTER_MIN_ESCAPE_NET_WEI", uint256(0.01 ether));
        require(minEscapeNet <= type(uint64).max, "PAYMASTER_MIN_ESCAPE_NET_WEI must be at most 2^64 - 1");
        uint256 escapes = vm.envOr("PAYMASTER_ESCAPES", uint256(0));
        require(escapes <= 1, "PAYMASTER_ESCAPES must be 0 or 1");
        // The casts are safe: each value was bounded above.
        // forge-lint: disable-start(unsafe-typecast)
        g.policy = ZkApiWithdrawalPaymaster.Policy({
            maxSponsoredCost: uint128(maxCost),
            flatFeeWei: uint64(flatFee),
            minEscapeNetWei: uint64(minEscapeNet),
            escapesEnabled: escapes == 1,
            sponsorshipPaused: false
        });
        // forge-lint: disable-end(unsafe-typecast)
        g.maxFeeCeiling = vm.envOr("PAYMASTER_MAX_FEE_CEILING_WEI", uint256(100 gwei));
        g.priorityFeeCeiling = vm.envOr("PAYMASTER_PRIORITY_FEE_CEILING_WEI", uint256(3 gwei));
        require(
            g.maxFeeCeiling > 0 && g.maxFeeCeiling <= MAX_FEE_HARD_CAP,
            "PAYMASTER_MAX_FEE_CEILING_WEI must be positive and at most 500 gwei"
        );
        require(
            g.priorityFeeCeiling > 0 && g.priorityFeeCeiling <= PRIORITY_FEE_HARD_CAP,
            "PAYMASTER_PRIORITY_FEE_CEILING_WEI must be positive and at most 20 gwei"
        );
        require(
            g.priorityFeeCeiling <= g.maxFeeCeiling,
            "PAYMASTER_PRIORITY_FEE_CEILING_WEI must not exceed PAYMASTER_MAX_FEE_CEILING_WEI"
        );

        require(
            address(g.entryPoint).codehash == ENTRY_POINT_V070_CODEHASH,
            "ENTRY_POINT is not EntryPoint v0.7.0 (no canonical runtime at that address; etch it on Anvil, or pass GASLESS=0)"
        );
        require(
            SENDER_CREATOR.codehash == SENDER_CREATOR_V070_CODEHASH,
            "SenderCreator v0.7.0 runtime missing at 0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C (etch it on Anvil, or pass GASLESS=0)"
        );
    }

    /// The paymaster's constructor refuses a chain that prices a fresh storage slot above
    /// FRESH_SLOT_GAS_BOUND, where none of its gas constants holds (EIP-8037). forge simulates the
    /// broadcast on its own EVM, whose schedule passes, so on such a chain the library, the adapter
    /// and the vault would be sent before the paymaster's creation reverted. The same measurement
    /// runs on the RPC first, as an eth_call of FRESH_SLOT_PROBE's creation, and stops GASLESS=1
    /// there. The gasless block needs the EntryPoint's runtime (_gasless), so an RPC is there.
    function _requireSponsorableGasSchedule() internal {
        bytes memory answer;
        try vm.rpc("eth_call", string.concat('[{"data":"', vm.toString(FRESH_SLOT_PROBE), '"},"latest"]')) returns (
            bytes memory result
        ) {
            answer = result;
        } catch {
            revert("GASLESS=1 measures a fresh storage slot through the RPC (eth_call), which failed");
        }
        require(answer.length == 32, "fresh-slot probe: unexpected eth_call result");
        uint256 freshSlotGas = abi.decode(answer, (uint256));
        require(
            freshSlotGas <= FRESH_SLOT_GAS_BOUND,
            string.concat(
                "the chain prices a fresh storage slot at ",
                vm.toString(freshSlotGas),
                " gas, above the paymaster's FRESH_SLOT_GAS_BOUND (25000): its gas policy does not hold here (EIP-8037); pass GASLESS=0"
            )
        );
        console2.log("gas schedule fresh slot", freshSlotGas);
    }

    /// The exit batcher's item gas caps: EXIT_BATCHER_*_GAS, else the defaults of the chain's gas
    /// schedule, which a fresh storage slot's measured price decides (EIP-8037 above
    /// FRESH_SLOT_GAS_BOUND).
    function _batcher() internal returns (Batcher memory b) {
        b.freshSlotGas = _freshSlotGas();
        bool repriced = b.freshSlotGas > FRESH_SLOT_GAS_BOUND;
        b.schedule = repriced ? "eip8037" : "eip2929";
        string[5] memory names = [
            "EXIT_BATCHER_CLOSE_GAS",
            "EXIT_BATCHER_ESCAPE_GAS",
            "EXIT_BATCHER_DEFEAT_GAS",
            "EXIT_BATCHER_RAISE_GAS",
            "EXIT_BATCHER_FINALIZE_GAS"
        ];
        for (uint256 k = 0; k < 5; ++k) {
            uint256 fallbackGas = repriced ? BATCHER_GAS_EIP8037[k] : BATCHER_GAS_MAINNET[k];
            b.itemGas[k] = vm.envOr(names[k], fallbackGas);
            require(
                b.itemGas[k] >= 50_000 && b.itemGas[k] <= 2_000_000,
                string.concat(names[k], " must be between 50000 and 2000000")
            );
        }
    }

    /// What one write of a nonzero word to a cold, zero slot costs on the target chain:
    /// FRESH_SLOT_PROBE's creation through the RPC (eth_call), or, without one (a dry run), on
    /// forge's own EVM, where the probe's runtime code is the 32-byte measurement.
    function _freshSlotGas() internal returns (uint256 freshSlotGas) {
        try vm.rpc("eth_call", string.concat('[{"data":"', vm.toString(FRESH_SLOT_PROBE), '"},"latest"]')) returns (
            bytes memory result
        ) {
            require(result.length == 32, "fresh-slot probe: unexpected eth_call result");
            return abi.decode(result, (uint256));
        } catch {
            address probe = _create(FRESH_SLOT_PROBE);
            bytes memory measured = probe.code;
            require(measured.length == 32, "fresh-slot probe: unexpected local result");
            return abi.decode(measured, (uint256));
        }
    }

    /// Post-deploy checks of the exit batcher: bound to this vault and its adapter, which reports
    /// the batch interface (the constructor checked it), with the chosen caps.
    function _checkBatcher(Deployed memory d, Batcher memory b) internal view {
        ZkApiExitBatcher batcher = d.batcher;
        require(address(batcher.vault()) == address(d.vault), "exitBatcher vault");
        require(address(batcher.adapter()) == address(d.adapter), "exitBatcher adapter");
        for (uint8 kind = 0; kind < 5; ++kind) {
            require(batcher.itemGas(kind) == b.itemGas[kind], "exitBatcher item gas");
        }
    }

    /// Deploys the paymaster (which deploys the factory, which deploys the account logic), stakes
    /// both with the EntryPoint and funds the float, inside the broadcast. The first stake may only
    /// be set by the paymaster's owner, so when PAYMASTER_OWNER is not the deployer the paymaster
    /// starts with the deployer as owner and the transfer is nominated last (Ownable2Step: the
    /// nominee accepts it; until then the deployer keeps the owner's powers).
    function _deployGasless(Deployed memory d, Params memory p, Gasless memory g) internal {
        bool handover = g.owner != p.deployer;
        d.paymaster = new ZkApiWithdrawalPaymaster(
            g.entryPoint, d.vault, handover ? p.deployer : g.owner, g.policy, g.maxFeeCeiling, g.priorityFeeCeiling
        );
        d.factory = d.paymaster.factory();
        d.implementation = address(d.factory.implementation());
        d.paymaster.addStake{value: g.stakeWei}(g.unstakeDelay);
        d.factory.addStake{value: g.factoryStakeWei}(g.unstakeDelay);
        d.paymaster.deposit{value: g.depositWei}();
        if (g.feeKeeper != address(0)) d.paymaster.setFeeKeeper(g.feeKeeper);
        if (handover) d.paymaster.transferOwnership(g.owner);
        d.paymasterOwnershipPending = handover;
    }

    /// The adapter compiled into this script verifies the setup in SETUP_MANIFEST, and is folded for
    /// the vault deployed after it: its folded vault, chain and keys are the vault's, and its folded
    /// points are IC0 + Σ c · IC with the manifest's IC points, summed here through the precompiles.
    /// A wrong fold would only cost gas (its proofs take the adapter's generic path), but the
    /// manifest records the deployment as it is meant to be, so any mismatch stops the script
    /// before the manifest is written.
    function _checkAdapter(Deployed memory d, Setup memory setup) internal view {
        Groth16ProofAdapter adapter = d.adapter;
        ZkApiVault vault = d.vault;
        require(adapter.CIRCUIT_ID_HASH() == keccak256(bytes(setup.circuitId)), "adapter CIRCUIT_ID_HASH != manifest");
        require(adapter.REQUEST_VK_HASH() == setup.requestVkHash, "adapter REQUEST_VK_HASH != manifest");
        require(adapter.WITHDRAWAL_VK_HASH() == setup.withdrawalVkHash, "adapter WITHDRAWAL_VK_HASH != manifest");
        require(adapter.foldedVault() == address(vault), "adapter folded for another vault address");
        require(adapter.foldedChainId() == block.chainid, "adapter folded for another chain");
        require(
            adapter.foldedStateSigningKeyX() == vault.stateSigningKeyX()
                && adapter.foldedStateSigningKeyY() == vault.stateSigningKeyY()
                && adapter.foldedClearanceSigningKeyX() == vault.clearanceSigningKeyX()
                && adapter.foldedClearanceSigningKeyY() == vault.clearanceSigningKeyY(),
            "adapter folded for other signing keys than the vault's"
        );
        uint256[] memory constants = new uint256[](7);
        constants[0] = vault.PROTOCOL_VERSION();
        constants[1] = block.chainid;
        constants[2] = uint160(address(vault));
        constants[3] = vault.stateSigningKeyX();
        constants[4] = vault.stateSigningKeyY();
        constants[5] = vault.clearanceSigningKeyX();
        constants[6] = vault.clearanceSigningKeyY();
        // Groth16 IC indices of the folded inputs (input i is IC i + 1): protocolVersion, chainId,
        // contractAddress, stateSigningKeyX/Y and, for withdrawals, clearanceSigningKeyX/Y.
        uint256[7] memory points = [uint256(1), 2, 3, 5, 6, 7, 8];
        (uint256 x, uint256 y) = _foldedPoint(setup.manifest, ".request.ic", constants, points, 5);
        require(
            adapter.foldedRequestIc0X() == x && adapter.foldedRequestIc0Y() == y,
            "adapter request fold != manifest verifying key"
        );
        (x, y) = _foldedPoint(setup.manifest, ".withdrawal.ic", constants, points, 7);
        require(
            adapter.foldedWithdrawalIc0X() == x && adapter.foldedWithdrawalIc0Y() == y,
            "adapter withdrawal fold != manifest verifying key"
        );
    }

    /// IC[0] + Σ constants[k] · IC[points[k]] over the first `count` folded inputs of the IC list at
    /// `key` in the setup manifest, through ecMul and ecAdd.
    function _foldedPoint(
        string memory manifest,
        string memory key,
        uint256[] memory constants,
        uint256[7] memory points,
        uint256 count
    ) internal view returns (uint256 x, uint256 y) {
        (x, y) = _manifestPoint(manifest, key, 0);
        for (uint256 k = 0; k < count; ++k) {
            (uint256 px, uint256 py) = _manifestPoint(manifest, key, points[k]);
            (bool ok, bytes memory out) = address(7).staticcall(abi.encode(px, py, constants[k]));
            require(ok && out.length == 64, "ecMul of a manifest IC point");
            (px, py) = abi.decode(out, (uint256, uint256));
            (ok, out) = address(6).staticcall(abi.encode(x, y, px, py));
            require(ok && out.length == 64, "ecAdd of a manifest IC point");
            (x, y) = abi.decode(out, (uint256, uint256));
        }
    }

    function _manifestPoint(string memory manifest, string memory key, uint256 index)
        internal
        pure
        returns (uint256, uint256)
    {
        string memory at = string.concat(key, "[", vm.toString(index), "]");
        return
            (vm.parseJsonUint(manifest, string.concat(at, "[0]")), vm.parseJsonUint(manifest, string.concat(at, "[1]")));
    }

    /// Post-deploy checks: the vault's getters equal the inputs and the expected constants.
    function _checkVault(Deployed memory d, Params memory p) internal view {
        ZkApiVault vault = d.vault;
        require(vault.PROTOCOL_VERSION() == 2, "PROTOCOL_VERSION");
        require(vault.CONCESSION_ESCAPE_VERSION() == 1, "CONCESSION_ESCAPE_VERSION");
        require(vault.ROOT_HISTORY_WINDOW() == 1 days, "ROOT_HISTORY_WINDOW");
        require(address(vault.proofAdapter()) == address(d.adapter), "proofAdapter");
        require(address(vault.poseidon()) == d.poseidon, "poseidon");
        require(vault.owner() == p.owner && vault.treasury() == p.treasury, "owner or treasury");
        require(
            vault.noteTtl() == p.noteTtl && vault.challengePeriod() == p.challengePeriod
                && vault.maxPauseDuration() == p.maxPauseDuration && vault.requestChargeCap() == p.requestChargeCap,
            "periods or cap"
        );
        require(
            vault.stateSigningKeyX() == p.stateKeyX && vault.stateSigningKeyY() == p.stateKeyY
                && vault.clearanceSigningKeyX() == p.clearanceKeyX && vault.clearanceSigningKeyY() == p.clearanceKeyY,
            "signing keys"
        );
        require(vault.isKnownRoot(vault.currentRoot()), "empty root not recorded");
    }

    /// Post-deploy checks of the gasless block: the paymaster's and the factory's pins equal the
    /// vault's and the EntryPoint's, the policy and ceilings equal the inputs, the deposit and
    /// both stakes are in place, the ownership is as recorded, and a transit address computed
    /// locally equals the factory's CREATE2 (a self-test of the creation code clients carry).
    function _checkGasless(Deployed memory d, Params memory p, Gasless memory g) internal view {
        ZkApiWithdrawalPaymaster pm = d.paymaster;
        ZkApiWithdrawalAccountFactory factory = d.factory;
        require(pm.ENTRY_POINT_V070_CODEHASH() == ENTRY_POINT_V070_CODEHASH, "EntryPoint codehash pin");
        require(pm.FRESH_SLOT_GAS_BOUND() == FRESH_SLOT_GAS_BOUND, "paymaster FRESH_SLOT_GAS_BOUND");
        require(!pm.scheduleRepriced(), "paymaster gas schedule");
        require(address(pm.entryPoint()) == address(g.entryPoint), "paymaster entryPoint");
        require(address(pm.vault()) == address(d.vault), "paymaster vault");
        require(address(pm.adapter()) == address(d.adapter), "paymaster adapter");
        require(address(pm.factory()) == address(factory) && factory.paymaster() == address(pm), "paymaster factory");
        require(factory.entryPoint() == address(g.entryPoint) && factory.vault() == address(d.vault), "factory pins");
        require(address(factory.implementation()) == d.implementation, "factory implementation");
        require(d.implementation == vm.computeCreateAddress(address(factory), 1), "implementation address");
        require(pm.WEI_PER_UNIT() == d.vault.nativeAssetWeiPerUnit(), "WEI_PER_UNIT");
        require(pm.MAX_PAUSE_DURATION() == d.vault.maxPauseDuration(), "MAX_PAUSE_DURATION");
        require(
            pm.STATE_X() == p.stateKeyX && pm.STATE_Y() == p.stateKeyY && pm.CLEAR_X() == p.clearanceKeyX
                && pm.CLEAR_Y() == p.clearanceKeyY,
            "paymaster signing keys"
        );
        bytes memory creation = factory.accountCreationCode();
        require(
            pm.accountCreationCodeHash() == factory.accountCreationCodeHash()
                && factory.accountCreationCodeHash() == keccak256(creation),
            "accountCreationCodeHash"
        );
        (uint128 maxSponsoredCost, uint64 flatFeeWei, uint64 minEscapeNetWei, bool escapesEnabled, bool paused) =
            pm.policy();
        require(
            maxSponsoredCost == g.policy.maxSponsoredCost && flatFeeWei == g.policy.flatFeeWei
                && minEscapeNetWei == g.policy.minEscapeNetWei && escapesEnabled == g.policy.escapesEnabled && !paused,
            "paymaster policy"
        );
        require(
            pm.maxFeeCeiling() == g.maxFeeCeiling && pm.priorityFeeCeiling() == g.priorityFeeCeiling, "fee ceilings"
        );
        require(pm.feeKeeper() == g.feeKeeper, "fee keeper");
        require(pm.owner() == (d.paymasterOwnershipPending ? p.deployer : g.owner), "paymaster owner");
        require(pm.pendingOwner() == (d.paymasterOwnershipPending ? g.owner : address(0)), "paymaster pending owner");
        require(g.entryPoint.balanceOf(address(pm)) >= g.depositWei, "paymaster deposit");
        IEntryPoint.DepositInfo memory info = g.entryPoint.getDepositInfo(address(pm));
        require(info.staked && info.stake >= g.stakeWei && info.unstakeDelaySec == g.unstakeDelay, "paymaster stake");
        info = g.entryPoint.getDepositInfo(address(factory));
        require(
            info.staked && info.stake >= g.factoryStakeWei && info.unstakeDelaySec == g.unstakeDelay, "factory stake"
        );
        // CREATE2 self-test of the transit account of (deployer, deployer).
        bytes32 initCodeHash = keccak256(
            abi.encodePacked(
                creation, abi.encode(address(g.entryPoint), address(d.vault), address(pm), p.deployer, p.deployer)
            )
        );
        address expected = address(
            uint160(uint256(keccak256(abi.encodePacked(bytes1(0xff), address(factory), bytes32(0), initCodeHash))))
        );
        require(
            factory.getAddress(p.deployer, p.deployer) == expected
                && pm.transitAccount(p.deployer, p.deployer) == expected,
            "transit account CREATE2"
        );
    }

    /// Writes the provisional manifest. `status` is "pending" (broadcast: the transactions are
    /// about to be sent) or "simulated" (dry run: nothing is sent). deployBlockLowerBound is the
    /// head of the chain the simulation ran on: every creation lands in a later block, and the
    /// finalize step records the vault's actual creation block as deployBlock.
    function _writeManifest(
        string memory path,
        Deployed memory d,
        Params memory p,
        Setup memory setup,
        Gasless memory g,
        Batcher memory b,
        string memory status
    ) internal {
        ZkApiVault vault = d.vault;
        string memory m = "deployment";
        vm.serializeString(m, "deploymentStatus", status);
        vm.serializeUint(m, "chainId", block.chainid);
        vm.serializeUint(m, "deployBlockLowerBound", block.number);
        vm.serializeUint(m, "protocolVersion", vault.PROTOCOL_VERSION());
        vm.serializeUint(m, "vaultRevision", VAULT_REVISION);
        vm.serializeUint(m, "concessionEscapeVersion", vault.CONCESSION_ESCAPE_VERSION());
        vm.serializeString(m, "circuitId", setup.circuitId);
        vm.serializeString(m, "setupId", setup.setupId);
        vm.serializeBool(m, "allowDevSetup", setup.allowDevSetup);
        vm.serializeBytes32(m, "circuitIdHash", d.adapter.CIRCUIT_ID_HASH());
        vm.serializeBytes32(m, "requestVkKeccak256", d.adapter.REQUEST_VK_HASH());
        vm.serializeBytes32(m, "withdrawalVkKeccak256", d.adapter.WITHDRAWAL_VK_HASH());
        vm.serializeAddress(m, "owner", p.owner);
        vm.serializeAddress(m, "vault", address(vault));
        vm.serializeAddress(m, "billingToken", vault.billingToken());
        vm.serializeAddress(m, "proofAdapter", address(d.adapter));
        vm.serializeAddress(m, "poseidonLibrary", d.poseidon);
        vm.serializeBool(m, "poseidonLibraryReused", d.poseidonReused);
        vm.serializeBytes32(m, "vaultRuntimeCodehash", address(vault).codehash);
        vm.serializeBytes32(m, "adapterRuntimeCodehash", address(d.adapter).codehash);
        vm.serializeBytes32(m, "poseidonRuntimeCodehash", d.poseidon.codehash);
        vm.serializeAddress(m, "treasury", p.treasury);
        vm.serializeUint(m, "requestChargeCap", p.requestChargeCap);
        vm.serializeString(m, "billing_asset", "native_eth");
        vm.serializeString(m, "billing_unit", "gwei");
        vm.serializeUint(m, "nativeAssetWeiPerUnit", vault.nativeAssetWeiPerUnit());
        vm.serializeUint(m, "challengePeriod", p.challengePeriod);
        vm.serializeUint(m, "maxPauseDuration", p.maxPauseDuration);
        vm.serializeUint(m, "pauseCooldown", vault.PAUSE_COOLDOWN());
        vm.serializeUint(m, "treasuryChangeDelay", vault.treasuryChangeDelay());
        vm.serializeUint(m, "unpauseClaimGrace", vault.unpauseClaimGrace());
        vm.serializeUint(m, "rootHistoryWindow", vault.ROOT_HISTORY_WINDOW());
        // serializeUint writes values up to 2^64 - 1 as bare JSON numbers, which JavaScript rounds
        // above 2^53 - 1; key coordinates can be any field element, so they are decimal strings.
        vm.serializeString(m, "stateSigningKeyX", vm.toString(p.stateKeyX));
        vm.serializeString(m, "stateSigningKeyY", vm.toString(p.stateKeyY));
        vm.serializeString(m, "clearanceSigningKeyX", vm.toString(p.clearanceKeyX));
        vm.serializeString(m, "clearanceSigningKeyY", vm.toString(p.clearanceKeyY));
        vm.serializeAddress(m, "exitBatcher", address(d.batcher));
        vm.serializeBytes32(m, "exitBatcherRuntimeCodehash", address(d.batcher).codehash);
        vm.serializeString(m, "exitBatcherGasSchedule", b.schedule);
        vm.serializeUint(m, "exitBatcherFreshSlotGas", b.freshSlotGas);
        string memory itemGas = "exitBatcherItemGas";
        vm.serializeUint(itemGas, "close", b.itemGas[0]);
        vm.serializeUint(itemGas, "escape", b.itemGas[1]);
        vm.serializeUint(itemGas, "defeat", b.itemGas[2]);
        vm.serializeUint(itemGas, "raise", b.itemGas[3]);
        vm.serializeString(m, "exitBatcherItemGas", vm.serializeUint(itemGas, "finalize", b.itemGas[4]));
        if (g.enabled) _serializeGasless(m, d, p, g);
        else vm.serializeString(m, "withdrawalPaymaster", NULL_PLACEHOLDER);
        string memory serialized = vm.serializeUint(m, "noteTtl", uint256(p.noteTtl));
        if (!g.enabled) {
            // vm.serialize* cannot write a JSON null; the placeholder becomes one here.
            string memory quoted = string.concat("\"withdrawalPaymaster\":\"", NULL_PLACEHOLDER, "\"");
            require(vm.indexOf(serialized, quoted) != type(uint256).max, "withdrawalPaymaster placeholder");
            serialized = vm.replace(serialized, quoted, "\"withdrawalPaymaster\":null");
        }
        vm.writeJson(serialized, path);
    }

    /// The manifest's gasless block: the EntryPoint and SenderCreator pins, the three deployed
    /// contracts with their runtime codehashes, the creation code clients carry, the owner, the
    /// policy, ceilings and gas policy (every pinned constant of the paymaster), and the stake and
    /// deposit amounts. Wei amounts exceed 2^53 - 1, so they are decimal strings; gas figures are
    /// numbers.
    function _serializeGasless(string memory m, Deployed memory d, Params memory p, Gasless memory g) internal {
        ZkApiWithdrawalPaymaster pm = d.paymaster;
        vm.serializeAddress(m, "entryPoint", address(g.entryPoint));
        vm.serializeBytes32(m, "entryPointRuntimeCodehash", address(g.entryPoint).codehash);
        vm.serializeAddress(m, "senderCreator", SENDER_CREATOR);
        vm.serializeBytes32(m, "senderCreatorRuntimeCodehash", SENDER_CREATOR.codehash);
        vm.serializeAddress(m, "withdrawalPaymaster", address(pm));
        vm.serializeAddress(m, "withdrawalAccountFactory", address(d.factory));
        vm.serializeAddress(m, "withdrawalAccountImplementation", d.implementation);
        vm.serializeBytes32(m, "paymasterRuntimeCodehash", address(pm).codehash);
        vm.serializeBytes32(m, "factoryRuntimeCodehash", address(d.factory).codehash);
        vm.serializeBytes32(m, "accountImplementationRuntimeCodehash", d.implementation.codehash);
        vm.serializeBytes(m, "accountCreationCode", d.factory.accountCreationCode());
        vm.serializeBytes32(m, "accountCreationCodeKeccak256", d.factory.accountCreationCodeHash());
        vm.serializeAddress(m, "paymasterOwner", g.owner);
        vm.serializeBool(m, "paymasterOwnershipTransferPending", d.paymasterOwnershipPending);
        vm.serializeAddress(m, "paymasterDeployer", p.deployer);
        vm.serializeAddress(m, "paymasterFeeKeeper", g.feeKeeper);
        vm.serializeString(m, "paymasterStakeWei", vm.toString(g.stakeWei));
        vm.serializeString(m, "factoryStakeWei", vm.toString(g.factoryStakeWei));
        vm.serializeUint(m, "paymasterUnstakeDelaySeconds", g.unstakeDelay);
        vm.serializeString(m, "paymasterInitialDepositWei", vm.toString(g.depositWei));

        string memory pol = "paymasterPolicy";
        vm.serializeString(pol, "maxSponsoredCostWei", vm.toString(g.policy.maxSponsoredCost));
        vm.serializeString(pol, "flatFeeWei", vm.toString(g.policy.flatFeeWei));
        vm.serializeString(pol, "minEscapeNetWei", vm.toString(g.policy.minEscapeNetWei));
        vm.serializeString(m, "paymasterPolicy", vm.serializeBool(pol, "escapesEnabled", g.policy.escapesEnabled));

        string memory fees = "paymasterFeeCeilings";
        vm.serializeString(fees, "maxFeeWei", vm.toString(g.maxFeeCeiling));
        vm.serializeString(
            m, "paymasterFeeCeilings", vm.serializeString(fees, "priorityFeeWei", vm.toString(g.priorityFeeCeiling))
        );

        ZkApiWithdrawalPaymaster.GasPolicy memory gp = pm.gasPolicy();
        string memory o = "paymasterGasPolicy";
        uint256[] memory floors = new uint256[](4);
        uint256[] memory caps = new uint256[](4);
        for (uint256 k = 0; k < 4; ++k) {
            floors[k] = _safe(gp.callFloor[k], "callFloor");
            caps[k] = _safe(gp.callHardCap[k], "callCap");
        }
        vm.serializeUint(o, "callFloor", floors);
        // The hard caps: the live callCap(kind) starts there and the owner may only lower it.
        vm.serializeUint(o, "callCap", caps);
        vm.serializeUint(o, "postOpFloor", _safe(gp.postOpFloor, "postOpFloor"));
        vm.serializeUint(o, "postOpCap", _safe(gp.postOpCap, "postOpCap"));
        vm.serializeUint(o, "verificationFloor", _safe(gp.verificationFloor, "verificationFloor"));
        vm.serializeUint(o, "verificationFloorInit", _safe(gp.verificationFloorInit, "verificationFloorInit"));
        vm.serializeUint(o, "verificationCap", _safe(gp.verificationCap, "verificationCap"));
        vm.serializeUint(o, "pvgFloor", _safe(gp.pvgFloor, "pvgFloor"));
        vm.serializeUint(o, "pvgCap", _safe(gp.pvgCap, "pvgCap"));
        vm.serializeUint(o, "pmVerificationFloor", _safe(gp.pmVerificationFloor, "pmVerificationFloor"));
        vm.serializeUint(o, "pmVerificationCap", _safe(gp.pmVerificationCap, "pmVerificationCap"));
        vm.serializeUint(o, "postOpBaseGas", _safe(gp.postOpBaseGas, "postOpBaseGas"));
        vm.serializeUint(o, "postOpEscapeGas", _safe(gp.postOpEscapeGas, "postOpEscapeGas"));
        vm.serializeUint(o, "postOpFinalizeExtraGas", _safe(gp.postOpFinalizeExtraGas, "postOpFinalizeExtraGas"));
        vm.serializeUint(o, "postOpEscapeForwardGas", _safe(gp.postOpEscapeForwardGas, "postOpEscapeForwardGas"));
        vm.serializeUint(o, "eoaPushGas", _safe(gp.eoaPushGas, "eoaPushGas"));
        vm.serializeUint(o, "newAccountGas", _safe(gp.newAccountGas, "newAccountGas"));
        vm.serializeUint(o, "payoutPushGas", _safe(gp.payoutPushGas, "payoutPushGas"));
        vm.serializeUint(o, "creditGas", _safe(gp.creditGas, "creditGas"));
        vm.serializeUint(o, "accountCallOverheadGas", _safe(gp.accountCallOverheadGas, "accountCallOverheadGas"));
        vm.serializeUint(
            o, "accountCallOverheadEscapeGas", _safe(gp.accountCallOverheadEscapeGas, "accountCallOverheadEscapeGas")
        );
        vm.serializeUint(o, "marginGas", _safe(gp.marginGas, "marginGas"));
        vm.serializeUint(o, "finalizeReserveGas", _safe(gp.finalizeReserveGas, "finalizeReserveGas"));
        vm.serializeString(
            m, "paymasterGasPolicy", vm.serializeUint(o, "maxAttempts", _safe(gp.maxAttempts, "maxAttempts"))
        );
    }

    function _logGasless(Deployed memory d, Gasless memory g) internal view {
        console2.log("entryPoint   ", address(g.entryPoint));
        console2.log("paymaster    ", address(d.paymaster));
        console2.log("factory      ", address(d.factory));
        console2.log("accountLogic ", d.implementation);
        console2.log("paymasterOwner", g.owner);
        if (d.paymasterOwnershipPending) {
            console2.log("WARNING: the deployer owns the paymaster until PAYMASTER_OWNER calls acceptOwnership() on it");
        }
        console2.log("paymaster deposit (wei)", g.depositWei);
        console2.log("paymaster stake (wei)  ", g.stakeWei);
        console2.log("factory stake (wei)    ", g.factoryStakeWei);
        console2.log("escapes sponsored      ", g.policy.escapesEnabled);
        console2.log("paymaster codehash");
        console2.logBytes32(address(d.paymaster).codehash);
        console2.log("factory codehash");
        console2.logBytes32(address(d.factory).codehash);
    }

    /// The directory part of `path`, with its final "/" ("" for a bare file name).
    function _directory(string memory path) internal pure returns (string memory) {
        bytes memory raw = bytes(path);
        uint256 end = raw.length;
        while (end > 0 && raw[end - 1] != "/") {
            --end;
        }
        bytes memory out = new bytes(end);
        for (uint256 i = 0; i < end; ++i) {
            out[i] = raw[i];
        }
        return string(out);
    }

    function _create(bytes memory initcode) internal returns (address deployed) {
        assembly ("memory-safe") {
            deployed := create(0, add(initcode, 0x20), mload(initcode))
        }
        require(deployed != address(0), "contract creation failed");
    }

    /// A positive uint64 that JSON carries exactly to JavaScript (at most 2^53 - 1 seconds).
    function _positiveSafeInteger(uint256 value, string memory name) internal pure returns (uint64) {
        require(value > 0 && value <= MAX_SAFE_INTEGER, string.concat(name, " must be a positive safe integer"));
        // casting to 'uint64' is safe because value is at most MAX_SAFE_INTEGER
        // forge-lint: disable-next-line(unsafe-typecast)
        return uint64(value);
    }

    /// A gas figure the manifest writes as a bare JSON number: at most 2^53 - 1.
    function _safe(uint256 value, string memory name) internal pure returns (uint256) {
        require(value <= MAX_SAFE_INTEGER, string.concat("paymaster gas policy ", name, " above 2^53 - 1"));
        return value;
    }
}
