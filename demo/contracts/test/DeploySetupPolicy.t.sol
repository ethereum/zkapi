// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SetupPolicy} from "../script/SetupPolicy.sol";

/// @dev Exposes the deployment script's setup policy.
contract DeploySetupPolicyHarness is SetupPolicy {
    function check(SetupFacts memory setup, bool local, bool allowDevSetup) external pure {
        _checkSetupPolicy(setup, local, allowDevSetup);
    }
}

/// @dev Deploy.s.sol deploys a single-party setup (dev, rehearsal) freely on local chains and off
///      local chains (mainnet included) only with ALLOW_DEV_SETUP=1, and an mpc-1 setup off local
///      chains only with the committed ceremony manifest's verifying keys, so neither the label nor
///      a self-made manifest gets a forgeable vault onto a public chain without the opt-in. The
///      policy depends on the chain only through `local`; CI simulates the script on Sepolia's and
///      mainnet's chain IDs.
contract DeploySetupPolicyTest is Test {
    // The committed dev setup's verifying-key hashes (protocol/setup/v2-concession-dev).
    bytes32 constant DEV_REQUEST_VK = 0x346b3c1414685205ebe8f7d6a1533cc2936be5f7922e90b24bf46d556d8a3790;
    bytes32 constant DEV_WITHDRAWAL_VK = 0xfe768c9fed820772e0ccc6015a82b6d5387183d1241e8b1d6361d865f30f2ae1;
    bytes32 constant CEREMONY_REQUEST_VK = keccak256("ceremony request vk");
    bytes32 constant CEREMONY_WITHDRAWAL_VK = keccak256("ceremony withdrawal vk");

    string constant SINGLE_PARTY_DEV =
        "setup dev is single-party: off local chains it deploys only with ALLOW_DEV_SETUP=1";
    string constant SINGLE_PARTY_REHEARSAL =
        "setup rehearsal is single-party: off local chains it deploys only with ALLOW_DEV_SETUP=1";
    string constant NOT_PINNED =
        "mpc-1 is not pinned yet: protocol/setup/v2-concession/manifest.json lands with the ceremony keys (G-SETUP step 7)";
    string constant NOT_THE_CEREMONY =
        "SETUP_MANIFEST's mpc-1 verifying keys are not the ceremony's (protocol/setup/v2-concession/manifest.json)";

    DeploySetupPolicyHarness harness;

    function setUp() public {
        harness = new DeploySetupPolicyHarness();
    }

    function _facts(string memory setupId, bytes32 request, bytes32 withdrawal, bool pinned)
        internal
        pure
        returns (SetupPolicy.SetupFacts memory facts)
    {
        facts.circuitId = "zkapi-v2-concession-v1";
        facts.setupId = setupId;
        facts.requestVkHash = request;
        facts.withdrawalVkHash = withdrawal;
        facts.ceremonyPinned = pinned;
        if (pinned) {
            facts.ceremonyRequestVkHash = CEREMONY_REQUEST_VK;
            facts.ceremonyWithdrawalVkHash = CEREMONY_WITHDRAWAL_VK;
        }
    }

    function test_singlePartySetupsDeployFreelyOnLocalChains() public view {
        harness.check(_facts("dev", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, false), true, false);
        harness.check(_facts("rehearsal", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, false), true, false);
    }

    /// Off local chains (Sepolia, mainnet or any other public chain) a single-party setup needs the
    /// explicit opt-in, whether or not the ceremony keys are pinned.
    function test_singlePartySetupsNeedTheOptInOffLocalChains() public {
        bool[2] memory pinned = [false, true];
        for (uint256 i = 0; i < pinned.length; ++i) {
            vm.expectRevert(bytes(SINGLE_PARTY_DEV));
            harness.check(_facts("dev", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, pinned[i]), false, false);
            vm.expectRevert(bytes(SINGLE_PARTY_REHEARSAL));
            harness.check(_facts("rehearsal", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, pinned[i]), false, false);
            harness.check(_facts("dev", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, pinned[i]), false, true);
            harness.check(_facts("rehearsal", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, pinned[i]), false, true);
        }
    }

    /// Before the ceremony keys are pinned no mpc-1 setup deploys off a local chain, whatever its
    /// manifest claims (a relabelled dev setup, or any self-made one) and whatever the opt-in says.
    function test_mpc1NeedsTheCommittedCeremonyPins() public {
        vm.expectRevert(bytes(NOT_PINNED));
        harness.check(_facts("mpc-1", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, false), false, true);
        vm.expectRevert(bytes(NOT_PINNED));
        harness.check(_facts("mpc-1", CEREMONY_REQUEST_VK, CEREMONY_WITHDRAWAL_VK, false), false, false);
    }

    /// Once pinned, an mpc-1 setup deploys only with both of the ceremony's verifying-key hashes.
    function test_mpc1MustMatchBothCeremonyVerifyingKeys() public {
        harness.check(_facts("mpc-1", CEREMONY_REQUEST_VK, CEREMONY_WITHDRAWAL_VK, true), false, false);
        vm.expectRevert(bytes(NOT_THE_CEREMONY));
        harness.check(_facts("mpc-1", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, true), false, true);
        vm.expectRevert(bytes(NOT_THE_CEREMONY));
        harness.check(_facts("mpc-1", CEREMONY_REQUEST_VK, DEV_WITHDRAWAL_VK, true), false, false);
        vm.expectRevert(bytes(NOT_THE_CEREMONY));
        harness.check(_facts("mpc-1", DEV_REQUEST_VK, CEREMONY_WITHDRAWAL_VK, true), false, false);
        // Local chains accept an mpc-1 setup that is not pinned (testing the import pipeline).
        harness.check(_facts("mpc-1", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, false), true, false);
    }

    function test_refusesOtherCircuitsAndUnknownSetupIds() public {
        SetupPolicy.SetupFacts memory facts = _facts("dev", DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, false);
        facts.circuitId = "zkapi-v2-note-bound-v1";
        vm.expectRevert(bytes("SETUP_MANIFEST is not a zkapi-v2-concession-v1 setup"));
        harness.check(facts, true, false);
        string[3] memory unknown = ["mpc-2", "", "DEV"];
        for (uint256 i = 0; i < unknown.length; ++i) {
            vm.expectRevert(bytes("SETUP_MANIFEST names an unknown setup_id"));
            harness.check(_facts(unknown[i], CEREMONY_REQUEST_VK, CEREMONY_WITHDRAWAL_VK, true), true, true);
        }
    }
}
