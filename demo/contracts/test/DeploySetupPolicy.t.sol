// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

import {Test} from "forge-std/Test.sol";
import {SetupPolicy} from "../script/SetupPolicy.sol";

/// @dev Exposes the deployment script's setup policy.
contract DeploySetupPolicyHarness is SetupPolicy {
    function check(SetupFacts memory setup, bool local, bool allowDevSetup) external pure {
        _checkSetupPolicy(setup, local, allowDevSetup);
    }

    function kinds() external pure returns (string[5] memory) {
        return _vkKinds();
    }
}

/// @dev Deploy.s.sol deploys a single-party setup (dev, rehearsal) freely on local chains and off
///      local chains (mainnet included) only with ALLOW_DEV_SETUP=1, and an mpc-1 setup off local
///      chains only with all five of the committed ceremony manifest's verifying keys (request,
///      withdrawal and the three insertion keys), so neither the label nor
///      a self-made manifest gets a forgeable vault onto a public chain without the opt-in. The
///      policy depends on the chain only through `local`; CI simulates the script on Sepolia's and
///      mainnet's chain IDs.
contract DeploySetupPolicyTest is Test {
    // The committed dev setup's verifying-key hashes (protocol/setup/v2-concession-dev), in
    // SetupPolicy._vkKinds() order: request, withdrawal, insertion1, insertion4, insertion16.
    bytes32 constant DEV_REQUEST_VK = 0x78ee5bb1fd0d0eeedfc36e769a24e36b9df6e6464154344e57824f4812fd4496;
    bytes32 constant DEV_WITHDRAWAL_VK = 0x8ea30a21c1727fdc919a895dcd76c968f869055539e9212066988f1678d0ac30;
    bytes32 constant DEV_INSERTION1_VK = 0xbfe4bbfa7e02e038151d9cbfd804bbed7d3778cea9e235698da7af9bd08ead38;
    bytes32 constant DEV_INSERTION4_VK = 0x2b2aec8bfe7f9bb89197afbf0956a72f93ddc8fff3618fa4b2e4dbb38da69414;
    bytes32 constant DEV_INSERTION16_VK = 0x2433029b1c075abbd406f222554051dd40cbad992ca650c3d7f0f3ba8839aa9a;

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

    function _dev() internal pure returns (bytes32[5] memory) {
        return [DEV_REQUEST_VK, DEV_WITHDRAWAL_VK, DEV_INSERTION1_VK, DEV_INSERTION4_VK, DEV_INSERTION16_VK];
    }

    function _ceremony() internal pure returns (bytes32[5] memory) {
        return [
            keccak256("ceremony request vk"),
            keccak256("ceremony withdrawal vk"),
            keccak256("ceremony insertion1 vk"),
            keccak256("ceremony insertion4 vk"),
            keccak256("ceremony insertion16 vk")
        ];
    }

    function _facts(string memory setupId, bytes32[5] memory vkHashes, bool pinned)
        internal
        pure
        returns (SetupPolicy.SetupFacts memory facts)
    {
        facts.circuitId = "zkapi-v2-concession-v2";
        facts.setupId = setupId;
        facts.vkHashes = vkHashes;
        facts.ceremonyPinned = pinned;
        if (pinned) facts.ceremonyVkHashes = _ceremony();
    }

    function test_singlePartySetupsDeployFreelyOnLocalChains() public view {
        harness.check(_facts("dev", _dev(), false), true, false);
        harness.check(_facts("rehearsal", _dev(), false), true, false);
    }

    /// Off local chains (Sepolia, mainnet or any other public chain) a single-party setup needs the
    /// explicit opt-in, whether or not the ceremony keys are pinned.
    function test_singlePartySetupsNeedTheOptInOffLocalChains() public {
        bool[2] memory pinned = [false, true];
        for (uint256 i = 0; i < pinned.length; ++i) {
            vm.expectRevert(bytes(SINGLE_PARTY_DEV));
            harness.check(_facts("dev", _dev(), pinned[i]), false, false);
            vm.expectRevert(bytes(SINGLE_PARTY_REHEARSAL));
            harness.check(_facts("rehearsal", _dev(), pinned[i]), false, false);
            harness.check(_facts("dev", _dev(), pinned[i]), false, true);
            harness.check(_facts("rehearsal", _dev(), pinned[i]), false, true);
        }
    }

    /// Before the ceremony keys are pinned no mpc-1 setup deploys off a local chain, whatever its
    /// manifest claims (a relabelled dev setup, or any self-made one) and whatever the opt-in says.
    function test_mpc1NeedsTheCommittedCeremonyPins() public {
        vm.expectRevert(bytes(NOT_PINNED));
        harness.check(_facts("mpc-1", _dev(), false), false, true);
        vm.expectRevert(bytes(NOT_PINNED));
        harness.check(_facts("mpc-1", _ceremony(), false), false, false);
    }

    /// Once pinned, an mpc-1 setup deploys only with all five of the ceremony's verifying-key
    /// hashes: a forged insertion proof sets the request tree's root, so one foreign insertion key
    /// refuses the setup as a foreign request or withdrawal key does.
    function test_mpc1MustMatchEveryCeremonyVerifyingKey() public {
        harness.check(_facts("mpc-1", _ceremony(), true), false, false);
        vm.expectRevert(bytes(NOT_THE_CEREMONY));
        harness.check(_facts("mpc-1", _dev(), true), false, true);
        for (uint256 k = 0; k < 5; ++k) {
            bytes32[5] memory oneForeign = _ceremony();
            oneForeign[k] = _dev()[k];
            vm.expectRevert(bytes(NOT_THE_CEREMONY));
            harness.check(_facts("mpc-1", oneForeign, true), false, false);
            bytes32[5] memory oneCeremony = _dev();
            oneCeremony[k] = _ceremony()[k];
            vm.expectRevert(bytes(NOT_THE_CEREMONY));
            harness.check(_facts("mpc-1", oneCeremony, true), false, true);
        }
        // Local chains accept an mpc-1 setup that is not pinned (testing the import pipeline).
        harness.check(_facts("mpc-1", _dev(), false), true, false);
    }

    function test_refusesOtherCircuitsAndUnknownSetupIds() public {
        string[2] memory others = ["zkapi-v2-note-bound-v1", "zkapi-v2-concession-v1"];
        for (uint256 i = 0; i < others.length; ++i) {
            SetupPolicy.SetupFacts memory facts = _facts("dev", _dev(), false);
            facts.circuitId = others[i];
            vm.expectRevert(bytes("SETUP_MANIFEST is not a zkapi-v2-concession-v2 setup"));
            harness.check(facts, true, false);
        }
        string[3] memory unknown = ["mpc-2", "", "DEV"];
        for (uint256 i = 0; i < unknown.length; ++i) {
            vm.expectRevert(bytes("SETUP_MANIFEST names an unknown setup_id"));
            harness.check(_facts(unknown[i], _ceremony(), true), true, true);
        }
    }

    /// The pinned dev hashes are the committed dev setup's, in _vkKinds() order, so the policy and
    /// Deploy.s.sol read the manifest's five keys under the names it writes.
    function test_devPinsAreTheCommittedSetupsInKindOrder() public view {
        string memory manifest = vm.readFile("../../protocol/setup/v2-concession-dev/manifest.json");
        string[5] memory kinds = harness.kinds();
        bytes32[5] memory dev = _dev();
        for (uint256 k = 0; k < kinds.length; ++k) {
            assertEq(vm.parseJsonBytes32(manifest, string.concat(".vk_keccak256.", kinds[k])), dev[k], kinds[k]);
        }
        assertEq(vm.parseJsonString(manifest, ".circuit_id"), "zkapi-v2-concession-v2");
    }
}
