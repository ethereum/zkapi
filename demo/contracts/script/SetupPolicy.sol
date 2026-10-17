// SPDX-License-Identifier: MIT
pragma solidity ^0.8.28;

/// @title SetupPolicy – which proving setup Deploy.s.sol may deploy a vault for (design sections
///        10.2 and 10.4), kept apart from the script so it can be tested without deploying.
/// @notice The dev and rehearsal setups are single-party: whoever generated them can forge every
///         proof, including defeat evidence. They deploy freely on local chains, and off local
///         chains (mainnet included) only with the explicit ALLOW_DEV_SETUP=1, which the manifest
///         records as allowDevSetup. The mpc-1 label is not trusted by itself: off local chains,
///         an mpc-1 setup must have all five verifying-key hashes (request, withdrawal and the 1-,
///         4- and 16-note insertion keys) of the committed ceremony manifest
///         (protocol/setup/v2-concession/manifest.json). zkapi-proof's release_policy_check keeps
///         that manifest absent until CEREMONY_VK_KECCAK256 pins the ceremony keys (G-SETUP step 7)
///         and equal to the pins afterwards, so before the ceremony no mpc-1 setup deploys off a
///         local chain.
abstract contract SetupPolicy {
    string internal constant CIRCUIT_ID = "zkapi-v2-concession-v2";
    string internal constant DEV_SETUP_ID = "dev";
    string internal constant REHEARSAL_SETUP_ID = "rehearsal";
    string internal constant CEREMONY_SETUP_ID = "mpc-1";
    /// The committed ceremony setup manifest, relative to demo/contracts (the script's project root).
    string internal constant CEREMONY_MANIFEST = "../../protocol/setup/v2-concession/manifest.json";

    /// The setup a SETUP_MANIFEST describes, and what the ceremony manifest pins. Verifying-key
    /// hashes are in _vkKinds() order.
    struct SetupFacts {
        string circuitId;
        string setupId;
        bytes32[5] vkHashes;
        /// Whether CEREMONY_MANIFEST exists (the ceremony keys are pinned).
        bool ceremonyPinned;
        bytes32[5] ceremonyVkHashes;
    }

    /// The verifying keys of a setup, as its manifest's vk_keccak256 names them: one adapter
    /// verifies all five.
    function _vkKinds() internal pure returns (string[5] memory) {
        return ["request", "withdrawal", "insertion1", "insertion4", "insertion16"];
    }

    /// Reverts unless a vault may be deployed for `setup`. `local` is a local chain (31337 or
    /// 1337); `allowDevSetup` is ALLOW_DEV_SETUP=1, the single-party opt-in.
    function _checkSetupPolicy(SetupFacts memory setup, bool local, bool allowDevSetup) internal pure {
        require(_eq(setup.circuitId, CIRCUIT_ID), "SETUP_MANIFEST is not a zkapi-v2-concession-v2 setup");
        bool singleParty = _eq(setup.setupId, DEV_SETUP_ID) || _eq(setup.setupId, REHEARSAL_SETUP_ID);
        if (singleParty) {
            require(
                local || allowDevSetup,
                string.concat(
                    "setup ", setup.setupId, " is single-party: off local chains it deploys only with ALLOW_DEV_SETUP=1"
                )
            );
            return;
        }
        require(_eq(setup.setupId, CEREMONY_SETUP_ID), "SETUP_MANIFEST names an unknown setup_id");
        if (local) return;
        require(
            setup.ceremonyPinned,
            "mpc-1 is not pinned yet: protocol/setup/v2-concession/manifest.json lands with the ceremony keys (G-SETUP step 7)"
        );
        for (uint256 k = 0; k < setup.vkHashes.length; ++k) {
            require(
                setup.vkHashes[k] == setup.ceremonyVkHashes[k],
                "SETUP_MANIFEST's mpc-1 verifying keys are not the ceremony's (protocol/setup/v2-concession/manifest.json)"
            );
        }
    }

    function _eq(string memory a, string memory b) internal pure returns (bool) {
        return keccak256(bytes(a)) == keccak256(bytes(b));
    }
}
