// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

// Compiles the vault's Poseidon (legacy pipeline, foundry.toml compilation_restrictions) into
// out/Bn254PoseidonRuntime.sol/Bn254PoseidonRuntime.json, which Deploy.s.sol deploys. Deploy.s.sol
// itself does not import it: an importer would join the legacy profile.
import "zkapi-contracts/poseidon/Bn254PoseidonRuntime.sol";

/// @dev Nothing: this file only brings Bn254PoseidonRuntime into the build.
abstract contract PoseidonRuntimeArtifact {}
