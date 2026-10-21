# Protocol source provenance

`protocol/` is tracked directly by this repository. A normal clone includes the
Rust workspace, Solidity contracts, selected proof setup, and Solidity
dependencies; no submodule initialization or separate protocol checkout is needed.
Make protocol changes here and commit them with the application changes that use
them. The Rust workspace under `rust/` remains separate from the root workspace.

The initial import preserves the files and executable modes from these pinned
revisions, except for the removed `.gitmodules` files:

| Directory relative to `protocol/` | Source repository | Imported commit |
| --- | --- | --- |
| `.` | <https://github.com/mingyech/zkapi> | `8b2d4e3da921f956e1eb6b93afbf722a877c060c` |
| `contracts/lib/forge-std` | <https://github.com/foundry-rs/forge-std> | `0844d7e1fc5e60d77b68e469bff60265f236c398` |
| `contracts/lib/openzeppelin-contracts` | <https://github.com/OpenZeppelin/openzeppelin-contracts> | `5fd1781b1454fd1ef8e722282f86f9293cacf256` |
| `contracts/lib/openzeppelin-contracts/lib/erc4626-tests` | <https://github.com/a16z/erc4626-tests> | `232ff9ba8194e406967f52ecc5cb52ed764209e9` |
| `contracts/lib/openzeppelin-contracts/lib/forge-std` | <https://github.com/foundry-rs/forge-std> | `3b20d60d14b343ee4f908cb8079495c07f5e8981` |
| `contracts/lib/openzeppelin-contracts/lib/halmos-cheatcodes` | <https://github.com/a16z/halmos-cheatcodes> | `7328abe100445fc53885c21d0e713b95293cf14c` |

The third-party libraries retain their upstream license files. Their own
documentation may describe upstream submodule workflows; those workflows do not
apply to this repository. Update these libraries as ordinary tracked files and
record their new revisions here. `contracts/foundry.lock` records the imported
direct dependency versions.

The files in `setup/v2/` (the legacy circuit `zkapi-v2-note-bound-v1`) are
unchanged from the pinned protocol revision; this import does not regenerate
their proving keys or verifiers. The setups of the current circuit,
`setup/v2-concession-dev/` and, once its ceremony has run,
`setup/v2-concession/`, are produced in this repository, as their READMEs
describe.

## Included dependency sources

The import revisions above describe provenance. The included OpenZeppelin
sources are Ownable, Ownable2Step, Context, ReentrancyGuard and StorageSlot,
with their license. `Ownable2Step.sol`, added for the vault's two-step
ownership transfer, is byte-for-byte the file of the recorded revision
(v5.6.1). The included forge-std sources are its helpers and licenses.

## ERC-4337 EntryPoint v0.7.0 runtime fixtures (test only)

The gasless withdrawal tests (`contracts/test/gasless/`) etch the canonical
ERC-4337 EntryPoint v0.7.0 and its SenderCreator at their mainnet addresses
(`vm.etch` in Forge; `anvil_setCode` in the acceptance harness). No EntryPoint
source is compiled into or linked with this repository: every eth-infinitism
file is GPL-3.0, `contracts/src/gasless/IERC4337.sol` is an original MIT
declaration of the v0.7.0 ABI subset the contracts use (written from EIP-4337
and the interface signatures, not copied), and `ZkApiWithdrawalPaymaster` pins
the canonical EntryPoint by its runtime codehash.

| Item | Provenance | License / use |
| --- | --- | --- |
| `contracts/test/fixtures/entrypoint-v0.7.0.runtime.hex` | Runtime code at `0x0000000071727De22E5E9d8BAf0edAc6f37da032`, read with `cast code` on 2026-10-12 from `https://ethereum-rpc.publicnode.com` (mainnet) and `https://ethereum-sepolia-rpc.publicnode.com` (Sepolia), byte-identical on both; 16,035 bytes; keccak256 `0x8db5ff695839d655407cc8490bb7a5d82337a86a6b39c3f0258aa6c3b582fc58`; source <https://github.com/eth-infinitism/account-abstraction> tag `v0.7.0` (commit `7af70c8993a6f42973f520ae0752386a5032abe7`), `contracts/core/EntryPoint.sol`, compiled per that tag's `hardhat.config.ts` (solc 0.8.23, optimizer 1,000,000 runs, viaIR) | GPL-3.0; redistributed unmodified beside `entrypoint-v0.7.0.LICENSE`; only etched into test chains, never compiled or linked |
| `contracts/test/fixtures/sender-creator-v0.7.0.runtime.hex` | Runtime at `0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C` (the CREATE of the EntryPoint at nonce 1, its `_senderCreator` immutable), same RPCs and date; 451 bytes; keccak256 `0x283c9d14378f5f4c4e24045b87d621d48443fa5b4af7dd7180a599b3756a7689`; `contracts/core/SenderCreator.sol` at the same tag and settings | same |
| `contracts/test/fixtures/entrypoint-v0.7.0.LICENSE` | The GPL-3.0 text of the tag, with a header naming the source, tag, commit, compiler settings, addresses, sizes, keccaks, fetch date and RPCs | the license of the two fixtures |

Reproduce either fixture and its keccak with

```
cast code 0x0000000071727De22E5E9d8BAf0edAc6f37da032 --rpc-url https://ethereum-rpc.publicnode.com | tee entrypoint-v0.7.0.runtime.hex
cast keccak "$(cat entrypoint-v0.7.0.runtime.hex)"
cast code 0xEFC2c1444eBCC4Db75e7613d20C6a62fF67A167C --rpc-url https://ethereum-rpc.publicnode.com | tee sender-creator-v0.7.0.runtime.hex
cast keccak "$(cat sender-creator-v0.7.0.runtime.hex)"
```

The tests assert both keccaks in `setUp`; the mainnet re-check before a public
deployment is a runbook step.

