# Browser deployment profile fixtures

These mirror the SDK's build profiles (`sdk/assets/config/{mainnet,sepolia}.json`)
for the leaf-bound concession-exit vault (revision 4, circuit
`zkapi-v2-concession-v2`, `leaf_bound_exit: 1`). Until that vault is deployed
on a network, both the SDK profile and the packaged clientd deployment are
`deployment_status: "not_deployed"` placeholders that pin only the circuit,
setup, proving-key hashes and the vault parameters, including
`min_deposit_units` (the vault's `minDeposit()`, 1,000,000 gwei) and
`fresh_slot_gas` (22,100 on mainnet rules, 110,000 on Sepolia under
EIP-8037). `deployments_test.go` checks that the packaged clientd deployments
pin the same values as these profiles.

`testdata/deployed/deployments/*.json` are invented, deployed concession
profiles (fake addresses and code hashes) that the package tests run
against in place of the placeholders. They pin `min_deposit_units: 1`, the
minimum of the vault test bases, so the tests' small deposits are valid.
