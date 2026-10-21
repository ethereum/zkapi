# Browser deployment profile fixtures

These mirror the SDK's build profiles (`sdk/assets/config/{mainnet,sepolia}.json`)
for the concession-exit vault (revision 3, circuit `zkapi-v2-concession-v1`).
Until that vault is deployed on a network, both the SDK profile and the
packaged clientd deployment are `deployment_status: "not_deployed"`
placeholders that pin only the circuit, setup, proving-key hashes and the
vault parameters. `deployments_test.go` checks that the packaged clientd
deployments pin the same values as these profiles.

`testdata/deployed/deployments/*.json` are invented, deployed concession
profiles (fake addresses and code hashes) that the package tests run
against in place of the placeholders.
