# zkAPI Homebrew tap

Install the formula using this repository's tap name (`OWNER/zkapi` for a
repository named `OWNER/homebrew-zkapi`):

```sh
brew install OWNER/zkapi/zkapi-clientd
zkapi-clientd config
brew services start OWNER/zkapi/zkapi-clientd
```

The service uses launchd on macOS and systemd on Linux. Run it as your login
user. Initialize your wallet before starting the service.

To update, stop the service, run `brew update && brew upgrade zkapi-clientd`,
then start the service again. Configuration and wallet state are retained.

Formulae are promoted from checksum-verified [zkAPI client releases](https://github.com/ethereum/zkapi/releases).
See the [packaging and service documentation](https://github.com/ethereum/zkapi/blob/main/zkapi-clientd/docs/CLI_PACKAGING.md).
