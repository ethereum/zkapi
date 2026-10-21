# Selecting the on-chain vault protocol

Save a per-profile preference, just like the default model:

```sh
CLIENT=$HOME/zkapi/zkapi-clientd/bin/zkapi-clientd-concession-tor
$CLIENT config --vault-protocol legacy
$CLIENT config             # show saved choice
$CLIENT serve                         # uses that choice, no repeated flag
$CLIENT config --vault-protocol concession  # switch with daemon stopped
$CLIENT config --vault-protocol default     # restore default: concession
```

Use `--config-dir DIR` when editing a non-default profile. Saving legacy requires
a compatible existing legacy profile. Native rewriter/cover settings are
preserved and implemented by both protocol stacks. The preference editor always runs locally, allowing
you to switch back even when legacy is selected. No network calls or payments.

For an optional one-command override, use the **global** option before the command:

```sh
CLIENT=$HOME/zkapi/zkapi-clientd/bin/zkapi-clientd-concession-tor

# Existing old-vault profile: old stack's automatic funding and inference flow.
$CLIENT --vault-protocol legacy --config-dir /absolute/path/to/legacy-profile serve

# New-vault profile: new stack. Currently refuses undeployed networks.
$CLIENT --vault-protocol concession --config-dir /absolute/path/to/concession-profile serve

# Withdrawal must use the same protocol/profile that owns the note.
$CLIENT --vault-protocol legacy --config-dir /absolute/path/to/legacy-profile withdraw
```

Precedence: explicit `--vault-protocol` > `ZKAPI_VAULT_PROTOCOL` (if set) > saved
profile preference > concession. No export or repeated flag is needed. Remove an
old environment override if you want the saved setting to take effect.

The owner-only `vault-protocol` file in the profile stores this preference;
`config.json` stays byte-for-byte unchanged because the legacy decoder rejects
unknown fields. Updates use the same `daemon.lock`, stale-snapshot protection,
atomic rename and fsync pattern as model configuration. Stop serve before edits.
`config --vault-protocol default` removes the preference. No wallet/profile conversion or credential
copying. `version`/top-level `help` report the dispatcher; command-specific help
in legacy mode requires its valid profile.

## This selects a stack, not an address

Concession uses circuit `zkapi-v2-concession-v1`, vault revision 3, and its current
compiled manifests. Legacy uses `zkapi-v2-note-bound-v1` and the historical
compiled manifests, client, companion and verified proving setup. A new prover
cannot operate an old vault by replacing a contract address.

Legacy dispatch verifies SHA-256 pins for the local historical executables:

- sibling `bin/zkapi-clientd-legacy-privacy`, legacy protocol source checkpoint
  `be04d85` plus current shared privacy code (not upstream 0.1.7);
- the legacy profile's explicitly configured absolute companion path, matching
  the preserved `bin/zkapi-walletd` artifact.

The profile must also explicitly name its absolute original proving-setup path;
the old companion validates its own proving/deployment pins. External companions
and companion/setup overrides through this dispatcher are refused. Missing or
changed binaries fail, with no PATH lookup, privacy-less legacy fallback or
concession fallback. This is a local development pairing, not a downloadable
production bundle. The original `zkapi-clientd-tor-mode` remains untouched for
historical recovery, but is no longer selected by this dispatcher.

### Shared privacy implementation and rebuilding

`bash zkapi-clientd/scripts/build-legacy-privacy.sh` reconstructs the pinned old
protocol source in a temporary directory, applies `packaging/legacy/privacy.patch`
(the adapter wiring), and overlays current files listed in
`packaging/legacy/shared-files.txt`. Rewriter, target transcript, server preview,
cover worker and their tests are shared verbatim—not independent forks. The
script runs the legacy race suite and vet, builds `bin/zkapi-clientd-legacy-privacy`,
and updates `cmd/zkapi-clientd/legacy_client.sha256`. Rebuild the primary client
afterward to embed that pin. The script uses the local Git checkpoint and current
Go toolchain; it never touches live profiles or starts a wallet. Run it after
shared privacy changes so both protocol engines stay in sync.

Switching protocols therefore preserves rewriter URL/key/model, exact saved
rewrites during each process lifetime, conversation-aware OR-key reuse rules,
Tor isolation, preview mode, and cover rate/targets/concurrency. Stopping and
restarting still clears in-memory transcripts and keys in either protocol;
unknown history is rewritten before inference. Protocol-specific proof, payment,
withdrawal and deployment checks necessarily remain different.

The dispatcher replaces itself with the legacy executable, preserving terminal
interaction, signals, profile locks and exit status. It does not sign or deposit
by itself, add approval flags, call raw contracts, or modify transaction journals.
`serve` retains the selected stack's existing automatic funding behavior.

## Important current limits

- **Concession remains `not_deployed`** on both shipping networks, with missing
  production proving keys. Selection does not make it available.
- The new legacy engine implements native rewriting and cover traffic, with the
  same default 5/s when cover is enabled. New concession exit/bundler settings
  are still incompatible with the old on-chain exit protocol and are refused;
  switching vaults does not translate them.
- Upstream's planned legacy 0.1.7 recovery line closes deposits and retires
  admission on a schedule. This selector does not establish that historical
  deposits or inference are still available today, and cannot bypass gateway,
  contract or selected-release closures. Do not deposit unless the legacy
  service's live availability and retirement schedule have been reviewed.
- The old gas-heavy deposit path remains gas-heavy. Selecting legacy is not a
  cheaper implementation of the concession protocol.
- Keep separate profile directories for the two stacks: funding records and
  pending signed transactions must not be repurposed across deployments. For
  recovery, point explicitly at the **original** legacy profile. An environment
  default config directory alone does not satisfy the legacy explicit-profile
  rule; a saved `legacy` selection does, so you need not repeat `--config-dir`.
  Use distinct API/companion ports if running both stacks concurrently.
- Configuration/profile edits do not migrate notes. A note remains withdrawable
  only through its matching protocol and original state/proving assets.

No service is restarted or live deposit attempted by implementing this option.
Both engines run the shared privacy regression tests, including no raw user
history at the target, OR-key continuity, rewrite/route failure before payment,
SSE previews, bounded cover workers and SOCKS/TLS fail-closed behavior. Dispatcher
tests verify privacy settings are accepted unchanged and only the privacy-enabled
legacy artifact is selected. No live legacy deposit acceptance or new-vault
availability has been verified.
