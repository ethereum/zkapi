# Git handoff for the ZK API Groth16 ceremony

**Preparation only: no ceremony has been initialized or run by this change.**
The scripts, configuration template, dependency lock and tests are provided.
Runtime tests/rehearsals and cross-platform checks have deliberately not been
run, at the operator's request. Complete the validation below before inviting
participants. The example configuration is deliberately invalid until the
operator chooses the circuit revision and public beacon schedule.

These tools wrap the existing [ceremony and import procedure](../../protocol/setup/v2-concession/README.md).
They cover the **request and withdrawal** circuits exported by `export_r1cs`.
They do not change the cryptography, deploy contracts, import production keys,
or update key pins automatically. The separate development-setup escape hatch
does not relax the requirements for a ceremony labelled `mpc-1`.

## Files and commands

Participants download an assigned directory/archive and run
`sh contribute.sh` (macOS/Linux) or `contribute.cmd` (Windows). Node.js 24+, npm,
and Git must already be installed. Rust is needed only on the coordinator and
independent reviewers' machines. Runtime dependencies are locked to snarkjs
0.7.6 and its exact transitive dependencies. The first launcher run downloads
those dependencies; this is not a self-contained/offline executable.

| Command | What it does |
| --- | --- |
| `init` | Exports frozen circuits, checks public phase 1, creates initial keys and a separate bare Git ledger |
| `pack` | Copies pinned scripts, powers of tau and a full input bundle into a new participant directory |
| `contribute` | Verifies inputs, contributes to both circuits, verifies outputs and creates an incremental return bundle |
| `accept` | Checks the exact parent, allowed files, both transcript prefixes, hashes and cryptographic validity before advancing |
| `finalize` | Enforces participant counts and beacon timing, applies and verifies the precommitted beacon |
| `export-final` | Exports final zkeys, full Git transcript, manifest and import arguments; does not run the Rust importer |
| `status` | Reports the accepted round and whether the ceremony is finalized |

Run commands below from `tools/ceremony`. All paths passed as arguments may be
absolute. Output directories must not already exist. There are no background
jobs, scheduled operations, upload commands or automatic publication.

## Before launch (intentionally not performed yet)

1. Review this tooling and the frozen circuit. Install dependencies with
   `npm ci --ignore-scripts --no-audit --no-fund`.
2. Run `npm test`, then explicitly run `npm run rehearse`. The latter **does
   generate disposable toy keys and contributions** and must wait until
   rehearsals are authorized. It exercises named/anonymous participants,
   forged and stale submissions, finalization and bundle export. Its known
   public phase-1 entropy is exclusively for a `rehearsal`, never `mpc-1`.
3. Perform the real-circuit fidelity gates in the existing setup README and a
   separate real-circuit rehearsal. Measure download size, memory, disk and
   runtime on the actual participant machines; no estimates are promised here.
   Exercise both launchers on their target operating systems.
4. Freeze a clean, reviewed source commit **including these tools and lockfile**.
   Circuit changes require a new ceremony. Initializing production invokes the
   Rust exporter from that exact clean checkout; the fixture override is
   restricted to `rehearsal`.
5. Obtain the public Hermez `powersOfTau28_hez_final_16.ptau` from the source
   listed in the [snarkjs README](https://github.com/iden3/snarkjs#7-prepare-phase-2).
   Production checks its published Blake2b-512, as pinned in
   `zkapi_proof::ceremony::PUBLIC_PTAU`, plus the configured SHA-256. This
   wrapper deliberately supports that power-16 public file only. A circuit
   exceeding its capacity needs a reviewed tooling change and a new ceremony.
6. Arrange ten sequential participants (configurable), including at least two
   **distinct externally nominated** contributors. Agree on their nomination
   evidence and private/pseudonymous communication if desired.
7. Copy `ceremony.config.example.json` to `ceremony.config.json`. Set the full
   source commit, expected count, UTC contribution deadline and exact future
   public beacon event. Close contributions **before** the beacon becomes
   available. Publicly commit the plan before any contributions. If the
   schedule is missed, these tools fail closed: start a new ceremony with a
   new plan rather than edit the frozen manifest.

## Start only when authorized

```sh
node ceremony.mjs init \
  --source /path/to/frozen/zkapi \
  --config ceremony.config.json \
  --ptau /path/to/powersOfTau28_hez_final_16.ptau \
  --out /path/to/ceremony-state
```

`init` is the first command that starts the ceremony. It runs phase-1
verification, exports both circuits, generates/verifies the initial zkeys, and
records their hashes and all executable tooling hashes in the initial commit.
It does not create participant contributions. Keep the state directory outside
the source checkout (or under ignored `tools/ceremony/work/`). Back it up after
each accepted round, including `ledger.git` and `pot.ptau`.

## One participant at a time

```sh
node ceremony.mjs pack --state /path/to/ceremony-state --out /path/to/participant-01
```

Archive the entire output directory as a ZIP or tar archive. Send it and a hash
of that archive through the agreed channel; communicate the printed assignment
hash separately too. `checksums.json` helps detect corruption but a manifest
inside an untrusted download does not authenticate itself. No files are sent by
these scripts. The [participant instructions](PARTICIPANT.md) are included.

The participant runs the launcher, optionally leaves both identity fields
empty, and returns one `contribution.bundle` plus its SHA-256 sidecar. An email
alone or a name alone is also supported. Empty receipt fields remain null;
both Git author and committer use explicit neutral placeholders for omissions.
No global identity, automatic signing, hooks or local Git templates are used.
All commit timestamps are fixed UTC to avoid recording participant timezones.

After checking the received file against its communicated hash:

```sh
node ceremony.mjs accept --state /path/to/ceremony-state \
  --bundle /path/to/contribution.bundle
```

For an externally nominated participant, add `--nomination /path/to/evidence.json`:

```json
{
  "nominatedBy": "external-reviewer-reference",
  "participantRef": "independent-participant-01",
  "evidence": "https://example.org/published-nomination-or-attestation"
}
```

This is public evidence stored in a coordinator acceptance commit; avoid real
names if the participant wants anonymous attribution. The scripts enforce two
distinct references before production finalization, but humans must check the
independence and evidence. A Git author or an operator-supplied nomination is
not a cryptographic identity attestation. Nomination evidence must be supplied
on acceptance; it cannot be retroactively added by an unverified participant.

Acceptance validates both circuits before atomically updating the one accepted
Git ref. It only imports data objects: it never checks out submitted content or
executes a submitted script. The candidate must have exactly one parent equal
to the current accepted commit and change only the two zkeys, state and its new
receipt. Every previous serialized contribution record must be preserved and
exactly one new ordinary contribution appended. This check supplements
`snarkjs zkey verify`, which alone can accept a different valid contribution
history. Unexpected files, beacons, rewritten prefixes and stale submissions
are rejected. Both cryptographic verifications must explicitly return true.

Then pack participant 02 from the new state. Do not prepare all ten packages
from the same starting state. Rejected/stale contributions must be recomputed;
Git cherry-picks and conflict resolution do not combine independent ceremonies.

## Finalization and independent review

After all planned participants are accepted and the precommitted beacon event
has occurred, independently obtain and check its value. Prepare:

```json
{
  "source": "EXACT SAME PUBLIC EVENT STRING AS THE FROZEN CONFIG",
  "value": "64_lowercase_hex_characters_from_that_public_event",
  "evidence": "https://public-source.example/event-and-value"
}
```

```sh
node ceremony.mjs finalize --state /path/to/ceremony-state --beacon /path/to/beacon.json
node ceremony.mjs export-final --state /path/to/ceremony-state --out /path/to/final-transcript
```

The software checks the pinned source description, time, counts, format and
resulting beacon contribution. **It does not fetch or authenticate the public
beacon event:** coordinator and external reviewers must verify that the value
actually came from the precommitted event, including its finality. Never use
locally generated randomness as a substitute for that public beacon.

Publish the export: final zkeys, circuit files, `transcript.json`, its SHA-256,
and `transcript.bundle`. The bundle contains the full history including every
intermediate zkey, receipt and nomination. It can be cloned for independent
inspection; no submission requires access to the application repository.

Each external reviewer independently obtains the public powers of tau, checks
both published hashes, exports circuits at the frozen source commit, compares
their hashes, and runs snarkjs verification against their own exports for both
final keys. Check that all accepted contribution receipts occur in the chain.
Reproduce the circuit fidelity checks and inspect the nomination/beacon evidence.

Only after those checks, run the existing Rust `import_zkey` procedure.
`import-arguments.json` contains the argument list and the computed transcript
hash, but is **not an executable script**. Run from the frozen source's
`protocol/rust` directory, replacing each artifact filename with its absolute
path in the export and choosing a fresh output directory. Use `mpc-1` for the
production ceremony, `rehearsal` for rehearsals. Then follow the original
README's proving gate, fixture generation, Solidity adapter, VK pin updates,
SDK/WASM rebuild and release checks in one reviewed repository change. These
tools do not perform that publishing/deployment step.

## Recovery, storage and trust boundaries

- The ceremony ledger is a separate bare Git repository. The return bundle is
  imported there, not applied directly as a source-code patch. It carries the
  participant commit; a coordinator commit records acceptance and nomination.
- Files stay in Git itself, not LFS pointers. Each new zkey is substantial;
  input packages contain the full accepted history and grow with every round.
  Measure before launch and use a file-transfer service if email limits are
  exceeded. Do not assume cryptographic point data delta-compresses well.
- `pack`, `accept`, `finalize` and `export-final` take a filesystem lock.
  Ordinary failures remove temporary files and do not advance the accepted
  ref. A killed process can leave `.ceremony-lock` and `.operation-*` directories.
  After confirming no process remains, inspect/remove those and retry. Partial
  output directories are not accepted results. Git ref updates use the previous
  commit as a compare-and-swap guard; do not manually change the ref.
- A repeated accepted bundle is stale. If an accept command was interrupted,
  run `status` before retrying. Rejected objects may remain unreachable inside
  the Git object database; they are not included in bundles of the accepted ref.
- Neither identity omission nor a Git commit proves secure secret erasure or
  independent ownership of machines. Contribution entropy stays in a short-lived
  child process, but JavaScript copies and OS swap/core dumps cannot be securely
  erased by this tool. No secret entropy is persisted intentionally.
- This is operational tooling, not a cryptographic audit. The deployment gates
  and independent circuit checks in the original ceremony README still apply.
