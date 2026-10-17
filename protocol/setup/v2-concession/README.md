# Ceremony setup for `zkapi-v2-concession-v2` (setup id `mpc-1`)

This directory will hold the production Groth16 keys of circuit
`zkapi-v2-concession-v2`, produced by a snarkjs multi-party phase-2 ceremony
(gate **G-SETUP**). The setup has five circuits, each with its own keys:
the request and withdrawal statements the clients prove, and the 1-, 4- and
16-note insertion statements with which the operator's activation worker
appends deposited notes to the request tree. **It holds no keys yet.** Until the ceremony is complete,
CI, tests and the drill vault use the development setup in
[`../v2-concession-dev`](../v2-concession-dev/README.md), which release builds
refuse.

One setup serves Sepolia and mainnet (`chain_id` is a public input; the
insertion statements bind no deployment, and the vault accepts them only for
its own root, cursor and stored notes). Never regenerate it after a public
deployment: the adapter's `REQUEST_VK_HASH`, `WITHDRAWAL_VK_HASH` and
`INSERTION{1,4,16}_VK_HASH`, `CEREMONY_VK_KECCAK256` in `compact.rs`, every
client profile and every deployment manifest pin these keys.

## Trust assumption

Groth16 is sound only if nobody knows the setup's toxic waste. A trapdoor
holder can forge any proof, including defeat evidence against an honest
user's escape, and an insertion proof that activates notes nobody deposited
(free anonymous requests) or installs a root nobody can open (which blocks
every later activation). The insertion keys therefore come from the same
ceremony and are pinned like the others. The toxic waste has a phase-1 part and a phase-2 part, and
**both** must be unknown. So the setup is sound only if all three of these
hold:

1. **Phase 1.** At least one contributor to the public powers-of-tau
   transcript was honest, **and** the file the ceremony used is that public
   transcript. Whoever knows its `τ` can forge proofs however honest the
   phase-2 contributors are: every H point is then a known multiple of
   `1/δ·G1`. A powers of tau that one party made alone passes
   `snarkjs powersoftau verify`, `snarkjs zkey verify` and every consistency
   check of the import. Only its hash shows where it comes from (steps 3, 5
   and 6).
2. **Phase 2.** At least one phase-2 contributor was honest and outside the
   attacker's control.
3. **Binding.** The keys are keys of these circuits.

Users can audit all three through the powers-of-tau hash in `manifest.json`,
the published transcript, the VK hashes in the adapter and the codehash pins
in the client profiles.

The third condition is not implied by the first two. Contributions only
re-randomize `δ`; they cannot repair a ceremony that the coordinator set up
from another R1CS. For example, the R1CS could keep the A and B matrices but
change C so that `enforce_equal` rows become vacuous. Steps 2(c), 5 and 6 check
this binding independently of the coordinator.

## Steps

All commands run from `protocol/rust` at the frozen circuit revision
(`circuit-freeze-v2c`).

1. **Export.** Write the circom R1CS of the five circuits:

   ```text
   cargo run --release -p zkapi-proof --example export_r1cs -- ceremony/
   ```

   The files come from the finalized arkworks matrices
   (`OptimizationGoal::Constraints`, then `finalize()`), exactly as the
   generator and the prover see them.
   - Wire order is `[one, public inputs in statement order, witnesses]`.
   - All public inputs are declared public inputs (`nPubOut = 0`).
   - `r1cs-manifest.json` records the SHA-256 of the five files and the
     circuit shapes. Publish it: everyone who checks the ceremony compares
     their own export with it.

   At this revision the shapes and SHA-256 are:

   | Circuit | Constraints | Public inputs | Witnesses | QAP domain | `.r1cs` SHA-256 |
   | --- | --- | --- | --- | --- | --- |
   | request | 23,990 | 12 | 23,698 | 2^15 | `704d4ede…1b23d3f6` |
   | withdrawal | 21,029 | 17 | 20,545 | 2^15 | `ab6378d7…1ca7922d` |
   | insertion1 | 16,439 | 5 | 16,467 | 2^15 | `b9398104…2257ca86` |
   | insertion4 | 18,941 | 11 | 18,962 | 2^15 | `c22dacdb…5575d9d0` |
   | insertion16 | 31,847 | 35 | 31,852 | 2^15 | `5ece6fd3…b2451db4` |

   The request circuit is unchanged from `zkapi-v2-concession-v1` (same
   export). The withdrawal circuit is bound to the stored note (its
   registration commitment and packed amount and expiry are public inputs
   3 and 16; no Merkle path). Every circuit fits the 2^15 domain, so one
   powers of tau of power 15 serves all five (step 3).

2. **Fidelity gate** (in CI, and again on the frozen circuit):
   - (a) `r1cs_export_roundtrip`: the files parse back with `ark-circom`'s
     R1CS reader to the in-memory A, B, C matrices, instance count, witness
     count and wire order. This shows that the export is faithful. It says
     nothing about which file a ceremony used.
   - (b) `r1cs_negative_assignments`: for every negative case of the WP-A
     test plan, an independent evaluator over the exported file rejects the
     full unsatisfying assignment.
   - (c) After the ceremony, `import_zkey` (step 6) binds the keys to the
     circuit. A snarkjs zkey stores no C matrix: C reaches the keys only
     through the IC and L points.
     - Coefficient check: the zkey's section-4 A and B coefficients must
       equal the synthesized matrices. snarkjs's prover reads them and ours
       does not, so this check is for consistency only.
     - Binding check (`zkapi_proof::ceremony::check_key_binding`): every
       circuit-dependent point must be what `snarkjs groth16 setup` derives
       from this build's A, B **and C** over the pinned powers of tau, up to
       `δ`. That covers the A and B queries, IC, L and H. This is the circuit
       half of `snarkjs zkey verify`, computed from our own matrices.
     - A key set up from an R1CS with the same A and B but another C passes
       the coefficient check and the proving gate. Only the binding check
       refuses it (`keys_set_up_from_another_c_matrix_are_refused`).

   ```text
   cargo test --release -p zkapi-proof --test r1cs_fidelity --test zkey_import
   ```

   On the real ceremony files, before importing:

   ```text
   ZKAPI_PTAU=pot.ptau ZKAPI_REQUEST_ZKEY=ceremony/request_final.zkey \
   ZKAPI_WITHDRAWAL_ZKEY=ceremony/withdrawal_final.zkey \
   ZKAPI_INSERTION1_ZKEY=ceremony/insertion1_final.zkey \
   ZKAPI_INSERTION4_ZKEY=ceremony/insertion4_final.zkey \
   ZKAPI_INSERTION16_ZKEY=ceremony/insertion16_final.zkey \
   cargo test --release -p zkapi-proof --test zkey_import ceremony_zkeys_pass_the_import_gates -- --ignored
   ```

3. **Powers of tau.** Use a public BN254 phase-1 transcript prepared for
   phase 2, of power at least 15 (the domain of all five circuits): one of
   the Hermez files in `zkapi_proof::ceremony::PUBLIC_PTAU`
   (`powersOfTau28_hez_final_15.ptau` to `_27`). The smallest,
   `powersOfTau28_hez_final_15.ptau`, is enough for every circuit.
   - Download it from the source the snarkjs README lists. Check its
     Blake2b-512 against the hash listed there (`b2sum`, or
     `openssl dgst -blake2b512` with OpenSSL 1.1 or later). `PUBLIC_PTAU`
     holds the same hashes, and an `mpc-1` import refuses any file not on
     it. Using another public transcript is a reviewed change to that list,
     with the hash its publisher lists.
   - For reference, from circom.info (October 2026): the power-15 file has
     the listed Blake2b-512 `982372c8…2969ae6e` and SHA-256
     `3ef2ecc5b75d687048cf2d59195119b42fb07c5af639c5f283d84bfa69829e7f`;
     the power-16 file has the listed Blake2b-512 `6a6277a2…3efec125` and
     SHA-256 `1c401abb57c9ce531370f3015c3e75c0892e0f32b8b1e94ace0f6682d9695922`.
     Both pass the import's reference-string checks below.
   - Pin its SHA-256 before the ceremony starts and record it as
     `ptau_sha256`. Import with `--ptau-sha256 <pin>`.
   - Check it with the import's own checks:

     ```text
     ZKAPI_PTAU=pot.ptau cargo test --release -p zkapi-proof --test zkey_import \
       public_powers_of_tau_passes_the_import_checks -- --ignored
     ```

     This confirms that the file is on `PUBLIC_PTAU`, and that the points
     the import uses form one reference string. The Lagrange sections must
     be the inverse FFT of the `τ`-power sections, and those must be powers
     of one `τ`, scaled by `α` and `β`. So a file whose Lagrange sections
     alone were replaced (for example its H points) is refused.
   - `snarkjs powersoftau verify` checks the file's internal consistency and
     its contribution chain. It does not show where the file comes from: it
     accepts a file that one party made alone. It never replaces the hash
     check.

4. **Contributions.** For each of the five circuits (`request`,
   `withdrawal`, `insertion1`, `insertion4`, `insertion16`), on its own
   zkey chain:

   ```text
   snarkjs groth16 setup <circuit>.r1cs pot.ptau <circuit>_0000.zkey      # the step-1 export
   snarkjs zkey contribute <circuit>_000i.zkey <circuit>_000(i+1).zkey   # each contributor
   snarkjs zkey beacon <circuit>_000n.zkey <circuit>_final.zkey <beacon> 10
   ```

   - At least three contributions, **at least two of them by parties the
     operator did not select** (nominated by the external reviewers or by a
     public call), then a public random beacon fixed in advance (for example
     a future block hash).
   - Before contributing, each contributor should run
     `snarkjs zkey verify <own export> pot.ptau <received zkey>` on their own
     export.
   - If fewer contributors are available, the ceremony still requires two
     externally nominated contributions plus the beacon; otherwise mainnet
     slips. No single-party setup ever reaches mainnet or production
     Sepolia.
   - The import refuses an `mpc-1` zkey that records fewer than three
     contributions before its beacon. The rule holds for each of the five
     zkeys: the insertion keys are as security-critical as the others.

5. **Publication and independent verification.** Publish the transcript
   (every intermediate `.zkey`, the contribution hashes and attestations),
   `r1cs-manifest.json`, and every hash. Record the transcript's SHA-256 as
   `transcript_sha256`.
   - The coordinator's own `snarkjs zkey verify` output is evidence only for
     the `.r1cs` it was run on.
   - So **each external reviewer** must, at the frozen revision:
     1. download the powers of tau themselves from its public source, not
        from the coordinator. Check its Blake2b-512 against the hash its
        publisher lists (for Hermez, the snarkjs README), and its SHA-256
        against `ptau_sha256` in `manifest.json`. Neither
        `snarkjs powersoftau verify` nor `snarkjs zkey verify` can replace
        this check (Trust assumption, condition 1);
     2. export the R1CS themselves (step 1);
     3. check its SHA-256 against `r1cs-manifest.json`;
     4. run `snarkjs zkey verify <own export> <own ptau> <circuit>_final.zkey`
        for each of the five circuits.
   - That run checks the contribution chain (each `δ` update and its proof
     of knowledge), which `import_zkey` does not check. It also checks the
     circuit binding a second time.

6. **Import.** Convert the final zkeys into this directory:

   ```text
   cargo run --release -p zkapi-proof --example import_zkey -- \
     --setup-id mpc-1 \
     --ptau pot.ptau --ptau-sha256 <pinned hex> \
     --request-r1cs ceremony/request.r1cs --withdrawal-r1cs ceremony/withdrawal.r1cs \
     --insertion1-r1cs ceremony/insertion1.r1cs --insertion4-r1cs ceremony/insertion4.r1cs \
     --insertion16-r1cs ceremony/insertion16.r1cs \
     --request ceremony/request_final.zkey --withdrawal ceremony/withdrawal_final.zkey \
     --insertion1 ceremony/insertion1_final.zkey --insertion4 ceremony/insertion4_final.zkey \
     --insertion16 ceremony/insertion16_final.zkey \
     --transcript-sha256 <hex> \
     ../setup/v2-concession
   ```

   Every circuit takes an `--<kind>-r1cs` and an `--<kind>` zkey; the import
   refuses to run without all ten. It runs every gate before it writes
   anything:
   - the `.r1cs` files the ceremony used must be byte for byte this build's
     export;
   - the powers of tau must hash to the pin and, for `mpc-1`, be a public
     transcript of `PUBLIC_PTAU` (by its published Blake2b-512);
   - the points of the powers of tau that the keys are checked against must
     form one reference string (step 3);
   - each zkey must record at least three contributions followed by a beacon
     (`mpc-1` only; checked for all five before the gates below);
   - each zkey must pass the coefficient and binding checks of 2(c);
   - each zkey must have the key shapes: one IC point per public input plus
     one (13 request, 18 withdrawal, 6, 12 and 36 insertion), and an H query
     of the domain size;
   - the proving gate: a canonical statement of each circuit, proved with
     the shipping `CircomReduction` prover, must verify, and must stop
     verifying when any single public input changes (for an insertion key,
     K notes appended after K activated notes).

   The import refuses to overwrite existing key, manifest or Solidity files.
   It then writes:

   | File | Content |
   | --- | --- |
   | `request.pk`, `request.vk`, `withdrawal.pk`, `withdrawal.vk`, `insertion{1,4,16}.pk`, `insertion{1,4,16}.vk` | arkworks keys with headers `zkapi-v2-concession-v2/mpc-1/<kind>\0` |
   | `manifest.json` | See below |
   | `Groth16ProofAdapter.sol` | the regenerated adapter with `CIRCUIT_ID_HASH`, `REQUEST_VK_HASH`, `WITHDRAWAL_VK_HASH` and `INSERTION{1,4,16}_VK_HASH` (then `forge fmt` into `protocol/contracts/src/adapters`) |
   | `Bn254Poseidon.sol` | the Poseidon library |

   `manifest.json` records:
   - `setup_id: "mpc-1"` and `reduction: "circom"`;
   - the SHA-256 of the ten keys, and `vk_keccak256` per kind (`request`,
     `withdrawal`, `insertion1`, `insertion4`, `insertion16`);
   - `r1cs_sha256` (this build's exports), `ptau_sha256` (computed by the
     import), `transcript_sha256` and `zkey_sha256` (the final zkeys);
   - the circuit shapes, the verifying keys and the Poseidon parameters.

7. **Proving gate, before the keys are published.** With the imported keys
   (`ZKAPI_SETUP_DIR` points the proof tests at them):

   ```text
   ZKAPI_SETUP_DIR=../setup/v2-concession \
     cargo test --release -p zkapi-proof --test proofs --test reduction_cross_check
   cargo run --release -p zkapi-proof --example solidity_fixture -- ../setup/v2-concession
   cargo run --release -p zkapi-proof --example vault_challenge_fixture -- ../setup/v2-concession
   ```

   The first command runs, against the `CircomReduction` prover and the
   native verifier:
   - the mutate-each-public-input tests (12 request, 17 withdrawal, and
     5, 11 and 35 insertion inputs) and the non-canonical-input tests;
   - the negative proving tests;
   - positive proofs of every kind: genesis and signed requests; escapes
     with `c = 0` and `c > 0`; a mutual close (kind 1); an ownership proof
     (kind 2); a full 160-bit destination; activations of 1, 4 and 16 notes;
   - the manifest and adapter checks.

   The fixtures feed the same statements to the adapter deployed on Anvil
   (the contract tests).

   Then replace the pins, in the same change that commits the keys:
   - set `CEREMONY_VK_KECCAK256` in `zkapi-proof/src/compact.rs` to the five
     VK hashes (`VkPins { request, withdrawal, insertion1, insertion4,
     insertion16 }`) and run
     `cargo run --release -p zkapi-proof --bin release_policy_check`. It
     fails while this directory holds keys and no pins, or pins and keys
     that a release build does not load (every loader, the insertion
     provers and verifiers of each batch size included);
   - update the adapter, the fixtures, the SDK assets and hashes, the
     activation worker's keys, and the deployment profiles;
   - rebuild the WebAssembly reproducibly.

## Rehearsals

Dry runs of this pipeline must use `--setup-id rehearsal`. Examples are a
throwaway powers of tau (which `mpc-1` refuses), or a single contribution. Rehearsal keys load only
in `dev-setup` builds. Never label a dry run `mpc-1`. Its toxic waste is
known to whoever ran it.

## Acceptance by builds

Release builds of `zkapi-proof` (no `dev-setup` feature) accept only the
setup ids in `RELEASE_SETUP_IDS = ["mpc-1"]`. An `mpc-1` key also needs a
verifying key whose keccak256 equals the pin of its kind in
`CEREMONY_VK_KECCAK256`, so a key that merely carries the label is refused.
That pin is `None` until step 7, so release builds load no key until then.

Test builds (`--features dev-setup`) also accept `dev`, `rehearsal` and
unpinned `mpc-1` keys, so the step-7 tests can run before the pins exist.

Only accepting keys needs the feature. Generating development keys
(`compact::setup`) and the fixtures (feature `dev-fixtures`) do not. Never
enable `dev-setup` on a dependency of a production binary: Cargo unifies
features across the packages of one build.

`cargo run --release -p zkapi-proof --bin release_policy_check` runs in CI in
its own job (`release-key-policy`). It fails unless all of these hold:
- the library, built as production binaries see it, refuses the committed
  development setup and development keys relabelled `rehearsal` or `mpc-1`;
- no production build gives `zkapi-proof` the `dev-setup` feature. It
  resolves the features (with `cargo tree`, without compiling) of the
  packages that `docker/Dockerfile` builds together in the root workspace,
  and of the WebAssembly client that `scripts/build-browser-client.sh`
  builds. It reads both package lists from those files;
- this directory agrees with the pins: no keys while `CEREMONY_VK_KECCAK256`
  is `None`, and once it is set, all ten keys load with each loader of a
  release build, with a `manifest.json` naming the pinned VK hashes.

Every key file names its circuit, setup and kind. So a request key cannot be
loaded as a withdrawal key, nor a 4-note insertion key as a 16-note one, and
a key of another circuit (including the previous revision
`zkapi-v2-concession-v1` and `zkapi-v2-note-bound-v1`) is refused before
decoding.
