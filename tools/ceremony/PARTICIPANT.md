# ZK API ceremony: your contribution

This package is for **your assigned turn**. Wait for the coordinator to send
it; another participant's package may be stale. The command contributes to
both the request and withdrawal circuits and creates one Git bundle to return.

You need Node.js **24 or newer**, npm (included with Node), Git, an internet
connection for the pinned npm dependencies, and enough disk space for several
copies of this package. You do not need Rust, a wallet, ETH, a GitHub account,
or repository write access. macOS/Linux and Windows launchers are provided;
platform validation must be completed by the coordinator before distribution.

1. Check the package archive's SHA-256 against the value the coordinator sent
   through your agreed channel. Review the scripts before running them. A
   checksum inside the same download alone does not authenticate that download.
2. Extract into a new directory. Open a terminal in that directory.
3. On macOS/Linux run:

   ```sh
   sh ./contribute.sh
   ```

   On Windows, in PowerShell:

   ```powershell
   .\contribute.cmd
   ```

   Both commands install the exact locked dependencies with package lifecycle
   scripts disabled, then start the contribution. They do not auto-upload.

4. Name and email are optional. **Press Enter twice for anonymous attribution.**
   Either field can be supplied alone. Supplied fields will be public in the
   Git commit and receipt. To skip both prompts, append `--anonymous`.
5. Wait for verification and both contributions to finish. Return
   `submission/contribution.bundle` and `submission/contribution.bundle.sha256`
   to the coordinator. Keep `submission/receipt.json` as your public receipt.
   The coordinator verifies independently before accepting your contribution.

If the coordinator supplied an assignment hash, append
`--assignment-sha256 THE_HASH` to the launcher command. To verify the circuits
against an export you made yourself at the frozen source commit, append
`--r1cs-dir /path/to/your/export`. Independently obtaining the public powers of
tau and reproducing the circuit export is required for external reviewers;
see the operator README in the source repository.

## Anonymous attribution

Empty fields stay null in the receipt. Missing Git fields use `Anonymous` and
`anonymous@participants.invalid`; the tool explicitly sets both author and
committer and ignores your Git identity/configuration environment. All commits
use a fixed UTC timestamp. The zkey name is `Anonymous` when no name is supplied.
No hostname, home directory or real timestamp is added to the receipt.

This omits identity from the artifact; it does not hide who sent an email,
uploaded a file, downloaded npm dependencies, or was nominated by a reviewer.
Use your agreed return channel accordingly. Git attribution is not an identity
signature, and the receipt is not proof that secret randomness was destroyed.

## Randomness and interrupted runs

Secret randomness is generated in a fresh local process for each circuit. It
is not derived from your name/email and never goes into Git, arguments, receipts
or logs. Only public outputs are returned. JavaScript/library memory copies,
OS swap and crash dumps prevent a promise of secure memory erasure; avoid
debuggers, process dumps and recording tools during your contribution.

On an ordinary failure, incomplete output is removed. After a hard power loss
or forced termination, a `submission.partial-*` directory may remain. Do not
send partial files. Keep or remove that directory after inspecting it, then
rerun from the same assignment if it is still current. Existing `submission/`
directories are never overwritten; rename one before rerunning. A stale
contribution cannot be rebased: obtain a new assignment and contribute again.
