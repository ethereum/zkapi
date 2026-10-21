//! Check the key policy of release builds:
//!
//! ```text
//! cargo run --release --manifest-path protocol/rust/Cargo.toml -p zkapi-proof --bin release_policy_check
//! ```
//!
//! CI runs it in its own job (`release-key-policy`), so that no failing step
//! of another job skips it.
//!
//! 1. **This build.** `cargo test` cannot check the policy of a release
//!    build: this crate's tests and examples enable the `dev-setup` feature
//!    through its self dev-dependency, and Cargo unifies features across one
//!    build. A binary built on its own (`cargo run -p zkapi-proof --bin ...`)
//!    activates no dev-dependency, so it sees the library as a production
//!    binary that does not enable `dev-setup` does. The check fails unless
//!    the build accepts only `mpc-1`, and refuses the committed development
//!    setup with every loader and development keys relabelled `rehearsal` or
//!    `mpc-1`.
//! 2. **The production builds.** A production binary gets `dev-setup` when
//!    any package of its build enables the feature on its normal dependency
//!    on `zkapi-proof`, and building this crate alone cannot see that. So
//!    the check resolves the features of each production build with
//!    `cargo tree`: the packages that `docker/Dockerfile` builds together in
//!    the root workspace, the companion (`zkapi-walletd`) that
//!    `zkapi-clientd/scripts/build-native.sh` builds for every clientd
//!    release, and the WebAssembly client that
//!    `scripts/build-browser-client.sh` builds. It reads the package lists
//!    from those files, and fails if `zkapi-proof` has `dev-setup` in any of
//!    these builds. `cargo tree` resolves without compiling, so this works
//!    while the root crates do not build. It may refresh a stale root
//!    `Cargo.lock`.
//!
//!    Each of these builds may still be built for a single-party vault (one
//!    deployed with `Deploy.s.sol`'s `ALLOW_DEV_SETUP=1`, which trusts its
//!    setup's generator not to forge proofs) by asking on its command line:
//!    `ALLOW_DEV_SETUP=1` for `docker/Dockerfile` and `build-native.sh`,
//!    `--setup dev` for `build-browser-client.sh`. The check resolves each
//!    build without that opt-in, so what it guards is that no build accepts
//!    development keys unless it was asked to.
//! 3. **The ceremony setup.** `protocol/setup/v2-concession` must agree with
//!    the pins. While `CEREMONY_VK_KECCAK256` is `None`, the directory holds
//!    no keys (committed keys would be refused by every release build). Once
//!    the pins are set, each of its keys loads under the release policy.
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{anyhow, bail, ensure, Context, Result};
use ark_bn254::Bn254;
use ark_groth16::{ProvingKey, VerifyingKey};
use zkapi_proof::compact::{
    accepted_setup_ids, decode_compressed_for, dev_setup_build, hex32, key_header, setup,
    strip_key_header, KeyKind, RequestProver, RequestVerifier, SetupManifest, VkPins,
    WithdrawalProver, WithdrawalVerifier, CEREMONY_SETUP_ID, CEREMONY_VK_KECCAK256,
    REHEARSAL_SETUP_ID, RELEASE_SETUP_IDS, SETUP_MANIFEST_FILE,
};

/// The feature a production build must not give `zkapi-proof`.
const DEV_SETUP_FEATURE: &str = "dev-setup";

/// One production build of `zkapi-proof`, paths relative to the repository
/// root.
struct ProductionBuild {
    /// The workspace the build runs in.
    manifest: &'static str,
    /// The script that holds the build's `cargo build -p ...` command.
    script: &'static str,
    /// The `cargo tree --target` to resolve for (`None`: the host).
    target: Option<&'static str>,
}

const PRODUCTION_BUILDS: &[ProductionBuild] = &[
    // The operator image: API server, indexer, challenger and CLI, on
    // whatever platform it is built for.
    ProductionBuild {
        manifest: "Cargo.toml",
        script: "docker/Dockerfile",
        target: Some("all"),
    },
    // The WebAssembly client the SDK ships.
    ProductionBuild {
        manifest: "protocol/rust/Cargo.toml",
        script: "scripts/build-browser-client.sh",
        target: Some("wasm32-unknown-unknown"),
    },
    // The companion every zkapi-clientd release bundles (zkapi-walletd),
    // which loads the proving keys of each clientd escape and close. The
    // release builds it in the root workspace of a prepared tree.
    ProductionBuild {
        manifest: "Cargo.toml",
        script: "zkapi-clientd/scripts/build-native.sh",
        target: Some("all"),
    },
];

fn refused<T>(what: &str, result: Result<T>, expected: &str) -> Result<()> {
    match result {
        Ok(_) => bail!("a release build loaded {what}"),
        Err(error) => {
            let message = format!("{error:#}");
            ensure!(
                message.contains(expected),
                "{what} was refused for another reason: {message}"
            );
            Ok(())
        }
    }
}

fn relabel(file: &[u8], setup_id: &str, kind: KeyKind) -> Result<Vec<u8>> {
    let (_, payload) = strip_key_header(file, kind)?;
    let mut bytes = key_header(setup_id, kind)?;
    bytes.extend_from_slice(payload);
    Ok(bytes)
}

/// The packages of every `cargo build` command in a Dockerfile or shell
/// script (its `-p` / `--package` arguments; backslash-continued lines are
/// joined).
fn cargo_build_packages(script: &str) -> Vec<String> {
    let joined = script.replace("\\\n", " ");
    let mut packages = Vec::new();
    for line in joined.lines().filter(|line| line.contains("cargo build")) {
        let mut words = line.split_whitespace();
        while let Some(word) = words.next() {
            if let Some(name) = word.strip_prefix("--package=") {
                packages.push(name.to_string());
            } else if word == "-p" || word == "--package" {
                packages.extend(words.next().map(str::to_string));
            }
        }
    }
    packages
}

fn cargo() -> OsString {
    std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into())
}

fn run(command: &mut Command) -> Result<String> {
    let output = command
        .output()
        .with_context(|| format!("run {command:?}"))?;
    ensure!(
        output.status.success(),
        "{command:?} failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).context("cargo output is not UTF-8")
}

/// The features `zkapi-proof` has when `packages` of the workspace at
/// `manifest` are built together (normal dependencies only: a
/// dev-dependency does not reach a binary), for `target` (`None`: the
/// host). Fails if a package is not a member of that workspace, or if none
/// of them depends on `zkapi-proof`.
fn proof_features(
    manifest: &Path,
    packages: &[String],
    target: Option<&str>,
) -> Result<Vec<String>> {
    ensure!(!packages.is_empty(), "no packages to check");
    let metadata: serde_json::Value = serde_json::from_str(&run(Command::new(cargo())
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-deps",
            "--manifest-path",
        ])
        .arg(manifest))?)
    .context("parse cargo metadata")?;
    let members: Vec<&str> = metadata["packages"]
        .as_array()
        .ok_or_else(|| anyhow!("cargo metadata lists no packages"))?
        .iter()
        .filter_map(|package| package["name"].as_str())
        .collect();
    for package in packages {
        ensure!(
            members.contains(&package.as_str()),
            "{package} is not a package of {} (members: {members:?})",
            manifest.display()
        );
    }
    let mut command = Command::new(cargo());
    command
        .args(["tree", "--manifest-path"])
        .arg(manifest)
        .args([
            "--edges",
            "normal",
            "--invert",
            "zkapi-proof",
            "--depth",
            "0",
        ])
        .args(["--prefix", "none", "--format", "{p}|{f}"]);
    if let Some(target) = target {
        command.args(["--target", target]);
    }
    for package in packages {
        command.args(["--package", package]);
    }
    let tree = run(&mut command)?;
    let lines: Vec<&str> = tree
        .lines()
        .filter(|line| line.starts_with("zkapi-proof "))
        .collect();
    ensure!(
        !lines.is_empty(),
        "none of {packages:?} depends on zkapi-proof:\n{tree}"
    );
    let mut features: Vec<String> = lines
        .iter()
        .filter_map(|line| line.split_once('|'))
        .flat_map(|(_, features)| features.split(','))
        .filter(|feature| !feature.is_empty())
        .map(str::to_string)
        .collect();
    features.sort();
    features.dedup();
    Ok(features)
}

/// Check each production build of `builds`, paths relative to `repository`:
/// `zkapi-proof` without `dev-setup` unless the build asks for it on its
/// command line (which `cargo tree` does not see).
fn check_production_builds(repository: &Path, builds: &[ProductionBuild]) -> Result<()> {
    for build in builds {
        let script_path = repository.join(build.script);
        let script = std::fs::read_to_string(&script_path)
            .with_context(|| format!("read {}", script_path.display()))?;
        let packages = cargo_build_packages(&script);
        ensure!(
            !packages.is_empty(),
            "{} has no `cargo build -p ...` command: update PRODUCTION_BUILDS",
            build.script
        );
        let features = proof_features(&repository.join(build.manifest), &packages, build.target)
            .with_context(|| format!("resolve the features of {}'s build", build.script))?;
        ensure!(
            !features.iter().any(|feature| feature == DEV_SETUP_FEATURE),
            "the production build of {} ({packages:?} in {}) gives zkapi-proof the features \
             {features:?}: a package of that build enables {DEV_SETUP_FEATURE} on a normal \
             dependency, so the binaries would accept development keys without being asked \
             to (a single-party build asks on its command line: ALLOW_DEV_SETUP=1 or \
             --setup dev)",
            build.script,
            build.manifest
        );
        println!(
            "{}: {packages:?} build zkapi-proof with features {features:?}",
            build.script
        );
    }
    Ok(())
}

/// Read a key file of the ceremony directory under the release policy with
/// `pins`, and require it to be an `mpc-1` key.
fn load_release_key<T: zkapi_proof::compact::SetupKey>(
    directory: &Path,
    file: &str,
    kind: KeyKind,
    pins: &VkPins,
) -> Result<T> {
    let path = directory.join(file);
    let bytes = std::fs::read(&path).with_context(|| format!("read {}", path.display()))?;
    let (key, setup_id) = decode_compressed_for::<T>(&bytes, kind, false, Some(pins))
        .with_context(|| format!("load {} under the release policy", path.display()))?;
    ensure!(
        setup_id == CEREMONY_SETUP_ID,
        "{} is a {setup_id} key",
        path.display()
    );
    Ok(key)
}

/// The ceremony setup directory agrees with `pins`: without pins it holds no
/// keys and no manifest; with pins its four keys load under the release
/// policy, each proving key holds its verifying key, and `manifest.json`
/// names the same keys.
fn check_ceremony_directory(directory: &Path, pins: Option<&VkPins>) -> Result<()> {
    let kinds = [KeyKind::Request, KeyKind::Withdrawal];
    let Some(pins) = pins else {
        for file in kinds
            .iter()
            .flat_map(|kind| [kind.proving_key_file(), kind.verifying_key_file()])
            .chain([SETUP_MANIFEST_FILE])
        {
            ensure!(
                !directory.join(file).exists(),
                "{} holds {file}, but CEREMONY_VK_KECCAK256 pins no ceremony keys, so every \
                 release build refuses them: set the pins in the same change (README step 7)",
                directory.display()
            );
        }
        return Ok(());
    };
    for kind in kinds {
        let pk: ProvingKey<Bn254> =
            load_release_key(directory, kind.proving_key_file(), kind, pins)?;
        let vk: VerifyingKey<Bn254> =
            load_release_key(directory, kind.verifying_key_file(), kind, pins)?;
        ensure!(
            pk.vk == vk,
            "the {kind} proving key of {} does not hold its verifying key",
            directory.display()
        );
    }
    let path = directory.join(SETUP_MANIFEST_FILE);
    let manifest: SetupManifest = serde_json::from_slice(
        &std::fs::read(&path).with_context(|| format!("read {}", path.display()))?,
    )
    .with_context(|| format!("parse {}", path.display()))?;
    ensure!(
        manifest.setup_id == CEREMONY_SETUP_ID,
        "{} names setup {}",
        path.display(),
        manifest.setup_id
    );
    for kind in kinds {
        ensure!(
            manifest.vk_keccak256.get(kind) == hex32(pins.get(kind)),
            "{} names the {kind} verifying key {}, the pin is {}",
            path.display(),
            manifest.vk_keccak256.get(kind),
            hex32(pins.get(kind))
        );
    }
    Ok(())
}

fn main() -> Result<()> {
    ensure!(
        !dev_setup_build() && accepted_setup_ids() == RELEASE_SETUP_IDS,
        "this build has the dev-setup feature (it accepts {:?}); run this check on its own: \
         cargo run -p zkapi-proof --bin release_policy_check",
        accepted_setup_ids()
    );
    // Key generation needs no feature (`zkapi setup` links it into the CLI).
    let _generate: fn(&Path) -> Result<()> = |directory| setup(directory);

    let crate_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let setup_root = crate_dir.join("../../../setup");
    let dev = setup_root.join("v2-concession-dev");
    refused(
        "the development request proving key",
        RequestProver::load(&dev),
        "not accepted",
    )?;
    refused(
        "the development request verifying key",
        RequestVerifier::load(&dev),
        "not accepted",
    )?;
    refused(
        "the development withdrawal proving key",
        WithdrawalProver::load(&dev),
        "not accepted",
    )?;
    refused(
        "the development withdrawal verifying key",
        WithdrawalVerifier::load(&dev),
        "not accepted",
    )?;

    let request_vk = std::fs::read(dev.join("request.vk"))?;
    refused(
        "a development key labelled rehearsal",
        RequestVerifier::from_bytes(&relabel(&request_vk, REHEARSAL_SETUP_ID, KeyKind::Request)?),
        "not accepted",
    )?;
    let expected = if CEREMONY_VK_KECCAK256.is_some() {
        "not the pinned ceremony key"
    } else {
        "no mpc-1 verifying keys are pinned"
    };
    refused(
        "a development key labelled mpc-1",
        RequestVerifier::from_bytes(&relabel(&request_vk, CEREMONY_SETUP_ID, KeyKind::Request)?),
        expected,
    )?;

    let ceremony: PathBuf = setup_root.join("v2-concession");
    check_ceremony_directory(&ceremony, CEREMONY_VK_KECCAK256.as_ref())?;
    if CEREMONY_VK_KECCAK256.is_some() {
        // The loaders of this build, as the daemons and clients call them.
        RequestProver::load(&ceremony)?;
        RequestVerifier::load(&ceremony)?;
        WithdrawalProver::load(&ceremony)?;
        WithdrawalVerifier::load(&ceremony)?;
    }

    check_production_builds(&crate_dir.join("../../../.."), PRODUCTION_BUILDS)?;
    println!(
        "release policy ok: accepts {RELEASE_SETUP_IDS:?} with pinned verifying keys ({}); \
         refuses the development setup and relabelled development keys; no production build \
         enables {DEV_SETUP_FEATURE} unless asked (ALLOW_DEV_SETUP=1 or --setup dev)",
        if CEREMONY_VK_KECCAK256.is_some() {
            "the ceremony setup loads"
        } else {
            "none pinned yet, and the ceremony setup holds no keys"
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use zkapi_proof::compact::{
        decode_compressed, write_setup_directory, SetupProvenance, REQUEST_VERIFYING_KEY_FILE,
        WITHDRAWAL_PROVING_KEY_FILE,
    };

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "zkapi-release-policy-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn dev_setup() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../setup/v2-concession-dev")
    }

    #[test]
    fn build_commands_name_their_packages() {
        assert_eq!(
            cargo_build_packages(
                "COPY . .\nRUN cargo build --locked --release -p zkapi-cli -p zkapi-indexerd \
                 --package zkapi-serverd --bins\nRUN cargo test -p other\n"
            ),
            ["zkapi-cli", "zkapi-indexerd", "zkapi-serverd"]
        );
        assert_eq!(
            cargo_build_packages(
                "cargo build \\\n  --manifest-path \"$x/Cargo.toml\" \\\n  -p zkapi-browser \\\n  \
                 --target wasm32-unknown-unknown\n"
            ),
            ["zkapi-browser"]
        );
        assert_eq!(cargo_build_packages("cargo build --package=a"), ["a"]);
        assert!(cargo_build_packages("cargo test -p a").is_empty());
        // The repository's own production builds name at least the packages
        // that depend on zkapi-proof today.
        let repository = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../../..");
        assert_eq!(PRODUCTION_BUILDS.len(), 3);
        for (build, expected) in PRODUCTION_BUILDS.iter().zip([
            &["zkapi-cli", "zkapi-serverd"][..],
            &["zkapi-browser"][..],
            &["zkapi-companion"][..],
        ]) {
            let script = std::fs::read_to_string(repository.join(build.script)).unwrap();
            let packages = cargo_build_packages(&script);
            for package in expected {
                assert!(
                    packages.iter().any(|name| name == package),
                    "{}: {packages:?}",
                    build.script
                );
            }
        }
    }

    /// The feature check sees what Cargo unifies into a build: a sibling
    /// package that enables `dev-setup` on its normal dependency, but not a
    /// dev-dependency that does.
    #[test]
    fn the_feature_check_sees_dev_setup_enabled_by_any_package_of_the_build() {
        let dir = scratch("features");
        let proof = Path::new(env!("CARGO_MANIFEST_DIR"));
        std::fs::write(
            dir.join("Cargo.toml"),
            "[workspace]\nresolver = \"2\"\nmembers = [\"daemon\", \"helper\", \"tests-only\"]\n",
        )
        .unwrap();
        // The lock file of the protocol workspace pins every registry crate.
        std::fs::copy(proof.join("../../Cargo.lock"), dir.join("Cargo.lock")).unwrap();
        for (name, dependencies) in [
            ("daemon", format!("zkapi-proof = {{ path = {proof:?} }}")),
            (
                "helper",
                format!("zkapi-proof = {{ path = {proof:?}, features = [\"dev-setup\"] }}"),
            ),
            (
                "tests-only",
                format!(
                    "zkapi-proof = {{ path = {proof:?} }}\n[dev-dependencies]\n\
                     zkapi-proof = {{ path = {proof:?}, features = [\"dev-setup\"] }}"
                ),
            ),
        ] {
            std::fs::create_dir_all(dir.join(name).join("src")).unwrap();
            std::fs::write(dir.join(name).join("src/main.rs"), "fn main() {}\n").unwrap();
            std::fs::write(
                dir.join(name).join("Cargo.toml"),
                format!(
                    "[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\
                     [dependencies]\n{dependencies}\n"
                ),
            )
            .unwrap();
        }
        let manifest = dir.join("Cargo.toml");
        let features = |packages: &[&str]| {
            let packages: Vec<String> = packages.iter().map(|p| p.to_string()).collect();
            proof_features(&manifest, &packages, None).map_err(|error| format!("{error:#}"))
        };
        assert_eq!(features(&["daemon"]).unwrap(), Vec::<String>::new());
        assert_eq!(features(&["tests-only"]).unwrap(), Vec::<String>::new());
        assert_eq!(
            features(&["daemon", "helper"]).unwrap(),
            [DEV_SETUP_FEATURE]
        );
        assert_eq!(
            features(&["daemon", "tests-only"]).unwrap(),
            Vec::<String>::new()
        );
        // A renamed package is an error, not a silently wider check.
        let error = features(&["daemon", "renamed"]).unwrap_err();
        assert!(error.contains("renamed is not a package"), "{error}");

        // The whole check, on a build script of this workspace.
        let check = |script: &str| {
            std::fs::write(dir.join("build.sh"), script).unwrap();
            check_production_builds(
                &dir,
                &[ProductionBuild {
                    manifest: "Cargo.toml",
                    script: "build.sh",
                    target: None,
                }],
            )
            .map_err(|error| format!("{error:#}"))
        };
        check("cargo build --release -p daemon -p tests-only --bins\n").unwrap();
        let error = check("cargo build --release \\\n  -p daemon \\\n  -p helper\n").unwrap_err();
        assert!(
            error.contains("gives zkapi-proof the features [\"dev-setup\"]"),
            "{error}"
        );
        // A build of one binary of a package, as zkapi-clientd's release
        // builds the companion.
        let error = check("cargo build --release --locked -p helper --bin helper\n").unwrap_err();
        assert!(
            error.contains("gives zkapi-proof the features [\"dev-setup\"]"),
            "{error}"
        );
        check("cargo build --release --locked -p tests-only --bin tests-only\n").unwrap();
        let error = check("cargo test -p daemon\n").unwrap_err();
        assert!(error.contains("no `cargo build -p ...` command"), "{error}");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn an_unpinned_ceremony_directory_holds_no_keys() {
        let dir = scratch("unpinned");
        std::fs::write(dir.join("README.md"), "keys come later\n").unwrap();
        check_ceremony_directory(&dir, None).unwrap();
        for file in [REQUEST_VERIFYING_KEY_FILE, SETUP_MANIFEST_FILE] {
            std::fs::write(dir.join(file), b"x").unwrap();
            let error = format!("{:#}", check_ceremony_directory(&dir, None).unwrap_err());
            assert!(error.contains("pins no ceremony keys"), "{file}: {error}");
            std::fs::remove_file(dir.join(file)).unwrap();
        }
        let _ = std::fs::remove_dir_all(dir);
    }

    /// With pins, the directory's keys must load under the release policy:
    /// development keys written as an `mpc-1` setup load with their own
    /// hashes as pins, and are refused with any other pins or a missing key.
    #[test]
    fn a_pinned_ceremony_directory_loads_under_the_release_policy() {
        let dir = scratch("pinned").join("v2-concession");
        let key = |kind: KeyKind| -> ProvingKey<Bn254> {
            let bytes = std::fs::read(dev_setup().join(kind.proving_key_file())).unwrap();
            decode_compressed(&bytes, kind).unwrap().0
        };
        let manifest = write_setup_directory(
            &dir,
            CEREMONY_SETUP_ID,
            &key(KeyKind::Request),
            &key(KeyKind::Withdrawal),
            &SetupProvenance::default(),
        )
        .unwrap();
        let pin = |hex: &str| -> [u8; 32] {
            hex::decode(hex.trim_start_matches("0x"))
                .unwrap()
                .try_into()
                .unwrap()
        };
        let pins = VkPins {
            request: pin(&manifest.vk_keccak256.request),
            withdrawal: pin(&manifest.vk_keccak256.withdrawal),
        };
        check_ceremony_directory(&dir, Some(&pins)).unwrap();
        // Keys committed without pins.
        assert!(check_ceremony_directory(&dir, None).is_err());
        // Pins of other keys.
        let swapped = VkPins {
            request: pins.withdrawal,
            withdrawal: pins.request,
        };
        let error = format!(
            "{:#}",
            check_ceremony_directory(&dir, Some(&swapped)).unwrap_err()
        );
        assert!(error.contains("not the pinned ceremony key"), "{error}");
        // A missing key.
        std::fs::remove_file(dir.join(WITHDRAWAL_PROVING_KEY_FILE)).unwrap();
        let error = format!(
            "{:#}",
            check_ceremony_directory(&dir, Some(&pins)).unwrap_err()
        );
        assert!(error.contains(WITHDRAWAL_PROVING_KEY_FILE), "{error}");
        // The development setup itself, with its hashes as pins: refused,
        // because release builds accept only mpc-1.
        let error = format!(
            "{:#}",
            check_ceremony_directory(&dev_setup(), Some(&pins)).unwrap_err()
        );
        assert!(error.contains("not accepted"), "{error}");
        let _ = std::fs::remove_dir_all(dir.parent().unwrap());
    }
}
