#!/usr/bin/env python3
"""Offline preparation regressions: prepare-zkapi.sh checks out exactly the
pinned commit of this repository, verify-zkapi-source.py refuses anything else,
and test-companion.sh tests the companion crates of both workspaces."""
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


SCRIPTS = Path(__file__).resolve().parent
PUBLIC_REPOSITORY = "https://github.com/ethereum/zkapi.git"
COMPANION_FILES = ("Cargo.toml", "Cargo.lock", "crates/zkapi-companion/Cargo.toml",
                   "crates/zkapi-auth/Cargo.toml", "protocol/rust/Cargo.lock",
                   "protocol/rust/crates/zkapi-client/Cargo.toml")


class Fixture:
    """A fixture repository with a commit holding the companion, a later tip,
    and a copy of this repository's packaging scripts pinned to that commit."""

    def __init__(self, root, local_checkout=False, pin=None):
        self.root = root
        root.mkdir(parents=True, exist_ok=True)
        self.global_config = root / "gitconfig"
        self.environment = dict(os.environ, GIT_CONFIG_GLOBAL=str(self.global_config),
                                GIT_CONFIG_NOSYSTEM="1", GIT_AUTHOR_NAME="Fixture",
                                GIT_AUTHOR_EMAIL="fixture@example.invalid",
                                GIT_COMMITTER_NAME="Fixture", GIT_COMMITTER_EMAIL="fixture@example.invalid")
        self.environment.pop("ZKAPI_SOURCE_REPOSITORY", None)

        upstream = root / "zkapi-upstream"
        upstream.mkdir()
        self.git(upstream, "init", "-q")
        (upstream / "unchanged.txt").write_text("unchanged\n")
        self.git(upstream, "add", ".")
        self.git(upstream, "commit", "-qm", "before the companion")
        self.without_companion = self.git(upstream, "rev-parse", "HEAD")
        for name in COMPANION_FILES:
            (upstream / name).parent.mkdir(parents=True, exist_ok=True)
            (upstream / name).write_text(f"pinned {name}\n")
        self.git(upstream, "add", ".")
        self.git(upstream, "commit", "-qm", "the companion")
        self.commit = self.git(upstream, "rev-parse", "HEAD")
        (upstream / "Cargo.toml").write_text("a later change\n")
        self.git(upstream, "commit", "-qam", "after the pin")
        self.tip = self.git(upstream, "rev-parse", "HEAD")

        if local_checkout:
            # This checkout holds the pinned commit; the public URL is broken.
            self.checkout = root / "checkout"
            self.git(root, "clone", "-q", str(upstream), str(self.checkout))
            public = root / "missing-repository"
        else:
            # A checkout without Git history (for example a release tarball).
            self.checkout = root / "tarball"
            self.checkout.mkdir()
            public = upstream
        self.global_config.write_text(
            '[protocol "file"]\n\tallow = always\n'
            f'[url "{public.as_uri()}"]\n\tinsteadOf = {PUBLIC_REPOSITORY}\n')
        self.scripts = self.checkout / "zkapi-clientd/scripts"
        self.scripts.mkdir(parents=True)
        packaging = self.checkout / "zkapi-clientd/packaging"
        packaging.mkdir()
        for name in ("prepare-zkapi.sh", "verify-zkapi-source.py", "test-companion.sh"):
            shutil.copy2(SCRIPTS / name, self.scripts / name)
        (packaging / "zkapi-source.env").write_text(f"ZKAPI_SOURCE_COMMIT={pin or self.commit}\n")
        self.prepared = root / "prepared"
        self.preparation = self.prepare(self.prepared)

    def prepare(self, destination, environment=None):
        return subprocess.run(["bash", str(self.scripts / "prepare-zkapi.sh"), str(destination)],
                              env=environment or self.environment, text=True, capture_output=True, timeout=60)

    def verify(self, source, commit):
        return subprocess.run(["python3", str(self.scripts / "verify-zkapi-source.py"), str(source), commit],
                              env=self.environment, text=True, capture_output=True, timeout=60)

    def git(self, path, *args):
        return subprocess.check_output(["git", "-C", str(path), *args],
                                       env=self.environment, stderr=subprocess.PIPE).decode().strip()


class PreparationTests(unittest.TestCase):
    def test_prepares_exactly_the_pinned_commit_and_refuses_any_change(self):
        with tempfile.TemporaryDirectory(prefix="zkapi-prepare-test-") as directory:
            fixture = Fixture(Path(directory))
            result = fixture.preparation
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("Verified the exact pinned companion source", result.stdout)
            prepared, git = fixture.prepared, fixture.git
            # The pinned commit, not the repository's later tip.
            self.assertEqual(git(prepared, "rev-parse", "HEAD"), fixture.commit)
            self.assertNotEqual(fixture.commit, fixture.tip)
            self.assertEqual((prepared / "Cargo.toml").read_text(), "pinned Cargo.toml\n")
            self.assertEqual(git(prepared, "status", "--porcelain", "--untracked-files=all"), "")

            # The destination must be new.
            again = fixture.prepare(prepared)
            self.assertNotEqual(again.returncode, 0)
            self.assertIn("Destination already exists", again.stderr)

            self.assertEqual(fixture.verify(prepared, fixture.commit).returncode, 0)
            for commit in (fixture.tip, fixture.commit[:12], fixture.commit.upper()):
                refused = fixture.verify(prepared, commit)
                self.assertNotEqual(refused.returncode, 0, commit)
            for mutation in ("untracked", "modified", "staged", "deleted"):
                target = prepared / ("unexpected.rs" if mutation == "untracked" else "crates/zkapi-companion/Cargo.toml")
                if mutation == "deleted":
                    target.unlink()
                else:
                    target.write_text("unexpected source\n")
                if mutation == "staged":
                    git(prepared, "add", str(target))
                refused = fixture.verify(prepared, fixture.commit)
                self.assertNotEqual(refused.returncode, 0, mutation)
                self.assertIn("differs from the pinned commit", refused.stderr, mutation)
                git(prepared, "reset", "-q", "--hard")
                (prepared / "unexpected.rs").unlink(missing_ok=True)
            self.assertEqual(fixture.verify(prepared, fixture.commit).returncode, 0)
            # A subdirectory of the checkout is not the checkout.
            refused = fixture.verify(prepared / "crates", fixture.commit)
            self.assertNotEqual(refused.returncode, 0)

    def test_a_checkout_holding_the_pinned_commit_needs_no_network(self):
        with tempfile.TemporaryDirectory(prefix="zkapi-prepare-local-test-") as directory:
            fixture = Fixture(Path(directory), local_checkout=True)
            result = fixture.preparation
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(fixture.git(fixture.prepared, "rev-parse", "HEAD"), fixture.commit)
            # A commit the checkout does not hold comes from the public
            # repository, which this fixture breaks.
            (fixture.checkout / "zkapi-clientd/packaging/zkapi-source.env").write_text(
                f"ZKAPI_SOURCE_COMMIT={'0' * 40}\n")
            missing = fixture.prepare(Path(directory) / "missing")
            self.assertNotEqual(missing.returncode, 0)

    def test_the_pin_is_a_full_hash_of_a_commit_holding_the_companion(self):
        with tempfile.TemporaryDirectory(prefix="zkapi-prepare-pin-test-") as directory:
            root = Path(directory)
            short = Fixture(root / "short", pin="abc123")
            self.assertNotEqual(short.preparation.returncode, 0)
            self.assertIn("full 40-character", short.preparation.stderr)
            self.assertFalse(short.prepared.exists())
            old = Fixture(root / "old")
            old_pin = old.without_companion
            (old.checkout / "zkapi-clientd/packaging/zkapi-source.env").write_text(f"ZKAPI_SOURCE_COMMIT={old_pin}\n")
            refused = old.prepare(root / "old-prepared")
            self.assertNotEqual(refused.returncode, 0)
            self.assertIn("does not hold the wallet companion", refused.stderr)

    def test_companion_tests_run_in_both_workspaces(self):
        # The root workspace excludes protocol/rust, so testing only the root
        # crates would never run zkapi-client's tests.
        with tempfile.TemporaryDirectory(prefix="zkapi-companion-test-") as directory:
            root = Path(directory)
            fixture = Fixture(root)
            self.assertEqual(fixture.preparation.returncode, 0,
                             fixture.preparation.stdout + fixture.preparation.stderr)

            # A stand-in cargo records where and how it runs, and fails in one
            # chosen directory.
            bin_dir = root / "bin"
            bin_dir.mkdir()
            log = root / "cargo.log"
            fake_cargo = bin_dir / "cargo"
            fake_cargo.write_text('#!/bin/sh\nprintf \'%s\\t%s\\n\' "$(pwd -P)" "$*" >> "$FAKE_CARGO_LOG"\n'
                                  'printf \'%s\\n\' "${ZKAPI_REQUIRE_ANVIL:-unset}" >> "$FAKE_CARGO_LOG.anvil"\n'
                                  'test "$(pwd -P)" != "$FAKE_CARGO_FAIL_IN"\n')
            fake_cargo.chmod(0o755)
            prepared = Path(os.path.realpath(fixture.prepared))
            protocol_rust = prepared / "protocol/rust"

            # PATH without Foundry: the fixture's stand-in cargo, git and the
            # system tools only.
            system_path = os.pathsep.join(
                directory for directory in os.environ["PATH"].split(os.pathsep)
                if not (Path(directory) / "forge").exists() and not (Path(directory) / "anvil").exists())

            def run_tests(fail_in="", extra_path=None):
                for stale in (log, Path(f"{log}.anvil")):
                    if stale.exists():
                        stale.unlink()
                path = os.pathsep.join(filter(None, [str(bin_dir), extra_path, system_path]))
                environment = dict(fixture.environment, PATH=path,
                                   FAKE_CARGO_LOG=str(log), FAKE_CARGO_FAIL_IN=fail_in)
                environment.pop("ZKAPI_REQUIRE_ANVIL", None)
                result = subprocess.run(["bash", str(fixture.scripts / "test-companion.sh"), str(fixture.prepared)],
                                        env=environment, text=True, capture_output=True, timeout=60)
                calls = [tuple(line.split("\t")) for line in log.read_text().splitlines()] if log.exists() else []
                return result, calls

            result, calls = run_tests()
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(calls, [
                (str(prepared), "test --release --locked -p zkapi-companion -p zkapi-auth"),
                (str(protocol_rust), "test --release --locked -p zkapi-client"),
            ])
            self.assertIn("Tested zkapi-companion, zkapi-auth and zkapi-client", result.stdout)
            self.assertIn("the Anvil adapter test is skipped", result.stdout)
            self.assertEqual(Path(f"{log}.anvil").read_text().split(), ["unset", "unset"])

            # With Foundry on PATH the Anvil adapter test is required.
            foundry = root / "foundry"
            foundry.mkdir()
            for name in ("forge", "anvil"):
                (foundry / name).write_text("#!/bin/sh\nexit 0\n")
                (foundry / name).chmod(0o755)
            result, calls = run_tests(extra_path=str(foundry))
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("the Anvil adapter test is required", result.stdout)
            self.assertEqual(Path(f"{log}.anvil").read_text().split()[0], "1")

            # A failing protocol crate test fails the run.
            result, calls = run_tests(fail_in=str(protocol_rust))
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(len(calls), 2)

            # A failing companion crate test fails the run before the protocol crates.
            result, calls = run_tests(fail_in=str(prepared))
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertEqual(len(calls), 1)

            # A tree that is not exactly the pinned commit is refused before
            # anything is tested.
            (fixture.prepared / "protocol/rust/crates/zkapi-client/Cargo.toml").write_text("changed\n")
            result, calls = run_tests()
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("differs from the pinned commit", result.stderr)
            self.assertEqual(calls, [])


if __name__ == "__main__":
    unittest.main(verbosity=2)
