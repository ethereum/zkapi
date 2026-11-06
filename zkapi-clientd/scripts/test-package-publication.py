#!/usr/bin/env python3
"""Offline publication regressions using release fixtures and local Git remotes."""

import importlib.util
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch


def load(name, filename):
    spec = importlib.util.spec_from_file_location(name, Path(__file__).with_name(filename))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


publication = load("publication", "publish-packages.py")
packages = load("packages", "test-packages.py")


class PublicationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = packages.PackageTests("test_generated_manifests_and_arch_payloads")
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.artifacts = self.fixture.artifacts
        self.version = self.fixture.version
        self.temp = tempfile.TemporaryDirectory(prefix="zkapi-publication-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def repository(self, platform):
        remote = self.root / (platform + ".git")
        checkout = self.root / platform
        branch = "master" if platform == "aur" else "main"
        publication.run("git", "init", "--bare", "-b", branch, remote)
        publication.run("git", "init", "-b", branch, checkout)
        publication.run("git", "-C", checkout, "remote", "add", "origin", remote)
        return remote, checkout

    def commit(self, checkout):
        publication.run("git", "-C", checkout, "add", ".")
        publication.run("git", "-C", checkout, "-c", "user.name=Test", "-c", "user.email=test@example.invalid",
                        "commit", "-m", "Fixture")

    def test_publish_all_platforms_and_retry_without_an_extra_commit(self):
        for platform in ("aur", "homebrew", "nix"):
            with self.subTest(platform=platform):
                remote, checkout = self.repository(platform)
                publication.publish(platform, self.artifacts, checkout)
                commit = publication.run("git", "-C", checkout, "rev-parse", "HEAD")
                self.assertEqual(publication.run("git", "--git-dir", remote, "rev-parse", "HEAD"), commit)
                self.assertEqual(publication.existing_version(platform, checkout), self.version)
                publication.publish(platform, self.artifacts, checkout)
                self.assertEqual(publication.run("git", "-C", checkout, "rev-parse", "HEAD"), commit)
                self.assertEqual(publication.run("git", "-C", checkout, "status", "--porcelain"), "")
                if platform == "aur":
                    self.assertTrue((checkout / ".SRCINFO").is_file())
                    self.assertTrue((checkout / "LICENSE").is_file())
                if platform == "nix":
                    self.assertTrue((checkout / "flake.nix").is_file())
                    self.assertFalse((checkout / "test-docker.sh").exists())

    def test_an_old_release_cannot_downgrade_any_platform(self):
        for platform, filename in (("aur", ".SRCINFO"), ("homebrew", "Formula/zkapi-clientd.rb"),
                                   ("nix", "package.nix")):
            with self.subTest(platform=platform):
                _, checkout = self.repository(platform)
                publication.publish(platform, self.artifacts, checkout)
                path = checkout / filename
                path.write_text(path.read_text().replace(self.version, "1.10.0"))
                self.commit(checkout)
                before = path.read_bytes()
                with self.assertRaisesRegex(ValueError, "Refusing to downgrade"):
                    publication.publish(platform, self.artifacts, checkout)
                self.assertEqual(path.read_bytes(), before)
                self.assertEqual(publication.run("git", "-C", checkout, "status", "--porcelain"), "")

    def test_same_version_cannot_be_silently_replaced(self):
        _, checkout = self.repository("homebrew")
        publication.publish("homebrew", self.artifacts, checkout)
        formula = checkout / "Formula/zkapi-clientd.rb"
        formula.write_text(formula.read_text() + "\n# different content\n")
        self.commit(checkout)
        with self.assertRaisesRegex(ValueError, "already published with different files"):
            publication.publish("homebrew", self.artifacts, checkout)

    def test_upgrade_preserves_other_packages_in_the_repository(self):
        _, checkout = self.repository("homebrew")
        publication.publish("homebrew", self.artifacts, checkout)
        formula = checkout / "Formula/zkapi-clientd.rb"
        formula.write_text(formula.read_text().replace(self.version, "1.2.2"))
        unrelated = checkout / "Formula/other.rb"
        unrelated.write_text("# A different package\n")
        self.commit(checkout)
        publication.publish("homebrew", self.artifacts, checkout)
        self.assertEqual(formula.read_bytes(), (self.artifacts / "homebrew/zkapi-clientd.rb").read_bytes())
        self.assertEqual(unrelated.read_text(), "# A different package\n")

    def test_retry_recovers_a_failed_push_after_the_local_commit(self):
        remote, checkout = self.repository("aur")
        real_run = publication.run

        def fail_push(*args, **kwargs):
            if "push" in args:
                raise subprocess.CalledProcessError(1, args)
            return real_run(*args, **kwargs)

        with patch.object(publication, "run", side_effect=fail_push):
            with self.assertRaises(subprocess.CalledProcessError):
                publication.publish("aur", self.artifacts, checkout)
        self.assertEqual(real_run("git", "ls-remote", remote), "")
        publication.publish("aur", self.artifacts, checkout)
        self.assertEqual(real_run("git", "--git-dir", remote, "rev-parse", "HEAD"),
                         real_run("git", "-C", checkout, "rev-parse", "HEAD"))

    def test_dry_run_stages_files_without_publishing(self):
        remote, checkout = self.repository("aur")
        publication.publish("aur", self.artifacts, checkout, dry_run=True)
        self.assertTrue((checkout / ".SRCINFO").is_file())
        self.assertEqual(publication.run("git", "ls-remote", remote), "")
        self.assertIn("A  PKGBUILD", publication.run("git", "-C", checkout, "status", "--porcelain"))

    def test_tampered_release_is_rejected_before_writing_repository(self):
        _, checkout = self.repository("aur")
        archive = self.artifacts / f"zkapi-clientd_{self.version}_linux_arm64.tar.gz"
        archive.write_bytes(archive.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "SHA256SUMS mismatch"):
            publication.publish("aur", self.artifacts, checkout)
        self.assertEqual(list(checkout.iterdir()), [checkout / ".git"])

    def download(self, *, draft=False, bad_digest=False):
        assets = [{"name": path.name, "digest": "sha256:" + packages.sha256(path)}
                  for path in self.artifacts.iterdir() if path.is_file()]
        if bad_digest:
            next(asset for asset in assets if asset["name"] == "SHA256SUMS")["digest"] = "sha256:" + "0" * 64
        release = {"tag_name": f"clientd-v{self.version}", "draft": draft,
                   "published_at": None if draft else "2026-10-01T00:00:00Z", "assets": assets}

        def gh(*args):
            if args[:2] == ("gh", "api"):
                return json.dumps(release)
            self.assertEqual(args[:3], ("gh", "release", "download"))
            directory = Path(args[args.index("--dir") + 1])
            for index, argument in enumerate(args):
                if argument == "--pattern":
                    shutil.copyfile(self.artifacts / args[index + 1], directory / args[index + 1])
            return ""

        return gh

    def test_prepare_verifies_exact_published_release_including_hidden_metadata(self):
        destination = self.root / "prepared"
        with patch.object(publication, "run", side_effect=self.download()):
            publication.prepare(f"clientd-v{self.version}", destination)
        self.assertEqual(packages.verify_artifacts(destination), self.version)
        record = json.loads((destination / "release.json").read_text())
        self.assertEqual(record["tag"], f"clientd-v{self.version}")
        self.assertEqual(len(record["artifacts"]), 4)

    def test_prepare_rejects_drafts_and_changed_server_digests(self):
        for settings, message in (({"draft": True}, "already published"),
                                  ({"bad_digest": True}, "GitHub asset digest mismatch")):
            destination = self.root / "rejected"
            with patch.object(publication, "run", side_effect=self.download(**settings)):
                with self.assertRaisesRegex(ValueError, message):
                    publication.prepare(f"clientd-v{self.version}", destination)
            self.assertFalse(destination.exists())


if __name__ == "__main__":
    unittest.main()
