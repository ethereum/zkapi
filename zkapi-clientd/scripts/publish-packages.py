#!/usr/bin/env python3
"""Verify a published client release, then promote its packages to Git repositories.

`prepare TAG DIRECTORY` downloads and validates public release assets. `publish
PLATFORM DIRECTORY REPOSITORY` copies only validated packaging files to an
existing checkout, commits them, and pushes (unless --dry-run is supplied).
Credentials are supplied by SSH or Git, never through command-line arguments.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


REPO = Path(__file__).resolve().parents[2]
GITHUB_REPO = "ethereum/zkapi"
NIX_FILES = ("flake.nix", "flake.lock", "package.nix", "nixos-module.nix",
             "home-manager-module.nix", "service-utils.nix", "README.md")


def run(*args, **kwargs):
    return subprocess.check_output([str(arg) for arg in args], text=True, **kwargs).strip()


def package_checks():
    spec = importlib.util.spec_from_file_location("package_checks", Path(__file__).with_name("test-packages.py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def version_number(version):
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("Expected a MAJOR.MINOR.PATCH client version")
    return tuple(map(int, version.split(".")))


def release_record(directory, version):
    checks = package_checks()
    return {"tag": f"clientd-v{version}", "artifacts": {
        f"zkapi-clientd_{version}_{target}.tar.gz":
            checks.sha256(directory / f"zkapi-clientd_{version}_{target}.tar.gz")
        for target in checks.TARGETS
    }}


def prepare(tag, directory):
    version = tag.removeprefix("clientd-v")
    version_number(version)
    if tag != f"clientd-v{version}":
        raise ValueError("Expected a clientd-vMAJOR.MINOR.PATCH tag")
    release = json.loads(run("gh", "api", f"repos/{GITHUB_REPO}/releases/tags/{tag}"))
    if release["draft"] or not release["published_at"] or release["tag_name"] != tag:
        raise ValueError("Only an already published client release can be promoted")
    # Numeric client tags may be marked prerelease, as the existing install
    # command is. Never use GitHub's /latest, which may be an operator release.
    names = [f"zkapi-clientd_{version}_{target}.tar.gz" for target in package_checks().TARGETS]
    names += ["zkapi-clientd-packaging.tar.gz", "zkapi-clientd-nix.tar.gz", "SHA256SUMS"]
    assets = {asset["name"]: asset for asset in release["assets"]}
    if not set(names).issubset(assets):
        raise ValueError("Release is missing required native or packaging assets")
    if directory.exists():
        raise ValueError("Use a new output directory; stale release files are not reused")
    with tempfile.TemporaryDirectory(prefix="zkapi-published-release-") as temp:
        staging = Path(temp)
        command = ["gh", "release", "download", tag, "--repo", GITHUB_REPO, "--dir", staging]
        for name in names:
            command += ["--pattern", name]
        run(*command)
        checks = package_checks()
        for name in names:
            # New GitHub assets include a server-computed SHA-256. Older assets
            # still have to pass the release's complete SHA256SUMS validation.
            digest = assets[name].get("digest")
            if digest and digest != "sha256:" + checks.sha256(staging / name):
                raise ValueError(f"GitHub asset digest mismatch: {name}")
        checks.extract_archive(staging / "zkapi-clientd-packaging.tar.gz", staging)
        if checks.verify_artifacts(staging) != version:
            raise ValueError("Published package version differs from the requested tag")
        record = release_record(staging, version)
        (staging / "release.json").write_text(json.dumps(record, indent=2) + "\n")
        shutil.copytree(staging, directory)
    print(f"Verified {tag} native archives, manifests, and standalone Nix flake in {directory}")


def existing_version(platform, checkout):
    if platform == "aur":
        path, pattern = checkout / ".SRCINFO", r"^\s*pkgver = (\S+)\s*$"
    elif platform == "homebrew":
        path, pattern = checkout / "Formula/zkapi-clientd.rb", r'^  version "([^"\n]+)"$'
    else:
        path, pattern = checkout / "package.nix", r'^  version = "([^"\n]+)";$'
    if not path.exists():
        return None
    match = re.search(pattern, path.read_text(), re.MULTILINE)
    if not match:
        raise ValueError(f"Cannot determine the existing version in {path}")
    return match.group(1)


def publish(platform, directory, checkout, dry_run=False):
    checks = package_checks()
    version = checks.verify_artifacts(directory)
    # Recheck downloaded workflow artifacts before writing a package repository.
    if run("git", "-C", checkout, "status", "--porcelain"):
        raise ValueError("Package repository checkout must be clean")
    previous = existing_version(platform, checkout)
    if previous and version_number(version) < version_number(previous):
        raise ValueError(f"Refusing to downgrade {platform} from {previous} to {version}")
    if platform == "aur":
        files = {"PKGBUILD": directory / "aur/PKGBUILD", ".SRCINFO": directory / "aur/.SRCINFO",
                 "LICENSE": REPO / "zkapi-clientd/packaging/arch/LICENSE"}
    elif platform == "homebrew":
        files = {"Formula/zkapi-clientd.rb": directory / "homebrew/zkapi-clientd.rb"}
    else:
        files = {name: directory / "nix" / name for name in NIX_FILES}
    if not previous and platform == "homebrew":
        files["README.md"] = REPO / "zkapi-clientd/packaging/homebrew/tap-README.md"
    if previous == version:
        # Publishing the same immutable release is safe to retry. A changed
        # payload needs a new upstream version rather than a silent overwrite.
        missing = [name for name in files if not (checkout / name).is_file()]
        changed = [name for name, source in files.items()
                   if (checkout / name).is_file() and (checkout / name).read_bytes() != source.read_bytes()]
        if changed or missing:
            raise ValueError(f"{platform} {version} is already published with different files: {changed + missing}")
        if not dry_run:
            # A previous push may have failed after its local commit succeeded.
            run("git", "-C", checkout, "push", "origin", "HEAD")
        print(f"{platform} {version} is already current")
        return
    for name, source in files.items():
        target = checkout / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
    run("git", "-C", checkout, "add", "--", *files)
    if dry_run:
        print(run("git", "-C", checkout, "diff", "--cached", "--stat"))
        print("Dry run: files staged; no commit or push")
        return
    run("git", "-C", checkout, "-c", "user.name=zkAPI release automation",
        "-c", "user.email=41898282+github-actions[bot]@users.noreply.github.com",
        "commit", "-m", f"zkapi-clientd: update to {version}")
    run("git", "-C", checkout, "push", "origin", "HEAD")
    print(f"Published {platform} {version}")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    download = commands.add_parser("prepare", help="Download and verify an exact published release")
    download.add_argument("tag")
    download.add_argument("directory", type=Path)
    promote = commands.add_parser("publish", help="Commit and push to an existing package repository checkout")
    promote.add_argument("platform", choices=("aur", "homebrew", "nix"))
    promote.add_argument("directory", type=Path)
    promote.add_argument("checkout", type=Path)
    promote.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            prepare(args.tag, args.directory.resolve())
        else:
            publish(args.platform, args.directory.resolve(), args.checkout.resolve(), args.dry_run)
    except (ValueError, subprocess.CalledProcessError) as error:
        parser.exit(1, f"Package publication failed: {error}\n")


if __name__ == "__main__":
    main()
