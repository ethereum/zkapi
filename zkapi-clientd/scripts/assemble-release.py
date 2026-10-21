#!/usr/bin/env python3
"""Render installable manifests from actual release artifacts, never placeholder hashes."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("version", help="MAJOR.MINOR.PATCH")
parser.add_argument("artifacts", type=Path, help="Directory containing all four native archives")
parser.add_argument("--fixture", action="store_true",
                    help="test fixtures only: skip the published point-release gate")
args = parser.parse_args()
if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.version):
    parser.error("version must be MAJOR.MINOR.PATCH")

repo = Path(__file__).resolve().parents[2]

# Design §10.7 D: this release's warnings send owners of the earlier vault's
# notes to that vault's point release (LegacyRelease in deployments.go), which
# withdraws them. It is assembled only once that release is published, with
# its checksum record checked in, so the release it names can be installed.
legacy = re.search(r'LegacyRelease = "zkapi-clientd ([0-9]+\.[0-9]+\.[0-9]+) ',
                   (repo / "zkapi-clientd/internal/zkapi/deployments.go").read_text())
if not legacy:
    parser.error("internal/zkapi/deployments.go names no LegacyRelease version")
if not args.fixture and args.version != legacy.group(1):
    record = repo / f"zkapi-clientd/packaging/releases/clientd-{legacy.group(1)}.json"
    published = False
    if record.is_file():
        try:
            published = json.loads(record.read_text()).get("tag") == f"clientd-v{legacy.group(1)}"
        except ValueError:
            published = False
    if not published:
        parser.error(f"publish the earlier vault's point release clientd-v{legacy.group(1)} first and "
                     f"check in packaging/releases/clientd-{legacy.group(1)}.json (design §10.7 D): "
                     "this release's warnings send owners of that vault's notes there")
artifacts = args.artifacts.resolve()
values = {
    "VERSION": args.version,
    "BASE_URL": f"https://github.com/ethereum/zkapi/releases/download/clientd-v{args.version}",
}
required = {"zkapi-clientd", "zkapi-walletd", "zkapi-clientd.service", "LICENSE", "CLI_PACKAGING.md", "VERSION"}
required |= {"share/zkapi-clientd/build-info.json", "share/zkapi-clientd/third-party/dependencies.json"}
required |= {"share/zkapi-clientd/proof-setup/" + name for name in
             ("request.pk", "request.vk", "withdrawal.pk", "withdrawal.vk", "manifest.json")}
for operating_system in ("darwin", "linux"):
    for architecture in ("amd64", "arm64"):
        filename = f"zkapi-clientd_{args.version}_{operating_system}_{architecture}.tar.gz"
        path = artifacts / filename
        with tarfile.open(path, "r:gz") as archive:
            members = archive.getmembers()
            names = set()
            for member in members:
                name = member.name.rstrip("/")
                if (not re.fullmatch(r"[A-Za-z0-9._/+@ -]+", name)
                        or any(part in ("", ".", "..") for part in name.split("/"))
                        or name in names or not (member.isfile() or member.isdir())):
                    parser.error(f"{filename} contains an unsafe or duplicate archive member: {member.name}")
                names.add(name)
            if not required.issubset(names):
                parser.error(f"{filename} is missing required release files")
            for name in required:
                member = archive.getmember(name)
                if not member.isfile() or member.size == 0:
                    parser.error(f"{filename} contains an empty or non-file payload: {name}")
            if archive.extractfile("VERSION").read().decode().strip() != args.version:
                parser.error(f"{filename} contains a mismatched version")
        values[f"{operating_system}_{architecture}_SHA256".upper()] = hashlib.sha256(path.read_bytes()).hexdigest()

for source, destination in (
    ("homebrew/zkapi-clientd.rb.in", "homebrew/zkapi-clientd.rb"),
    ("arch/PKGBUILD.in", "aur/PKGBUILD"),
    ("arch/.SRCINFO.in", "aur/.SRCINFO"),
    ("nix/package.nix.in", "nix/package.nix"),
):
    rendered = (repo / "zkapi-clientd/packaging" / source).read_text()
    for key, value in values.items():
        rendered = rendered.replace(f"@@{key}@@", value)
    if "@@" in rendered:
        parser.error(f"unresolved template variable in {source}")
    target = artifacts / destination
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(rendered)

# Keep the release self-contained without copying the checked-in package.nix
# over the freshly rendered version (or shipping development test runners).
for name in ("flake.nix", "flake.lock", "nixos-module.nix", "home-manager-module.nix",
             "service-utils.nix", "README.md"):
    shutil.copyfile(repo / "zkapi-clientd/packaging/nix" / name, artifacts / "nix" / name)

installer_source = (repo / "zkapi-clientd/install.sh").read_text()
if installer_source.count("@@VERSION@@") != 1:
    parser.error("zkapi-clientd/install.sh must contain exactly one release-version placeholder")
installer = artifacts / "install.sh"
installer.write_text(installer_source.replace("@@VERSION@@", args.version))
installer.chmod(0o755)

with tempfile.TemporaryDirectory(prefix="zkapi-clientd-manifests-") as temporary:
    for directory in ("homebrew", "aur", "nix"):
        shutil.copytree(artifacts / directory, Path(temporary) / directory)
    subprocess.run([
        sys.executable, str(repo / "zkapi-clientd/scripts/archive-release.py"),
        temporary, str(artifacts / "zkapi-clientd-packaging.tar.gz"),
    ], check=True)

# A standalone flake archive can be used directly by Nix; the combined
# packaging archive retains all three distribution handoff directories.
subprocess.run([
    sys.executable, str(repo / "zkapi-clientd/scripts/archive-release.py"),
    str(artifacts / "nix"), str(artifacts / "zkapi-clientd-nix.tar.gz"),
], check=True)

checksums = []
for path in sorted(artifacts.rglob("*")):
    if path.is_file() and path.name != "SHA256SUMS":
        checksums.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path.relative_to(artifacts)}")
(artifacts / "SHA256SUMS").write_text("\n".join(checksums) + "\n")
print(f"Generated installer, Homebrew, AUR, Nix, and SHA256SUMS files under {artifacts}")
