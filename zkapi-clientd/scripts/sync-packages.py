#!/usr/bin/env python3
"""Refresh directly installable packages using pinned release checksums.

The release assembler still computes hashes from actual native archives. This
command copies the pinned hashes into the source-tree packages;
it never uses moving download URLs or placeholder checksums.
"""
import argparse
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[2]
PACKAGING = ROOT / "zkapi-clientd/packaging"
MANIFESTS = ("arch/PKGBUILD", "arch/.SRCINFO", "homebrew/zkapi-clientd.rb", "nix/package.nix")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("version", nargs="?", help="Published MAJOR.MINOR.PATCH; defaults to the checked-in package version")
    parser.add_argument("--check", action="store_true", help="Fail if checked-in packages need refreshing")
    args = parser.parse_args()
    if args.version is None:
        checked_in = re.search(r"^pkgver=([0-9]+\.[0-9]+\.[0-9]+)$",
                               (PACKAGING / "arch/PKGBUILD").read_text(), re.MULTILINE)
        if not checked_in:
            parser.error("cannot determine the checked-in PKGBUILD version")
        args.version = checked_in.group(1)
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", args.version):
        parser.error("version must be MAJOR.MINOR.PATCH")
    record = json.loads((PACKAGING / f"releases/clientd-{args.version}.json").read_text())
    if record["tag"] != f"clientd-v{args.version}":
        parser.error("checksum metadata tag does not match requested version")
    values = {
        "VERSION": args.version,
        "BASE_URL": f"https://github.com/ethereum/zkapi/releases/download/clientd-v{args.version}",
    }
    for target in ("linux_amd64", "linux_arm64", "darwin_amd64", "darwin_arm64"):
        digest = record["artifacts"][f"zkapi-clientd_{args.version}_{target}.tar.gz"]
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            parser.error(f"invalid release checksum for {target}")
        values[target.upper() + "_SHA256"] = digest
    stale = []
    for name in MANIFESTS:
        destination = PACKAGING / name
        rendered = (PACKAGING / (name + ".in")).read_text()
        for key, value in values.items():
            rendered = rendered.replace(f"@@{key}@@", value)
        if "@@" in rendered:
            parser.error(f"unresolved template placeholder in {name}")
        if args.check:
            if not destination.is_file() or destination.read_text() != rendered:
                stale.append(name)
        else:
            destination.write_text(rendered)
    if stale:
        parser.exit(1, "Packages need refreshing: " + ", ".join(stale)
                    + f"\nRun python3 zkapi-clientd/scripts/sync-packages.py {args.version}\n")
    print(f"{'Checked' if args.check else 'Refreshed'} packages for clientd-v{args.version}")


if __name__ == "__main__":
    main()
