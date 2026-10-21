#!/usr/bin/env python3
"""Require a checkout of exactly the pinned commit of this repository, holding
the wallet companion, with no changed, staged or untracked files."""
import argparse
from pathlib import Path
import re
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("source", type=Path)
parser.add_argument("commit")
args = parser.parse_args()
source = args.source.resolve()

if not re.fullmatch(r"[0-9a-f]{40}", args.commit):
    parser.error("the pinned commit must be a full 40-character lowercase hash")


def git(*arguments):
    return subprocess.check_output(["git", "-C", str(source), *arguments]).decode()


try:
    head = git("rev-parse", "--verify", "HEAD").strip()
    top = Path(git("rev-parse", "--show-toplevel").strip()).resolve()
except subprocess.CalledProcessError:
    parser.error(f"{source} is not a Git checkout; prepare a fresh checkout")
if top != source:
    parser.error(f"{source} is not the top of its checkout; prepare a fresh checkout")
if head != args.commit:
    parser.error(f"unexpected source revision {head}; expected the pinned {args.commit}")
status = git("status", "--porcelain=v1", "--untracked-files=all", "--ignore-submodules=none")
if status.strip():
    parser.error("the source differs from the pinned commit (changed or untracked files); prepare a fresh checkout")
for required in ("Cargo.toml", "Cargo.lock", "crates/zkapi-companion/Cargo.toml",
                 "crates/zkapi-auth/Cargo.toml", "protocol/rust/Cargo.lock",
                 "protocol/rust/crates/zkapi-client/Cargo.toml"):
    if not (source / required).is_file():
        parser.error(f"the pinned commit has no {required}; it does not hold the wallet companion")
print(f"Verified the exact pinned companion source {args.commit} with a clean tree")
