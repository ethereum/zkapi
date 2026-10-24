#!/usr/bin/env python3
"""Preserve dependency license texts/declarations and release provenance."""
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

repo = Path(__file__).resolve().parents[2]
companion = Path(sys.argv[1]).resolve()
stage = Path(sys.argv[2]).resolve()
share = stage / "share/zkapi-clientd"
notices = share / "third-party"
notices.mkdir(parents=True)

def command(args, cwd=None):
    return subprocess.check_output(args, cwd=cwd, text=True)

def json_stream(text):
    decoder = json.JSONDecoder()
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        yield value
        text = text.lstrip()[end:]

records = []
def collect(name, version, directory, license_expression=None, source=None, license_file=None):
    identifier = re.sub(r"[^a-zA-Z0-9._-]", "_", name + "-" + version)
    destination = notices / identifier
    copied = []
    for path in sorted(Path(directory).iterdir()):
        if path.is_file() and re.match(r"^(LICENSE|LICENCE|COPYING|NOTICE|AUTHORS)([._-]|$)", path.name, re.I):
            destination.mkdir(exist_ok=True)
            shutil.copyfile(path, destination / path.name)
            copied.append(str((destination / path.name).relative_to(share)))
    if license_file:
        path = Path(license_file)
        if not path.is_absolute():
            path = Path(directory) / path
        if path.is_file() and not (destination / path.name).exists():
            destination.mkdir(exist_ok=True)
            shutil.copyfile(path, destination / path.name)
            copied.append(str((destination / path.name).relative_to(share)))
    records.append({"name": name, "version": version, "license": license_expression,
                    "source": source, "license_files": copied})

modules = {}
for package in json_stream(command(["go", "list", "-deps", "-json", "./cmd/zkapi-clientd"], repo / "zkapi-clientd")):
    module = package.get("Module")
    if module and not module.get("Main"):
        modules[module["Path"]] = module
for name, module in sorted(modules.items()):
    collect(name, module["Version"], module["Dir"], source="https://" + name)
go_version = command(["go", "version"]).strip()
collect("Go", go_version.split()[2], command(["go", "env", "GOROOT"]).strip(), "BSD-3-Clause", "https://go.dev/")
collect("AnOversizedMooseWithSocks/leCore", "5cef1aec",
        repo / "zkapi-clientd/internal/lecore", "MIT",
        "https://github.com/AnOversizedMooseWithSocks/leCore/tree/5cef1aec")

rust_version = command(["rustc", "-vV"])
host = next(line.split(": ", 1)[1] for line in rust_version.splitlines() if line.startswith("host: "))
metadata = json.loads(command(["cargo", "metadata", "--locked", "--format-version", "1", "--filter-platform", host], companion))
packages = {package["id"]: package for package in metadata["packages"]}
nodes = {node["id"]: node for node in metadata["resolve"]["nodes"]}
pending = [package["id"] for package in metadata["packages"]
           if Path(package["manifest_path"]) == companion / "crates/zkapi-companion/Cargo.toml"]
if len(pending) != 1:
    sys.exit("the prepared source has no crates/zkapi-companion package")
visited = set()
while pending:
    identifier = pending.pop()
    if identifier in visited:
        continue
    visited.add(identifier)
    pending.extend(nodes[identifier]["dependencies"])
for identifier in sorted(visited):
    package = packages[identifier]
    collect(package["name"], package["version"], Path(package["manifest_path"]).parent,
            package.get("license"), package.get("repository") or package.get("source"), package.get("license_file"))

(notices / "dependencies.json").write_text(json.dumps(records, indent=2, sort_keys=True) + "\n")
(notices / "README.txt").write_text(
    "This directory preserves license/notice texts for resolved Go and Rust build dependencies\n"
    "and the locally adapted leCore retrieval code.\n"
    "dependencies.json records upstream license declarations and source references.\n"
    "The zkAPI wallet companion and protocol crates declare MIT OR Apache-2.0 in their Cargo\n"
    "manifests; their pinned source tree does not provide top-level license text files. Those\n"
    "declarations are retained here without assigning them the zkAPI client's copyright notice.\n"
    "Companion and protocol source: https://github.com/ethereum/zkapi at the commit recorded\n"
    "as source_commit in build-info.json (crates/zkapi-companion, protocol/rust).\n"
)
build_info = {
    "zkapi_clientd_source": "https://github.com/ethereum/zkapi",
    "zkapi_clientd_commit": command(["git", "rev-parse", "HEAD"], repo).strip(),
    "zkapi_clientd_source_dirty": bool(command(["git", "status", "--porcelain"], repo).strip()),
    "source_commit": command(["git", "rev-parse", "HEAD"], companion).strip(),
    "go_toolchain": go_version,
    "rust_toolchain": rust_version.strip(),
    "cargo_version": command(["cargo", "--version"]).strip(),
    "source_date_epoch": os.environ.get("SOURCE_DATE_EPOCH", "0"),
}
(share / "build-info.json").write_text(json.dumps(build_info, indent=2, sort_keys=True) + "\n")
print(f"Collected license declarations/notices for {len(records)} dependencies and build provenance")
