"""Validate source/tag selection and downloaded release checksums."""

import argparse
import hashlib
import json
import os
import re
from pathlib import Path

from release_tools.prepare import git, version


def normalize_tag(value):
    if not re.fullmatch(r"v?\d+\.\d+\.\d+", value):
        raise ValueError("Use an existing tag such as v0.5.0.")
    return "v" + value.removeprefix("v")


def resolve(draft=False):
    current = version()
    commit = git("rev-parse", "HEAD")
    tag = ""
    if os.environ.get("GITHUB_REF_TYPE") == "tag":
        tag = normalize_tag(os.environ["GITHUB_REF_NAME"])
    elif draft:
        tag = f"v{current}"
    if tag:
        if tag != f"v{current}":
            raise ValueError("The selected tag must match pyproject.toml's version.")
        if git("rev-parse", "--verify", f"refs/tags/{tag}^{{commit}}") != commit:
            raise ValueError("The release tag must already point to the checked-out commit.")
    values = {"version": current, "tag": tag, "source_sha": commit}
    if output := os.environ.get("GITHUB_OUTPUT"):
        with Path(output).open("a", encoding="utf-8") as stream:
            for key, value in values.items():
                stream.write(f"{key}={value}\n")
    return values


def verify(directory, tag=None, prerelease=True):
    directory = Path(directory)
    with (directory / "release.json").open("rb") as stream:
        raw = stream.read(1_000_001)
    if len(raw) > 1_000_000:
        raise ValueError("Oversized release manifest.")
    manifest = json.loads(raw)
    expected = normalize_tag(tag) if tag else f"v{manifest['version']}"
    if f"v{manifest['version']}" != expected:
        raise ValueError("Release version and tag disagree.")
    if tag:
        if (
            git("rev-parse", "--verify", f"refs/tags/{expected}^{{commit}}")
            != manifest["source_commit"]
        ):
            raise ValueError("Release artifacts do not match the tag's commit.")
        if manifest["source_dirty"]:
            raise ValueError("Repository releases require an unchanged source tree.")
    if not prerelease and manifest["signing_mode"] != "certificate":
        raise ValueError("Stable publication requires production certificate signing.")
    names = set()
    for item in manifest["assets"]:
        name = item["name"]
        if name != Path(name).name or "/" in name or "\\" in name or name in names:
            raise ValueError("Unsafe or duplicate asset name.")
        names.add(name)
        path = directory / name
        if path.stat().st_size != item["size"]:
            raise ValueError(f"Incorrect asset size: {name}")
        with path.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        if digest != item["sha256"]:
            raise ValueError(f"Incorrect SHA-256: {name}")
    prefix = f"NetworkPacketSniffer-{manifest['version']}-"
    required = {prefix + "x64-setup.exe", prefix + "x64.msix", prefix + "source.zip"}
    if not required <= names or manifest["python"] != "3.14.7":
        raise ValueError("Missing required artifacts or incorrect Python version.")
    expected_sums = {item["name"]: item["sha256"] for item in manifest["assets"]}
    expected_sums["release.json"] = hashlib.sha256(raw).hexdigest()
    with (directory / "SHA256SUMS.txt").open(encoding="utf-8-sig") as stream:
        raw_sums = stream.read(100_001)
    if len(raw_sums) > 100_000:
        raise ValueError("Oversized checksum file.")
    actual_sums = {}
    for line in raw_sums.splitlines():
        digest, separator, name = line.partition("  ")
        if not separator or name in actual_sums or not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("Invalid or duplicate checksum line.")
        actual_sums[name] = digest
    if actual_sums != expected_sums:
        raise ValueError("SHA256SUMS.txt disagrees with the release manifest.")
    return manifest


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("resolve", "verify"))
    parser.add_argument("--draft", action="store_true")
    parser.add_argument("--directory", type=Path)
    parser.add_argument("--tag")
    parser.add_argument("--stable", action="store_true")
    args = parser.parse_args()
    result = (
        resolve(args.draft)
        if args.command == "resolve"
        else verify(args.directory, args.tag, not args.stable)
    )
    print(json.dumps(result, indent=2))
