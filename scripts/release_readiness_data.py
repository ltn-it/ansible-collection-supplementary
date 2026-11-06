"""Export only bounded YAML blobs for the trusted Main release preflight."""

from __future__ import annotations

import argparse
import re
import shutil
import subprocess
from pathlib import Path

MAX_BYTES = 1024 * 1024
MAX_FRAGMENTS = 256


def git(*arguments):
    executable = shutil.which("git")
    if executable is None:
        raise ValueError("Git executable unavailable")
    with subprocess.Popen(  # noqa: S603 -- fixed Git operations, validated immutable object IDs.
        [executable, "-c", "safe.directory=/workspace", *arguments],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
    ) as process:
        assert process.stdout is not None
        raw = process.stdout.read(MAX_BYTES + 1)
        if len(raw) > MAX_BYTES:
            process.kill()
            process.wait()
            raise ValueError("release Git object output exceeds limit")
        if process.wait() != 0:
            raise ValueError("release Git object read failed")
        return raw


def export(revision: str, destination: Path):
    if re.fullmatch(r"[0-9a-f]{40}", revision) is None:
        raise ValueError("immutable content revision required")
    if destination.exists() or destination.is_symlink():
        raise ValueError("fresh data directory required")
    # Read raw objects: candidate hooks, scripts and Python search paths are never installed.
    inventory = git("ls-tree", "-rz", "--full-tree", revision, "--", "galaxy.yml", "changelogs/fragments")
    if len(inventory) > MAX_BYTES:
        raise ValueError("release data inventory exceeds limit")
    selected = []
    for record in inventory.split(b"\0"):
        if not record:
            continue
        metadata, raw_path = record.split(b"\t", 1)
        path = raw_path.decode("utf-8")
        if path != "galaxy.yml" and not path.lower().endswith((".yml", ".yaml")):
            continue
        mode, kind, raw_oid = metadata.decode("ascii").split()
        if (
            path != "galaxy.yml"
            and re.fullmatch(
                r"changelogs/fragments/[A-Za-z0-9][A-Za-z0-9._-]*\.ya?ml",
                path,
            )
            is None
        ):
            raise ValueError("unsafe fragment path")
        if mode not in {"100644", "100755"} or kind != "blob" or re.fullmatch(r"[0-9a-f]{40}", raw_oid) is None:
            raise ValueError("regular release data blob required")
        size = int(git("cat-file", "-s", raw_oid))
        if size > MAX_BYTES:
            raise ValueError("release data blob exceeds limit")
        selected.append((path, raw_oid, size))
    if sum(path == "galaxy.yml" for path, _unused, _unused in selected) != 1 or len(selected) > MAX_FRAGMENTS + 1:
        raise ValueError("release metadata or fragment count invalid")
    destination.mkdir(mode=0o700)
    (destination / "changelogs/fragments").mkdir(parents=True, mode=0o700)
    for path, oid, size in selected:
        raw = git("cat-file", "blob", oid)
        if len(raw) != size:
            raise ValueError("release blob size changed")
        with (destination / path).open("xb") as stream:
            stream.write(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    export(args.revision, args.destination)


if __name__ == "__main__":
    main()
