"""Shared BIN-only archive for validated M7 and M4 builds; no hardware or Git writes."""

from __future__ import annotations

import fcntl
import json
import os
import tempfile
from pathlib import Path
from contextlib import contextmanager

try:
    from tools.firmware_identity import (
        IDENTITY_MARKER,
        extract_identity,
        plain_version,
        validate_build_version,
    )
except ModuleNotFoundError:
    from firmware_identity import (
        IDENTITY_MARKER,
        extract_identity,
        plain_version,
        validate_build_version,
    )


def processor_name(package: str) -> str:
    processor = {"opta-m7": "m7", "opta-m4-quarantine": "m4"}.get(package)
    if processor is None:
        raise ValueError("unsupported firmware archive package")
    return processor


@contextmanager
def allocated_version(
    archive_root: Path,
    package: str,
    minimum: str,
    requested: str | None,
    *,
    identity: dict | None = None,
):
    """Serialize allocation and build/publication for this processor's archive."""
    plain_version(minimum)
    root = archive_root / processor_name(package)
    root.mkdir(parents=True, exist_ok=True)
    with (root / ".build.lock").open("a") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        versions = sorted(
            (plain_version(p.name), p) for p in root.iterdir() if p.is_dir()
        )
        # Repeated clean-source preflight/build checks must retain the same BIN.
        # Dirty source cannot be matched by its Git revision alone.
        if (
            requested is None
            and package == "opta-m7"
            and identity
            and identity["source_state"] == "clean"
        ):
            for number, folder in reversed(versions):
                if number < plain_version(minimum):
                    continue
                candidate = folder / "m7.bin"
                if not candidate.exists():
                    continue
                binary = candidate.read_bytes()
                start = binary.index(IDENTITY_MARKER) + len(IDENTITY_MARKER)
                stored = json.loads(binary[start : binary.index(b"\0", start)])
                extract_identity(binary, stored)
                if {**stored, "version": minimum} == identity:
                    requested = stored["version"]
                    break
        if requested is None:
            highest = versions[-1][0] if versions else (-1, -1, -1)
            requested = minimum
            if highest >= plain_version(minimum):
                requested = f"{highest[0]}.{highest[1]}.{highest[2] + 1}"
        yield validate_build_version(requested, minimum)


def archive_binary(
    binary: bytes, identity: dict, archive_root: Path, *, package: str
) -> Path:
    """A processor/version owns one BIN forever; conflicting bytes fail closed."""
    processor = processor_name(package)
    version = identity["version"]
    plain_version(version)
    destination = archive_root / processor / version / f"{processor}.bin"
    destination.parent.mkdir(parents=True, exist_ok=True)
    # Publish atomically without replacing an existing file, even on reruns.
    with tempfile.NamedTemporaryFile(dir=destination.parent, suffix=".bin") as pending:
        pending.write(binary)
        pending.flush()
        os.fsync(pending.fileno())
        try:
            os.link(pending.name, destination)
        except FileExistsError:
            if destination.is_symlink() or destination.read_bytes() != binary:
                raise RuntimeError(
                    f"firmware archive conflict: {destination}; use a new version"
                )
    return destination
