#!/usr/bin/env python3
"""Resolve bounded M7 source identity; never build, install, or accept a release."""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
import re
import subprocess
import tomllib
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
VERSION_PATH = Path("firmware/opta-m7/VERSION")
MANIFEST_PATH = Path("firmware/opta-m7/Cargo.toml")
MAX_VERSION_BYTES = 32
MAX_FLAVOR_BYTES = 96
MAX_EPOCH = (1 << 64) - 1
IDENTITY_MARKER = b"OPTA-FIRMWARE-V1\0"
# Conservative admission boundary, including ignored files. Unrelated notes
# outside these build-input trees do not affect identity. This is not Cargo's
# final dependency inventory; the embedding slice must also verify dep-info.
BUILD_INPUT_PATHS = (
    "Cargo.toml",
    "Cargo.lock",
    "rust-toolchain.toml",
    ".cargo",
    "firmware/opta-m7",
    "crates",
    "vendor",
    "tools/firmware_identity.py",
    "tools/firmware_build_archive.py",
    "tools/check_m7_build_resource.py",
)
SEMVER = re.compile(
    r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
    r"(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?"
)


def parse_version(raw: bytes) -> str:
    """SemVer 2.0.0 plus the product's ASCII bound and exact LF terminator."""
    if not raw.endswith(b"\n") or len(raw) > MAX_VERSION_BYTES + 1:
        raise ValueError("VERSION must contain at most 32 ASCII bytes and one LF")
    try:
        version = raw[:-1].decode("ascii")
    except UnicodeDecodeError as exc:
        raise ValueError("VERSION must be ASCII") from exc
    match = SEMVER.fullmatch(version)
    if match is None or any(
        part.isdigit() and len(part) > 1 and part.startswith("0")
        for part in (match[4] or "").split(".")
    ):
        raise ValueError("VERSION is not Semantic Versioning 2.0.0")
    return version


def validate_revision(revision: str) -> str:
    if not re.fullmatch(r"git-sha1:[0-9a-f]{40}|git-sha256:[0-9a-f]{64}", revision):
        raise ValueError("revision must be a full algorithm-qualified lowercase Git ID")
    return revision


FIRMWARE_STATUS_KEYS = {
    "firmware-version", "firmware-revision", "firmware-flavor",
    "firmware-source-state", "firmware-build-date",
}


def firmware_status_label(values: dict[str, str], *, legacy_recovery: bool = False) -> str:
    """Validate reported identity; only explicit recovery may omit all five keys."""
    present = FIRMWARE_STATUS_KEYS & values.keys()
    if not present and legacy_recovery:
        return "unavailable (legacy recovery)"
    if present != FIRMWARE_STATUS_KEYS:
        raise ValueError("firmware status is missing required identity fields")
    version = values["firmware-version"]
    plain_version(version)
    revision = values["firmware-revision"]
    state = values["firmware-source-state"]
    if state not in {"clean", "dirty", "unknown"}:
        raise ValueError("invalid firmware source state")
    if revision == "unknown":
        if state != "unknown" or values["firmware-build-date"] != "1970-01-01T00:00:00Z":
            raise ValueError("inconsistent unknown firmware identity")
    else:
        validate_revision(revision)
        if state == "unknown":
            raise ValueError("inconsistent firmware source state")
    flavor = values["firmware-flavor"]
    if not re.fullmatch(r"[a-z0-9+-]{1,96}", flavor):
        raise ValueError("invalid firmware flavor")
    date = values["firmware-build-date"]
    parsed = dt.datetime.strptime(date, "%Y-%m-%dT%H:%M:%SZ")
    if parsed.strftime("%Y-%m-%dT%H:%M:%SZ") != date:
        raise ValueError("invalid firmware UTC build date")
    return f"{version} ({revision.partition(':')[2][:12] if ':' in revision else revision})"


def plain_version(version: str) -> tuple[int, int, int]:
    parse_version((version + "\n").encode("ascii"))
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", version):
        raise ValueError("build versions must be plain major.minor.patch numbers")
    major, minor, patch = map(int, version.split("."))
    return major, minor, patch


def validate_build_version(version: str, minimum: str) -> str:
    if plain_version(version) < plain_version(minimum):
        raise ValueError("build version is below the source minimum version")
    return version


def parse_epoch(value: str) -> int:
    if not re.fullmatch(r"0|[1-9][0-9]{0,19}", value) or int(value) > MAX_EPOCH:
        raise ValueError("SOURCE_DATE_EPOCH must be unsigned 64-bit decimal seconds")
    return int(value)


def canonical_flavor(manifest: dict, features: list[str]) -> str:
    """Expand local feature aliases so indirect diagnostics cannot say product.

    Accept one declared M7 feature per argument, as the canonical builder does.
    Dependency-feature syntax is deliberately unavailable to callers; only the
    checked manifest may enable it.
    """
    declared = manifest["features"]
    if declared.get("default") != ["product"]:
        raise ValueError("M7 default features must be exactly product")
    if len(features) != len(set(features)):
        raise ValueError("duplicate feature arguments")
    if any(name not in declared for name in features):
        raise ValueError("features must name declared M7 features individually")
    enabled: set[str] = set()
    pending = ["default", *features]
    while pending:
        feature = pending.pop()
        if feature in enabled:
            continue
        enabled.add(feature)
        pending.extend(name for name in declared[feature] if name in declared)
    flavor = "+".join(["product", *sorted(enabled - {"default", "product"})])
    if len(flavor) > MAX_FLAVOR_BYTES or not re.fullmatch(r"[a-z0-9+-]+", flavor):
        raise ValueError("canonical flavor exceeds 96 ASCII bytes or has invalid names")
    return flavor


def git(root: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(root), *args],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    ).stdout.decode("utf-8")


def resolve_source_identity(
    root: Path,
    *,
    input_paths: tuple[str, ...] = BUILD_INPUT_PATHS,
    environ: dict[str, str] | None = None,
) -> dict:
    """Resolve shared checkout provenance without choosing a processor version."""
    root = root.resolve()
    env = os.environ if environ is None else environ
    revision, state, epoch = "unknown", "unknown", 0
    try:
        # An exported tree inside another repository must not borrow its HEAD.
        if Path(git(root, "rev-parse", "--show-toplevel").strip()).resolve() != root:
            raise ValueError("identity root is not the Git checkout root")
        algorithm = git(root, "rev-parse", "--show-object-format=storage").strip()
        commit = git(root, "rev-parse", "--verify", "HEAD").strip()
        revision = validate_revision(f"git-{algorithm}:{commit}")
        epoch = parse_epoch(git(root, "show", "-s", "--format=%ct", commit).strip())
        tracked = git(root, "status", "--porcelain=v1", "--untracked-files=no")
        untracked = git(root, "ls-files", "--others", "-z", "--", *input_paths)
        # Hidden index entries can suppress normal dirty reporting. Do not
        # certify a checkout whose source has been excluded from that check.
        entries = git(root, "ls-files", "-v", "-z").split("\0")
        hidden = any(row and (row[0].islower() or row[0] == "S") for row in entries)
        state = "dirty" if tracked or untracked or hidden else "clean"
        if git(root, "rev-parse", "--verify", "HEAD").strip() != commit:
            raise ValueError("source commit changed while resolving identity")
    except (FileNotFoundError, subprocess.CalledProcessError):
        revision, state, epoch = "unknown", "unknown", 0
    if "SOURCE_DATE_EPOCH" in env:
        supplied = parse_epoch(env["SOURCE_DATE_EPOCH"])
        if revision == "unknown" or supplied != epoch:
            raise ValueError("SOURCE_DATE_EPOCH does not match the known source commit")
    return {"revision": revision, "source_state": state, "source_date_epoch": epoch}


def resolve_identity(
    root: Path = REPO_ROOT,
    features: list[str] | None = None,
    *,
    release_candidate: bool = False,
    environ: dict[str, str] | None = None,
    build_version: str | None = None,
) -> dict:
    root = root.resolve()
    env = os.environ if environ is None else environ
    version = parse_version((root / VERSION_PATH).read_bytes())
    version = validate_build_version(build_version or version, version)
    manifest = tomllib.loads((root / MANIFEST_PATH).read_text(encoding="utf-8"))
    flavor = canonical_flavor(manifest, features or [])
    source = resolve_source_identity(root, environ=env)
    identity = {
        "version": version,
        "flavor": flavor,
        **source,
    }
    if release_candidate and (source["source_state"] != "clean" or flavor != "product"):
        raise ValueError(
            "release candidate requires clean known source and product flavor"
        )
    return identity


def cargo_environment(identity: dict) -> dict[str, str]:
    """Explicit identity channel for the later canonical embedding integration."""
    return {
        **{
            f"OPTA_FIRMWARE_{key.upper()}": str(value)
            for key, value in identity.items()
            if key != "source_date_epoch"
        },
        "SOURCE_DATE_EPOCH": str(identity["source_date_epoch"]),
    }


def build_script_identity(root: Path, env: dict[str, str]) -> dict:
    """Validate the canonical channel against Cargo's actual enabled features.

    Direct Cargo builds always report unknown provenance, avoiding stale Git
    identity when Cargo reuses a build-script result after unrelated commits.
    """
    manifest = tomllib.loads((root / MANIFEST_PATH).read_text(encoding="utf-8"))
    enabled = [
        name
        for name in manifest["features"]
        if f"CARGO_FEATURE_{name.upper().replace('-', '_')}" in env
    ]
    if "default" not in enabled:
        flavor = "+".join(["custom", *sorted(enabled)])
        if len(flavor) > MAX_FLAVOR_BYTES:
            raise ValueError("custom flavor exceeds 96 ASCII bytes")
    else:
        flavor = canonical_flavor(manifest, enabled)
    supplied = {
        key: value for key, value in env.items() if key.startswith("OPTA_FIRMWARE_")
    }
    if supplied:
        resolved = resolve_identity(
            root, enabled, environ=env, build_version=env.get("OPTA_FIRMWARE_VERSION")
        )
        expected = cargo_environment(resolved)
        if (
            flavor != resolved["flavor"]
            or supplied
            != {
                key: value
                for key, value in expected.items()
                if key.startswith("OPTA_FIRMWARE_")
            }
            or env.get("SOURCE_DATE_EPOCH") != expected["SOURCE_DATE_EPOCH"]
        ):
            raise ValueError("Cargo build identity differs from canonical inputs")
        return resolved
    if "SOURCE_DATE_EPOCH" in env and env["SOURCE_DATE_EPOCH"] != "0":
        raise ValueError("direct Cargo build has no validated source timestamp")
    return {
        "version": parse_version((root / VERSION_PATH).read_bytes()),
        "revision": "unknown",
        "source_state": "unknown",
        "flavor": flavor,
        "source_date_epoch": 0,
    }


def identity_record(identity: dict) -> bytes:
    return (
        IDENTITY_MARKER
        + json.dumps(
            identity, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("ascii")
        + b"\0"
    )


def verify_build_dependencies(root: Path, dep_info: Path) -> dict:
    """Check Cargo's emitted path-source inventory, including include_bytes!.

    Registry/toolchain dependencies remain covered by the locked/offline build
    inputs. Cargo-generated OUT_DIR files are listed separately from source.
    """
    root = root.resolve()
    text = dep_info.read_text(encoding="utf-8").replace("\\\n", "")
    if not text.strip():
        raise ValueError("missing Cargo dependency inventory")
    _, separator, dependencies = text.splitlines()[0].partition(": ")
    if not separator or not dependencies:
        raise ValueError("missing Cargo dependency inventory")
    tracked = set(git(root, "ls-files", "-z").split("\0"))
    source, generated = [], []
    for token in re.findall(r"(?:\\.|[^\s])+", dependencies):
        path = Path(re.sub(r"\\(.)", r"\1", token)).resolve()
        try:
            relative = path.relative_to(root).as_posix()
        except ValueError as exc:
            raise ValueError(f"build path input escapes repository: {path}") from exc
        if not path.is_file():
            raise ValueError(f"missing build input: {relative}")
        if re.fullmatch(
            r"target/thumbv7em-none-eabihf/release/build/[^/]+/out/.+", relative
        ):
            generated.append(relative)
        elif relative not in tracked:
            raise ValueError(f"untracked source consumed by build: {relative}")
        else:
            source.append(relative)
    if not source:
        raise ValueError("Cargo inventory contains no tracked source")
    return {
        "tracked_source_inputs": sorted(set(source)),
        "generated_inputs": sorted(set(generated)),
    }


def extract_identity(binary: bytes, expected: dict) -> dict:
    """Require exactly one loadable identity record, with exact canonical bytes."""
    if binary.count(IDENTITY_MARKER) != 1:
        raise ValueError("image must contain exactly one firmware identity record")
    start = binary.index(IDENTITY_MARKER)
    record = identity_record(expected)
    if binary[start : start + len(record)] != record:
        raise ValueError("embedded firmware identity differs from requested identity")
    return json.loads(record[len(IDENTITY_MARKER) : -1])


def emit_rust(identity: dict, output: Path) -> None:
    record = identity_record(identity)
    build_date = dt.datetime.fromtimestamp(
        identity["source_date_epoch"], tz=dt.timezone.utc
    ).strftime("%Y-%m-%dT%H:%M:%SZ")
    build_number = f"{identity['revision']};{identity['flavor']};{identity['source_state']}"
    # Part 6: signed 100 ns ticks since 1601-01-01, zero when unknown.
    opcua_date = 0 if identity["source_state"] == "unknown" else (identity["source_date_epoch"] + 11_644_473_600) * 10_000_000
    if opcua_date > (1 << 63) - 1:
        raise ValueError("build date exceeds OPC UA DateTime range")
    constants = [f"pub const OPCUA_BUILD_DATE: i64 = {opcua_date};"]
    for key, value in {**identity, "build_date": build_date, "build_number": build_number}.items():
        rust_type = "u64" if isinstance(value, int) else "&str"
        constants.append(f"pub const {key.upper()}: {rust_type} = {json.dumps(value)};")
    constants.extend(
        [
            "#[used]",
            "#[no_mangle]",
            '#[link_section = ".rodata.firmware_identity"]',
            f"pub static OPTA_FIRMWARE_IDENTITY: [u8; {len(record)}] = {list(record)};",
        ]
    )
    output.write_text("\n".join(constants) + "\n", encoding="ascii")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=REPO_ROOT)
    parser.add_argument("--features", action="append", default=[])
    parser.add_argument("--release-candidate", action="store_true")
    parser.add_argument(
        "--emit-rust",
        type=Path,
        help="build.rs only: validate Cargo inputs and write OUT_DIR constants",
    )
    args = parser.parse_args()
    try:
        if args.emit_rust:
            if args.features or args.release_candidate:
                raise ValueError("build-script mode takes features only from Cargo")
            emit_rust(
                build_script_identity(args.root, dict(os.environ)), args.emit_rust
            )
            return 0
        identity = resolve_identity(
            args.root, args.features, release_candidate=args.release_candidate
        )
    except (OSError, ValueError, KeyError) as exc:
        parser.exit(1, f"firmware identity: {exc}\n")
    print(json.dumps(identity, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
