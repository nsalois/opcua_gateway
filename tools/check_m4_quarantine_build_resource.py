#!/usr/bin/env python3
# Copyright 2026 Nicholas Salois.
#
# Licensed under the Apache License, Version 2.0.
# See the LICENSE file in the repository root for the full license.

"""Build and validate the dependency-free Opta M4 quarantine artifact.

This is a host/build-resource checker only. It cannot contact the bench,
program either Flash bank, change option bytes, or modify recovery selections.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

try:
    from tools.firmware_build_archive import allocated_version, archive_binary
    from tools.firmware_identity import (
        parse_version,
        resolve_source_identity,
        validate_build_version,
    )
except ModuleNotFoundError:
    from firmware_build_archive import allocated_version, archive_binary
    from firmware_identity import (
        parse_version,
        resolve_source_identity,
        validate_build_version,
    )

REPO_ROOT = Path(__file__).resolve().parents[1]
CRATE_ROOT = REPO_ROOT / "firmware" / "opta-m4-quarantine"
MANIFEST = CRATE_ROOT / "Cargo.toml"
VERSION_PATH = CRATE_ROOT / "VERSION"
LOCKFILE = CRATE_ROOT / "Cargo.lock"
INTERRUPT_SOURCE = CRATE_ROOT / "stm32h747xx-cm4-interrupts.csv"
TARGET = "thumbv7em-none-eabihf"
PACKAGE = "opta-m4-quarantine"
TARGET_DIR = REPO_ROOT / "target" / "opta-m4-quarantine"
ARTIFACT = TARGET_DIR / TARGET / "release" / PACKAGE
COMPACT_BINARY = TARGET_DIR / TARGET / "release" / f"{PACKAGE}.bin"
BUILD_STD_COMPONENTS = "core,compiler_builtins"

FLASH_ORIGIN = 0x0810_0000
FLASH_PREFIX_END = 0x0810_1000
FLASH_PREFIX_BYTES = FLASH_PREFIX_END - FLASH_ORIGIN
FULL_BANK_BYTES = 1024 * 1024
ERASED_BYTE = 0xFF
CM4_STACK_START = 0x1004_7C00
CM4_STACK_END = 0x1004_8000
CM4_STACK_BYTES = CM4_STACK_END - CM4_STACK_START
LAST_EXTERNAL_IRQ = 149
VECTOR_WORDS = 16 + LAST_EXTERNAL_IRQ + 1
VECTOR_BYTES = VECTOR_WORDS * 4
DEFINED_EXTERNAL_IRQS = 145
EXPECTED_INTERRUPT_SOURCE_SHA256 = (
    "bcd309a2d64eecd18a4f1f71ee0600f4bf8995d93b45dcb1499f104d63056048"
)
EXPECTED_ST_HEADER_SHA256 = (
    "0a4bcfa3d25fb1da45cf83d7ba19fd69f9a0f1fdeccb902dd00745a348b92e43"
)


def run_command(
    argv: list[str], *, env: dict[str, str] | None = None
) -> dict[str, Any]:
    completed = subprocess.run(
        argv,
        cwd=REPO_ROOT,
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    return {
        "argv": argv,
        "returncode": completed.returncode,
        "output": completed.stdout,
    }


def command_output_or_raise(command: dict[str, Any]) -> str:
    if command["returncode"] != 0:
        raise RuntimeError(
            f"command failed: {' '.join(command['argv'])}\n{command['output']}"
        )
    return str(command["output"])


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"required tool not found on PATH: {name}")
    return path


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def parse_interrupt_source_text(text: str) -> tuple[dict[str, str], dict[int, str]]:
    metadata: dict[str, str] = {}
    entries: dict[int, str] = {}
    saw_header = False
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if line.startswith("#"):
            key, separator, value = line[1:].strip().partition("=")
            if separator:
                if key in metadata:
                    raise RuntimeError(f"duplicate interrupt metadata key: {key}")
                metadata[key] = value
            continue
        if not saw_header:
            if line != "irqn,name":
                raise RuntimeError("interrupt source has an unexpected header")
            saw_header = True
            continue
        parts = line.split(",")
        if len(parts) != 2:
            raise RuntimeError(f"malformed interrupt row: {line!r}")
        number_text, name = parts
        try:
            number = int(number_text, 10)
        except ValueError as exc:
            raise RuntimeError(f"invalid interrupt number: {number_text!r}") from exc
        if number in entries:
            raise RuntimeError(f"duplicate interrupt number: {number}")
        if not re.fullmatch(r"[A-Za-z0-9_]+", name):
            raise RuntimeError(f"invalid interrupt name: {name!r}")
        entries[number] = name

    if not saw_header:
        raise RuntimeError("interrupt source is missing its CSV header")
    required_metadata = {
        "schema",
        "source_title",
        "source_url",
        "source_package",
        "source_sha256",
        "extraction",
    }
    missing_metadata = sorted(required_metadata - set(metadata))
    if missing_metadata:
        raise RuntimeError(f"interrupt source metadata missing: {missing_metadata}")
    if metadata["source_sha256"] != EXPECTED_ST_HEADER_SHA256:
        raise RuntimeError("pinned ST CMSIS header SHA-256 changed")
    if entries.get(-14) != "NonMaskableInt":
        raise RuntimeError("pinned exception list does not start with NMI -14")
    if entries.get(LAST_EXTERNAL_IRQ) != "WAKEUP_PIN":
        raise RuntimeError("pinned external interrupt list does not end at IRQ 149")
    if any(number < -14 or number > LAST_EXTERNAL_IRQ for number in entries):
        raise RuntimeError("interrupt number is outside the accepted vector range")
    if -15 in entries:
        raise RuntimeError("reset must be supplied only by the quarantine artifact")
    external_count = sum(number >= 0 for number in entries)
    if external_count != DEFINED_EXTERNAL_IRQS:
        raise RuntimeError(
            f"expected {DEFINED_EXTERNAL_IRQS} defined external IRQs, got {external_count}"
        )
    return metadata, entries


def load_pinned_interrupt_source() -> tuple[dict[str, str], dict[int, str]]:
    digest = sha256_file(INTERRUPT_SOURCE)
    if digest != EXPECTED_INTERRUPT_SOURCE_SHA256:
        raise RuntimeError(
            "pinned STM32H747 CM4 interrupt-source SHA-256 changed: "
            f"expected {EXPECTED_INTERRUPT_SOURCE_SHA256}, got {digest}"
        )
    return parse_interrupt_source_text(INTERRUPT_SOURCE.read_text(encoding="utf-8"))


def parse_size_summary(output: str) -> dict[str, int]:
    rows = [line.split() for line in output.splitlines() if line.strip()]
    if len(rows) < 2 or len(rows[-1]) < 6:
        raise RuntimeError(f"unexpected llvm-size output:\n{output}")
    return {
        "text": int(rows[-1][0]),
        "data": int(rows[-1][1]),
        "bss": int(rows[-1][2]),
        "dec": int(rows[-1][3]),
    }


def parse_size_sections(output: str) -> dict[str, dict[str, int]]:
    sections: dict[str, dict[str, int]] = {}
    for line in output.splitlines():
        parts = line.split()
        if len(parts) != 3 or not parts[0].startswith("."):
            continue
        try:
            sections[parts[0]] = {"size": int(parts[1], 10), "addr": int(parts[2], 10)}
        except ValueError:
            continue
    return sections


def parse_elf_header(output: str) -> dict[str, int | str]:
    header: dict[str, int | str] = {}
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("Machine:"):
            header["machine"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Entry point address:"):
            header["entry_point"] = int(stripped.split(":", 1)[1].strip(), 16)
        elif stripped.startswith("Class:"):
            header["class"] = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("Data:"):
            header["data"] = stripped.split(":", 1)[1].strip()
    return header


def parse_symbols(output: str) -> dict[str, int]:
    wanted = {
        "__vector_table",
        "__vector_table_end",
        "quarantine_reset",
        "quarantine_wait",
        "quarantine_inert",
        "__quarantine_flash_origin",
        "__quarantine_flash_limit",
        "__quarantine_stack_start",
        "__quarantine_stack_end",
        "__quarantine_image_end",
    }
    symbols: dict[str, int] = {}
    pattern = re.compile(
        r"^\s*\d+:\s+([0-9a-fA-F]+)\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s*$"
    )
    for line in output.splitlines():
        match = pattern.match(line)
        if match and match.group(2) in wanted:
            symbols[match.group(2)] = int(match.group(1), 16)
    missing = sorted(wanted - set(symbols))
    if missing:
        raise RuntimeError(f"missing quarantine ELF symbols: {missing}")
    return symbols


def parse_hex_section(output: str) -> bytes:
    data = bytearray()
    row_pattern = re.compile(r"^0x[0-9a-fA-F]+\s+((?:[0-9a-fA-F]{8}\s*)+)")
    for line in output.splitlines():
        match = row_pattern.match(line.strip())
        if match:
            for group in match.group(1).split():
                data.extend(bytes.fromhex(group))
    if not data:
        raise RuntimeError(f"could not parse section hex dump:\n{output}")
    return bytes(data)


def vector_words(vector_bytes: bytes) -> list[int]:
    if len(vector_bytes) != VECTOR_BYTES:
        raise RuntimeError(
            f"vector table must be {VECTOR_BYTES} bytes, got {len(vector_bytes)}"
        )
    return [
        int.from_bytes(vector_bytes[offset : offset + 4], "little")
        for offset in range(0, len(vector_bytes), 4)
    ]


def validate_vector_table(
    words: list[int], entries: dict[int, str], symbols: dict[str, int]
) -> dict[str, Any]:
    if len(words) != VECTOR_WORDS:
        raise RuntimeError(f"vector table must contain {VECTOR_WORDS} words")
    if words[0] != CM4_STACK_END:
        raise RuntimeError(
            f"initial SP expected 0x{CM4_STACK_END:08x}, got 0x{words[0]:08x}"
        )
    if words[1] != symbols["quarantine_reset"]:
        raise RuntimeError("reset vector does not match quarantine_reset")
    if words[1] & 1 != 1:
        raise RuntimeError("reset vector is missing the Thumb bit")

    defined_slots: list[int] = []
    reserved_slots: list[int] = []
    for slot in range(2, VECTOR_WORDS):
        irqn = slot - 16
        expected = symbols["quarantine_inert"] if irqn in entries else 0
        if words[slot] != expected:
            raise RuntimeError(
                f"vector slot {slot} (IRQn {irqn}) expected 0x{expected:08x}, "
                f"got 0x{words[slot]:08x}"
            )
        (defined_slots if expected else reserved_slots).append(slot)

    return {
        "word_count": len(words),
        "byte_count": len(words) * 4,
        "alignment_bytes": 1024,
        "initial_sp": f"0x{words[0]:08x}",
        "reset_vector": f"0x{words[1]:08x}",
        "inert_vector": f"0x{symbols['quarantine_inert']:08x}",
        "defined_non_reset_slots": len(defined_slots),
        "reserved_zero_slots": reserved_slots,
    }


def parse_disassembly(output: str) -> dict[str, list[tuple[str, str]]]:
    functions: dict[str, list[tuple[str, str]]] = {}
    current: str | None = None
    function_pattern = re.compile(r"^[0-9a-fA-F]+ <([^>]+)>:$")
    instruction_pattern = re.compile(
        r"^\s*[0-9a-fA-F]+:\s+(?:(?:[0-9a-fA-F]{4}|[0-9a-fA-F]{8})\s+)+"
        r"([a-z][a-z0-9.]*)\s*(.*?)\s*$"
    )
    for line in output.splitlines():
        function_match = function_pattern.match(line.strip())
        if function_match:
            current = function_match.group(1)
            functions[current] = []
            continue
        if current is None:
            continue
        instruction_match = instruction_pattern.match(line)
        if instruction_match:
            mnemonic, operands = instruction_match.groups()
            functions[current].append((mnemonic, operands))
    return functions


def validate_disassembly(output: str) -> dict[str, Any]:
    functions = parse_disassembly(output)
    expected_names = {"quarantine_reset", "quarantine_wait", "quarantine_inert"}
    if set(functions) != expected_names:
        raise RuntimeError(
            f"unexpected executable functions: {sorted(set(functions) - expected_names)}; "
            f"missing: {sorted(expected_names - set(functions))}"
        )

    reset = functions["quarantine_reset"]
    wait = functions["quarantine_wait"]
    inert = functions["quarantine_inert"]
    if [instruction[0] for instruction in reset] != ["cpsid", "b.w"]:
        raise RuntimeError(f"unexpected reset instructions: {reset}")
    if reset[0][1] != "i" or "<quarantine_wait>" not in reset[1][1]:
        raise RuntimeError(f"reset does not mask interrupts then enter wait: {reset}")
    if [instruction[0] for instruction in wait] != ["wfi", "b.w"]:
        raise RuntimeError(f"unexpected wait-loop instructions: {wait}")
    if wait[0][1] or "<quarantine_wait>" not in wait[1][1]:
        raise RuntimeError(
            f"wait loop does not execute WFI and return to itself: {wait}"
        )
    if [instruction[0] for instruction in inert] != ["cpsid", "b.w"]:
        raise RuntimeError(f"unexpected inert-handler instructions: {inert}")
    if inert[0][1] != "i" or "<quarantine_wait>" not in inert[1][1]:
        raise RuntimeError(f"inert handler does not mask then enter wait: {inert}")

    return {
        "functions": sorted(functions),
        "exact_instruction_count": sum(len(rows) for rows in functions.values()),
        "reset_masks_interrupts_first": True,
        "wait_executes_wfi_and_loops": True,
        "every_non_reserved_vector_uses_one_inert_handler": True,
        "memory_or_peripheral_write_instructions": [],
    }


def padded_bank_sha256(compact: bytes) -> str:
    if len(compact) > FLASH_PREFIX_BYTES:
        raise RuntimeError("compact image exceeds the 4 KiB programmed prefix")
    digest = hashlib.sha256()
    digest.update(compact)
    remaining = FULL_BANK_BYTES - len(compact)
    erased_chunk = bytes([ERASED_BYTE]) * (64 * 1024)
    while remaining:
        count = min(remaining, len(erased_chunk))
        digest.update(erased_chunk[:count])
        remaining -= count
    return digest.hexdigest()


def canonical_build_command() -> list[str]:
    return [
        "cargo",
        "-Z",
        f"build-std={BUILD_STD_COMPONENTS}",
        "rustc",
        "--manifest-path",
        str(MANIFEST.relative_to(REPO_ROOT)),
        "--bin",
        PACKAGE,
        "--release",
        "--locked",
        "--offline",
        "--target",
        TARGET,
    ]


def archive_identity(build_version: str | None = None) -> dict:
    minimum = parse_version(VERSION_PATH.read_bytes())
    version = validate_build_version(build_version or minimum, minimum)
    return {
        "version": version,
        "flavor": "default",
        **resolve_source_identity(
            REPO_ROOT,
            input_paths=(
                ".cargo",
                "rust-toolchain.toml",
                "firmware/opta-m4-quarantine",
                "tools/check_m4_quarantine_build_resource.py",
                "tools/firmware_identity.py",
                "tools/firmware_build_archive.py",
            ),
        ),
    }


def collect_report(
    archive_dir: Path | None = None, build_version: str | None = None
) -> dict[str, Any]:
    identity = archive_identity(build_version)
    for tool in (
        "cargo",
        "rustc",
        "llvm-size",
        "llvm-readelf",
        "llvm-objdump",
        "llvm-objcopy",
        "llvm-nm",
    ):
        require_tool(tool)

    source_metadata, interrupt_entries = load_pinned_interrupt_source()
    commands: list[dict[str, Any]] = []
    rustc_version = run_command(["rustc", "--version"])
    cargo_version = run_command(["cargo", "--version"])
    rustc_sysroot = run_command(["rustc", "--print", "sysroot"])
    commands.extend(
        [
            {"name": "rustc_version", **rustc_version},
            {"name": "cargo_version", **cargo_version},
            {"name": "rustc_sysroot", **rustc_sysroot},
        ]
    )
    sysroot = Path(command_output_or_raise(rustc_sysroot).strip())
    rust_src_manifest = (
        sysroot / "lib" / "rustlib" / "src" / "rust" / "library" / "Cargo.toml"
    )
    if not rust_src_manifest.is_file():
        raise RuntimeError(
            "canonical M4 build requires the pinned toolchain rust-src component"
        )

    env = os.environ.copy()
    env["RUSTC_BOOTSTRAP"] = "1"
    env["CARGO_TARGET_DIR"] = str(TARGET_DIR)
    env["CARGO_TARGET_THUMBV7EM_NONE_EABIHF_RUSTFLAGS"] = (
        "-C target-cpu=cortex-m4 -C panic=abort"
    )
    build = run_command(canonical_build_command(), env=env)
    commands.append({"name": "m4_quarantine_canonical_build", **build})
    command_output_or_raise(build)
    if not ARTIFACT.is_file():
        raise RuntimeError(f"M4 artifact missing after build: {ARTIFACT}")

    inspections = {
        "size": run_command(["llvm-size", str(ARTIFACT)]),
        "sections": run_command(["llvm-size", "-A", str(ARTIFACT)]),
        "header": run_command(["llvm-readelf", "-h", str(ARTIFACT)]),
        "attributes": run_command(["llvm-readelf", "-A", str(ARTIFACT)]),
        "symbols": run_command(["llvm-readelf", "-s", str(ARTIFACT)]),
        "vectors": run_command(["llvm-readelf", "-x", ".vector_table", str(ARTIFACT)]),
        "disassembly": run_command(["llvm-objdump", "-d", str(ARTIFACT)]),
        "undefined": run_command(["llvm-nm", "-u", str(ARTIFACT)]),
        "relocations": run_command(["llvm-readelf", "-r", str(ARTIFACT)]),
        "metadata": run_command(
            [
                "cargo",
                "metadata",
                "--manifest-path",
                str(MANIFEST.relative_to(REPO_ROOT)),
                "--format-version",
                "1",
                "--no-deps",
                "--locked",
                "--offline",
            ]
        ),
    }
    for name, command in inspections.items():
        commands.append({"name": f"m4_{name}", **command})
    outputs = {
        name: command_output_or_raise(command) for name, command in inspections.items()
    }

    size = parse_size_summary(outputs["size"])
    sections = parse_size_sections(outputs["sections"])
    header = parse_elf_header(outputs["header"])
    symbols = parse_symbols(outputs["symbols"])
    words = vector_words(parse_hex_section(outputs["vectors"]))
    vector_contract = validate_vector_table(words, interrupt_entries, symbols)
    instruction_contract = validate_disassembly(outputs["disassembly"])

    if size["data"] != 0 or size["bss"] != 0:
        raise RuntimeError(f"quarantine static RAM must be zero, got {size}")
    if size["text"] > FLASH_PREFIX_BYTES:
        raise RuntimeError(f"quarantine allocated Flash exceeds 4 KiB: {size['text']}")
    vector_section = sections.get(".vector_table")
    if vector_section != {"size": VECTOR_BYTES, "addr": FLASH_ORIGIN}:
        raise RuntimeError(f"unexpected vector section: {vector_section}")
    text_section = sections.get(".text")
    if text_section is None or text_section["addr"] != FLASH_ORIGIN + VECTOR_BYTES:
        raise RuntimeError(f"unexpected text section: {text_section}")
    for name in (".rodata", ".data", ".bss", ".uninit", ".got"):
        if sections.get(name, {"size": 0})["size"] != 0:
            raise RuntimeError(f"forbidden nonzero section {name}: {sections[name]}")
    if header.get("machine") != "ARM" or header.get("class") != "ELF32":
        raise RuntimeError(f"unexpected ELF header: {header}")
    if header.get("entry_point") != symbols["quarantine_reset"]:
        raise RuntimeError("ELF entry point does not match quarantine_reset")
    if "Value: cortex-m4" not in outputs["attributes"]:
        raise RuntimeError("ELF attributes do not prove target-cpu=cortex-m4")
    if outputs["undefined"].strip():
        raise RuntimeError(
            f"quarantine artifact has undefined symbols:\n{outputs['undefined']}"
        )
    if "There are no relocations" not in outputs["relocations"]:
        raise RuntimeError("quarantine artifact retains relocations")

    metadata = json.loads(outputs["metadata"])
    packages = metadata.get("packages", [])
    if len(packages) != 1 or packages[0].get("name") != PACKAGE:
        raise RuntimeError("quarantine Cargo metadata contains unexpected packages")
    if packages[0].get("dependencies"):
        raise RuntimeError("quarantine crate must have no Cargo dependencies")
    lock_text = LOCKFILE.read_text(encoding="utf-8")
    if lock_text.count("[[package]]") != 1:
        raise RuntimeError("quarantine lockfile must contain only its own package")

    objcopy = run_command(
        ["llvm-objcopy", "-O", "binary", str(ARTIFACT), str(COMPACT_BINARY)]
    )
    commands.append({"name": "m4_compact_binary", **objcopy})
    command_output_or_raise(objcopy)
    compact = COMPACT_BINARY.read_bytes()
    if len(compact) != size["text"]:
        raise RuntimeError(
            f"compact binary size {len(compact)} does not match allocated Flash {size['text']}"
        )
    if len(compact) > FLASH_PREFIX_BYTES:
        raise RuntimeError("compact binary exceeds first 4 KiB")
    if symbols["__quarantine_image_end"] != FLASH_ORIGIN + len(compact):
        raise RuntimeError("compact binary end does not match linker image-end symbol")

    if archive_identity(build_version) != identity:
        raise RuntimeError("M4 source identity changed while building")
    archive_root = archive_dir or REPO_ROOT / "firmware-builds"
    if not archive_root.is_absolute():
        archive_root = REPO_ROOT / archive_root
    archived_binary = archive_binary(compact, identity, archive_root, package=PACKAGE)

    return {
        "schema": "opta-m4-quarantine-build-resource-report-v1",
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scope": "Cortex-M4 quarantine host build/resource proof only; no target or hardware claim",
        "hardware_actions": [],
        "package": PACKAGE,
        "target": TARGET,
        "artifact": str(ARTIFACT.relative_to(REPO_ROOT)),
        "artifact_sha256": sha256_file(ARTIFACT),
        "compact_binary": str(COMPACT_BINARY.relative_to(REPO_ROOT)),
        "compact_binary_bytes": len(compact),
        "compact_binary_sha256": sha256_bytes(compact),
        "archive_identity": identity,
        "archive_identity_scope": "external build provenance; not embedded in M4 BIN",
        "archive_path": str(archived_binary),
        "expected_full_bank": {
            "origin": f"0x{FLASH_ORIGIN:08x}",
            "end_exclusive": f"0x{FLASH_ORIGIN + FULL_BANK_BYTES:08x}",
            "bytes": FULL_BANK_BYTES,
            "programmed_prefix_limit_bytes": FLASH_PREFIX_BYTES,
            "erased_byte": f"0x{ERASED_BYTE:02x}",
            "sha256": padded_bank_sha256(compact),
        },
        "size_summary": size,
        "sections": sections,
        "symbols": {name: f"0x{value:08x}" for name, value in sorted(symbols.items())},
        "vector_contract": vector_contract,
        "instruction_contract": instruction_contract,
        "interrupt_source": {
            **source_metadata,
            "snapshot": str(INTERRUPT_SOURCE.relative_to(REPO_ROOT)),
            "snapshot_sha256": sha256_file(INTERRUPT_SOURCE),
            "defined_external_irqs": DEFINED_EXTERNAL_IRQS,
            "last_external_irq": LAST_EXTERNAL_IRQ,
        },
        "toolchain": {
            "rustc": command_output_or_raise(rustc_version).strip(),
            "cargo": command_output_or_raise(cargo_version).strip(),
            "rust_src_manifest_sha256": sha256_file(rust_src_manifest),
            "build_std_components": BUILD_STD_COMPONENTS.split(","),
            "cargo_locked": True,
            "cargo_offline": True,
            "target_cpu": "cortex-m4",
            "panic": "abort",
            "isolated_target_dir": str(TARGET_DIR.relative_to(REPO_ROOT)),
        },
        "resource_impact_measured": {
            "m4_programmed_bytes": len(compact),
            "m4_full_bank_owned_bytes": FULL_BANK_BYTES,
            "m4_stack_reserved_bytes": CM4_STACK_BYTES,
            "m4_data_bytes": size["data"],
            "m4_bss_bytes": size["bss"],
            "heap_or_alloc": "none",
            "product_dependencies": [],
            "m7_flash_bytes": 0,
            "m7_d1_bytes": 0,
            "m7_d2_linked_bytes": 0,
            "sram4_bytes": 0,
            "qspi": "not used or touched",
            "backup_registers": "not used or touched",
        },
        "acceptance": {
            "dependency_free": True,
            "complete_stm32h747_cm4_vector_table": True,
            "reserved_vectors_are_zero": True,
            "all_non_reserved_vectors_use_one_inert_handler": True,
            "initial_sp_matches_reserved_d2_alias": True,
            "reset_masks_interrupts_before_wait": True,
            "wait_loop_is_wfi_only": True,
            "allocated_flash_at_most_4096_bytes": True,
            "data_bss_uninit_got_are_zero": True,
            "undefined_symbols_absent": True,
            "relocations_absent": True,
            "heap_absent": True,
            "target_cpu_is_cortex_m4": True,
            "target_cache_isolated_from_m7": True,
            "no_hardware_actions": True,
            "m4_flash_write_authorized": False,
            "quarantine_package_added": False,
            "release_acceptance": False,
        },
        "commands": commands,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--build-std",
        action="store_true",
        required=True,
        help="use the only canonical locked/offline core+compiler_builtins build",
    )
    parser.add_argument(
        "--output", type=Path, help="write the JSON report to this path"
    )
    parser.add_argument(
        "--version",
        dest="build_version",
        help="rebuild this exact version; default allocates the next unused plain version",
    )
    parser.add_argument(
        "--archive-dir",
        type=Path,
        help="retain each validated BIN here (default: firmware-builds/ in this checkout)",
    )
    args = parser.parse_args()

    archive_root = args.archive_dir or REPO_ROOT / "firmware-builds"
    if not archive_root.is_absolute():
        archive_root = REPO_ROOT / archive_root
    minimum = parse_version(VERSION_PATH.read_bytes())
    with allocated_version(
        archive_root, PACKAGE, minimum, args.build_version
    ) as version:
        report = collect_report(archive_root, version)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = args.output if args.output.is_absolute() else REPO_ROOT / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text, encoding="utf-8")
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
