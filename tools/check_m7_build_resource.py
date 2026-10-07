#!/usr/bin/env python3
# Copyright 2026 Nicholas Salois.
#
# Licensed under the Apache License, Version 2.0.
# See the LICENSE file in the repository root for the full license.

"""Build/report the canonical opta-m7 firmware artifact.

This checker performs host/build-resource validation only. It never flashes
hardware, invokes DFU, mutates QSPI, changes option bytes, touches backup
registers, or replaces recovery images.
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
import sys
from pathlib import Path
from typing import Any

try:
    from tools.firmware_build_archive import allocated_version, archive_binary
    from tools.firmware_identity import (
        cargo_environment,
        extract_identity,
        resolve_identity,
        verify_build_dependencies,
    )
except ModuleNotFoundError:
    from firmware_build_archive import allocated_version, archive_binary
    from firmware_identity import (
        cargo_environment,
        extract_identity,
        resolve_identity,
        verify_build_dependencies,
    )

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET = "thumbv7em-none-eabihf"
PACKAGE = "opta-m7"
ARTIFACT = REPO_ROOT / "target" / TARGET / "release" / PACKAGE
FLASH_ORIGIN = 0x0804_0000
FLASH_END = 0x080C_0000
FLASH_BYTES = FLASH_END - FLASH_ORIGIN
HEADROOM_REVIEW_PERCENT = 25
RAM_D1_ORIGIN = 0x2400_0000
RAM_D1_END = 0x2408_0000
RAM_D2_ORIGIN = 0x3000_0000
RAM_D2_END = 0x3004_8000
RAM_D2_M7_ALLOC_END = 0x3004_7C00
CM4_QUARANTINE_STACK_START = RAM_D2_M7_ALLOC_END
CM4_QUARANTINE_STACK_END = RAM_D2_END
CM4_QUARANTINE_STACK_BYTES = 1024
SRAM4_ORIGIN = 0x3800_0000
SRAM4_END = 0x3801_0000
TIM7_IRQ_NUMBER = 55
DEFAULT_ETH_DMA_MPU_BYTES = 64 * 1024
ETHERNET_TRACE_DMA_MPU_BYTES = 128 * 1024
# The perturbations enable ingress tracing through Cargo feature dependencies.
# Their ring layout and required symbols are identical to selecting tracing directly.
ETHERNET_TRACE_FEATURES = {
    "diagnostic-ethernet-ingress",
    "diagnostic-ethernet-rx-ring-16",
    "diagnostic-dcache-disabled",
}
# The release stack reserve is derived from the measured default-product call
# chains plus interrupt and indirect-call allowance. memory.x is the source of
# truth; this constant gates against accidental drift.
STACK_SIZE = 0x10000
STACK_GUARD_BYTES = 16_384
MEASURED_WORST_DIRECT_CALL_CHAIN_BYTES = 15_100
IRQ_NESTING_ALLOWANCE_BYTES = 2_048
BUILD_STD_COMPONENTS = "core,compiler_builtins"
TLS_MOCK_SMOKE_FEATURE = "diagnostic-tls-mock"
LSE_RETENTION_FEATURE = "diagnostic-lse-retention"
STACK_WATERMARK_FEATURE = "diagnostic-stack-watermark"
STACK_GUARD_TRIP_FEATURE = "diagnostic-stack-guard-trip"
WATCHDOG_CPU_BUSY_FEATURE = "diagnostic-watchdog-cpu-busy"
PRE_CLOCK_STALL_FEATURE = "diagnostic-pre-clock-stall"
ACCELERATED_CLOCK_FEATURE = "diagnostic-accelerated-clock"
RUNTIME_COUNTER_FEATURE = "diagnostic-runtime-counters"
CACHE_AGE_FEATURE = "diagnostic-cache-ages"
CACHE_AGE_OBJECTS = {"M7_CACHE_AGE_ENABLE_INPUT": 4, "M7_CACHE_AGE_HEADER": 1088,
                     "M7_CACHE_AGE_BASELINES": 5120, "M7_CACHE_AGE_ROWS": 61440}
CACHE_AGE_GATE = "M7_CACHE_AGE_GATE"
TRUST_HEARTBEAT_FEATURE = "diagnostic-trust-heartbeat-counters"
TRUST_HEARTBEAT_OBJECTS = {"M7_OWNER_COUNTER_RECIPE_INPUT": 4,
    "M7_OWNER_COUNTER_HEADER": 256, "M7_OWNER_TRUST_ROWS": 640,
    "M7_OWNER_HEARTBEAT_ROWS": 320, "M7_OWNER_WATCHDOG_ROWS": 320,
    "M7_OWNER_TRUST_MATERIAL": 4096}
TRUST_HEARTBEAT_GATE = "M7_OWNER_COUNTER_GATE"
PROTOCOL_IDENTIFIER_FEATURE = "diagnostic-protocol-identifiers"
PROTOCOL_IDENTIFIER_OBJECTS = {"M7_PROTOCOL_RECIPE_INPUT": 4,
                               "M7_PROTOCOL_INITIAL_HEADER": 32}
RUNTIME_COUNTER_PROBE_SYMBOLS = {
    "M7_COUNTER_RECIPE_INPUT", "M7_COUNTER_ADMISSION",
    "M7_COUNTER_EVENTS", "M7_COUNTER_EVENT_SUMMARY",
}
RUNTIME_COUNTER_GATE_SYMBOL = "M7_COUNTER_ADMISSION_GATE"
RUNTIME_COUNTER_EVENTS_GATE_SYMBOL = "M7_COUNTER_EVENTS_GATE"
ACCELERATED_CLOCK_PROBE_SYMBOLS = {
    "M7_ACCELERATED_ORIGIN_LOW", "M7_ACCELERATED_ORIGIN_HIGH",
    "M7_ACCELERATED_SETUP_READY", "M7_ACCELERATED_TICK_HZ",
    "M7_ACCELERATED_PERIOD", "M7_ACCELERATED_COUNTER", "M7_ACCELERATED_DIER",
    "M7_ACCELERATED_ALARM_LOW", "M7_ACCELERATED_ALARM_HIGH",
    "M7_ACCELERATED_CHECKINS", "M7_ACCELERATED_TRUST_LOW", "M7_ACCELERATED_TRUST_HIGH",
    "M7_ACCELERATED_UNPUBLISHED_TAGS", "M7_ACCELERATED_WRITE_QUEUE_DEPTH",
    "M7_ACCELERATED_DEPENDENT_NOW_LOW", "M7_ACCELERATED_DEPENDENT_NOW_HIGH",
    "M7_ACCELERATED_DEPENDENTS_READY",
}
STACK_GUARD_TRIP_FIXED_FRAME_SYMBOL = "opta_m7_stack_guard_trip"
TLS_MOCK_SOURCE = REPO_ROOT / "firmware" / "opta-m7" / "src" / "tls_mock.rs"
TLS_MOCK_CA_DER = (
    REPO_ROOT / "firmware" / "opta-m7" / "src" / "certs" / "mock_buchi_test_ca.der"
)
TLS_MOCK_SOURCE_SENTINELS = {
    "TLS_MOCK_PORT": "18_443",
    "TLS_MOCK_DEFAULT_IPV4": "[192, 0, 2, 1]",
    "TLS_MOCK_CA_DER": 'include_bytes!("certs/mock_buchi_test_ca.der")',
    "TLS_MOCK_VERIFIER_TIME": "1_782_388_800",
}
BASE_PROBE_SYMBOLS = {
    "M7_BOOT_SENTINEL",
    "M7_SPIN_COUNT",
    "M7_BOOT_STAGE_PROBE",
    "M7_FAULT_REASON_PROBE",
    "M7_UPTIME_MS",
    "M7_LOOP_MAX_GAP_MS",
    "M7_HEARTBEAT_MAX_GAP_MS",
    "M7_LATE_HEARTBEAT_COUNT",
    "M7_LOOP_TIMING_READY",
    "M7_TLS_LAST_HANDSHAKE_MS",
    "M7_TLS_MAX_HANDSHAKE_MS",
    "M7_RESET_FLAGS_PROBE",
    "M7_WATCHDOG_ARMED",
    "M7_EARLY_IWDG_FAILURE_PROBE",
    "M7_WATCHDOG_STALE_MASK",
    "M7_WATCHDOG_OBSERVED_STALE_SLOTS",
    "M7_WATCHDOG_PUBLIC_FRESH_MASK",
    "M7_WATCHDOG_LAST_KICK_MS",
    "M7_WATCHDOG_REFRESH_COUNT",
    "M7_LAST_FAULT_SEQUENCE_PROBE",
    "M7_INDUCED_HANG_PROBE",
    "M7_IPV4_ADDR",
    "M7_LINK_STATE",
    "M7_ETH_INIT_RETRIES",
    "M7_ENTRY_CCR",
}
TLS_MOCK_TRANSPORT_PROBE_SYMBOLS = {
    "M7_TLS_STAGE",
    "M7_TLS_LAST_ERROR",
    "M7_TLS_COMPLETED_FETCHES",
    "M7_TLS_FAILED_FETCHES",
    "M7_TLS_LAST_HTTP_STATUS",
    "M7_TLS_LAST_CACHE_STATUS",
    "M7_TLS_LAST_SERVER_IPV4",
}
PRODUCT_USB_PROBE_SYMBOLS = {
    "M7_USB_STAGE",
    "M7_USB_LAST_ERROR",
    "M7_USB_CHECKIN_COUNT",
    "M7_USB_PROGRESS_COUNT",
    "M7_USB_LAST_WRITE_LEN",
    "M7_USB_BUS_EVENT_MASK",
    "M7_USB_LAST_BUS_EVENT",
    "M7_USB_BUS_EVENT_COUNT",
    "M7_USB_CONTROL_SETUP_COUNT",
}
PRODUCT_OPCUA_PROBE_SYMBOLS = {
    "M7_OPCUA_STAGE",
    "M7_OPCUA_LAST_ERROR",
    "M7_OPCUA_ACCEPTED_CONNECTIONS",
    "M7_OPCUA_FRAMES_HANDLED",
    "M7_OPCUA_LAST_SERVICE_ID",
    "M7_OPCUA_LAST_STATUS",
    "M7_OPCUA_LAST_READ_NODE",
}
PRODUCT_TRUST_PROBE_SYMBOLS = {
    "M7_BUCHI_TRUST_READY",
    "M7_BUCHI_TRUST_STATE",
    "M7_BUCHI_TRUST_ANCHOR_PRESENT",
    "M7_BUCHI_TRUST_RTC_USABLE",
    "M7_BUCHI_TRUST_LAST_VERIFY_ERROR",
    "M7_BUCHI_TRUST_VERIFY_ATTEMPTS",
    "M7_BUCHI_TRUST_VERIFIED_SESSIONS",
    "M7_BUCHI_TRUST_REVOCATIONS",
}
LSE_RETENTION_PROBE_SYMBOLS = {
    "M7_P05_RTC_CAPTURE_STATUS",
    "M7_P05_RTC_CAPTURE_ATTEMPTS",
    "M7_P05_BOOT_RCC_BDCR",
    "M7_P05_BOOT_RTC_ISR",
    "M7_P05_BOOT_RTC_PRER",
    "M7_P05_BOOT_RTC_SSR_BEFORE",
    "M7_P05_BOOT_RTC_TR",
    "M7_P05_BOOT_RTC_DR",
    "M7_P05_BOOT_RTC_SSR_AFTER",
}
STACK_WATERMARK_PROBE_SYMBOLS = {
    "M7_STACK_WATERMARK_PHASE",
    "M7_STACK_WATERMARK_PAINT_START",
    "M7_STACK_WATERMARK_PAINT_END",
    "M7_STACK_GUARD_BASE",
    "M7_STACK_GUARD_BYTES",
}
WATCHDOG_CPU_BUSY_PROBE_SYMBOLS = {
    "M7_WATCHDOG_CPU_BUSY_START_REFRESH_COUNT",
    "M7_WATCHDOG_CPU_BUSY_END_REFRESH_COUNT",
    "M7_WATCHDOG_CPU_BUSY_ELAPSED_MS",
    "M7_WATCHDOG_CPU_BUSY_PASSED",
}
EARLY_STARTUP_PROBE_SYMBOLS = {"M7_BOOTLOADER_RESET_REASON_PROBE"}
STACK_WATERMARK_GATE_SYMBOL = "M7_STACK_WATERMARK_GATE"
PRODUCT_CACHE_ON_D2_PROBE_SYMBOLS = {
    "M7_CACHE_CCR_PROBE",
    "M7_ETH_DMA_STATUS_PROBE",
    "M7_ETH_RX_DROP_EVENTS",
    "M7_MPU_CTRL_PROBE",
}
PRODUCT_CACHE_ON_D2_LINKER_SYMBOLS = {
    "__eth_dma_start",
    "__eth_dma_end",
    "__cm4_quarantine_stack_start",
    "__cm4_quarantine_stack_end",
}
ETHERNET_TRACE_SYMBOLS = {
    "M7_F8_RX_RING",
    "M7_F8_RX_RING_WRITE_INDEX",
    "M7_F8_TX_RING",
    "M7_F8_TX_RING_WRITE_INDEX",
}
USB_TASK_POOL_SYMBOLS = {
    "usb_console_task": "opta_m7::usb_console::usb_console_task::POOL",
    "usb_device_task": "opta_m7::usb_console::usb_device_task::POOL",
}
WATCHDOG_TASK_POOL_SYMBOL = "opta_m7::watchdog::watchdog_monitor_task::POOL"
WATCHDOG_INTERRUPT_EXECUTOR_SYMBOL = "M7_WATCHDOG_INTERRUPT_EXECUTOR"

# Fixed frames are generated-code measurements, not source estimates. The
# budgets below are the independently reproduced default-product frames plus
# approximately 20 percent. Any unlisted symbol gets the main-frame budget so
# a newly introduced large frame cannot hide behind a more permissive maximum.
MAIN_FIXED_FRAME_SYMBOL = (
    "opta_m7::____embassy_main_task::"
    "____embassy_main_task_inner_function::{closure#0}"
)
WRITE_CONFIG_SLOT_FIXED_FRAME_SYMBOL = "opta_m7::config_storage::write_config_slot"
BUCHI_TLS_FIXED_FRAME_SYMBOL_PREFIX = (
    "opta_m7::buchi_tls_transport::run_buchi_tls_client::<"
)
DEFAULT_GENERATED_FIXED_FRAME_BUDGET_BYTES = 8_544
PINNED_GENERATED_FIXED_FRAME_EXACT_BUDGETS = {
    MAIN_FIXED_FRAME_SYMBOL: 8_544,  # 7,120 B measured, +20%.
    WRITE_CONFIG_SLOT_FIXED_FRAME_SYMBOL: 11_312,  # 9,424 B measured, +20%.
}
PINNED_GENERATED_FIXED_FRAME_PREFIX_BUDGETS = {
    # The product and diagnostic overlays instantiate the same function with
    # different observer types but retain the same generated frame.
    BUCHI_TLS_FIXED_FRAME_SYMBOL_PREFIX: 12_240,  # 10,200 B measured, +20%.
}

OBJDUMP_FUNCTION_RE = re.compile(r"^[0-9a-fA-F]+ <(.+)>:$")
OBJDUMP_SUB_SP_RE = re.compile(
    r"\bsubw?(?:\.w|s)?\s+sp,\s*(?:sp,\s*)?#(0x[0-9a-fA-F]+|\d+)"
)
OBJDUMP_PUSH_RE = re.compile(r"\b(v?push)(?:\.w)?\s+\{([^}]*)\}")
OBJDUMP_INDIRECT_BLX_RE = re.compile(r"\bblx\s+r(?:1[0-5]|[0-9])\b")


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


def require_tool(name: str) -> str:
    path = shutil.which(name)
    if path is None:
        raise RuntimeError(f"required tool not found on PATH: {name}")
    return path


def command_output_or_raise(command: dict[str, Any]) -> str:
    if command["returncode"] != 0:
        argv = " ".join(command["argv"])
        raise RuntimeError(f"command failed: {argv}\n{command['output']}")
    return command["output"]


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def validate_tls_mock_source_boundary() -> dict[str, Any]:
    """Prove bench-only trust literals stay in the diagnostic module.

    The ELF checks below prove whether the diagnostic module was linked. This
    source-topology check catches a later copy of one of its trust/time/network
    assumptions into another firmware module before linker reachability can
    obscure the regression.
    """

    if not TLS_MOCK_SOURCE.is_file():
        raise RuntimeError(f"TLS mock diagnostic source not found: {TLS_MOCK_SOURCE}")
    if not TLS_MOCK_CA_DER.is_file():
        raise RuntimeError(f"TLS mock CA not found: {TLS_MOCK_CA_DER}")

    diagnostic_source = TLS_MOCK_SOURCE.read_text()
    missing = [
        name
        for name, fragment in TLS_MOCK_SOURCE_SENTINELS.items()
        if fragment not in diagnostic_source
    ]
    if missing:
        raise RuntimeError(
            "TLS mock source boundary sentinels missing from diagnostic module: "
            + ", ".join(sorted(missing))
        )

    leaks: list[str] = []
    source_root = TLS_MOCK_SOURCE.parent
    for path in sorted(source_root.rglob("*.rs")):
        if path == TLS_MOCK_SOURCE:
            continue
        source = path.read_text()
        for name, fragment in TLS_MOCK_SOURCE_SENTINELS.items():
            if fragment in source:
                leaks.append(f"{path.relative_to(REPO_ROOT)}: {name}")
    if leaks:
        raise RuntimeError(
            "TLS mock bench assumptions escaped the diagnostic module:\n"
            + "\n".join(leaks)
        )

    return {
        "diagnostic_source": str(TLS_MOCK_SOURCE.relative_to(REPO_ROOT)),
        "mock_ca_der": str(TLS_MOCK_CA_DER.relative_to(REPO_ROOT)),
        "sentinels_confined_to_diagnostic_source": True,
        "sentinels": sorted(TLS_MOCK_SOURCE_SENTINELS),
    }


def parse_size_summary(output: str) -> dict[str, Any]:
    lines = [line.strip() for line in output.splitlines() if line.strip()]
    if len(lines) < 2:
        raise RuntimeError(f"unexpected llvm-size summary output:\n{output}")
    parts = lines[-1].split()
    if len(parts) < 6:
        raise RuntimeError(f"unexpected llvm-size summary row: {lines[-1]}")
    return {
        "text": int(parts[0]),
        "data": int(parts[1]),
        "bss": int(parts[2]),
        "dec": int(parts[3]),
        "hex": parts[4],
        "filename": parts[5],
    }


def parse_size_sections(output: str) -> dict[str, dict[str, int]]:
    sections: dict[str, dict[str, int]] = {}
    for line in output.splitlines():
        stripped = line.strip()
        if (
            not stripped
            or stripped.startswith("section")
            or stripped.startswith("Total")
        ):
            continue
        parts = stripped.split()
        if len(parts) != 3:
            continue
        name, size, addr = parts
        try:
            sections[name] = {"size": int(size, 0), "addr": int(addr, 0)}
        except ValueError:
            continue
    return sections


def section_bytes_in_range(
    sections: dict[str, dict[str, int]], start: int, end: int
) -> int:
    total = 0
    for section in sections.values():
        addr = section["addr"]
        size = section["size"]
        if size == 0:
            continue
        section_end = addr + size
        overlap_start = max(addr, start)
        overlap_end = min(section_end, end)
        if overlap_start < overlap_end:
            total += overlap_end - overlap_start
    return total


def parse_readelf_header(output: str) -> dict[str, Any]:
    header: dict[str, Any] = {}
    for line in output.splitlines():
        if "Entry point address:" in line:
            header["entry_point"] = int(line.split(":", 1)[1].strip(), 16)
        elif "Machine:" in line:
            header["machine"] = line.split(":", 1)[1].strip()
        elif "Flags:" in line:
            header["flags"] = line.split(":", 1)[1].strip()
    return header


def parse_readelf_symbols(output: str, names: set[str]) -> dict[str, int]:
    symbols: dict[str, int] = {}
    symbol_re = re.compile(
        r"^\s*\d+:\s+([0-9a-fA-F]+)\s+\d+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\S+)\s*$"
    )
    for line in output.splitlines():
        match = symbol_re.match(line)
        if not match:
            continue
        value, name = match.groups()
        if name in names:
            symbols[name] = int(value, 16)
    return symbols


def parse_exact_demangled_elf_symbols(
    output: str, names: set[str]
) -> dict[str, dict[str, Any]]:
    """Parse exact demangled ELF symbol values and ``st_size`` fields."""

    symbols: dict[str, dict[str, Any]] = {}
    for line in output.splitlines():
        parts = line.strip().split(maxsplit=7)
        if len(parts) != 8 or not parts[0].endswith(":"):
            continue
        number, value, size, symbol_type, binding, visibility, section, name = parts
        if name not in names:
            continue
        if name in symbols:
            raise RuntimeError(f"duplicate exact demangled ELF symbol: {name}")
        try:
            symbols[name] = {
                "symbol_table_index": int(number[:-1]),
                "address": int(value, 16),
                "size_bytes": int(size, 10),
                "type": symbol_type,
                "binding": binding,
                "visibility": visibility,
                "section": section,
            }
        except ValueError as exc:
            raise RuntimeError(
                f"invalid exact demangled ELF symbol row for {name}"
            ) from exc
    missing = sorted(names - set(symbols))
    if missing:
        raise RuntimeError(
            "missing exact demangled ELF symbols required for resource "
            f"measurement: {missing}"
        )
    return symbols


def parse_vector_table_words(output: str) -> dict[str, int]:
    """Parse startup and dedicated watchdog vectors from the vector table."""
    section_bytes = bytearray()
    hex_re = re.compile(r"^0x[0-9a-fA-F]+\s+((?:[0-9a-fA-F]{8}\s*)+)")
    for line in output.splitlines():
        match = hex_re.match(line.strip())
        if not match:
            continue
        for word in match.group(1).split():
            section_bytes.extend(bytes.fromhex(word))
    tim7_offset = (16 + TIM7_IRQ_NUMBER) * 4
    if len(section_bytes) < tim7_offset + 4:
        raise RuntimeError(f"unexpected .vector_table hex dump:\n{output}")
    return {
        "initial_sp": int.from_bytes(section_bytes[0:4], "little"),
        "reset_vector": int.from_bytes(section_bytes[4:8], "little"),
        "tim7_irq_number": TIM7_IRQ_NUMBER,
        "tim7_vector": int.from_bytes(
            section_bytes[tim7_offset : tim7_offset + 4], "little"
        ),
    }


def pushed_register_bytes(registers: str) -> int:
    """Return bytes reserved by one integer or floating-point push list."""

    total = 0
    for item in registers.split(","):
        item = item.strip()
        if not item:
            continue
        if "-" in item:
            first, last = (part.strip() for part in item.split("-", 1))
            first_index = int(re.sub(r"[^0-9]", "", first) or 0)
            last_index = int(re.sub(r"[^0-9]", "", last) or 0)
            register_count = last_index - first_index + 1
            register_bytes = 8 if first.startswith("d") else 4
            total += register_count * register_bytes
        else:
            total += 8 if item.startswith("d") else 4
    return total


def parse_generated_fixed_frames(
    output: str,
) -> tuple[dict[str, int], list[str]]:
    """Measure fixed frames and identify functions with indirect dispatch.

    This intentionally matches the retained measurement method: sum every
    immediate `sub sp` and every `push`/`vpush` in a symbol. Summing all stack
    decrements is conservative within a symbol. It does not infer call edges,
    and functions containing register-indirect `blx` remain explicit because
    static direct-call depth cannot be a proof of maximum stack use.
    """

    frames: dict[str, int] = {}
    indirect_dispatch_symbols: set[str] = set()
    current_symbol: str | None = None
    for line in output.splitlines():
        function_match = OBJDUMP_FUNCTION_RE.match(line.strip())
        if function_match:
            current_symbol = function_match.group(1)
            frames.setdefault(current_symbol, 0)
            continue
        if current_symbol is None:
            continue
        for match in OBJDUMP_SUB_SP_RE.finditer(line):
            frames[current_symbol] += int(match.group(1), 0)
        for match in OBJDUMP_PUSH_RE.finditer(line):
            frames[current_symbol] += pushed_register_bytes(match.group(2))
        if OBJDUMP_INDIRECT_BLX_RE.search(line):
            indirect_dispatch_symbols.add(current_symbol)
    return frames, sorted(indirect_dispatch_symbols)


def parse_generated_sub_sp_adjustments(output: str) -> dict[str, list[int]]:
    """Return each immediate generated stack adjustment per symbol."""

    adjustments: dict[str, list[int]] = {}
    current_symbol: str | None = None
    for line in output.splitlines():
        function_match = OBJDUMP_FUNCTION_RE.match(line.strip())
        if function_match:
            current_symbol = function_match.group(1)
            adjustments.setdefault(current_symbol, [])
            continue
        if current_symbol is None:
            continue
        adjustments[current_symbol].extend(
            int(match.group(1), 0) for match in OBJDUMP_SUB_SP_RE.finditer(line)
        )
    return adjustments


def evaluate_generated_fixed_frame_budgets(
    frames: dict[str, int],
    features: list[str],
) -> tuple[list[str], list[dict[str, Any]]]:
    """Return budget failures and all measured symbols, largest first."""

    failures: list[str] = []
    guard_trip_selected = STACK_GUARD_TRIP_FEATURE in features
    if guard_trip_selected and STACK_GUARD_TRIP_FIXED_FRAME_SYMBOL not in frames:
        failures.append(
            "missing feature-scoped stack-guard-trip generated-frame symbol: "
            f"{STACK_GUARD_TRIP_FIXED_FRAME_SYMBOL}"
        )
    for symbol in sorted(PINNED_GENERATED_FIXED_FRAME_EXACT_BUDGETS):
        if symbol not in frames:
            failures.append(f"missing pinned generated-frame symbol: {symbol}")
    for prefix in sorted(PINNED_GENERATED_FIXED_FRAME_PREFIX_BUDGETS):
        if not any(symbol.startswith(prefix) for symbol in frames):
            failures.append(f"missing pinned generated-frame symbol prefix: {prefix}")

    measurements: list[dict[str, Any]] = []
    for symbol, frame_bytes in frames.items():
        budget_bytes = PINNED_GENERATED_FIXED_FRAME_EXACT_BUDGETS.get(symbol)
        if budget_bytes is None:
            budget_bytes = next(
                (
                    budget
                    for prefix, budget in PINNED_GENERATED_FIXED_FRAME_PREFIX_BUDGETS.items()
                    if symbol.startswith(prefix)
                ),
                None,
            )
        pinned = budget_bytes is not None
        if budget_bytes is None:
            budget_bytes = DEFAULT_GENERATED_FIXED_FRAME_BUDGET_BYTES
        feature_scoped_exemption = (
            guard_trip_selected and symbol == STACK_GUARD_TRIP_FIXED_FRAME_SYMBOL
        )
        within_budget = frame_bytes <= budget_bytes
        passes = within_budget or feature_scoped_exemption
        measurements.append(
            {
                "symbol": symbol,
                "fixed_frame_bytes": frame_bytes,
                "budget_bytes": budget_bytes,
                "pinned_budget": pinned,
                "feature_scoped_exemption": feature_scoped_exemption,
                "within_budget": within_budget,
                "passes": passes,
            }
        )
        if not passes:
            failures.append(
                "generated fixed frame exceeds budget: "
                f"{symbol}: {frame_bytes} B > {budget_bytes} B"
            )
    measurements.sort(
        key=lambda measurement: (
            -measurement["fixed_frame_bytes"],
            measurement["symbol"],
        )
    )
    return failures, measurements


def evaluate_stack_guard_trip_frame_contract(
    *,
    features: list[str],
    frames: dict[str, int],
    sub_sp_adjustments: dict[str, list[int]],
) -> tuple[list[str], dict[str, Any]]:
    """Require one emitted oversized adjustment in the diagnostic trip symbol."""

    selected = STACK_GUARD_TRIP_FEATURE in features
    contract: dict[str, Any] = {
        "feature": STACK_GUARD_TRIP_FEATURE,
        "selected": selected,
        "symbol": STACK_GUARD_TRIP_FIXED_FRAME_SYMBOL,
        "exempt_from_per_symbol_budget_only_when_selected": True,
        "included_in_permitted_fixed_frame_budgets": False,
    }
    if not selected:
        if STACK_GUARD_TRIP_FIXED_FRAME_SYMBOL in frames:
            return [
                "default/product build links diagnostic stack-guard-trip symbol: "
                f"{STACK_GUARD_TRIP_FIXED_FRAME_SYMBOL}"
            ], contract
        return [], contract

    failures: list[str] = []
    frame_bytes = frames.get(STACK_GUARD_TRIP_FIXED_FRAME_SYMBOL)
    adjustments = sub_sp_adjustments.get(STACK_GUARD_TRIP_FIXED_FRAME_SYMBOL, [])
    oversized_adjustments = [value for value in adjustments if value > STACK_GUARD_BYTES]
    contract.update(
        {
            "fixed_frame_bytes": frame_bytes,
            "sub_sp_adjustments_bytes": adjustments,
            "oversized_sub_sp_adjustments_bytes": oversized_adjustments,
        }
    )
    if frame_bytes is None:
        failures.append(
            "stack-guard-trip feature is missing its generated-frame symbol: "
            f"{STACK_GUARD_TRIP_FIXED_FRAME_SYMBOL}"
        )
    elif frame_bytes <= STACK_GUARD_BYTES:
        failures.append(
            "stack-guard-trip generated fixed frame does not exceed guard: "
            f"{frame_bytes} B <= {STACK_GUARD_BYTES} B"
        )
    if len(oversized_adjustments) != 1:
        failures.append(
            "stack-guard-trip must emit exactly one sub sp adjustment larger than "
            f"the guard, got {oversized_adjustments}"
        )
    return failures, contract


def permitted_generated_fixed_frame_budgets() -> list[int]:
    """Return product frame budgets coupled to the MPU guard invariant."""

    return [
        DEFAULT_GENERATED_FIXED_FRAME_BUDGET_BYTES,
        *PINNED_GENERATED_FIXED_FRAME_EXACT_BUDGETS.values(),
        *PINNED_GENERATED_FIXED_FRAME_PREFIX_BUDGETS.values(),
    ]


def evaluate_stack_guard_contract(
    *,
    stack_size: int,
    stack_guard_bytes: int,
    permitted_fixed_frame_budgets: list[int],
    measured_worst_chain_bytes: int,
    irq_allowance_bytes: int,
) -> tuple[list[str], dict[str, Any]]:
    """Couple frame budgets, the MPU band, and usable reserved stack."""

    max_permitted_frame_bytes = max(permitted_fixed_frame_budgets)
    usable_stack_bytes = stack_size - stack_guard_bytes
    required_usable_stack_bytes = measured_worst_chain_bytes + irq_allowance_bytes
    failures: list[str] = []
    if stack_guard_bytes < max_permitted_frame_bytes:
        failures.append(
            "stack guard is smaller than the maximum permitted generated frame: "
            f"{stack_guard_bytes} B < {max_permitted_frame_bytes} B"
        )
    if usable_stack_bytes < required_usable_stack_bytes:
        failures.append(
            "usable stack after guard is smaller than measured chain plus IRQ allowance: "
            f"{usable_stack_bytes} B < {required_usable_stack_bytes} B"
        )
    return failures, {
        "stack_reserve_bytes": stack_size,
        "stack_guard_bytes": stack_guard_bytes,
        "usable_stack_bytes": usable_stack_bytes,
        "max_permitted_generated_frame_bytes": max_permitted_frame_bytes,
        "measured_worst_direct_call_chain_bytes": measured_worst_chain_bytes,
        "irq_nesting_allowance_bytes": irq_allowance_bytes,
        "required_usable_stack_bytes": required_usable_stack_bytes,
        "indirect_call_margin_bytes": usable_stack_bytes - required_usable_stack_bytes,
        "guard_covers_max_permitted_frame": stack_guard_bytes
        >= max_permitted_frame_bytes,
        "measured_chain_plus_irq_fits_usable_stack": usable_stack_bytes
        >= required_usable_stack_bytes,
    }


def compact_command_outputs(
    commands: list[dict[str, Any]], limit: int = 2400
) -> list[dict[str, Any]]:
    compacted: list[dict[str, Any]] = []
    for command in commands:
        entry = dict(command)
        output = entry.get("output")
        if isinstance(output, str) and len(output) > limit:
            head_len = limit // 2
            tail_len = limit - head_len
            entry["output"] = (
                output[:head_len]
                + "\n... <truncated by check_m7_build_resource.py> ...\n"
                + output[-tail_len:]
            )
            entry["output_truncated"] = True
            entry["output_original_bytes"] = len(output.encode())
        compacted.append(entry)
    return compacted


def canonical_build_std_command(features: list[str]) -> list[str]:
    command = [
        "cargo",
        "-Z",
        f"build-std={BUILD_STD_COMPONENTS}",
        "rustc",
        "-p",
        PACKAGE,
        "--release",
        "--locked",
        "--offline",
        "--target",
        TARGET,
    ]
    for feature in features:
        command.extend(["--features", feature])
    command.extend(
        [
            "--",
            "-C",
            "target-cpu=cortex-m7",
            "-C",
            "panic=abort",
        ]
    )
    return command


def required_probe_symbols(features: list[str]) -> set[str]:
    # This helper never passes --no-default-features, so every artifact carries
    # the opta-m7 `product` default composition. Feature arguments are additive
    # diagnostic overlays only.
    symbols = (
        set(BASE_PROBE_SYMBOLS)
        | PRODUCT_USB_PROBE_SYMBOLS
        | PRODUCT_OPCUA_PROBE_SYMBOLS
        | PRODUCT_TRUST_PROBE_SYMBOLS
        | PRODUCT_CACHE_ON_D2_PROBE_SYMBOLS
    )
    if TLS_MOCK_SMOKE_FEATURE in features:
        symbols |= TLS_MOCK_TRANSPORT_PROBE_SYMBOLS
    if LSE_RETENTION_FEATURE in features:
        symbols |= LSE_RETENTION_PROBE_SYMBOLS
    if STACK_WATERMARK_FEATURE in features:
        symbols |= STACK_WATERMARK_PROBE_SYMBOLS
    if WATCHDOG_CPU_BUSY_FEATURE in features:
        symbols |= WATCHDOG_CPU_BUSY_PROBE_SYMBOLS
    if PRE_CLOCK_STALL_FEATURE in features:
        symbols |= EARLY_STARTUP_PROBE_SYMBOLS
    if any(feature in features for feature in (ACCELERATED_CLOCK_FEATURE, RUNTIME_COUNTER_FEATURE, CACHE_AGE_FEATURE, TRUST_HEARTBEAT_FEATURE, PROTOCOL_IDENTIFIER_FEATURE)):
        symbols |= ACCELERATED_CLOCK_PROBE_SYMBOLS
    if RUNTIME_COUNTER_FEATURE in features:
        symbols |= RUNTIME_COUNTER_PROBE_SYMBOLS
    if CACHE_AGE_FEATURE in features:
        symbols |= set(CACHE_AGE_OBJECTS)
    if TRUST_HEARTBEAT_FEATURE in features:
        symbols |= set(TRUST_HEARTBEAT_OBJECTS)
    if PROTOCOL_IDENTIFIER_FEATURE in features:
        symbols |= set(PROTOCOL_IDENTIFIER_OBJECTS)
    return symbols


def evaluate_resource_margins(
    flash_used_bytes: int, d1_static_end: int | None, stack_limit: int | None,
) -> tuple[list[str], dict[str, Any], list[str]]:
    """Reject capacity violations; report advisory headroom after reservations."""
    failures: list[str] = []
    warnings: list[str] = []
    margins: dict[str, Any] = {}
    if not (
        d1_static_end is not None and stack_limit is not None
        and RAM_D1_ORIGIN <= d1_static_end <= stack_limit <= RAM_D1_END
    ):
        failures.append("M7 D1 static allocation/stack bounds are missing, invalid, or overlapping")
    else:
        margins["ram_d1"] = {
            "capacity_bytes": RAM_D1_END - RAM_D1_ORIGIN,
            "used_bytes": d1_static_end - RAM_D1_ORIGIN + RAM_D1_END - stack_limit,
            "static_extent_bytes": d1_static_end - RAM_D1_ORIGIN,
            "stack_reserved_bytes": RAM_D1_END - stack_limit,
        }
    margins["flash"] = {"capacity_bytes": FLASH_BYTES, "used_bytes": flash_used_bytes}
    for region, margin in margins.items():
        capacity, used = margin["capacity_bytes"], margin["used_bytes"]
        free = capacity - used
        fits = 0 <= used <= capacity
        review = free * 100 < capacity * HEADROOM_REVIEW_PERCENT
        margin.update({
            "free_bytes": free,
            "free_percent": free * 100.0 / capacity,
            "capacity_passed": fits,
            "review_threshold_percent": HEADROOM_REVIEW_PERCENT,
            "review_threshold_bytes": capacity * HEADROOM_REVIEW_PERCENT // 100,
            "review_required": review,
        })
        if not fits:
            failures.append(f"M7 {region} capacity exceeded or invalid: used={used} capacity={capacity}")
        elif review:
            warnings.append(
                f"M7 {region} headroom review required: {free} B free "
                f"({margin['free_percent']:.2f}%), below {HEADROOM_REVIEW_PERCENT}%; "
                "document the remaining-byte budget and evidence before release acceptance"
            )
    return failures, margins, warnings


def eth_dma_mpu_bytes(features: list[str]) -> int:
    return (
        ETHERNET_TRACE_DMA_MPU_BYTES
        if not ETHERNET_TRACE_FEATURES.isdisjoint(features)
        else DEFAULT_ETH_DMA_MPU_BYTES
    )


def build_artifact(
    features: list[str], identity: dict | None = None
) -> tuple[str, list[dict[str, Any]]]:
    """Build only through the pinned, explicit build-std release path.

    The former target-dependent fallback first tried the direct Cargo alias and
    silently selected a different artifact when the prebuilt target `core`
    component happened to be installed. Release resource evidence must not
    depend on host component inventory, so there is no direct-build probe here.
    """
    env = os.environ.copy()
    for name in (
        "RUSTFLAGS", "CARGO_ENCODED_RUSTFLAGS", "CARGO_BUILD_RUSTFLAGS",
        "CARGO_TARGET_THUMBV7EM_NONE_EABIHF_RUSTFLAGS",
    ):
        if env.get(name):
            raise ValueError(f"canonical build rejects ambient compiler flags: {name}")
    env.update(cargo_environment(identity or resolve_identity(REPO_ROOT, features)))
    # The report has always described this exact target directory. Prevent a
    # caller's target override from making us inspect an older unrelated ELF.
    env["CARGO_TARGET_DIR"] = str(REPO_ROOT / "target")
    env["RUSTC_BOOTSTRAP"] = "1"
    command = run_command(canonical_build_std_command(features), env=env)
    commands = [{"name": "m7_build_canonical_build_std", **command}]
    if command["returncode"] == 0:
        return "build-std", commands
    return "failed", commands


def collect_report(args: argparse.Namespace) -> dict[str, Any]:
    require_tool("cargo")
    require_tool("rustc")
    require_tool("llvm-size")
    require_tool("llvm-readelf")
    require_tool("llvm-objdump")
    require_tool("llvm-objcopy")

    identity = resolve_identity(
        REPO_ROOT,
        args.features,
        release_candidate=getattr(args, "release_candidate", False),
        build_version=getattr(args, "build_version", None),
    )

    source_boundary = validate_tls_mock_source_boundary()

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
            "canonical build-std requires the pinned toolchain rust-src component: "
            f"missing {rust_src_manifest}"
        )

    build_mode, build_commands = build_artifact(args.features, identity)
    commands.extend(build_commands)
    if build_mode == "failed":
        command_output_or_raise(build_commands[-1])

    if not ARTIFACT.exists():
        raise RuntimeError(f"artifact not found: {ARTIFACT}")

    if resolve_identity(REPO_ROOT, args.features, build_version=identity["version"]) != identity:
        raise RuntimeError("firmware source identity changed during the build")
    dependency_inputs = verify_build_dependencies(REPO_ROOT, ARTIFACT.with_suffix(".d"))
    binary_path = ARTIFACT.with_suffix(".bin")
    binary_command = run_command(
        ["llvm-objcopy", "-O", "binary", str(ARTIFACT), str(binary_path)]
    )
    command_output_or_raise(binary_command)
    commands.append({"name": "extract_loadable_binary", **binary_command})
    binary = binary_path.read_bytes()
    embedded_identity = extract_identity(binary, identity)

    size_summary_cmd = run_command(["llvm-size", str(ARTIFACT)])
    size_sections_cmd = run_command(["llvm-size", "-A", str(ARTIFACT)])
    readelf_header_cmd = run_command(["llvm-readelf", "-h", str(ARTIFACT)])
    readelf_symbols_cmd = run_command(["llvm-readelf", "-s", str(ARTIFACT)])
    readelf_demangled_symbols_cmd = run_command(
        ["llvm-readelf", "-sW", "--demangle", str(ARTIFACT)]
    )
    readelf_vector_cmd = run_command(
        ["llvm-readelf", "-x", ".vector_table", str(ARTIFACT)]
    )
    objdump_disassembly_cmd = run_command(
        ["llvm-objdump", "-d", "--demangle", str(ARTIFACT)]
    )
    commands.extend(
        [
            {"name": "llvm_size", **size_summary_cmd},
            {"name": "llvm_size_sections", **size_sections_cmd},
            {"name": "llvm_readelf_header", **readelf_header_cmd},
            {"name": "llvm_readelf_symbols", **readelf_symbols_cmd},
            {
                "name": "llvm_readelf_demangled_symbols",
                **readelf_demangled_symbols_cmd,
            },
            {"name": "llvm_readelf_vector_table", **readelf_vector_cmd},
            {"name": "llvm_objdump_disassembly", **objdump_disassembly_cmd},
        ]
    )

    size_summary = parse_size_summary(command_output_or_raise(size_summary_cmd))
    sections = parse_size_sections(command_output_or_raise(size_sections_cmd))
    d1_sram_bytes = section_bytes_in_range(sections, RAM_D1_ORIGIN, RAM_D1_END)
    d2_sram_bytes = section_bytes_in_range(sections, RAM_D2_ORIGIN, RAM_D2_END)
    sram4_bytes = section_bytes_in_range(sections, SRAM4_ORIGIN, SRAM4_END)
    header = parse_readelf_header(command_output_or_raise(readelf_header_cmd))
    vector_words = parse_vector_table_words(command_output_or_raise(readelf_vector_cmd))
    objdump_disassembly = command_output_or_raise(objdump_disassembly_cmd)
    generated_fixed_frames, indirect_dispatch_symbols = parse_generated_fixed_frames(
        objdump_disassembly
    )
    generated_sub_sp_adjustments = parse_generated_sub_sp_adjustments(objdump_disassembly)
    readelf_demangled_symbols = command_output_or_raise(readelf_demangled_symbols_cmd)
    usb_task_pool_symbols = parse_exact_demangled_elf_symbols(
        readelf_demangled_symbols, set(USB_TASK_POOL_SYMBOLS.values())
    )
    watchdog_runtime_symbols = parse_exact_demangled_elf_symbols(
        readelf_demangled_symbols,
        {
            WATCHDOG_TASK_POOL_SYMBOL,
            WATCHDOG_INTERRUPT_EXECUTOR_SYMBOL,
        },
    )
    generated_frame_failures, generated_frame_measurements = (
        evaluate_generated_fixed_frame_budgets(generated_fixed_frames, args.features)
    )
    guard_trip_frame_failures, guard_trip_frame_contract = (
        evaluate_stack_guard_trip_frame_contract(
            features=args.features,
            frames=generated_fixed_frames,
            sub_sp_adjustments=generated_sub_sp_adjustments,
        )
    )
    stack_guard_contract_failures, stack_guard_contract = evaluate_stack_guard_contract(
        stack_size=STACK_SIZE,
        stack_guard_bytes=STACK_GUARD_BYTES,
        permitted_fixed_frame_budgets=permitted_generated_fixed_frame_budgets(),
        measured_worst_chain_bytes=MEASURED_WORST_DIRECT_CALL_CHAIN_BYTES,
        irq_allowance_bytes=IRQ_NESTING_ALLOWANCE_BYTES,
    )
    cache_on_d2_enabled = True
    probe_symbol_names = required_probe_symbols(args.features)
    ethernet_trace_symbol_names = (
        ETHERNET_TRACE_SYMBOLS
        if not ETHERNET_TRACE_FEATURES.isdisjoint(args.features)
        else set()
    )
    linker_symbol_names = PRODUCT_CACHE_ON_D2_LINKER_SYMBOLS
    startup_symbol_names = {
        "__vector_table",
        "__STACK_START",
        "__RESET_VECTOR",
        "Reset",
        "main",
        "HardFault",
        "MemoryManagement",
        "TIM7",
        "DefaultHandler",
        "__stack_top",
        "__stack_limit",
        "__stack_size",
        "__ebss",
        "__sheap",
    }
    if STACK_WATERMARK_FEATURE in args.features:
        startup_symbol_names.add(STACK_WATERMARK_GATE_SYMBOL)
    symbols = parse_readelf_symbols(
        command_output_or_raise(readelf_symbols_cmd),
        startup_symbol_names
        | probe_symbol_names
        | linker_symbol_names
        | ethernet_trace_symbol_names
        | TLS_MOCK_TRANSPORT_PROBE_SYMBOLS
        | LSE_RETENTION_PROBE_SYMBOLS
        | WATCHDOG_CPU_BUSY_PROBE_SYMBOLS
        | ACCELERATED_CLOCK_PROBE_SYMBOLS
        | RUNTIME_COUNTER_PROBE_SYMBOLS | {RUNTIME_COUNTER_GATE_SYMBOL, RUNTIME_COUNTER_EVENTS_GATE_SYMBOL}
        | set(CACHE_AGE_OBJECTS) | {CACHE_AGE_GATE}
        | set(TRUST_HEARTBEAT_OBJECTS) | {TRUST_HEARTBEAT_GATE}
        | {"M7_ACCELERATED_CLOCK_GATE", "M7_ACCELERATED_DEPENDENTS_READY_GATE"},
    )

    failures: list[str] = []
    vector_table = sections.get(".vector_table")
    reset = symbols.get("Reset")
    entry_main = symbols.get("main")
    stack_top = symbols.get("__stack_top")
    stack_limit = symbols.get("__stack_limit")
    stack_size = symbols.get("__stack_size")
    stack_guard_handler = symbols.get("MemoryManagement")
    tim7_handler = symbols.get("TIM7")
    sheap = symbols.get("__sheap")
    probe_symbols = {name: symbols.get(name) for name in sorted(probe_symbol_names)}
    eth_dma_start = symbols.get("__eth_dma_start")
    eth_dma_end = symbols.get("__eth_dma_end")
    cm4_stack_start = symbols.get("__cm4_quarantine_stack_start")
    cm4_stack_end = symbols.get("__cm4_quarantine_stack_end")
    expected_eth_dma_mpu_bytes = eth_dma_mpu_bytes(args.features)
    # The BIN extent also charges load-address gaps and alignment padding.
    flash_used_bytes = max(size_summary["text"] + size_summary["data"], len(binary))
    margin_failures, resource_margins, resource_warnings = evaluate_resource_margins(
        flash_used_bytes, sheap, stack_limit
    )
    failures.extend(margin_failures)
    tls_mock_feature_enabled = TLS_MOCK_SMOKE_FEATURE in args.features
    tls_mock_probe_symbols_present = sorted(
        name for name in TLS_MOCK_TRANSPORT_PROBE_SYMBOLS if name in symbols
    )
    lse_retention_feature_enabled = LSE_RETENTION_FEATURE in args.features
    lse_retention_probe_symbols_present = sorted(
        name for name in LSE_RETENTION_PROBE_SYMBOLS if name in symbols
    )
    watchdog_cpu_busy_feature_enabled = WATCHDOG_CPU_BUSY_FEATURE in args.features
    watchdog_cpu_busy_probe_symbols_present = sorted(
        name for name in WATCHDOG_CPU_BUSY_PROBE_SYMBOLS if name in symbols
    )
    usb_task_pools = {
        task: {
            "symbol": symbol,
            **usb_task_pool_symbols[symbol],
        }
        for task, symbol in USB_TASK_POOL_SYMBOLS.items()
    }
    usb_task_pool_total_bytes = sum(
        measurement["size_bytes"] for measurement in usb_task_pools.values()
    )
    watchdog_task_pool = watchdog_runtime_symbols[WATCHDOG_TASK_POOL_SYMBOL]
    watchdog_interrupt_executor = watchdog_runtime_symbols[
        WATCHDOG_INTERRUPT_EXECUTOR_SYMBOL
    ]
    executor_features_source = (REPO_ROOT / "firmware/opta-m7/Cargo.toml").read_text()
    dual_executor_pender_enabled = all(
        feature in executor_features_source
        for feature in ('"executor-thread"', '"executor-interrupt"')
    )
    standalone_pender_symbol_after_lto = any(
        line.strip().endswith(" __pender")
        for line in readelf_demangled_symbols.splitlines()
    )
    sev_instruction_count = len(re.findall(r"\bsev\b", objdump_disassembly))
    artifact_bytes = ARTIFACT.read_bytes()
    mock_ca_der_embedded = TLS_MOCK_CA_DER.read_bytes() in artifact_bytes

    if vector_table is None:
        failures.append("missing .vector_table section")
    elif vector_table["addr"] != FLASH_ORIGIN:
        failures.append(
            f".vector_table expected 0x{FLASH_ORIGIN:08x}, got 0x{vector_table['addr']:08x}"
        )
    elif vector_table["size"] <= 8:
        failures.append(f".vector_table is still only {vector_table['size']} bytes")
    if reset is None or not (FLASH_ORIGIN <= reset < FLASH_END):
        failures.append(f"Reset outside M7 Flash window: {reset!r}")
    if entry_main is None or not (FLASH_ORIGIN <= entry_main < FLASH_END):
        failures.append(f"main outside M7 Flash window: {entry_main!r}")
    if stack_top != RAM_D1_END:
        failures.append(f"__stack_top expected 0x{RAM_D1_END:08x}, got {stack_top!r}")
    if stack_size != STACK_SIZE:
        failures.append(f"__stack_size expected 0x{STACK_SIZE:x}, got {stack_size!r}")
    if stack_limit != RAM_D1_END - STACK_SIZE:
        failures.append(
            f"__stack_limit expected 0x{RAM_D1_END - STACK_SIZE:08x}, got {stack_limit!r}"
        )
    if stack_limit is not None and stack_limit % STACK_GUARD_BYTES != 0:
        failures.append(
            f"__stack_limit is not {STACK_GUARD_BYTES}-byte aligned: 0x{stack_limit:08x}"
        )
    if stack_guard_handler is None or not (
        FLASH_ORIGIN <= stack_guard_handler < FLASH_END
    ):
        failures.append(
            "MemoryManagement stack-guard handler outside M7 Flash window: "
            f"{stack_guard_handler!r}"
        )
    if STACK_WATERMARK_FEATURE in args.features:
        gate = symbols.get(STACK_WATERMARK_GATE_SYMBOL)
        if gate is None or not (FLASH_ORIGIN <= (gate & ~1) < FLASH_END):
            failures.append(
                "M7_STACK_WATERMARK_GATE outside M7 Flash window: "
                f"{gate!r}"
            )
    if vector_words["initial_sp"] != RAM_D1_END:
        failures.append(
            f"vector initial SP expected 0x{RAM_D1_END:08x}, got 0x{vector_words['initial_sp']:08x}"
        )
    if not (FLASH_ORIGIN <= (vector_words["reset_vector"] & ~1) < FLASH_END):
        failures.append(
            f"vector reset PC outside M7 Flash window: 0x{vector_words['reset_vector']:08x}"
        )
    if vector_words["reset_vector"] & 1 != 1:
        failures.append(
            f"vector reset PC must carry Thumb bit, got 0x{vector_words['reset_vector']:08x}"
        )
    if reset is not None and vector_words["reset_vector"] != reset:
        failures.append(
            f"vector reset PC 0x{vector_words['reset_vector']:08x} does not match Reset symbol 0x{reset:08x}"
        )
    if tim7_handler is None or not (
        FLASH_ORIGIN <= (tim7_handler & ~1) < FLASH_END
    ):
        failures.append(f"TIM7 handler outside M7 Flash window: {tim7_handler!r}")
    elif vector_words["tim7_vector"] != tim7_handler:
        failures.append(
            f"TIM7 vector 0x{vector_words['tim7_vector']:08x} does not match "
            f"handler symbol 0x{tim7_handler:08x}"
        )
    for name, value in probe_symbols.items():
        if value is None or not (RAM_D1_ORIGIN <= value < RAM_D1_END):
            failures.append(f"{name} outside M7 RAM_D1 window: {value!r}")
    for task, measurement in usb_task_pools.items():
        address = measurement["address"]
        size_bytes = measurement["size_bytes"]
        if measurement["type"] != "OBJECT":
            failures.append(
                f"{task} pool exact ELF symbol is not OBJECT: "
                f"{measurement['type']!r}"
            )
        if size_bytes <= 0:
            failures.append(f"{task} pool exact ELF symbol has no measurable size")
        if not (
            RAM_D1_ORIGIN <= address
            and address + size_bytes <= RAM_D1_END
        ):
            failures.append(
                f"{task} pool exact ELF symbol outside M7 RAM_D1: "
                f"address=0x{address:08x} size={size_bytes}"
            )
    for name, measurement in (
        ("watchdog task pool", watchdog_task_pool),
        ("watchdog interrupt executor", watchdog_interrupt_executor),
    ):
        address = measurement["address"]
        size_bytes = measurement["size_bytes"]
        if measurement["type"] != "OBJECT":
            failures.append(f"{name} exact ELF symbol is not OBJECT")
        if size_bytes <= 0:
            failures.append(f"{name} exact ELF symbol has no measurable size")
        if not (RAM_D1_ORIGIN <= address and address + size_bytes <= RAM_D1_END):
            failures.append(
                f"{name} exact ELF symbol outside M7 RAM_D1: "
                f"address=0x{address:08x} size={size_bytes}"
            )
    if not dual_executor_pender_enabled:
        failures.append(
            "embassy-executor must retain both executor-thread and executor-interrupt"
        )
    if sev_instruction_count <= 0:
        failures.append("artifact has no linked SEV instruction despite executor-thread")
    for name in sorted(ethernet_trace_symbol_names):
        value = symbols.get(name)
        if value is None or not (RAM_D2_ORIGIN <= value < RAM_D2_M7_ALLOC_END):
            failures.append(f"{name} outside RAM_D2 window: {value!r}")
    if cm4_stack_start != CM4_QUARANTINE_STACK_START:
        failures.append(
            "__cm4_quarantine_stack_start expected "
            f"0x{CM4_QUARANTINE_STACK_START:08x}, got {cm4_stack_start!r}"
        )
    if cm4_stack_end != CM4_QUARANTINE_STACK_END:
        failures.append(
            "__cm4_quarantine_stack_end expected "
            f"0x{CM4_QUARANTINE_STACK_END:08x}, got {cm4_stack_end!r}"
        )
    if (
        cm4_stack_start is not None
        and cm4_stack_end is not None
        and cm4_stack_end - cm4_stack_start != CM4_QUARANTINE_STACK_BYTES
    ):
        failures.append(
            "CM4 quarantine stack reservation expected "
            f"{CM4_QUARANTINE_STACK_BYTES} bytes, got "
            f"{cm4_stack_end - cm4_stack_start}"
        )
    if cache_on_d2_enabled:
        if eth_dma_start is None or eth_dma_end is None:
            failures.append("missing __eth_dma_start/__eth_dma_end symbols")
        else:
            eth_dma_bytes = eth_dma_end - eth_dma_start
            if eth_dma_start != RAM_D2_ORIGIN:
                failures.append(
                    f"__eth_dma_start expected 0x{RAM_D2_ORIGIN:08x}, got 0x{eth_dma_start:08x}"
                )
            if eth_dma_end <= eth_dma_start:
                failures.append(
                    f".eth_dma section is empty or inverted: start=0x{eth_dma_start:08x} end=0x{eth_dma_end:08x}"
                )
            if eth_dma_bytes > expected_eth_dma_mpu_bytes:
                failures.append(
                    ".eth_dma exceeds "
                    f"{expected_eth_dma_mpu_bytes} byte MPU span: {eth_dma_bytes} bytes"
                )
            if eth_dma_start % expected_eth_dma_mpu_bytes != 0 or eth_dma_end % 32 != 0:
                failures.append(
                    f".eth_dma alignment invalid: start=0x{eth_dma_start:08x} end=0x{eth_dma_end:08x}"
                )
            if eth_dma_end > RAM_D2_M7_ALLOC_END:
                failures.append(
                    ".eth_dma overlaps the CM4 quarantine stack reservation: "
                    f"end=0x{eth_dma_end:08x}, M7 allocation end=0x{RAM_D2_M7_ALLOC_END:08x}"
                )
            for name in sorted(ethernet_trace_symbol_names):
                value = symbols.get(name)
                if value is not None and not (eth_dma_start <= value < eth_dma_end):
                    failures.append(
                        f"{name} outside linked .eth_dma section: {value:#x}"
                    )
    if tls_mock_feature_enabled:
        if not mock_ca_der_embedded:
            failures.append("diagnostic overlay does not embed the mock CA DER")
        missing_tls_mock_probes = sorted(
            TLS_MOCK_TRANSPORT_PROBE_SYMBOLS - set(tls_mock_probe_symbols_present)
        )
        if missing_tls_mock_probes:
            failures.append(
                "diagnostic overlay is missing TLS mock probes: "
                + ", ".join(missing_tls_mock_probes)
            )
    else:
        if mock_ca_der_embedded:
            failures.append("default product artifact embeds the mock CA DER")
        if tls_mock_probe_symbols_present:
            failures.append(
                "default product artifact links TLS mock transport probes: "
                + ", ".join(tls_mock_probe_symbols_present)
            )
    if lse_retention_feature_enabled:
        missing_p05_probes = sorted(
            LSE_RETENTION_PROBE_SYMBOLS
            - set(lse_retention_probe_symbols_present)
        )
        if missing_p05_probes:
            failures.append(
                "P05 LSE retention instrument is missing boot probes: "
                + ", ".join(missing_p05_probes)
            )
    elif lse_retention_probe_symbols_present:
        failures.append(
            "default product artifact links P05 LSE retention probes: "
            + ", ".join(lse_retention_probe_symbols_present)
        )
    if watchdog_cpu_busy_feature_enabled:
        missing_watchdog_cpu_busy_probes = sorted(
            WATCHDOG_CPU_BUSY_PROBE_SYMBOLS
            - set(watchdog_cpu_busy_probe_symbols_present)
        )
        if missing_watchdog_cpu_busy_probes:
            failures.append(
                "watchdog CPU-busy overlay is missing probes: "
                + ", ".join(missing_watchdog_cpu_busy_probes)
            )
    elif watchdog_cpu_busy_probe_symbols_present:
        failures.append(
            "default product artifact links watchdog CPU-busy probes: "
            + ", ".join(watchdog_cpu_busy_probe_symbols_present)
        )
    failures.extend(generated_frame_failures)
    failures.extend(guard_trip_frame_failures)
    failures.extend(stack_guard_contract_failures)
    accelerated_selected = (ACCELERATED_CLOCK_FEATURE in args.features
                            or RUNTIME_COUNTER_FEATURE in args.features
                            or CACHE_AGE_FEATURE in args.features
                            or TRUST_HEARTBEAT_FEATURE in args.features
                            or PROTOCOL_IDENTIFIER_FEATURE in args.features)
    accelerated_present = set(symbols) & ACCELERATED_CLOCK_PROBE_SYMBOLS
    if accelerated_selected != (accelerated_present == ACCELERATED_CLOCK_PROBE_SYMBOLS):
        failures.append("accelerated clock probes do not match the explicit feature")
    if not accelerated_selected and accelerated_present:
        failures.append("product build contains accelerated clock diagnostic probes")
    for gate in ("M7_ACCELERATED_CLOCK_GATE", "M7_ACCELERATED_DEPENDENTS_READY_GATE"):
        gate_address = symbols.get(gate)
        if accelerated_selected:
            if gate_address is None or not 0x08040000 <= gate_address < 0x080C0000:
                failures.append(f"accelerated startup gate missing or outside M7 Flash: {gate}")
        elif gate_address is not None:
            failures.append(f"product build links accelerated startup gate: {gate}")
    counter_selected = RUNTIME_COUNTER_FEATURE in args.features
    counter_present = set(symbols) & RUNTIME_COUNTER_PROBE_SYMBOLS
    if counter_selected and counter_present != RUNTIME_COUNTER_PROBE_SYMBOLS:
        failures.append("counter diagnostic probes missing from explicit feature")
    if not counter_selected and (counter_present or RUNTIME_COUNTER_GATE_SYMBOL in symbols
                                or RUNTIME_COUNTER_EVENTS_GATE_SYMBOL in symbols):
        failures.append("build without counter feature links counter diagnostic probes")
    if counter_selected:
        gate_address = symbols.get(RUNTIME_COUNTER_GATE_SYMBOL, 0)
        if not 0x08040000 <= gate_address < 0x080C0000:
            failures.append("counter gate missing or outside M7 Flash")
        event_gate = symbols.get(RUNTIME_COUNTER_EVENTS_GATE_SYMBOL, 0)
        if not 0x08040000 <= event_gate < 0x080C0000:
            failures.append("counter event gate missing or outside M7 Flash")
        snapshot_address = symbols.get("M7_COUNTER_ADMISSION", 0)
        if snapshot_address % 32 or not RAM_D1_ORIGIN <= snapshot_address <= RAM_D1_END - 320:
            failures.append("counter snapshot is not a whole-line aligned D1 extent")
        input_address = symbols.get("M7_COUNTER_RECIPE_INPUT", 0)
        if input_address % 4 or not RAM_D1_ORIGIN <= input_address <= RAM_D1_END - 4:
            failures.append("counter recipe input is not aligned D1 storage")
        for name, size in (("M7_COUNTER_EVENTS", 6144), ("M7_COUNTER_EVENT_SUMMARY", 128)):
            address = symbols.get(name, 0)
            if address % 32 or not RAM_D1_ORIGIN <= address <= RAM_D1_END - size:
                failures.append(f"counter event object lacks whole-line aligned D1 extent: {name}")
    cache_selected = CACHE_AGE_FEATURE in args.features
    cache_present = set(symbols) & (set(CACHE_AGE_OBJECTS) | {CACHE_AGE_GATE})
    if cache_selected:
        if cache_present != set(CACHE_AGE_OBJECTS) | {CACHE_AGE_GATE}:
            failures.append("cache age diagnostic probes/gate missing")
        if not 0x08040000 <= symbols.get(CACHE_AGE_GATE, 0) < 0x080C0000:
            failures.append("cache age gate missing or outside M7 Flash")
        for name, size in CACHE_AGE_OBJECTS.items():
            address = symbols.get(name, 0)
            alignment = 4 if size == 4 else 32
            if address % alignment or not RAM_D1_ORIGIN <= address <= RAM_D1_END - size:
                failures.append(f"cache age object lacks aligned D1 extent: {name}")
    elif cache_present:
        failures.append("build without cache age feature links cache diagnostics")
    owner_selected = TRUST_HEARTBEAT_FEATURE in args.features
    owner_present = set(symbols) & (set(TRUST_HEARTBEAT_OBJECTS) | {TRUST_HEARTBEAT_GATE})
    if owner_selected:
        if owner_present != set(TRUST_HEARTBEAT_OBJECTS) | {TRUST_HEARTBEAT_GATE}:
            failures.append("trust/heartbeat diagnostic probes/gate missing")
        if not 0x08040000 <= symbols.get(TRUST_HEARTBEAT_GATE, 0) < 0x080C0000:
            failures.append("trust/heartbeat gate missing or outside M7 Flash")
        for name, size in TRUST_HEARTBEAT_OBJECTS.items():
            address = symbols.get(name, 0)
            alignment = 4 if size == 4 else 32
            if address % alignment or not RAM_D1_ORIGIN <= address <= RAM_D1_END - size:
                failures.append(f"trust/heartbeat object lacks aligned D1 extent: {name}")
    elif owner_present:
        failures.append("build without trust/heartbeat feature links owner diagnostics")
    protocol_selected = PROTOCOL_IDENTIFIER_FEATURE in args.features
    protocol_present = set(symbols) & set(PROTOCOL_IDENTIFIER_OBJECTS)
    if protocol_selected:
        if protocol_present != set(PROTOCOL_IDENTIFIER_OBJECTS):
            failures.append("protocol identifier diagnostic probes missing")
        for name, size in PROTOCOL_IDENTIFIER_OBJECTS.items():
            address = symbols.get(name, 0)
            alignment = 4 if size == 4 else 32
            if address % alignment or not RAM_D1_ORIGIN <= address <= RAM_D1_END - size:
                failures.append(f"protocol identifier object lacks aligned D1 extent: {name}")
    elif protocol_present:
        failures.append("build without protocol identifier feature links its diagnostics")
    if failures:
        raise RuntimeError("M7 resource validation failed:\n" + "\n".join(failures))

    eth_dma_section = {
        "enabled": cache_on_d2_enabled,
        "start": f"0x{eth_dma_start:08x}" if eth_dma_start is not None else None,
        "end_exclusive": f"0x{eth_dma_end:08x}" if eth_dma_end is not None else None,
        "bytes": (
            (eth_dma_end - eth_dma_start)
            if eth_dma_start is not None and eth_dma_end is not None
            else 0
        ),
        "mpu_region_bytes": expected_eth_dma_mpu_bytes if cache_on_d2_enabled else 0,
        "cacheability": (
            "normal-shareable-non-cacheable"
            if cache_on_d2_enabled
            else "cache-off baseline; no D2 Ethernet section"
        ),
    }

    archive_root = getattr(args, "archive_dir", None) or REPO_ROOT / "firmware-builds"
    if not archive_root.is_absolute():
        archive_root = REPO_ROOT / archive_root
    archived_binary = archive_binary(binary, embedded_identity, archive_root, package=PACKAGE)

    return {
        "schema": "opta-m7-build-resource-report-v1",
        "firmware_identity_schema": "opta-firmware-identity-v1",
        "firmware_identity": embedded_identity,
        "firmware_dependency_inputs": dependency_inputs,
        "artifact_size_bytes": ARTIFACT.stat().st_size,
        "binary": {
            "path": str(binary_path.relative_to(REPO_ROOT)),
            "archive_path": str(archived_binary),
            "size_bytes": len(binary),
            "sha256": hashlib.sha256(binary).hexdigest(),
        },
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "scope": "release-relevant Cortex-M7 no_std default product firmware; build/resource measurement only; no hardware action",
        "hardware_actions": [],
        "package": PACKAGE,
        "target": TARGET,
        "features": args.features,
        "feature_composition": {
            "cargo_default_product": True,
            "diagnostic_overlays": args.features,
        },
        "diagnostic_overlay_contract": {
            **source_boundary,
            "tls_mock_feature_enabled": tls_mock_feature_enabled,
            "mock_ca_der_sha256": sha256_file(TLS_MOCK_CA_DER),
            "mock_ca_der_embedded": mock_ca_der_embedded,
            "tls_mock_probe_symbols_present": tls_mock_probe_symbols_present,
        },
        "p05_lse_retention_instrument_contract": {
            "feature": LSE_RETENTION_FEATURE,
            "feature_enabled": lse_retention_feature_enabled,
            "probe_symbols_present": lse_retention_probe_symbols_present,
            "product_candidate": False,
        },
        "watchdog_cpu_busy_instrument_contract": {
            "feature": WATCHDOG_CPU_BUSY_FEATURE,
            "feature_enabled": watchdog_cpu_busy_feature_enabled,
            "probe_symbols_present": watchdog_cpu_busy_probe_symbols_present,
            "product_candidate": False,
        },
        "build_mode": build_mode,
        "artifact": str(ARTIFACT.relative_to(REPO_ROOT)),
        "artifact_sha256": sha256_file(ARTIFACT),
        "toolchain": {
            "rustc": command_output_or_raise(rustc_version).strip(),
            "cargo": command_output_or_raise(cargo_version).strip(),
            "rust_src_manifest": str(rust_src_manifest),
            "rust_src_manifest_sha256": sha256_file(rust_src_manifest),
            "build_std_components": BUILD_STD_COMPONENTS.split(","),
            "cargo_locked": True,
            "cargo_offline": True,
            "target_cpu": "cortex-m7",
            "panic": "abort",
        },
        "memory_contract": {
            "flash_origin": f"0x{FLASH_ORIGIN:08x}",
            "flash_end_exclusive": f"0x{FLASH_END:08x}",
            "ram_d1_origin": f"0x{RAM_D1_ORIGIN:08x}",
            "ram_d1_end_exclusive": f"0x{RAM_D1_END:08x}",
            "stack_size": STACK_SIZE,
            "stack_guard_bytes": STACK_GUARD_BYTES,
            "stack_guard_base": (
                f"0x{stack_limit:08x}" if stack_limit is not None else None
            ),
            "stack_guard_memmanage_handler": (
                f"0x{stack_guard_handler:08x}"
                if stack_guard_handler is not None
                else None
            ),
            "d2_sram_used": d2_sram_bytes != 0,
            "d2_physical_end_exclusive": f"0x{RAM_D2_END:08x}",
            "d2_m7_allocation_end_exclusive": f"0x{RAM_D2_M7_ALLOC_END:08x}",
            "cm4_quarantine_stack": {
                "m7_alias_start": (
                    f"0x{cm4_stack_start:08x}"
                    if cm4_stack_start is not None
                    else None
                ),
                "m7_alias_end_exclusive": (
                    f"0x{cm4_stack_end:08x}" if cm4_stack_end is not None else None
                ),
                "cm4_alias_start": "0x10047c00",
                "cm4_alias_end_exclusive": "0x10048000",
                "reserved_bytes": CM4_QUARANTINE_STACK_BYTES,
                "linked_m7_bytes": 0,
            },
            "sram4_used": sram4_bytes != 0,
            "eth_dma_section": eth_dma_section,
        },
        "size_summary": size_summary,
        "sections": sections,
        "elf_header": header,
        "vector_table_words": vector_words,
        "symbols": symbols,
        "usb_task_pools": {
            "method": (
                "exact demangled llvm-readelf -sW --demangle ELF symbol "
                "st_size; source-derived estimates are forbidden"
            ),
            "tasks": usb_task_pools,
            "total_bytes": usb_task_pool_total_bytes,
            "included_in_ram_d1_linked_bytes": True,
        },
        "watchdog_interrupt_executor": {
            "method": "exact demangled llvm-readelf -sW --demangle ELF symbol st_size",
            "task_pool": {
                "symbol": WATCHDOG_TASK_POOL_SYMBOL,
                **watchdog_task_pool,
            },
            "interrupt_executor": {
                "symbol": WATCHDOG_INTERRUPT_EXECUTOR_SYMBOL,
                **watchdog_interrupt_executor,
            },
            "residual_thread_pender_branch": {
                "dual_executor_features_enabled": dual_executor_pender_enabled,
                "linked_sev_instruction_count": sev_instruction_count,
                "standalone_symbol_after_lto": standalone_pender_symbol_after_lto,
                "size_accounting": "folded into linked Flash total and compared by resource delta; release LTO emits no standalone __pender symbol",
                "reason": "embassy-executor retains both executor-thread and executor-interrupt",
            },
            "included_in_ram_d1_linked_bytes": True,
            "irq_nesting_allowance_bytes": IRQ_NESTING_ALLOWANCE_BYTES,
        },
        "generated_fixed_frames": {
            "method": "per symbol: sum all immediate sub sp plus push/vpush bytes in llvm-objdump -d --demangle output",
            "scope": "generated fixed-frame gate only; not a proof of maximum call-chain depth",
            "default_unlisted_budget_bytes": DEFAULT_GENERATED_FIXED_FRAME_BUDGET_BYTES,
            "pinned_exact_budgets_bytes": PINNED_GENERATED_FIXED_FRAME_EXACT_BUDGETS,
            "pinned_prefix_budgets_bytes": PINNED_GENERATED_FIXED_FRAME_PREFIX_BUDGETS,
            "indirect_dispatch_symbol_count": len(indirect_dispatch_symbols),
            "indirect_dispatch_symbols": indirect_dispatch_symbols,
            "static_call_depth_is_lower_bound": True,
            "top_measurements": generated_frame_measurements[:25],
        },
        "stack_guard_trip_frame": guard_trip_frame_contract,
        "stack_guard_contract": {
            **stack_guard_contract,
            "scope": "build-time coupling of permitted fixed frames, MPU guard band, and usable reserve; target fault proof remains required",
        },
        "resource_impact_measured": {
            "flash_text_bytes": size_summary["text"],
            "ram_data_bytes": size_summary["data"],
            "ram_bss_bytes": size_summary["bss"],
            "ram_d1_linked_bytes": d1_sram_bytes,
            "usb_console_task_pool_bytes": usb_task_pools["usb_console_task"][
                "size_bytes"
            ],
            "usb_device_task_pool_bytes": usb_task_pools["usb_device_task"][
                "size_bytes"
            ],
            "usb_task_pool_total_bytes": usb_task_pool_total_bytes,
            "watchdog_task_pool_bytes": watchdog_task_pool["size_bytes"],
            "watchdog_interrupt_executor_bytes": watchdog_interrupt_executor[
                "size_bytes"
            ],
            "embassy_pender_flash_bytes": None,
            "stack_reserved_bytes": STACK_SIZE,
            "ram_d1_unlinked_before_stack_bytes": (
                stack_limit - sheap
                if stack_limit is not None
                and sheap is not None
                and sheap <= stack_limit
                else None
            ),
            "d2_sram_bytes": d2_sram_bytes,
            "d2_cm4_quarantine_stack_reserved_bytes": CM4_QUARANTINE_STACK_BYTES,
            "d2_m7_allocatable_bytes": RAM_D2_M7_ALLOC_END - RAM_D2_ORIGIN,
            "sram4_bytes": sram4_bytes,
            "heap_or_alloc": "none",
            "qspi": "not touched",
            "backup_registers": "runtime writers use BKP0 for DFU handoff and BKP2..BKP7+BKP15 for last-fault; build does not touch hardware",
            "m4_runtime": (
                "not linked, started, or serviced by M7; only the separate "
                "1024-byte D2 exception-stack reservation is charged"
            ),
        },
        "resource_margins": {
            **resource_margins,
            "flash": {
                **resource_margins["flash"],
                # Historical v1 keys retained for report readers. They describe
                # the advisory threshold; no percentage-based gate is required.
                "minimum_free_percent": HEADROOM_REVIEW_PERCENT,
                "minimum_free_bytes": FLASH_BYTES * HEADROOM_REVIEW_PERCENT // 100,
                "release_margin_required": False,
                "passes_release_margin": not resource_margins["flash"]["review_required"],
                "exemption": None,
            },
        },
        "resource_policy": "adr-0029-advisory-headroom",
        "resource_warnings": resource_warnings,
        "release_accepted": False,
        "acceptance": {
            "artifact_built": True,
            "accelerated_clock_probes_match_feature_boundary": True,
            "reset_vector_at_flash_origin": True,
            "reset_handler_in_flash_window": True,
            "vector_table_at_flash_origin": True,
            "reset_in_flash_window": True,
            "main_in_flash_window": True,
            "vector_initial_sp_matches_stack": True,
            "vector_reset_matches_reset_symbol": True,
            "probe_words_in_ram_d1": True,
            "usb_task_pools_measured_from_exact_elf_symbols": True,
            "usb_task_pools_in_ram_d1": True,
            "watchdog_task_pool_measured_from_exact_elf_symbol": True,
            "watchdog_interrupt_executor_measured_from_exact_elf_symbol": True,
            "watchdog_runtime_symbols_in_ram_d1": True,
            "residual_thread_pender_branch_accounted_in_flash_delta": True,
            "tim7_vector_matches_interrupt_executor_handler": True,
            "cm4_quarantine_stack_reserved_from_m7_linker": True,
            "cm4_quarantine_stack_is_exactly_1024_bytes": True,
            "eth_dma_does_not_overlap_cm4_quarantine_stack": True,
            "stack_in_ram_d1": True,
            "stack_guard_base_aligned": True,
            "stack_guard_memmanage_handler_in_flash": True,
            "generated_fixed_frame_budgets_passed": True,
            "stack_guard_covers_max_permitted_generated_frame": True,
            "measured_chain_plus_irq_fits_usable_stack": True,
            "static_call_depth_is_only_a_lower_bound": True,
            "flash_capacity_passed": resource_margins["flash"]["capacity_passed"],
            "ram_d1_capacity_passed": resource_margins["ram_d1"]["capacity_passed"],
            "release_flash_margin_required": False,
            "release_flash_margin_at_least_25_percent": not resource_margins["flash"]["review_required"],
            "tls_mock_source_assumptions_confined_to_diagnostic_module": True,
            "tls_mock_ca_matches_feature_boundary": (
                mock_ca_der_embedded
                if tls_mock_feature_enabled
                else not mock_ca_der_embedded
            ),
            "tls_mock_transport_matches_feature_boundary": (
                set(tls_mock_probe_symbols_present) == TLS_MOCK_TRANSPORT_PROBE_SYMBOLS
                if tls_mock_feature_enabled
                else not tls_mock_probe_symbols_present
            ),
            "p05_lse_retention_probes_match_feature_boundary": (
                set(lse_retention_probe_symbols_present)
                == LSE_RETENTION_PROBE_SYMBOLS
                if lse_retention_feature_enabled
                else not lse_retention_probe_symbols_present
            ),
            "watchdog_cpu_busy_probes_match_feature_boundary": (
                set(watchdog_cpu_busy_probe_symbols_present)
                == WATCHDOG_CPU_BUSY_PROBE_SYMBOLS
                if watchdog_cpu_busy_feature_enabled
                else not watchdog_cpu_busy_probe_symbols_present
            ),
            "no_hardware_actions": True,
        },
        "commands": compact_command_outputs(commands),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, help="write JSON report to path")
    parser.add_argument(
        "--version", dest="build_version",
        help="rebuild this exact version; default allocates the next unused plain version",
    )
    parser.add_argument(
        "--archive-dir",
        type=Path,
        help="retain each validated BIN here (default: firmware-builds/ in this checkout)",
    )
    parser.add_argument(
        "--release-candidate",
        action="store_true",
        help="require a clean known revision and default product identity",
    )
    parser.add_argument(
        "--build-std",
        action="store_true",
        required=True,
        help="use the sole canonical release path: pinned rust-src core/compiler_builtins",
    )
    parser.add_argument(
        "--features",
        action="append",
        default=[],
        help="firmware feature to enable; repeat for multiple features",
    )
    args = parser.parse_args()

    args.archive_dir = args.archive_dir or REPO_ROOT / "firmware-builds"
    if not args.archive_dir.is_absolute():
        args.archive_dir = REPO_ROOT / args.archive_dir
    source_identity = resolve_identity(REPO_ROOT, args.features)
    minimum = source_identity["version"]
    with allocated_version(args.archive_dir, PACKAGE, minimum, args.build_version, identity=source_identity) as version:
        args.build_version = version
        report = collect_report(args)
    for warning in report["resource_warnings"]:
        print(f"WARNING: {warning}", file=sys.stderr)
    text = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output:
        output = args.output if args.output.is_absolute() else REPO_ROOT / args.output
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(text)
    else:
        print(text, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
