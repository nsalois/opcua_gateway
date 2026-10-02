# Opta OPC UA gateway firmware

Source for the Arduino Opta Lite gateway's **M7 product firmware and required
M4 quarantine companion**. M7 exposes numeric and boolean Buchi R-300 HTTPS
data through a bounded OPC UA server. M4 runs the separately built inert
quarantine image; it is not a second product runtime.

This repository builds both images. It supplies no installer, bootloader,
device credentials, vendor trust certificates or release package. Building
does not establish hardware compatibility, unattended reliability or OPC
Foundation conformance, and does not install either image.

## Linux build

Supported host: Linux x86_64. Install Python 3.11+, Git, a host C compiler/linker
(GCC), and LLVM tools providing `ld.lld`, `llvm-size`, `llvm-readelf`,
`llvm-objdump`, `llvm-objcopy`, and `llvm-nm` on `PATH`. Fedora packages are
`python3`, `git`, `gcc`, `llvm`, and `lld`. Install [rustup](https://rustup.rs/)
using the official instructions. No Python packages, Node, Docker, hardware
tools or private service are needed.

Run from a Git clone of this repository. Install the pinned Rust toolchain and
fetch both workspaces' dependencies while online:

```bash
rustup toolchain install 1.96.1 --profile minimal \
  --component rust-src,rustfmt,clippy --target thumbv7em-none-eabihf \
  --no-self-update
RUSTC_BOOTSTRAP=1 cargo -Z build-std=core,compiler_builtins fetch \
  --locked --target thumbv7em-none-eabihf
cargo fetch --locked
RUSTC_BOOTSTRAP=1 cargo -Z build-std=core,compiler_builtins fetch \
  --manifest-path firmware/opta-m4-quarantine/Cargo.toml \
  --locked --target thumbv7em-none-eabihf
```

The checkers rebuild the pinned compiler's `core` and `compiler_builtins` using
Cargo's [build-std support](https://doc.rust-lang.org/cargo/reference/unstable.html#build-std).
They set `RUSTC_BOOTSTRAP=1` and always build locked and offline. The unfiltered
fetch also prepares host/platform metadata dependencies. To check setup from
scratch, start with empty `CARGO_HOME` and `RUSTUP_HOME` and keep those same
directories for both builds.

Commit source changes before building. Clear ambient `RUSTFLAGS` and Cargo
rustflag overrides, and run both canonical builders:

```bash
python3 -B tools/check_m7_build_resource.py --build-std \
  --release-candidate --version 1.2.0 \
  --archive-dir "$PWD/build-output/archive" \
  --output "$PWD/build-output/m7-report.json"
python3 -B tools/check_m4_quarantine_build_resource.py --build-std \
  --version 1.1.0 \
  --archive-dir "$PWD/build-output/archive" \
  --output "$PWD/build-output/m4-report.json"
```

M7 uses default product features; no feature arguments are needed.
`--release-candidate` enforces clean committed M7 source and product features,
not release approval. M4 has a separate workspace and target directory, with
its Cortex-M4 compiler flags selected by its checker. Confirm both reports
name the same clean source revision. M7 embeds that identity; M4 records it
externally in its report rather than changing the minimal binary.

| Output | Path |
| --- | --- |
| M7 ELF and BIN | `target/thumbv7em-none-eabihf/release/opta-m7` and `.bin` |
| M4 ELF and BIN | `target/opta-m4-quarantine/thumbv7em-none-eabihf/release/opta-m4-quarantine` and `.bin` |
| Immutable archive copies | `build-output/archive/m7/1.2.0/m7.bin`, `build-output/archive/m4/1.1.0/m4.bin` |
| Validation and identity | `build-output/m7-report.json`, `build-output/m4-report.json` |

Keep reports with the binaries. M7 validates resource limits and diagnostic
certificate/probe exclusion. M4 validates its interrupt table, vectors,
instruction sequence, memory limits, dependency isolation and image hashes.
Neither command contacts hardware. Generated outputs are ignored and must
not enter source history.

## Versions and scope

The initial complete source export deliberately uses **M7 1.2.0** and
**M4 1.1.0**, continuing independent version sequences. Earlier M7 1.1.x
numbers were reserved for preparation of the M7-only export; the complete
export advances M7's minor version. Neither processor restarts at 1.0.0.
Internal Cargo package versions remain 0.1.0. Each processor's `VERSION`
file supplies its firmware minimum; use the explicit versions above to
reproduce this source snapshot.

For changed source, allocate new firmware versions and update `VERSION` and
these instructions together. Never assign different bytes to an existing
version. Omitting `--version` allocates from the local archive; independent
clones do not coordinate their numbering. M7's embedded Git identity changes
binary bytes across commits even without runtime changes. M4 provenance stays
in the report, so equal M4 bytes do not by themselves identify a source commit.

The five shared crates, both firmware crates and patched Embassy dependency
retain their existing paths. Host applications, standalone test suites and
their manifest targets/dependencies are omitted; self-contained inline tests
remain. The canonical builders are retained. Diagnostic example addresses
use documentation-only addresses, with corresponding checker sentinels.
The diagnostic certificate is synthetic; see its
[provenance](firmware/opta-m7/src/certs/README.md). Diagnostic and maintenance
code remains feature-gated; the supported M7 build is the default product.
See the [M4 notes](firmware/opta-m4-quarantine/README.md) for its build scope.

## Licensing

Copyright 2026 Nicholas Salois. Original gateway source, build support,
documentation and the synthetic test certificate are [Apache-2.0](LICENSE).
Dependency contributions retain their own licenses. The M4 interrupt-table
extract retains STMicroelectronics attribution and BSD-3-Clause terms.
See [third-party information](THIRD_PARTY.md). No grant is asserted over
excluded vendor trust certificates, hardware manuals or third-party binaries.
