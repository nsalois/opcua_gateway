# Opta OPC UA gateway

Rust firmware connecting one Büchi R-300 Rotavapor to an industrial OPC UA
client through an Arduino/Finder Opta Lite. The Cortex-M7 runs the gateway;
a separately built, inert Cortex-M4 companion keeps that core from interfering.

**Development source: production qualification is incomplete.** This repository
contains source, host tests and firmware build checks. Its builds are not approved
installation packages. Simulator tests do not establish real R-300 compatibility
or months of unattended operation. See the [testing report](firmware-testing-report.md).

## What it does

- Polls numeric and boolean R-300 data over verified HTTPS.
- Serves readings, quality and bounded DataChange subscriptions over OPC UA.
- Validates and forwards a limited set of numeric and boolean setpoint writes.
- Supports device identity, static addressing, USB provisioning and diagnostics.
- Uses a watchdog for recovery from selected firmware hangs.

Each gateway serves one instrument. DHCP is the factory default; a configured
static address does not fall back to DHCP. Address allocation belongs to the
network administrator.

The OPC UA endpoint uses **SecurityPolicy None and anonymous sessions**;
it provides no OPC UA authentication or transport encryption. Deployments require
an appropriately controlled network. Methods, Events, History and PubSub are
outside the implemented surface. No OPC Foundation certification is claimed.

## Build on Linux

Use Linux x86_64, Python 3.11+, Git, GCC and LLVM tools providing `ld.lld`,
`llvm-size`, `llvm-readelf`, `llvm-objdump`, `llvm-objcopy` and `llvm-nm` on
`PATH`. Ubuntu and Fedora packages are `python3 git gcc llvm lld`.
Install [rustup](https://rustup.rs/) if needed. Normal builds and tests require
no Python packages, Node, Docker or hardware.

Clone the repository and prepare pinned dependencies while online:

```bash
git clone https://github.com/nsalois/opcua_gateway.git
cd opcua_gateway
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

Run the host regressions, including debug and optimized profiles:

```bash
bash tools/check.sh
```

Save source changes in Git before building a candidate. Clear ambient
`RUSTFLAGS` and Cargo rustflag overrides. Build both processors:

```bash
python3 -B tools/check_m7_build_resource.py --build-std \
  --release-candidate --version 1.3.1 \
  --archive-dir "$PWD/build-output/archive" \
  --output "$PWD/build-output/m7-report.json"
python3 -B tools/check_m4_quarantine_build_resource.py --build-std \
  --version 1.1.0 \
  --archive-dir "$PWD/build-output/archive" \
  --output "$PWD/build-output/m4-report.json"
```

The canonical builders use Cargo locked/offline mode and rebuild the pinned
compiler's `core` and `compiler_builtins` through
[build-std](https://doc.rust-lang.org/cargo/reference/unstable.html#build-std).
M7 selects only the default product features. Neither builder contacts hardware.
`--release-candidate` checks cleanliness and composition; it is not production
acceptance.

| Result | Location |
| --- | --- |
| M7 ELF and BIN | `target/thumbv7em-none-eabihf/release/opta-m7` and `.bin` |
| M4 ELF and BIN | `target/opta-m4-quarantine/thumbv7em-none-eabihf/release/opta-m4-quarantine` and `.bin` |
| Versioned binary copies | `build-output/archive/m7/1.3.1/m7.bin`, `build-output/archive/m4/1.1.0/m4.bin` |
| Resource and source-identity reports | `build-output/m7-report.json`, `build-output/m4-report.json` |

Keep reports beside their binaries. Both reports must identify the same source
commit and clean state. M7 embeds its version, source identity and build flavor;
M4 records source identity externally. See the [M4 notes](firmware/opta-m4-quarantine/README.md).

## Versions and source scope

This publication uses **M7 1.3.1** and **M4 1.1.0**. M7 1.3.0 is reserved for
prepublication validation. Firmware versions are independent of internal Cargo
package versions. Changed source requires a new M7 version: update its `VERSION`
file, the commands above and the workflow together. Embedded source identity
changes bytes even for documentation-only commits. Reuse an M4 version only
when its binary is identical. Never assign different bytes to an existing
processor/version; independent clones do not coordinate numbering.

The five shared crates, both firmware crates and modified Embassy dependency
retain their original structure. Host regression suites and synthetic fixtures
are included. Bench services, hardware runners, recovery images, real vendor
certificates and the equipment manual are outside this source distribution.
Diagnostic and maintenance features remain opt-in; the supported build above
is the default product. The [diagnostic CA](firmware/opta-m7/src/certs/README.md)
and [TLS fixtures](crates/tls-verify/testdata/README.md) are synthetic.

[GitHub checks](.github/workflows/check.yml) run the same host checks and both
firmware builders. Historical tests and remaining acceptance work are described
separately in the [testing report](firmware-testing-report.md).

## Licensing

Copyright 2026 Nicholas Salois. Original source, documentation, build support
and synthetic fixtures are [Apache-2.0](LICENSE). Third-party code retains its
own attribution and notices; see [THIRD_PARTY.md](THIRD_PARTY.md).
Product names identify compatible equipment and do not imply endorsement.
