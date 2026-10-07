# Opta OPC UA gateway

Rust firmware connecting one Büchi R-300 Rotavapor to an industrial OPC UA
client through an Arduino/Finder Opta Lite. The Cortex-M7 runs the gateway;
a separately built, inert Cortex-M4 companion keeps that core from interfering.

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
outside the implemented surface.

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
  --release-candidate --version 1.3.8 \
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
M7 selects the default product features. The `--release-candidate` option checks
source cleanliness and product composition.

The commands above create these files on your computer:

| Result | Location |
| --- | --- |
| M7 ELF and BIN | `target/thumbv7em-none-eabihf/release/opta-m7` and `.bin` |
| M4 ELF and BIN | `target/opta-m4-quarantine/thumbv7em-none-eabihf/release/opta-m4-quarantine` and `.bin` |
| Versioned binary copies | `build-output/archive/m7/1.3.8/m7.bin`, `build-output/archive/m4/1.1.0/m4.bin` |
| Resource and source-identity reports | `build-output/m7-report.json`, `build-output/m4-report.json` |

The reports record each build’s source revision and resource use. See the
[M4 notes](firmware/opta-m4-quarantine/README.md) for companion firmware details.

This source-only repository includes host tests and build tools. See the
[testing report](firmware-testing-report.md) for test coverage and results.

## Licensing

Copyright 2026 Nicholas Salois. Original source, documentation, build support
and synthetic fixtures are [Apache-2.0](LICENSE). Third-party code retains its
own attribution and notices; see [THIRD_PARTY.md](THIRD_PARTY.md).
Product names identify compatible equipment and do not imply endorsement.
