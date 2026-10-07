#!/usr/bin/env bash
# Host-only public checks; no network services or hardware.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --check
cargo fmt --manifest-path firmware/opta-m4-quarantine/Cargo.toml -- --check
cargo clippy --workspace --exclude opta-m7 --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --exclude opta-m7 --all-features --locked --offline
cargo test --workspace --exclude opta-m7 --all-features --locked --offline --release
python3 -B -m unittest tools.test_buchi_inflight_completion
