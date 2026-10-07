#!/usr/bin/env bash
# Copyright 2026 Nicholas Salois.
#
# Licensed under the Apache License, Version 2.0.
# See the LICENSE file in the repository root for the full license.

# Host-only public checks; no network services or hardware.
set -euo pipefail
cd "$(dirname "$0")/.."

cargo fmt --check
cargo fmt --manifest-path firmware/opta-m4-quarantine/Cargo.toml -- --check
cargo clippy --workspace --exclude opta-m7 --all-targets --all-features --locked --offline -- -D warnings
cargo test --workspace --exclude opta-m7 --all-features --locked --offline
cargo test --workspace --exclude opta-m7 --all-features --locked --offline --release
python3 -B -m unittest tools.test_buchi_inflight_completion
