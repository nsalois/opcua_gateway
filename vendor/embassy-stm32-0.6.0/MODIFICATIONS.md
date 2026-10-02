# Local modifications

Baseline: the crates.io `embassy-stm32` 0.6.0 package, whose
`.cargo_vcs_info.json` identifies upstream revision
`84444a19eb57d978e3c09fcdc8e60cdd7278eb03` and directory `embassy-stm32` in
<https://github.com/embassy-rs/embassy>. The normalized `Cargo.toml` is the
build authority; `Cargo.toml.orig` is retained for upstream provenance.

These files differ from that baseline:

| File | Local change |
| --- | --- |
| `Cargo.toml`, `Cargo.toml.orig` | Opt-in diagnostic feature declarations. |
| `src/eth/mod.rs` | Ethernet progress hook and opt-in packet tracing. |
| `src/eth/f8_trace.rs` | New bounded diagnostic packet digest parser. |
| `src/eth/v2/descriptors.rs` | DMA ring tail-pointer corrections and diagnostic capture. |
| `src/eth/v2/mod.rs` | RMII ordering, bounded reset wait and failure callback. |
| `src/flash/h7.rs` | Clear completion/error flags through the clear register. |
| `src/usb/otg.rs` | Product progress hooks around bus and control operations. |
| `src/time_driver/gp16.rs` | Opt-in time counters and tracing callbacks. |
| `src/i2c/v1.rs` | Whitespace-only cleanup. |

The 2026-10-01 source export adds this notice and a notice at the top of each
changed file, removes the local packet parser's standalone inline test block,
and restores `LICENSE-MIT`, `LICENSE-APACHE`, and `NOTICE.md` verbatim from
the pinned upstream root. The upstream source set is otherwise retained
without peripheral pruning. Package cache markers, package-local lockfile,
and upstream changelog are omitted; the workspace lockfile controls builds.

Upstream copyright and terms remain intact. Original local additions:
Copyright 2026 Nicholas Salois, Apache-2.0. These modifications are not an
upstream Embassy release or an endorsement by its contributors. See the
[license summary](../../THIRD_PARTY.md).
