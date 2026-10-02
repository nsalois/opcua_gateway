# Opta M4 quarantine firmware

This dependency-free Cortex-M4 image is the inert companion to the M7 product.
The checker validates the complete vector table, initial stack, masked reset,
wait loop, memory limits and exact compact/padded image hashes. It performs no
hardware contact or installation. M4 has no product runtime or Cargo dependencies.

From the repository root:

```bash
python3 -B tools/check_m4_quarantine_build_resource.py --build-std \
  --version 1.1.0 --archive-dir "$PWD/build-output/archive" \
  --output "$PWD/build-output/m4-report.json"
```

See the root [build instructions](../../README.md) for prerequisites and setup.
M4 version/source identity is recorded in the build report, not embedded in its
minimal binary. Keep that report with the binary. This is not a flashable release
package or hardware qualification.

Original source is Apache-2.0. The pinned interrupt-table extract retains the
STMicroelectronics copyright and [BSD-3-Clause terms](LICENSE-ST); see the root
[third-party information](../../THIRD_PARTY.md).
