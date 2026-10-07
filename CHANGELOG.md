# Source publication changes

## M7 1.3.9 / M4 1.1.0 — 2026-10-06

- Add firmware downloads and replace the build-output table with direct links.
- Update the original five-goal testing report with the October results and
  recounted development inventory. Runtime source is unchanged.

## M7 1.3.8 / M4 1.1.0 — 2026-10-06

- Streamline the README introduction and scope, remove front-page qualification
  notices, and clarify that its output table describes locally generated files.
  Runtime source is unchanged; M7 is rebuilt to record the updated revision.

## M7 1.3.1 / M4 1.1.0 — 2026-10-06

- Refresh subscription scheduling and interval/lifetime handling, including
  counter-boundary cases, and select the newest saved settings across sequence
  rollover.
- Record failed outcomes for queued writes cancelled by trust loss and writes
  whose trust changes while awaiting an upstream reply. This accounting does
  not retract an upstream operation already sent.
- Include executable host regression suites, synthetic certificate fixtures,
  pinned dependency metadata and GitHub build/test checks. Diagnostic features
  stay opt-in; the default firmware is the product composition.
- Publish source without the equipment manual or private engineering history.

Precommit canonical product validation (M7 1.3.0) measured Flash text
386,784 bytes, data 272, BSS 291,836, D2 36,992 and SRAM4 zero. Relative to the
previous public M7 1.2.8 build: text -688 bytes, BSS +1,632; data, D2, SRAM4,
65,536-byte stack reserve and 16,384-byte guard were unchanged. Compact BIN
extent was 387,064 bytes with 26.17% application Flash free and no resource
warnings. Final clean-build reports bind the publication commit and versions.
No export-specific QSPI/backup-state change or hardware measurement is claimed.
M4 source and intended minimal binary are unchanged.

The host suite passed in debug and optimized profiles. Dedicated board
confirmation of the write fixes and final production qualification remain open;
see the [testing report](firmware-testing-report.md).
