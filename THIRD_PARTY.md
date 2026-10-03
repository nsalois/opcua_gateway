# Third-party licensing

The root Apache-2.0 license covers original project contributions only.
Fetched dependencies are identified by exact versions and checksums in
`Cargo.lock`; their original license files and notices accompany their
registry packages. They are not relicensed by this repository. Rust and
system build tools are separate prerequisites with their own terms.

## Vendored Embassy STM32 0.6.0

Copyright (c) Embassy project contributors. Upstream is
[embassy-rs/embassy](https://github.com/embassy-rs/embassy), revision
`84444a19eb57d978e3c09fcdc8e60cdd7278eb03`, directory `embassy-stm32`.
The packaged baseline is
[embassy-stm32 0.6.0](https://static.crates.io/crates/embassy-stm32/embassy-stm32-0.6.0.crate).
The upstream project offers **MIT OR Apache-2.0**; restored verbatim texts
and notices are retained in the vendor directory:

- [MIT](vendor/embassy-stm32-0.6.0/LICENSE-MIT)
- [Apache-2.0](vendor/embassy-stm32-0.6.0/LICENSE-APACHE)
- [Upstream notice](vendor/embassy-stm32-0.6.0/NOTICE.md)
- [Local modifications and provenance](vendor/embassy-stm32-0.6.0/MODIFICATIONS.md)

Original local additions are Apache-2.0, Copyright 2026 Nicholas Salois;
they do not claim ownership of upstream work. The combined modified
package is offered under Apache-2.0, as declared by its locally modified
Cargo manifests. The upstream dual-license statement is preserved and applies to upstream contributions.

No other third-party implementation is copied into this source repository.
The M4 interrupt-table extract is separately covered below.
The lockfile also resolves optional platform and upstream development
dependencies; presence in it does not mean a package is linked into M7.
Any later binary distribution needs notices for its actual linked contents.

## STMicroelectronics M4 interrupt table

`firmware/opta-m4-quarantine/stm32h747xx-cm4-interrupts.csv` extracts
`IRQn_Type` assignments for Cortex-M4 from the STM32H747xx device header in
[ArduinoCore-mbed 4.5.0](https://github.com/arduino/ArduinoCore-mbed/blob/4.5.0/cores/arduino/mbed/targets/TARGET_STM/TARGET_STM32H7/STM32Cube_FW/CMSIS/stm32h747xx.h).
The header attributes Copyright (c) 2019 STMicroelectronics, All rights
reserved, and explicitly grants BSD-3-Clause. The extract keeps that license;
it is not covered by the original project's Apache-2.0 grant.

The complete [BSD-3-Clause notice](firmware/opta-m4-quarantine/LICENSE-ST)
accompanies the extract. The CSV retains its upstream URL, package, source
hash and extraction description. Its bytes and checker hash pin are unchanged.
Only the interrupt assignments are included, not the full device header.
