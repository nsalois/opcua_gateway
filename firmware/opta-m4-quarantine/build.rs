// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

use std::{
    collections::BTreeMap,
    env, fs,
    path::{Path, PathBuf},
};

const FIRST_EXTERNAL_IRQ: i16 = 0;
const LAST_EXTERNAL_IRQ: i16 = 149;
const VECTOR_WORDS: usize = 16 + LAST_EXTERNAL_IRQ as usize + 1;

fn parse_interrupts(path: &Path) -> BTreeMap<i16, String> {
    let source = fs::read_to_string(path).expect("read pinned STM32H747 interrupt list");
    let mut interrupts = BTreeMap::new();
    let mut saw_header = false;

    for raw_line in source.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if !saw_header {
            assert_eq!(line, "irqn,name", "unexpected interrupt-list header");
            saw_header = true;
            continue;
        }
        let (irqn, name) = line
            .split_once(',')
            .expect("interrupt row must contain exactly one comma");
        assert!(!name.is_empty(), "interrupt name must not be empty");
        assert!(
            name.bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
            "interrupt name contains a non-identifier byte"
        );
        let irqn: i16 = irqn
            .parse()
            .expect("interrupt number must be a signed integer");
        assert!(
            (-14..=LAST_EXTERNAL_IRQ).contains(&irqn),
            "interrupt number is outside the STM32H747 CM4 vector range"
        );
        assert_ne!(irqn, -15, "reset is supplied by the quarantine image");
        assert!(
            interrupts.insert(irqn, name.to_owned()).is_none(),
            "duplicate interrupt number"
        );
    }

    assert!(saw_header, "missing interrupt-list header");
    assert_eq!(
        interrupts.get(&-14).map(String::as_str),
        Some("NonMaskableInt")
    );
    assert_eq!(
        interrupts.get(&LAST_EXTERNAL_IRQ).map(String::as_str),
        Some("WAKEUP_PIN")
    );
    assert_eq!(
        interrupts.range(FIRST_EXTERNAL_IRQ..).count(),
        145,
        "pinned STM32H747 CM4 source must define 145 external IRQs"
    );
    interrupts
}

fn generated_assembly(interrupts: &BTreeMap<i16, String>) -> String {
    let mut assembly = String::from(
        r#".syntax unified
.cpu cortex-m4
.thumb

.section .vector_table,"a",%progbits
.balign 1024
.global __vector_table
.type __vector_table,%object
__vector_table:
"#,
    );

    for slot in 0..VECTOR_WORDS {
        let word = match slot {
            0 => "0x10048000",
            1 => "quarantine_reset",
            _ => {
                let irqn = slot as i16 - 16;
                if interrupts.contains_key(&irqn) {
                    "quarantine_inert"
                } else {
                    "0"
                }
            }
        };
        assembly.push_str(&format!("  .word {word}\n"));
    }

    assembly.push_str(
        r#".global __vector_table_end
__vector_table_end:
.size __vector_table, __vector_table_end - __vector_table

.section .text.quarantine,"ax",%progbits
.balign 2
.global quarantine_reset
.type quarantine_reset,%function
.thumb_func
quarantine_reset:
  cpsid i
  b quarantine_wait
.size quarantine_reset, . - quarantine_reset

.global quarantine_wait
.type quarantine_wait,%function
.thumb_func
quarantine_wait:
  wfi
  b quarantine_wait
.size quarantine_wait, . - quarantine_wait

.global quarantine_inert
.type quarantine_inert,%function
.thumb_func
quarantine_inert:
  cpsid i
  b quarantine_wait
.size quarantine_inert, . - quarantine_inert

.section .note.GNU-stack,"",%progbits
"#,
    );
    assembly
}

fn main() {
    let manifest_dir = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").unwrap());
    let interrupt_list = manifest_dir.join("stm32h747xx-cm4-interrupts.csv");
    let linker_script = manifest_dir.join("linker.ld");
    let out_dir = PathBuf::from(env::var_os("OUT_DIR").unwrap());

    let interrupts = parse_interrupts(&interrupt_list);
    let assembly = generated_assembly(&interrupts);
    fs::write(out_dir.join("quarantine.S"), assembly).expect("write generated assembly");

    println!("cargo:rerun-if-changed={}", interrupt_list.display());
    println!("cargo:rerun-if-changed={}", linker_script.display());
    println!("cargo:rustc-link-search={}", manifest_dir.display());
    println!("cargo:rustc-link-arg=-Tlinker.ld");
    println!("cargo:rustc-link-arg=--nmagic");
}
