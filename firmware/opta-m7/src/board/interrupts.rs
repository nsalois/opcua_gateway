// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Deterministic Cortex-M7 product interrupt priorities and TIM7 IRQ hygiene.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use embassy_stm32::interrupt::{InterruptExt, Priority};

const _: () = assert!(Priority::P0 as u8 == 0x00);
const _: () = assert!(Priority::P1 as u8 == 0x10);

/// Pin every product interrupt that can interact with the watchdog executor.
///
/// This runs after warm-launch NVIC normalization and before `init_primary`,
/// because the TIM2 Embassy time driver is enabled during primary init. The
/// STM32H747 implements four priority bits, so P0 and P1 map to raw IPR values
/// 0x00 and 0x10 respectively (RM0399 NVIC programming model).
pub(crate) fn configure_product_interrupt_priorities() {
    embassy_stm32::interrupt::TIM2.set_priority(Priority::P0);
    embassy_stm32::interrupt::ETH.set_priority(Priority::P0);
    embassy_stm32::interrupt::OTG_FS.set_priority(Priority::P0);
    embassy_stm32::interrupt::RNG.set_priority(Priority::P0);
    embassy_stm32::interrupt::TIM7.set_priority(Priority::P1);
}

/// Leave TIM7 hardware quiescent while reserving only its NVIC line for the
/// Embassy interrupt executor.
pub(crate) fn prepare_watchdog_executor_interrupt() {
    let tim7_irq = embassy_stm32::interrupt::TIM7;
    tim7_irq.disable();
    tim7_irq.unpend();

    // RM0399 RCC_APB1LRSTR.TIM7RST resets CR1/DIER and every other TIM7
    // peripheral register without using the timer as a time source. Clear the
    // APB clock gate first and leave it clear; only the otherwise-unused IRQ 55
    // is used by the software executor.
    let rcc = stm32_metapac::RCC;
    rcc.apb1lenr().modify(|w| w.set_tim7en(false));
    rcc.apb1lrstr().modify(|w| w.set_tim7rst(true));
    cortex_m::asm::dsb();
    rcc.apb1lrstr().modify(|w| w.set_tim7rst(false));
    cortex_m::asm::dsb();

    assert!(!rcc.apb1lenr().read().tim7en());
    assert!(!rcc.apb1lrstr().read().tim7rst());
    tim7_irq.unpend();
}
