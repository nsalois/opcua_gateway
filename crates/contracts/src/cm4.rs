// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Pure STM32H747 CM4 boot-authorization decoding used by firmware and tests.

/// `SYSCFG_UR1.BCM4`, copied from the option-byte boot policy.
pub const SYSCFG_UR1_BCM4: u32 = 1 << 0;
/// `RCC_CR.D2CKRDY`, which reports D2 clock availability, not CM4 execution.
pub const RCC_CR_D2CKRDY: u32 = 1 << 15;
/// `RCC_GCR.WW1RSC`, the full-system WWDG1 reset-scope control.
pub const RCC_GCR_WW1RSC: u32 = 1 << 0;
/// `RCC_GCR.BOOT_C2`, the software release authorization for CPU2/CM4.
pub const RCC_GCR_BOOT_C2: u32 = 1 << 3;

/// Stable debugger-facing authorization states. These do not prove execution.
#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Cm4AuthorizationState {
    Unknown = 0,
    HeldByOption = 1,
    BootEnabledByOption = 2,
    BootReleasedBySoftware = 3,
}

impl Cm4AuthorizationState {
    pub const fn as_word(self) -> u32 {
        self as u32
    }
}

pub const fn bcm4_enabled(syscfg_ur1: u32) -> bool {
    syscfg_ur1 & SYSCFG_UR1_BCM4 != 0
}

pub const fn boot_c2_set(rcc_gcr: u32) -> bool {
    rcc_gcr & RCC_GCR_BOOT_C2 != 0
}

pub const fn d2_clocks_ready(rcc_cr: u32) -> bool {
    rcc_cr & RCC_CR_D2CKRDY != 0
}

/// Classify boot authorization according to RM0399 Rev 4 section 9.4.8 and
/// Table 58. `BOOT_C2` dominates because it authorizes CPU2 regardless of
/// `BCM4`; neither result asserts that CM4 is presently executing.
pub const fn authorization_state(syscfg_ur1: u32, rcc_gcr: u32) -> Cm4AuthorizationState {
    if boot_c2_set(rcc_gcr) {
        Cm4AuthorizationState::BootReleasedBySoftware
    } else if bcm4_enabled(syscfg_ur1) {
        Cm4AuthorizationState::BootEnabledByOption
    } else {
        Cm4AuthorizationState::HeldByOption
    }
}
