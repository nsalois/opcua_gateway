//! Dedicated interrupt-mode executor for the watchdog monitor.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use embassy_executor::{InterruptExecutor, SendSpawner};

use crate::board;

const TIM7_IRQ_NUMBER: u16 = embassy_stm32::interrupt::TIM7 as u16;
const _: () = assert!(TIM7_IRQ_NUMBER == 55);

// SAFETY: the stable symbol exposes a read-only address/size for build and HIL
// accounting. Rust owns the executor, starts it exactly once, and its only poll
// entry is the TIM7 vector below.
#[unsafe(export_name = "M7_WATCHDOG_INTERRUPT_EXECUTOR")]
pub static WATCHDOG_EXECUTOR: InterruptExecutor = InterruptExecutor::new();

/// Start the watchdog executor after clocks, retained diagnostics, IWDG, and
/// task check-ins are initialized. `InterruptExecutor::start` unmasks IRQ 55.
pub(crate) fn start() -> SendSpawner {
    board::prepare_watchdog_executor_interrupt();
    WATCHDOG_EXECUTOR.start(embassy_stm32::interrupt::TIM7)
}

// SAFETY: cortex-m-rt resolves the TIM7 vector to this exact C symbol. IRQ 55
// is dedicated to this software executor; TIM7 hardware remains reset and
// clock-gated, so no peripheral source can invoke the vector.
#[allow(non_snake_case)]
#[unsafe(no_mangle)]
unsafe extern "C" fn TIM7() {
    // SAFETY: this function is the dedicated TIM7 interrupt handler and start()
    // initializes the executor before unmasking the IRQ.
    unsafe { WATCHDOG_EXECUTOR.on_interrupt() }
}
