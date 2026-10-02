#![no_std]
#![no_main]

// SAFETY: build.rs generates only the complete STM32H747 CM4 vector table and
// three non-returning Cortex-M4 routines admitted by ADR 0023. linker.ld fixes
// the vector origin and the exclusive 1 KiB D2 stack alias, rejects all static
// RAM, and caps allocated Flash at 4 KiB. The resource checker independently
// validates every word and instruction before this artifact can be packaged.
core::arch::global_asm!(include_str!(concat!(env!("OUT_DIR"), "/quarantine.S")));

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo<'_>) -> ! {
    // This routine is unreachable from the assembly-only entry path and is
    // garbage-collected. It exists solely to satisfy the no_std crate contract.
    loop {
        core::hint::spin_loop();
    }
}
