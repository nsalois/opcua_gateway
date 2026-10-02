//! Diagnostic-only single-generated-frame trip of the product MPU stack guard.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use core::hint::black_box;
use core::mem::MaybeUninit;

use crate::board::STACK_GUARD_MPU_SIZE_BYTES;

// One complete stack reserve makes the generated adjustment cross the 16 KiB
// no-access band from the normal post-boot MSP position. The build/resource gate
// measures the emitted frame and admits this symbol only for this diagnostic.
const TRIP_FRAME_BYTES: usize = 65_536;

// SAFETY: memory.x defines this 16-KiB-aligned boundary at the bottom of the
// reserved M7 stack. This diagnostic deliberately targets the middle of its
// product MPU no-access region after the generated frame has moved MSP below it.
unsafe extern "C" {
    static __stack_limit: u8;
}

/// Cross the complete guard with one generated frame, then fault on a store
/// through that frame into the no-access band.
#[inline(never)]
// SAFETY: this stable symbol is named explicitly so the build/resource gate can
// confine its sole oversized-frame exemption to this diagnostic function.
#[unsafe(no_mangle)]
pub(crate) extern "C" fn opta_m7_stack_guard_trip() {
    let mut frame = MaybeUninit::<[u8; TRIP_FRAME_BYTES]>::uninit();
    let frame_base = black_box(frame.as_mut_ptr().cast::<u8>());
    let guard_target = core::ptr::addr_of!(__stack_limit)
        .cast::<u8>()
        .wrapping_add((STACK_GUARD_MPU_SIZE_BYTES / 2) as usize);
    let guard_offset = black_box((guard_target as usize).wrapping_sub(frame_base as usize));

    // SAFETY: the 64 KiB generated frame spans the linked guard target when
    // called after normal boot from the reserved stack. The underlying address
    // is valid D1 SRAM; the deliberate MPU denial is the behavior under test.
    unsafe {
        frame_base.wrapping_add(guard_offset).write_volatile(0xA5);
    }

    // A missing MPU fault must remain observable as a failed proof rather than
    // allowing this diagnostic image to continue serving as a product image.
    loop {
        cortex_m::asm::nop();
    }
}

pub(crate) fn trigger() {
    let trip: extern "C" fn() = black_box(opta_m7_stack_guard_trip);
    trip();
}
