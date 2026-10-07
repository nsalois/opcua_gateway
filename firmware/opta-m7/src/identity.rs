// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! UID-derived MAC and USB serial identity.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use core::fmt::Write as FmtWrite;

use embassy_stm32::uid;

pub(crate) const USB_SERIAL_NUMBER_BYTES: usize = 12;

/// Locally administered MAC derived from the STM32H7 96-bit unique ID.
///
/// RM0399 Rev 4 §64.1 defines the read-only UID and its base address. The
/// product compresses it to 32 variable MAC bits, which is stable without
/// provisioning but does not mathematically guarantee collision-free fleets.
pub(crate) fn uid_words() -> [u32; 3] {
    let bytes = uid::uid();
    [
        u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]),
    ]
}

/// Locally administered MAC derived from the supplied STM32H7 unique ID.
pub(crate) fn mac_from_uid(uid: [u32; 3]) -> [u8; 6] {
    let mix = uid[0] ^ uid[1].rotate_left(11) ^ uid[2].rotate_left(22);
    [
        0x02, // locally administered, unicast
        0xA7, // project discriminator inside the locally administered prefix
        (mix >> 24) as u8,
        (mix >> 16) as u8,
        (mix >> 8) as u8,
        mix as u8,
    ]
}

/// Stable USB identity derived from the same unique-ID-backed MAC used by the
/// network stack. The 12 hexadecimal digits fit exactly in the fixed buffer.
pub(crate) fn usb_serial_number_from_mac(
    mac: [u8; 6],
) -> heapless::String<USB_SERIAL_NUMBER_BYTES> {
    let mut serial = heapless::String::new();
    let _ = write!(
        serial,
        "{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    serial
}
