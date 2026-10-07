// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

use super::VerifyError;

pub(crate) const TAG_BOOLEAN: u8 = 0x01;
pub(crate) const TAG_INTEGER: u8 = 0x02;
pub(crate) const TAG_BIT_STRING: u8 = 0x03;
pub(crate) const TAG_OCTET_STRING: u8 = 0x04;
pub(crate) const TAG_NULL: u8 = 0x05;
pub(crate) const TAG_OBJECT_ID: u8 = 0x06;
pub(crate) const TAG_SEQUENCE: u8 = 0x30;
pub(crate) const TAG_UTC_TIME: u8 = 0x17;
pub(crate) const TAG_GENERALIZED_TIME: u8 = 0x18;
pub(crate) const TAG_CONTEXT_0: u8 = 0xa0;
pub(crate) const TAG_CONTEXT_1: u8 = 0x81;
pub(crate) const TAG_CONTEXT_2: u8 = 0x82;
pub(crate) const TAG_CONTEXT_3_CONSTRUCTED: u8 = 0xa3;
pub(crate) const TAG_CONTEXT_7: u8 = 0x87;

pub const MAX_CERT_DER_BYTES: usize = 2048;

pub(crate) fn normalize_positive_integer(value: &[u8]) -> Result<&[u8], VerifyError> {
    if value.is_empty() {
        return Err(VerifyError::MalformedDer);
    }
    if value[0] == 0 {
        if value.len() == 1 {
            return Err(VerifyError::UnsupportedKey);
        }
        if value[1] & 0x80 == 0 {
            return Err(VerifyError::MalformedDer);
        }
        Ok(&value[1..])
    } else if value[0] & 0x80 != 0 {
        Err(VerifyError::MalformedDer)
    } else {
        Ok(value)
    }
}

pub(crate) fn parse_small_integer(value: &[u8]) -> Result<u32, VerifyError> {
    let unsigned = normalize_positive_integer(value)?;
    if unsigned.len() > 4 {
        return Err(VerifyError::OversizedField);
    }
    let mut out = 0u32;
    for byte in unsigned {
        out = (out << 8) | u32::from(*byte);
    }
    Ok(out)
}

pub(crate) fn parse_boolean(value: &[u8]) -> Result<bool, VerifyError> {
    match value {
        [0x00] => Ok(false),
        [0xff] => Ok(true),
        _ => Err(VerifyError::MalformedDer),
    }
}

pub(crate) struct BitString<'a> {
    pub(crate) unused_bits: u8,
    pub(crate) bytes: &'a [u8],
}

pub(crate) fn parse_bit_string_with_unused(value: &[u8]) -> Result<BitString<'_>, VerifyError> {
    let Some((&unused_bits, bytes)) = value.split_first() else {
        return Err(VerifyError::MalformedDer);
    };
    if unused_bits > 7 {
        return Err(VerifyError::MalformedDer);
    }
    if bytes.is_empty() && unused_bits != 0 {
        return Err(VerifyError::MalformedDer);
    }
    if let Some(last) = bytes.last() {
        let unused_mask = if unused_bits == 0 {
            0
        } else {
            (1u8 << unused_bits) - 1
        };
        if last & unused_mask != 0 {
            return Err(VerifyError::MalformedDer);
        }
    }
    Ok(BitString { unused_bits, bytes })
}

pub(crate) fn parse_bit_string_bytes(value: &[u8]) -> Result<&[u8], VerifyError> {
    let bits = parse_bit_string_with_unused(value)?;
    if bits.unused_bits != 0 {
        return Err(VerifyError::MalformedDer);
    }
    Ok(bits.bytes)
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct Tlv<'a> {
    pub(crate) tag: u8,
    pub(crate) value: &'a [u8],
    pub(crate) full: &'a [u8],
}

#[derive(Debug, Copy, Clone)]
pub(crate) struct DerReader<'a> {
    input: &'a [u8],
    pos: usize,
}

impl<'a> DerReader<'a> {
    pub(crate) const fn new(input: &'a [u8]) -> Self {
        Self { input, pos: 0 }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.pos == self.input.len()
    }

    pub(crate) fn peek_tag(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    pub(crate) fn finish(&self) -> Result<(), VerifyError> {
        if self.is_empty() {
            Ok(())
        } else {
            Err(VerifyError::MalformedDer)
        }
    }

    pub(crate) fn read_expected(&mut self, tag: u8) -> Result<Tlv<'a>, VerifyError> {
        let tlv = self.read_any()?;
        if tlv.tag == tag {
            Ok(tlv)
        } else {
            Err(VerifyError::MalformedDer)
        }
    }

    pub(crate) fn read_any(&mut self) -> Result<Tlv<'a>, VerifyError> {
        let start = self.pos;
        let tag = *self.input.get(self.pos).ok_or(VerifyError::MalformedDer)?;
        if tag & 0x1f == 0x1f {
            return Err(VerifyError::MalformedDer);
        }
        self.pos += 1;
        let len = self.read_length()?;
        let value_start = self.pos;
        let value_end = value_start
            .checked_add(len)
            .ok_or(VerifyError::MalformedDer)?;
        if value_end > self.input.len() {
            return Err(VerifyError::MalformedDer);
        }
        self.pos = value_end;
        Ok(Tlv {
            tag,
            value: &self.input[value_start..value_end],
            full: &self.input[start..value_end],
        })
    }

    fn read_length(&mut self) -> Result<usize, VerifyError> {
        let first = *self.input.get(self.pos).ok_or(VerifyError::MalformedDer)?;
        self.pos += 1;
        if first & 0x80 == 0 {
            return Ok(first as usize);
        }
        let octets = (first & 0x7f) as usize;
        if octets == 0 || octets > 2 {
            return Err(VerifyError::MalformedDer);
        }
        if self.pos + octets > self.input.len() {
            return Err(VerifyError::MalformedDer);
        }
        if self.input[self.pos] == 0 {
            return Err(VerifyError::MalformedDer);
        }
        let mut len = 0usize;
        for _ in 0..octets {
            len = (len << 8) | usize::from(self.input[self.pos]);
            self.pos += 1;
        }
        if len < 128 {
            return Err(VerifyError::MalformedDer);
        }
        Ok(len)
    }
}
