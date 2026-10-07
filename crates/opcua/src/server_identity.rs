// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

use core::str;

pub const APPLICATION_URI_PREFIX: &str = "urn:opta:gateway:rust-native-opcua:";
const APPLICATION_URI_LEN: usize = 59;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ServerIdentity {
    uri: [u8; APPLICATION_URI_LEN],
}

impl ServerIdentity {
    pub const fn from_uid_words(words: [u32; 3]) -> Self {
        let prefix = APPLICATION_URI_PREFIX.as_bytes();
        let mut uri = [0u8; APPLICATION_URI_LEN];
        let mut i = 0;
        while i < prefix.len() {
            uri[i] = prefix[i];
            i += 1;
        }
        let mut word = 0;
        while word < 3 {
            let bytes = words[word].to_be_bytes();
            let mut digit = 0;
            while digit < 4 {
                let byte = bytes[digit];
                uri[prefix.len() + word * 8 + digit * 2] = hex(byte >> 4);
                uri[prefix.len() + word * 8 + digit * 2 + 1] = hex(byte & 0x0f);
                digit += 1;
            }
            word += 1;
        }
        Self { uri }
    }

    pub const fn application_uri(&self) -> &str {
        match str::from_utf8(&self.uri) {
            Ok(value) => value,
            Err(_) => panic!("server identity is always ASCII"),
        }
    }
}

const fn hex(value: u8) -> u8 {
    match value {
        0..=9 => b'0' + value,
        _ => b'A' + value - 10,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_full_uid_in_canonical_order() {
        assert_eq!(
            ServerIdentity::from_uid_words([0x004B0032, 0x3033510D, 0x34323932]).application_uri(),
            "urn:opta:gateway:rust-native-opcua:004B00323033510D34323932"
        );
        assert_eq!(
            ServerIdentity::from_uid_words([0, 0, 0]).application_uri(),
            "urn:opta:gateway:rust-native-opcua:000000000000000000000000"
        );
        assert_eq!(
            ServerIdentity::from_uid_words([u32::MAX, u32::MAX, u32::MAX]).application_uri(),
            "urn:opta:gateway:rust-native-opcua:FFFFFFFFFFFFFFFFFFFFFFFF"
        );
        assert_ne!(
            ServerIdentity::from_uid_words([1, 2, 3]),
            ServerIdentity::from_uid_words([1, 2, 4])
        );
        assert_ne!(
            ServerIdentity::from_uid_words([1, 2, 3]),
            ServerIdentity::from_uid_words([1, 3, 3])
        );
        assert_ne!(
            ServerIdentity::from_uid_words([1, 2, 3]),
            ServerIdentity::from_uid_words([2, 2, 3])
        );
        assert_ne!(
            ServerIdentity::from_uid_words([0, 0, 0]),
            ServerIdentity::from_uid_words([1u32.rotate_left(11), 1, 0])
        );
    }
}
