// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Immutable software identity for the standard namespace-zero BuildInfo value.
//! OPC UA Part 5 sections 7.7/12.4; Part 6 section 5.2.2.15.
use crate::{Encoder, Result, PRODUCT_URI};

pub(crate) const DATATYPE_STRUCTURE: u32 = 22;
pub(crate) const NODEID_HAS_MODELLING_RULE: u32 = 37;
pub(crate) const NODEID_MODELLING_RULE_TYPE: u32 = 77;
pub(crate) const NODEID_MANDATORY: u32 = 78;
pub(crate) const NODEID_HAS_ENCODING: u32 = 38;
pub(crate) const NODEID_DATA_TYPE_ENCODING_TYPE: u32 = 76;
pub(crate) const DATATYPE_BUILD_INFO: u32 = 338;
pub(crate) const BUILD_INFO_BINARY: u32 = 340;
pub(crate) const NODEID_BUILD_INFO: u32 = 2260;
pub(crate) const NODEID_BUILD_INFO_TYPE: u32 = 3051;
// Instance IDs in structure-field order, from the official UA NodeSet.
pub(crate) const BUILD_INFO_FIELDS: [(u32, &str); 6] = [
    (2262, "ProductUri"),
    (2263, "ManufacturerName"),
    (2261, "ProductName"),
    (2264, "SoftwareVersion"),
    (2265, "BuildNumber"),
    (2266, "BuildDate"),
];

/// Static strings are borrowed once per server; no runtime allocation or mutation.
#[derive(Debug, PartialEq)]
pub struct BuildInfo {
    manufacturer: &'static str,
    version: &'static str,
    number: &'static str,
    date: i64,
}

impl BuildInfo {
    /// BuildDate uses OPC UA UTC ticks. A zero date explicitly means unknown.
    pub const fn new(
        manufacturer: &'static str,
        version: &'static str,
        number: &'static str,
        date: i64,
    ) -> Self {
        assert!(!manufacturer.is_empty() && manufacturer.len() <= 96);
        assert!(!version.is_empty() && version.len() <= 32);
        assert!(!number.is_empty() && number.len() <= 180);
        assert!(date >= 0);
        Self {
            manufacturer,
            version,
            number,
            date,
        }
    }

    pub(crate) const fn strings(&self) -> [&'static str; 5] {
        [
            PRODUCT_URI,
            self.manufacturer,
            "Opta Buchi OPC UA Gateway",
            self.version,
            self.number,
        ]
    }

    pub(crate) const fn date(&self) -> i64 {
        self.date
    }

    pub(crate) fn write_variant(&self, e: &mut Encoder<'_>) -> Result<()> {
        e.write_u8(22)?; // Scalar ExtensionObject Variant.
        let body = e.begin_extension_object(BUILD_INFO_BINARY)?;
        for value in self.strings() {
            e.write_string(value)?;
        }
        e.write_i64(self.date)?;
        e.end_extension_object(body)
    }
}
