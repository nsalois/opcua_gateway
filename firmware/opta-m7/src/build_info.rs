//! Immutable firmware identity, generated and validated on the build host.
// Firmware policy marker: crate root declares #![no_std]; no runtime host work.
// USB and OPC UA consume the same generated source identity.
#![allow(dead_code)]

include!(concat!(env!("OUT_DIR"), "/build_info.rs"));

#[cfg(feature = "product")]
pub(crate) static OPCUA_BUILD_INFO: opta_opcua::BuildInfo = opta_opcua::BuildInfo::new(
    "Opta Gateway Project",
    VERSION,
    BUILD_NUMBER,
    OPCUA_BUILD_DATE,
);
