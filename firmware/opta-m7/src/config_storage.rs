// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! A/B flash-backed field configuration and trust-record persistence.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use embassy_stm32::flash::{Blocking, Flash};
use opta_gateway_contracts::config::{
    self as field_config, ConfigSource, FactoryResetOutcome, FactoryResetState, FactoryResetStep,
    GatewayConfig, GatewayTrust, RecordKind,
};

use crate::watchdog::FlashMaintenanceGuard;

const FLASH_BASE_ADDR: u32 = 0x0800_0000;

pub(crate) type M7Flash = Flash<'static, Blocking>;

fn config_slot_slice(address: u32) -> &'static [u8] {
    // SAFETY: SLOT_A_ADDR/SLOT_B_ADDR are fixed internal-Flash config sectors
    // reserved by memory.x for persistent configuration. Reading them as immutable bytes is safe;
    // writes are routed through the STM32 flash driver and never alias a mutable
    // Rust reference while this slice is used for CRC/arbitration. Every runtime
    // write/erase invalidates this aligned record window before it can be read.
    // SAFETY: the fixed record window satisfies the lifetime and aliasing invariant above.
    unsafe { core::slice::from_raw_parts(address as *const u8, field_config::RECORD_SIZE) }
}

pub(crate) fn load_field_config(
    uid_words: [u32; 3],
    trust_out: &mut GatewayTrust,
) -> (field_config::LoadStatus, GatewayConfig) {
    field_config::select_config_into(
        config_slot_slice(field_config::SLOT_A_ADDR),
        config_slot_slice(field_config::SLOT_B_ADDR),
        GatewayConfig::defaults_from_uid(uid_words),
        trust_out,
    )
}

fn slot_addr(source: ConfigSource) -> u32 {
    match source {
        ConfigSource::SlotA => field_config::SLOT_A_ADDR,
        ConfigSource::SlotB => field_config::SLOT_B_ADDR,
        ConfigSource::Defaults => field_config::SLOT_A_ADDR,
    }
}

fn slot_offset(source: ConfigSource) -> u32 {
    slot_addr(source) - FLASH_BASE_ADDR
}

fn invalidate_config_slot_cache(source: ConfigSource) {
    let address = slot_addr(source) as usize;
    // SAFETY: both Flash slot addresses and RECORD_SIZE are 32-byte aligned,
    // satisfying Cortex-M7 cache-line requirements. The range is memory-mapped
    // internal Flash, so it cannot contain dirty CPU stores that invalidation
    // could discard. M7Flash serializes the write/erase operation, which has
    // completed before this runs; main memory therefore contains initialized
    // erased or programmed Flash data. SCB cache-maintenance registers are
    // write-only/stateless, so stealing this proxy cannot race retained state.
    // SAFETY: stealing the stateless cache-maintenance proxy preserves the invariant above.
    let mut cp = unsafe { cortex_m::Peripherals::steal() };
    // SAFETY: the aligned Flash record contains no dirty CPU stores to discard.
    unsafe {
        cp.SCB
            .invalidate_dcache_by_address(address, field_config::RECORD_SIZE);
    }
}

fn erase_config_slot(
    flash: &mut M7Flash,
    source: ConfigSource,
) -> Result<(), embassy_stm32::flash::Error> {
    let offset = slot_offset(source);
    let result = {
        let _maintenance = FlashMaintenanceGuard::enter();
        flash.blocking_erase(offset, offset + field_config::SLOT_SIZE as u32)
    };
    invalidate_config_slot_cache(source);
    result
}

fn program_config_slot_bytes(
    flash: &mut M7Flash,
    source: ConfigSource,
    record_offset: u32,
    bytes: &[u8],
) -> Result<(), embassy_stm32::flash::Error> {
    let result = {
        let _maintenance = FlashMaintenanceGuard::enter();
        flash.blocking_write(slot_offset(source) + record_offset, bytes)
    };
    invalidate_config_slot_cache(source);
    result
}

fn verify_config_slot(
    source: ConfigSource,
    expected_kind: RecordKind,
    sequence: u64,
    config: &GatewayConfig,
    trust: &GatewayTrust,
) -> bool {
    invalidate_config_slot_cache(source);
    let readback = config_slot_slice(slot_addr(source));
    let mut decoded_trust = GatewayTrust::missing();
    matches!(
        field_config::decode_slot_into(readback, &mut decoded_trust),
        Ok((kind, _, decoded_sequence, decoded_config))
            if kind == expected_kind
                && decoded_sequence == sequence
                && decoded_config == *config
                && decoded_trust == *trust
    )
}

pub(crate) fn write_config_slot(
    flash: &mut M7Flash,
    source: ConfigSource,
    sequence: u64,
    config: &GatewayConfig,
    trust: &GatewayTrust,
) -> Result<(), &'static str> {
    let record = field_config::encode_slot(sequence, config, trust).map_err(|_| "encode")?;
    if field_config::RECORD_BODY_SIZE % field_config::FLASH_WRITE_GRANULE != 0
        || field_config::RECORD_SIZE % field_config::FLASH_WRITE_GRANULE != 0
    {
        return Err("alignment");
    }
    erase_config_slot(flash, source).map_err(|_| "erase")?;
    program_config_slot_bytes(flash, source, 0, &record[..field_config::RECORD_BODY_SIZE])
        .map_err(|_| "program-body")?;
    // Commit the marker in a separate final flash granule. Selection rejects a
    // slot until the marker and CRC-covered body both decode, so a reset during
    // erase/body programming leaves the previously active slot authoritative.
    program_config_slot_bytes(
        flash,
        source,
        field_config::RECORD_BODY_SIZE as u32,
        &record[field_config::RECORD_BODY_SIZE..],
    )
    .map_err(|_| "program-marker")?;
    if verify_config_slot(source, RecordKind::Normal, sequence, config, trust) {
        Ok(())
    } else {
        Err("verify")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FactoryResetResult {
    state: FactoryResetState,
    error: Option<&'static str>,
}

impl FactoryResetResult {
    fn failed(state: FactoryResetState, stage: &'static str) -> Self {
        Self {
            state,
            error: Some(stage),
        }
    }

    fn awaiting_ram_revocation(state: FactoryResetState) -> Self {
        Self { state, error: None }
    }

    pub(crate) const fn outcome(self) -> FactoryResetOutcome {
        self.state.failure_outcome()
    }

    pub(crate) const fn error(self) -> Option<&'static str> {
        self.error
    }

    pub(crate) const fn target_slot(self) -> ConfigSource {
        self.state.target_slot()
    }

    pub(crate) const fn tombstone_sequence(self) -> u64 {
        self.state.tombstone_sequence()
    }

    pub(crate) fn complete_ram_revocation(&mut self) -> bool {
        self.state.complete_step(FactoryResetStep::RevokeRam)
    }
}

pub(crate) fn factory_reset_config(flash: &mut M7Flash, uid_words: [u32; 3]) -> FactoryResetResult {
    let mac = crate::identity::mac_from_uid(uid_words);
    let mut current_trust = GatewayTrust::missing();
    let (current, _) = load_field_config(uid_words, &mut current_trust);
    let mut state = FactoryResetState::new(current.source, current.sequence);
    let record = match field_config::encode_reset_slot(state.tombstone_sequence(), mac) {
        Ok(record) => record,
        Err(_) => return FactoryResetResult::failed(state, "encode"),
    };
    if field_config::RECORD_BODY_SIZE % field_config::FLASH_WRITE_GRANULE != 0
        || field_config::RECORD_SIZE % field_config::FLASH_WRITE_GRANULE != 0
    {
        return FactoryResetResult::failed(state, "alignment");
    }

    if erase_config_slot(flash, state.target_slot()).is_err() {
        return FactoryResetResult::failed(state, "erase-inactive");
    }
    let advanced = state.complete_step(FactoryResetStep::EraseInactive);
    debug_assert!(advanced);

    if program_config_slot_bytes(
        flash,
        state.target_slot(),
        0,
        &record[..field_config::RECORD_BODY_SIZE],
    )
    .is_err()
    {
        return FactoryResetResult::failed(state, "program-tombstone-body");
    }
    let advanced = state.complete_step(FactoryResetStep::ProgramTombstoneBody);
    debug_assert!(advanced);

    if program_config_slot_bytes(
        flash,
        state.target_slot(),
        field_config::RECORD_BODY_SIZE as u32,
        &record[field_config::RECORD_BODY_SIZE..],
    )
    .is_err()
    {
        return FactoryResetResult::failed(state, "program-tombstone-marker");
    }
    let advanced = state.complete_step(FactoryResetStep::ProgramTombstoneMarker);
    debug_assert!(advanced);

    if erase_config_slot(flash, state.old_slot()).is_err() {
        return FactoryResetResult::failed(state, "erase-old-slot");
    }
    let advanced = state.complete_step(FactoryResetStep::EraseOldSlot);
    debug_assert!(advanced);

    let defaults = GatewayConfig::defaults_from_mac(mac);
    let missing = GatewayTrust::missing();
    if !verify_config_slot(
        state.target_slot(),
        RecordKind::Reset,
        state.tombstone_sequence(),
        &defaults,
        &missing,
    ) {
        return FactoryResetResult::failed(state, "verify-tombstone");
    }
    let advanced = state.complete_step(FactoryResetStep::Readback);
    debug_assert!(advanced);
    FactoryResetResult::awaiting_ram_revocation(state)
}
