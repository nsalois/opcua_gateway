//! Product runtime trust state and RTC-backed verifier time.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use core::sync::atomic::{AtomicU32, Ordering};

use embassy_stm32::rtc::{DateTime, DayOfWeek, RtcTimeProvider};
use opta_gateway_contracts::config::{
    unix_seconds_to_utc, utc_to_unix_seconds, ConfigSource, GatewayConfig, GatewayTrust,
    TrustState, UtcDateTime,
};
use opta_gateway_contracts::trust_time::verifier_now_seconds as monotonic_verifier_now_seconds;
#[cfg(feature = "product")]
use opta_runtime::BuchiTrustHealthSnapshot;
use opta_tls_verify::{verify_ca_certificate_with_optional_time, UnixTime};
use static_cell::{ConstStaticCell, StaticCell};

use crate::config_storage::{load_field_config, write_config_slot, M7Flash};
use crate::uptime_now_ms_u64;

// SAFETY: stable debugger/HIL readback symbol for whether a usable Buchi TLS
// trust source was installed. Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_BUCHI_TRUST_READY: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL trust-state probes; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_BUCHI_TRUST_STATE: AtomicU32 = AtomicU32::new(TrustState::Missing as u32);

// SAFETY: stable debugger/HIL trust-state probe; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_BUCHI_TRUST_ANCHOR_PRESENT: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL trust-state probe; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_BUCHI_TRUST_RTC_USABLE: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL trust-state probe; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_BUCHI_TRUST_LAST_VERIFY_ERROR: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL trust-state probe; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_BUCHI_TRUST_VERIFY_ATTEMPTS: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL trust-state probe; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_BUCHI_TRUST_VERIFIED_SESSIONS: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL trust-state probe; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_BUCHI_TRUST_REVOCATIONS: AtomicU32 = AtomicU32::new(0);

// SAFETY: cross-task revocation latch; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_BUCHI_RUNTIME_REVOKED: AtomicU32 = AtomicU32::new(0);

#[cfg(feature = "product")]
pub(crate) fn snapshot_buchi_trust_health() -> BuchiTrustHealthSnapshot {
    let state = TrustState::from_u32(M7_BUCHI_TRUST_STATE.load(Ordering::Relaxed))
        .unwrap_or(TrustState::Missing);
    BuchiTrustHealthSnapshot {
        state,
        anchor_present: M7_BUCHI_TRUST_ANCHOR_PRESENT.load(Ordering::Relaxed) != 0,
        rtc_usable: M7_BUCHI_TRUST_RTC_USABLE.load(Ordering::Relaxed) != 0,
        last_verify_error: M7_BUCHI_TRUST_LAST_VERIFY_ERROR.load(Ordering::Relaxed),
        verify_attempt_count: M7_BUCHI_TRUST_VERIFY_ATTEMPTS.load(Ordering::Relaxed),
        verified_session_count: M7_BUCHI_TRUST_VERIFIED_SESSIONS.load(Ordering::Relaxed),
        revocation_count: M7_BUCHI_TRUST_REVOCATIONS.load(Ordering::Relaxed),
    }
}

#[cfg(feature = "product")]
pub(crate) type SharedRuntime = embassy_sync::mutex::Mutex<
    embassy_sync::blocking_mutex::raw::NoopRawMutex,
    opta_runtime::RuntimeDataAccess<
        { opta_gateway_contracts::product::BUCHI_WRITE_QUEUE_CAPACITY },
    >,
>;
#[cfg(feature = "product")]
pub(crate) static PRODUCT_RUNTIME: StaticCell<SharedRuntime> = StaticCell::new();

#[cfg(feature = "product")]
pub(crate) struct RuntimeTrust {
    pub(crate) material: GatewayTrust,
    pub(crate) state: TrustState,
    pub(crate) rtc_usable: bool,
    verifier_base_unix_seconds: u64,
    verifier_base_monotonic_ms: u64,
    pub(crate) generation: u32,
}

#[cfg(feature = "product")]
pub(crate) struct RuntimeTrustSnapshot {
    pub(crate) material: GatewayTrust,
    pub(crate) state: TrustState,
    pub(crate) verifier_now_seconds: Option<u64>,
    pub(crate) generation: u32,
}

#[cfg(feature = "product")]
impl RuntimeTrust {
    pub(crate) const EMPTY: Self = Self {
        material: GatewayTrust::missing(),
        state: TrustState::Missing,
        rtc_usable: false,
        verifier_base_unix_seconds: 0,
        verifier_base_monotonic_ms: 0,
        generation: 0,
    };

    pub(crate) fn from_boot(material: GatewayTrust, rtc_unix_seconds: Option<u64>) -> Self {
        let mut trust = Self::EMPTY;
        trust.material = material;
        trust.initialize_from_boot(rtc_unix_seconds);
        trust
    }

    pub(crate) fn initialize_from_boot(&mut self, rtc_unix_seconds: Option<u64>) {
        let material = &self.material;
        let rtc_usable = rtc_unix_seconds.is_some() && material.time_provisioned();
        let mut state = TrustState::Missing;
        let mut last_verify_error = 0;
        if material.is_complete() {
            let verifier_time = if rtc_usable {
                rtc_unix_seconds.map(UnixTime::from_seconds)
            } else {
                None
            };
            if verify_ca_certificate_with_optional_time(material.ca_der(), verifier_time).is_ok() {
                state = TrustState::Provisioned;
            } else {
                last_verify_error = 2;
            }
        }
        self.state = state;
        self.rtc_usable = rtc_usable;
        self.verifier_base_unix_seconds = rtc_unix_seconds.unwrap_or(0);
        self.verifier_base_monotonic_ms = uptime_now_ms_u64();
        self.generation = 0;
        publish_trust_probes(self, last_verify_error);
    }

    pub(crate) fn verifier_now_seconds(&self) -> Option<u64> {
        if !self.rtc_usable {
            return None;
        }
        Some(monotonic_verifier_now_seconds(
            self.verifier_base_unix_seconds,
            self.verifier_base_monotonic_ms,
            uptime_now_ms_u64(),
        ))
    }

    pub(crate) fn snapshot(&self) -> RuntimeTrustSnapshot {
        RuntimeTrustSnapshot {
            material: self.material.clone(),
            state: self.state,
            verifier_now_seconds: self.verifier_now_seconds(),
            generation: self.generation,
        }
    }

    pub(crate) fn transition_if_generation(
        &mut self,
        generation: u32,
        state: TrustState,
        last_verify_error: u32,
    ) -> bool {
        if self.generation != generation || self.state == TrustState::Revoked {
            return false;
        }
        self.state = state;
        publish_trust_probes(self, last_verify_error);
        true
    }

    pub(crate) fn install(&mut self, material: GatewayTrust, rtc_unix_seconds: u64) {
        self.install_inner(material, Some(rtc_unix_seconds));
    }

    pub(crate) fn install_without_time(&mut self, material: GatewayTrust) {
        self.install_inner(material, None);
    }

    fn install_inner(&mut self, material: GatewayTrust, rtc_unix_seconds: Option<u64>) {
        self.material = material;
        self.state = if self.material.is_complete() {
            TrustState::Provisioned
        } else {
            TrustState::Missing
        };
        self.rtc_usable = rtc_unix_seconds.is_some() && self.material.time_provisioned();
        self.verifier_base_unix_seconds = rtc_unix_seconds.unwrap_or(0);
        self.verifier_base_monotonic_ms = uptime_now_ms_u64();
        self.generation = self.generation.wrapping_add(1);
        M7_BUCHI_RUNTIME_REVOKED.store(0, Ordering::Relaxed);
        publish_trust_probes(self, 0);
    }

    pub(crate) fn revoke(&mut self) {
        self.material = GatewayTrust::missing();
        self.state = TrustState::Revoked;
        self.rtc_usable = false;
        self.verifier_base_unix_seconds = 0;
        self.verifier_base_monotonic_ms = uptime_now_ms_u64();
        self.generation = self.generation.wrapping_add(1);
        M7_BUCHI_RUNTIME_REVOKED.store(1, Ordering::Relaxed);
        M7_BUCHI_TRUST_REVOCATIONS.fetch_add(1, Ordering::Relaxed);
        publish_trust_probes(self, 0);
    }
}

#[cfg(feature = "product")]
pub(crate) type SharedTrust =
    embassy_sync::mutex::Mutex<embassy_sync::blocking_mutex::raw::NoopRawMutex, RuntimeTrust>;

#[cfg(feature = "product")]
pub(crate) static PRODUCT_TRUST: ConstStaticCell<SharedTrust> =
    ConstStaticCell::new(SharedTrust::new(RuntimeTrust::EMPTY));

#[cfg(feature = "product")]
fn publish_trust_probes(trust: &RuntimeTrust, last_verify_error: u32) {
    M7_BUCHI_TRUST_READY.store(
        u32::from(trust.state == TrustState::Verified),
        Ordering::Relaxed,
    );
    M7_BUCHI_TRUST_STATE.store(trust.state as u32, Ordering::Relaxed);
    M7_BUCHI_TRUST_ANCHOR_PRESENT.store(
        u32::from(trust.material.is_anchor_present()),
        Ordering::Relaxed,
    );
    M7_BUCHI_TRUST_RTC_USABLE.store(u32::from(trust.rtc_usable), Ordering::Relaxed);
    M7_BUCHI_TRUST_LAST_VERIFY_ERROR.store(last_verify_error, Ordering::Relaxed);
}

#[cfg(feature = "product")]
#[derive(Clone, Copy)]
pub(crate) struct TrustStatusSnapshot {
    pub(crate) state: TrustState,
    pub(crate) anchor_present: bool,
    pub(crate) rtc_usable: bool,
    pub(crate) upload_expected: usize,
    pub(crate) upload_received: usize,
}

#[cfg(feature = "product")]
pub(crate) fn rtc_datetime_from_unix(seconds: u64) -> Result<DateTime, &'static str> {
    let value = unix_seconds_to_utc(seconds).map_err(|_| "trust-time-out-of-range")?;
    let weekday = match value.weekday {
        1 => DayOfWeek::Monday,
        2 => DayOfWeek::Tuesday,
        3 => DayOfWeek::Wednesday,
        4 => DayOfWeek::Thursday,
        5 => DayOfWeek::Friday,
        6 => DayOfWeek::Saturday,
        7 => DayOfWeek::Sunday,
        _ => return Err("trust-time-out-of-range"),
    };
    DateTime::from(
        value.year,
        value.month,
        value.day,
        weekday,
        value.hour,
        value.minute,
        value.second,
        0,
    )
    .map_err(|_| "trust-time-out-of-range")
}

#[cfg(feature = "product")]
fn rtc_datetime_to_unix(value: &DateTime) -> Option<u64> {
    utc_to_unix_seconds(UtcDateTime {
        year: value.year(),
        month: value.month(),
        day: value.day(),
        weekday: value.day_of_week() as u8,
        hour: value.hour(),
        minute: value.minute(),
        second: value.second(),
    })
    .ok()
}

#[cfg(feature = "product")]
pub(crate) fn read_usable_rtc_seconds(provider: &RtcTimeProvider) -> Option<u64> {
    provider
        .now()
        .ok()
        .and_then(|value| rtc_datetime_to_unix(&value))
}

#[cfg(feature = "product")]
pub(crate) fn commit_trust_record(
    flash: &mut M7Flash,
    uid_words: [u32; 3],
    trust: &GatewayTrust,
) -> Result<(ConfigSource, u64, GatewayConfig), &'static str> {
    let mut current_trust = GatewayTrust::missing();
    let (current, config) = load_field_config(uid_words, &mut current_trust);
    let target = current.inactive_slot();
    let sequence = current.next_sequence();
    write_config_slot(flash, target, sequence, &config, trust)?;
    Ok((target, sequence, config))
}

#[cfg(feature = "product")]
pub(crate) async fn apply_runtime_revocation(
    runtime: &'static SharedRuntime,
    trust: &'static SharedTrust,
) {
    {
        let mut trust = trust.lock().await;
        trust.revoke();
    }
    {
        let mut data_access = runtime.lock().await;
        data_access.revoke_upstream_trust();
    }
}
