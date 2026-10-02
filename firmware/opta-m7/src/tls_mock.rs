// Firmware policy marker: crate root declares #![no_std]; this diagnostic
// wrapper must not use alloc or std.
use core::sync::atomic::{AtomicU32, Ordering};

use embassy_net::Stack;
use embassy_stm32::peripherals::RNG;
use embassy_stm32::rng::Rng;
use opta_gateway_contracts::config::{GatewayConfig, TrustState};
use opta_gateway_contracts::freshness::CacheReadStatus;
use opta_tls_verify::UnixTime;

use crate::buchi_tls_transport::{
    run_buchi_tls_client, BuchiTlsConfig, BuchiTlsTrustSource, TlsObserver, TlsStage,
    TlsTransportError,
};
use crate::SharedRuntime;

// Every mock-only source assumption stays in this diagnostic wrapper. The
// default composition obtains all four values from runtime configuration/trust.
const TLS_MOCK_PORT: u16 = 18_443;
const TLS_MOCK_DEFAULT_IPV4: [u8; 4] = [192, 0, 2, 1];
const TLS_MOCK_CA_DER: &[u8] = include_bytes!("certs/mock_buchi_test_ca.der");
const TLS_MOCK_VERIFIER_TIME: UnixTime = UnixTime::from_seconds(1_782_388_800);

// SAFETY: stable debugger/HIL readback symbols for the diagnostic TLS mock
// overlay. Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_TLS_STAGE: AtomicU32 = AtomicU32::new(TlsStage::Disabled as u32);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_TLS_LAST_ERROR: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_TLS_COMPLETED_FETCHES: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_TLS_FAILED_FETCHES: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_TLS_LAST_HTTP_STATUS: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_TLS_LAST_CACHE_STATUS: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_TLS_LAST_SERVER_IPV4: AtomicU32 = AtomicU32::new(0);

struct DiagnosticObserver;

impl TlsObserver for DiagnosticObserver {
    fn set_stage(&self, stage: TlsStage) {
        M7_TLS_STAGE.store(stage as u32, Ordering::Relaxed);
    }

    fn set_error(&self, error: TlsTransportError) {
        M7_TLS_LAST_ERROR.store(error as u32, Ordering::Relaxed);
    }

    fn set_server_ipv4(&self, server_ipv4: [u8; 4]) {
        M7_TLS_LAST_SERVER_IPV4.store(u32::from_be_bytes(server_ipv4), Ordering::Relaxed);
    }

    fn set_http_status(&self, status: i32) {
        M7_TLS_LAST_HTTP_STATUS.store(status.max(0) as u32, Ordering::Relaxed);
    }

    fn set_counts(&self, completed: u32, failed: u32) {
        M7_TLS_COMPLETED_FETCHES.store(completed, Ordering::Relaxed);
        M7_TLS_FAILED_FETCHES.store(failed, Ordering::Relaxed);
    }

    fn set_cache_status(&self, status: CacheReadStatus) {
        M7_TLS_LAST_CACHE_STATUS.store(cache_status_code(status), Ordering::Relaxed);
    }
}

#[embassy_executor::task]
pub(crate) async fn buchi_tls_client_shared_task(
    stack: Stack<'static>,
    rng: Rng<'static, RNG>,
    reconnect_seed: u32,
    config: GatewayConfig,
    runtime: &'static SharedRuntime,
) -> ! {
    crate::M7_BUCHI_TRUST_STATE.store(TrustState::Provisioned as u32, Ordering::Relaxed);
    crate::M7_BUCHI_TRUST_ANCHOR_PRESENT.store(1, Ordering::Relaxed);
    crate::M7_BUCHI_TRUST_RTC_USABLE.store(1, Ordering::Relaxed);

    let server_ipv4 = if config.buchi_ip == [0, 0, 0, 0] {
        TLS_MOCK_DEFAULT_IPV4
    } else {
        config.buchi_ip
    };
    run_buchi_tls_client(
        stack,
        rng,
        reconnect_seed,
        BuchiTlsConfig {
            gateway: config,
            server_ipv4,
            port: TLS_MOCK_PORT,
            trust_source: BuchiTlsTrustSource::Static {
                ca_der: TLS_MOCK_CA_DER,
                verifier_time: TLS_MOCK_VERIFIER_TIME,
            },
        },
        runtime,
        DiagnosticObserver,
    )
    .await
}

const fn cache_status_code(status: CacheReadStatus) -> u32 {
    match status {
        CacheReadStatus::Ok => 1,
        CacheReadStatus::InvalidIndex => 2,
        CacheReadStatus::NeverPublished => 3,
        CacheReadStatus::Stale => 4,
        CacheReadStatus::NotConnected => 5,
        CacheReadStatus::RetryExhausted => 6,
    }
}
