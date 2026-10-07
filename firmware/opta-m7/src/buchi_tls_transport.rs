// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Generic bounded verified-TLS Büchi transport.
//!
//! Mock addresses, ports, fixed time, CA bytes, and debugger diagnostics are
//! deliberately supplied by the diagnostic wrapper and do not belong here.
// Firmware policy marker: the crate root declares #![no_std]; this module must
// not use alloc or std.
use core::fmt::Write as _;
use core::future::Future;
use core::str;
use core::sync::atomic::Ordering;

use crate::{RuntimeTrustSnapshot, SharedRuntime, SharedTrust};
use embassy_futures::select::{select, Either};
use embassy_net::tcp::TcpSocket;
use embassy_net::{IpAddress, IpEndpoint, Ipv4Address, Stack};
use embassy_stm32::peripherals::RNG;
use embassy_stm32::rng::Rng;
use embassy_time::{with_timeout, Duration, TimeoutError, Timer};
use embedded_tls::{
    Aes128GcmSha256, CryptoProvider, TlsConfig, TlsConnection, TlsContext, TlsError, TlsVerifier,
};
use opta_buchi::{
    build_basic_auth_token, build_get_request_with_connection, Endpoint, EndpointResponseError,
    HttpConnectionMode, HttpReadProgress, HttpReceiveBuffer, HttpResponseError,
};
use opta_buchi::{build_put_request_with_connection, write_http_status_to_opcua_status};
use opta_gateway_contracts::config::{GatewayConfig, GatewayTrust, Ipv4Display, TrustState};
use opta_gateway_contracts::freshness::CacheReadStatus;
use opta_gateway_contracts::opcua_status;
use opta_gateway_contracts::product;
use opta_gateway_contracts::reconnect::ReconnectPolicy;
use opta_gateway_contracts::watchdog::WatchdogSlot;
use opta_runtime::RuntimeWriteDispatchError;
use opta_runtime::{EndpointDueSet, EndpointPollScheduler, POLL_ENDPOINTS};
use opta_runtime::{RuntimeCache, RuntimeNode};
use opta_tls_verify::{EmbeddedTlsRsaVerifier, UnixTime};

const TLS_READ_RECORD_BYTES: usize = 16_640;
const TLS_WRITE_RECORD_BYTES: usize = 4_096;
const TLS_TCP_RX_BYTES: usize = 8_192;
const TLS_TCP_TX_BYTES: usize = 4_096;
const TLS_READ_CHUNK_BYTES: usize = 384;
const TLS_AUTH_TOKEN_BYTES: usize = 128;
const TLS_HOST_HEADER_BYTES: usize = 48;
const TLS_SERVER_NAME_BYTES: usize = 32;
const TLS_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(20);
const TLS_IO_TIMEOUT: Duration = Duration::from_secs(5);
const TLS_WATCHDOG_CHECKIN_INTERVAL: Duration = Duration::from_millis(250);
const TLS_SUCCESS_BACKOFF: Duration = Duration::from_secs(1);
const PRODUCT_TLS_PORT: u16 = 443;

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TlsStage {
    Disabled = 0,
    Config = 1,
    WaitNetwork = 2,
    TcpConnect = 3,
    TlsHandshake = 4,
    FetchProcess = 5,
    FetchSettings = 6,
    FetchInfo = 7,
    CacheApplied = 8,
    Backoff = 9,
    WriteProcess = 10,
    WriteSettings = 11,
    Error = 0xff,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum TlsTransportError {
    None = 0,
    MissingCredentials = 1,
    BuildAuth = 2,
    BuildHost = 3,
    NetworkWaitTimeout = 4,
    TcpConnect = 5,
    TlsHandshake = 6,
    BuildRequest = 7,
    TlsWrite = 8,
    TlsRead = 9,
    HttpResponse = 10,
    CacheApply = 11,
    TlsClose = 12,
    /// Write aborted because trust was revoked after dequeue (BH-8 pre-send gate).
    /// Distinct from [`Self::TlsWrite`] so probes/health do not mis-attribute
    /// a deliberate authorization refusal as a transport I/O failure.
    TrustRevoked = 13,
}

pub(crate) trait TlsObserver {
    fn set_stage(&self, stage: TlsStage);
    fn set_error(&self, error: TlsTransportError);
    fn set_server_ipv4(&self, server_ipv4: [u8; 4]);
    fn set_http_status(&self, status: i32);
    fn set_counts(&self, completed: u32, failed: u32);
    fn set_cache_status(&self, status: CacheReadStatus);
}

struct ProductObserver;

impl TlsObserver for ProductObserver {
    fn set_stage(&self, _stage: TlsStage) {
        #[cfg(feature = "diagnostic-executor-wakeup")]
        crate::time_trace::set_tls_stage(_stage as u32);
    }
    fn set_error(&self, _error: TlsTransportError) {}
    fn set_server_ipv4(&self, _server_ipv4: [u8; 4]) {}
    fn set_http_status(&self, _status: i32) {}
    fn set_counts(&self, _completed: u32, _failed: u32) {}
    fn set_cache_status(&self, _status: CacheReadStatus) {}
}

#[derive(Clone, Copy)]
pub(crate) enum BuchiTlsTrustSource {
    Static {
        ca_der: &'static [u8],
        verifier_time: UnixTime,
    },
    Runtime(&'static SharedTrust),
}

pub(crate) struct BuchiTlsConfig {
    pub gateway: GatewayConfig,
    pub server_ipv4: [u8; 4],
    pub port: u16,
    pub trust_source: BuchiTlsTrustSource,
}

enum AttemptTrust {
    Static {
        ca_der: &'static [u8],
        verifier_time: UnixTime,
    },
    Runtime {
        material: GatewayTrust,
        verifier_time: Option<UnixTime>,
        generation: u32,
    },
}

impl AttemptTrust {
    fn ca_der(&self) -> &[u8] {
        match self {
            Self::Static { ca_der, .. } => ca_der,
            Self::Runtime { material, .. } => material.ca_der(),
        }
    }

    const fn verifier_time(&self) -> Option<UnixTime> {
        match self {
            Self::Static { verifier_time, .. } => Some(*verifier_time),
            Self::Runtime { verifier_time, .. } => *verifier_time,
        }
    }

    const fn generation(&self) -> Option<u32> {
        match self {
            Self::Static { .. } => None,
            Self::Runtime { generation, .. } => Some(*generation),
        }
    }
}

struct VerifyingProvider<'a> {
    rng: &'a mut Rng<'static, RNG>,
    verifier: EmbeddedTlsRsaVerifier<'a>,
}

impl<'a> VerifyingProvider<'a> {
    fn new(
        rng: &'a mut Rng<'static, RNG>,
        ca_der: &'a [u8],
        verifier_time: Option<UnixTime>,
    ) -> Self {
        Self {
            rng,
            verifier: EmbeddedTlsRsaVerifier::new_with_optional_time(ca_der, verifier_time),
        }
    }
}

impl CryptoProvider for VerifyingProvider<'_> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = [u8; 128];

    fn rng(&mut self) -> impl embedded_tls::CryptoRngCore {
        &mut *self.rng
    }

    fn verifier(&mut self) -> Result<&mut impl TlsVerifier<Self::CipherSuite>, TlsError> {
        Ok(&mut self.verifier)
    }
}

type TlsConnectionType<'a> = TlsConnection<'a, TcpSocket<'a>, Aes128GcmSha256>;

#[embassy_executor::task]
pub(crate) async fn buchi_tls_client_product_task(
    stack: Stack<'static>,
    rng: Rng<'static, RNG>,
    reconnect_seed: u32,
    gateway: GatewayConfig,
    runtime: &'static SharedRuntime,
    trust: &'static SharedTrust,
) -> ! {
    run_buchi_tls_client(
        stack,
        rng,
        reconnect_seed,
        BuchiTlsConfig {
            gateway,
            server_ipv4: gateway.buchi_ip,
            port: PRODUCT_TLS_PORT,
            trust_source: BuchiTlsTrustSource::Runtime(trust),
        },
        runtime,
        ProductObserver,
    )
    .await
}

pub(crate) async fn run_buchi_tls_client<O: TlsObserver>(
    stack: Stack<'static>,
    rng: Rng<'static, RNG>,
    reconnect_seed: u32,
    config: BuchiTlsConfig,
    runtime: &'static SharedRuntime,
    observer: O,
) -> ! {
    observer.set_stage(TlsStage::Config);
    observer.set_error(TlsTransportError::None);
    let mut rng = rng;
    let mut reconnect_policy = ReconnectPolicy::new(reconnect_seed);
    initialize_trust_source(config.trust_source, runtime).await;
    let server_ipv4 = config.server_ipv4;
    let server = Ipv4Address::new(
        server_ipv4[0],
        server_ipv4[1],
        server_ipv4[2],
        server_ipv4[3],
    );
    observer.set_server_ipv4(server_ipv4);

    let mut host_header = heapless::String::<TLS_HOST_HEADER_BYTES>::new();
    if write!(host_header, "{}:{}", Ipv4Display(server_ipv4), config.port).is_err() {
        record_config_failure(&observer, TlsTransportError::BuildHost);
    }
    let mut server_name = heapless::String::<TLS_SERVER_NAME_BYTES>::new();
    if write!(server_name, "{}", Ipv4Display(server_ipv4)).is_err() {
        record_config_failure(&observer, TlsTransportError::BuildHost);
    }

    let username = config.gateway.buchi_user.as_str();
    let password = config.gateway.buchi_password.as_str();
    let mut auth_token = [0u8; TLS_AUTH_TOKEN_BYTES];
    let auth_len = match build_basic_auth_token(username, password, &mut auth_token) {
        Ok(len) => len,
        Err(_) if username.is_empty() || password.is_empty() => {
            record_config_failure(&observer, TlsTransportError::MissingCredentials);
            0
        }
        Err(_) => {
            record_config_failure(&observer, TlsTransportError::BuildAuth);
            0
        }
    };
    let auth_token = str::from_utf8(&auth_token[..auth_len]).unwrap_or("");

    {
        let mut data_access = runtime.lock().await;
        data_access.set_buchi_status_inputs(
            !auth_token.is_empty() && !host_header.is_empty() && !server_name.is_empty(),
            false,
            false,
        );
    }

    let mut socket_rx = [0u8; TLS_TCP_RX_BYTES];
    let mut socket_tx = [0u8; TLS_TCP_TX_BYTES];
    let mut read_record_buffer = [0u8; TLS_READ_RECORD_BYTES];
    let mut write_record_buffer = [0u8; TLS_WRITE_RECORD_BYTES];
    let mut request = [0u8; product::BUCHI_HTTP_REQUEST_BYTES];
    let mut response = HttpReceiveBuffer::<{ product::BUCHI_HTTP_RESPONSE_BYTES }>::new();
    let mut read_chunk = [0u8; TLS_READ_CHUNK_BYTES];
    let mut scheduler = EndpointPollScheduler::new(crate::uptime_now_ms());
    #[cfg(feature = "diagnostic-runtime-counters")]
    let mut counter_session = crate::counter_diagnostic::CounterSession::from_startup();
    #[cfg(feature = "diagnostic-cache-ages")]
    let mut cache_age_session = crate::cache_age_diagnostic::CacheAgeSession::from_startup();

    loop {
        crate::task_checkin(WatchdogSlot::BuchiTlsClient);
        update_shared_cache_status_probe(&observer, runtime).await;

        if runtime_trust_revoked() {
            crate::M7_BUCHI_TRUST_READY.store(0, Ordering::Relaxed);
            {
                let mut data_access = runtime.lock().await;
                data_access.set_trust_state(TrustState::Revoked);
                data_access.set_write_enabled(false);
            }
            observer.set_stage(TlsStage::Disabled);
            Timer::after_millis(250).await;
            continue;
        }

        if auth_token.is_empty() || host_header.is_empty() || server_name.is_empty() {
            Timer::after_secs(1).await;
            continue;
        }

        let now_ms = crate::uptime_now_ms();
        let due = scheduler.due_endpoints(now_ms);
        if due.is_empty() {
            Timer::after_millis(u64::from(
                shared_next_poll_delay_ms(&scheduler, now_ms).min(500),
            ))
            .await;
            continue;
        }

        let attempt_trust = match load_attempt_trust(config.trust_source).await {
            Ok(attempt) => attempt,
            Err(state) => {
                crate::M7_BUCHI_TRUST_READY.store(0, Ordering::Relaxed);
                let mut data_access = runtime.lock().await;
                data_access.set_trust_state(state);
                data_access.set_write_enabled(false);
                observer.set_stage(TlsStage::Disabled);
                drop(data_access);
                Timer::after_millis(250).await;
                continue;
            }
        };

        observer.set_stage(TlsStage::WaitNetwork);
        if tls_watchdog_timeout(crate::WATCHDOG_TASK_DEADLINE, stack.wait_config_up())
            .await
            .is_err()
        {
            record_transport_failure_shared(
                &observer,
                runtime,
                due.first_due().unwrap_or(Endpoint::Process),
                TlsTransportError::NetworkWaitTimeout,
            )
            .await;
            mark_due_endpoints_polled(&mut scheduler, due);
            continue;
        }

        let remote = IpEndpoint::new(IpAddress::Ipv4(server), config.port);
        let mut socket = TcpSocket::new(stack, &mut socket_rx, &mut socket_tx);
        socket.set_timeout(Some(Duration::from_secs(15)));
        socket.set_keep_alive(Some(Duration::from_secs(2)));
        socket.set_nagle_enabled(false);

        observer.set_stage(TlsStage::TcpConnect);
        let connected = matches!(
            tls_watchdog_timeout(TLS_CONNECT_TIMEOUT, socket.connect(remote)).await,
            Ok(Ok(()))
        );
        if !connected {
            record_transport_failure_shared(
                &observer,
                runtime,
                due.first_due().unwrap_or(Endpoint::Process),
                TlsTransportError::TcpConnect,
            )
            .await;
            mark_due_endpoints_polled(&mut scheduler, due);
            socket.abort();
            // Flushing an aborted socket waits for its RST to go out, which
            // never completes while the link is down. Unbounded, that starves
            // the RESET-CRITICAL BuchiTlsClient check-in and the supervisor
            // stops refreshing IWDG, so cable loss alone reset-loops the
            // gateway. Bound it and keep checking in.
            let _ = tls_watchdog_timeout(TLS_IO_TIMEOUT, socket.flush()).await;
            tls_failure_backoff(&mut reconnect_policy).await;
            continue;
        }

        {
            let mut data_access = runtime.lock().await;
            data_access.set_buchi_status_inputs(true, true, false);
        }

        let mut tls = TlsConnection::new(socket, &mut read_record_buffer, &mut write_record_buffer);
        let tls_config = TlsConfig::new()
            .with_server_name(server_name.as_str())
            .enable_rsa_signatures();
        let mut provider = VerifyingProvider::new(
            &mut rng,
            attempt_trust.ca_der(),
            attempt_trust.verifier_time(),
        );

        observer.set_stage(TlsStage::TlsHandshake);
        crate::M7_BUCHI_TRUST_VERIFY_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
        let handshake_started_ms = crate::uptime_now_ms_u64();
        let open_result = tls_watchdog_timeout(
            TLS_HANDSHAKE_TIMEOUT,
            tls.open(TlsContext::new(&tls_config, &mut provider)),
        )
        .await;
        crate::probes::record_tls_handshake_duration(
            crate::uptime_now_ms_u64().saturating_sub(handshake_started_ms),
        );
        let opened = matches!(open_result, Ok(Ok(())));
        if !opened {
            transition_trust_source(
                config.trust_source,
                attempt_trust.generation(),
                TrustState::VerifyRejected,
                TlsTransportError::TlsHandshake as u32,
            )
            .await;
            {
                let mut data_access = runtime.lock().await;
                data_access.set_trust_state(TrustState::VerifyRejected);
                data_access.set_write_enabled(false);
            }
            record_transport_failure_shared(
                &observer,
                runtime,
                due.first_due().unwrap_or(Endpoint::Process),
                TlsTransportError::TlsHandshake,
            )
            .await;
            mark_due_endpoints_polled(&mut scheduler, due);
            tls_failure_backoff(&mut reconnect_policy).await;
            continue;
        }
        if runtime_trust_revoked() {
            crate::M7_BUCHI_TRUST_READY.store(0, Ordering::Relaxed);
            runtime.lock().await.set_trust_state(TrustState::Revoked);
            continue;
        }
        if !transition_trust_source(
            config.trust_source,
            attempt_trust.generation(),
            TrustState::Verified,
            0,
        )
        .await
        {
            runtime
                .lock()
                .await
                .set_trust_state(TrustState::Provisioned);
            continue;
        }
        crate::M7_BUCHI_TRUST_VERIFIED_SESSIONS.fetch_add(1, Ordering::Relaxed);
        {
            let mut data_access = runtime.lock().await;
            data_access.set_verified_trust_session(attempt_trust.verifier_time().is_some());
            data_access.set_write_enabled(config.gateway.write_enable);
        }

        let mut connection_failed;
        loop {
            crate::task_checkin(WatchdogSlot::BuchiTlsClient);
            if !trust_session_current(config.trust_source, attempt_trust.generation()).await {
                crate::M7_BUCHI_TRUST_READY.store(0, Ordering::Relaxed);
                {
                    let mut data_access = runtime.lock().await;
                    data_access.set_trust_state(if runtime_trust_revoked() {
                        TrustState::Revoked
                    } else {
                        TrustState::Provisioned
                    });
                    data_access.set_write_enabled(false);
                }
                connection_failed = true;
                break;
            }
            let now_ms = crate::uptime_now_ms();
            let due = scheduler.due_endpoints(now_ms);
            if due.is_empty() {
                Timer::after_millis(u64::from(
                    shared_next_poll_delay_ms(&scheduler, now_ms).min(500),
                ))
                .await;
                continue;
            }

            connection_failed = false;
            for endpoint in POLL_ENDPOINTS {
                if !due.contains(endpoint) {
                    continue;
                }
                if !fetch_endpoint_over_tls_shared(
                    &mut tls,
                    endpoint,
                    host_header.as_str(),
                    auth_token,
                    &mut request,
                    &mut response,
                    &mut read_chunk,
                    runtime,
                    &observer,
                    config.trust_source,
                    attempt_trust.generation(),
                    #[cfg(any(
                        feature = "diagnostic-runtime-counters",
                        feature = "diagnostic-cache-ages"
                    ))]
                    attempt_trust.verifier_time().is_some(),
                    #[cfg(feature = "diagnostic-runtime-counters")]
                    &mut counter_session,
                    #[cfg(feature = "diagnostic-cache-ages")]
                    &mut cache_age_session,
                    #[cfg(any(
                        feature = "diagnostic-runtime-counters",
                        feature = "diagnostic-cache-ages"
                    ))]
                    POLL_ENDPOINTS.map(|owner| scheduler.next_due_ms(owner)),
                )
                .await
                {
                    scheduler.mark_polled(endpoint, crate::uptime_now_ms());
                    connection_failed = true;
                    break;
                }
                reconnect_policy.record_success();
                scheduler.mark_polled(endpoint, crate::uptime_now_ms());
                crate::task_checkin(WatchdogSlot::BuchiTlsClient);
            }

            if !connection_failed {
                #[cfg(feature = "diagnostic-runtime-counters")]
                counter_session.before_drain();
                if !drain_pending_writes_over_tls_shared(
                    &mut tls,
                    host_header.as_str(),
                    auth_token,
                    &mut request,
                    &mut response,
                    &mut read_chunk,
                    runtime,
                    &observer,
                    config.trust_source,
                    attempt_trust.generation(),
                )
                .await
                {
                    connection_failed = true;
                }
            }

            if connection_failed {
                break;
            }
        }

        if connection_failed {
            #[cfg(feature = "diagnostic-runtime-counters")]
            crate::counter_events::abort(3);
            crate::M7_BUCHI_TRUST_READY.store(0, Ordering::Relaxed);
            let revoked = runtime_trust_revoked();
            let state = if revoked {
                TrustState::Revoked
            } else {
                TrustState::Provisioned
            };
            transition_trust_source(config.trust_source, attempt_trust.generation(), state, 0)
                .await;
            {
                let mut data_access = runtime.lock().await;
                data_access.set_trust_state(state);
                data_access.set_write_enabled(false);
            }
            tls_failure_backoff(&mut reconnect_policy).await;
            continue;
        }

        match tls_watchdog_timeout(TLS_IO_TIMEOUT, tls.close()).await {
            Ok(Ok(_socket)) => {}
            Ok(Err((_socket, _error))) => {
                observer.set_error(TlsTransportError::TlsClose);
            }
            Err(_) => {
                observer.set_error(TlsTransportError::TlsClose);
            }
        }

        observer.set_stage(TlsStage::Backoff);
        Timer::after(TLS_SUCCESS_BACKOFF).await;
    }
}

async fn initialize_trust_source(source: BuchiTlsTrustSource, runtime: &'static SharedRuntime) {
    let state = match source {
        BuchiTlsTrustSource::Static { .. } => {
            crate::M7_BUCHI_TRUST_STATE.store(TrustState::Provisioned as u32, Ordering::Relaxed);
            crate::M7_BUCHI_TRUST_ANCHOR_PRESENT.store(1, Ordering::Relaxed);
            crate::M7_BUCHI_TRUST_RTC_USABLE.store(1, Ordering::Relaxed);
            TrustState::Provisioned
        }
        BuchiTlsTrustSource::Runtime(trust) => trust.lock().await.state,
    };
    runtime.lock().await.set_trust_state(state);
}

async fn load_attempt_trust(source: BuchiTlsTrustSource) -> Result<AttemptTrust, TrustState> {
    match source {
        BuchiTlsTrustSource::Static {
            ca_der,
            verifier_time,
        } => {
            if runtime_trust_revoked() {
                Err(TrustState::Revoked)
            } else {
                Ok(AttemptTrust::Static {
                    ca_der,
                    verifier_time,
                })
            }
        }
        BuchiTlsTrustSource::Runtime(trust) => {
            let snapshot: RuntimeTrustSnapshot = trust.lock().await.snapshot();
            if matches!(snapshot.state, TrustState::Missing | TrustState::Revoked)
                || !snapshot.material.is_complete()
            {
                return Err(snapshot.state);
            }
            Ok(AttemptTrust::Runtime {
                material: snapshot.material,
                verifier_time: snapshot.verifier_now_seconds.map(UnixTime::from_seconds),
                generation: snapshot.generation,
            })
        }
    }
}

async fn transition_trust_source(
    source: BuchiTlsTrustSource,
    generation: Option<u32>,
    state: TrustState,
    last_verify_error: u32,
) -> bool {
    match source {
        BuchiTlsTrustSource::Static { .. } => {
            if runtime_trust_revoked() && state != TrustState::Revoked {
                return false;
            }
            crate::M7_BUCHI_TRUST_READY
                .store(u32::from(state == TrustState::Verified), Ordering::Relaxed);
            crate::M7_BUCHI_TRUST_STATE.store(state as u32, Ordering::Relaxed);
            crate::M7_BUCHI_TRUST_LAST_VERIFY_ERROR.store(last_verify_error, Ordering::Relaxed);
            true
        }
        BuchiTlsTrustSource::Runtime(trust) => {
            let Some(generation) = generation else {
                return false;
            };
            trust
                .lock()
                .await
                .transition_if_generation(generation, state, last_verify_error)
        }
    }
}

async fn trust_session_current(source: BuchiTlsTrustSource, generation: Option<u32>) -> bool {
    if runtime_trust_revoked() {
        return false;
    }
    match source {
        BuchiTlsTrustSource::Static { .. } => true,
        BuchiTlsTrustSource::Runtime(trust) => {
            let Some(generation) = generation else {
                return false;
            };
            let trust = trust.lock().await;
            trust.generation == generation && trust.state == TrustState::Verified
        }
    }
}

fn shared_next_poll_delay_ms(scheduler: &EndpointPollScheduler, now_ms: u32) -> u32 {
    if !scheduler.due_endpoints(now_ms).is_empty() {
        return 0;
    }
    let mut delay = u32::MAX;
    for endpoint in POLL_ENDPOINTS {
        delay = delay.min(scheduler.next_due_ms(endpoint).wrapping_sub(now_ms));
    }
    delay
}

fn mark_due_endpoints_polled(scheduler: &mut EndpointPollScheduler, due: EndpointDueSet) {
    let now_ms = crate::uptime_now_ms();
    for endpoint in POLL_ENDPOINTS {
        if due.contains(endpoint) {
            scheduler.mark_polled(endpoint, now_ms);
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn drain_pending_writes_over_tls_shared<const RESPONSE_CAPACITY: usize>(
    tls: &mut TlsConnectionType<'_>,
    host: &str,
    basic_auth_token: &str,
    request: &mut [u8; product::BUCHI_HTTP_REQUEST_BYTES],
    response: &mut HttpReceiveBuffer<RESPONSE_CAPACITY>,
    read_chunk: &mut [u8; TLS_READ_CHUNK_BYTES],
    runtime: &'static SharedRuntime,
    observer: &impl TlsObserver,
    trust_source: BuchiTlsTrustSource,
    trust_generation: Option<u32>,
) -> bool {
    if !trust_session_current(trust_source, trust_generation).await {
        return false;
    }
    let pending = {
        let data_access = runtime.lock().await;
        if !data_access.trust_verified() {
            return false;
        }
        data_access.write_queue_depth()
    };
    if pending == 0 {
        return true;
    }

    let mut body = [0u8; product::BUCHI_WRITE_JSON_BYTES];
    for _ in 0..pending {
        crate::task_checkin(WatchdogSlot::BuchiTlsClient);
        if !trust_session_current(trust_source, trust_generation).await {
            return false;
        }
        let dispatch = {
            let mut data_access = runtime.lock().await;
            if !data_access.trust_verified() {
                return false;
            }
            match data_access.pop_next_write_json(&mut body) {
                Ok(dispatch) => dispatch,
                Err(RuntimeWriteDispatchError::EmptyQueue) => return true,
                Err(RuntimeWriteDispatchError::Build(_)) => {
                    observer.set_stage(TlsStage::Error);
                    observer.set_error(TlsTransportError::BuildRequest);
                    return false;
                }
            }
        };

        observer.set_stage(write_stage_for_endpoint(dispatch.endpoint));
        let request_len = match build_put_request_with_connection(
            dispatch.endpoint,
            host,
            basic_auth_token,
            &body[..dispatch.body_len],
            HttpConnectionMode::KeepAlive,
            request,
        ) {
            Ok(len) => len,
            Err(_) => {
                record_write_completion_shared(
                    observer,
                    runtime,
                    dispatch.request.node_id,
                    0,
                    write_http_status_to_opcua_status(0, -1),
                    TlsTransportError::BuildRequest,
                    #[cfg(feature = "diagnostic-runtime-counters")]
                    dispatch.request.sequence,
                )
                .await;
                return false;
            }
        };

        // BH-8 pre-send gate: re-check trust after dequeue/build and before the
        // first TLS write. Revoke can clear the queue and bump generation while
        // this item is already dequeued; abort without putting bytes on the wire.
        // Residual boundary: once any PUT byte has entered the TLS/TCP stack,
        // revoke cannot retract the upstream setpoint.
        if !trust_session_current(trust_source, trust_generation).await {
            record_write_completion_shared(
                observer,
                runtime,
                dispatch.request.node_id,
                0,
                opcua_status::BAD_USER_ACCESS_DENIED,
                TlsTransportError::TrustRevoked,
                #[cfg(feature = "diagnostic-runtime-counters")]
                dispatch.request.sequence,
            )
            .await;
            return false;
        }

        let mut written = 0usize;
        while written < request_len {
            crate::task_checkin(WatchdogSlot::BuchiTlsClient);
            // Re-check before each chunk so a revoke after a prior await cannot
            // continue streaming the remainder of a dequeued PUT (BH-8).
            if !trust_session_current(trust_source, trust_generation).await {
                record_write_completion_shared(
                    observer,
                    runtime,
                    dispatch.request.node_id,
                    0,
                    opcua_status::BAD_USER_ACCESS_DENIED,
                    TlsTransportError::TrustRevoked,
                    #[cfg(feature = "diagnostic-runtime-counters")]
                    dispatch.request.sequence,
                )
                .await;
                return false;
            }
            match tls_watchdog_timeout(TLS_IO_TIMEOUT, tls.write(&request[written..request_len]))
                .await
            {
                Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
                    record_write_completion_shared(
                        observer,
                        runtime,
                        dispatch.request.node_id,
                        0,
                        write_http_status_to_opcua_status(0, -1),
                        TlsTransportError::TlsWrite,
                        #[cfg(feature = "diagnostic-runtime-counters")]
                        dispatch.request.sequence,
                    )
                    .await;
                    return false;
                }
                Ok(Ok(count)) => written += count,
            }
        }
        if !matches!(
            tls_watchdog_timeout(TLS_IO_TIMEOUT, tls.flush()).await,
            Ok(Ok(()))
        ) {
            record_write_completion_shared(
                observer,
                runtime,
                dispatch.request.node_id,
                0,
                write_http_status_to_opcua_status(0, -1),
                TlsTransportError::TlsWrite,
                #[cfg(feature = "diagnostic-runtime-counters")]
                dispatch.request.sequence,
            )
            .await;
            return false;
        }

        response.clear();
        loop {
            crate::task_checkin(WatchdogSlot::BuchiTlsClient);
            let read = match tls_watchdog_timeout(TLS_IO_TIMEOUT, tls.read(read_chunk)).await {
                Ok(Ok(count)) => count,
                Ok(Err(_)) | Err(_) => {
                    record_write_completion_shared(
                        observer,
                        runtime,
                        dispatch.request.node_id,
                        0,
                        write_http_status_to_opcua_status(0, -1),
                        TlsTransportError::TlsRead,
                        #[cfg(feature = "diagnostic-runtime-counters")]
                        dispatch.request.sequence,
                    )
                    .await;
                    return false;
                }
            };
            if read == 0 {
                record_write_completion_shared(
                    observer,
                    runtime,
                    dispatch.request.node_id,
                    0,
                    write_http_status_to_opcua_status(0, -1),
                    TlsTransportError::TlsRead,
                    #[cfg(feature = "diagnostic-runtime-counters")]
                    dispatch.request.sequence,
                )
                .await;
                return false;
            }
            if response.append(&read_chunk[..read]).is_err() {
                record_write_completion_shared(
                    observer,
                    runtime,
                    dispatch.request.node_id,
                    0,
                    write_http_status_to_opcua_status(0, -1),
                    TlsTransportError::HttpResponse,
                    #[cfg(feature = "diagnostic-runtime-counters")]
                    dispatch.request.sequence,
                )
                .await;
                return false;
            }
            match response.finish_persistent_response() {
                Ok(HttpReadProgress::ReadMore) => {}
                Ok(HttpReadProgress::Complete) => break,
                Ok(HttpReadProgress::ProbeForExtraBytes) | Err(_) => {
                    record_write_completion_shared(
                        observer,
                        runtime,
                        dispatch.request.node_id,
                        0,
                        write_http_status_to_opcua_status(0, -1),
                        TlsTransportError::HttpResponse,
                        #[cfg(feature = "diagnostic-runtime-counters")]
                        dispatch.request.sequence,
                    )
                    .await;
                    return false;
                }
            }
        }

        let http_status = match response.response() {
            Ok(http_response) => http_response.status,
            Err(_) => {
                record_write_completion_shared(
                    observer,
                    runtime,
                    dispatch.request.node_id,
                    0,
                    write_http_status_to_opcua_status(0, -1),
                    TlsTransportError::HttpResponse,
                    #[cfg(feature = "diagnostic-runtime-counters")]
                    dispatch.request.sequence,
                )
                .await;
                return false;
            }
        };
        let completion_status = write_http_status_to_opcua_status(http_status, 0);
        if !trust_session_current(trust_source, trust_generation).await {
            // The request was already dequeued before awaiting the response.
            // Record the local failed outcome without publishing the obsolete-trust reply.
            record_write_completion_shared(
                observer,
                runtime,
                dispatch.request.node_id,
                http_status,
                opcua_status::BAD_USER_ACCESS_DENIED,
                TlsTransportError::TrustRevoked,
                #[cfg(feature = "diagnostic-runtime-counters")]
                dispatch.request.sequence,
            )
            .await;
            return false;
        }
        {
            let mut data_access = runtime.lock().await;
            #[cfg(feature = "diagnostic-runtime-counters")]
            let counters_before = data_access.diagnostic_counters();
            data_access.record_buchi_write_result(
                dispatch.request.node_id,
                http_status,
                completion_status,
            );
            data_access.set_buchi_status_inputs(true, true, false);
            observer.set_http_status(http_status);
            if http_status == 200 {
                match data_access.apply_http_response(
                    dispatch.endpoint,
                    response.buffered(),
                    response.capacity(),
                    crate::uptime_now_ms_u64(),
                ) {
                    Ok(report) => {
                        observer.set_error(TlsTransportError::None);
                        observer.set_counts(report.completed_fetches, report.failed_fetches);
                        observer.set_http_status(report.last_http_status.unwrap_or(http_status));
                        observer.set_stage(TlsStage::CacheApplied);
                        update_cache_status_probe(observer, data_access.cache());
                    }
                    Err(failure) => {
                        observer.set_error(TlsTransportError::CacheApply);
                        observer.set_counts(failure.completed_fetches, failure.failed_fetches);
                        observer.set_http_status(failure.last_http_status.unwrap_or(http_status));
                        update_cache_status_probe(observer, data_access.cache());
                        #[cfg(feature = "diagnostic-runtime-counters")]
                        {
                            crate::counter_events::record(
                                2,
                                u32::from(dispatch.request.node_id),
                                dispatch.request.sequence,
                                http_status,
                                completion_status,
                                crate::uptime_now_ms_u64(),
                                counters_before,
                                &data_access,
                            );
                            crate::counter_events::abort(2);
                        }
                        return false;
                    }
                }
            }
            #[cfg(feature = "diagnostic-runtime-counters")]
            crate::counter_events::record(
                2,
                u32::from(dispatch.request.node_id),
                dispatch.request.sequence,
                http_status,
                completion_status,
                crate::uptime_now_ms_u64(),
                counters_before,
                &data_access,
            );
        }
    }
    true
}

async fn record_write_completion_shared(
    observer: &impl TlsObserver,
    runtime: &'static SharedRuntime,
    node_id: u16,
    http_status: i32,
    completion_status: u32,
    error: TlsTransportError,
    #[cfg(feature = "diagnostic-runtime-counters")] write_sequence: u32,
) {
    observer.set_stage(TlsStage::Error);
    observer.set_error(error);
    observer.set_http_status(http_status);
    let mut data_access = runtime.lock().await;
    #[cfg(feature = "diagnostic-runtime-counters")]
    let counters_before = data_access.diagnostic_counters();
    data_access.set_buchi_status_inputs(true, false, false);
    data_access.record_buchi_write_result(node_id, http_status, completion_status);
    update_cache_status_probe(observer, data_access.cache());
    #[cfg(feature = "diagnostic-runtime-counters")]
    {
        crate::counter_events::record(
            2,
            u32::from(node_id),
            write_sequence,
            http_status,
            completion_status,
            crate::uptime_now_ms_u64(),
            counters_before,
            &data_access,
        );
        crate::counter_events::abort(1);
    }
}

#[allow(clippy::too_many_arguments)]
async fn fetch_endpoint_over_tls_shared<const RESPONSE_CAPACITY: usize>(
    tls: &mut TlsConnectionType<'_>,
    endpoint: Endpoint,
    host: &str,
    basic_auth_token: &str,
    request: &mut [u8; product::BUCHI_HTTP_REQUEST_BYTES],
    response: &mut HttpReceiveBuffer<RESPONSE_CAPACITY>,
    read_chunk: &mut [u8; TLS_READ_CHUNK_BYTES],
    runtime: &'static SharedRuntime,
    observer: &impl TlsObserver,
    trust_source: BuchiTlsTrustSource,
    trust_generation: Option<u32>,
    #[cfg(any(
        feature = "diagnostic-runtime-counters",
        feature = "diagnostic-cache-ages"
    ))]
    handshake_time_checked: bool,
    #[cfg(feature = "diagnostic-runtime-counters")]
    counter_session: &mut crate::counter_diagnostic::CounterSession,
    #[cfg(feature = "diagnostic-cache-ages")]
    cache_age_session: &mut crate::cache_age_diagnostic::CacheAgeSession,
    #[cfg(any(
        feature = "diagnostic-runtime-counters",
        feature = "diagnostic-cache-ages"
    ))]
    poll_deadlines_ms: [u32; 3],
) -> bool {
    if !trust_session_current(trust_source, trust_generation).await {
        return false;
    }
    observer.set_stage(stage_for_endpoint(endpoint));
    response.clear();
    let request_len = match build_get_request_with_connection(
        endpoint,
        host,
        basic_auth_token,
        HttpConnectionMode::KeepAlive,
        request,
    ) {
        Ok(len) => len,
        Err(_) => {
            record_transport_failure_shared(
                observer,
                runtime,
                endpoint,
                TlsTransportError::BuildRequest,
            )
            .await;
            return false;
        }
    };

    let mut written = 0usize;
    while written < request_len {
        crate::task_checkin(WatchdogSlot::BuchiTlsClient);
        match tls_watchdog_timeout(TLS_IO_TIMEOUT, tls.write(&request[written..request_len])).await
        {
            Ok(Ok(0)) | Ok(Err(_)) | Err(_) => {
                record_transport_failure_shared(
                    observer,
                    runtime,
                    endpoint,
                    TlsTransportError::TlsWrite,
                )
                .await;
                return false;
            }
            Ok(Ok(count)) => written += count,
        }
    }
    if !matches!(
        tls_watchdog_timeout(TLS_IO_TIMEOUT, tls.flush()).await,
        Ok(Ok(()))
    ) {
        record_transport_failure_shared(observer, runtime, endpoint, TlsTransportError::TlsWrite)
            .await;
        return false;
    }

    loop {
        crate::task_checkin(WatchdogSlot::BuchiTlsClient);
        let read = match tls_watchdog_timeout(TLS_IO_TIMEOUT, tls.read(read_chunk)).await {
            Ok(Ok(count)) => count,
            Ok(Err(_)) | Err(_) => {
                record_transport_failure_shared(
                    observer,
                    runtime,
                    endpoint,
                    TlsTransportError::TlsRead,
                )
                .await;
                return false;
            }
        };
        if read == 0 {
            record_transport_failure_shared(
                observer,
                runtime,
                endpoint,
                TlsTransportError::TlsRead,
            )
            .await;
            return false;
        }
        if response.append(&read_chunk[..read]).is_err() {
            record_transport_failure_shared(
                observer,
                runtime,
                endpoint,
                TlsTransportError::HttpResponse,
            )
            .await;
            return false;
        }
        match response.finish_persistent_response() {
            Ok(HttpReadProgress::ReadMore) => {}
            Ok(HttpReadProgress::Complete) => break,
            Ok(HttpReadProgress::ProbeForExtraBytes) | Err(_) => {
                record_transport_failure_shared(
                    observer,
                    runtime,
                    endpoint,
                    TlsTransportError::HttpResponse,
                )
                .await;
                return false;
            }
        }
    }

    if let Ok(http_response) = response.response() {
        if http_response.status >= 0 {
            observer.set_http_status(http_response.status);
        }
    }

    let freshness_now_ms = crate::uptime_now_ms_u64();
    if !trust_session_current(trust_source, trust_generation).await {
        return false;
    }
    // Diagnostic admission holds the real trust owner first. No code holding
    // runtime awaits trust (USB/revocation release trust before runtime). The
    // startup try-lock snapshot is pre-executor, not this async lock order.
    #[cfg(any(
        feature = "diagnostic-runtime-counters",
        feature = "diagnostic-cache-ages"
    ))]
    let trust_guard = match trust_source {
        BuchiTlsTrustSource::Runtime(owner) => Some(owner.lock().await),
        BuchiTlsTrustSource::Static { .. } => None,
    };
    #[cfg(any(
        feature = "diagnostic-runtime-counters",
        feature = "diagnostic-cache-ages"
    ))]
    if trust_guard.as_ref().is_some_and(|owner| {
        runtime_trust_revoked()
            || owner.state != TrustState::Verified
            || Some(owner.generation) != trust_generation
    }) {
        return false;
    }
    let mut data_access = runtime.lock().await;
    #[cfg(feature = "diagnostic-runtime-counters")]
    let event_before =
        crate::counter_events::collecting().then(|| data_access.diagnostic_counters());
    match data_access.apply_http_response(
        endpoint,
        response.buffered(),
        response.capacity(),
        freshness_now_ms,
    ) {
        Ok(report) => {
            data_access.set_buchi_status_inputs(true, true, false);
            observer.set_error(TlsTransportError::None);
            observer.set_counts(report.completed_fetches, report.failed_fetches);
            observer.set_http_status(report.last_http_status.unwrap_or(0));
            observer.set_stage(TlsStage::CacheApplied);
            update_cache_status_probe(observer, data_access.cache());
            #[cfg(feature = "diagnostic-cache-ages")]
            if cache_age_session.after_get(
                trust_guard.as_deref(),
                trust_generation,
                handshake_time_checked,
                &mut data_access,
                endpoint,
                freshness_now_ms,
                poll_deadlines_ms,
            ) {
                crate::cache_age_diagnostic::M7_CACHE_AGE_GATE();
            }
            #[cfg(feature = "diagnostic-runtime-counters")]
            if counter_session.after_get(
                trust_guard.as_deref(),
                trust_generation,
                handshake_time_checked,
                &mut data_access,
                endpoint,
                freshness_now_ms,
                poll_deadlines_ms,
            ) {
                // Seeded counts are actual owner state; do not expose the
                // pre-seed report as a contradictory acceptance oracle.
                observer.set_counts(
                    data_access.cache().completed_fetches(),
                    data_access.cache().failed_fetches(),
                );
                if crate::counter_diagnostic::M7_COUNTER_ADMISSION.0[0].load(Ordering::Acquire) == 1
                {
                    crate::counter_events::begin(
                        trust_generation.expect("admitted runtime generation"),
                    );
                }
                crate::counter_diagnostic::M7_COUNTER_ADMISSION_GATE();
            }
            #[cfg(feature = "diagnostic-runtime-counters")]
            if let Some(before) = event_before {
                crate::counter_events::record(
                    1,
                    match endpoint {
                        Endpoint::Process => 0,
                        Endpoint::Settings => 1,
                        Endpoint::Info => 2,
                    },
                    0,
                    200,
                    opcua_status::GOOD,
                    freshness_now_ms,
                    before,
                    &data_access,
                );
                if let Some(trust) = trust_guard.as_deref() {
                    if crate::counter_events::finish(
                        &data_access,
                        trust.generation,
                        trust.state as u32,
                        freshness_now_ms,
                    ) {
                        crate::counter_events::M7_COUNTER_EVENTS_GATE();
                    }
                }
            }
            true
        }
        Err(failure) => {
            #[cfg(feature = "diagnostic-runtime-counters")]
            crate::counter_events::abort(2);
            data_access.set_buchi_status_inputs(true, true, false);
            observer.set_error(TlsTransportError::CacheApply);
            observer.set_counts(failure.completed_fetches, failure.failed_fetches);
            observer.set_http_status(failure.last_http_status.unwrap_or(0));
            update_cache_status_probe(observer, data_access.cache());
            false
        }
    }
}

fn runtime_trust_revoked() -> bool {
    crate::M7_BUCHI_RUNTIME_REVOKED.load(Ordering::Relaxed) != 0
}

async fn tls_failure_backoff(policy: &mut ReconnectPolicy) {
    let mut remaining = Duration::from_millis(u64::from(policy.next_failure_delay_ms()));
    loop {
        crate::task_checkin(WatchdogSlot::BuchiTlsClient);
        let chunk = remaining.min(TLS_WATCHDOG_CHECKIN_INTERVAL);
        Timer::after(chunk).await;
        if remaining <= TLS_WATCHDOG_CHECKIN_INTERVAL {
            return;
        }
        remaining -= chunk;
    }
}

async fn tls_watchdog_timeout<F>(timeout: Duration, future: F) -> Result<F::Output, TimeoutError>
where
    F: Future,
{
    let guarded = with_timeout(timeout, future);
    let mut guarded = core::pin::pin!(guarded);
    loop {
        crate::task_checkin(WatchdogSlot::BuchiTlsClient);
        match select(
            guarded.as_mut(),
            Timer::after(TLS_WATCHDOG_CHECKIN_INTERVAL),
        )
        .await
        {
            Either::First(result) => return result,
            Either::Second(()) => {}
        }
    }
}

fn record_config_failure(observer: &impl TlsObserver, error: TlsTransportError) {
    observer.set_stage(TlsStage::Error);
    observer.set_error(error);
}

async fn record_transport_failure_shared(
    observer: &impl TlsObserver,
    runtime: &'static SharedRuntime,
    endpoint: Endpoint,
    error: TlsTransportError,
) {
    #[cfg(feature = "diagnostic-runtime-counters")]
    crate::counter_events::abort(1);
    observer.set_stage(TlsStage::Error);
    observer.set_error(error);
    let mut data_access = runtime.lock().await;
    data_access.set_buchi_status_inputs(true, false, false);
    let failure = data_access.record_endpoint_failure(
        endpoint,
        EndpointResponseError::Http(HttpResponseError::HeaderTerminatorMissing),
    );
    observer.set_counts(failure.completed_fetches, failure.failed_fetches);
    observer.set_http_status(failure.last_http_status.unwrap_or(0));
    update_cache_status_probe(observer, data_access.cache());
}

async fn update_shared_cache_status_probe(
    observer: &impl TlsObserver,
    runtime: &'static SharedRuntime,
) {
    let data_access = runtime.lock().await;
    update_cache_status_probe(observer, data_access.cache());
}

fn update_cache_status_probe(observer: &impl TlsObserver, cache: &RuntimeCache) {
    let read = cache.read(RuntimeNode::ProcessHeatingSet, crate::uptime_now_ms_u64());
    observer.set_cache_status(read.status);
}

const fn stage_for_endpoint(endpoint: Endpoint) -> TlsStage {
    match endpoint {
        Endpoint::Process => TlsStage::FetchProcess,
        Endpoint::Settings => TlsStage::FetchSettings,
        Endpoint::Info => TlsStage::FetchInfo,
    }
}

const fn write_stage_for_endpoint(endpoint: Endpoint) -> TlsStage {
    match endpoint {
        Endpoint::Process => TlsStage::WriteProcess,
        Endpoint::Settings => TlsStage::WriteSettings,
        Endpoint::Info => TlsStage::Error,
    }
}
