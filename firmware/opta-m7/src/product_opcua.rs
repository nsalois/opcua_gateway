// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use core::future::Future;
use core::sync::atomic::{AtomicU32, Ordering};

use embassy_futures::select::{select, Either};
use embassy_net::tcp::TcpSocket;
use embassy_net::Stack;
use embassy_time::{with_timeout, Duration, TimeoutError, Timer};
use embedded_io_async::{Read as _, Write as _};
use opta_gateway_contracts::opcua_status;
use opta_gateway_contracts::product;
use opta_gateway_contracts::watchdog::WatchdogSlot;
#[cfg(not(feature = "diagnostic-protocol-identifiers"))]
use opta_opcua::TransportLimits;
use opta_opcua::{
    decode_first_read_value_node, decode_uasc_request_info, parse_frame_header, FrameKind,
    OpcUaServer, ServerIdentity, PRODUCT_TARGET_BUFFER_SIZE,
};
use rtt_target::rprintln;
use static_cell::ConstStaticCell;

use crate::SharedRuntime;

pub(crate) const OPCUA_PORT: u16 = 4_840;
const OPCUA_FRAME_BYTES: usize = PRODUCT_TARGET_BUFFER_SIZE as usize;
const OPCUA_TCP_RX_BYTES: usize = 4_096;
// A due PublishResponse can legally contain all 134 default monitored items.
// Keep the TCP TX buffer aligned with the advertised UASC message cap so a
// full response can be handed to the stack without wedging a listener behind a
// slow or disconnecting client.
const OPCUA_TCP_TX_BYTES: usize = OPCUA_FRAME_BYTES;
const OPCUA_IO_TIMEOUT: Duration = Duration::from_secs(10);
const OPCUA_CLOSE_DRAIN_READ_TIMEOUT: Duration = Duration::from_millis(500);
const OPCUA_CLOSE_DRAIN_TIMEOUT_MS: u32 = 2_000;
const OPCUA_FIRST_FRAME_TIMEOUT_MS: u32 = 10_000;
const OPCUA_WATCHDOG_CHECKIN_INTERVAL: Duration = Duration::from_millis(250);
const OPCUA_LISTENER_PROBE_COUNT: usize = 3;

pub(crate) struct OpcUaBuffers {
    frame: [u8; OPCUA_FRAME_BYTES],
    out: [u8; OPCUA_FRAME_BYTES],
}

impl OpcUaBuffers {
    const ZERO: Self = Self {
        frame: [0; OPCUA_FRAME_BYTES],
        out: [0; OPCUA_FRAME_BYTES],
    };
}

// ConstStaticCell, not StaticCell: a runtime `init_with` closure returns the
// 32 KiB workspace by value, and the release compiler materialised one shared
// 32 KiB temporary in the main task frame to construct listeners 1 and 2.
// `take()` only hands out a pointer to already-const-zeroed .bss, so the main
// poll frame carries no listener workspace at all.
static OPCUA_BUFFERS_0: ConstStaticCell<OpcUaBuffers> = ConstStaticCell::new(OpcUaBuffers::ZERO);
static OPCUA_BUFFERS_1: ConstStaticCell<OpcUaBuffers> = ConstStaticCell::new(OpcUaBuffers::ZERO);
static OPCUA_BUFFERS_2: ConstStaticCell<OpcUaBuffers> = ConstStaticCell::new(OpcUaBuffers::ZERO);
static OPCUA_SESSION_TOKEN_NONCE: AtomicU32 = AtomicU32::new(0x0001_7001);

pub(crate) fn init_opcua_buffers() -> (
    &'static mut OpcUaBuffers,
    &'static mut OpcUaBuffers,
    &'static mut OpcUaBuffers,
) {
    (
        OPCUA_BUFFERS_0.take(),
        OPCUA_BUFFERS_1.take(),
        OPCUA_BUFFERS_2.take(),
    )
}

// SAFETY: stable debugger/HIL readback symbols for the product OPC UA server.
// Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_OPCUA_STAGE: AtomicU32 = AtomicU32::new(OpcUaStage::Disabled as u32);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_OPCUA_LAST_ERROR: AtomicU32 = AtomicU32::new(OpcUaTaskError::None as u32);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_OPCUA_ACCEPTED_CONNECTIONS: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_OPCUA_FRAMES_HANDLED: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_OPCUA_LAST_SERVICE_ID: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_OPCUA_LAST_STATUS: AtomicU32 = AtomicU32::new(opcua_status::GOOD);

// SAFETY: stable debugger/HIL readback symbol; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_OPCUA_LAST_READ_NODE: AtomicU32 = AtomicU32::new(0);

// SAFETY: stable debugger/HIL readback symbols; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_OPCUA_LISTENER_STAGE: [AtomicU32; OPCUA_LISTENER_PROBE_COUNT] = [
    AtomicU32::new(OpcUaStage::Disabled as u32),
    AtomicU32::new(OpcUaStage::Disabled as u32),
    AtomicU32::new(OpcUaStage::Disabled as u32),
];

// SAFETY: stable debugger/HIL readback symbols; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_OPCUA_LISTENER_LAST_ERROR: [AtomicU32; OPCUA_LISTENER_PROBE_COUNT] =
    [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];

// SAFETY: stable debugger/HIL readback symbols; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_OPCUA_LISTENER_ACCEPTED_CONNECTIONS: [AtomicU32; OPCUA_LISTENER_PROBE_COUNT] =
    [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];

// SAFETY: stable debugger/HIL readback symbols; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_OPCUA_LISTENER_FRAMES_HANDLED: [AtomicU32; OPCUA_LISTENER_PROBE_COUNT] =
    [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];

// SAFETY: stable debugger/HIL readback symbols; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_OPCUA_LISTENER_LAST_SERVICE_ID: [AtomicU32; OPCUA_LISTENER_PROBE_COUNT] =
    [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];

// SAFETY: stable debugger/HIL readback symbols; Rust owns all atomic writes.
#[unsafe(no_mangle)]
pub static M7_OPCUA_LISTENER_WRITE_FAILURES: [AtomicU32; OPCUA_LISTENER_PROBE_COUNT] =
    [AtomicU32::new(0), AtomicU32::new(0), AtomicU32::new(0)];

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpcUaStage {
    Disabled = 0,
    WaitNetwork = 1,
    Accept = 2,
    Connected = 3,
    ReadHeader = 4,
    ReadBody = 5,
    HandleFrame = 6,
    WriteResponse = 7,
    Close = 8,
    Backoff = 9,
    Error = 0xff,
}

#[cfg(all(
    feature = "diagnostic-stack-watermark",
    feature = "diagnostic-accelerated-clock"
))]
pub(crate) fn watermark_listeners_idle() -> bool {
    M7_OPCUA_LISTENER_STAGE
        .iter()
        .all(|stage| stage.load(Ordering::Relaxed) == OpcUaStage::Accept as u32)
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpcUaTaskError {
    None = 0,
    NetworkWaitTimeout = 1,
    Accept = 2,
    ReadHeader = 3,
    ReadBody = 4,
    InvalidFrameSize = 5,
    FrameTooLarge = 6,
    HandleFrame = 7,
    WriteResponse = 8,
    Flush = 9,
    UnsupportedService = 10,
}

#[embassy_executor::task(pool_size = 3)]
pub(crate) async fn opcua_server_task(
    stack: Stack<'static>,
    runtime: &'static SharedRuntime,
    buffers: &'static mut OpcUaBuffers,
    listener_id: u32,
    identity: ServerIdentity,
) -> ! {
    let mut socket_rx = [0u8; OPCUA_TCP_RX_BYTES];
    let mut socket_tx = [0u8; OPCUA_TCP_TX_BYTES];
    let watchdog_slot = listener_watchdog_slot(listener_id);

    loop {
        crate::task_checkin(watchdog_slot);
        record_stage(listener_id, OpcUaStage::WaitNetwork);
        if opcua_watchdog_timeout(
            watchdog_slot,
            crate::WATCHDOG_TASK_DEADLINE,
            stack.wait_config_up(),
        )
        .await
        .is_err()
        {
            record_error(listener_id, OpcUaTaskError::NetworkWaitTimeout);
            continue;
        }

        let mut socket = TcpSocket::new(stack, &mut socket_rx, &mut socket_tx);
        socket.set_timeout(Some(Duration::from_secs(30)));
        socket.set_keep_alive(Some(Duration::from_secs(10)));
        socket.set_nagle_enabled(false);

        record_stage(listener_id, OpcUaStage::Accept);
        match opcua_watchdog_checkin(watchdog_slot, socket.accept(OPCUA_PORT)).await {
            Ok(()) => {}
            Err(_) => {
                record_error(listener_id, OpcUaTaskError::Accept);
                Timer::after_millis(100).await;
                continue;
            }
        }

        M7_OPCUA_ACCEPTED_CONNECTIONS.fetch_add(1, Ordering::Relaxed);
        listener_probe(listener_id, &M7_OPCUA_LISTENER_ACCEPTED_CONNECTIONS)
            .fetch_add(1, Ordering::Relaxed);
        M7_OPCUA_LAST_ERROR.store(OpcUaTaskError::None as u32, Ordering::Relaxed);
        listener_probe(listener_id, &M7_OPCUA_LISTENER_LAST_ERROR)
            .store(OpcUaTaskError::None as u32, Ordering::Relaxed);
        record_stage(listener_id, OpcUaStage::Connected);
        rprintln!("opcua/product: listener {} client connected", listener_id);

        let session_nonce = next_opcua_session_token_nonce(listener_id);
        #[cfg(not(feature = "diagnostic-protocol-identifiers"))]
        let mut server = OpcUaServer::new_with_limits_and_session_nonce(
            identity,
            &crate::build_info::OPCUA_BUILD_INFO,
            TransportLimits::product_target(),
            session_nonce,
        );
        #[cfg(feature = "diagnostic-protocol-identifiers")]
        let mut server = crate::protocol_id_diagnostic::new_server(
            listener_id,
            identity,
            &crate::build_info::OPCUA_BUILD_INFO,
            session_nonce,
        );
        let mut close_mode = OpcUaCloseMode::Abort;
        let accepted_ms = crate::uptime_now_ms();
        let mut first_frame_received = false;
        loop {
            crate::task_checkin(watchdog_slot);
            let scheduler_now_ms = crate::uptime_now_ms();
            if let Some(delay_ms) = server.next_publish_delay_ms(scheduler_now_ms) {
                let wait_ms = core::cmp::min(delay_ms, 500);
                match select(
                    socket.wait_read_ready(),
                    Timer::after_millis(u64::from(wait_ms)),
                )
                .await
                {
                    Either::First(()) => {}
                    Either::Second(()) => {
                        let scheduler_now_ms = crate::uptime_now_ms();
                        if should_close_idle_connection(
                            &socket,
                            first_frame_received,
                            accepted_ms,
                            scheduler_now_ms,
                        ) {
                            close_mode = OpcUaCloseMode::GracefulDrain;
                            break;
                        }
                        let response_len = {
                            let mut data_access = runtime.lock().await;
                            if let Some(snapshot) = crate::probes::snapshot_loop_timing() {
                                data_access.set_loop_timing_diagnostics(
                                    snapshot.loop_max_gap_ms,
                                    snapshot.heartbeat_max_gap_ms,
                                    snapshot.late_heartbeat_count,
                                );
                            }
                            data_access
                                .set_single_core_health(crate::snapshot_single_core_health());
                            data_access
                                .set_buchi_trust_health(crate::snapshot_buchi_trust_health());
                            server.drain_due_publish_response(
                                &mut buffers.out,
                                &*data_access,
                                crate::uptime_now_ms_u64(),
                            )
                        };
                        let drain = match response_len {
                            Ok(drain) => drain,
                            Err(_) => {
                                record_error(listener_id, OpcUaTaskError::HandleFrame);
                                break;
                            }
                        };
                        match drain {
                            opta_opcua::TimerDrainResult::CloseConnection => {
                                // Idle session reclaim: free the listener for Accept.
                                close_mode = OpcUaCloseMode::GracefulDrain;
                                break;
                            }
                            opta_opcua::TimerDrainResult::Response(response_len) => {
                                record_stage(listener_id, OpcUaStage::WriteResponse);
                                update_response_status_probe(&buffers.out[..response_len]);
                                if !matches!(
                                    opcua_watchdog_timeout(
                                        watchdog_slot,
                                        OPCUA_IO_TIMEOUT,
                                        socket.write_all(&buffers.out[..response_len])
                                    )
                                    .await,
                                    Ok(Ok(()))
                                ) {
                                    listener_probe(listener_id, &M7_OPCUA_LISTENER_WRITE_FAILURES)
                                        .fetch_add(1, Ordering::Relaxed);
                                    record_error(listener_id, OpcUaTaskError::WriteResponse);
                                    break;
                                }
                                if !matches!(
                                    opcua_watchdog_timeout(
                                        watchdog_slot,
                                        OPCUA_IO_TIMEOUT,
                                        socket.flush(),
                                    )
                                    .await,
                                    Ok(Ok(()))
                                ) {
                                    listener_probe(listener_id, &M7_OPCUA_LISTENER_WRITE_FAILURES)
                                        .fetch_add(1, Ordering::Relaxed);
                                    record_error(listener_id, OpcUaTaskError::Flush);
                                    break;
                                }
                            }
                            opta_opcua::TimerDrainResult::None => {}
                        }
                        Timer::after_millis(1).await;
                        continue;
                    }
                }
            } else {
                match select(socket.wait_read_ready(), Timer::after_millis(500)).await {
                    Either::First(()) => {}
                    Either::Second(()) => {
                        let scheduler_now_ms = crate::uptime_now_ms();
                        if should_close_idle_connection(
                            &socket,
                            first_frame_received,
                            accepted_ms,
                            scheduler_now_ms,
                        ) {
                            close_mode = OpcUaCloseMode::GracefulDrain;
                            break;
                        }
                        continue;
                    }
                }
            }
            let frame_len =
                match read_frame(listener_id, watchdog_slot, &mut socket, &mut buffers.frame).await
                {
                    Ok(len) => len,
                    Err(OpcUaTaskError::ReadHeader) | Err(OpcUaTaskError::ReadBody) => {
                        break;
                    }
                    Err(error) => {
                        record_error(listener_id, error);
                        break;
                    }
                };
            first_frame_received = true;

            update_request_probes(listener_id, &buffers.frame[..frame_len]);
            record_stage(listener_id, OpcUaStage::HandleFrame);
            let freshness_now_ms = crate::uptime_now_ms_u64();
            let action = {
                let mut data_access = runtime.lock().await;
                if let Some(snapshot) = crate::probes::snapshot_loop_timing() {
                    data_access.set_loop_timing_diagnostics(
                        snapshot.loop_max_gap_ms,
                        snapshot.heartbeat_max_gap_ms,
                        snapshot.late_heartbeat_count,
                    );
                }
                data_access.set_single_core_health(crate::snapshot_single_core_health());
                data_access.set_buchi_trust_health(crate::snapshot_buchi_trust_health());
                server.handle_frame(
                    &buffers.frame[..frame_len],
                    &mut buffers.out,
                    &mut *data_access,
                    freshness_now_ms,
                )
            };

            let action = match action {
                Ok(action) => action,
                Err(_) => {
                    record_error(listener_id, OpcUaTaskError::HandleFrame);
                    break;
                }
            };
            M7_OPCUA_FRAMES_HANDLED.fetch_add(1, Ordering::Relaxed);
            listener_probe(listener_id, &M7_OPCUA_LISTENER_FRAMES_HANDLED)
                .fetch_add(1, Ordering::Relaxed);

            if let Some(response_len) = action.response_len() {
                record_stage(listener_id, OpcUaStage::WriteResponse);
                update_response_status_probe(&buffers.out[..response_len]);
                if !matches!(
                    opcua_watchdog_timeout(
                        watchdog_slot,
                        OPCUA_IO_TIMEOUT,
                        socket.write_all(&buffers.out[..response_len])
                    )
                    .await,
                    Ok(Ok(()))
                ) {
                    listener_probe(listener_id, &M7_OPCUA_LISTENER_WRITE_FAILURES)
                        .fetch_add(1, Ordering::Relaxed);
                    record_error(listener_id, OpcUaTaskError::WriteResponse);
                    break;
                }
                if !matches!(
                    opcua_watchdog_timeout(watchdog_slot, OPCUA_IO_TIMEOUT, socket.flush()).await,
                    Ok(Ok(()))
                ) {
                    listener_probe(listener_id, &M7_OPCUA_LISTENER_WRITE_FAILURES)
                        .fetch_add(1, Ordering::Relaxed);
                    record_error(listener_id, OpcUaTaskError::Flush);
                    break;
                }
            }

            let no_response = action.response_len().is_none() && !action.closes_connection();
            if action.closes_connection() {
                close_mode = if matches!(action, opta_opcua::FrameAction::Close) {
                    OpcUaCloseMode::GracefulDrain
                } else {
                    OpcUaCloseMode::Abort
                };
                break;
            }
            // Yield after each handled frame so one busy client cannot monopolize
            // the executor. Queued Publish requests that returned NoResponse get a
            // longer backoff to reduce client-side publish churn.
            Timer::after_millis(if no_response { 10 } else { 1 }).await;
        }

        record_stage(listener_id, OpcUaStage::Close);
        match close_mode {
            OpcUaCloseMode::GracefulDrain => {
                graceful_close_socket(listener_id, watchdog_slot, &mut socket).await;
            }
            OpcUaCloseMode::Abort => {
                socket.abort();
                let _ =
                    opcua_watchdog_timeout(watchdog_slot, OPCUA_IO_TIMEOUT, socket.flush()).await;
            }
        }
        rprintln!("opcua/product: listener {} client closed", listener_id);
        // Re-enter accept immediately after a clean client close. Product
        // clients depend on having a listener available during rapid
        // CloseSecureChannel/reconnect cycles; accept errors still use
        // their own bounded backoff above.
    }
}

fn next_opcua_session_token_nonce(listener_id: u32) -> u32 {
    let counter = OPCUA_SESSION_TOKEN_NONCE.fetch_add(1, Ordering::Relaxed);
    counter
        .wrapping_add(crate::uptime_now_ms())
        .wrapping_add(listener_id.rotate_left(16))
        .max(1)
}

fn listener_watchdog_slot(listener_id: u32) -> WatchdogSlot {
    match listener_id {
        0 => WatchdogSlot::OpcUaListener0,
        1 => WatchdogSlot::OpcUaListener1,
        2 => WatchdogSlot::OpcUaListener2,
        _ => panic!("invalid OPC UA listener id"),
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum OpcUaCloseMode {
    GracefulDrain,
    Abort,
}

fn should_close_idle_connection(
    socket: &TcpSocket<'_>,
    first_frame_received: bool,
    accepted_ms: u32,
    now_ms: u32,
) -> bool {
    if !socket.may_recv() {
        return true;
    }
    !first_frame_received && now_ms.wrapping_sub(accepted_ms) >= OPCUA_FIRST_FRAME_TIMEOUT_MS
}

async fn read_frame(
    listener_id: u32,
    watchdog_slot: WatchdogSlot,
    socket: &mut TcpSocket<'_>,
    frame: &mut [u8; OPCUA_FRAME_BYTES],
) -> Result<usize, OpcUaTaskError> {
    let mut header = [0u8; 8];
    record_stage(listener_id, OpcUaStage::ReadHeader);
    match opcua_watchdog_timeout(
        watchdog_slot,
        OPCUA_IO_TIMEOUT,
        socket.read_exact(&mut header),
    )
    .await
    {
        Ok(Ok(())) => {}
        Ok(Err(_)) | Err(_) => return Err(OpcUaTaskError::ReadHeader),
    }

    let message_size = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if message_size < 8 {
        return Err(OpcUaTaskError::InvalidFrameSize);
    }
    if message_size > frame.len() {
        return Err(OpcUaTaskError::FrameTooLarge);
    }

    frame[..8].copy_from_slice(&header);
    if message_size > 8 {
        record_stage(listener_id, OpcUaStage::ReadBody);
        match opcua_watchdog_timeout(
            watchdog_slot,
            OPCUA_IO_TIMEOUT,
            socket.read_exact(&mut frame[8..message_size]),
        )
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(_)) | Err(_) => return Err(OpcUaTaskError::ReadBody),
        }
    }
    Ok(message_size)
}

async fn graceful_close_socket(
    listener_id: u32,
    watchdog_slot: WatchdogSlot,
    socket: &mut TcpSocket<'_>,
) {
    socket.close();
    if !matches!(
        opcua_watchdog_timeout(watchdog_slot, OPCUA_IO_TIMEOUT, socket.flush()).await,
        Ok(Ok(()))
    ) {
        record_error(listener_id, OpcUaTaskError::Flush);
        socket.abort();
        let _ = opcua_watchdog_timeout(watchdog_slot, OPCUA_IO_TIMEOUT, socket.flush()).await;
        return;
    }

    let started_ms = crate::uptime_now_ms();
    let mut scratch = [0u8; 64];
    loop {
        if crate::uptime_now_ms().wrapping_sub(started_ms) >= OPCUA_CLOSE_DRAIN_TIMEOUT_MS {
            return;
        }
        match opcua_watchdog_timeout(
            watchdog_slot,
            OPCUA_CLOSE_DRAIN_READ_TIMEOUT,
            socket.read(&mut scratch),
        )
        .await
        {
            Ok(Ok(0)) | Ok(Err(_)) => return,
            Ok(Ok(_)) => {}
            Err(_) => {}
        }
    }
}

async fn opcua_watchdog_timeout<F>(
    watchdog_slot: WatchdogSlot,
    timeout: Duration,
    future: F,
) -> Result<F::Output, TimeoutError>
where
    F: Future,
{
    let guarded = with_timeout(timeout, future);
    let mut guarded = core::pin::pin!(guarded);
    loop {
        crate::task_checkin(watchdog_slot);
        match select(
            guarded.as_mut(),
            Timer::after(OPCUA_WATCHDOG_CHECKIN_INTERVAL),
        )
        .await
        {
            Either::First(result) => return result,
            Either::Second(()) => {}
        }
    }
}

async fn opcua_watchdog_checkin<F>(watchdog_slot: WatchdogSlot, future: F) -> F::Output
where
    F: Future,
{
    let mut future = core::pin::pin!(future);
    loop {
        crate::task_checkin(watchdog_slot);
        match select(
            future.as_mut(),
            Timer::after(OPCUA_WATCHDOG_CHECKIN_INTERVAL),
        )
        .await
        {
            Either::First(result) => return result,
            Either::Second(()) => {}
        }
    }
}

fn update_request_probes(listener_id: u32, frame: &[u8]) {
    let Ok(header) = parse_frame_header(frame) else {
        return;
    };
    match header.kind {
        FrameKind::Hello => {
            M7_OPCUA_LAST_SERVICE_ID.store(0, Ordering::Relaxed);
            listener_probe(listener_id, &M7_OPCUA_LISTENER_LAST_SERVICE_ID)
                .store(0, Ordering::Relaxed);
        }
        FrameKind::OpenSecureChannel | FrameKind::Message | FrameKind::Close => {
            if let Ok(info) = decode_uasc_request_info(frame) {
                M7_OPCUA_LAST_SERVICE_ID.store(info.service_type_id, Ordering::Relaxed);
                listener_probe(listener_id, &M7_OPCUA_LISTENER_LAST_SERVICE_ID)
                    .store(info.service_type_id, Ordering::Relaxed);
            }
            if let Ok(Some(node)) = decode_first_read_value_node(frame) {
                M7_OPCUA_LAST_READ_NODE.store(
                    encode_probe_node(node.namespace, node.identifier),
                    Ordering::Relaxed,
                );
            }
        }
    }
}

fn update_response_status_probe(response: &[u8]) {
    if response.len() >= 12 && &response[..3] == b"ERR" {
        M7_OPCUA_LAST_STATUS.store(
            u32::from_le_bytes([response[8], response[9], response[10], response[11]]),
            Ordering::Relaxed,
        );
    } else {
        M7_OPCUA_LAST_STATUS.store(opcua_status::GOOD, Ordering::Relaxed);
    }
}

fn record_stage(listener_id: u32, stage: OpcUaStage) {
    M7_OPCUA_STAGE.store(stage as u32, Ordering::Relaxed);
    listener_probe(listener_id, &M7_OPCUA_LISTENER_STAGE).store(stage as u32, Ordering::Relaxed);
}

fn record_error(listener_id: u32, error: OpcUaTaskError) {
    record_stage(listener_id, OpcUaStage::Error);
    M7_OPCUA_LAST_ERROR.store(error as u32, Ordering::Relaxed);
    listener_probe(listener_id, &M7_OPCUA_LISTENER_LAST_ERROR)
        .store(error as u32, Ordering::Relaxed);
}

fn listener_probe(
    listener_id: u32,
    probes: &'static [AtomicU32; OPCUA_LISTENER_PROBE_COUNT],
) -> &'static AtomicU32 {
    let index = if listener_id as usize >= OPCUA_LISTENER_PROBE_COUNT {
        OPCUA_LISTENER_PROBE_COUNT - 1
    } else {
        listener_id as usize
    };
    &probes[index]
}

const fn encode_probe_node(namespace: u16, identifier: u32) -> u32 {
    (namespace as u32) << 16 | (identifier & 0xffff)
}

const _: () = {
    assert!(OPCUA_FRAME_BYTES == 16_384);
    assert!(OPCUA_TCP_RX_BYTES == 4_096);
    assert!(OPCUA_TCP_TX_BYTES == OPCUA_FRAME_BYTES);
    assert!(product::BUCHI_WRITE_QUEUE_CAPACITY == 32);
};
