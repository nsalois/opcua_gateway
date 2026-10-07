#![allow(dead_code)]
use std::cell::Cell;
use std::future::Future;
use std::sync::{Mutex, MutexGuard};
use std::sync::atomic::{AtomicU32, Ordering};
use opta_buchi::{build_put_request_with_connection, write_http_status_to_opcua_status, Endpoint, HttpConnectionMode, HttpReadProgress, HttpReceiveBuffer};
use opta_gateway_contracts::{opcua_status, product};
use opta_gateway_contracts::config::TrustState;
use opta_gateway_contracts::freshness::{CacheReadStatus, ScalarValue};
use opta_gateway_contracts::watchdog::WatchdogSlot;
use opta_runtime::{RuntimeCache, RuntimeDataAccess, RuntimeNode, RuntimeWriteDispatchError};

// Only the hardware-facing collaborators are doubles; firmware functions below
// are extracted unchanged from the exact source, using real runtime/HTTP logic.
struct HostMutex<T>(Mutex<T>);
impl<T> HostMutex<T> {
    async fn lock(&self) -> MutexGuard<'_, T> { self.0.lock().unwrap() }
}
type SharedRuntime = HostMutex<RuntimeDataAccess<{product::BUCHI_WRITE_QUEUE_CAPACITY}>>;
type SharedTrust = HostMutex<Trust>;
struct Trust { generation: u32, state: TrustState }
#[derive(Clone, Copy)]
struct UnixTime;
static M7_BUCHI_RUNTIME_REVOKED: AtomicU32 = AtomicU32::new(0);
fn task_checkin(_: WatchdogSlot) {}
fn uptime_now_ms_u64() -> u64 { 1_000 }
const TLS_READ_CHUNK_BYTES: usize = 384;
const TLS_IO_TIMEOUT: () = ();
async fn tls_watchdog_timeout<F: Future>(_: (), future: F) -> Result<F::Output, ()> { Ok(future.await) }

#[derive(Clone, Copy, Debug)]
enum TrustChange { None, Revoke, Replace }
struct TlsConnectionType<'a> {
    runtime: &'static SharedRuntime,
    trust: &'static SharedTrust,
    change: TrustChange,
    reply: &'a [u8],
    sent: Vec<u8>,
    reads: usize,
}
impl TlsConnectionType<'_> {
    async fn write(&mut self, bytes: &[u8]) -> Result<usize, ()> { self.sent.extend_from_slice(bytes); Ok(bytes.len()) }
    async fn flush(&mut self) -> Result<(), ()> { Ok(()) }
    async fn read(&mut self, out: &mut [u8]) -> Result<usize, ()> {
        // The real firmware is suspended at its read await. Script the other
        // task's trust transition before completing that read with a full reply.
        let mut yielded = false;
        std::future::poll_fn(|cx| {
            if yielded { std::task::Poll::Ready(()) } else {
                yielded = true; cx.waker().wake_by_ref(); std::task::Poll::Pending
            }
        }).await;
        assert_eq!(self.reads, 0);
        self.reads += 1;
        assert!(self.sent.starts_with(b"PUT /api/v1/process HTTP/1.1\r\n"));
        assert!(self.sent.ends_with(br#"{"heating":{"set":42.000}}"#));
        match self.change {
            TrustChange::None => (),
            TrustChange::Revoke => {
                { let mut trust = self.trust.lock().await; trust.generation += 1; trust.state = TrustState::Revoked; }
                M7_BUCHI_RUNTIME_REVOKED.store(1, Ordering::Relaxed);
                self.runtime.lock().await.revoke_upstream_trust();
            }
            TrustChange::Replace => {
                { let mut trust = self.trust.lock().await; trust.generation += 1; trust.state = TrustState::Provisioned; }
                self.runtime.lock().await.revoke_upstream_trust();
            }
        }
        out[..self.reply.len()].copy_from_slice(self.reply);
        Ok(self.reply.len())
    }
}

include!("firmware.rs");

struct Observer { error: Cell<TlsTransportError>, status: Cell<i32> }
impl TlsObserver for Observer {
    fn set_stage(&self, _: TlsStage) {}
    fn set_error(&self, error: TlsTransportError) { self.error.set(error); }
    fn set_server_ipv4(&self, _: [u8; 4]) {}
    fn set_http_status(&self, status: i32) { self.status.set(status); }
    fn set_counts(&self, _: u32, _: u32) {}
    fn set_cache_status(&self, _: CacheReadStatus) {}
}
fn block_on<F: Future>(future: F) -> (F::Output, usize) {
    let mut future = std::pin::pin!(future);
    let mut cx = std::task::Context::from_waker(std::task::Waker::noop());
    for polls in 1..=20 {
        if let std::task::Poll::Ready(result) = future.as_mut().poll(&mut cx) { return (result, polls); }
    }
    panic!("host poll bound exceeded");
}

#[cfg(test)]
mod tests {
    use super::*;
    // Global revoked flag is a real firmware input; serialize tests explicitly.
    static SERIAL: Mutex<()> = Mutex::new(());
    fn scenario(change: TrustChange, http_status: i32, queued_peer: bool) {
        let _serial = SERIAL.lock().unwrap_or_else(|error| error.into_inner());
        M7_BUCHI_RUNTIME_REVOKED.store(0, Ordering::Relaxed);
        let mut data = RuntimeDataAccess::new();
        data.set_trust_state(TrustState::Verified);
        data.set_write_enabled(true);
        assert!(data.enqueue_write_node_id(2001, ScalarValue::FloatMilli(42_000)).accepted);
        if queued_peer { assert!(data.enqueue_write_node_id(2003, ScalarValue::Boolean(true)).accepted); }
        let runtime = Box::leak(Box::new(HostMutex(Mutex::new(data))));
        let trust = Box::leak(Box::new(HostMutex(Mutex::new(Trust { generation: 7, state: TrustState::Verified }))));
        let body = br#"{"heating":{"set":41.500}}"#;
        let mut reply = format!("HTTP/1.1 {http_status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n",body.len()).into_bytes();
        reply.extend_from_slice(body);
        let mut tls = TlsConnectionType { runtime, trust, change, reply: &reply, sent: Vec::new(), reads: 0 };
        let observer = Observer { error: Cell::new(TlsTransportError::None), status: Cell::new(0) };
        let mut request = [0u8; product::BUCHI_HTTP_REQUEST_BYTES];
        let mut response = HttpReceiveBuffer::<512>::new();
        let mut read_chunk = [0u8; TLS_READ_CHUNK_BYTES];
        let (continued,polls) = block_on(drain_pending_writes_over_tls_shared(&mut tls,"mock.local","dGVzdDp0ZXN0",&mut request,&mut response,&mut read_chunk,runtime,&observer,BuchiTlsTrustSource::Runtime(trust),Some(7)));
        assert!(polls >= 2, "read must suspend the actual production future");
        assert_eq!(tls.reads,1);
        assert_eq!(response.response().unwrap().status,http_status);
        let data = runtime.0.lock().unwrap();
        assert_eq!(data.write_queue_depth(),0);
        assert_eq!(data.health().buchi_write_accepted_count,if queued_peer {2} else {1});
        println!("change={change:?} http={http_status} accepted={} completed={} failed={} target={} last_http={} last_status={:#x} polls={polls}",data.health().buchi_write_accepted_count,data.health().buchi_write_completed_count,data.health().buchi_write_failed_count,data.health().buchi_write_last_target_node_id,data.health().buchi_write_last_http_status,data.health().buchi_write_last_opcua_status);
        match change {
            TrustChange::None => {
                assert!(continued);
                assert_eq!(data.health().buchi_write_completed_count,u32::from(http_status==200));
                assert_eq!(data.health().buchi_write_failed_count,u32::from(http_status!=200));
                assert_eq!(data.health().buchi_write_last_http_status,http_status as u32);
                assert_eq!(data.health().buchi_write_last_opcua_status,if http_status==200 {opcua_status::GOOD} else {opcua_status::BAD_RESOURCE_UNAVAILABLE});
                let read = data.read_node(RuntimeNode::ProcessHeatingSet,1_000);
                if http_status==200 { assert_eq!(read.opcua_status,opcua_status::GOOD);assert_eq!(read.value,Some(ScalarValue::FloatMilli(41_500))); }
                else { assert_eq!(read.cache_status,CacheReadStatus::NeverPublished); }
            }
            _ => {
                assert!(!continued);
                assert_eq!(data.health().buchi_write_completed_count,0);
                assert_eq!(data.health().buchi_write_failed_count,if queued_peer {2} else {1},"in-flight request needs its own terminal failure");
                assert_eq!(data.health().buchi_write_last_target_node_id,2001);
                assert_eq!(data.health().buchi_write_last_http_status,http_status as u32);
                assert_eq!(data.health().buchi_write_last_opcua_status,opcua_status::BAD_USER_ACCESS_DENIED);
                assert_eq!(observer.error.get(),TlsTransportError::TrustRevoked);
                assert_eq!(observer.status.get(),http_status);
                assert_eq!(data.read_node(RuntimeNode::ProcessHeatingSet,1_000).cache_status,CacheReadStatus::NeverPublished);
            }
        }
    }
    #[test] fn current_trust_success_response() { scenario(TrustChange::None,200,false); }
    #[test] fn current_trust_failed_response() { scenario(TrustChange::None,503,false); }
    #[test] fn revoked_during_response_records_inflight_separately_from_queue() { for status in [200,503] { scenario(TrustChange::Revoke,status,true); } }
    #[test] fn replaced_during_response_records_inflight_without_publish() { for status in [200,503] { scenario(TrustChange::Replace,status,false); } }
}
