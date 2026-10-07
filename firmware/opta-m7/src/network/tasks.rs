// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Network runner, mDNS, status, and diagnostic tasks.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use core::future::poll_fn;
use core::sync::atomic::{AtomicU8, Ordering};

use embassy_net::udp::{PacketMetadata, SendError, UdpSocket};
use embassy_net::{IpAddress, IpEndpoint, Runner};
use embassy_time::{with_timeout, Duration, Instant, Timer};
use opta_gateway_contracts::watchdog::WatchdogSlot;
use rtt_target::rprintln;

use super::mdns::{
    build_mdns_a_response, build_mdns_probe, mdns_ipv4_is_current, packet_event, Discovery,
    PacketKind, MDNS_GROUP, MDNS_PACKET_META, MDNS_PORT, MDNS_RX_BYTES, MDNS_TX_BYTES,
};
use super::EthDevice;
use crate::probes::M7_IPV4_ADDR;
#[cfg(feature = "product")]
use crate::probes::{
    M7_ETH_DMA_STATUS_PROBE, M7_ETH_MAC_RX_ALIGNMENT_SNAPSHOT, M7_ETH_MAC_RX_CRC_SNAPSHOT,
    M7_ETH_MAC_RX_LPI_TRANSITION_SNAPSHOT, M7_ETH_RX_DROP_EVENTS,
};
#[cfg(feature = "diagnostic-ethernet-ingress")]
use crate::probes::{
    M7_ETH_MAC_MMC_CONTROL_SNAPSHOT, M7_ETH_MAC_RX_LPI_USEC_SNAPSHOT,
    M7_ETH_MAC_RX_UNICAST_GOOD_SNAPSHOT, M7_ETH_MAC_TX_LPI_TRANSITION_SNAPSHOT,
    M7_ETH_MAC_TX_LPI_USEC_SNAPSHOT, M7_ETH_MAC_TX_MULTIPLE_COLLISION_GOOD_SNAPSHOT,
    M7_ETH_MAC_TX_PACKET_COUNT_GOOD_SNAPSHOT, M7_ETH_MAC_TX_SINGLE_COLLISION_GOOD_SNAPSHOT,
};
use crate::watchdog::{task_checkin, WATCHDOG_TASK_DEADLINE};

#[cfg(feature = "product")]
const ETH_RX_DROP_PROBE_INTERVAL_MS: u64 = 100;

#[cfg(feature = "product")]
#[embassy_executor::task]
pub(crate) async fn eth_rx_drop_probe_task() -> ! {
    let mac = stm32_metapac::ETH.ethernet_mac();
    let dma = stm32_metapac::ETH.ethernet_dma();
    let mtl = stm32_metapac::ETH.ethernet_mtl();

    loop {
        let crc_errors = mac.rx_crc_error_packets().read().rxcrcerr();
        M7_ETH_MAC_RX_CRC_SNAPSHOT.store(crc_errors, Ordering::Relaxed);
        let alignment_errors = mac.rx_alignment_error_packets().read().rxalgnerr();
        M7_ETH_MAC_RX_ALIGNMENT_SNAPSHOT.store(alignment_errors, Ordering::Relaxed);
        let rx_lpi_transitions = mac.rx_lpi_tran_cntr().read().rxlpitrc();
        M7_ETH_MAC_RX_LPI_TRANSITION_SNAPSHOT.store(rx_lpi_transitions, Ordering::Relaxed);

        #[cfg(feature = "diagnostic-ethernet-ingress")]
        {
            M7_ETH_MAC_MMC_CONTROL_SNAPSHOT.store(mac.mmc_control().read().0, Ordering::Relaxed);
            M7_ETH_MAC_TX_PACKET_COUNT_GOOD_SNAPSHOT.store(
                mac.tx_packet_count_good().read().txpktg(),
                Ordering::Relaxed,
            );
            M7_ETH_MAC_TX_SINGLE_COLLISION_GOOD_SNAPSHOT.store(
                mac.tx_single_collision_good_packets().read().txsnglcolg(),
                Ordering::Relaxed,
            );
            M7_ETH_MAC_TX_MULTIPLE_COLLISION_GOOD_SNAPSHOT.store(
                mac.tx_multiple_collision_good_packets().read().txmultcolg(),
                Ordering::Relaxed,
            );
            M7_ETH_MAC_RX_UNICAST_GOOD_SNAPSHOT.store(
                mac.rx_unicast_packets_good().read().rxucastg(),
                Ordering::Relaxed,
            );
            M7_ETH_MAC_TX_LPI_USEC_SNAPSHOT
                .store(mac.tx_lpi_usec_cntr().read().txlpiusc(), Ordering::Relaxed);
            M7_ETH_MAC_TX_LPI_TRANSITION_SNAPSHOT
                .store(mac.tx_lpi_tran_cntr().read().txlpitrc(), Ordering::Relaxed);
            M7_ETH_MAC_RX_LPI_USEC_SNAPSHOT
                .store(mac.rx_lpi_usec_cntr().read().rxlpiusc(), Ordering::Relaxed);
        }

        let dmacsr = dma.dmacsr().read();
        M7_ETH_DMA_STATUS_PROBE.store(dmacsr.0, Ordering::Relaxed);

        let mut observed = 0u32;
        if dmacsr.rbu() {
            observed = observed.wrapping_add(1);
            dma.dmacsr().write(|w| {
                w.set_rbu(true);
                if dmacsr.ais() {
                    w.set_ais(true);
                }
            });
        }

        let missed = dma.dmacmfcr().read();
        observed = observed
            .wrapping_add(u32::from(missed.mfc()))
            .wrapping_add(if missed.mfco() { 1 } else { 0 });

        let rx_queue = mtl.mtlrx_qmpocr().read();
        observed = observed
            .wrapping_add(u32::from(rx_queue.mispktcnt()))
            .wrapping_add(if rx_queue.miscntovf() { 1 } else { 0 })
            .wrapping_add(u32::from(rx_queue.ovfpktcnt()))
            .wrapping_add(if rx_queue.ovfcntovf() { 1 } else { 0 });

        if observed != 0 {
            M7_ETH_RX_DROP_EVENTS.fetch_add(observed, Ordering::Relaxed);
        }

        Timer::after_millis(ETH_RX_DROP_PROBE_INTERVAL_MS).await;
    }
}

#[embassy_executor::task]
pub(crate) async fn net_task(mut runner: Runner<'static, EthDevice>) -> ! {
    runner.run().await
}

static MDNS_STATE: AtomicU8 = AtomicU8::new(0);

pub(crate) fn mdns_status() -> &'static str {
    match MDNS_STATE.load(Ordering::Relaxed) {
        1 => "probing",
        2 => "active",
        3 => "conflict",
        _ => "waiting",
    }
}

#[embassy_executor::task]
pub(crate) async fn mdns_task(
    stack: embassy_net::Stack<'static>,
    hostname: heapless::String<32>,
    seed: u32,
) -> ! {
    let mut rx_meta = [PacketMetadata::EMPTY; MDNS_PACKET_META];
    let mut tx_meta = [PacketMetadata::EMPTY; MDNS_PACKET_META];
    let mut rx_buffer = [0u8; MDNS_RX_BYTES];
    let mut tx_buffer = [0u8; MDNS_TX_BYTES];
    let mut response = [0u8; MDNS_TX_BYTES];

    loop {
        MDNS_STATE.store(0, Ordering::Relaxed);
        task_checkin(WatchdogSlot::MdnsResponder);
        if with_timeout(WATCHDOG_TASK_DEADLINE, stack.wait_link_up())
            .await
            .is_err()
        {
            continue;
        }
        task_checkin(WatchdogSlot::MdnsResponder);
        if with_timeout(WATCHDOG_TASK_DEADLINE, stack.wait_config_up())
            .await
            .is_err()
        {
            continue;
        }
        let ipv4 = match stack.config_v4() {
            Some(cfg) => cfg.address.address(),
            None => {
                Timer::after_millis(100).await;
                continue;
            }
        };

        if stack.join_multicast_group(MDNS_GROUP).is_err() {
            Timer::after_secs(1).await;
            continue;
        }

        let mut socket = UdpSocket::new(
            stack,
            &mut rx_meta,
            &mut rx_buffer,
            &mut tx_meta,
            &mut tx_buffer,
        );
        if socket.bind(MDNS_PORT).is_err() {
            Timer::after_secs(1).await;
            continue;
        }

        socket.set_hop_limit(Some(255));
        let group = IpEndpoint::new(IpAddress::Ipv4(MDNS_GROUP), MDNS_PORT);
        let now = Instant::now().as_millis();
        let mut discovery = Discovery::new(now, seed ^ now as u32);
        let mut last_multicast = None;
        MDNS_STATE.store(discovery.status(), Ordering::Relaxed);

        loop {
            task_checkin(WatchdogSlot::MdnsResponder);
            let current_ipv4 = stack.config_v4().map(|cfg| cfg.address.address());
            if !mdns_ipv4_is_current(ipv4, current_ipv4) || !stack.is_link_up() {
                break;
            }
            let mut destination = group;
            let now = Instant::now().as_millis();
            let mut kind = PacketKind::Answer;
            let response_len = if let Some(due) = discovery.pending(now) {
                kind = due;
                if due == PacketKind::Probe {
                    build_mdns_probe(&mut response, hostname.as_str(), ipv4)
                } else {
                    build_mdns_a_response(&mut response, hostname.as_str(), ipv4)
                }
            } else {
                with_timeout(
                    Duration::from_millis(25),
                    socket.recv_from_with(|packet, _remote| {
                        let now = Instant::now().as_millis();
                        let event = packet_event(
                            packet,
                            hostname.as_str(),
                            ipv4,
                            matches!(discovery, Discovery::Probing { .. }),
                        )?;
                        let answer = discovery.receive(event, now);
                        MDNS_STATE.store(discovery.status(), Ordering::Relaxed);
                        if !answer {
                            return None;
                        }
                        if event.unicast && _remote.endpoint.port == MDNS_PORT {
                            destination = _remote.endpoint;
                        } else if !event.multicast_due(now, last_multicast) {
                            return None;
                        }
                        build_mdns_a_response(&mut response, hostname.as_str(), ipv4)
                    }),
                )
                .await
                .unwrap_or(None)
            };
            if let Some(response_len) = response_len {
                task_checkin(WatchdogSlot::MdnsResponder);
                if with_timeout(
                    WATCHDOG_TASK_DEADLINE,
                    poll_fn(|cx| socket.poll_send_ready(cx)),
                )
                .await
                .is_err()
                {
                    continue;
                }
                let current_ipv4 = stack.config_v4().map(|cfg| cfg.address.address());
                if !mdns_ipv4_is_current(ipv4, current_ipv4) || !stack.is_link_up() {
                    break;
                }
                task_checkin(WatchdogSlot::MdnsResponder);
                if with_timeout(
                    WATCHDOG_TASK_DEADLINE,
                    socket.send_to(&response[..response_len], destination),
                )
                .await
                .unwrap_or(Err(SendError::NoRoute))
                .is_err()
                {
                    Timer::after_millis(100).await;
                    continue;
                }
                let now = Instant::now().as_millis();
                if destination == group {
                    last_multicast = Some(now);
                }
                discovery.sent(kind, now);
                MDNS_STATE.store(discovery.status(), Ordering::Relaxed);
            }
        }
    }
}

/// Publish network state to RTT and the `M7_IPV4_ADDR` probe word (big-endian
/// octets) so the bench can verify link + IP config without an RTT session.
#[embassy_executor::task]
pub(crate) async fn net_status_task(stack: embassy_net::Stack<'static>) -> ! {
    loop {
        task_checkin(WatchdogSlot::NetStatus);
        if with_timeout(WATCHDOG_TASK_DEADLINE, stack.wait_config_up())
            .await
            .is_err()
        {
            continue;
        }
        if let Some(cfg) = stack.config_v4() {
            let octets = cfg.address.address().octets();
            M7_IPV4_ADDR.store(u32::from_be_bytes(octets), Ordering::Relaxed);
            rprintln!(
                "net: up {}.{}.{}.{}/{}",
                octets[0],
                octets[1],
                octets[2],
                octets[3],
                cfg.address.prefix_len()
            );
        }
        loop {
            task_checkin(WatchdogSlot::NetStatus);
            if with_timeout(WATCHDOG_TASK_DEADLINE, stack.wait_config_down())
                .await
                .is_ok()
            {
                break;
            }
        }
        M7_IPV4_ADDR.store(0, Ordering::Relaxed);
        rprintln!("net: down");
    }
}
