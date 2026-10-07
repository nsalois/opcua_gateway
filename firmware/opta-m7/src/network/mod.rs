// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Network-facing types, Ethernet bring-up, and network tasks.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use embassy_net::StackResources;
use embassy_stm32::eth::{Ethernet, Sma};
use embassy_stm32::peripherals::{ETH, ETH_SMA};
use static_cell::StaticCell;

mod config;
mod ethernet;
mod mdns;
mod phy_probe;
mod tasks;

pub(crate) use config::{configured_hostname, configured_net_config};
#[cfg(feature = "diagnostic-ethernet-ingress")]
pub(crate) use ethernet::configure_ethernet_mmc_counters;
#[cfg(feature = "product")]
pub(crate) use ethernet::init_eth_packets;
pub(crate) use ethernet::{prepare_ethernet_reset_domain_or_panic, select_rmii_before_eth_init};
#[cfg(not(feature = "product"))]
pub(crate) use ethernet::{EthPacketQueue, ETH_PACKETS};
pub(crate) use phy_probe::Lan8742ProbePhy;
#[cfg(feature = "product")]
pub(crate) use tasks::eth_rx_drop_probe_task;
pub(crate) use tasks::{mdns_status, mdns_task, net_status_task, net_task};

pub(crate) type EthDevice = Ethernet<'static, ETH, Lan8742ProbePhy<Sma<'static, ETH_SMA>>>;

// Socket slots cover mDNS, the persistent Buchi TLS poller, three OPC UA accept
// sockets, and spare churn headroom. Two OPC UA listeners passed scripted
// single-session HIL but left a no-listener window during UaExpert discovery.
pub(crate) static NET_RESOURCES: StaticCell<StackResources<10>> = StaticCell::new();
