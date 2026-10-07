// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Embassy-net configuration built from the field GatewayConfig record.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use embassy_net::Ipv4Address;
use opta_gateway_contracts::config::{self as field_config, GatewayConfig};

fn ipv4(value: [u8; 4]) -> Ipv4Address {
    Ipv4Address::new(value[0], value[1], value[2], value[3])
}

pub(crate) fn configured_hostname(config: &GatewayConfig) -> heapless::String<32> {
    let mut hostname = heapless::String::<32>::new();
    let _ = hostname.push_str(config.device_name.as_str());
    hostname
}

pub(crate) fn configured_net_config(
    config: &GatewayConfig,
    hostname: heapless::String<32>,
) -> embassy_net::Config {
    match config.net_mode {
        field_config::NetMode::Dhcp => {
            let mut dhcp = embassy_net::DhcpConfig::default();
            dhcp.hostname = Some(hostname);
            embassy_net::Config::dhcpv4(dhcp)
        }
        field_config::NetMode::Static => {
            let mut dns_servers = heapless::Vec::new();
            if !field_config::is_unspecified(config.static_dns) {
                let _ = dns_servers.push(ipv4(config.static_dns));
            }
            embassy_net::Config::ipv4_static(embassy_net::StaticConfigV4 {
                address: embassy_net::Ipv4Cidr::new(
                    ipv4(config.static_ip),
                    field_config::netmask_prefix_len(config.static_netmask).unwrap_or(0),
                ),
                gateway: if field_config::is_unspecified(config.static_gateway) {
                    None
                } else {
                    Some(ipv4(config.static_gateway))
                },
                dns_servers,
            })
        }
    }
}
