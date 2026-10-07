// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

// Modified for the Opta gateway; see MODIFICATIONS.md for provenance and terms.
//! Minimal feature-gated Ethernet/IPv4/TCP digest parsing for the Opta F8 campaign.

const ETHERNET_HEADER_LEN: usize = 14;
const VLAN_HEADER_LEN: usize = 4;
const ETHERTYPE_IPV4: u16 = 0x0800;
const ETHERTYPE_8021Q: u16 = 0x8100;
const ETHERTYPE_8021AD: u16 = 0x88a8;
const IPV4_MIN_HEADER_LEN: usize = 20;
const TCP_MIN_HEADER_LEN: usize = 20;
const TCP_PROTOCOL: u8 = 6;
const OPCUA_PORT: u16 = 4840;
const CHECKSUM_NOT_CHECKED: u8 = 0;
const CHECKSUM_GOOD: u8 = 1;
const CHECKSUM_BAD: u8 = 2;

unsafe extern "C" {
    fn opta_f8_record_rx_digest(
        seq_raw: u32,
        payload_len: u16,
        tcp_flags: u8,
        checksum_verdict: u8,
    );
    fn opta_f8_record_tx_digest(ack_raw: u32, payload_len: u16, tcp_flags: u8);
}

struct TcpDigest {
    seq_raw: u32,
    ack_raw: u32,
    payload_len: u16,
    tcp_flags: u8,
    checksum_verdict: u8,
}

#[inline(always)]
pub(super) fn record_rx(frame: &[u8]) {
    let Some(digest) = parse_tcp_digest(frame, true) else {
        return;
    };
    // The Phase-1 sizing contract records RX payload segments only. Pure ACKs
    // do not help locate a missing client data original and would wrap the
    // 2,048-entry ring before the end of a ten-minute run.
    if digest.payload_len == 0 {
        return;
    }
    // SAFETY: `opta-f8-ingress-trace` is a final-binary contract. opta-m7
    // exports this exact scalar-only C ABI callback; no frame pointer crosses
    // the boundary and the callback only writes its feature-gated static ring.
    unsafe {
        opta_f8_record_rx_digest(
            digest.seq_raw,
            digest.payload_len,
            digest.tcp_flags,
            digest.checksum_verdict,
        )
    }
}

#[inline(always)]
pub(super) fn record_tx(frame: &[u8]) {
    let Some(digest) = parse_tcp_digest(frame, false) else {
        return;
    };
    // SAFETY: `opta-f8-ingress-trace` is a final-binary contract. opta-m7
    // exports this exact scalar-only C ABI callback, which only writes its
    // feature-gated static ring.
    unsafe { opta_f8_record_tx_digest(digest.ack_raw, digest.payload_len, digest.tcp_flags) }
}

fn parse_tcp_digest(frame: &[u8], verify_payload_checksum: bool) -> Option<TcpDigest> {
    if frame.len() < ETHERNET_HEADER_LEN {
        return None;
    }
    let mut ip_offset = ETHERNET_HEADER_LEN;
    let mut ethertype = read_u16(frame, 12)?;
    if ethertype == ETHERTYPE_8021Q || ethertype == ETHERTYPE_8021AD {
        if frame.len() < ETHERNET_HEADER_LEN + VLAN_HEADER_LEN {
            return None;
        }
        ethertype = read_u16(frame, 16)?;
        ip_offset += VLAN_HEADER_LEN;
    }
    if ethertype != ETHERTYPE_IPV4 || frame.len() < ip_offset + IPV4_MIN_HEADER_LEN {
        return None;
    }

    let ip = &frame[ip_offset..];
    if ip[0] >> 4 != 4 {
        return None;
    }
    let ip_header_len = usize::from(ip[0] & 0x0f) * 4;
    if ip_header_len < IPV4_MIN_HEADER_LEN || ip.len() < ip_header_len {
        return None;
    }
    let ip_total_len = usize::from(read_u16(ip, 2)?);
    if ip_total_len < ip_header_len + TCP_MIN_HEADER_LEN || ip.len() < ip_total_len {
        return None;
    }
    if ip[9] != TCP_PROTOCOL {
        return None;
    }
    // A fragmented datagram does not expose a complete CPU-visible TCP
    // segment at this hook, so it is outside the declared digest contract.
    if read_u16(ip, 6)? & 0x3fff != 0 {
        return None;
    }

    let tcp = &ip[ip_header_len..ip_total_len];
    let tcp_header_len = usize::from(tcp[12] >> 4) * 4;
    if tcp_header_len < TCP_MIN_HEADER_LEN || tcp.len() < tcp_header_len {
        return None;
    }
    let source_port = read_u16(tcp, 0)?;
    let destination_port = read_u16(tcp, 2)?;
    if source_port != OPCUA_PORT && destination_port != OPCUA_PORT {
        return None;
    }
    let payload_len = u16::try_from(tcp.len() - tcp_header_len).ok()?;
    Some(TcpDigest {
        seq_raw: read_u32(tcp, 4)?,
        ack_raw: read_u32(tcp, 8)?,
        payload_len,
        tcp_flags: tcp[13],
        checksum_verdict: if verify_payload_checksum && payload_len != 0 {
            if tcp_checksum_is_valid(ip, tcp) {
                CHECKSUM_GOOD
            } else {
                CHECKSUM_BAD
            }
        } else {
            CHECKSUM_NOT_CHECKED
        },
    })
}

fn tcp_checksum_is_valid(ip: &[u8], tcp: &[u8]) -> bool {
    let Ok(tcp_len) = u16::try_from(tcp.len()) else {
        return false;
    };
    let mut sum = 0u32;
    sum = add_bytes(sum, &ip[12..20]);
    sum = sum.wrapping_add(u32::from(TCP_PROTOCOL));
    sum = sum.wrapping_add(u32::from(tcp_len));
    sum = add_bytes(sum, tcp);
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum == 0xffff
}

fn add_bytes(mut sum: u32, bytes: &[u8]) -> u32 {
    let mut chunks = bytes.chunks_exact(2);
    for chunk in &mut chunks {
        sum = sum.wrapping_add(u32::from(u16::from_be_bytes([chunk[0], chunk[1]])));
    }
    if let [last] = chunks.remainder() {
        sum = sum.wrapping_add(u32::from(*last) << 8);
    }
    sum
}

fn read_u16(bytes: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
    ]))
}

fn read_u32(bytes: &[u8], offset: usize) -> Option<u32> {
    Some(u32::from_be_bytes([
        *bytes.get(offset)?,
        *bytes.get(offset + 1)?,
        *bytes.get(offset + 2)?,
        *bytes.get(offset + 3)?,
    ]))
}
