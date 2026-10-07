// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! DNS name matching and mDNS A-record response construction.

// Firmware policy marker: crate root declares #![no_std]; this module must not
// use alloc or std.
use embassy_net::Ipv4Address;

pub(super) const MDNS_PORT: u16 = 5353;
pub(super) const MDNS_GROUP: Ipv4Address = Ipv4Address::new(224, 0, 0, 251);
const MDNS_TTL_SECONDS: u32 = 120;
pub(super) const MDNS_RX_BYTES: usize = 1472;
pub(super) const MDNS_TX_BYTES: usize = 512;
pub(super) const MDNS_PACKET_META: usize = 4;

/// Return whether a responder built for `bound` still owns the active address.
///
/// The mDNS task uses this pure check before receiving and again before
/// transmitting so a DHCP loss or replacement forces the socket loop to be
/// rebuilt instead of advertising a stale A record.
pub(super) fn mdns_ipv4_is_current(bound: Ipv4Address, current: Option<Ipv4Address>) -> bool {
    current == Some(bound)
}

#[cfg(test)]
fn mdns_query_matches(packet: &[u8], hostname: &str) -> bool {
    packet.get(2).is_some_and(|flags| flags & 0x80 == 0)
        && questions(packet, hostname).is_some_and(|(_, matched, _)| matched)
}

fn questions(packet: &[u8], hostname: &str) -> Option<(usize, bool, bool)> {
    if packet.len() < 12 || read_u16(packet, 2) & 0x780f != 0 {
        return None;
    }
    let mut offset = 12;
    let mut matched = false;
    let mut unicast = false;
    for _ in 0..read_u16(packet, 4) {
        let (name_end, name_matches) = mdns_name(packet, offset, hostname)?;
        if name_end + 4 > packet.len() {
            return None;
        }
        let qtype = read_u16(packet, name_end);
        let qclass = read_u16(packet, name_end + 2);
        let ours = name_matches && (qtype == 1 || qtype == 255) && qclass & 0x7fff == 1;
        matched |= ours;
        unicast |= ours && qclass & 0x8000 != 0;
        offset = name_end + 4;
    }
    Some((offset, matched, unicast))
}

/// Parse the whole name even when it is not ours, so later questions remain
/// reachable. RFC 1035 section 4.1.4 pointers reference earlier occurrences.
/// A shrinking pointer limit and the 255-byte expanded limit bound all work.
fn mdns_name(packet: &[u8], mut offset: usize, hostname: &str) -> Option<(usize, bool)> {
    let mut end = None;
    let mut pointer_limit = offset;
    let mut expanded = 1usize; // terminating zero
    let mut labels = 0usize;
    let mut matches = true;
    loop {
        let length = *packet.get(offset)?;
        if length == 0 {
            return Some((end.unwrap_or(offset + 1), matches && labels == 2));
        }
        if length & 0xc0 == 0xc0 {
            let pointer = (usize::from(length & 0x3f) << 8) | usize::from(*packet.get(offset + 1)?);
            if pointer < 12 || pointer >= pointer_limit {
                return None;
            }
            end.get_or_insert(offset + 2);
            pointer_limit = pointer;
            offset = pointer;
            continue;
        }
        if length & 0xc0 != 0 {
            return None;
        }
        let length = usize::from(length);
        expanded += length + 1;
        if expanded > 255 {
            return None;
        }
        let label = packet.get(offset + 1..offset + 1 + length)?;
        let expected = match labels {
            0 => hostname.as_bytes(),
            1 => b"local",
            _ => b"",
        };
        matches &= label.eq_ignore_ascii_case(expected);
        labels += 1;
        offset += length + 1;
        if end.is_none() {
            pointer_limit = offset;
        }
    }
}

pub(super) fn build_mdns_a_response(
    out: &mut [u8],
    hostname: &str,
    ipv4: Ipv4Address,
) -> Option<usize> {
    let mut cursor = 0;
    write_u16(out, &mut cursor, 0)?; // mDNS responses use transaction ID 0.
    write_u16(out, &mut cursor, 0x8400)?; // response + authoritative answer.
    write_u16(out, &mut cursor, 0)?; // QDCOUNT
    write_u16(out, &mut cursor, 1)?; // ANCOUNT
    write_u16(out, &mut cursor, 0)?; // NSCOUNT
    write_u16(out, &mut cursor, 0)?; // ARCOUNT

    write_dns_label(out, &mut cursor, hostname.as_bytes())?;
    write_dns_label(out, &mut cursor, b"local")?;
    write_u8(out, &mut cursor, 0)?;
    write_u16(out, &mut cursor, 1)?; // TYPE A
    write_u16(out, &mut cursor, 0x8001)?; // cache-flush + CLASS IN
    write_u32(out, &mut cursor, MDNS_TTL_SECONDS)?;
    write_u16(out, &mut cursor, 4)?;
    for octet in ipv4.octets() {
        write_u8(out, &mut cursor, octet)?;
    }

    Some(cursor)
}

fn read_u16(input: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([input[offset], input[offset + 1]])
}

fn write_u8(out: &mut [u8], cursor: &mut usize, value: u8) -> Option<()> {
    if *cursor >= out.len() {
        return None;
    }
    out[*cursor] = value;
    *cursor += 1;
    Some(())
}

fn write_u16(out: &mut [u8], cursor: &mut usize, value: u16) -> Option<()> {
    for byte in value.to_be_bytes() {
        write_u8(out, cursor, byte)?;
    }
    Some(())
}

fn write_u32(out: &mut [u8], cursor: &mut usize, value: u32) -> Option<()> {
    for byte in value.to_be_bytes() {
        write_u8(out, cursor, byte)?;
    }
    Some(())
}

fn write_dns_label(out: &mut [u8], cursor: &mut usize, label: &[u8]) -> Option<()> {
    if label.len() > 63 {
        return None;
    }
    write_u8(out, cursor, label.len() as u8)?;
    for &byte in label {
        write_u8(out, cursor, byte)?;
    }
    Some(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PacketKind {
    Probe,
    Announcement,
    Answer,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Discovery {
    Probing { sent: u8, due: u64 },
    Active { second_announcement: Option<u64> },
    Conflict,
}

impl Discovery {
    pub(super) fn new(now: u64, jitter: u32) -> Self {
        Self::Probing {
            sent: 0,
            due: now + u64::from(jitter % 251),
        }
    }

    pub(super) fn status(self) -> u8 {
        match self {
            Self::Probing { .. } => 1,
            Self::Active { .. } => 2,
            Self::Conflict => 3,
        }
    }

    pub(super) fn pending(self, now: u64) -> Option<PacketKind> {
        match self {
            Self::Probing { sent, due } if now >= due => Some(if sent < 3 {
                PacketKind::Probe
            } else {
                PacketKind::Announcement
            }),
            Self::Active {
                second_announcement: Some(due),
            } if now >= due => Some(PacketKind::Announcement),
            _ => None,
        }
    }

    pub(super) fn sent(&mut self, kind: PacketKind, now: u64) {
        match (*self, kind) {
            (Self::Probing { sent, .. }, PacketKind::Probe) => {
                *self = Self::Probing {
                    sent: sent + 1,
                    due: now + 250,
                }
            }
            (Self::Probing { sent: 3, .. }, PacketKind::Announcement) => {
                *self = Self::Active {
                    second_announcement: Some(now + 1000),
                }
            }
            (Self::Active { .. }, PacketKind::Announcement) => {
                *self = Self::Active {
                    second_announcement: None,
                }
            }
            _ => {}
        }
    }

    pub(super) fn receive(&mut self, event: PacketEvent, now: u64) -> bool {
        match *self {
            Self::Probing { sent: 0, .. } | Self::Conflict => false,
            Self::Probing { .. } => {
                if event.conflict {
                    *self = Self::Conflict;
                } else if event.lost_probe {
                    *self = Self::Probing {
                        sent: 0,
                        due: now + 5000,
                    };
                }
                false
            }
            Self::Active { .. } => {
                if event.conflict {
                    *self = Self::Probing {
                        sent: 0,
                        due: now + 5000,
                    };
                    false
                } else {
                    event.query && !event.known_answer
                }
            }
        }
    }
}

#[derive(Clone, Copy, Default)]
pub(super) struct PacketEvent {
    pub(super) query: bool,
    pub(super) unicast: bool,
    pub(super) conflict: bool,
    pub(super) lost_probe: bool,
    pub(super) known_answer: bool,
    pub(super) probe: bool,
}

impl PacketEvent {
    pub(super) fn multicast_due(self, now: u64, last: Option<u64>) -> bool {
        // RFC 6762 section 6: probes require a response within the 750 ms
        // ownership window; ordinary one-second suppression is too long.
        let interval = if self.probe { 250 } else { 1000 };
        last.is_none_or(|last| now.saturating_sub(last) >= interval)
    }
}

pub(super) fn packet_event(
    packet: &[u8],
    hostname: &str,
    ipv4: Ipv4Address,
    probing: bool,
) -> Option<PacketEvent> {
    let (mut offset, query, unicast) = questions(packet, hostname)?;
    let response = read_u16(packet, 2) & 0x8000 != 0;
    let mut event = PacketEvent {
        query: query && !response,
        unicast,
        ..PacketEvent::default()
    };
    let own = ipv4.octets();
    let mut earlier = false;
    let mut later = false;
    for section in 0..3 {
        for _ in 0..read_u16(packet, 6 + section * 2) {
            let (end, ours) = mdns_name(packet, offset, hostname)?;
            if end + 10 > packet.len() {
                return None;
            }
            let kind = read_u16(packet, end);
            let class = read_u16(packet, end + 2) & 0x7fff;
            let ttl = u32::from_be_bytes(packet[end + 4..end + 8].try_into().ok()?);
            let size = usize::from(read_u16(packet, end + 8));
            let data = packet.get(end + 10..end + 10 + size)?;
            offset = end + 10 + size;
            if kind == 1 && size != 4 {
                return None;
            }
            if !ours || class != 1 {
                continue;
            }
            let identical = kind == 1 && data == own;
            if response && ttl != 0 && !identical && (probing || kind == 1) {
                event.conflict = true;
            }
            if !response && section == 0 && identical && ttl >= MDNS_TTL_SECONDS / 2 {
                event.known_answer = true;
            }
            if !response && section == 1 && query {
                event.probe = true;
                // Our RRset has exactly one IN A record. Comparing its first
                // member with the minimum peer member avoids sorting/storage.
                let order = kind.cmp(&1).then_with(|| data.cmp(&own));
                earlier |= order.is_lt();
                later |= order.is_gt();
            }
        }
    }
    event.lost_probe = !earlier && later;
    Some(event)
}

pub(super) fn build_mdns_probe(out: &mut [u8], hostname: &str, ipv4: Ipv4Address) -> Option<usize> {
    let mut cursor = 0;
    for value in [0, 0, 1, 0, 1, 0] {
        write_u16(out, &mut cursor, value)?;
    }
    write_dns_label(out, &mut cursor, hostname.as_bytes())?;
    write_dns_label(out, &mut cursor, b"local")?;
    write_u8(out, &mut cursor, 0)?;
    write_u16(out, &mut cursor, 255)?;
    write_u16(out, &mut cursor, 0x8001)?; // QU, IN
    write_u16(out, &mut cursor, 0xc00c)?; // owner references question
    write_u16(out, &mut cursor, 1)?;
    write_u16(out, &mut cursor, 1)?; // no cache-flush during probing
    write_u32(out, &mut cursor, MDNS_TTL_SECONDS)?;
    write_u16(out, &mut cursor, 4)?;
    for byte in ipv4.octets() {
        write_u8(out, &mut cursor, byte)?;
    }
    Some(cursor)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn question(packet: &mut std::vec::Vec<u8>, name: &str, kind: u16) {
        packet.push(name.len() as u8);
        packet.extend_from_slice(name.as_bytes());
        packet.extend_from_slice(b"\x05local\0");
        packet.extend_from_slice(&kind.to_be_bytes());
        packet.extend_from_slice(&1u16.to_be_bytes());
    }

    fn packet(kind: PacketKind, ip: [u8; 4]) -> std::vec::Vec<u8> {
        let mut bytes = [0u8; MDNS_TX_BYTES];
        let ip = Ipv4Address::from(ip);
        let length = if kind == PacketKind::Probe {
            build_mdns_probe(&mut bytes, "opta", ip)
        } else {
            build_mdns_a_response(&mut bytes, "opta", ip)
        }
        .unwrap();
        bytes[..length].to_vec()
    }

    #[test]
    fn ownership_requires_three_successful_probes_and_two_announcements() {
        let mut state = Discovery::new(1000, 250);
        assert_eq!(state.pending(1249), None);
        assert_eq!(state.pending(1250), Some(PacketKind::Probe));
        // A failed enqueue cannot advance ownership.
        assert_eq!(state.pending(1400), Some(PacketKind::Probe));
        for now in [1400, 1650, 1900] {
            assert_eq!(state.pending(now), Some(PacketKind::Probe));
            state.sent(PacketKind::Probe, now);
            assert_eq!(state.pending(now + 249), None);
            assert_eq!(state.status(), 1);
        }
        assert_eq!(state.pending(2150), Some(PacketKind::Announcement));
        state.sent(PacketKind::Announcement, 2150);
        assert_eq!(state.status(), 2);
        assert_eq!(state.pending(3149), None);
        assert_eq!(state.pending(3150), Some(PacketKind::Announcement));
        state.sent(PacketKind::Announcement, 3150);
        assert_eq!(state.pending(100_000), None); // no periodic announcements
        assert!(state.receive(
            PacketEvent {
                query: true,
                ..PacketEvent::default()
            },
            4000
        ));
    }

    #[test]
    fn conflicts_reprobe_then_refuse_without_reboot_or_persistent_writes() {
        let conflict = packet_event(
            &packet(PacketKind::Announcement, [192, 0, 2, 231]),
            "opta",
            Ipv4Address::new(192, 0, 2, 230),
            true,
        )
        .unwrap();
        assert!(conflict.conflict);
        let mut state = Discovery::new(0, 0);
        assert!(!state.receive(conflict, 0)); // stale response before our first probe
        assert_eq!(state.status(), 1);
        state.sent(PacketKind::Probe, 0);
        assert!(!state.receive(conflict, 1));
        assert_eq!(state, Discovery::Conflict);
        assert_eq!(state.pending(100_000), None);
        state = Discovery::Active {
            second_announcement: None,
        };
        assert!(!state.receive(conflict, 100));
        assert_eq!(state.pending(5099), None);
        assert_eq!(state.pending(5100), Some(PacketKind::Probe));
        state.sent(PacketKind::Probe, 5100);
        state.receive(conflict, 5101);
        assert_eq!(state, Discovery::Conflict);
        // A fresh link/address epoch starts probing, never inherits ownership.
        assert_eq!(Discovery::new(6000, 0).status(), 1);
    }

    #[test]
    fn compressed_probe_tie_breaks_and_known_answers_are_correct() {
        let own = Ipv4Address::new(192, 0, 2, 230);
        let higher = packet(PacketKind::Probe, [192, 0, 2, 231]);
        let mut event = packet_event(&higher, "opta", own, true).unwrap();
        assert!(event.query && event.unicast && event.lost_probe && !event.conflict && event.probe);
        assert!(!event.multicast_due(249, Some(0)));
        assert!(event.multicast_due(250, Some(0)));
        assert!(!PacketEvent::default().multicast_due(999, Some(0)));
        assert!(PacketEvent::default().multicast_due(1000, Some(0)));
        let mut state = Discovery::Probing { sent: 1, due: 250 };
        state.receive(event, 20);
        assert_eq!(state, Discovery::Probing { sent: 0, due: 5020 });
        event = packet_event(
            &packet(PacketKind::Probe, [192, 0, 2, 229]),
            "opta",
            own,
            true,
        )
        .unwrap();
        assert!(!event.lost_probe);
        let same = packet(PacketKind::Announcement, own.octets());
        assert!(!packet_event(&same, "opta", own, true).unwrap().conflict);
        let mut multi = higher.clone();
        multi[9] = 2;
        let lower = packet(PacketKind::Probe, [192, 0, 2, 229]);
        multi.extend_from_slice(&lower[lower.len() - 16..]);
        assert!(!packet_event(&multi, "opta", own, true).unwrap().lost_probe);
        let mut known = std::vec![0u8; 12];
        known[5] = 1;
        known[7] = 1;
        question(&mut known, "opta", 1);
        known.extend_from_slice(&same[12..]);
        event = packet_event(&known, "opta", own, false).unwrap();
        assert!(event.query && event.known_answer && !event.conflict);
        assert!(!Discovery::Active {
            second_announcement: None
        }
        .receive(event, 1000));
        for end in 0..higher.len() {
            assert!(packet_event(&higher[..end], "opta", own, true).is_none());
        }
    }

    #[test]
    fn later_questions_compression_and_case_are_supported() {
        let mut packet = std::vec![0u8; 12];
        packet[5] = 3;
        question(&mut packet, "someone-else", 1);
        let offset = packet.len() as u8;
        question(&mut packet, "OpTa", 28); // ours, but wrong query type
        packet.extend_from_slice(&[0xc0, offset, 0, 1, 0x80, 1]);
        assert!(mdns_query_matches(&packet, "opta"));
        for length in 0..packet.len() {
            assert!(!mdns_query_matches(&packet[..length], "opta"));
        }
        packet[2] = 0x80;
        assert!(!mdns_query_matches(&packet, "opta"));
    }

    #[test]
    fn malformed_pointer_and_overlong_names_fail_closed() {
        let mut packet = std::vec![0u8; 12];
        packet[5] = 1;
        packet.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1]); // self pointer
        assert!(!mdns_query_matches(&packet, "opta"));
        packet[13] = 0; // header pointer
        assert!(!mdns_query_matches(&packet, "opta"));
        packet.truncate(12);
        for _ in 0..4 {
            packet.push(63);
            packet.extend_from_slice(&[b'a'; 63]);
        }
        packet.extend_from_slice(&[0, 0, 1, 0, 1]);
        assert!(!mdns_query_matches(&packet, "opta"));
        // Deterministic bounded malformed-input sweep: no panic or pointer loop.
        let mut random = 1u32;
        for length in 0..512 {
            let mut bytes = std::vec![0u8; length];
            for byte in &mut bytes {
                random = random.wrapping_mul(1664525).wrapping_add(1013904223);
                *byte = (random >> 24) as u8;
            }
            let _ = mdns_query_matches(&bytes, "opta");
            let _ = packet_event(&bytes, "opta", Ipv4Address::new(192, 0, 2, 230), true);
        }
    }
}
