use super::retained_record;

pub const LAST_FAULT_MAGIC: u32 = 0x504D_3032; // "PM02": uptime word is seconds
pub const LAST_FAULT_PENDING_MAGIC: u32 = 0x504D_5032; // "PMP2"
pub const LEGACY_LAST_FAULT_MAGIC: u32 = 0x504D_3031; // "PM01": uptime word is ms
pub const LEGACY_LAST_FAULT_PENDING_MAGIC: u32 = 0x504D_5031; // "PMP1"

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LastFaultFormat {
    SecondsV2,
    LegacyMillisecondsV1,
}

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LastFaultReason {
    None = 0,
    /// Historical decode value retained for backup records written by older
    /// dual-core experiments. Current product firmware never persists it.
    M4HeartbeatFault = 1,
    HardFault = 2,
    MemManageFault = 3,
    BusFault = 4,
    UsageFault = 5,
    StackOverflow = 6,
    Assert = 7,
    IwdgReset = 8,
    EthInitSwrTimeout = 9,
    EthInitStrapLatch = 10,
}

impl LastFaultReason {
    pub const fn from_word(word: u32) -> Option<Self> {
        match word {
            0 => Some(Self::None),
            1 => Some(Self::M4HeartbeatFault),
            2 => Some(Self::HardFault),
            3 => Some(Self::MemManageFault),
            4 => Some(Self::BusFault),
            5 => Some(Self::UsageFault),
            6 => Some(Self::StackOverflow),
            7 => Some(Self::Assert),
            8 => Some(Self::IwdgReset),
            9 => Some(Self::EthInitSwrTimeout),
            10 => Some(Self::EthInitStrapLatch),
            _ => None,
        }
    }

    pub const fn as_word(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LastFaultWords {
    pub magic: u32,
    pub reason: u32,
    pub sequence: u32,
    /// Unit is selected by `magic`: seconds for PM02/PMP2, milliseconds for
    /// legacy PM01/PMP1.
    pub uptime_word: u32,
    pub detail: u32,
    pub reset_flags: u32,
    pub checksum: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LastFaultRecord {
    pub valid: bool,
    pub reason_word: u32,
    pub known_reason: Option<LastFaultReason>,
    pub sequence: u32,
    pub format: Option<LastFaultFormat>,
    pub uptime_word: u32,
    pub detail: u32,
    pub reset_flags: u32,
}

impl LastFaultRecord {
    pub const fn invalid() -> Self {
        Self {
            valid: false,
            reason_word: 0,
            known_reason: Some(LastFaultReason::None),
            sequence: 0,
            format: None,
            uptime_word: 0,
            detail: 0,
            reset_flags: 0,
        }
    }

    pub const fn uptime_seconds(self) -> Option<u32> {
        match self.format {
            Some(LastFaultFormat::SecondsV2) => Some(self.uptime_word),
            Some(LastFaultFormat::LegacyMillisecondsV1) | None => None,
        }
    }

    pub const fn legacy_uptime_ms(self) -> Option<u32> {
        match self.format {
            Some(LastFaultFormat::LegacyMillisecondsV1) => Some(self.uptime_word),
            Some(LastFaultFormat::SecondsV2) | None => None,
        }
    }
}

pub fn checksum(
    reason: u32,
    sequence: u32,
    uptime_seconds: u32,
    detail: u32,
    reset_flags: u32,
) -> u32 {
    retained_record::fnv1a32_words(&[
        LAST_FAULT_MAGIC,
        reason,
        sequence,
        uptime_seconds,
        detail,
        reset_flags,
    ])
}

fn pending_checksum(reason: u32, sequence: u32, uptime_seconds: u32, detail: u32) -> u32 {
    retained_record::fnv1a32_words(&[
        LAST_FAULT_PENDING_MAGIC,
        reason,
        sequence,
        uptime_seconds,
        detail,
        0,
    ])
}

pub fn legacy_checksum(
    reason: u32,
    sequence: u32,
    uptime_ms: u32,
    detail: u32,
    reset_flags: u32,
) -> u32 {
    retained_record::fnv1a32_words(&[reason, sequence, uptime_ms, detail, reset_flags])
}

fn legacy_pending_checksum(reason: u32, sequence: u32, uptime_ms: u32, detail: u32) -> u32 {
    retained_record::fnv1a32_words(&[
        LEGACY_LAST_FAULT_PENDING_MAGIC,
        reason,
        sequence,
        uptime_ms,
        detail,
        0,
    ])
}

pub const fn next_sequence(existing_valid: bool, existing_sequence: u32) -> u32 {
    if existing_valid && existing_sequence != u32::MAX {
        existing_sequence + 1
    } else {
        1
    }
}

pub fn encode_record(
    reason: LastFaultReason,
    sequence: u32,
    uptime_seconds: u32,
    detail: u32,
    reset_flags: u32,
) -> LastFaultWords {
    encode_record_words(
        reason.as_word(),
        sequence,
        uptime_seconds,
        detail,
        reset_flags,
    )
}

pub fn encode_record_words(
    reason_word: u32,
    sequence: u32,
    uptime_seconds: u32,
    detail: u32,
    reset_flags: u32,
) -> LastFaultWords {
    LastFaultWords {
        magic: LAST_FAULT_MAGIC,
        reason: reason_word,
        sequence,
        uptime_word: uptime_seconds,
        detail,
        reset_flags,
        checksum: checksum(reason_word, sequence, uptime_seconds, detail, reset_flags),
    }
}

/// Start a new retained-fault lifecycle with reset classification pending.
///
/// The pending format keeps the existing seven-word backup-register layout,
/// clears any reset flags inherited from the previous fault, and uses a
/// state-specific checksum so a corrupted magic cannot silently change a
/// pending record into a classified record (or vice versa).
pub fn encode_pending_record(
    reason: LastFaultReason,
    sequence: u32,
    uptime_seconds: u32,
    detail: u32,
) -> LastFaultWords {
    let reason = reason.as_word();
    LastFaultWords {
        magic: LAST_FAULT_PENDING_MAGIC,
        reason,
        sequence,
        uptime_word: uptime_seconds,
        detail,
        reset_flags: 0,
        checksum: pending_checksum(reason, sequence, uptime_seconds, detail),
    }
}

/// Encode a legacy PM01 record for compatibility tests and downgrade evidence.
pub fn encode_legacy_record_words(
    reason_word: u32,
    sequence: u32,
    uptime_ms: u32,
    detail: u32,
    reset_flags: u32,
) -> LastFaultWords {
    LastFaultWords {
        magic: LEGACY_LAST_FAULT_MAGIC,
        reason: reason_word,
        sequence,
        uptime_word: uptime_ms,
        detail,
        reset_flags,
        checksum: legacy_checksum(reason_word, sequence, uptime_ms, detail, reset_flags),
    }
}

/// Encode a legacy PMP1 record for compatibility tests.
pub fn encode_legacy_pending_record(
    reason: LastFaultReason,
    sequence: u32,
    uptime_ms: u32,
    detail: u32,
) -> LastFaultWords {
    let reason = reason.as_word();
    LastFaultWords {
        magic: LEGACY_LAST_FAULT_PENDING_MAGIC,
        reason,
        sequence,
        uptime_word: uptime_ms,
        detail,
        reset_flags: 0,
        checksum: legacy_pending_checksum(reason, sequence, uptime_ms, detail),
    }
}

/// Classify a pending fault from its immediately following boot exactly once.
///
/// Final PM02 and legacy PM01 records are already classified and return
/// `None`. A legacy PMP1 record is finalized as PM01 without changing units.
pub fn classify_reset_once(words: LastFaultWords, reset_flags: u32) -> Option<LastFaultWords> {
    let record = decode_record(words);
    if !record.valid {
        return None;
    }
    match words.magic {
        LAST_FAULT_PENDING_MAGIC => Some(encode_record_words(
            record.reason_word,
            record.sequence,
            record.uptime_word,
            record.detail,
            reset_flags,
        )),
        LEGACY_LAST_FAULT_PENDING_MAGIC => Some(encode_legacy_record_words(
            record.reason_word,
            record.sequence,
            record.uptime_word,
            record.detail,
            reset_flags,
        )),
        _ => None,
    }
}

pub fn is_reset_classification_pending(words: LastFaultWords) -> bool {
    matches!(
        words.magic,
        LAST_FAULT_PENDING_MAGIC | LEGACY_LAST_FAULT_PENDING_MAGIC
    ) && decode_record(words).valid
}

pub fn decode_record(words: LastFaultWords) -> LastFaultRecord {
    let (format, expected_checksum) = match words.magic {
        LAST_FAULT_MAGIC => (
            LastFaultFormat::SecondsV2,
            checksum(
                words.reason,
                words.sequence,
                words.uptime_word,
                words.detail,
                words.reset_flags,
            ),
        ),
        LAST_FAULT_PENDING_MAGIC if words.reset_flags == 0 => (
            LastFaultFormat::SecondsV2,
            pending_checksum(
                words.reason,
                words.sequence,
                words.uptime_word,
                words.detail,
            ),
        ),
        LEGACY_LAST_FAULT_MAGIC => (
            LastFaultFormat::LegacyMillisecondsV1,
            legacy_checksum(
                words.reason,
                words.sequence,
                words.uptime_word,
                words.detail,
                words.reset_flags,
            ),
        ),
        LEGACY_LAST_FAULT_PENDING_MAGIC if words.reset_flags == 0 => (
            LastFaultFormat::LegacyMillisecondsV1,
            legacy_pending_checksum(
                words.reason,
                words.sequence,
                words.uptime_word,
                words.detail,
            ),
        ),
        _ => return LastFaultRecord::invalid(),
    };
    if words.checksum != expected_checksum {
        return LastFaultRecord::invalid();
    }
    LastFaultRecord {
        valid: true,
        reason_word: words.reason,
        known_reason: LastFaultReason::from_word(words.reason),
        sequence: words.sequence,
        format: Some(format),
        uptime_word: words.uptime_word,
        detail: words.detail,
        reset_flags: words.reset_flags,
    }
}

pub const fn fault_detail_from_frame(fault_pc: u32, fault_lr: u32, fault_psr: u32) -> u32 {
    (fault_pc & 0xFFFF_0000) | ((fault_lr ^ fault_psr) & 0x0000_FFFF)
}
