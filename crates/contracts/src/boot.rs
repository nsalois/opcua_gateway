use super::retained_record;

pub const BOOT_BREADCRUMB_MAGIC: u32 = 0x4254_3031; // "BT01"

#[repr(u32)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BootStage {
    None = 0,
    SetupEntry = 1,
    FaultHandlersInstalled = 2,
    SerialReady = 3,
    SignsOfLifeConfigured = 4,
    ResetFlagsCaptured = 5,
    DeviceConfigReady = 6,
    BannerStart = 7,
    BannerPrinted = 8,
    FactoryResetHandled = 9,
    MailboxReady = 10,
    M4BootRequested = 11,
    EthernetReady = 12,
    SntpReady = 13,
    TcpProbeReady = 14,
    BuchiReady = 15,
    ConsoleReady = 16,
    OpcuaReady = 17,
    ResourceMetricsReady = 18,
    FactoryResetStopComplete = 19,
    WatchdogArmed = 20,
    SetupComplete = 21,
    LoopEntered = 22,
}

impl BootStage {
    pub const fn from_word(word: u32) -> Option<Self> {
        match word {
            0 => Some(Self::None),
            1 => Some(Self::SetupEntry),
            2 => Some(Self::FaultHandlersInstalled),
            3 => Some(Self::SerialReady),
            4 => Some(Self::SignsOfLifeConfigured),
            5 => Some(Self::ResetFlagsCaptured),
            6 => Some(Self::DeviceConfigReady),
            7 => Some(Self::BannerStart),
            8 => Some(Self::BannerPrinted),
            9 => Some(Self::FactoryResetHandled),
            10 => Some(Self::MailboxReady),
            11 => Some(Self::M4BootRequested),
            12 => Some(Self::EthernetReady),
            13 => Some(Self::SntpReady),
            14 => Some(Self::TcpProbeReady),
            15 => Some(Self::BuchiReady),
            16 => Some(Self::ConsoleReady),
            17 => Some(Self::OpcuaReady),
            18 => Some(Self::ResourceMetricsReady),
            19 => Some(Self::FactoryResetStopComplete),
            20 => Some(Self::WatchdogArmed),
            21 => Some(Self::SetupComplete),
            22 => Some(Self::LoopEntered),
            _ => None,
        }
    }

    pub const fn as_word(self) -> u32 {
        self as u32
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootBreadcrumbWords {
    pub magic: u32,
    pub stage: u32,
    pub sequence: u32,
    pub uptime_ms: u32,
    pub detail: u32,
    pub checksum: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BootBreadcrumbRecord {
    pub valid: bool,
    pub stage_word: u32,
    pub known_stage: Option<BootStage>,
    pub sequence: u32,
    pub uptime_ms: u32,
    pub detail: u32,
}

impl BootBreadcrumbRecord {
    pub const fn invalid() -> Self {
        Self {
            valid: false,
            stage_word: 0,
            known_stage: Some(BootStage::None),
            sequence: 0,
            uptime_ms: 0,
            detail: 0,
        }
    }
}

pub fn checksum(stage: u32, sequence: u32, uptime_ms: u32, detail: u32) -> u32 {
    retained_record::fnv1a32_words(&[stage, sequence, uptime_ms, detail])
}

pub const fn next_sequence(existing_valid: bool, existing_sequence: u32) -> u32 {
    if existing_valid && existing_sequence != u32::MAX {
        existing_sequence + 1
    } else {
        1
    }
}

pub fn encode_breadcrumb(
    stage: BootStage,
    existing_valid: bool,
    existing_sequence: u32,
    uptime_ms: u32,
    detail: u32,
) -> BootBreadcrumbWords {
    let stage_word = stage.as_word();
    let sequence = next_sequence(existing_valid, existing_sequence);
    BootBreadcrumbWords {
        magic: BOOT_BREADCRUMB_MAGIC,
        stage: stage_word,
        sequence,
        uptime_ms,
        detail,
        checksum: checksum(stage_word, sequence, uptime_ms, detail),
    }
}

pub fn decode_breadcrumb(words: BootBreadcrumbWords) -> BootBreadcrumbRecord {
    if words.magic != BOOT_BREADCRUMB_MAGIC {
        return BootBreadcrumbRecord::invalid();
    }
    if words.checksum != checksum(words.stage, words.sequence, words.uptime_ms, words.detail) {
        return BootBreadcrumbRecord::invalid();
    }
    BootBreadcrumbRecord {
        valid: true,
        stage_word: words.stage,
        known_stage: BootStage::from_word(words.stage),
        sequence: words.sequence,
        uptime_ms: words.uptime_ms,
        detail: words.detail,
    }
}

pub const fn stage_name(stage: BootStage) -> &'static str {
    match stage {
        BootStage::None => "none",
        BootStage::SetupEntry => "setup-entry",
        BootStage::FaultHandlersInstalled => "fault-handlers-installed",
        BootStage::SerialReady => "serial-ready",
        BootStage::SignsOfLifeConfigured => "signs-of-life-configured",
        BootStage::ResetFlagsCaptured => "reset-flags-captured",
        BootStage::DeviceConfigReady => "device-config-ready",
        BootStage::BannerStart => "banner-start",
        BootStage::BannerPrinted => "banner-printed",
        BootStage::FactoryResetHandled => "factory-reset-handled",
        BootStage::MailboxReady => "mailbox-ready",
        BootStage::M4BootRequested => "m4-boot-requested",
        BootStage::EthernetReady => "ethernet-ready",
        BootStage::SntpReady => "sntp-ready",
        BootStage::TcpProbeReady => "tcp-probe-ready",
        BootStage::BuchiReady => "buchi-ready",
        BootStage::ConsoleReady => "console-ready",
        BootStage::OpcuaReady => "opcua-ready",
        BootStage::ResourceMetricsReady => "resource-metrics-ready",
        BootStage::FactoryResetStopComplete => "factory-reset-stop-complete",
        BootStage::WatchdogArmed => "watchdog-armed",
        BootStage::SetupComplete => "setup-complete",
        BootStage::LoopEntered => "loop-entered",
    }
}

pub const fn stage_name_from_word(word: u32) -> &'static str {
    match BootStage::from_word(word) {
        Some(stage) => stage_name(stage),
        None => "unknown",
    }
}
