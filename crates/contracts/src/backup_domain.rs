/// STM32H7 RTC backup registers currently in use by the product contract.
pub const BACKUP_REGISTER_COUNT: u8 = 16;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupRegisterUse {
    DfuHandshake,
    FactoryResetLatch,
    LastFaultMagic,
    LastFaultReason,
    LastFaultSequence,
    LastFaultUptime,
    LastFaultDetail,
    LastFaultResetFlags,
    BootloaderScratch,
    BootBreadcrumbMagic,
    BootBreadcrumbStage,
    BootBreadcrumbSequence,
    BootBreadcrumbUptimeMs,
    BootBreadcrumbDetail,
    BootBreadcrumbChecksum,
    LastFaultChecksum,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BackupRegisterOwner {
    BootloaderReserved,
    M7Project,
    BootloaderScratch,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProjectRecordDomain {
    None,
    FactoryResetLatch,
    LastFault,
    BootBreadcrumb,
}

pub const fn classify(register: u8) -> Option<BackupRegisterUse> {
    match register {
        0 => Some(BackupRegisterUse::DfuHandshake),
        1 => Some(BackupRegisterUse::FactoryResetLatch),
        2 => Some(BackupRegisterUse::LastFaultMagic),
        3 => Some(BackupRegisterUse::LastFaultReason),
        4 => Some(BackupRegisterUse::LastFaultSequence),
        5 => Some(BackupRegisterUse::LastFaultUptime),
        6 => Some(BackupRegisterUse::LastFaultDetail),
        7 => Some(BackupRegisterUse::LastFaultResetFlags),
        8 => Some(BackupRegisterUse::BootloaderScratch),
        9 => Some(BackupRegisterUse::BootBreadcrumbMagic),
        10 => Some(BackupRegisterUse::BootBreadcrumbStage),
        11 => Some(BackupRegisterUse::BootBreadcrumbSequence),
        12 => Some(BackupRegisterUse::BootBreadcrumbUptimeMs),
        13 => Some(BackupRegisterUse::BootBreadcrumbDetail),
        14 => Some(BackupRegisterUse::BootBreadcrumbChecksum),
        15 => Some(BackupRegisterUse::LastFaultChecksum),
        _ => None,
    }
}

pub const fn owner_of(use_: BackupRegisterUse) -> BackupRegisterOwner {
    match use_ {
        BackupRegisterUse::DfuHandshake => BackupRegisterOwner::BootloaderReserved,
        BackupRegisterUse::BootloaderScratch => BackupRegisterOwner::BootloaderScratch,
        _ => BackupRegisterOwner::M7Project,
    }
}

pub const fn project_domain_of(use_: BackupRegisterUse) -> ProjectRecordDomain {
    match use_ {
        BackupRegisterUse::FactoryResetLatch => ProjectRecordDomain::FactoryResetLatch,
        BackupRegisterUse::LastFaultMagic
        | BackupRegisterUse::LastFaultReason
        | BackupRegisterUse::LastFaultSequence
        | BackupRegisterUse::LastFaultUptime
        | BackupRegisterUse::LastFaultDetail
        | BackupRegisterUse::LastFaultResetFlags
        | BackupRegisterUse::LastFaultChecksum => ProjectRecordDomain::LastFault,
        BackupRegisterUse::BootBreadcrumbMagic
        | BackupRegisterUse::BootBreadcrumbStage
        | BackupRegisterUse::BootBreadcrumbSequence
        | BackupRegisterUse::BootBreadcrumbUptimeMs
        | BackupRegisterUse::BootBreadcrumbDetail
        | BackupRegisterUse::BootBreadcrumbChecksum => ProjectRecordDomain::BootBreadcrumb,
        BackupRegisterUse::DfuHandshake | BackupRegisterUse::BootloaderScratch => {
            ProjectRecordDomain::None
        }
    }
}

pub const fn is_project_owned(register: u8) -> bool {
    match classify(register) {
        Some(use_) => matches!(owner_of(use_), BackupRegisterOwner::M7Project),
        None => false,
    }
}

pub const fn is_bootloader_reserved(register: u8) -> bool {
    match classify(register) {
        Some(use_) => !matches!(owner_of(use_), BackupRegisterOwner::M7Project),
        None => true,
    }
}
