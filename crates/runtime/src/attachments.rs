// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

pub const ATTACHMENT_HYSTERESIS_POLLS: u8 = 3;
pub const SUBSYSTEM_COUNT: usize = 5;

#[repr(usize)]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Subsystem {
    Bath = 0,
    Chiller,
    Rotavapor,
    Pump,
    Vacubox,
}

impl Subsystem {
    pub const fn index(self) -> usize {
        self as usize
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AttachmentState {
    Unknown,
    Attached,
    Detached,
}

impl AttachmentState {
    pub const fn is_detached(self) -> bool {
        matches!(self, Self::Detached)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AttachmentTracker {
    state: AttachmentState,
    consecutive_present: u8,
    consecutive_absent: u8,
}

impl AttachmentTracker {
    const fn new() -> Self {
        Self {
            state: AttachmentState::Unknown,
            consecutive_present: 0,
            consecutive_absent: 0,
        }
    }

    fn observe(&mut self, present: bool) {
        if present {
            self.consecutive_present = self.consecutive_present.saturating_add(1);
            self.consecutive_absent = 0;
            if self.consecutive_present >= ATTACHMENT_HYSTERESIS_POLLS {
                self.state = AttachmentState::Attached;
            }
        } else {
            self.consecutive_absent = self.consecutive_absent.saturating_add(1);
            self.consecutive_present = 0;
            if self.consecutive_absent >= ATTACHMENT_HYSTERESIS_POLLS {
                self.state = AttachmentState::Detached;
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct SubsystemAttachments {
    trackers: [AttachmentTracker; SUBSYSTEM_COUNT],
}

impl SubsystemAttachments {
    pub(crate) const fn new() -> Self {
        Self {
            trackers: [AttachmentTracker::new(); SUBSYSTEM_COUNT],
        }
    }

    pub(crate) const fn state(&self, subsystem: Subsystem) -> AttachmentState {
        self.trackers[subsystem.index()].state
    }

    pub(crate) fn observe(&mut self, subsystem: Subsystem, present: bool) {
        self.trackers[subsystem.index()].observe(present);
    }

    pub(crate) const fn is_detached(&self, subsystem: Subsystem) -> bool {
        self.state(subsystem).is_detached()
    }
}
