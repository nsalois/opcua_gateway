// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

//! Finite volatile diagnostic inputs, never part of the normal product API.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DiagnosticCounterSeed {
    MaxMinusTwo,
    MaxMinusOne,
    Max,
}

impl DiagnosticCounterSeed {
    pub(crate) const fn value(self) -> u32 {
        match self {
            Self::MaxMinusTwo => u32::MAX - 2,
            Self::MaxMinusOne => u32::MAX - 1,
            Self::Max => u32::MAX,
        }
    }
}

/// A copy of the actual owner fields, not an expected-value or PASS record.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticCounterSnapshot {
    pub next_write_sequence: u32,
    pub accepted_writes: u32,
    pub completed_writes: u32,
    pub failed_writes: u32,
    pub successful_fetches: u32,
}
