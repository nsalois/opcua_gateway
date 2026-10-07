// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

use opta_buchi::Endpoint;

pub const POLL_ENDPOINT_COUNT: usize = 3;
pub const POLL_ENDPOINTS: [Endpoint; POLL_ENDPOINT_COUNT] =
    [Endpoint::Process, Endpoint::Settings, Endpoint::Info];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointDueSet {
    pub process: bool,
    pub settings: bool,
    pub info: bool,
}

impl EndpointDueSet {
    pub const fn empty() -> Self {
        Self {
            process: false,
            settings: false,
            info: false,
        }
    }

    pub const fn contains(self, endpoint: Endpoint) -> bool {
        match endpoint {
            Endpoint::Process => self.process,
            Endpoint::Settings => self.settings,
            Endpoint::Info => self.info,
        }
    }

    pub const fn is_empty(self) -> bool {
        !self.process && !self.settings && !self.info
    }

    pub const fn count(self) -> usize {
        self.process as usize + self.settings as usize + self.info as usize
    }

    pub const fn first_due(self) -> Option<Endpoint> {
        if self.process {
            Some(Endpoint::Process)
        } else if self.settings {
            Some(Endpoint::Settings)
        } else if self.info {
            Some(Endpoint::Info)
        } else {
            None
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EndpointPollScheduler {
    next_due_ms: [u32; POLL_ENDPOINT_COUNT],
    last_poll_ms: [Option<u32>; POLL_ENDPOINT_COUNT],
}

impl EndpointPollScheduler {
    pub const fn new(start_ms: u32) -> Self {
        Self {
            next_due_ms: [start_ms; POLL_ENDPOINT_COUNT],
            last_poll_ms: [None; POLL_ENDPOINT_COUNT],
        }
    }

    pub const fn next_due_ms(&self, endpoint: Endpoint) -> u32 {
        self.next_due_ms[endpoint_index(endpoint)]
    }

    pub const fn last_poll_ms(&self, endpoint: Endpoint) -> Option<u32> {
        self.last_poll_ms[endpoint_index(endpoint)]
    }

    pub fn due_endpoints(&self, now_ms: u32) -> EndpointDueSet {
        EndpointDueSet {
            process: endpoint_due(now_ms, self.next_due_ms[endpoint_index(Endpoint::Process)]),
            settings: endpoint_due(now_ms, self.next_due_ms[endpoint_index(Endpoint::Settings)]),
            info: endpoint_due(now_ms, self.next_due_ms[endpoint_index(Endpoint::Info)]),
        }
    }

    pub fn next_due_endpoint(&self, now_ms: u32) -> Option<Endpoint> {
        self.due_endpoints(now_ms).first_due()
    }

    pub fn mark_polled(&mut self, endpoint: Endpoint, now_ms: u32) {
        let index = endpoint_index(endpoint);
        self.last_poll_ms[index] = Some(now_ms);
        self.next_due_ms[index] = now_ms.wrapping_add(endpoint.poll_ms());
    }
}

impl Default for EndpointPollScheduler {
    fn default() -> Self {
        Self::new(0)
    }
}

const fn endpoint_index(endpoint: Endpoint) -> usize {
    match endpoint {
        Endpoint::Process => 0,
        Endpoint::Settings => 1,
        Endpoint::Info => 2,
    }
}

fn endpoint_due(now_ms: u32, due_ms: u32) -> bool {
    now_ms.wrapping_sub(due_ms) < 0x8000_0000
}
