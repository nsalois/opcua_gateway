/// Published lifetime timing diagnostics for the main executor loop.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoopTimingSnapshot {
    pub loop_max_gap_ms: u32,
    pub heartbeat_max_gap_ms: u32,
    pub late_heartbeat_count: u32,
}

/// Allocation-free lifetime timing monitor driven by the Embassy monotonic clock.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LoopTimingMonitor {
    target_period_ms: u64,
    late_tolerance_ms: u64,
    previous_iteration_ms: Option<u64>,
    previous_heartbeat_ms: Option<u64>,
    loop_max_gap_ms: u64,
    heartbeat_max_gap_ms: u64,
    late_heartbeat_count: u64,
}

impl LoopTimingMonitor {
    pub const fn new(target_period_ms: u64, late_tolerance_ms: u64) -> Self {
        Self {
            target_period_ms,
            late_tolerance_ms,
            previous_iteration_ms: None,
            previous_heartbeat_ms: None,
            loop_max_gap_ms: 0,
            heartbeat_max_gap_ms: 0,
            late_heartbeat_count: 0,
        }
    }

    /// Observe one completed ticker wait and its successful heartbeat check-in.
    ///
    /// The first call establishes both baselines. Later calls return a complete
    /// lifetime snapshot whose published fields saturate at `u32::MAX`.
    pub fn observe(
        &mut self,
        iteration_ms: u64,
        heartbeat_checkin_ms: u64,
    ) -> Option<LoopTimingSnapshot> {
        let previous_iteration_ms = self.previous_iteration_ms.replace(iteration_ms);
        let previous_heartbeat_ms = self.previous_heartbeat_ms.replace(heartbeat_checkin_ms);
        let (Some(previous_iteration_ms), Some(previous_heartbeat_ms)) =
            (previous_iteration_ms, previous_heartbeat_ms)
        else {
            return None;
        };

        self.loop_max_gap_ms = self
            .loop_max_gap_ms
            .max(iteration_ms.saturating_sub(previous_iteration_ms));
        let heartbeat_gap_ms = heartbeat_checkin_ms.saturating_sub(previous_heartbeat_ms);
        self.heartbeat_max_gap_ms = self.heartbeat_max_gap_ms.max(heartbeat_gap_ms);
        if heartbeat_gap_ms > self.target_period_ms.saturating_add(self.late_tolerance_ms) {
            self.late_heartbeat_count = self.late_heartbeat_count.saturating_add(1);
        }

        Some(self.snapshot())
    }

    const fn snapshot(&self) -> LoopTimingSnapshot {
        LoopTimingSnapshot {
            loop_max_gap_ms: saturating_u32(self.loop_max_gap_ms),
            heartbeat_max_gap_ms: saturating_u32(self.heartbeat_max_gap_ms),
            late_heartbeat_count: saturating_u32(self.late_heartbeat_count),
        }
    }
}

const fn saturating_u32(value: u64) -> u32 {
    if value > u32::MAX as u64 {
        u32::MAX
    } else {
        value as u32
    }
}
