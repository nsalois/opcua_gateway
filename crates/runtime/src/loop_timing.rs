// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

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

#[cfg(test)]
mod counter_tests {
    use super::LoopTimingMonitor;

    #[test]
    fn accelerated_timing_publication_saturates_with_full_width_state() {
        for seed in [
            u64::from(u32::MAX) - 2,
            u64::from(u32::MAX) - 1,
            u64::from(u32::MAX),
            u64::MAX - 2,
            u64::MAX - 1,
            u64::MAX,
        ] {
            let mut monitor = LoopTimingMonitor::new(1, 0);
            monitor.late_heartbeat_count = seed;
            assert_eq!(monitor.late_heartbeat_count, seed);
            assert!(monitor.observe(0, 0).is_none());
            for step in 1..=5u64 {
                let now = step * 4_294_967_296;
                let result = monitor.observe(now, now).unwrap();
                let expected = (u128::from(seed) + u128::from(step)).min(u128::from(u64::MAX));
                assert_eq!(u128::from(monitor.late_heartbeat_count), expected);
                assert_eq!(
                    result.late_heartbeat_count,
                    expected.min(u128::from(u32::MAX)) as u32
                );
                assert_eq!(result.loop_max_gap_ms, u32::MAX);
                assert_eq!(result.heartbeat_max_gap_ms, u32::MAX);
            }
        }
    }
}
