/// Initial reconnect delay before jitter is applied.
pub const BASE_MS: u32 = 500;
/// Maximum nominal reconnect delay before jitter is applied.
pub const CAP_MS: u32 = 8_000;
/// Symmetric reconnect jitter as a percentage of the nominal delay.
pub const JITTER_PCT: u32 = 25;
/// Maximum exponential shift applied to [`BASE_MS`].
pub const MAX_SHIFT: u8 = 4;

const ZERO_SEED_GUARD: u32 = 0xA5A5_1F3D;

/// Small deterministic PRNG used only for reconnect scheduling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct XorShift32 {
    state: u32,
}

impl XorShift32 {
    pub const fn new(seed: u32) -> Self {
        Self {
            state: if seed == 0 { ZERO_SEED_GUARD } else { seed },
        }
    }

    pub fn next_u32(&mut self) -> u32 {
        let mut value = self.state;
        value ^= value << 13;
        value ^= value >> 17;
        value ^= value << 5;
        self.state = value;
        value
    }

    fn uniform_inclusive(&mut self, upper: u32) -> u32 {
        ((u64::from(self.next_u32()) * (u64::from(upper) + 1)) >> 32) as u32
    }
}

/// Bounded exponential reconnect policy with deterministic per-seed jitter.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReconnectPolicy {
    failures: u8,
    rng: XorShift32,
}

impl ReconnectPolicy {
    pub const fn new(seed: u32) -> Self {
        Self {
            failures: 0,
            rng: XorShift32::new(seed),
        }
    }

    /// Returns the next failure delay and advances the saturating failure count.
    pub fn next_failure_delay_ms(&mut self) -> u32 {
        let shift = self.failures.min(MAX_SHIFT);
        let nominal_ms = (BASE_MS << shift).min(CAP_MS);
        let jitter_ms = nominal_ms * JITTER_PCT / 100;
        let offset = self.rng.uniform_inclusive(jitter_ms * 2);
        self.failures = self.failures.saturating_add(1).min(MAX_SHIFT);
        nominal_ms - jitter_ms + offset
    }

    /// Resets the failure count after verified application traffic succeeds.
    pub fn record_success(&mut self) {
        self.failures = 0;
    }
}

#[cfg(test)]
mod tests {
    use super::{ReconnectPolicy, XorShift32, BASE_MS, CAP_MS, JITTER_PCT, MAX_SHIFT};

    fn jitter_bounds(nominal_ms: u32) -> (u32, u32) {
        let jitter_ms = nominal_ms * JITTER_PCT / 100;
        (nominal_ms - jitter_ms, nominal_ms + jitter_ms)
    }

    #[test]
    fn reconnect_first_failure_stays_in_base_jitter_band() {
        let delay_ms = ReconnectPolicy::new(0x1234_5678).next_failure_delay_ms();
        assert!((375..=625).contains(&delay_ms));
    }

    #[test]
    fn reconnect_backoff_follows_exponential_envelopes_and_global_bounds() {
        let mut policy = ReconnectPolicy::new(0xA861_0A50);
        for nominal_ms in [500, 1_000, 2_000, 4_000, 8_000] {
            let delay_ms = policy.next_failure_delay_ms();
            let (minimum_ms, maximum_ms) = jitter_bounds(nominal_ms);
            assert!(
                (minimum_ms..=maximum_ms).contains(&delay_ms),
                "{delay_ms} not in {minimum_ms}..={maximum_ms}"
            );
            assert!((375..=10_000).contains(&delay_ms));
        }
    }

    #[test]
    fn reconnect_failure_counter_saturates_without_wrap() {
        let mut policy = ReconnectPolicy::new(0xCAFE_BABE);
        for nominal_ms in [500, 1_000, 2_000, 4_000, 8_000] {
            let (minimum_ms, maximum_ms) = jitter_bounds(nominal_ms);
            assert!((minimum_ms..=maximum_ms).contains(&policy.next_failure_delay_ms()));
        }
        for _ in 5..100 {
            assert!((6_000..=10_000).contains(&policy.next_failure_delay_ms()));
        }
        assert_eq!(policy.failures, MAX_SHIFT);
        for _ in 0..100 {
            assert!((6_000..=10_000).contains(&policy.next_failure_delay_ms()));
            assert_eq!(policy.failures, MAX_SHIFT);
        }
    }

    #[test]
    fn reconnect_success_resets_to_base_band() {
        let mut policy = ReconnectPolicy::new(0x1020_3040);
        for _ in 0..10 {
            let _ = policy.next_failure_delay_ms();
        }
        policy.record_success();
        assert_eq!(policy.failures, 0);
        assert!((375..=625).contains(&policy.next_failure_delay_ms()));
    }

    #[test]
    fn reconnect_sequences_are_seed_specific() {
        let mut first = ReconnectPolicy::new(0xA861_0A50);
        let mut second = ReconnectPolicy::new(0xA861_0A51);
        let first_sequence = core::array::from_fn::<_, 8, _>(|_| first.next_failure_delay_ms());
        let second_sequence = core::array::from_fn::<_, 8, _>(|_| second.next_failure_delay_ms());
        assert_ne!(first_sequence, second_sequence);
    }

    #[test]
    fn reconnect_sequence_is_deterministic() {
        let mut first = ReconnectPolicy::new(0x4455_6677);
        let mut second = ReconnectPolicy::new(0x4455_6677);
        for _ in 0..32 {
            assert_eq!(
                first.next_failure_delay_ms(),
                second.next_failure_delay_ms()
            );
        }
    }

    #[test]
    fn reconnect_zero_seed_is_guarded() {
        let mut rng = XorShift32::new(0);
        let sequence = core::array::from_fn::<_, 8, _>(|_| rng.next_u32());
        assert!(sequence.iter().all(|value| *value != 0));
        assert!(sequence.windows(2).all(|pair| pair[0] != pair[1]));
    }

    #[test]
    fn reconnect_policy_constants_pin_the_contract() {
        assert_eq!(BASE_MS, 500);
        assert_eq!(CAP_MS, 8_000);
        assert_eq!(JITTER_PCT, 25);
        assert_eq!(MAX_SHIFT, 4);
    }
}
