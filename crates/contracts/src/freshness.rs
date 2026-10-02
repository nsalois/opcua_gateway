use super::opcua_status;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CacheReadStatus {
    Ok,
    InvalidIndex,
    NeverPublished,
    Stale,
    NotConnected,
    RetryExhausted,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EntryMetadata {
    pub published: bool,
    pub last_publish_monotonic_ms: u64,
    pub freshness_ms: u32,
}

impl EntryMetadata {
    pub const fn unpublished(freshness_ms: u32) -> Self {
        Self {
            published: false,
            last_publish_monotonic_ms: 0,
            freshness_ms,
        }
    }

    pub const fn published_at(last_publish_monotonic_ms: u64, freshness_ms: u32) -> Self {
        Self {
            published: true,
            last_publish_monotonic_ms,
            freshness_ms,
        }
    }
}

pub const fn elapsed_ms(now_monotonic_ms: u64, then_monotonic_ms: u64) -> Option<u64> {
    now_monotonic_ms.checked_sub(then_monotonic_ms)
}

pub const fn is_fresh(entry: EntryMetadata, now_monotonic_ms: u64) -> bool {
    if !entry.published {
        return false;
    }
    let Some(elapsed) = elapsed_ms(now_monotonic_ms, entry.last_publish_monotonic_ms) else {
        return false;
    };
    elapsed <= entry.freshness_ms as u64
}

pub const fn classify(entry: EntryMetadata, now_monotonic_ms: u64) -> CacheReadStatus {
    if !entry.published {
        CacheReadStatus::NeverPublished
    } else if !is_fresh(entry, now_monotonic_ms) {
        CacheReadStatus::Stale
    } else {
        CacheReadStatus::Ok
    }
}

pub const fn maps_to_fresh_value(status: CacheReadStatus) -> bool {
    matches!(status, CacheReadStatus::Ok)
}

pub const fn opcua_status_for_cache_read(status: CacheReadStatus) -> u32 {
    match status {
        CacheReadStatus::Ok => opcua_status::GOOD,
        CacheReadStatus::InvalidIndex => opcua_status::BAD_INDEX_RANGE_INVALID,
        CacheReadStatus::NeverPublished | CacheReadStatus::Stale => {
            opcua_status::BAD_WAITING_FOR_INITIAL_DATA
        }
        CacheReadStatus::NotConnected => opcua_status::BAD_NOT_CONNECTED,
        CacheReadStatus::RetryExhausted => opcua_status::BAD_RESOURCE_UNAVAILABLE,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedStateCache<const ENTRIES: usize> {
    entries: [EntryMetadata; ENTRIES],
}

impl<const ENTRIES: usize> FixedStateCache<ENTRIES> {
    pub const fn new(default_freshness_ms: u32) -> Self {
        Self {
            entries: [EntryMetadata::unpublished(default_freshness_ms); ENTRIES],
        }
    }

    pub fn publish(&mut self, index: usize, now_monotonic_ms: u64, freshness_ms: u32) -> bool {
        if index >= ENTRIES {
            return false;
        }
        self.entries[index] = EntryMetadata::published_at(now_monotonic_ms, freshness_ms);
        true
    }

    pub fn read_status(&self, index: usize, now_monotonic_ms: u64) -> CacheReadStatus {
        let Some(entry) = self.entries.get(index) else {
            return CacheReadStatus::InvalidIndex;
        };
        classify(*entry, now_monotonic_ms)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ScalarValue {
    Boolean(bool),
    Int32(i32),
    UInt32(u32),
    /// Fixed-point float representation carried as milli-units so cache
    /// movement stays exact and `no_std`/no-heap friendly.
    FloatMilli(i32),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheRead {
    pub status: CacheReadStatus,
    pub value: Option<ScalarValue>,
}

impl CacheRead {
    pub const fn opcua_status(self) -> u32 {
        opcua_status_for_cache_read(self.status)
    }

    pub const fn has_fresh_value(self) -> bool {
        matches!(self.status, CacheReadStatus::Ok) && self.value.is_some()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ValueSlot {
    metadata: EntryMetadata,
    value: Option<ScalarValue>,
}

impl ValueSlot {
    const fn unpublished(freshness_ms: u32) -> Self {
        Self {
            metadata: EntryMetadata::unpublished(freshness_ms),
            value: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FixedValueCache<const ENTRIES: usize> {
    entries: [ValueSlot; ENTRIES],
}

impl<const ENTRIES: usize> FixedValueCache<ENTRIES> {
    pub const fn new(default_freshness_ms: u32) -> Self {
        Self {
            entries: [ValueSlot::unpublished(default_freshness_ms); ENTRIES],
        }
    }

    pub fn publish(
        &mut self,
        index: usize,
        value: ScalarValue,
        now_monotonic_ms: u64,
        freshness_ms: u32,
    ) -> bool {
        if index >= ENTRIES {
            return false;
        }
        self.entries[index] = ValueSlot {
            metadata: EntryMetadata::published_at(now_monotonic_ms, freshness_ms),
            value: Some(value),
        };
        true
    }

    /// Clear a previously published entry so subsequent reads are not Good.
    ///
    /// Used when a successful upstream payload omits an optional object that
    /// previously owned the tag (BH-6 honest quality).
    pub fn unpublish(&mut self, index: usize, freshness_ms: u32) -> bool {
        if index >= ENTRIES {
            return false;
        }
        self.entries[index] = ValueSlot::unpublished(freshness_ms);
        true
    }

    pub fn read(&self, index: usize, now_monotonic_ms: u64) -> CacheRead {
        let Some(entry) = self.entries.get(index) else {
            return CacheRead {
                status: CacheReadStatus::InvalidIndex,
                value: None,
            };
        };
        let status = classify(entry.metadata, now_monotonic_ms);
        CacheRead {
            status,
            value: if matches!(status, CacheReadStatus::Ok) {
                entry.value
            } else {
                None
            },
        }
    }
}

#[cfg(test)]
mod layout_tests {
    use super::{EntryMetadata, FixedValueCache, ValueSlot};

    #[test]
    fn cache_layout_sizes_are_reported() {
        println!(
            "EntryMetadata={} ValueSlot={} FixedValueCache<86>={}",
            core::mem::size_of::<EntryMetadata>(),
            core::mem::size_of::<ValueSlot>(),
            core::mem::size_of::<FixedValueCache<86>>()
        );
    }
}
