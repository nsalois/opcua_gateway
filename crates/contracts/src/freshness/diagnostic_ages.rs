//! Finite, value-preserving diagnostic publication ages. Absent from product.
use super::{EntryMetadata, FixedValueCache};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum DiagnosticAge {
    BeforeFreshness = 1,
    AtFreshness,
    AfterFreshness,
    Future,
    Epoch1,
    Epoch2,
    Epoch3,
    Epoch4,
    Epoch5,
    Epoch6,
    Epoch7,
    Epoch8,
}

impl DiagnosticAge {
    pub const ALL: [Self; 12] = [
        Self::BeforeFreshness,
        Self::AtFreshness,
        Self::AfterFreshness,
        Self::Future,
        Self::Epoch1,
        Self::Epoch2,
        Self::Epoch3,
        Self::Epoch4,
        Self::Epoch5,
        Self::Epoch6,
        Self::Epoch7,
        Self::Epoch8,
    ];

    fn publication(self, now: u64, freshness: u32) -> Option<u64> {
        let age = match self {
            Self::BeforeFreshness => u64::from(freshness.checked_sub(1)?),
            Self::AtFreshness => u64::from(freshness),
            Self::AfterFreshness => u64::from(freshness) + 1,
            Self::Future => return now.checked_add(1),
            _ => (self as u64 - 4) * (1u64 << 32),
        };
        now.checked_sub(age)
    }
}

/// Opaque original metadata. Callers cannot manufacture restoration values.
/// Must be consumed synchronously before releasing the owning runtime lock.
#[must_use]
pub struct DiagnosticAgeRestore {
    index: usize,
    original: EntryMetadata,
}

impl<const N: usize> FixedValueCache<N> {
    pub fn diagnostic_begin_age(
        &mut self,
        index: usize,
        now: u64,
        age: DiagnosticAge,
    ) -> Option<DiagnosticAgeRestore> {
        let entry = self.entries.get_mut(index)?;
        if !entry.metadata.published
            || entry.value.is_none()
            || !super::is_fresh(entry.metadata, now)
        {
            return None;
        }
        let original = entry.metadata;
        let publication = age.publication(now, original.freshness_ms)?;
        entry.metadata.last_publish_monotonic_ms = publication;
        Some(DiagnosticAgeRestore { index, original })
    }

    pub fn diagnostic_restore_age(&mut self, restore: DiagnosticAgeRestore) {
        self.entries[restore.index].metadata = restore.original;
    }
}
