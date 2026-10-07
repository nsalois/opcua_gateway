use super::RuntimeDataAccess;
use crate::{DataAccessRead, DataChangeSample, DataChangeSubscription, RuntimeNode};
use opta_gateway_contracts::{
    freshness::{DiagnosticAge, EntryMetadata},
    opcua_status,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiagnosticAgeObservation {
    pub original: EntryMetadata,
    pub baseline: DataAccessRead,
    pub injected: EntryMetadata,
    pub direct: DataAccessRead,
    pub sampled: Option<DataChangeSample>,
    pub restored: EntryMetadata,
    pub restored_read: DataAccessRead,
}

impl<const N: usize> RuntimeDataAccess<N> {
    /// One synchronous finite case on the actual owning cache. No await, value
    /// setter, generic timestamp input, or borrowed mutable cache escapes.
    /// The firmware supplies its real consuming clock while holding trust then
    /// runtime. A host trust flag alone is not target authentication evidence.
    pub fn diagnostic_age_case(
        &mut self,
        node: RuntimeNode,
        age: DiagnosticAge,
        now: u64,
    ) -> Option<DiagnosticAgeObservation> {
        if !self.writes_allowed()
            || !self.cache.last_fetch_ok()
            || self.cache.last_endpoint() != Some(node.endpoint())
            || !self.write_queue.is_empty()
            || self.next_write_sequence != 1
            || self.health.buchi_write_accepted_count != 0
        {
            return None;
        }
        let baseline = self.read_node(node, now);
        if baseline.opcua_status != opcua_status::GOOD || baseline.value.is_none() {
            return None;
        }
        let mut subscription = DataChangeSubscription::<1>::new();
        subscription.add_runtime_node(node, 1).slot?;
        let original = self.cache.diagnostic_publication(node);
        let restore = self.cache.diagnostic_begin_age(node, now, age)?;
        let injected = self.cache.diagnostic_publication(node);
        let direct = self.read_node(node, now);
        let sampled = subscription.sample_slot(0, self, now);
        // Unconditional restoration, including a missing sample. Retain that
        // failure in the observation; never leave the fault installed.
        self.cache.diagnostic_restore_age(restore);
        let restored = self.cache.diagnostic_publication(node);
        let restored_read = self.read_node(node, now);
        Some(DiagnosticAgeObservation {
            original,
            baseline,
            injected,
            direct,
            sampled,
            restored,
            restored_read,
        })
    }
}
