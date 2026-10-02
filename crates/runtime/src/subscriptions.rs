use opta_gateway_contracts::freshness::{CacheReadStatus, ScalarValue};
use opta_gateway_contracts::{opcua_status, product};

use crate::{
    lookup_default_namespace_node, lookup_default_namespace_runtime_node,
    runtime_node_contract_by_index, NamespaceTarget, RuntimeDataAccess, RuntimeNode,
};

pub type DefaultDataChangeSubscription = DataChangeSubscription<{ product::MAX_MONITORED_ITEMS }>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MonitoredItemAddStatus {
    Ok,
    InvalidNodeIndex,
    InvalidNamespaceNodeId,
    CapacityReached,
}

pub const fn opcua_status_for_monitored_item_add(status: MonitoredItemAddStatus) -> u32 {
    match status {
        MonitoredItemAddStatus::Ok => opcua_status::GOOD,
        MonitoredItemAddStatus::InvalidNodeIndex
        | MonitoredItemAddStatus::InvalidNamespaceNodeId => opcua_status::BAD_INDEX_RANGE_INVALID,
        MonitoredItemAddStatus::CapacityReached => opcua_status::BAD_TOO_MANY_MONITORED_ITEMS,
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitoredItemAddResult {
    pub status: MonitoredItemAddStatus,
    pub opcua_status: u32,
    pub slot: Option<usize>,
    pub depth: usize,
}

impl MonitoredItemAddResult {
    const fn rejected(status: MonitoredItemAddStatus, depth: usize) -> Self {
        Self {
            status,
            opcua_status: opcua_status_for_monitored_item_add(status),
            slot: None,
            depth,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MonitoredItem {
    pub node_id: u16,
    pub client_handle: u32,
    last_sample_monotonic_ms: u32,
    sampled_once: bool,
    last_cache_status: Option<CacheReadStatus>,
    last_opcua_status: Option<u32>,
    last_value: Option<ScalarValue>,
}

impl MonitoredItem {
    pub const fn new(node_id: u16, client_handle: u32) -> Self {
        Self {
            node_id,
            client_handle,
            last_sample_monotonic_ms: 0,
            sampled_once: false,
            last_cache_status: None,
            last_opcua_status: None,
            last_value: None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataChangeSample {
    pub client_handle: u32,
    pub node_id: u16,
    pub target: Option<NamespaceTarget>,
    pub node: Option<RuntimeNode>,
    pub cache_status: Option<CacheReadStatus>,
    pub opcua_status: u32,
    pub value: Option<ScalarValue>,
    pub changed: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DataChangeSubscription<const CAPACITY: usize> {
    items: [Option<MonitoredItem>; CAPACITY],
    len: usize,
    sampling_interval_ms: u32,
}

impl<const CAPACITY: usize> DataChangeSubscription<CAPACITY> {
    pub const fn new() -> Self {
        Self {
            items: [None; CAPACITY],
            len: 0,
            sampling_interval_ms: product::DATA_CHANGE_INTERVAL_MS,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn capacity(&self) -> usize {
        CAPACITY
    }

    pub const fn sampling_interval_ms(&self) -> u32 {
        self.sampling_interval_ms
    }

    pub fn clear(&mut self) {
        self.items = [None; CAPACITY];
        self.len = 0;
    }

    pub fn add_runtime_node(
        &mut self,
        node: RuntimeNode,
        client_handle: u32,
    ) -> MonitoredItemAddResult {
        let Some(namespace_node) = lookup_default_namespace_runtime_node(node) else {
            return MonitoredItemAddResult::rejected(
                MonitoredItemAddStatus::InvalidNodeIndex,
                self.len,
            );
        };
        self.add_namespace_node_id(namespace_node.node_id, client_handle)
    }

    pub fn add_node_index(
        &mut self,
        node_index: usize,
        client_handle: u32,
    ) -> MonitoredItemAddResult {
        let Some(contract) = runtime_node_contract_by_index(node_index) else {
            return MonitoredItemAddResult::rejected(
                MonitoredItemAddStatus::InvalidNodeIndex,
                self.len,
            );
        };
        self.add_runtime_node(contract.node, client_handle)
    }

    pub fn add_namespace_node_id(
        &mut self,
        node_id: u16,
        client_handle: u32,
    ) -> MonitoredItemAddResult {
        if lookup_default_namespace_node(node_id).is_none() {
            return MonitoredItemAddResult::rejected(
                MonitoredItemAddStatus::InvalidNamespaceNodeId,
                self.len,
            );
        }
        if self.len == CAPACITY {
            return MonitoredItemAddResult::rejected(
                MonitoredItemAddStatus::CapacityReached,
                self.len,
            );
        }
        let Some(slot) = self.items.iter().position(Option::is_none) else {
            return MonitoredItemAddResult::rejected(
                MonitoredItemAddStatus::CapacityReached,
                self.len,
            );
        };
        self.items[slot] = Some(MonitoredItem::new(node_id, client_handle));
        self.len += 1;
        MonitoredItemAddResult {
            status: MonitoredItemAddStatus::Ok,
            opcua_status: opcua_status::GOOD,
            slot: Some(slot),
            depth: self.len,
        }
    }

    pub fn remove_client_handle(&mut self, client_handle: u32) -> bool {
        for item in &mut self.items {
            if item.is_some_and(|item| item.client_handle == client_handle) {
                *item = None;
                self.len -= 1;
                return true;
            }
        }
        false
    }

    pub fn remove_slot(&mut self, slot: usize) -> bool {
        let Some(item) = self.items.get_mut(slot) else {
            return false;
        };
        if item.is_none() {
            return false;
        }
        *item = None;
        self.len -= 1;
        true
    }

    pub fn due_changed_count<const WRITE_CAPACITY: usize>(
        &self,
        data_access: &RuntimeDataAccess<WRITE_CAPACITY>,
        freshness_now_ms: u64,
    ) -> usize {
        // Subscription scheduling stays on the deliberate short-horizon u32
        // compare used by OPC UA; only cache freshness consumes the full u64.
        let scheduler_now_ms = freshness_now_ms as u32;
        let mut changed_count = 0usize;
        for item in self.items.iter().flatten() {
            if item.sampled_once
                && scheduler_now_ms.wrapping_sub(item.last_sample_monotonic_ms)
                    < self.sampling_interval_ms
            {
                continue;
            }
            let read = data_access.read_namespace_node_id(item.node_id, freshness_now_ms);
            if item.last_cache_status != read.cache_status
                || item.last_opcua_status != Some(read.opcua_status)
                || item.last_value != read.value
            {
                changed_count += 1;
            }
        }
        changed_count
    }

    pub fn sample_slot<const WRITE_CAPACITY: usize>(
        &mut self,
        slot: usize,
        data_access: &RuntimeDataAccess<WRITE_CAPACITY>,
        freshness_now_ms: u64,
    ) -> Option<DataChangeSample> {
        // Subscription scheduling stays on the deliberate short-horizon u32
        // compare used by OPC UA; only cache freshness consumes the full u64.
        let scheduler_now_ms = freshness_now_ms as u32;
        let item = self.items.get_mut(slot)?.as_mut()?;
        if item.sampled_once
            && scheduler_now_ms.wrapping_sub(item.last_sample_monotonic_ms)
                < self.sampling_interval_ms
        {
            return None;
        }
        item.last_sample_monotonic_ms = scheduler_now_ms;
        item.sampled_once = true;
        let read = data_access.read_namespace_node_id(item.node_id, freshness_now_ms);
        let changed = item.last_cache_status != read.cache_status
            || item.last_opcua_status != Some(read.opcua_status)
            || item.last_value != read.value;
        item.last_cache_status = read.cache_status;
        item.last_opcua_status = Some(read.opcua_status);
        item.last_value = read.value;
        let node = match read.target {
            Some(NamespaceTarget::Runtime(node)) => Some(node),
            Some(NamespaceTarget::Health(_)) | None => None,
        };
        Some(DataChangeSample {
            client_handle: item.client_handle,
            node_id: item.node_id,
            target: read.target,
            node,
            cache_status: read.cache_status,
            opcua_status: read.opcua_status,
            value: read.value,
            changed,
        })
    }
}

impl<const CAPACITY: usize> Default for DataChangeSubscription<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}
