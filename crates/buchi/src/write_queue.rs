use opta_gateway_contracts::product;

use crate::WriteTarget;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum WriteValidationStatus {
    Ok,
    UnknownTarget,
    TypeMismatch,
    OutOfRange,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteRequest {
    pub target: WriteTarget,
    pub raw_value: i32,
    pub node_id: u16,
    pub sequence: u32,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WriteQueuePushResult {
    pub accepted: bool,
    pub coalesced: bool,
    pub depth: usize,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WriteQueue<const CAPACITY: usize> {
    storage: [Option<WriteRequest>; CAPACITY],
    head: usize,
    tail: usize,
    size: usize,
}

pub type DefaultWriteQueue = WriteQueue<{ product::BUCHI_WRITE_QUEUE_CAPACITY }>;

impl<const CAPACITY: usize> WriteQueue<CAPACITY> {
    pub const fn new() -> Self {
        Self {
            storage: [None; CAPACITY],
            head: 0,
            tail: 0,
            size: 0,
        }
    }

    pub fn push(&mut self, request: WriteRequest) -> WriteQueuePushResult {
        for offset in 0..self.size {
            let index = (self.tail + offset) % CAPACITY;
            if self.storage[index].is_some_and(|stored| stored.target == request.target) {
                self.storage[index] = Some(request);
                return WriteQueuePushResult {
                    accepted: true,
                    coalesced: true,
                    depth: self.size,
                };
            }
        }

        if self.is_full() {
            return WriteQueuePushResult {
                accepted: false,
                coalesced: false,
                depth: self.size,
            };
        }

        self.storage[self.head] = Some(request);
        self.head = (self.head + 1) % CAPACITY;
        self.size += 1;
        WriteQueuePushResult {
            accepted: true,
            coalesced: false,
            depth: self.size,
        }
    }

    pub fn peek(&self) -> Option<WriteRequest> {
        if self.is_empty() {
            return None;
        }
        self.storage[self.tail]
    }

    pub fn pop(&mut self) -> Option<WriteRequest> {
        if self.is_empty() {
            return None;
        }
        let request = self.storage[self.tail].take();
        self.tail = (self.tail + 1) % CAPACITY;
        self.size -= 1;
        request
    }

    pub fn clear(&mut self) {
        self.storage = [None; CAPACITY];
        self.head = 0;
        self.tail = 0;
        self.size = 0;
    }

    pub const fn is_empty(&self) -> bool {
        self.size == 0
    }

    pub const fn is_full(&self) -> bool {
        self.size == CAPACITY
    }

    pub const fn len(&self) -> usize {
        self.size
    }

    pub const fn capacity(&self) -> usize {
        CAPACITY
    }
}

impl<const CAPACITY: usize> Default for WriteQueue<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}
