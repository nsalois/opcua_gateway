use opta_buchi::{
    drive_get_transaction_transport_step, drive_put_transaction_transport_step,
    BuchiGetTransaction, BuchiGetTransactionError, BuchiGetTransportError, BuchiPutTransaction,
    BuchiPutTransportError, BuchiTransport, BuchiTransportStep, Endpoint, EndpointValues,
    HttpReadProgress, WriteTarget,
};
use opta_gateway_contracts::product;

use crate::{
    endpoint_from_values, EndpointPollFailure, EndpointPollReport, EndpointPollScheduler,
    RuntimeDataAccess, RuntimeWriteCompletion, RuntimeWriteCompletionError,
    RuntimeWriteTransactionError,
};

pub type DefaultBuchiPollRuntime = BuchiPollRuntime<{ product::BUCHI_WRITE_QUEUE_CAPACITY }>;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuchiPollRequest {
    pub endpoint: Endpoint,
    pub path: &'static str,
    pub poll_ms: u32,
}

impl BuchiPollRequest {
    pub const fn new(endpoint: Endpoint) -> Self {
        Self {
            endpoint,
            path: endpoint.path(),
            poll_ms: endpoint.poll_ms(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct BuchiPollCompletion {
    pub endpoint: Endpoint,
    pub result: Result<EndpointPollReport, EndpointPollFailure>,
    pub next_due_ms: u32,
}

pub type DefaultBuchiPollTransaction = BuchiPollTransaction<
    { product::BUCHI_HTTP_REQUEST_BYTES },
    { product::BUCHI_HTTP_RESPONSE_BYTES },
>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuchiPollTransaction<const REQUEST_CAPACITY: usize, const RESPONSE_CAPACITY: usize> {
    pub request: BuchiPollRequest,
    pub transaction: BuchiGetTransaction<REQUEST_CAPACITY, RESPONSE_CAPACITY>,
}

pub type DefaultBuchiClientTransaction = BuchiClientTransaction<
    { product::BUCHI_WRITE_JSON_BYTES },
    { product::BUCHI_HTTP_REQUEST_BYTES },
    { product::BUCHI_HTTP_RESPONSE_BYTES },
>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuchiClientTransaction<
    const BODY_CAPACITY: usize,
    const REQUEST_CAPACITY: usize,
    const RESPONSE_CAPACITY: usize,
> {
    Write(BuchiPutTransaction<BODY_CAPACITY, REQUEST_CAPACITY, RESPONSE_CAPACITY>),
    Poll(BuchiPollTransaction<REQUEST_CAPACITY, RESPONSE_CAPACITY>),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuchiClientTransactionBuildError {
    Write(RuntimeWriteTransactionError),
    Poll(BuchiGetTransactionError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuchiClientTransactionCompletion {
    Write(RuntimeWriteCompletion),
    Poll(BuchiPollCompletion),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuchiClientTransactionCompletionError {
    Write(RuntimeWriteCompletionError),
    Poll(BuchiGetTransactionError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuchiClientTransportError {
    Write(BuchiPutTransportError),
    Poll(BuchiGetTransportError),
}

impl<const BODY_CAPACITY: usize, const REQUEST_CAPACITY: usize, const RESPONSE_CAPACITY: usize>
    BuchiClientTransaction<BODY_CAPACITY, REQUEST_CAPACITY, RESPONSE_CAPACITY>
{
    pub fn kind(&self) -> BuchiClientTransactionKind {
        match self {
            Self::Write(transaction) => {
                let request = transaction.write_request();
                BuchiClientTransactionKind::Write {
                    node_id: request.node_id,
                    target: request.target,
                }
            }
            Self::Poll(poll) => BuchiClientTransactionKind::Poll {
                endpoint: poll.request.endpoint,
            },
        }
    }

    pub fn drive_transport_step(
        &mut self,
        transport: &mut impl BuchiTransport,
        read_scratch: &mut [u8],
    ) -> Result<BuchiTransportStep, BuchiClientTransportError> {
        match self {
            Self::Write(transaction) => {
                drive_put_transaction_transport_step(transaction, transport, read_scratch)
                    .map_err(BuchiClientTransportError::Write)
            }
            Self::Poll(poll) => {
                drive_get_transaction_transport_step(&mut poll.transaction, transport, read_scratch)
                    .map_err(BuchiClientTransportError::Poll)
            }
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuchiClientTransactionKind {
    Write { node_id: u16, target: WriteTarget },
    Poll { endpoint: Endpoint },
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuchiClientTaskStep {
    Idle,
    Started(BuchiClientTransactionKind),
    InFlight(BuchiTransportStep),
    Completed(BuchiClientTransactionCompletion),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuchiClientTaskError {
    Build(BuchiClientTransactionBuildError),
    Transport(BuchiClientTransportError),
    Completion(BuchiClientTransactionCompletionError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuchiClientTask<
    const WRITE_CAPACITY: usize,
    const BODY_CAPACITY: usize,
    const REQUEST_CAPACITY: usize,
    const RESPONSE_CAPACITY: usize,
> {
    runtime: BuchiPollRuntime<WRITE_CAPACITY>,
    in_flight: Option<BuchiClientTransaction<BODY_CAPACITY, REQUEST_CAPACITY, RESPONSE_CAPACITY>>,
}

impl<
        const WRITE_CAPACITY: usize,
        const BODY_CAPACITY: usize,
        const REQUEST_CAPACITY: usize,
        const RESPONSE_CAPACITY: usize,
    > BuchiClientTask<WRITE_CAPACITY, BODY_CAPACITY, REQUEST_CAPACITY, RESPONSE_CAPACITY>
{
    pub const fn new(start_ms: u32) -> Self {
        Self {
            runtime: BuchiPollRuntime::new(start_ms),
            in_flight: None,
        }
    }

    pub const fn runtime(&self) -> &BuchiPollRuntime<WRITE_CAPACITY> {
        &self.runtime
    }

    pub fn runtime_mut(&mut self) -> &mut BuchiPollRuntime<WRITE_CAPACITY> {
        &mut self.runtime
    }

    pub fn in_flight_kind(&self) -> Option<BuchiClientTransactionKind> {
        self.in_flight.as_ref().map(BuchiClientTransaction::kind)
    }

    // TODO(C11): collapse these host transport-step inputs only when the C10
    // seam is retired and its existing-mock and verified-TLS host proofs have
    // a green async replacement; see `docs/history/production-readiness-catalog-20260719.md`.
    #[allow(clippy::too_many_arguments)]
    pub fn poll_transport_step(
        &mut self,
        freshness_now_ms: u64,
        host: &str,
        read_auth_token: &str,
        write_auth_token: &str,
        write_transport_result: i32,
        transport: &mut impl BuchiTransport,
        read_scratch: &mut [u8],
    ) -> Result<BuchiClientTaskStep, BuchiClientTaskError> {
        let scheduler_now_ms = freshness_now_ms as u32;
        if self.in_flight.is_none() {
            let Some(transaction) = self
                .runtime
                .next_client_transaction(scheduler_now_ms, host, read_auth_token, write_auth_token)
                .map_err(BuchiClientTaskError::Build)?
            else {
                return Ok(BuchiClientTaskStep::Idle);
            };
            let kind = transaction.kind();
            self.in_flight = Some(transaction);
            return Ok(BuchiClientTaskStep::Started(kind));
        }

        let step = {
            let Some(transaction) = self.in_flight.as_mut() else {
                return Ok(BuchiClientTaskStep::Idle);
            };
            transaction
                .drive_transport_step(transport, read_scratch)
                .map_err(BuchiClientTaskError::Transport)?
        };

        if matches!(
            step,
            BuchiTransportStep::Complete | BuchiTransportStep::Received(HttpReadProgress::Complete)
        ) {
            let Some(transaction) = self.in_flight.take() else {
                return Ok(BuchiClientTaskStep::Idle);
            };
            let completion = self
                .runtime
                .apply_completed_client_transaction(
                    &transaction,
                    freshness_now_ms,
                    write_transport_result,
                )
                .map_err(BuchiClientTaskError::Completion)?;
            Ok(BuchiClientTaskStep::Completed(completion))
        } else {
            Ok(BuchiClientTaskStep::InFlight(step))
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuchiPollRuntime<const WRITE_CAPACITY: usize> {
    scheduler: EndpointPollScheduler,
    data_access: RuntimeDataAccess<WRITE_CAPACITY>,
}

impl<const WRITE_CAPACITY: usize> BuchiPollRuntime<WRITE_CAPACITY> {
    pub const fn new(start_ms: u32) -> Self {
        Self {
            scheduler: EndpointPollScheduler::new(start_ms),
            data_access: RuntimeDataAccess::new(),
        }
    }

    pub const fn scheduler(&self) -> &EndpointPollScheduler {
        &self.scheduler
    }

    pub const fn data_access(&self) -> &RuntimeDataAccess<WRITE_CAPACITY> {
        &self.data_access
    }

    pub fn data_access_mut(&mut self) -> &mut RuntimeDataAccess<WRITE_CAPACITY> {
        &mut self.data_access
    }

    pub fn next_poll(&self, now_ms: u32) -> Option<BuchiPollRequest> {
        self.scheduler
            .next_due_endpoint(now_ms)
            .map(BuchiPollRequest::new)
    }

    pub fn next_poll_transaction<const REQUEST_CAPACITY: usize, const RESPONSE_CAPACITY: usize>(
        &self,
        now_ms: u32,
        host: &str,
        basic_auth_token: &str,
    ) -> Result<
        Option<BuchiPollTransaction<REQUEST_CAPACITY, RESPONSE_CAPACITY>>,
        BuchiGetTransactionError,
    > {
        let Some(request) = self.next_poll(now_ms) else {
            return Ok(None);
        };
        let transaction = BuchiGetTransaction::new(request.endpoint, host, basic_auth_token)?;
        Ok(Some(BuchiPollTransaction {
            request,
            transaction,
        }))
    }

    pub fn next_client_transaction<
        const BODY_CAPACITY: usize,
        const REQUEST_CAPACITY: usize,
        const RESPONSE_CAPACITY: usize,
    >(
        &mut self,
        now_ms: u32,
        host: &str,
        read_auth_token: &str,
        write_auth_token: &str,
    ) -> Result<
        Option<BuchiClientTransaction<BODY_CAPACITY, REQUEST_CAPACITY, RESPONSE_CAPACITY>>,
        BuchiClientTransactionBuildError,
    > {
        if self.data_access.write_queue_depth() > 0 {
            let transaction = self
                .data_access
                .pop_next_write_transaction::<BODY_CAPACITY, REQUEST_CAPACITY, RESPONSE_CAPACITY>(
                    host,
                    write_auth_token,
                )
                .map_err(BuchiClientTransactionBuildError::Write)?;
            return Ok(Some(BuchiClientTransaction::Write(transaction)));
        }

        self.next_poll_transaction::<REQUEST_CAPACITY, RESPONSE_CAPACITY>(
            now_ms,
            host,
            read_auth_token,
        )
        .map(|poll| poll.map(BuchiClientTransaction::Poll))
        .map_err(BuchiClientTransactionBuildError::Poll)
    }

    pub fn apply_poll_http_response(
        &mut self,
        endpoint: Endpoint,
        response: &[u8],
        response_limit: usize,
        freshness_now_ms: u64,
    ) -> BuchiPollCompletion {
        let result = self.data_access.apply_http_response(
            endpoint,
            response,
            response_limit,
            freshness_now_ms,
        );
        let scheduler_now_ms = freshness_now_ms as u32;
        self.scheduler.mark_polled(endpoint, scheduler_now_ms);
        BuchiPollCompletion {
            endpoint,
            result,
            next_due_ms: self.scheduler.next_due_ms(endpoint),
        }
    }

    pub fn apply_completed_poll_transaction<
        const REQUEST_CAPACITY: usize,
        const RESPONSE_CAPACITY: usize,
    >(
        &mut self,
        poll: &BuchiPollTransaction<REQUEST_CAPACITY, RESPONSE_CAPACITY>,
        freshness_now_ms: u64,
    ) -> Result<BuchiPollCompletion, BuchiGetTransactionError> {
        let endpoint = poll.request.endpoint;
        let result = match poll.transaction.values() {
            Ok(values) => Ok(self
                .data_access
                .apply_endpoint_values_report(values, freshness_now_ms)),
            Err(BuchiGetTransactionError::Endpoint(error)) => {
                Err(self.data_access.record_endpoint_failure(endpoint, error))
            }
            Err(error) => return Err(error),
        };
        let scheduler_now_ms = freshness_now_ms as u32;
        self.scheduler.mark_polled(endpoint, scheduler_now_ms);
        Ok(BuchiPollCompletion {
            endpoint,
            result,
            next_due_ms: self.scheduler.next_due_ms(endpoint),
        })
    }

    pub fn apply_completed_client_transaction<
        const BODY_CAPACITY: usize,
        const REQUEST_CAPACITY: usize,
        const RESPONSE_CAPACITY: usize,
    >(
        &mut self,
        transaction: &BuchiClientTransaction<BODY_CAPACITY, REQUEST_CAPACITY, RESPONSE_CAPACITY>,
        freshness_now_ms: u64,
        write_transport_result: i32,
    ) -> Result<BuchiClientTransactionCompletion, BuchiClientTransactionCompletionError> {
        match transaction {
            BuchiClientTransaction::Write(transaction) => self
                .data_access
                .record_write_transaction_completion(transaction, write_transport_result)
                .map(BuchiClientTransactionCompletion::Write)
                .map_err(BuchiClientTransactionCompletionError::Write),
            BuchiClientTransaction::Poll(poll) => self
                .apply_completed_poll_transaction(poll, freshness_now_ms)
                .map(BuchiClientTransactionCompletion::Poll)
                .map_err(BuchiClientTransactionCompletionError::Poll),
        }
    }

    pub fn apply_poll_values(
        &mut self,
        values: EndpointValues,
        freshness_now_ms: u64,
    ) -> BuchiPollCompletion {
        let endpoint = endpoint_from_values(&values);
        let result = Ok(self
            .data_access
            .apply_endpoint_values_report(values, freshness_now_ms));
        let scheduler_now_ms = freshness_now_ms as u32;
        self.scheduler.mark_polled(endpoint, scheduler_now_ms);
        BuchiPollCompletion {
            endpoint,
            result,
            next_due_ms: self.scheduler.next_due_ms(endpoint),
        }
    }
}

impl<const WRITE_CAPACITY: usize> Default for BuchiPollRuntime<WRITE_CAPACITY> {
    fn default() -> Self {
        Self::new(0)
    }
}
