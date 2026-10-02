use opta_gateway_contracts::product;

use crate::{
    build_get_request, build_put_request, build_write_json, lookup_write_spec,
    parse_endpoint_http_response, write_http_status_to_opcua_status, Endpoint,
    EndpointResponseError, EndpointValues, HttpReadProgress, HttpReceiveBuffer, HttpResponse,
    HttpResponseError, WriteRequest, WriteValidationStatus,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildWriteJsonError {
    UnknownTarget,
    InvalidValue(WriteValidationStatus),
    UnsupportedScale,
    OutputTooSmall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuildHttpRequestError {
    UnsupportedMethod,
    EmptyHost,
    EmptyAuth,
    InvalidHeaderValue,
    EmptyBody,
    OutputTooSmall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BasicAuthError {
    EmptyCredential,
    NonAscii,
    OutputTooSmall,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpRequestSendError {
    EmptyRequest,
    ZeroLengthWrite,
    WriteBeyondRequest,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpRequestSendStatus {
    Pending {
        sent_len: usize,
        remaining_len: usize,
    },
    Complete {
        sent_len: usize,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpExchangePhase {
    Sending,
    Receiving,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpExchangeProgress {
    Sending(HttpRequestSendStatus),
    Receiving(HttpReadProgress),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpExchangeError {
    Send(HttpRequestSendError),
    Receive(HttpResponseError),
    NotSending,
    NotReceiving,
    RequestSliceTooShort,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuchiGetTransactionError {
    Build(BuildHttpRequestError),
    Send(HttpRequestSendError),
    Exchange(HttpExchangeError),
    Endpoint(EndpointResponseError),
    Incomplete,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuchiPutTransactionError {
    BuildBody(BuildWriteJsonError),
    BuildRequest(BuildHttpRequestError),
    Send(HttpRequestSendError),
    Exchange(HttpExchangeError),
    Endpoint(EndpointResponseError),
    Incomplete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpRequestSendCursor {
    request_len: usize,
    sent_len: usize,
}

impl HttpRequestSendCursor {
    pub const fn new(request_len: usize) -> Result<Self, HttpRequestSendError> {
        if request_len == 0 {
            return Err(HttpRequestSendError::EmptyRequest);
        }
        Ok(Self {
            request_len,
            sent_len: 0,
        })
    }

    pub const fn request_len(self) -> usize {
        self.request_len
    }

    pub const fn sent_len(self) -> usize {
        self.sent_len
    }

    pub const fn remaining_len(self) -> usize {
        self.request_len - self.sent_len
    }

    pub const fn is_complete(self) -> bool {
        self.sent_len == self.request_len
    }

    pub fn remaining_bytes<'a>(&self, request: &'a [u8]) -> Option<&'a [u8]> {
        request.get(self.sent_len..self.request_len)
    }

    pub fn advance(
        &mut self,
        written_len: usize,
    ) -> Result<HttpRequestSendStatus, HttpRequestSendError> {
        if written_len == 0 {
            return Err(HttpRequestSendError::ZeroLengthWrite);
        }
        let Some(sent_len) = self.sent_len.checked_add(written_len) else {
            return Err(HttpRequestSendError::WriteBeyondRequest);
        };
        if sent_len > self.request_len {
            return Err(HttpRequestSendError::WriteBeyondRequest);
        }
        self.sent_len = sent_len;
        if self.is_complete() {
            Ok(HttpRequestSendStatus::Complete {
                sent_len: self.sent_len,
            })
        } else {
            Ok(HttpRequestSendStatus::Pending {
                sent_len: self.sent_len,
                remaining_len: self.remaining_len(),
            })
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpExchange<const RESPONSE_CAPACITY: usize> {
    phase: HttpExchangePhase,
    send: HttpRequestSendCursor,
    receive: HttpReceiveBuffer<RESPONSE_CAPACITY>,
}

impl<const RESPONSE_CAPACITY: usize> HttpExchange<RESPONSE_CAPACITY> {
    pub const fn new(request_len: usize) -> Result<Self, HttpRequestSendError> {
        let send = match HttpRequestSendCursor::new(request_len) {
            Ok(send) => send,
            Err(error) => return Err(error),
        };
        Ok(Self {
            phase: HttpExchangePhase::Sending,
            send,
            receive: HttpReceiveBuffer::new(),
        })
    }

    pub const fn phase(&self) -> HttpExchangePhase {
        self.phase
    }

    pub const fn receive_buffer(&self) -> &HttpReceiveBuffer<RESPONSE_CAPACITY> {
        &self.receive
    }

    pub fn next_write<'a>(&self, request: &'a [u8]) -> Result<&'a [u8], HttpExchangeError> {
        if self.phase != HttpExchangePhase::Sending {
            return Err(HttpExchangeError::NotSending);
        }
        self.send
            .remaining_bytes(request)
            .ok_or(HttpExchangeError::RequestSliceTooShort)
    }

    pub fn record_write(
        &mut self,
        written_len: usize,
    ) -> Result<HttpExchangeProgress, HttpExchangeError> {
        if self.phase != HttpExchangePhase::Sending {
            return Err(HttpExchangeError::NotSending);
        }
        let status = self
            .send
            .advance(written_len)
            .map_err(HttpExchangeError::Send)?;
        if matches!(status, HttpRequestSendStatus::Complete { .. }) {
            self.phase = HttpExchangePhase::Receiving;
        }
        Ok(HttpExchangeProgress::Sending(status))
    }

    pub fn append_response(
        &mut self,
        chunk: &[u8],
    ) -> Result<HttpExchangeProgress, HttpExchangeError> {
        if self.phase != HttpExchangePhase::Receiving {
            return Err(HttpExchangeError::NotReceiving);
        }
        let progress = self
            .receive
            .append(chunk)
            .map_err(HttpExchangeError::Receive)?;
        if progress == HttpReadProgress::Complete {
            self.phase = HttpExchangePhase::Complete;
        }
        Ok(HttpExchangeProgress::Receiving(progress))
    }

    pub fn finish_extra_body_probe(&mut self) -> Result<HttpExchangeProgress, HttpExchangeError> {
        if self.phase != HttpExchangePhase::Receiving {
            return Err(HttpExchangeError::NotReceiving);
        }
        let progress = self
            .receive
            .finish_extra_body_probe()
            .map_err(HttpExchangeError::Receive)?;
        if progress == HttpReadProgress::Complete {
            self.phase = HttpExchangePhase::Complete;
        }
        Ok(HttpExchangeProgress::Receiving(progress))
    }

    pub fn response(&self) -> Result<HttpResponse<'_>, HttpExchangeError> {
        self.receive.response().map_err(HttpExchangeError::Receive)
    }
}

pub type DefaultBuchiGetTransaction = BuchiGetTransaction<
    { product::BUCHI_HTTP_REQUEST_BYTES },
    { product::BUCHI_HTTP_RESPONSE_BYTES },
>;

pub type DefaultBuchiPutTransaction = BuchiPutTransaction<
    { product::BUCHI_WRITE_JSON_BYTES },
    { product::BUCHI_HTTP_REQUEST_BYTES },
    { product::BUCHI_HTTP_RESPONSE_BYTES },
>;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuchiGetTransaction<const REQUEST_CAPACITY: usize, const RESPONSE_CAPACITY: usize> {
    endpoint: Endpoint,
    request: [u8; REQUEST_CAPACITY],
    request_len: usize,
    exchange: HttpExchange<RESPONSE_CAPACITY>,
}

impl<const REQUEST_CAPACITY: usize, const RESPONSE_CAPACITY: usize>
    BuchiGetTransaction<REQUEST_CAPACITY, RESPONSE_CAPACITY>
{
    pub fn new(
        endpoint: Endpoint,
        host: &str,
        basic_auth_token: &str,
    ) -> Result<Self, BuchiGetTransactionError> {
        let mut request = [0u8; REQUEST_CAPACITY];
        let request_len = build_get_request(endpoint, host, basic_auth_token, &mut request)
            .map_err(BuchiGetTransactionError::Build)?;
        let exchange = HttpExchange::new(request_len).map_err(BuchiGetTransactionError::Send)?;
        Ok(Self {
            endpoint,
            request,
            request_len,
            exchange,
        })
    }

    pub const fn endpoint(&self) -> Endpoint {
        self.endpoint
    }

    pub const fn request_len(&self) -> usize {
        self.request_len
    }

    pub fn request(&self) -> &[u8] {
        &self.request[..self.request_len]
    }

    pub const fn phase(&self) -> HttpExchangePhase {
        self.exchange.phase()
    }

    pub const fn exchange(&self) -> &HttpExchange<RESPONSE_CAPACITY> {
        &self.exchange
    }

    pub fn next_write(&self) -> Result<&[u8], BuchiGetTransactionError> {
        self.exchange
            .next_write(self.request())
            .map_err(BuchiGetTransactionError::Exchange)
    }

    pub fn record_write(
        &mut self,
        written_len: usize,
    ) -> Result<HttpExchangeProgress, BuchiGetTransactionError> {
        self.exchange
            .record_write(written_len)
            .map_err(BuchiGetTransactionError::Exchange)
    }

    pub fn append_response(
        &mut self,
        chunk: &[u8],
    ) -> Result<HttpExchangeProgress, BuchiGetTransactionError> {
        self.exchange
            .append_response(chunk)
            .map_err(BuchiGetTransactionError::Exchange)
    }

    pub fn finish_extra_body_probe(
        &mut self,
    ) -> Result<HttpExchangeProgress, BuchiGetTransactionError> {
        self.exchange
            .finish_extra_body_probe()
            .map_err(BuchiGetTransactionError::Exchange)
    }

    pub fn values(&self) -> Result<EndpointValues, BuchiGetTransactionError> {
        if self.phase() != HttpExchangePhase::Complete {
            return Err(BuchiGetTransactionError::Incomplete);
        }
        parse_endpoint_http_response(
            self.endpoint,
            self.exchange.receive_buffer().buffered(),
            self.exchange.receive_buffer().capacity(),
        )
        .map_err(BuchiGetTransactionError::Endpoint)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BuchiPutTransaction<
    const BODY_CAPACITY: usize,
    const REQUEST_CAPACITY: usize,
    const RESPONSE_CAPACITY: usize,
> {
    write_request: WriteRequest,
    endpoint: Endpoint,
    request: [u8; REQUEST_CAPACITY],
    request_len: usize,
    body_len: usize,
    exchange: HttpExchange<RESPONSE_CAPACITY>,
}

impl<const BODY_CAPACITY: usize, const REQUEST_CAPACITY: usize, const RESPONSE_CAPACITY: usize>
    BuchiPutTransaction<BODY_CAPACITY, REQUEST_CAPACITY, RESPONSE_CAPACITY>
{
    pub fn new(
        write_request: WriteRequest,
        host: &str,
        basic_auth_token: &str,
    ) -> Result<Self, BuchiPutTransactionError> {
        let spec = lookup_write_spec(write_request.target).ok_or(
            BuchiPutTransactionError::BuildBody(BuildWriteJsonError::UnknownTarget),
        )?;

        let mut body = [0u8; BODY_CAPACITY];
        let body_len = build_write_json(write_request, &mut body)
            .map_err(BuchiPutTransactionError::BuildBody)?;

        let endpoint = spec.endpoint.endpoint();
        let mut request = [0u8; REQUEST_CAPACITY];
        let request_len = build_put_request(
            endpoint,
            host,
            basic_auth_token,
            &body[..body_len],
            &mut request,
        )
        .map_err(BuchiPutTransactionError::BuildRequest)?;
        let exchange = HttpExchange::new(request_len).map_err(BuchiPutTransactionError::Send)?;
        Ok(Self {
            write_request,
            endpoint,
            request,
            request_len,
            body_len,
            exchange,
        })
    }

    pub const fn write_request(&self) -> WriteRequest {
        self.write_request
    }

    pub const fn endpoint(&self) -> Endpoint {
        self.endpoint
    }

    pub const fn request_len(&self) -> usize {
        self.request_len
    }

    pub const fn body_len(&self) -> usize {
        self.body_len
    }

    pub fn request(&self) -> &[u8] {
        &self.request[..self.request_len]
    }

    pub const fn phase(&self) -> HttpExchangePhase {
        self.exchange.phase()
    }

    pub const fn exchange(&self) -> &HttpExchange<RESPONSE_CAPACITY> {
        &self.exchange
    }

    pub fn next_write(&self) -> Result<&[u8], BuchiPutTransactionError> {
        self.exchange
            .next_write(self.request())
            .map_err(BuchiPutTransactionError::Exchange)
    }

    pub fn record_write(
        &mut self,
        written_len: usize,
    ) -> Result<HttpExchangeProgress, BuchiPutTransactionError> {
        self.exchange
            .record_write(written_len)
            .map_err(BuchiPutTransactionError::Exchange)
    }

    pub fn append_response(
        &mut self,
        chunk: &[u8],
    ) -> Result<HttpExchangeProgress, BuchiPutTransactionError> {
        self.exchange
            .append_response(chunk)
            .map_err(BuchiPutTransactionError::Exchange)
    }

    pub fn finish_extra_body_probe(
        &mut self,
    ) -> Result<HttpExchangeProgress, BuchiPutTransactionError> {
        self.exchange
            .finish_extra_body_probe()
            .map_err(BuchiPutTransactionError::Exchange)
    }

    pub fn response(&self) -> Result<HttpResponse<'_>, BuchiPutTransactionError> {
        if self.phase() != HttpExchangePhase::Complete {
            return Err(BuchiPutTransactionError::Incomplete);
        }
        self.exchange
            .response()
            .map_err(BuchiPutTransactionError::Exchange)
    }

    pub fn http_status(&self) -> Result<i32, BuchiPutTransactionError> {
        Ok(self.response()?.status)
    }

    pub fn completion_opcua_status(
        &self,
        transport_result: i32,
    ) -> Result<u32, BuchiPutTransactionError> {
        Ok(write_http_status_to_opcua_status(
            self.http_status()?,
            transport_result,
        ))
    }

    pub fn values(&self) -> Result<EndpointValues, BuchiPutTransactionError> {
        if self.phase() != HttpExchangePhase::Complete {
            return Err(BuchiPutTransactionError::Incomplete);
        }
        parse_endpoint_http_response(
            self.endpoint,
            self.exchange.receive_buffer().buffered(),
            self.exchange.receive_buffer().capacity(),
        )
        .map_err(BuchiPutTransactionError::Endpoint)
    }
}
