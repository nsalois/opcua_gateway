use crate::{
    BuchiGetTransaction, BuchiGetTransactionError, BuchiPutTransaction, BuchiPutTransactionError,
    HttpExchangePhase, HttpExchangeProgress, HttpReadProgress, HttpRequestSendStatus,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuchiTransportIoError {
    WouldBlock,
    ReadFailed,
    WriteFailed,
}

pub trait BuchiTransport {
    fn write(&mut self, bytes: &[u8]) -> Result<usize, BuchiTransportIoError>;
    fn read(&mut self, out: &mut [u8]) -> Result<usize, BuchiTransportIoError>;
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BuchiTransportStep {
    Sent(HttpRequestSendStatus),
    Received(HttpReadProgress),
    Complete,
    WouldBlock,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuchiGetTransportError {
    EmptyReadBuffer,
    UnexpectedEof,
    Transport(BuchiTransportIoError),
    Transaction(BuchiGetTransactionError),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BuchiPutTransportError {
    EmptyReadBuffer,
    UnexpectedEof,
    Transport(BuchiTransportIoError),
    Transaction(BuchiPutTransactionError),
}

pub fn drive_get_transaction_transport_step<
    const REQUEST_CAPACITY: usize,
    const RESPONSE_CAPACITY: usize,
>(
    transaction: &mut BuchiGetTransaction<REQUEST_CAPACITY, RESPONSE_CAPACITY>,
    transport: &mut impl BuchiTransport,
    read_scratch: &mut [u8],
) -> Result<BuchiTransportStep, BuchiGetTransportError> {
    match transaction.phase() {
        HttpExchangePhase::Sending => match transport.write(
            transaction
                .next_write()
                .map_err(BuchiGetTransportError::Transaction)?,
        ) {
            Ok(written_len) => transaction
                .record_write(written_len)
                .map(transport_step_from_exchange_progress)
                .map_err(BuchiGetTransportError::Transaction),
            Err(BuchiTransportIoError::WouldBlock) => Ok(BuchiTransportStep::WouldBlock),
            Err(error) => Err(BuchiGetTransportError::Transport(error)),
        },
        HttpExchangePhase::Receiving => {
            drive_get_transaction_receive_step(transaction, transport, read_scratch)
        }
        HttpExchangePhase::Complete => Ok(BuchiTransportStep::Complete),
    }
}

fn drive_get_transaction_receive_step<
    const REQUEST_CAPACITY: usize,
    const RESPONSE_CAPACITY: usize,
>(
    transaction: &mut BuchiGetTransaction<REQUEST_CAPACITY, RESPONSE_CAPACITY>,
    transport: &mut impl BuchiTransport,
    read_scratch: &mut [u8],
) -> Result<BuchiTransportStep, BuchiGetTransportError> {
    if read_scratch.is_empty() {
        return Err(BuchiGetTransportError::EmptyReadBuffer);
    }
    match transport.read(read_scratch) {
        Ok(0) => {
            let progress = transaction
                .finish_extra_body_probe()
                .map_err(BuchiGetTransportError::Transaction)?;
            if matches!(
                progress,
                HttpExchangeProgress::Receiving(HttpReadProgress::Complete)
            ) {
                Ok(BuchiTransportStep::Received(HttpReadProgress::Complete))
            } else {
                Err(BuchiGetTransportError::UnexpectedEof)
            }
        }
        Ok(read_len) => transaction
            .append_response(&read_scratch[..read_len])
            .map(transport_step_from_exchange_progress)
            .map_err(BuchiGetTransportError::Transaction),
        Err(BuchiTransportIoError::WouldBlock) => Ok(BuchiTransportStep::WouldBlock),
        Err(error) => Err(BuchiGetTransportError::Transport(error)),
    }
}

pub fn drive_put_transaction_transport_step<
    const BODY_CAPACITY: usize,
    const REQUEST_CAPACITY: usize,
    const RESPONSE_CAPACITY: usize,
>(
    transaction: &mut BuchiPutTransaction<BODY_CAPACITY, REQUEST_CAPACITY, RESPONSE_CAPACITY>,
    transport: &mut impl BuchiTransport,
    read_scratch: &mut [u8],
) -> Result<BuchiTransportStep, BuchiPutTransportError> {
    match transaction.phase() {
        HttpExchangePhase::Sending => match transport.write(
            transaction
                .next_write()
                .map_err(BuchiPutTransportError::Transaction)?,
        ) {
            Ok(written_len) => transaction
                .record_write(written_len)
                .map(transport_step_from_exchange_progress)
                .map_err(BuchiPutTransportError::Transaction),
            Err(BuchiTransportIoError::WouldBlock) => Ok(BuchiTransportStep::WouldBlock),
            Err(error) => Err(BuchiPutTransportError::Transport(error)),
        },
        HttpExchangePhase::Receiving => {
            drive_put_transaction_receive_step(transaction, transport, read_scratch)
        }
        HttpExchangePhase::Complete => Ok(BuchiTransportStep::Complete),
    }
}

fn drive_put_transaction_receive_step<
    const BODY_CAPACITY: usize,
    const REQUEST_CAPACITY: usize,
    const RESPONSE_CAPACITY: usize,
>(
    transaction: &mut BuchiPutTransaction<BODY_CAPACITY, REQUEST_CAPACITY, RESPONSE_CAPACITY>,
    transport: &mut impl BuchiTransport,
    read_scratch: &mut [u8],
) -> Result<BuchiTransportStep, BuchiPutTransportError> {
    if read_scratch.is_empty() {
        return Err(BuchiPutTransportError::EmptyReadBuffer);
    }
    match transport.read(read_scratch) {
        Ok(0) => {
            let progress = transaction
                .finish_extra_body_probe()
                .map_err(BuchiPutTransportError::Transaction)?;
            if matches!(
                progress,
                HttpExchangeProgress::Receiving(HttpReadProgress::Complete)
            ) {
                Ok(BuchiTransportStep::Received(HttpReadProgress::Complete))
            } else {
                Err(BuchiPutTransportError::UnexpectedEof)
            }
        }
        Ok(read_len) => transaction
            .append_response(&read_scratch[..read_len])
            .map(transport_step_from_exchange_progress)
            .map_err(BuchiPutTransportError::Transaction),
        Err(BuchiTransportIoError::WouldBlock) => Ok(BuchiTransportStep::WouldBlock),
        Err(error) => Err(BuchiPutTransportError::Transport(error)),
    }
}

const fn transport_step_from_exchange_progress(
    progress: HttpExchangeProgress,
) -> BuchiTransportStep {
    match progress {
        HttpExchangeProgress::Sending(status) => BuchiTransportStep::Sent(status),
        HttpExchangeProgress::Receiving(progress) => BuchiTransportStep::Received(progress),
    }
}
