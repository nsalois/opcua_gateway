// Copyright 2026 Nicholas Salois.
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file in the repository root for the full license.

use crate::{
    consume_one_or_more_digits, eq_ignore_ascii_case, find_crlf, find_header_body_split,
    is_http_whitespace, parse_info_json, parse_process_json, parse_received_http_headers,
    parse_settings_json, trim_http_whitespace, Endpoint, HeaderLines, InfoValues, ProcessValues,
    SettingsValues,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ParseError {
    Empty,
    Malformed,
    NoSupportedFields,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointValues {
    Process(ProcessValues),
    Settings(SettingsValues),
    Info(InfoValues),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EndpointResponseError {
    Http(HttpResponseError),
    UnexpectedStatus(i32),
    Body(ParseError),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpHeaderLookup<'a> {
    Missing,
    Found(&'a [u8]),
    Duplicate,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpBodySizeResult {
    Invalid,
    Truncated,
    Extra,
    Exact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpReadProgress {
    ReadMore,
    ProbeForExtraBytes,
    Complete,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct HttpResponse<'a> {
    pub status: i32,
    pub body: &'a [u8],
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HttpResponseError {
    HeaderTerminatorMissing,
    StatusLineMissing,
    InvalidStatusLine,
    DuplicateTransferEncoding,
    UnsupportedTransferEncoding,
    DuplicateContentEncoding,
    UnsupportedContentEncoding,
    MissingContentLength,
    DuplicateContentLength,
    InvalidContentLength,
    MissingContentType,
    DuplicateContentType,
    UnexpectedContentType,
    ResponseTooLarge,
    BodySize(HttpBodySizeResult),
    ExtraBodyProbeRequired,
}

pub fn find_unique_http_header_value<'a>(headers: &'a [u8], name: &[u8]) -> HttpHeaderLookup<'a> {
    if name.is_empty() {
        return HttpHeaderLookup::Missing;
    }

    let mut found: Option<&'a [u8]> = None;
    for line in HeaderLines::new(headers) {
        if line.is_empty() {
            break;
        }
        if line.len() <= name.len()
            || line.get(name.len()) != Some(&b':')
            || !eq_ignore_ascii_case(&line[..name.len()], name)
        {
            continue;
        }
        if found.is_some() {
            return HttpHeaderLookup::Duplicate;
        }
        found = Some(trim_http_whitespace(&line[name.len() + 1..]));
    }

    found.map_or(HttpHeaderLookup::Missing, HttpHeaderLookup::Found)
}

pub fn parse_content_length_value(value: &[u8]) -> Option<usize> {
    let value = trim_http_whitespace(value);
    if value.is_empty() {
        return None;
    }
    let mut parsed = 0usize;
    for byte in value {
        if !byte.is_ascii_digit() {
            return None;
        }
        let digit = (byte - b'0') as usize;
        parsed = parsed.checked_mul(10)?.checked_add(digit)?;
    }
    Some(parsed)
}

pub fn http_header_value_is_json_content_type(value: &[u8]) -> bool {
    const JSON_MEDIA_TYPE: &[u8] = b"application/json";
    let value = trim_http_whitespace(value);
    if value.len() < JSON_MEDIA_TYPE.len()
        || !eq_ignore_ascii_case(&value[..JSON_MEDIA_TYPE.len()], JSON_MEDIA_TYPE)
    {
        return false;
    }
    let mut cursor = JSON_MEDIA_TYPE.len();
    while value
        .get(cursor)
        .is_some_and(|byte| is_http_whitespace(*byte))
    {
        cursor += 1;
    }
    cursor == value.len() || value.get(cursor) == Some(&b';')
}

pub fn parse_http_status_line(line: &[u8]) -> Option<i32> {
    let mut cursor = 0usize;
    let prefix = b"HTTP/";
    if line.get(..prefix.len()) != Some(prefix) {
        return None;
    }
    cursor += prefix.len();

    cursor = consume_one_or_more_digits(line, cursor)?;
    if line.get(cursor) != Some(&b'.') {
        return None;
    }
    cursor += 1;
    cursor = consume_one_or_more_digits(line, cursor)?;
    if !line
        .get(cursor)
        .is_some_and(|byte| is_http_whitespace(*byte))
    {
        return None;
    }
    while line
        .get(cursor)
        .is_some_and(|byte| is_http_whitespace(*byte))
    {
        cursor += 1;
    }

    let status_digits = line.get(cursor..cursor + 3)?;
    if !status_digits.iter().all(u8::is_ascii_digit) {
        return None;
    }
    let status = ((status_digits[0] - b'0') as i32 * 100)
        + ((status_digits[1] - b'0') as i32 * 10)
        + (status_digits[2] - b'0') as i32;
    if !(100..=599).contains(&status) {
        return None;
    }
    cursor += 3;
    if cursor < line.len() && !is_http_whitespace(line[cursor]) {
        return None;
    }
    Some(status)
}

pub fn compute_http_expected_total_bytes(
    body_offset: usize,
    content_length: usize,
    response_limit: usize,
) -> Option<usize> {
    if body_offset > response_limit || content_length > response_limit - body_offset {
        return None;
    }
    body_offset.checked_add(content_length)
}

pub fn check_http_body_size(
    response_size: usize,
    body_offset: usize,
    content_length: usize,
) -> HttpBodySizeResult {
    let Some(expected_total) = body_offset.checked_add(content_length) else {
        return HttpBodySizeResult::Invalid;
    };
    if response_size < expected_total {
        HttpBodySizeResult::Truncated
    } else if response_size > expected_total {
        HttpBodySizeResult::Extra
    } else {
        HttpBodySizeResult::Exact
    }
}

pub const fn classify_http_read_progress(
    headers_parsed: bool,
    response_size: usize,
    expected_total_bytes: usize,
    extra_body_probe_attempted: bool,
) -> HttpReadProgress {
    if !headers_parsed || response_size < expected_total_bytes {
        HttpReadProgress::ReadMore
    } else if response_size > expected_total_bytes || extra_body_probe_attempted {
        HttpReadProgress::Complete
    } else {
        HttpReadProgress::ProbeForExtraBytes
    }
}

pub fn parse_http_response<'a>(
    response: &'a [u8],
    response_limit: usize,
) -> Result<HttpResponse<'a>, HttpResponseError> {
    let (header_end, body_offset) =
        find_header_body_split(response).ok_or(HttpResponseError::HeaderTerminatorMissing)?;
    let header_block = &response[..header_end];
    let status_line_end = find_crlf(header_block).ok_or(HttpResponseError::StatusLineMissing)?;
    let status_line = &header_block[..status_line_end];
    let headers = &header_block[status_line_end + 2..];
    let status = parse_http_status_line(status_line).ok_or(HttpResponseError::InvalidStatusLine)?;

    let content_length = match find_unique_http_header_value(headers, b"Content-Length") {
        HttpHeaderLookup::Found(value) => {
            parse_content_length_value(value).ok_or(HttpResponseError::InvalidContentLength)?
        }
        HttpHeaderLookup::Missing => return Err(HttpResponseError::MissingContentLength),
        HttpHeaderLookup::Duplicate => return Err(HttpResponseError::DuplicateContentLength),
    };
    if status == 200 {
        match find_unique_http_header_value(headers, b"Content-Type") {
            HttpHeaderLookup::Found(value) => {
                if !http_header_value_is_json_content_type(value) {
                    return Err(HttpResponseError::UnexpectedContentType);
                }
            }
            HttpHeaderLookup::Missing => return Err(HttpResponseError::MissingContentType),
            HttpHeaderLookup::Duplicate => return Err(HttpResponseError::DuplicateContentType),
        }
    }

    let expected_total =
        compute_http_expected_total_bytes(body_offset, content_length, response_limit)
            .ok_or(HttpResponseError::ResponseTooLarge)?;
    let body_size = check_http_body_size(response.len(), body_offset, content_length);
    if body_size != HttpBodySizeResult::Exact {
        return Err(HttpResponseError::BodySize(body_size));
    }
    Ok(HttpResponse {
        status,
        body: &response[body_offset..expected_total],
    })
}

pub fn parse_endpoint_http_response(
    endpoint: Endpoint,
    response: &[u8],
    response_limit: usize,
) -> Result<EndpointValues, EndpointResponseError> {
    let response =
        parse_http_response(response, response_limit).map_err(EndpointResponseError::Http)?;
    if response.status != 200 {
        return Err(EndpointResponseError::UnexpectedStatus(response.status));
    }
    match endpoint {
        Endpoint::Process => parse_process_json(response.body)
            .map(EndpointValues::Process)
            .map_err(EndpointResponseError::Body),
        Endpoint::Settings => parse_settings_json(response.body)
            .map(EndpointValues::Settings)
            .map_err(EndpointResponseError::Body),
        Endpoint::Info => parse_info_json(response.body)
            .map(EndpointValues::Info)
            .map_err(EndpointResponseError::Body),
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct HttpReceiveBuffer<const CAPACITY: usize> {
    bytes: [u8; CAPACITY],
    used: usize,
    headers_parsed: bool,
    expected_total_bytes: usize,
    body_offset: usize,
    status: i32,
    extra_body_probe_attempted: bool,
}

impl<const CAPACITY: usize> HttpReceiveBuffer<CAPACITY> {
    pub const fn new() -> Self {
        Self {
            bytes: [0; CAPACITY],
            used: 0,
            headers_parsed: false,
            expected_total_bytes: 0,
            body_offset: 0,
            status: 0,
            extra_body_probe_attempted: false,
        }
    }

    pub fn clear(&mut self) {
        *self = Self::new();
    }

    pub fn append(&mut self, chunk: &[u8]) -> Result<HttpReadProgress, HttpResponseError> {
        if chunk.len() > CAPACITY.saturating_sub(self.used) {
            return Err(HttpResponseError::ResponseTooLarge);
        }
        let end = self.used + chunk.len();
        self.bytes[self.used..end].copy_from_slice(chunk);
        self.used = end;

        if !self.headers_parsed {
            if let Some((header_end, body_offset)) = find_header_body_split(self.buffered()) {
                let header_block = &self.buffered()[..header_end];
                let parsed = parse_received_http_headers(header_block, body_offset, CAPACITY)?;
                self.headers_parsed = true;
                self.expected_total_bytes = parsed.expected_total_bytes;
                self.body_offset = body_offset;
                self.status = parsed.status;
            }
        }

        self.progress()
    }

    pub fn finish_extra_body_probe(&mut self) -> Result<HttpReadProgress, HttpResponseError> {
        if self.progress()? != HttpReadProgress::ProbeForExtraBytes {
            return self.progress();
        }
        self.extra_body_probe_attempted = true;
        self.progress()
    }

    pub fn finish_persistent_response(&mut self) -> Result<HttpReadProgress, HttpResponseError> {
        match self.persistent_progress()? {
            HttpReadProgress::Complete => {
                self.extra_body_probe_attempted = true;
                Ok(HttpReadProgress::Complete)
            }
            progress => Ok(progress),
        }
    }

    pub fn response(&self) -> Result<HttpResponse<'_>, HttpResponseError> {
        match self.progress()? {
            HttpReadProgress::ReadMore => {
                if self.headers_parsed {
                    Err(HttpResponseError::BodySize(HttpBodySizeResult::Truncated))
                } else {
                    Err(HttpResponseError::HeaderTerminatorMissing)
                }
            }
            HttpReadProgress::ProbeForExtraBytes => Err(HttpResponseError::ExtraBodyProbeRequired),
            HttpReadProgress::Complete => Ok(HttpResponse {
                status: self.status,
                body: &self.bytes[self.body_offset..self.expected_total_bytes],
            }),
        }
    }

    pub const fn len(&self) -> usize {
        self.used
    }

    pub const fn is_empty(&self) -> bool {
        self.used == 0
    }

    pub const fn capacity(&self) -> usize {
        CAPACITY
    }

    pub const fn headers_parsed(&self) -> bool {
        self.headers_parsed
    }

    pub const fn status(&self) -> Option<i32> {
        if self.headers_parsed {
            Some(self.status)
        } else {
            None
        }
    }

    pub fn buffered(&self) -> &[u8] {
        &self.bytes[..self.used]
    }

    fn progress(&self) -> Result<HttpReadProgress, HttpResponseError> {
        if self.headers_parsed && self.used > self.expected_total_bytes {
            return Err(HttpResponseError::BodySize(HttpBodySizeResult::Extra));
        }
        Ok(classify_http_read_progress(
            self.headers_parsed,
            self.used,
            self.expected_total_bytes,
            self.extra_body_probe_attempted,
        ))
    }

    fn persistent_progress(&self) -> Result<HttpReadProgress, HttpResponseError> {
        if self.headers_parsed && self.used > self.expected_total_bytes {
            return Err(HttpResponseError::BodySize(HttpBodySizeResult::Extra));
        }
        if !self.headers_parsed || self.used < self.expected_total_bytes {
            Ok(HttpReadProgress::ReadMore)
        } else {
            Ok(HttpReadProgress::Complete)
        }
    }
}

impl<const CAPACITY: usize> Default for HttpReceiveBuffer<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}
