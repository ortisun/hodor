//! Outbound HTTP.
//!
//! A port: contexts never open a connection themselves. The one
//! implementation, `hodor-adapters-http`, decides whether a destination
//! may be called at all. See `docs/security/outbound-http.md`.

use crate::error::DomainError;
use std::time::Duration;

/// The methods a context may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// Read.
    Get,
    /// Submit.
    Post,
}

/// A request to an address outside Hodor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequest {
    /// The method.
    pub method: HttpMethod,
    /// The whole address, such as `https://example.com/keys`.
    pub url: String,
    /// Header names and values.
    pub headers: Vec<(String, String)>,
    /// The body, if any.
    pub body: Option<Vec<u8>>,
    /// A time limit for this request alone. The shorter of it and the
    /// client's own limit applies; running out is `http.timed_out`.
    pub time_limit: Option<Duration>,
}

impl HttpRequest {
    /// A `GET` of `url` with no headers.
    #[must_use]
    pub fn get(url: impl Into<String>) -> Self {
        Self {
            method: HttpMethod::Get,
            url: url.into(),
            headers: Vec::new(),
            body: None,
            time_limit: None,
        }
    }

    /// A `POST` of `body` to `url` with the given content type.
    #[must_use]
    pub fn post(url: impl Into<String>, content_type: &str, body: Vec<u8>) -> Self {
        Self {
            method: HttpMethod::Post,
            url: url.into(),
            headers: vec![("content-type".to_owned(), content_type.to_owned())],
            body: Some(body),
            time_limit: None,
        }
    }

    /// Gives this request a time limit of its own.
    #[must_use]
    pub const fn within(mut self, limit: Duration) -> Self {
        self.time_limit = Some(limit);
        self
    }

    /// Adds a header.
    #[must_use]
    pub fn header(mut self, name: &str, value: impl Into<String>) -> Self {
        self.headers.push((name.to_owned(), value.into()));
        self
    }
}

/// What came back. A redirect or an error status is a response like any
/// other: the caller decides what a status means.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    /// The status code.
    pub status: u16,
    /// Header names, in lowercase, and values.
    pub headers: Vec<(String, String)>,
    /// The body, within the client's size limit.
    pub body: Vec<u8>,
}

impl HttpResponse {
    /// Whether the status is in the 200 range.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        self.status >= 200 && self.status < 300
    }

    /// The first value of a header, by its name in any case.
    #[must_use]
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

/// Makes requests to addresses outside Hodor, after deciding that the
/// destination may be called.
#[async_trait::async_trait]
pub trait HttpClient: Send + Sync {
    /// Sends `request` and answers with the response, whatever its status.
    ///
    /// # Errors
    ///
    /// Returns `http.url_invalid`, `http.destination_forbidden`,
    /// `http.unreachable`, `http.timed_out` or `http.response_too_large`.
    /// No message repeats the address.
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, DomainError>;
}
