//! A stand-in for the guarded outbound client that serves request objects
//! at clients' addresses, and says what was asked of it.

use super::lock;
use hodor_kernel::{DomainError, ErrorKind, HttpClient, HttpRequest, HttpResponse};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// What an address answers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressAnswer {
    /// A status and a body.
    Content(u16, Vec<u8>),
    /// A redirect to another address, which is never followed.
    Redirect(String),
    /// The failure the guarded client gives, by its code, such as
    /// `http.timed_out` or `http.destination_forbidden`.
    Failure(&'static str),
}

/// Request objects at clients' addresses, in place of the guarded outbound
/// client: an address given no answer does not answer. Every request made
/// is kept, so that a test can say what was never fetched. Never use
/// outside tests.
#[derive(Debug, Clone, Default)]
pub struct RequestObjectAddresses {
    answers: Arc<Mutex<BTreeMap<String, AddressAnswer>>>,
    asked: Arc<Mutex<Vec<HttpRequest>>>,
}

impl RequestObjectAddresses {
    /// Makes `url` answer `answer`.
    pub fn answer(&self, url: &str, answer: AddressAnswer) {
        lock(&self.answers).insert(url.to_owned(), answer);
    }

    /// Makes `url` answer `body` with status 200.
    pub fn serve(&self, url: &str, body: &str) {
        self.answer(url, AddressAnswer::Content(200, body.as_bytes().to_vec()));
    }

    /// Every request made, in order.
    #[must_use]
    pub fn asked(&self) -> Vec<HttpRequest> {
        lock(&self.asked).clone()
    }

    /// The addresses fetched, in order.
    #[must_use]
    pub fn fetched(&self) -> Vec<String> {
        lock(&self.asked)
            .iter()
            .map(|request| request.url.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl HttpClient for RequestObjectAddresses {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, DomainError> {
        lock(&self.asked).push(request.clone());
        let answer = lock(&self.answers).get(&request.url).cloned();
        match answer {
            Some(AddressAnswer::Content(status, body)) => Ok(HttpResponse {
                status,
                headers: vec![(
                    "content-type".to_owned(),
                    "application/oauth-authz-req+jwt".to_owned(),
                )],
                body,
            }),
            Some(AddressAnswer::Redirect(location)) => Ok(HttpResponse {
                status: 302,
                headers: vec![("location".to_owned(), location)],
                body: Vec::new(),
            }),
            Some(AddressAnswer::Failure(code)) => Err(DomainError::new(
                ErrorKind::Unavailable,
                code,
                "the address did not answer",
            )),
            None => Err(DomainError::new(
                ErrorKind::Unavailable,
                "http.unreachable",
                "the address did not answer",
            )),
        }
    }
}
