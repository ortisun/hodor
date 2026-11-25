//! Request objects at a client's address (OpenID Connect Core, section
//! 6.2, and RFC 9101, section 5.2): the addresses a client registers as
//! its `request_uris`, which `request_uri` of a request may be fetched,
//! and how what was fetched becomes the request.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Request object
//! addresses" and "Request objects at a client's address", and Decision
//! 0045.

use crate::domain::authorization::{AuthorizationParameters, AuthorizationRefusal, Given};
use crate::domain::backchannel::check_backchannel_logout_uri;
use crate::domain::client::{Client, MAX_REDIRECT_URI_LENGTH};
use crate::domain::pushed::{Reference, refused_reference};
use crate::domain::request_object::MAX_REQUEST_OBJECT_BYTES;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::{Digest, DomainError};
use std::time::Duration;

/// The most request object addresses a client registers.
pub const MAX_REQUEST_URIS: usize = 10;
/// The longest request object address, registered or named by a request.
pub const MAX_REQUEST_URI_LENGTH: usize = MAX_REDIRECT_URI_LENGTH;
/// How long a fetch of a request object may take.
pub const REQUEST_OBJECT_TIME_LIMIT: Duration = Duration::from_secs(5);
/// What a fetch of a request object asks for.
pub const REQUEST_OBJECT_ACCEPT: &str = "application/oauth-authz-req+jwt, application/jwt";

pub(crate) fn request_uri_invalid(reason: impl Into<String>) -> DomainError {
    DomainError::invalid(
        "oauth.client_request_uri_invalid",
        "a request object address is an HTTPS address of at most 2000 characters, with a host \
         and a path and without a name and password or a fragment; a client has at most 10, \
         and only with `authorization_code`",
    )
    .with_detail(reason)
}

/// Checks the form of a request object address a client registers: as a
/// back-channel logout address, `https://` or `http://`, a host and maybe
/// a port, no name and password, no fragment, printable ASCII; and a path,
/// at least `/`, so that every address that starts with it names the same
/// host and port. Whether it may be called is for the guarded client to
/// say.
///
/// # Errors
///
/// Returns `oauth.client_request_uri_invalid`.
pub fn check_request_uri(value: &str) -> Result<(), DomainError> {
    check_backchannel_logout_uri(value)
        .map_err(|error| request_uri_invalid(error.detail().unwrap_or_default().to_owned()))?;
    let rest = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
        .unwrap_or_default();
    match rest.find(['/', '?']) {
        Some(end) if rest[end..].starts_with('/') => Ok(()),
        _ => Err(request_uri_invalid(
            "the address has no path after its host",
        )),
    }
}

/// An address a request names, to be fetched: the address without its
/// fragment, and the fragment, the hash the client gave of the content.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AddressToFetch<'a> {
    /// What is fetched: the address without its fragment.
    pub url: &'a str,
    /// What follows `#`, when the address has one.
    pub fragment: Option<&'a str>,
}

/// Whether `reference` starts, before its fragment, with one of the
/// addresses `client` registered, character for character.
#[must_use]
pub fn is_registered(reference: &str, client: &Client) -> bool {
    if reference.len() > MAX_REQUEST_URI_LENGTH || !reference.bytes().all(|b| b.is_ascii_graphic())
    {
        return false;
    }
    let url = reference.split_once('#').map_or(reference, |(url, _)| url);
    client
        .snapshot()
        .settings
        .request_uris
        .iter()
        .any(|registered| url.starts_with(registered.as_str()))
}

/// Decides whether the address that `outside` names as `request_uri` may
/// be fetched for `client`, the trusted client its `client_id` names, and
/// what to fetch. Nothing is fetched before this has passed. `pushed_only`
/// says that the client or its tenant requires pushed requests.
///
/// # Errors
///
/// Returns the refusal: `invalid_request` for `request` beside it or for a
/// client that must push its requests, and `invalid_request_uri` for an
/// address that is not one the client registered, each at the redirect
/// address outside when it is the client's, otherwise on Hodor's own page.
pub fn address_to_fetch<'a>(
    outside: &'a AuthorizationParameters,
    client: &Client,
    pushed_only: bool,
) -> Result<AddressToFetch<'a>, AuthorizationRefusal> {
    let refuse = |error, description| refused_reference(outside, client, error, description);
    if !matches!(outside.given("request"), Given::Absent) {
        return Err(refuse(
            "invalid_request",
            "request and request_uri cannot be given together",
        ));
    }
    if pushed_only {
        return Err(refuse(
            "invalid_request",
            "this client must push its authorization requests",
        ));
    }
    let Reference::Address(reference) = outside.reference() else {
        return Err(refuse(
            "invalid_request_uri",
            "the request_uri is not a reference this server made",
        ));
    };
    if !is_registered(reference, client) {
        return Err(refuse(
            "invalid_request_uri",
            "the request_uri is not at an address the client registered",
        ));
    }
    Ok(match reference.split_once('#') {
        Some((url, fragment)) => AddressToFetch {
            url,
            fragment: Some(fragment),
        },
        None => AddressToFetch {
            url: reference,
            fragment: None,
        },
    })
}

/// Why an address that may be fetched gave no request object.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FetchRefusal {
    /// The guarded client refused the destination, or the address did not
    /// answer in time.
    Unreachable,
    /// It answered a status other than 200 to 299, a redirect included.
    Status,
    /// It answered more than 16 kibibytes.
    TooLarge,
    /// The fragment is not the SHA-256 of what it answered.
    HashMismatch,
    /// What it answered is not text.
    NotText,
}

impl FetchRefusal {
    /// The `error_description` of the answer, which never repeats the
    /// address or what it answered.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Unreachable => "the request_uri could not be fetched",
            Self::Status => "the request_uri did not answer a request object",
            Self::TooLarge => "the request_uri answered more than 16 kibibytes",
            Self::HashMismatch => "the content of the request_uri does not have the hash after #",
            Self::NotText => "the content of the request_uri is not a request object",
        }
    }
}

/// Reads what an address answered, with `status`, as the request object:
/// within 16 kibibytes, with the hash its fragment gives, text in UTF-8,
/// without the spaces and line ends around it.
///
/// # Errors
///
/// Returns why it is not a request object.
pub fn fetched_object(
    status: u16,
    body: &[u8],
    address: &AddressToFetch<'_>,
    digest: &dyn Digest,
) -> Result<String, FetchRefusal> {
    if !(200..300).contains(&status) {
        return Err(FetchRefusal::Status);
    }
    if body.len() > MAX_REQUEST_OBJECT_BYTES {
        return Err(FetchRefusal::TooLarge);
    }
    if let Some(fragment) = address.fragment
        && URL_SAFE_NO_PAD.encode(digest.sha256(body)) != fragment
    {
        return Err(FetchRefusal::HashMismatch);
    }
    let text = std::str::from_utf8(body).map_err(|_| FetchRefusal::NotText)?;
    let object = text.trim_matches(|c: char| c.is_ascii_whitespace());
    if object.is_empty() {
        return Err(FetchRefusal::NotText);
    }
    Ok(object.to_owned())
}

/// A refusal of an address before its content was read: `invalid_request_uri`
/// at the redirect address outside when it is the client's, otherwise on
/// Hodor's own page.
#[must_use]
pub fn refused_fetch(
    outside: &AuthorizationParameters,
    client: &Client,
    refusal: FetchRefusal,
) -> AuthorizationRefusal {
    refused_reference(
        outside,
        client,
        "invalid_request_uri",
        refusal.description(),
    )
}

/// The request with what was fetched given as `request` instead of
/// `request_uri`, to be checked as a request object given by value.
#[must_use]
pub fn with_fetched_object(
    outside: &AuthorizationParameters,
    object: String,
) -> AuthorizationParameters {
    outside.with_object(object)
}

#[cfg(test)]
mod tests;
