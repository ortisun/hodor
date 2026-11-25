//! Request objects: an authorization request sent as a JSON Web Token in
//! `request` (OpenID Connect Core, section 6, and RFC 9101), checked with
//! the client's keys and read as the parameters of the request.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Request objects",
//! and Decision 0045.

use crate::domain::authorization::{AuthorizationParameters, Given};
use crate::domain::client::{Client, RequestObjectAlgorithm};
use crate::domain::token::{CLOCK_ALLOWANCE, KeyChoice, client_key_for, decode_json};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::{SignatureAlgorithm, SignatureVerifier, Timestamp};
use serde_json::{Map, Value};
use std::collections::BTreeSet;

/// The largest request object read: 16 kibibytes.
pub const MAX_REQUEST_OBJECT_BYTES: usize = 16 * 1024;

/// The claims that are the object's own, not parameters of the request.
const OWN_CLAIMS: [&str; 6] = ["iss", "aud", "exp", "nbf", "iat", "jti"];

/// What a request object is checked against: the tenant it was sent to,
/// the time, and the signature checking of the kernel.
#[derive(Clone, Copy)]
pub struct RequestObjectCheck<'a> {
    /// The tenant's issuer, which `aud` must hold when it is given.
    pub issuer: &'a str,
    /// The time now.
    pub now: Timestamp,
    /// Checks a signed object's signature.
    pub verifier: &'a dyn SignatureVerifier,
}

impl std::fmt::Debug for RequestObjectCheck<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RequestObjectCheck")
            .field("issuer", &self.issuer)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

/// Why a request with a request object is refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestObjectRefusal {
    /// The object itself fails a check: `invalid_request_object`.
    Invalid(&'static str),
    /// The parameters outside it say something else, or are given in a way
    /// the request cannot be read with: `invalid_request`.
    Contradicted(&'static str),
}

impl RequestObjectRefusal {
    /// The `error` of the answer.
    #[must_use]
    pub const fn error(self) -> &'static str {
        match self {
            Self::Invalid(_) => "invalid_request_object",
            Self::Contradicted(_) => "invalid_request",
        }
    }

    /// The `error_description` of the answer.
    #[must_use]
    pub const fn description(self) -> &'static str {
        match self {
            Self::Invalid(reason) | Self::Contradicted(reason) => reason,
        }
    }
}

/// The claims of an object, read without checking anything: only to know
/// which client it names when `client_id` is not given outside it, and
/// where an error may go. Nothing read here is trusted.
#[must_use]
pub(crate) fn unchecked_claims(object: &str) -> Option<Map<String, Value>> {
    if object.len() > MAX_REQUEST_OBJECT_BYTES {
        return None;
    }
    let mut parts = object.split('.');
    let _header = parts.next()?;
    decode_json(parts.next()?)
}

const fn key_refusal(choice: KeyChoice) -> RequestObjectRefusal {
    RequestObjectRefusal::Invalid(match choice {
        KeyChoice::KidNotText => "the request object's kid is not text",
        KeyChoice::NoneFits => "no key of the client fits the request object",
        KeyChoice::Ambiguous => {
            "the request object does not say which of the client's keys signed it"
        }
    })
}

/// Checks the signature, or its absence, against what the client accepts.
/// Answers whether the object was signed.
fn check_signature(
    header_part: &str,
    claims_part: &str,
    signature_part: &str,
    client: &Client,
    verifier: &dyn SignatureVerifier,
) -> Result<bool, RequestObjectRefusal> {
    let invalid = RequestObjectRefusal::Invalid;
    let header =
        decode_json(header_part).ok_or(invalid("the request object's header is malformed"))?;
    let named = header
        .get("alg")
        .and_then(Value::as_str)
        .ok_or(invalid("the request object names no algorithm"))?;
    let chosen = client.snapshot().settings.request_object_algorithm;
    if named == "none" {
        if chosen != Some(RequestObjectAlgorithm::None) {
            return Err(invalid("this client's request objects must be signed"));
        }
        if !signature_part.is_empty() {
            return Err(invalid("an unsigned request object carries a signature"));
        }
        return Ok(false);
    }
    let algorithm = SignatureAlgorithm::from_name(named).ok_or(invalid(
        "the request object names an algorithm that is not accepted",
    ))?;
    if chosen.is_some_and(|chosen| chosen.signature() != Some(algorithm)) {
        return Err(invalid(
            "the request object is not signed with the client's algorithm",
        ));
    }
    let signature = URL_SAFE_NO_PAD
        .decode(signature_part)
        .map_err(|_| invalid("the request object's signature is malformed"))?;
    let key = client_key_for(client, &header, algorithm).map_err(key_refusal)?;
    let signed = format!("{header_part}.{claims_part}");
    if !verifier.verify(algorithm, &key, signed.as_bytes(), &signature) {
        return Err(invalid("the request object's signature does not verify"));
    }
    Ok(true)
}

fn moment(
    claims: &Map<String, Value>,
    name: &str,
) -> Result<Option<Timestamp>, RequestObjectRefusal> {
    match claims.get(name) {
        None => Ok(None),
        Some(value) => value
            .as_i64()
            .and_then(|seconds| Timestamp::from_unix_timestamp(seconds).ok())
            .map(Some)
            .ok_or(RequestObjectRefusal::Invalid(
                "the request object has a malformed time",
            )),
    }
}

/// Checks what a checked object says about itself.
fn check_claims(
    claims: &Map<String, Value>,
    signed: bool,
    client: &Client,
    check: RequestObjectCheck<'_>,
) -> Result<(), RequestObjectRefusal> {
    let invalid = RequestObjectRefusal::Invalid;
    let id = client.id().to_string();
    match claims.get("iss") {
        None if signed => {
            return Err(invalid(
                "a signed request object does not name its client as iss",
            ));
        }
        None => {}
        Some(Value::String(issuer)) if *issuer == id => {}
        Some(_) => return Err(invalid("the request object is not from this client")),
    }
    match claims.get("client_id") {
        None => {}
        Some(Value::String(named)) if *named == id => {}
        Some(_) => return Err(invalid("the request object names another client")),
    }
    let for_us = match claims.get("aud") {
        None => true,
        Some(Value::String(one)) => one == check.issuer,
        Some(Value::Array(many)) => many
            .iter()
            .any(|given| given.as_str() == Some(check.issuer)),
        Some(_) => false,
    };
    if !for_us {
        return Err(invalid("the request object is not for this server"));
    }
    if moment(claims, "exp")?.is_some_and(|expires| expires + CLOCK_ALLOWANCE <= check.now) {
        return Err(invalid("the request object has expired"));
    }
    if moment(claims, "nbf")?.is_some_and(|from| from > check.now + CLOCK_ALLOWANCE) {
        return Err(invalid("the request object is not valid yet"));
    }
    Ok(())
}

/// The parameters an object's claims give: text as it is, a number or a
/// boolean as JSON writes it, an object as its JSON, a list once for each
/// element. The object's own claims are not parameters, and `client_id`
/// is the client's.
fn parameters_of(
    claims: &Map<String, Value>,
    client: &Client,
) -> Result<Vec<(String, String)>, RequestObjectRefusal> {
    let mut pairs = vec![("client_id".to_owned(), client.id().to_string())];
    for (name, value) in claims {
        if OWN_CLAIMS.contains(&name.as_str()) || name == "client_id" {
            continue;
        }
        if name == "request" || name == "request_uri" {
            return Err(RequestObjectRefusal::Invalid(
                "a request object cannot hold another request",
            ));
        }
        match value {
            Value::Null => {}
            Value::String(text) => pairs.push((name.clone(), text.clone())),
            Value::Number(_) | Value::Bool(_) | Value::Object(_) => {
                pairs.push((name.clone(), value.to_string()));
            }
            Value::Array(items) => {
                for item in items {
                    let Value::String(text) = item else {
                        return Err(RequestObjectRefusal::Invalid(
                            "a list in the request object holds something other than text",
                        ));
                    };
                    pairs.push((name.clone(), text.clone()));
                }
            }
        }
    }
    Ok(pairs)
}

fn scopes(value: &str) -> BTreeSet<&str> {
    value.split(' ').filter(|scope| !scope.is_empty()).collect()
}

/// Whether the parameters OpenID Connect asks a client to repeat outside
/// the object say what the object says.
fn check_outside(
    outside: &AuthorizationParameters,
    inside: &AuthorizationParameters,
) -> Result<(), RequestObjectRefusal> {
    let contradicted = RequestObjectRefusal::Contradicted;
    match outside.given("response_type") {
        Given::Absent => {}
        Given::Once(given) if inside.once("response_type") == Some(given) => {}
        Given::Once(_) | Given::Repeated => {
            return Err(contradicted(
                "response_type outside the request object is not the one inside",
            ));
        }
    }
    match outside.given("scope") {
        Given::Absent => {}
        Given::Once(given)
            if inside
                .once("scope")
                .is_some_and(|within| scopes(within) == scopes(given)) => {}
        Given::Once(_) | Given::Repeated => {
            return Err(contradicted(
                "scope outside the request object is not the one inside",
            ));
        }
    }
    Ok(())
}

/// Checks a request object for `client`, the client the request names in
/// this tenant, and reads it as the request: only `client_id` of the
/// parameters `outside` it counts, beside the three that must match.
///
/// # Errors
///
/// Returns the refusal: `invalid_request_object` for the object itself,
/// `invalid_request` for parameters outside that contradict it.
pub fn check_request_object(
    object: &str,
    client: &Client,
    outside: &AuthorizationParameters,
    check: RequestObjectCheck<'_>,
) -> Result<AuthorizationParameters, RequestObjectRefusal> {
    if !matches!(outside.given("request_uri"), Given::Absent) {
        return Err(RequestObjectRefusal::Contradicted(
            "request and request_uri cannot be given together",
        ));
    }
    if object.len() > MAX_REQUEST_OBJECT_BYTES {
        return Err(RequestObjectRefusal::Invalid(
            "the request object is larger than 16 kibibytes",
        ));
    }
    let parts: Vec<&str> = object.split('.').collect();
    let [header_part, claims_part, signature_part] = parts.as_slice() else {
        return Err(RequestObjectRefusal::Invalid(
            "the request object is not three parts",
        ));
    };
    let signed = check_signature(
        header_part,
        claims_part,
        signature_part,
        client,
        check.verifier,
    )?;
    // Only now is anything the object says used.
    let claims = decode_json(claims_part).ok_or(RequestObjectRefusal::Invalid(
        "the request object's claims are malformed",
    ))?;
    check_claims(&claims, signed, client, check)?;
    let inside = AuthorizationParameters::from_pairs(parameters_of(&claims, client)?);
    check_outside(outside, &inside)?;
    Ok(inside)
}

#[cfg(test)]
mod tests;
