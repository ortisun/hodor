//! A client's keys at its address, its `jwks_uri`: the form of the
//! address, the set it answers, and when a kept set is used or fetched
//! again.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Keys at the
//! client's address", and Decision 0079.

use crate::domain::backchannel::check_backchannel_logout_uri;
use crate::domain::key::ClientKey;
use crate::domain::request_object::MAX_REQUEST_OBJECT_BYTES;
use crate::domain::token::{KeyChoice, client_key_for, decode_json};
use hodor_kernel::{DomainError, SignatureAlgorithm, Timestamp};
use serde_json::Value;
use time::Duration;

/// The longest key set address, in characters.
pub const MAX_JWKS_URI_LENGTH: usize = 2000;
/// The most bytes of a key set read: 64 kibibytes.
pub const MAX_KEY_SET_BYTES: usize = 64 * 1024;
/// How long an address may take to answer its set.
pub const KEY_SET_TIME_LIMIT: std::time::Duration = std::time::Duration::from_secs(5);
/// How long a fetched set is used: one hour, never more.
pub const KEY_SET_KEPT_FOR: Duration = Duration::hours(1);
/// The shortest time between two fetches of one client's address.
pub const KEY_SET_REFETCH_AFTER: Duration = Duration::minutes(1);
/// The most keys read of one set; the rest are left out.
pub const MAX_PUBLISHED_KEYS: usize = 20;
/// The media types a key set is asked for in.
pub const KEY_SET_ACCEPT: &str = "application/jwk-set+json, application/json";

fn jwks_uri_invalid(reason: impl Into<String>) -> DomainError {
    DomainError::invalid(
        "oauth.client_jwks_uri_invalid",
        "a key set address is an HTTPS address of at most 2000 characters, with a host and \
         without a name and password or a fragment, for a client using `private_key_jwt` only",
    )
    .with_detail(reason)
}

/// Checks the form of a key set address, as a back-channel logout address
/// is checked: `https://` or `http://`, a host and maybe a port, no name
/// and password, no fragment, printable ASCII. Whether it may be called,
/// plain HTTP included, is for the guarded client to say.
///
/// # Errors
///
/// Returns `oauth.client_jwks_uri_invalid`.
pub fn check_jwks_uri(value: &str) -> Result<(), DomainError> {
    check_backchannel_logout_uri(value)
        .map_err(|error| jwks_uri_invalid(error.detail().unwrap_or_default().to_owned()))
}

/// The refusal of an address on a client that does not use
/// `private_key_jwt`.
pub(crate) fn jwks_uri_not_allowed() -> DomainError {
    jwks_uri_invalid("only a client using `private_key_jwt` has a key set address")
}

/// The keys of a set an address answered: a JSON object with a list
/// `keys`, of which the first [`MAX_PUBLISHED_KEYS`] public signature keys
/// Hodor accepts are kept, each checked as an administrator's key is. A
/// key Hodor would refuse, one with a private part above all, is left out.
/// `None` when the answer is not a set at all.
#[must_use]
pub(crate) fn published_keys(body: &[u8], now: Timestamp) -> Option<Vec<ClientKey>> {
    if body.len() > MAX_KEY_SET_BYTES {
        return None;
    }
    let Value::Object(set) = serde_json::from_slice::<Value>(body).ok()? else {
        return None;
    };
    let Value::Array(keys) = set.get("keys")? else {
        return None;
    };
    Some(
        keys.iter()
            .filter_map(|key| ClientKey::published(key, now))
            .take(MAX_PUBLISHED_KEYS)
            .collect(),
    )
}

/// Whether the JSON Web Token `signed`, an assertion or a request object,
/// names a key that `keys` lack: its header names a `kid` none of them
/// has, or names none while none fits its algorithm. Read without
/// checking anything, only to know whether the address is worth fetching
/// again; a header Hodor would refuse anyway names no key.
#[must_use]
pub(crate) fn names_unknown_key(signed: &str, keys: &[ClientKey]) -> bool {
    if signed.len() > MAX_REQUEST_OBJECT_BYTES {
        return false;
    }
    let Some(header) = signed.split('.').next().and_then(decode_json) else {
        return false;
    };
    let Some(algorithm) = header
        .get("alg")
        .and_then(Value::as_str)
        .and_then(SignatureAlgorithm::from_name)
    else {
        return false;
    };
    matches!(
        client_key_for(keys, &header, algorithm),
        Err(KeyChoice::NoneFits)
    )
}

/// What one server keeps of one client's address: the set it last
/// answered, and when it was last fetched and last asked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct KeptSet {
    /// The address the set was fetched from.
    pub address: String,
    /// The keys it answered.
    pub keys: Vec<ClientKey>,
    /// When the fetch that answered them started, if one has.
    pub fetched_at: Option<Timestamp>,
    /// When the last fetch started, whether it answered or not.
    pub asked_at: Timestamp,
}

/// What to do for a request that needs a client's keys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum KeySetStep {
    /// Check with these keys, fetching nothing.
    Use(Vec<ClientKey>),
    /// Fetch the address first.
    Fetch,
}

impl KeptSet {
    /// Nothing fetched yet from `address`, asked for now.
    pub(crate) const fn asked(address: String, now: Timestamp) -> Self {
        Self {
            address,
            keys: Vec::new(),
            fetched_at: None,
            asked_at: now,
        }
    }

    /// Whether the set is young enough to be used at `now`.
    pub(crate) fn is_fresh(&self, now: Timestamp) -> bool {
        self.fetched_at
            .is_some_and(|at| (Duration::ZERO..KEY_SET_KEPT_FOR).contains(&(now - at)))
    }

    /// The keys that may be used at `now`: none once the set is an hour
    /// old.
    pub(crate) fn usable(&self, now: Timestamp) -> &[ClientKey] {
        if self.is_fresh(now) { &self.keys } else { &[] }
    }

    /// Whether the address was asked less than a minute before `now`.
    pub(crate) fn asked_lately(&self, now: Timestamp) -> bool {
        (Duration::ZERO..KEY_SET_REFETCH_AFTER).contains(&(now - self.asked_at))
    }
}

/// Whether a request that needs the keys at `address` uses what is kept,
/// `kept`, or fetches first. It fetches when nothing young enough is kept
/// for that address, or when `signed` names a key the kept set lacks; and
/// never when the address was asked less than a minute ago, whatever the
/// reason.
#[must_use]
pub(crate) fn next_step(
    kept: Option<&KeptSet>,
    address: &str,
    signed: Option<&str>,
    now: Timestamp,
) -> KeySetStep {
    let Some(kept) = kept.filter(|kept| kept.address == address) else {
        return KeySetStep::Fetch;
    };
    let keys = kept.usable(now);
    let wanted =
        !kept.is_fresh(now) || signed.is_some_and(|signed| names_unknown_key(signed, keys));
    if wanted && !kept.asked_lately(now) {
        KeySetStep::Fetch
    } else {
        KeySetStep::Use(keys.to_vec())
    }
}

#[cfg(test)]
mod tests;
