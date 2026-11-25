//! SPIFFE client authentication with a JWT-SVID (`spiffe_jwt`,
//! draft-ietf-oauth-spiffe-client-auth-03): the SPIFFE identifier a client
//! is bound to, and how a JWT-SVID is checked against its trust domain's
//! bundle.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "The SPIFFE
//! identifier of a client" and "Checking a JWT-SVID", and in Decision 0055.

use crate::domain::key::verifying_key_of;
use crate::domain::token::{CLOCK_ALLOWANCE, MAX_ASSERTION_BYTES, decode_json};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::{Digest, DomainError, SignatureAlgorithm, SignatureVerifier, Timestamp};
use hodor_keys::api::{TrustBundle, TrustDomainName};
use serde_json::Value;
use std::fmt;
use time::Duration;

/// The `client_assertion_type` of a JWT-SVID
/// (draft-ietf-oauth-spiffe-client-auth-03, section 3.2).
pub const SPIFFE_ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-spiffe";
/// The version of the Internet-Draft `spiffe_jwt` follows. A change of it is
/// a change to Hodor, written in the changelog.
pub const SPIFFE_CLIENT_AUTHENTICATION_DRAFT: &str = "draft-ietf-oauth-spiffe-client-auth-03";
/// The longest SPIFFE identifier, in bytes, as the SPIFFE identifier
/// specification bounds a URI.
pub const MAX_SPIFFE_ID_LENGTH: usize = 2048;
/// The furthest ahead a JWT-SVID may expire: what is remembered of it is
/// kept no longer.
pub const SVID_LONGEST_AHEAD: Duration = Duration::hours(1);
/// What a JWT-SVID's mark in the register of client assertions begins
/// with, so that it is never taken for the `jti` of an assertion.
pub const SVID_MARK_PREFIX: &str = "jwt-svid:";

const SCHEME: &str = "spiffe://";

fn spiffe_id_invalid(reason: &'static str) -> DomainError {
    DomainError::invalid(
        "oauth.client_spiffe_id_invalid",
        "a client using `spiffe_jwt` is bound to one SPIFFE identifier, \
         `spiffe://<trust domain>/<path>` with a path of segments of letters, digits, `.`, `-` \
         and `_`, at most 2048 characters, without `*`; only such a client has one, and it has a \
         principal",
    )
    .with_detail(reason)
}

/// A SPIFFE identifier, as the SPIFFE identifier specification writes it,
/// with a path: the identity of one workload. Compared byte for byte.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SpiffeId {
    text: String,
    /// Where the trust domain's name ends in `text`.
    trust_domain_end: usize,
}

impl fmt::Debug for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("SpiffeId").field(&self.text).finish()
    }
}

impl fmt::Display for SpiffeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.text)
    }
}

impl SpiffeId {
    /// Reads an identifier: `spiffe://`, a trust domain's name by the rule
    /// of the keys context, and a path of one or more segments, each `/`
    /// and 1 or more letters, digits, `.`, `-` or `_`, never `.` or `..`
    /// alone. Nothing is changed: an uppercase scheme or trust domain is
    /// refused, not lowered. A `*`, and so a prefix match, is refused.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_spiffe_id_invalid`.
    pub fn parse(text: &str) -> Result<Self, DomainError> {
        if text.len() > MAX_SPIFFE_ID_LENGTH {
            return Err(spiffe_id_invalid("the identifier is too long"));
        }
        let rest = text
            .strip_prefix(SCHEME)
            .ok_or_else(|| spiffe_id_invalid("the identifier does not begin with `spiffe://`"))?;
        let (trust_domain, path) = rest
            .split_once('/')
            .ok_or_else(|| spiffe_id_invalid("the identifier has no path"))?;
        TrustDomainName::parse(trust_domain)
            .map_err(|_| spiffe_id_invalid("the trust domain's name is not one SPIFFE allows"))?;
        for segment in path.split('/') {
            let fits = !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'));
            if !fits {
                return Err(spiffe_id_invalid(
                    "a segment of the path is empty, `.`, `..`, or has a character SPIFFE does \
                     not allow, such as `*`",
                ));
            }
        }
        Ok(Self {
            text: text.to_owned(),
            trust_domain_end: SCHEME.len() + trust_domain.len(),
        })
    }

    /// The identifier, as it was given.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.text
    }

    /// The name of its trust domain.
    #[must_use]
    pub fn trust_domain(&self) -> &str {
        &self.text[SCHEME.len()..self.trust_domain_end]
    }
}

/// A JWT-SVID whose every check passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedSvid {
    /// What is remembered of it until it expires: [`SVID_MARK_PREFIX`] and
    /// the SHA-256 of its first two parts, in base64url.
    pub mark: String,
    /// When it expires.
    pub expires_at: Timestamp,
}

fn at(seconds: i64) -> Option<Timestamp> {
    Timestamp::from_unix_timestamp(seconds).ok()
}

/// Checks a JWT-SVID presented by the client bound to `spiffe_id`, against
/// `bundle`, the bundle of that identifier's trust domain in the client's
/// tenant, for the tenant's `issuer`. Nothing the JWT-SVID says is used
/// before its signature has been checked, and nothing it says chooses the
/// keys.
///
/// # Errors
///
/// Returns why it is refused; the client is told `invalid_client` whatever
/// the reason.
pub fn check_svid(
    svid: &str,
    spiffe_id: &SpiffeId,
    bundle: &TrustBundle,
    issuer: &str,
    now: Timestamp,
    verifier: &dyn SignatureVerifier,
    digest: &dyn Digest,
) -> Result<CheckedSvid, &'static str> {
    if svid.len() > MAX_ASSERTION_BYTES {
        return Err("the JWT-SVID is too large");
    }
    let parts: Vec<&str> = svid.split('.').collect();
    let [header_part, claims_part, signature_part] = parts.as_slice() else {
        return Err("the JWT-SVID is not three parts");
    };
    let header = decode_json(header_part).ok_or("the JWT-SVID's header is malformed")?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_part)
        .map_err(|_| "the JWT-SVID's signature is malformed")?;
    let algorithm = header
        .get("alg")
        .and_then(Value::as_str)
        .and_then(SignatureAlgorithm::from_name)
        .ok_or("the JWT-SVID names an algorithm that is not accepted")?;
    match header.get("typ") {
        None => {}
        Some(Value::String(kind)) if kind == "JWT" || kind == "JOSE" => {}
        Some(_) => return Err("the JWT-SVID's typ is neither JWT nor JOSE"),
    }
    let key_id = match header.get("kid") {
        Some(Value::String(kid)) => kid,
        Some(_) => return Err("the JWT-SVID's kid is not text"),
        None => return Err("the JWT-SVID names no kid"),
    };
    let element = bundle
        .jwt_key(key_id)
        .ok_or("the trust domain's bundle has no key of the JWT-SVID's kid")?;
    let key = verifying_key_of(&element.jwk, algorithm)
        .ok_or("the bundle's key does not fit the JWT-SVID's algorithm")?;
    let signed = format!("{header_part}.{claims_part}");
    if !verifier.verify(algorithm, &key, signed.as_bytes(), &signature) {
        return Err("the JWT-SVID's signature does not verify");
    }

    // Only now is anything the JWT-SVID says used.
    let claims = decode_json(claims_part).ok_or("the JWT-SVID's claims are malformed")?;
    if claims.get("sub").and_then(Value::as_str) != Some(spiffe_id.as_str()) {
        return Err("the JWT-SVID is not of the client's SPIFFE identifier");
    }
    let sole_audience = match claims.get("aud") {
        Some(Value::String(one)) => Some(one.as_str()),
        Some(Value::Array(many)) => match many.as_slice() {
            [Value::String(one)] => Some(one.as_str()),
            _ => None,
        },
        _ => None,
    };
    if sole_audience != Some(issuer) {
        return Err("the JWT-SVID's audience is not the tenant's issuer alone");
    }
    let expires_at = claims
        .get("exp")
        .and_then(Value::as_i64)
        .and_then(at)
        .ok_or("the JWT-SVID does not say when it expires")?;
    if expires_at + CLOCK_ALLOWANCE <= now {
        return Err("the JWT-SVID has expired");
    }
    if expires_at > now + SVID_LONGEST_AHEAD + CLOCK_ALLOWANCE {
        return Err("the JWT-SVID expires too far ahead");
    }
    for name in ["nbf", "iat"] {
        if let Some(value) = claims.get(name) {
            let moment = value
                .as_i64()
                .and_then(at)
                .ok_or("the JWT-SVID has a malformed time")?;
            if moment > now + CLOCK_ALLOWANCE {
                return Err("the JWT-SVID is from the future");
            }
        }
    }
    // The signature is left out: an ECDSA signature can be rewritten into
    // another that verifies, and the JWT-SVID would still be the same.
    let hash = digest.sha256(signed.as_bytes());
    Ok(CheckedSvid {
        mark: format!("{SVID_MARK_PREFIX}{}", URL_SAFE_NO_PAD.encode(hash)),
        expires_at,
    })
}

#[cfg(test)]
mod tests;
