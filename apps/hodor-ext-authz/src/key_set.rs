//! The tenant's published key set, kept in memory, and the signature of a
//! bearer token checked against it before Hodor is asked anything.
//!
//! Specified in `docs/operations/hodor-ext-authz.md`, "The subject", and
//! Decision 0082.

use crate::check::Denial;
use crate::config::Settings;
use aws_lc_rs::signature::{self, RsaPublicKeyComponents, UnparsedPublicKey};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use reqwest::StatusCode;
use reqwest::header::ACCEPT;
use serde_json::{Map, Value};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

/// How long a fetched set is used: five minutes, the time Hodor's answer
/// allows it to be kept, never more.
pub const KEY_SET_KEPT_FOR: Duration = Duration::from_secs(300);
/// The shortest time between two fetches, whatever caused them.
pub const KEY_SET_REFETCH_AFTER: Duration = Duration::from_secs(10);
/// The most bytes of a key set read: 64 kibibytes.
pub const MAX_KEY_SET_BYTES: usize = 64 * 1024;
/// The most keys read of one set; the rest are left out.
pub const MAX_KEYS: usize = 32;
/// The longest bearer token read: 16 kibibytes.
pub const MAX_TOKEN_BYTES: usize = 16 * 1024;
/// The media types the set is asked for in.
const KEY_SET_ACCEPT: &str = "application/jwk-set+json, application/json";
/// The fewest bytes of an RSA modulus: 2048 bits.
const MIN_RSA_MODULUS_BYTES: usize = 256;

/// The algorithms Hodor signs with, and the only ones accepted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    /// ECDSA on P-256 with SHA-256.
    Es256,
    /// RSA with PKCS#1 version 1.5 padding and SHA-256.
    Rs256,
    /// RSA with PSS padding and SHA-256.
    Ps256,
    /// EdDSA on Ed25519.
    EdDsa,
}

impl Algorithm {
    /// The algorithm a header or a key names, exactly; `None` for any
    /// other name, `none` and the HMAC algorithms included.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "ES256" => Some(Self::Es256),
            "RS256" => Some(Self::Rs256),
            "PS256" => Some(Self::Ps256),
            "EdDSA" => Some(Self::EdDsa),
            _ => None,
        }
    }
}

/// The public part of a key, as the verification needs it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Material {
    /// A point on P-256, uncompressed: `0x04`, `x` and `y`.
    P256(Vec<u8>),
    /// An RSA modulus and exponent, big-endian without leading zeros.
    Rsa { n: Vec<u8>, e: Vec<u8> },
    /// An Ed25519 public key's 32 bytes.
    Ed25519(Vec<u8>),
}

/// One key of the published set.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedKey {
    kid: String,
    algorithm: Algorithm,
    material: Material,
}

/// The members of a key that only a private or a symmetric key has.
const SECRET_MEMBERS: &[&str] = &["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

impl PublishedKey {
    /// A key of the set, if it is one Hodor publishes: a `kid`, an `alg`
    /// it signs with, `use` absent or `sig`, no private part, and the
    /// public parts of a key of that algorithm's type.
    fn read(key: &Value) -> Option<Self> {
        let key = key.as_object()?;
        let text = |name: &str| key.get(name).and_then(Value::as_str);
        let bytes = |name: &str| text(name).and_then(|value| URL_SAFE_NO_PAD.decode(value).ok());
        let kid = text("kid").filter(|kid| !kid.is_empty())?.to_owned();
        let algorithm = text("alg").and_then(Algorithm::from_name)?;
        if key.get("use").is_some_and(|usage| usage != "sig")
            || SECRET_MEMBERS
                .iter()
                .any(|member| key.contains_key(*member))
        {
            return None;
        }
        let material = match algorithm {
            Algorithm::Es256 => {
                if text("kty")? != "EC" || text("crv")? != "P-256" {
                    return None;
                }
                let (x, y) = (bytes("x")?, bytes("y")?);
                if x.len() != 32 || y.len() != 32 {
                    return None;
                }
                let mut point = Vec::with_capacity(65);
                point.push(0x04);
                point.extend_from_slice(&x);
                point.extend_from_slice(&y);
                Material::P256(point)
            }
            Algorithm::Rs256 | Algorithm::Ps256 => {
                if text("kty")? != "RSA" {
                    return None;
                }
                let n = without_leading_zeros(bytes("n")?);
                let e = without_leading_zeros(bytes("e")?);
                if n.len() < MIN_RSA_MODULUS_BYTES || e.is_empty() {
                    return None;
                }
                Material::Rsa { n, e }
            }
            Algorithm::EdDsa => {
                if text("kty")? != "OKP" || text("crv")? != "Ed25519" {
                    return None;
                }
                let x = bytes("x")?;
                if x.len() != 32 {
                    return None;
                }
                Material::Ed25519(x)
            }
        };
        Some(Self {
            kid,
            algorithm,
            material,
        })
    }

    /// Whether `signature` is this key's signature of `message`, with the
    /// key's own algorithm.
    fn verifies(&self, message: &[u8], signature: &[u8]) -> bool {
        match (&self.material, self.algorithm) {
            (Material::P256(point), Algorithm::Es256) => {
                UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, point)
                    .verify(message, signature)
                    .is_ok()
            }
            (Material::Rsa { n, e }, Algorithm::Rs256) => RsaPublicKeyComponents { n, e }
                .verify(&signature::RSA_PKCS1_2048_8192_SHA256, message, signature)
                .is_ok(),
            (Material::Rsa { n, e }, Algorithm::Ps256) => RsaPublicKeyComponents { n, e }
                .verify(&signature::RSA_PSS_2048_8192_SHA256, message, signature)
                .is_ok(),
            (Material::Ed25519(x), Algorithm::EdDsa) => {
                UnparsedPublicKey::new(&signature::ED25519, x)
                    .verify(message, signature)
                    .is_ok()
            }
            _ => false,
        }
    }
}

fn without_leading_zeros(mut bytes: Vec<u8>) -> Vec<u8> {
    let zeros = bytes.iter().take_while(|byte| **byte == 0).count();
    bytes.drain(..zeros);
    bytes
}

/// The keys of a set: a JSON object with a list `keys`, of which the first
/// [`MAX_KEYS`] keys Hodor publishes are kept and the others left out.
/// `None` when the answer is not a set at all.
#[must_use]
pub fn published_keys(body: &[u8]) -> Option<Vec<PublishedKey>> {
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
            .filter_map(PublishedKey::read)
            .take(MAX_KEYS)
            .collect(),
    )
}

/// A bearer token read, before its signature is checked.
struct Read<'a> {
    algorithm: Algorithm,
    kid: String,
    /// The header and the claims as they were signed, with the dot.
    signed: &'a str,
    signature: Vec<u8>,
    claims: Map<String, Value>,
}

/// Reads a bearer token as a JSON Web Signature in its compact form: a
/// header naming an algorithm Hodor signs with and a `kid`, and no `crit`;
/// claims that are a JSON object; a signature.
fn read(token: &str) -> Result<Read<'_>, Denial> {
    if token.len() > MAX_TOKEN_BYTES {
        return Err(Denial("the bearer token is too long"));
    }
    let not_a_token = Denial("the bearer token is not a JSON Web Token");
    let mut parts = token.split('.');
    let (Some(header), Some(payload), Some(signature), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(not_a_token);
    };
    let object = |part: &str| {
        URL_SAFE_NO_PAD
            .decode(part)
            .ok()
            .and_then(|bytes| match serde_json::from_slice(&bytes) {
                Ok(Value::Object(object)) => Some(object),
                _ => None,
            })
    };
    let header = object(header).ok_or(not_a_token)?;
    let algorithm = header
        .get("alg")
        .and_then(Value::as_str)
        .and_then(Algorithm::from_name)
        .ok_or(Denial("the token's algorithm is not one Hodor signs with"))?;
    if header.contains_key("crit") {
        return Err(Denial("the token's header names extensions"));
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .filter(|kid| !kid.is_empty())
        .ok_or(Denial("the token's header names no key"))?
        .to_owned();
    let claims = object(payload).ok_or(Denial("the token's claims are not a JSON object"))?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature)
        .ok()
        .filter(|signature| !signature.is_empty())
        .ok_or(not_a_token)?;
    let signed = &token[..header_and_payload_length(token)];
    Ok(Read {
        algorithm,
        kid,
        signed,
        signature,
        claims,
    })
}

/// The length of the header, the dot and the claims of a compact token.
fn header_and_payload_length(token: &str) -> usize {
    token.rfind('.').unwrap_or(token.len())
}

/// What the adapter keeps of the set: the keys it last answered, and when
/// it was last fetched and last asked.
#[derive(Debug, Default)]
struct Kept {
    keys: Vec<PublishedKey>,
    /// When the fetch that answered the keys started, if one has.
    fetched_at: Option<Instant>,
    /// When the last fetch started, whether it answered or not.
    asked_at: Option<Instant>,
}

impl Kept {
    fn is_fresh(&self, now: Instant) -> bool {
        self.fetched_at
            .is_some_and(|at| now.saturating_duration_since(at) < KEY_SET_KEPT_FOR)
    }

    fn asked_lately(&self, now: Instant) -> bool {
        self.asked_at
            .is_some_and(|at| now.saturating_duration_since(at) < KEY_SET_REFETCH_AFTER)
    }

    /// The key named `kid`, if the set may still be used at `now`.
    fn key(&self, kid: &str, now: Instant) -> Option<PublishedKey> {
        if !self.is_fresh(now) {
            return None;
        }
        self.keys.iter().find(|key| key.kid == kid).cloned()
    }
}

/// The tenant's published key set, read at Hodor's own address: fetched
/// when a token needs it, used for [`KEY_SET_KEPT_FOR`], and fetched again
/// for a `kid` it lacks, never more often than [`KEY_SET_REFETCH_AFTER`].
#[derive(Debug)]
pub struct KeySet {
    http: reqwest::Client,
    address: String,
    timeout: Duration,
    kept: Mutex<Kept>,
    /// Held while a fetch runs, so that checks arriving meanwhile wait for
    /// it rather than fetch again.
    fetching: tokio::sync::Mutex<()>,
}

impl KeySet {
    /// The key set of the tenant `settings` name, fetched through `http`,
    /// which should follow no redirect.
    #[must_use]
    pub fn new(settings: &Settings, http: reqwest::Client) -> Self {
        Self {
            http,
            address: settings.key_set_endpoint(),
            timeout: settings.timeout,
            kept: Mutex::new(Kept::default()),
            fetching: tokio::sync::Mutex::new(()),
        }
    }

    fn kept(&self) -> MutexGuard<'_, Kept> {
        self.kept.lock().unwrap_or_else(PoisonError::into_inner)
    }

    /// The claims of `token` once its signature holds with the key its
    /// `kid` names in the tenant's set, of the algorithm its header names.
    ///
    /// # Errors
    ///
    /// Returns the [`Denial`] of a token that does not read, names an
    /// algorithm Hodor does not sign with or a key the set lacks, or whose
    /// signature fails.
    pub async fn verify(&self, token: &str) -> Result<Map<String, Value>, Denial> {
        let token = read(token)?;
        let key = self
            .key(&token.kid)
            .await
            .ok_or(Denial("the token's key is not in the tenant's key set"))?;
        if key.algorithm != token.algorithm {
            return Err(Denial("the token's algorithm is not its key's"));
        }
        if !key.verifies(token.signed.as_bytes(), &token.signature) {
            return Err(Denial("the token's signature does not hold"));
        }
        Ok(token.claims)
    }

    /// The key named `kid`: from the kept set while it is fresh and has
    /// it; otherwise after a fetch, unless one started less than
    /// [`KEY_SET_REFETCH_AFTER`] ago. A fetch that fails keeps what was
    /// kept.
    async fn key(&self, kid: &str) -> Option<PublishedKey> {
        if let Some(key) = self.kept().key(kid, Instant::now()) {
            return Some(key);
        }
        let _fetching = self.fetching.lock().await;
        let now = Instant::now();
        {
            let mut kept = self.kept();
            // A fetch that ran while this one waited may have brought it.
            if let Some(key) = kept.key(kid, now) {
                return Some(key);
            }
            if kept.asked_lately(now) {
                return None;
            }
            // Counted before the fetch answers, and whether it does.
            kept.asked_at = Some(now);
        }
        let fetched = self.fetch().await;
        let mut kept = self.kept();
        if let Some(keys) = fetched {
            kept.keys = keys;
            kept.fetched_at = Some(now);
        }
        kept.key(kid, Instant::now())
    }

    /// What Hodor answers at the set's address, if it answers a set within
    /// the bounds.
    async fn fetch(&self) -> Option<Vec<PublishedKey>> {
        let failed = |reason: String| {
            tracing::warn!(address = %self.address, reason = %reason, "the tenant's key set could not be read");
            None
        };
        let mut answer = match self
            .http
            .get(&self.address)
            .timeout(self.timeout)
            .header(ACCEPT, KEY_SET_ACCEPT)
            .send()
            .await
        {
            Ok(answer) => answer,
            Err(error) => return failed(format!("it could not be reached: {error}")),
        };
        // A redirect, followed or not, is not the set.
        if answer.status() != StatusCode::OK {
            return failed(format!("it answered {}", answer.status()));
        }
        if answer
            .content_length()
            .is_some_and(|length| length > MAX_KEY_SET_BYTES as u64)
        {
            return failed("its answer is too long".to_owned());
        }
        let mut body = Vec::new();
        loop {
            match answer.chunk().await {
                Ok(Some(chunk)) if body.len() + chunk.len() <= MAX_KEY_SET_BYTES => {
                    body.extend_from_slice(&chunk);
                }
                Ok(Some(_)) => return failed("its answer is too long".to_owned()),
                Ok(None) => break,
                Err(error) => return failed(format!("its answer could not be read: {error}")),
            }
        }
        published_keys(&body).or_else(|| failed("its answer is not a key set".to_owned()))
    }

    /// Makes the kept set and the last fetch look `by` older, as time
    /// passing would.
    #[cfg(test)]
    fn age(&self, by: Duration) {
        let mut kept = self.kept();
        let earlier = |at: Instant| at.checked_sub(by).expect("an earlier instant");
        kept.fetched_at = kept.fetched_at.map(earlier);
        kept.asked_at = kept.asked_at.map(earlier);
    }
}

#[cfg(test)]
mod tests;
