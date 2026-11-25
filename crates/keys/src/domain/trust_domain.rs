//! Trust domains: the SPIFFE trust domains a tenant trusts, each with the
//! bundle of its authorities, given by an administrator, fetched from a
//! bundle endpoint, or left to the mesh.
//!
//! See `docs/architecture/contexts/keys.md`, "Trust domains".

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hodor_kernel::{DomainError, Timestamp};
use serde_json::{Map, Value};
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies a trust domain of a tenant.
    TrustDomainId
);

/// The most trust domains a tenant may have.
pub const MAX_TRUST_DOMAINS: u32 = 50;
/// The longest name of a trust domain.
pub const MAX_NAME_LENGTH: usize = 255;
/// The longest address of a bundle endpoint, in characters.
pub const MAX_BUNDLE_ENDPOINT_LENGTH: usize = 1000;
/// The largest bundle document, in bytes, given or fetched.
pub const MAX_BUNDLE_BYTES: usize = 64 * 1024;
/// The most elements the `keys` of a bundle may have.
pub const MAX_BUNDLE_ELEMENTS: usize = 100;
/// The longest code of a failed fetch kept on a trust domain.
pub const MAX_ERROR_LENGTH: usize = 100;
/// How long a fetch may take.
pub const FETCH_TIME_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);
/// How long past the time limit of a fetch a lease lasts.
pub(crate) const LEASE_MARGIN: Duration = Duration::minutes(1);
/// The interval of a bundle with no refresh hint.
pub const DEFAULT_REFRESH: Duration = Duration::minutes(5);
/// The shortest interval a refresh hint may set.
pub const SHORTEST_REFRESH: Duration = Duration::minutes(1);
/// The longest interval a refresh hint may set.
pub const LONGEST_REFRESH: Duration = Duration::days(1);
/// The longest wait after a failed fetch.
pub const LONGEST_RETRY: Duration = Duration::minutes(5);

/// The largest certificate of an `x509-svid` element, in bytes.
const MAX_CERTIFICATE_BYTES: usize = 16 * 1024;
/// The longest `kid` of a `jwt-svid` element.
const MAX_KEY_ID_LENGTH: usize = 128;
/// The shortest RSA modulus kept, in bits.
const SHORTEST_RSA_MODULUS: usize = 2048;
/// Members that only a private or a symmetric key has.
const PRIVATE_MEMBERS: [&str; 8] = ["d", "p", "q", "dp", "dq", "qi", "oth", "k"];

/// The name of a trust domain, as it appears in a SPIFFE identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TrustDomainName(String);

impl TrustDomainName {
    /// Reads a name: 1 to 255 characters, each a lowercase letter, a
    /// digit, `.`, `-` or `_` (the SPIFFE identifier specification,
    /// section 2.1). Nothing is changed: an uppercase letter is refused,
    /// not lowered.
    ///
    /// # Errors
    ///
    /// Returns `keys.trust_domain_name_invalid`.
    pub fn parse(name: &str) -> Result<Self, DomainError> {
        let fits = !name.is_empty()
            && name.len() <= MAX_NAME_LENGTH
            && name.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'.' | b'-' | b'_')
            });
        if fits {
            Ok(Self(name.to_owned()))
        } else {
            Err(DomainError::invalid(
                "keys.trust_domain_name_invalid",
                "a trust domain's name is 1 to 255 lowercase letters, digits, `.`, `-` and `_`, \
                 as in `spiffe://<name>/…`",
            ))
        }
    }

    /// The name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for TrustDomainName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// What an element of a bundle is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SvidKind {
    /// An authority of X.509-SVIDs: one certificate.
    X509,
    /// A key that signs JWT-SVIDs.
    Jwt,
}

impl SvidKind {
    /// The `use` of the element.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::X509 => "x509-svid",
            Self::Jwt => "jwt-svid",
        }
    }

    fn from_use(name: &str) -> Option<Self> {
        match name {
            "x509-svid" => Some(Self::X509),
            "jwt-svid" => Some(Self::Jwt),
            _ => None,
        }
    }
}

/// An element of a bundle that was kept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleKey {
    /// What it is for.
    pub kind: SvidKind,
    /// The `kid` of a `jwt-svid` element; `None` for an `x509-svid` one.
    pub key_id: Option<String>,
    /// The element, written as compact JSON with its members in order.
    pub jwk: String,
}

fn bundle_invalid(reason: impl Into<String>) -> DomainError {
    DomainError::invalid(
        "keys.trust_bundle_invalid",
        "a trust bundle is a SPIFFE bundle: a JSON Web Key Set of at most 64 kibibytes and 100 \
         elements, each `x509-svid` element with one certificate and no `kid`, each `jwt-svid` \
         element with a `kid` of its own, none with a private part",
    )
    .with_detail(reason.into())
}

fn decoded(key: &Map<String, Value>, member: &str) -> Result<Vec<u8>, DomainError> {
    let value = key
        .get(member)
        .and_then(Value::as_str)
        .ok_or_else(|| bundle_invalid(format!("an element lacks `{member}`")))?;
    URL_SAFE_NO_PAD
        .decode(value)
        .map_err(|_| bundle_invalid(format!("an element's `{member}` is not base64url")))
}

fn rsa_modulus_bits(modulus: &[u8]) -> usize {
    let mut significant = modulus.iter().skip_while(|byte| **byte == 0);
    match significant.next() {
        None => 0,
        Some(first) => {
            let rest = significant.count();
            rest * 8 + (8 - first.leading_zeros() as usize)
        }
    }
}

/// The key types Hodor knows, with the length of a coordinate for a curve
/// and the algorithms each may be used with. `None` for a type Hodor does
/// not know, whose element is ignored.
fn known_type(kind: &str, curve: Option<&str>) -> Option<(Option<usize>, &'static [&'static str])> {
    match (kind, curve) {
        ("EC", Some("P-256")) => Some((Some(32), &["ES256"])),
        ("EC", Some("P-384")) => Some((Some(48), &["ES384"])),
        ("EC", Some("P-521")) => Some((Some(66), &["ES512"])),
        ("RSA", _) => Some((
            None,
            &["RS256", "RS384", "RS512", "PS256", "PS384", "PS512"],
        )),
        _ => None,
    }
}

/// Reads one element: `None` when it is to be ignored, the kept element,
/// or the reason the whole bundle is refused.
fn read_element(element: Value) -> Result<Option<BundleKey>, DomainError> {
    let Value::Object(key) = element else {
        return Err(bundle_invalid("an element of `keys` is not a JSON object"));
    };
    let Some(kind) = key
        .get("use")
        .and_then(Value::as_str)
        .and_then(SvidKind::from_use)
    else {
        return Ok(None);
    };
    let Some(key_type) = key.get("kty").and_then(Value::as_str) else {
        return Ok(None);
    };
    let Some((coordinate, algorithms)) =
        known_type(key_type, key.get("crv").and_then(Value::as_str))
    else {
        return Ok(None);
    };
    if PRIVATE_MEMBERS
        .iter()
        .any(|member| key.contains_key(*member))
    {
        return Err(bundle_invalid("an element has a private part"));
    }
    match coordinate {
        Some(length) => {
            for member in ["x", "y"] {
                if decoded(&key, member)?.len() != length {
                    return Err(bundle_invalid("a coordinate has the wrong length"));
                }
            }
        }
        None => {
            if rsa_modulus_bits(&decoded(&key, "n")?) < SHORTEST_RSA_MODULUS {
                return Err(bundle_invalid("an RSA modulus is shorter than 2048 bits"));
            }
            if decoded(&key, "e")?.is_empty() {
                return Err(bundle_invalid("an RSA exponent is empty"));
            }
        }
    }
    if let Some(algorithm) = key.get("alg") {
        let fits = algorithm
            .as_str()
            .is_some_and(|name| algorithms.contains(&name));
        if !fits {
            return Err(bundle_invalid("an element's `alg` does not fit its key"));
        }
    }
    let key_id = match kind {
        SvidKind::X509 => {
            if key.contains_key("kid") {
                return Err(bundle_invalid("an `x509-svid` element has a `kid`"));
            }
            let certificates = key
                .get("x5c")
                .and_then(Value::as_array)
                .ok_or_else(|| bundle_invalid("an `x509-svid` element has no `x5c`"))?;
            let [certificate] = certificates.as_slice() else {
                return Err(bundle_invalid(
                    "an `x509-svid` element does not hold exactly one certificate",
                ));
            };
            let der = certificate
                .as_str()
                .and_then(|text| STANDARD.decode(text).ok())
                .ok_or_else(|| bundle_invalid("a certificate is not base64"))?;
            if der.len() > MAX_CERTIFICATE_BYTES || der.first() != Some(&0x30) {
                return Err(bundle_invalid(
                    "a certificate is not a DER sequence of at most 16 kibibytes",
                ));
            }
            None
        }
        SvidKind::Jwt => {
            let key_id = key
                .get("kid")
                .and_then(Value::as_str)
                .filter(|kid| {
                    !kid.is_empty()
                        && kid.len() <= MAX_KEY_ID_LENGTH
                        && kid.bytes().all(|byte| byte.is_ascii_graphic())
                })
                .ok_or_else(|| bundle_invalid("a `jwt-svid` element has no usable `kid`"))?;
            Some(key_id.to_owned())
        }
    };
    // Written with its members in order, so that the same element is
    // always the same text, however it was given.
    let ordered: BTreeMap<String, Value> = key.into_iter().collect();
    let jwk = serde_json::to_string(&ordered)
        .map_err(|_| bundle_invalid("an element cannot be written as JSON"))?;
    Ok(Some(BundleKey { kind, key_id, jwk }))
}

fn whole_number(
    bundle: &Map<String, Value>,
    member: &str,
    least: u64,
) -> Result<Option<u64>, DomainError> {
    match bundle.get(member) {
        None => Ok(None),
        Some(value) => value
            .as_u64()
            .filter(|number| *number >= least && i64::try_from(*number).is_ok())
            .map(Some)
            .ok_or_else(|| bundle_invalid(format!("`{member}` is not a whole number in bounds"))),
    }
}

/// A SPIFFE bundle as Hodor keeps it: the elements it kept, its sequence
/// number and its refresh hint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustBundle {
    sequence: Option<u64>,
    refresh_hint: Option<u64>,
    keys: Vec<BundleKey>,
    document: String,
}

impl TrustBundle {
    /// Reads a bundle as an administrator gives it or an endpoint answers
    /// it. Elements of an unknown `use` or key type are ignored; any other
    /// fault refuses the whole bundle.
    ///
    /// # Errors
    ///
    /// Returns `keys.trust_bundle_invalid`, with the reason as its detail.
    pub fn parse(bytes: &[u8]) -> Result<Self, DomainError> {
        if bytes.len() > MAX_BUNDLE_BYTES {
            return Err(bundle_invalid("the bundle is larger than 64 kibibytes"));
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_| bundle_invalid("the bundle is not UTF-8"))?;
        let value: Value =
            serde_json::from_str(text).map_err(|_| bundle_invalid("the bundle is not JSON"))?;
        let Value::Object(mut bundle) = value else {
            return Err(bundle_invalid("the bundle is not a JSON object"));
        };
        let sequence = whole_number(&bundle, "spiffe_sequence", 0)?;
        let refresh_hint = whole_number(&bundle, "spiffe_refresh_hint", 1)?;
        let Some(Value::Array(elements)) = bundle.remove("keys") else {
            return Err(bundle_invalid("the bundle has no `keys` array"));
        };
        if elements.len() > MAX_BUNDLE_ELEMENTS {
            return Err(bundle_invalid("the bundle has more than 100 elements"));
        }
        let mut keys = Vec::new();
        let mut key_ids = BTreeSet::new();
        for element in elements {
            if let Some(key) = read_element(element)? {
                if let Some(key_id) = &key.key_id
                    && !key_ids.insert(key_id.clone())
                {
                    return Err(bundle_invalid(
                        "two `jwt-svid` elements have the same `kid`",
                    ));
                }
                keys.push(key);
            }
        }
        Ok(Self::assemble(sequence, refresh_hint, keys))
    }

    fn assemble(sequence: Option<u64>, refresh_hint: Option<u64>, keys: Vec<BundleKey>) -> Self {
        // The members in order: `keys`, `spiffe_refresh_hint`,
        // `spiffe_sequence`.
        let mut document = String::from("{\"keys\":[");
        for (index, key) in keys.iter().enumerate() {
            if index > 0 {
                document.push(',');
            }
            document.push_str(&key.jwk);
        }
        document.push(']');
        if let Some(hint) = refresh_hint {
            document.push_str(&format!(",\"spiffe_refresh_hint\":{hint}"));
        }
        if let Some(sequence) = sequence {
            document.push_str(&format!(",\"spiffe_sequence\":{sequence}"));
        }
        document.push('}');
        Self {
            sequence,
            refresh_hint,
            keys,
            document,
        }
    }

    /// Reads a bundle as a store kept it.
    ///
    /// # Errors
    ///
    /// Returns `keys.stored_data_invalid` if it no longer reads.
    pub fn from_stored(document: &str) -> Result<Self, DomainError> {
        Self::parse(document.as_bytes()).map_err(|_| {
            DomainError::internal(
                "keys.stored_data_invalid",
                "the trust bundle could not be loaded",
            )
        })
    }

    /// The bundle as it is kept: compact JSON, the kept elements in their
    /// order, each with its members in order. Two bundles are the same when
    /// this is.
    #[must_use]
    pub fn document(&self) -> &str {
        &self.document
    }

    /// Its `spiffe_sequence`.
    #[must_use]
    pub const fn sequence(&self) -> Option<u64> {
        self.sequence
    }

    /// Its `spiffe_refresh_hint`, in seconds.
    #[must_use]
    pub const fn refresh_hint(&self) -> Option<u64> {
        self.refresh_hint
    }

    /// The elements it kept, in their order.
    #[must_use]
    pub fn keys(&self) -> &[BundleKey] {
        &self.keys
    }

    /// How many authorities of each kind it holds.
    #[must_use]
    pub fn authorities(&self, kind: SvidKind) -> usize {
        self.keys.iter().filter(|key| key.kind == kind).count()
    }

    /// The `jwt-svid` element with this `kid`.
    #[must_use]
    pub fn jwt_key(&self, key_id: &str) -> Option<&BundleKey> {
        self.keys
            .iter()
            .find(|key| key.kind == SvidKind::Jwt && key.key_id.as_deref() == Some(key_id))
    }

    /// How long after a fetch that read the next one is due: the refresh
    /// hint, between one minute and one day, or five minutes without one.
    #[must_use]
    pub fn refresh_interval(&self) -> Duration {
        self.refresh_hint.map_or(DEFAULT_REFRESH, |seconds| {
            Duration::seconds(i64::try_from(seconds).unwrap_or(i64::MAX))
                .clamp(SHORTEST_REFRESH, LONGEST_REFRESH)
        })
    }

    /// Whether this bundle, fetched, may replace `in_force`: it never goes
    /// back. When the bundle in force has a sequence number, this one has
    /// one too, larger, or the same with the same contents.
    ///
    /// # Errors
    ///
    /// Returns `keys.trust_bundle_sequence_invalid`.
    pub fn may_follow(&self, in_force: &Self) -> Result<(), DomainError> {
        let Some(kept) = in_force.sequence else {
            return Ok(());
        };
        let follows = match self.sequence {
            Some(fetched) => {
                fetched > kept || (fetched == kept && self.document == in_force.document)
            }
            None => false,
        };
        if follows {
            Ok(())
        } else {
            Err(DomainError::invalid(
                "keys.trust_bundle_sequence_invalid",
                "the fetched bundle's sequence number goes back, is missing, or is the same with \
                 other contents; the bundle in force is kept",
            ))
        }
    }
}

/// Where a trust domain's bundle comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TrustSource {
    /// Given by an administrator.
    Uploaded,
    /// Fetched from a SPIFFE bundle endpoint.
    BundleEndpoint,
    /// Checked by the mesh in front of Hodor; no bundle.
    Mesh,
}

impl TrustSource {
    /// The name it is stored and answered under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Uploaded => "uploaded",
            Self::BundleEndpoint => "bundle_endpoint",
            Self::Mesh => "mesh",
        }
    }

    /// Reads a stored or given name.
    ///
    /// # Errors
    ///
    /// Returns `keys.trust_domain_source_invalid`.
    pub fn parse(name: &str) -> Result<Self, DomainError> {
        match name {
            "uploaded" => Ok(Self::Uploaded),
            "bundle_endpoint" => Ok(Self::BundleEndpoint),
            "mesh" => Ok(Self::Mesh),
            _ => Err(source_invalid()),
        }
    }
}

/// The refusal of a source that is not one of the three or lacks what it
/// needs.
#[must_use]
pub(crate) fn source_invalid() -> DomainError {
    DomainError::invalid(
        "keys.trust_domain_source_invalid",
        "a trust domain's source is `uploaded` with a `bundle`, `bundle_endpoint` with a \
         `bundle_endpoint_url`, or `mesh` with neither",
    )
}

/// The refusal of a bundle endpoint's address that is not one.
#[must_use]
pub(crate) fn bundle_endpoint_invalid() -> DomainError {
    DomainError::invalid(
        "keys.bundle_endpoint_invalid",
        "a bundle endpoint is an HTTPS address of at most 1000 characters, without a name and \
         password or a fragment",
    )
}

/// The rules a bundle endpoint's address follows before anyone resolves
/// it: an HTTP or HTTPS address with a host, printable, without spaces, a
/// name and password or a fragment. Whether plain HTTP may be used, and
/// whether the host may be called, is for the destination check to say.
///
/// # Errors
///
/// Returns `keys.bundle_endpoint_invalid`.
pub(crate) fn check_bundle_endpoint(url: &str) -> Result<(), DomainError> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(bundle_endpoint_invalid)?;
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    let plain = url.chars().count() <= MAX_BUNDLE_ENDPOINT_LENGTH
        && !authority.is_empty()
        && !authority.contains('@')
        && url.bytes().all(|byte| {
            byte.is_ascii_graphic() && !matches!(byte, b'#' | b'\\' | b'"' | b'<' | b'>')
        });
    if plain {
        Ok(())
    } else {
        Err(bundle_endpoint_invalid())
    }
}

/// A source with what it needs, checked: the bundle read, or fetched from
/// the address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CheckedSource {
    /// A bundle an administrator gave.
    Uploaded(TrustBundle),
    /// A bundle endpoint and the bundle it answered.
    BundleEndpoint {
        /// Its address.
        url: String,
        /// What it answered.
        bundle: TrustBundle,
    },
    /// Checked by the mesh.
    Mesh,
}

impl CheckedSource {
    /// Which source it is.
    #[must_use]
    pub const fn kind(&self) -> TrustSource {
        match self {
            Self::Uploaded(_) => TrustSource::Uploaded,
            Self::BundleEndpoint { .. } => TrustSource::BundleEndpoint,
            Self::Mesh => TrustSource::Mesh,
        }
    }
}

/// Everything about a trust domain, for storage and for reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustDomainSnapshot {
    /// The identifier.
    pub id: TrustDomainId,
    /// The name; never changes.
    pub name: TrustDomainName,
    /// Where its bundle comes from.
    pub source: TrustSource,
    /// The address of its bundle endpoint, for `bundle_endpoint`.
    pub bundle_endpoint_url: Option<String>,
    /// The bundle in force; `None` exactly for `mesh`.
    pub bundle: Option<TrustBundle>,
    /// When the bundle in force was given or fetched as new.
    pub bundle_changed_at: Option<Timestamp>,
    /// The last fetch that read.
    pub fetched_at: Option<Timestamp>,
    /// When the next fetch is due, for `bundle_endpoint`.
    pub next_refresh_at: Option<Timestamp>,
    /// While a worker fetches it.
    pub leased_until: Option<Timestamp>,
    /// Since when fetching fails.
    pub failing_since: Option<Timestamp>,
    /// The code of the last reason fetching failed, while it fails.
    pub last_error: Option<String>,
    /// When it was added.
    pub created_at: Timestamp,
    /// When it was last changed.
    pub updated_at: Timestamp,
    /// Incremented on every stored change, for optimistic locking.
    pub version: u32,
}

/// What a fetch by the worker did to a trust domain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FetchOutcome {
    /// The fetched bundle replaced the one in force.
    Changed {
        /// The sequence number of the bundle it replaced.
        previous_sequence: Option<u64>,
    },
    /// The fetched bundle is the one in force.
    Unchanged,
    /// The fetch failed or its bundle was refused; the bundle in force is
    /// kept.
    Failed {
        /// The code of the reason.
        reason: String,
        /// Whether this is the first failure since the last fetch that read.
        first: bool,
    },
}

/// A SPIFFE trust domain of a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TrustDomain {
    state: TrustDomainSnapshot,
}

impl TrustDomain {
    /// A new trust domain, with its source checked.
    ///
    /// # Errors
    ///
    /// Returns `keys.trust_domain_name_invalid`.
    pub fn add(name: &str, source: CheckedSource, now: Timestamp) -> Result<Self, DomainError> {
        let name = TrustDomainName::parse(name)?;
        let mut domain = Self {
            state: TrustDomainSnapshot {
                id: TrustDomainId::generate(),
                name,
                source: TrustSource::Mesh,
                bundle_endpoint_url: None,
                bundle: None,
                bundle_changed_at: None,
                fetched_at: None,
                next_refresh_at: None,
                leased_until: None,
                failing_since: None,
                last_error: None,
                created_at: now,
                updated_at: now,
                version: 0,
            },
        };
        domain.set_source(source, now);
        Ok(domain)
    }

    /// Rebuilds a trust domain from storage.
    #[must_use]
    pub const fn from_snapshot(state: TrustDomainSnapshot) -> Self {
        Self { state }
    }

    /// Everything about it.
    #[must_use]
    pub const fn snapshot(&self) -> &TrustDomainSnapshot {
        &self.state
    }

    /// Its identifier.
    #[must_use]
    pub const fn id(&self) -> TrustDomainId {
        self.state.id
    }

    /// Its name.
    #[must_use]
    pub const fn name(&self) -> &TrustDomainName {
        &self.state.name
    }

    /// Where its bundle comes from.
    #[must_use]
    pub const fn source(&self) -> TrustSource {
        self.state.source
    }

    /// The bundle in force, if it has one.
    #[must_use]
    pub const fn bundle(&self) -> Option<&TrustBundle> {
        self.state.bundle.as_ref()
    }

    /// The version it was read at.
    #[must_use]
    pub const fn version(&self) -> u32 {
        self.state.version
    }

    fn set_source(&mut self, source: CheckedSource, now: Timestamp) {
        let state = &mut self.state;
        state.source = source.kind();
        state.leased_until = None;
        state.failing_since = None;
        state.last_error = None;
        state.updated_at = now;
        match source {
            CheckedSource::Uploaded(bundle) => {
                state.bundle = Some(bundle);
                state.bundle_changed_at = Some(now);
                state.bundle_endpoint_url = None;
                state.fetched_at = None;
                state.next_refresh_at = None;
            }
            CheckedSource::BundleEndpoint { url, bundle } => {
                state.next_refresh_at = Some(now + bundle.refresh_interval());
                state.bundle = Some(bundle);
                state.bundle_changed_at = Some(now);
                state.bundle_endpoint_url = Some(url);
                state.fetched_at = Some(now);
            }
            CheckedSource::Mesh => {
                state.bundle = None;
                state.bundle_changed_at = None;
                state.bundle_endpoint_url = None;
                state.fetched_at = None;
                state.next_refresh_at = None;
            }
        }
    }

    /// Gives it another source, checked, as an administrator does. A bundle
    /// given or fetched here is not held to the rule of sequence numbers.
    pub fn replace(&mut self, source: CheckedSource, now: Timestamp) {
        self.set_source(source, now);
    }

    /// Whether the worker should fetch its bundle at `now`: from a bundle
    /// endpoint, due, and not leased past `now`.
    #[must_use]
    pub fn is_due(&self, now: Timestamp) -> bool {
        self.state.source == TrustSource::BundleEndpoint
            && self.state.next_refresh_at.is_some_and(|due| due <= now)
            && self.state.leased_until.is_none_or(|until| until <= now)
    }

    /// The address to fetch, for a lease.
    #[must_use]
    pub fn bundle_endpoint_url(&self) -> Option<&str> {
        self.state.bundle_endpoint_url.as_deref()
    }

    /// Leases it to a worker until `until`.
    ///
    /// # Errors
    ///
    /// Returns `keys.trust_domain_not_due` if it is not due at `now`.
    pub fn lease(&mut self, now: Timestamp, until: Timestamp) -> Result<(), DomainError> {
        if !self.is_due(now) {
            return Err(DomainError::conflict(
                "keys.trust_domain_not_due",
                "the trust domain's bundle is not due to be fetched",
            ));
        }
        self.state.leased_until = Some(until);
        Ok(())
    }

    /// Records what a fetch by the worker gave: a bundle that read, or the
    /// reason it failed. A bundle that goes back is a failure. The bundle in
    /// force is kept on every failure.
    pub fn record_fetch(
        &mut self,
        fetched: Result<TrustBundle, DomainError>,
        now: Timestamp,
    ) -> FetchOutcome {
        let interval = self
            .state
            .bundle
            .as_ref()
            .map_or(DEFAULT_REFRESH, TrustBundle::refresh_interval);
        self.state.leased_until = None;
        let checked = fetched.and_then(|bundle| match &self.state.bundle {
            Some(in_force) => bundle.may_follow(in_force).map(|()| bundle),
            None => Ok(bundle),
        });
        match checked {
            Ok(bundle) => {
                self.state.fetched_at = Some(now);
                self.state.failing_since = None;
                self.state.last_error = None;
                self.state.next_refresh_at = Some(now + bundle.refresh_interval());
                let unchanged = self
                    .state
                    .bundle
                    .as_ref()
                    .is_some_and(|in_force| in_force.document() == bundle.document());
                if unchanged {
                    return FetchOutcome::Unchanged;
                }
                let previous_sequence = self.state.bundle.as_ref().and_then(TrustBundle::sequence);
                self.state.bundle = Some(bundle);
                self.state.bundle_changed_at = Some(now);
                self.state.updated_at = now;
                FetchOutcome::Changed { previous_sequence }
            }
            Err(error) => {
                let first = self.state.failing_since.is_none();
                if first {
                    self.state.failing_since = Some(now);
                }
                let reason: String = error.code().chars().take(MAX_ERROR_LENGTH).collect();
                self.state.last_error = Some(reason.clone());
                self.state.next_refresh_at = Some(now + interval.min(LONGEST_RETRY));
                FetchOutcome::Failed { reason, first }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn encoded(bytes: &[u8]) -> String {
        URL_SAFE_NO_PAD.encode(bytes)
    }

    fn x509() -> Value {
        json!({"use": "x509-svid", "kty": "EC", "crv": "P-256", "x": encoded(&[1; 32]),
               "y": encoded(&[2; 32]), "x5c": [STANDARD.encode([0x30, 0x03, 0x02, 0x01, 0x01])]})
    }

    fn jwt(kid: &str) -> Value {
        json!({"use": "jwt-svid", "kty": "EC", "crv": "P-256", "kid": kid,
               "x": encoded(&[3; 32]), "y": encoded(&[4; 32])})
    }

    fn rsa(bits: usize) -> Value {
        let mut modulus = vec![0xff_u8; bits / 8];
        modulus.insert(0, 0);
        json!({"use": "jwt-svid", "kty": "RSA", "kid": "rsa", "n": encoded(&modulus), "e": "AQAB"})
    }

    fn parse(value: &Value) -> Result<TrustBundle, DomainError> {
        TrustBundle::parse(value.to_string().as_bytes())
    }

    fn reason(value: &Value) -> String {
        let error = parse(value).expect_err("refused");
        assert_eq!(error.code(), "keys.trust_bundle_invalid");
        error.detail().unwrap_or_default().to_owned()
    }

    #[test]
    fn a_bundle_of_both_kinds_is_read_and_kept_in_order() {
        let bundle = parse(&json!({
            "spiffe_sequence": 7,
            "spiffe_refresh_hint": 600,
            "keys": [jwt("one"), x509(), rsa(2048)],
            "other": "not kept",
        }))
        .expect("read");
        assert_eq!(bundle.sequence(), Some(7));
        assert_eq!(bundle.refresh_hint(), Some(600));
        assert_eq!(bundle.authorities(SvidKind::Jwt), 2);
        assert_eq!(bundle.authorities(SvidKind::X509), 1);
        assert!(bundle.jwt_key("one").is_some());
        assert!(bundle.jwt_key("two").is_none());
        assert!(!bundle.document().contains("other"));
        assert_eq!(bundle.refresh_interval(), Duration::minutes(10));
        // What is kept reads back the same.
        let again = TrustBundle::from_stored(bundle.document()).expect("stored");
        assert_eq!(again, bundle);
    }

    #[test]
    fn the_same_bundle_written_another_way_is_the_same() {
        let one = parse(&json!({"keys": [jwt("a")], "spiffe_sequence": 1})).expect("read");
        let text = format!(
            "{{ \"spiffe_sequence\" : 1, \"keys\": [ {{\"y\":\"{}\",\"x\":\"{}\",\"kid\":\"a\",\"crv\":\"P-256\",\"kty\":\"EC\",\"use\":\"jwt-svid\"}} ] }}",
            encoded(&[4; 32]),
            encoded(&[3; 32])
        );
        let other = TrustBundle::parse(text.as_bytes()).expect("read");
        assert_eq!(one.document(), other.document());
    }

    #[test]
    fn elements_of_an_unknown_use_or_key_type_are_ignored() {
        let mut no_use = jwt("a");
        no_use.as_object_mut().expect("object").remove("use");
        let mut other_use = jwt("b");
        other_use["use"] = json!("sig");
        let mut other_curve = jwt("c");
        other_curve["crv"] = json!("secp256k1");
        let okp = json!({"use": "jwt-svid", "kty": "OKP", "crv": "Ed25519", "kid": "d", "x": encoded(&[1; 32])});
        let mut no_type = jwt("e");
        no_type.as_object_mut().expect("object").remove("kty");
        let bundle =
            parse(&json!({"keys": [no_use, other_use, other_curve, okp, no_type, jwt("kept")]}))
                .expect("read");
        assert_eq!(bundle.keys().len(), 1);
        assert_eq!(bundle.keys()[0].key_id.as_deref(), Some("kept"));
    }

    #[test]
    fn an_empty_bundle_trusts_nothing_and_is_read() {
        let bundle = parse(&json!({"keys": []})).expect("read");
        assert!(bundle.keys().is_empty());
        assert_eq!(bundle.refresh_interval(), DEFAULT_REFRESH);
    }

    #[test]
    fn a_bundle_that_breaks_a_rule_is_refused_whole_with_its_reason() {
        let mut private = jwt("a");
        private["d"] = json!(encoded(&[5; 32]));
        let mut x509_with_kid = x509();
        x509_with_kid["kid"] = json!("k");
        let mut two_certificates = x509();
        two_certificates["x5c"] = json!([STANDARD.encode([0x30, 0]), STANDARD.encode([0x30, 0])]);
        let mut not_der = x509();
        not_der["x5c"] = json!([STANDARD.encode([0x04, 0])]);
        let mut not_base64 = x509();
        not_base64["x5c"] = json!(["***"]);
        let mut no_certificate = x509();
        no_certificate
            .as_object_mut()
            .expect("object")
            .remove("x5c");
        let mut no_kid = jwt("a");
        no_kid.as_object_mut().expect("object").remove("kid");
        let mut short = jwt("a");
        short["x"] = json!(encoded(&[1; 31]));
        let mut wrong_algorithm = jwt("a");
        wrong_algorithm["alg"] = json!("RS256");
        let cases = [
            (json!({"keys": [private]}), "private part"),
            (json!({"keys": [x509_with_kid]}), "has a `kid`"),
            (
                json!({"keys": [two_certificates]}),
                "exactly one certificate",
            ),
            (json!({"keys": [not_der]}), "DER sequence"),
            (json!({"keys": [not_base64]}), "not base64"),
            (json!({"keys": [no_certificate]}), "no `x5c`"),
            (json!({"keys": [no_kid]}), "no usable `kid`"),
            (json!({"keys": [jwt("same"), jwt("same")]}), "same `kid`"),
            (json!({"keys": [short]}), "wrong length"),
            (json!({"keys": [rsa(1024)]}), "2048 bits"),
            (json!({"keys": [wrong_algorithm]}), "`alg`"),
            (json!({"keys": ["not an object"]}), "not a JSON object"),
            (json!({"keys": {}}), "no `keys` array"),
            (json!({}), "no `keys` array"),
            (json!([]), "not a JSON object"),
            (
                json!({"keys": [], "spiffe_sequence": -1}),
                "`spiffe_sequence`",
            ),
            (
                json!({"keys": [], "spiffe_sequence": "1"}),
                "`spiffe_sequence`",
            ),
            (
                json!({"keys": [], "spiffe_refresh_hint": 0}),
                "`spiffe_refresh_hint`",
            ),
            (
                json!({"keys": (0..101).map(|i| jwt(&i.to_string())).collect::<Vec<_>>()}),
                "100 elements",
            ),
        ];
        for (bundle, expected) in cases {
            let found = reason(&bundle);
            assert!(found.contains(expected), "{found} should say {expected}");
        }
        assert!(TrustBundle::parse(b"not json").is_err());
        assert!(TrustBundle::parse(&[0xff, 0xfe]).is_err());
        let large = vec![b' '; MAX_BUNDLE_BYTES + 1];
        assert!(reason_of_bytes(&large).contains("64 kibibytes"));
    }

    fn reason_of_bytes(bytes: &[u8]) -> String {
        TrustBundle::parse(bytes)
            .expect_err("refused")
            .detail()
            .unwrap_or_default()
            .to_owned()
    }

    #[test]
    fn the_refresh_hint_is_bounded() {
        let short = parse(&json!({"keys": [], "spiffe_refresh_hint": 1})).expect("read");
        assert_eq!(short.refresh_interval(), SHORTEST_REFRESH);
        let long = parse(&json!({"keys": [], "spiffe_refresh_hint": 10_000_000})).expect("read");
        assert_eq!(long.refresh_interval(), LONGEST_REFRESH);
    }

    #[test]
    fn a_fetched_bundle_never_goes_back() {
        let kept = parse(&json!({"keys": [jwt("a")], "spiffe_sequence": 5})).expect("read");
        let newer = parse(&json!({"keys": [jwt("b")], "spiffe_sequence": 6})).expect("read");
        let older = parse(&json!({"keys": [jwt("b")], "spiffe_sequence": 4})).expect("read");
        let same_other = parse(&json!({"keys": [jwt("b")], "spiffe_sequence": 5})).expect("read");
        let unnumbered = parse(&json!({"keys": [jwt("b")]})).expect("read");
        assert!(newer.may_follow(&kept).is_ok());
        assert!(kept.may_follow(&kept).is_ok());
        for refused in [&older, &same_other, &unnumbered] {
            assert_eq!(
                refused.may_follow(&kept).expect_err("goes back").code(),
                "keys.trust_bundle_sequence_invalid"
            );
        }
        // A bundle in force without a number is followed by anything.
        assert!(older.may_follow(&unnumbered).is_ok());
    }

    #[test]
    fn names_follow_the_spiffe_rule() {
        for name in [
            "cluster.local",
            "prod.example.com",
            "a",
            "my_domain-2",
            &"a".repeat(255),
        ] {
            assert_eq!(TrustDomainName::parse(name).expect(name).as_str(), name);
        }
        for name in [
            "",
            "Prod.example.com",
            "spiffe://a",
            "a/b",
            "a b",
            "é",
            &"a".repeat(256),
        ] {
            assert_eq!(
                TrustDomainName::parse(name).expect_err(name).code(),
                "keys.trust_domain_name_invalid"
            );
        }
    }

    #[test]
    fn bundle_endpoint_addresses_follow_their_rule() {
        for url in [
            "https://spire.example.com/bundle",
            "http://127.0.0.1:8080/b?x=1",
        ] {
            assert!(check_bundle_endpoint(url).is_ok(), "{url}");
        }
        let long = format!("https://example.com/{}", "a".repeat(1000));
        for url in [
            "ftp://example.com",
            "https://",
            "https://user:pass@example.com/",
            "https://example.com/#fragment",
            "https://example.com/a b",
            long.as_str(),
        ] {
            assert_eq!(
                check_bundle_endpoint(url).expect_err(url).code(),
                "keys.bundle_endpoint_invalid"
            );
        }
    }

    fn fetched_domain(bundle: &Value) -> TrustDomain {
        TrustDomain::add(
            "prod.example.com",
            CheckedSource::BundleEndpoint {
                url: "https://spire.example.com/bundle".to_owned(),
                bundle: parse(bundle).expect("read"),
            },
            NOW,
        )
        .expect("added")
    }

    #[test]
    fn a_fetch_replaces_keeps_or_fails_and_the_bundle_in_force_stays_on_failure() {
        let mut domain = fetched_domain(
            &json!({"keys": [jwt("a")], "spiffe_sequence": 1, "spiffe_refresh_hint": 120}),
        );
        let first = domain.bundle().expect("bundle").clone();
        assert_eq!(
            domain.snapshot().next_refresh_at,
            Some(NOW + Duration::minutes(2))
        );
        assert!(!domain.is_due(NOW));
        let later = NOW + Duration::minutes(2);
        assert!(domain.is_due(later));
        domain
            .lease(later, later + Duration::seconds(70))
            .expect("leased");
        assert!(!domain.is_due(later));
        assert!(domain.lease(later, later).is_err());

        // A failure keeps the bundle and waits the interval, at most five
        // minutes; only the first of a run says so.
        let outcome = domain.record_fetch(
            Err(DomainError::invalid(
                "keys.bundle_endpoint_unreachable",
                "x",
            )),
            later,
        );
        assert_eq!(
            outcome,
            FetchOutcome::Failed {
                reason: "keys.bundle_endpoint_unreachable".to_owned(),
                first: true
            }
        );
        assert_eq!(domain.bundle(), Some(&first));
        assert_eq!(domain.snapshot().failing_since, Some(later));
        assert_eq!(domain.snapshot().leased_until, None);
        assert_eq!(
            domain.snapshot().next_refresh_at,
            Some(later + Duration::minutes(2))
        );
        let older = parse(&json!({"keys": [jwt("b")], "spiffe_sequence": 0})).expect("read");
        let outcome = domain.record_fetch(Ok(older), later + Duration::minutes(2));
        assert_eq!(
            outcome,
            FetchOutcome::Failed {
                reason: "keys.trust_bundle_sequence_invalid".to_owned(),
                first: false
            }
        );
        assert_eq!(domain.bundle(), Some(&first));
        assert_eq!(domain.snapshot().failing_since, Some(later));

        // The same bundle changes nothing but the time of the fetch.
        let at = later + Duration::minutes(4);
        assert_eq!(
            domain.record_fetch(Ok(first.clone()), at),
            FetchOutcome::Unchanged
        );
        assert_eq!(domain.snapshot().fetched_at, Some(at));
        assert_eq!(domain.snapshot().failing_since, None);
        assert_eq!(domain.snapshot().last_error, None);
        assert_eq!(domain.snapshot().bundle_changed_at, Some(NOW));

        // A newer one replaces it.
        let newer = parse(&json!({"keys": [jwt("c")], "spiffe_sequence": 2})).expect("read");
        assert_eq!(
            domain.record_fetch(Ok(newer.clone()), at),
            FetchOutcome::Changed {
                previous_sequence: Some(1)
            }
        );
        assert_eq!(domain.bundle(), Some(&newer));
        assert_eq!(
            domain.snapshot().next_refresh_at,
            Some(at + DEFAULT_REFRESH)
        );
    }

    #[test]
    fn a_long_interval_still_retries_within_five_minutes() {
        let mut domain = fetched_domain(&json!({"keys": [], "spiffe_refresh_hint": 86_400}));
        let at = NOW + Duration::days(1);
        domain.record_fetch(
            Err(DomainError::invalid("keys.trust_bundle_invalid", "x")),
            at,
        );
        assert_eq!(domain.snapshot().next_refresh_at, Some(at + LONGEST_RETRY));
    }

    #[test]
    fn each_source_holds_what_it_needs_and_nothing_else() {
        let bundle = parse(&json!({"keys": [jwt("a")]})).expect("read");
        let mut domain = TrustDomain::add(
            "cluster.local",
            CheckedSource::Uploaded(bundle.clone()),
            NOW,
        )
        .expect("added");
        assert_eq!(domain.source(), TrustSource::Uploaded);
        assert_eq!(domain.snapshot().next_refresh_at, None);
        assert!(!domain.is_due(NOW + Duration::days(9)));
        domain.replace(CheckedSource::Mesh, NOW);
        assert_eq!(domain.source(), TrustSource::Mesh);
        assert_eq!(domain.bundle(), None);
        assert_eq!(domain.snapshot().bundle_changed_at, None);
        domain.replace(
            CheckedSource::BundleEndpoint {
                url: "https://e.example/b".to_owned(),
                bundle,
            },
            NOW,
        );
        assert_eq!(domain.bundle_endpoint_url(), Some("https://e.example/b"));
        assert_eq!(
            domain.snapshot().next_refresh_at,
            Some(NOW + DEFAULT_REFRESH)
        );
        assert!(TrustDomain::add("Upper", CheckedSource::Mesh, NOW).is_err());
        for source in [
            TrustSource::Uploaded,
            TrustSource::BundleEndpoint,
            TrustSource::Mesh,
        ] {
            assert_eq!(TrustSource::parse(source.as_str()).expect("read"), source);
        }
        assert!(TrustSource::parse("other").is_err());
    }
}
