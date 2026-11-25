//! Pushed authorization requests (RFC 9126): a request a client pushes to
//! Hodor first, checked at once and kept as a pending request found by the
//! hash of its reference, and the reference the browser then brings to the
//! authorization endpoint, used once.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Pushed
//! authorization requests", and Decision 0045.

use crate::domain::application::Application;
use crate::domain::authorization::{
    AuthorizationError, AuthorizationParameters, AuthorizationRefusal, AuthorizationRequest, Given,
    MAX_OPAQUE_LENGTH, PendingAuthorizationId, TOKEN_LENGTH, check_request, is_base64url,
    is_printable, random_token,
};
use crate::domain::client::Client;
use crate::domain::request_object::RequestObjectCheck;
use crate::domain::resource_server::ResourceServer;
use crate::domain::response::error_mode;
use crate::domain::token::{BasicCredentials, PresentedClient, TokenError, presented_client};
use hodor_kernel::{Digest, RandomSource, Secret, Timestamp};
use std::collections::BTreeSet;
use std::fmt;
use time::Duration;

/// What every reference Hodor makes starts with (RFC 9126, section 2.2).
pub const REFERENCE_PREFIX: &str = "urn:ietf:params:oauth:request_uri:";
/// The most pushed requests a client has waiting at once; the oldest goes
/// when another arrives.
pub const MAX_PUSHED_PER_CLIENT: usize = 5;
/// How long a pushed request waits for its browser unless the tenant says
/// otherwise.
pub const DEFAULT_PUSHED_LIFETIME: Duration = Duration::seconds(60);
/// The shortest a tenant may let a pushed request wait.
pub const SHORTEST_PUSHED_LIFETIME: Duration = Duration::seconds(10);
/// The longest a pushed request may wait.
pub const LONGEST_PUSHED_LIFETIME: Duration = Duration::seconds(600);
/// The page that answers a reference that cannot be used when the request
/// names none of the client's redirect addresses.
const REFERENCE_PAGE: &str = "oauth.authorization_request_uri_invalid";

/// What the tenant says of pushed requests: how long one waits, and
/// whether every client must push its requests. The HTTP layer reads it
/// from the tenant's settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushedRequestPolicy {
    /// How long a pushed request waits for its browser.
    pub lifetime: Duration,
    /// Whether every client of the tenant must push its requests.
    pub required: bool,
}

impl Default for PushedRequestPolicy {
    fn default() -> Self {
        Self {
            lifetime: DEFAULT_PUSHED_LIFETIME,
            required: false,
        }
    }
}

impl PushedRequestPolicy {
    /// Whether `client` must push its requests: when it says so, or when
    /// its tenant does.
    #[must_use]
    pub fn requires(&self, client: Option<&Client>) -> bool {
        self.required
            || client.is_some_and(|client| client.snapshot().settings.require_pushed_requests)
    }
}

/// The SHA-256 of a reference; what is stored.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ReferenceHash([u8; 32]);

impl ReferenceHash {
    /// The hash of a reference as presented, or `None` when it does not
    /// have the shape of one Hodor makes: it cannot be one, and nothing is
    /// computed.
    #[must_use]
    pub fn of_presented(value: &str, digest: &dyn Digest) -> Option<Self> {
        let random = value.strip_prefix(REFERENCE_PREFIX)?;
        (random.len() == TOKEN_LENGTH && is_base64url(random))
            .then(|| Self(digest.sha256(value.as_bytes())))
    }

    /// Rebuilds a hash read from storage.
    #[must_use]
    pub const fn from_stored(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The bytes, for storage.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for ReferenceHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReferenceHash(..)")
    }
}

/// A reference itself: given to the client once, and stored nowhere.
pub struct RequestReference(Secret<String>);

impl RequestReference {
    /// The reference, for the answer.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for RequestReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RequestReference([REDACTED])")
    }
}

/// A checked request a client pushed, waiting for its browser.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PushedAuthorization {
    /// Its identifier, as every pending request has.
    pub id: PendingAuthorizationId,
    /// The hash of its reference.
    pub reference_hash: ReferenceHash,
    /// The request.
    pub request: AuthorizationRequest,
    /// When it was pushed.
    pub received_at: Timestamp,
    /// When it can no longer be used.
    pub expires_at: Timestamp,
}

impl PushedAuthorization {
    /// Keeps `request` for `lifetime`; the client gets the reference.
    #[must_use]
    pub fn push(
        request: AuthorizationRequest,
        lifetime: Duration,
        now: Timestamp,
        random: &dyn RandomSource,
        digest: &dyn Digest,
    ) -> (Self, RequestReference) {
        let reference = format!("{REFERENCE_PREFIX}{}", random_token(random));
        let pushed = Self {
            id: PendingAuthorizationId::generate(),
            reference_hash: ReferenceHash(digest.sha256(reference.as_bytes())),
            request,
            received_at: now,
            expires_at: now + lifetime,
        };
        (pushed, RequestReference(Secret::from(reference)))
    }

    /// Whether it can still be used at `now`.
    #[must_use]
    pub fn is_live_at(&self, now: Timestamp) -> bool {
        now < self.expires_at
    }
}

/// What the `request_uri` of a request at the authorization endpoint is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reference<'a> {
    /// There is none: the request is the parameters, or its request
    /// object.
    Absent,
    /// It has the shape of a reference Hodor makes.
    Pushed(&'a str),
    /// An address of the client's, read when references at a client's
    /// address are built.
    Address,
    /// Anything else, or given twice.
    Unknown,
}

impl AuthorizationParameters {
    /// What `request_uri` names.
    #[must_use]
    pub fn reference(&self) -> Reference<'_> {
        match self.given("request_uri") {
            Given::Absent => Reference::Absent,
            Given::Repeated => Reference::Unknown,
            Given::Once(value) if value.starts_with(REFERENCE_PREFIX) => Reference::Pushed(value),
            Given::Once(value) if value.starts_with("https://") => Reference::Address,
            Given::Once(_) => Reference::Unknown,
        }
    }
}

/// Where a reference that cannot be used is answered: the redirect
/// address outside when it is one of the client's, with the `state` beside
/// it, in the response mode named beside it, otherwise Hodor's own page.
/// Nothing of the request can be read.
fn refused_reference(
    outside: &AuthorizationParameters,
    client: &Client,
    error: &'static str,
    description: &'static str,
) -> AuthorizationRefusal {
    match outside
        .once("redirect_uri")
        .filter(|uri| client.accepts_redirect_uri(uri))
    {
        Some(redirect_uri) => AuthorizationRefusal::Redirect(AuthorizationError {
            redirect_uri: redirect_uri.to_owned(),
            error,
            description,
            state: outside
                .once("state")
                .filter(|value| value.len() <= MAX_OPAQUE_LENGTH && is_printable(value))
                .map(str::to_owned),
            mode: error_mode(outside.once("response_type"), outside.once("response_mode")),
        }),
        None => AuthorizationRefusal::NotRedirectable(REFERENCE_PAGE),
    }
}

fn scopes(value: &str) -> BTreeSet<&str> {
    value.split(' ').filter(|scope| !scope.is_empty()).collect()
}

/// Reads a request that names a pushed request by reference, for
/// `client`, the trusted client its `client_id` names. `taken` is the
/// pushed request the reference named, of this client and tenant, already
/// taken from storage so that it is used once; `None` when there was none.
///
/// # Errors
///
/// Returns the refusal: `invalid_request_uri` for a reference that cannot
/// be used, `request_uri_not_supported` for an address of the client's,
/// and `invalid_request` for `request` beside it, each at the redirect
/// address outside when it is the client's, otherwise on Hodor's own page;
/// `invalid_request` at the pushed request's redirect address when what
/// OpenID Connect asks to repeat outside says something else.
pub fn check_reference(
    outside: &AuthorizationParameters,
    client: &Client,
    taken: Option<PushedAuthorization>,
    now: Timestamp,
) -> Result<AuthorizationRequest, AuthorizationRefusal> {
    let refuse = |error, description| refused_reference(outside, client, error, description);
    if !matches!(outside.given("request"), Given::Absent) {
        return Err(refuse(
            "invalid_request",
            "request and request_uri cannot be given together",
        ));
    }
    match outside.reference() {
        Reference::Pushed(_) => {}
        Reference::Address => {
            return Err(refuse(
                "request_uri_not_supported",
                "references at a client's address are not supported",
            ));
        }
        Reference::Absent | Reference::Unknown => {
            return Err(refuse(
                "invalid_request_uri",
                "the request_uri is not a reference this server made",
            ));
        }
    }
    let Some(pushed) = taken.filter(|pushed| pushed.request.client_id == client.id()) else {
        return Err(refuse(
            "invalid_request_uri",
            "the request_uri is unknown, used before or of another client",
        ));
    };
    if !pushed.is_live_at(now) {
        return Err(refuse(
            "invalid_request_uri",
            "the pushed request has expired",
        ));
    }
    let request = pushed.request;
    let contradicted = |description: &'static str| {
        AuthorizationRefusal::Redirect(AuthorizationError {
            redirect_uri: request.redirect_uri.clone(),
            error: "invalid_request",
            description,
            state: request.state.clone(),
            mode: request.response_mode,
        })
    };
    match outside.given("response_type") {
        Given::Absent | Given::Once("code") => {}
        Given::Once(_) | Given::Repeated => {
            return Err(contradicted(
                "response_type outside is not the pushed request's",
            ));
        }
    }
    match outside.given("scope") {
        Given::Absent => {}
        Given::Once(given)
            if scopes(given) == request.scopes.iter().map(String::as_str).collect() => {}
        Given::Once(_) | Given::Repeated => {
            return Err(contradicted("scope outside is not the pushed request's"));
        }
    }
    Ok(request)
}

/// The parameters that prove who the client is, and are not parameters of
/// the request it pushes.
const AUTHENTICATION_PARAMETERS: [&str; 3] =
    ["client_secret", "client_assertion", "client_assertion_type"];

/// A request to the pushed request endpoint, read but not yet checked
/// against any client.
#[derive(Debug)]
pub struct PushedRequest {
    /// How the client says who it is.
    pub client: PresentedClient,
    /// The authorization request it pushes.
    pub parameters: AuthorizationParameters,
}

impl PushedRequest {
    /// Reads a request from its form and the credentials of its
    /// `Authorization: Basic` header.
    ///
    /// # Errors
    ///
    /// Returns the error to answer with: `invalid_request` for a parameter
    /// given twice, `resource` excepted, or a client that proves who it is
    /// in more than one way, and `invalid_client` for one that does not say
    /// who it is.
    pub fn parse(
        basic: Option<BasicCredentials>,
        pairs: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, TokenError> {
        let pairs: Vec<(String, String)> = pairs.into_iter().collect();
        let mut seen = BTreeSet::new();
        for (name, _) in &pairs {
            if name != "resource" && !seen.insert(name.as_str()) {
                return Err(TokenError::invalid_request("a parameter is given twice"));
            }
        }
        let text = |name: &str| {
            pairs
                .iter()
                .find(|(given, _)| given == name)
                .map(|(_, value)| value.clone())
        };
        let client = presented_client(basic, &text)?;
        let parameters = AuthorizationParameters::from_pairs(
            pairs
                .into_iter()
                .filter(|(name, _)| !AUTHENTICATION_PARAMETERS.contains(&name.as_str())),
        );
        Ok(Self { client, parameters })
    }
}

/// What the pushed request endpoint answers: the reference, once, and how
/// many seconds it lives.
pub struct PushedAnswer {
    /// The reference, given to the client once.
    pub reference: RequestReference,
    /// How many seconds it lives, as `expires_in`.
    pub expires_in: i64,
}

impl fmt::Debug for PushedAnswer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PushedAnswer")
            .field("expires_in", &self.expires_in)
            .finish_non_exhaustive()
    }
}

/// The life a pushed request is given: the tenant's, kept within the
/// bounds whatever it says.
#[must_use]
pub fn pushed_lifetime(policy: &PushedRequestPolicy) -> Duration {
    policy
        .lifetime
        .clamp(SHORTEST_PUSHED_LIFETIME, LONGEST_PUSHED_LIFETIME)
}

/// Checks a request `client` pushed, the client that proved who it is, of
/// `application`, against the tenant's `servers`: every check of the
/// authorization endpoint, a request object first, answered as the pushed
/// request endpoint answers.
///
/// # Errors
///
/// Returns the error to answer with as JSON: never at a redirect address.
pub fn check_pushed_request(
    parameters: AuthorizationParameters,
    client: &Client,
    application: &Application,
    servers: &[ResourceServer],
    objects: RequestObjectCheck<'_>,
) -> Result<AuthorizationRequest, TokenError> {
    if parameters
        .once("client_id")
        .is_some_and(|named| named != client.id().to_string())
        || matches!(parameters.given("client_id"), Given::Repeated)
    {
        return Err(TokenError::invalid_request(
            "client_id names another client than the one that proved who it is",
        ));
    }
    let parameters = parameters.naming(client.id());
    check_request(
        &parameters,
        Some(client),
        Some(application),
        servers,
        objects,
        false,
    )
    .map_err(|refusal| match refusal {
        AuthorizationRefusal::NotRedirectable("oauth.authorization_client_unknown") => {
            TokenError::unauthorized_client("the client may not use the authorization code")
        }
        AuthorizationRefusal::NotRedirectable("oauth.authorization_request_object_invalid") => {
            TokenError::refused("invalid_request_object", "the request object is not valid")
        }
        AuthorizationRefusal::NotRedirectable(_) => TokenError::invalid_request(
            "redirect_uri is missing, or not one of the client's redirect addresses",
        ),
        AuthorizationRefusal::Redirect(error) => {
            TokenError::refused(error.error, error.description)
        }
    })
}

#[cfg(test)]
mod tests;
