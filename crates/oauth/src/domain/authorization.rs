//! The authorization endpoint's rules: what makes a request acceptable,
//! whether the person must sign in, the pending request that waits for
//! them, the grant, and the authorization code with its redemption.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Authorization
//! endpoint".

use crate::domain::application::Application;
use crate::domain::client::{Client, ClientId, GrantType};
use crate::domain::event::OauthEvent;
use crate::domain::resource_server::{OPENID_SCOPES, ResourceServer};
use crate::domain::text::is_scope;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::{Digest, DomainError, RandomSource, Secret, Timestamp, UserId};
use hodor_session::api::SessionId;
use serde::{Deserialize, Serialize};
use std::fmt;
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies a pending authorization request. Kept in a cookie with
    /// the secret that binds the request to its browser.
    PendingAuthorizationId
);

hodor_kernel::define_id!(
    /// Identifies a grant: that a person let a client act for them.
    GrantId
);

/// How long an authorization code lives.
pub const CODE_LIFETIME: Duration = Duration::seconds(60);
/// How long a request waits for its person to sign in: the life of a
/// sign-in.
pub const PENDING_LIFETIME: Duration = Duration::minutes(10);
/// The most `resource` values one request may name.
pub const MAX_RESOURCES: usize = 10;
/// The longest `state` or `nonce` accepted.
const MAX_OPAQUE_LENGTH: usize = 1024;
/// The longest `login_hint`, `ui_locales` or `acr_values` accepted.
const MAX_HINT_LENGTH: usize = 255;
/// The largest `max_age` accepted: a year, in seconds.
const MAX_AGE_SECONDS: u32 = 31_536_000;
/// The length of a code challenge made with S256: a SHA-256 digest in
/// base64url without padding.
const CHALLENGE_LENGTH: usize = 43;
/// The length of a code, and of a pending request's secret: 32 bytes in
/// base64url without padding.
pub(crate) const TOKEN_LENGTH: usize = 43;

/// The parameters of an authorization request, as they arrived, in order.
/// A parameter sent without a value is treated as if it were omitted, as
/// RFC 6749 requires.
#[derive(Debug, Clone, Default)]
pub struct AuthorizationParameters {
    pairs: Vec<(String, String)>,
}

enum Given<'a> {
    Absent,
    Once(&'a str),
    Repeated,
}

impl AuthorizationParameters {
    /// The parameters from name and value pairs, such as a decoded query.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            pairs: pairs
                .into_iter()
                .filter(|(_, value)| !value.is_empty())
                .collect(),
        }
    }

    fn given(&self, name: &str) -> Given<'_> {
        let mut found = self.pairs.iter().filter(|(key, _)| key == name);
        match (found.next(), found.next()) {
            (None, _) => Given::Absent,
            (Some((_, value)), None) => Given::Once(value),
            (Some(_), Some(_)) => Given::Repeated,
        }
    }

    fn all(&self, name: &str) -> Vec<&str> {
        self.pairs
            .iter()
            .filter(|(key, _)| key == name)
            .map(|(_, value)| value.as_str())
            .collect()
    }

    fn once(&self, name: &str) -> Option<&str> {
        match self.given(name) {
            Given::Once(value) => Some(value),
            Given::Absent | Given::Repeated => None,
        }
    }

    fn any_repeated(&self) -> bool {
        self.pairs.iter().enumerate().any(|(index, (name, _))| {
            name != "resource"
                && self.pairs[index + 1..]
                    .iter()
                    .any(|(later, _)| later == name)
        })
    }

    /// The `client_id`, if it was given once and is the identifier of a
    /// client at all. Which tenant has it is for the store to say.
    #[must_use]
    pub fn client_id(&self) -> Option<ClientId> {
        self.once("client_id")?.parse().ok()
    }
}

/// A request that passed every check: what the code will be issued for.
/// Stored as it is while the person signs in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizationRequest {
    /// The client that asked.
    pub client_id: ClientId,
    /// Where the answer goes: one of the client's redirect addresses.
    pub redirect_uri: String,
    /// The scopes asked for, in the order given, without repeats.
    pub scopes: Vec<String>,
    /// The audiences of the resource servers the tokens will be for.
    pub audiences: Vec<String>,
    /// The S256 code challenge, when the client sent one.
    pub code_challenge: Option<String>,
    /// What the client wants back, untouched.
    pub state: Option<String>,
    /// For the ID token of Issue-59.
    pub nonce: Option<String>,
    /// The values of `prompt` that were given.
    pub prompt: Vec<String>,
    /// The most seconds since the person signed in that the client accepts.
    pub max_age: Option<u32>,
    /// Kept for Issue-59.
    pub login_hint: Option<String>,
    /// Kept for Issue-59.
    pub ui_locales: Option<String>,
    /// The levels asked for, separated by spaces, as given.
    pub acr_values: Option<String>,
}

/// An error that may be sent back to the client at its redirect address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationError {
    /// The trusted redirect address it is sent to.
    pub redirect_uri: String,
    /// The `error` of RFC 6749.
    pub error: &'static str,
    /// The `error_description`.
    pub description: &'static str,
    /// The `state` of the request, when it had one that could be read.
    pub state: Option<String>,
}

/// Why a request is refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthorizationRefusal {
    /// The client or its redirect address is not known to be genuine, so
    /// nothing is sent there: Hodor answers with a page of its own. Holds
    /// the code of the reason.
    NotRedirectable(&'static str),
    /// Sent back to the client at its redirect address.
    Redirect(AuthorizationError),
}

fn is_printable(value: &str) -> bool {
    value.bytes().all(|b| (0x20..=0x7e).contains(&b))
}

pub(crate) fn is_base64url(value: &str) -> bool {
    value
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Whether `value` is an absolute address without a fragment, as RFC 8707
/// requires of a `resource`.
fn is_absolute_without_fragment(value: &str) -> bool {
    let Some((scheme, rest)) = value.split_once(':') else {
        return false;
    };
    let mut letters = scheme.bytes();
    letters.next().is_some_and(|b| b.is_ascii_alphabetic())
        && letters.all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'-' || b == b'.')
        && !rest.is_empty()
        && !value.contains('#')
        && is_printable(value)
        && !value.contains(' ')
}

const PROMPTS: [&str; 4] = ["none", "login", "consent", "select_account"];

/// Checks a request in the order the specification gives, the first
/// failure deciding the answer. `client` is the client its `client_id`
/// names in this tenant, `application` that client's application, and
/// `servers` the tenant's resource servers.
///
/// # Errors
///
/// Returns the refusal: a page of Hodor's own until the redirect address
/// is trusted, an error at that address after.
pub fn check_request(
    parameters: &AuthorizationParameters,
    client: Option<&Client>,
    application: Option<&Application>,
    servers: &[ResourceServer],
) -> Result<AuthorizationRequest, AuthorizationRefusal> {
    let unknown = AuthorizationRefusal::NotRedirectable("oauth.authorization_client_unknown");
    let (client, application) = match (parameters.given("client_id"), client, application) {
        (Given::Once(named), Some(client), Some(application))
            if named.parse::<ClientId>().ok() == Some(client.id())
                && client.is_enabled()
                && application.is_enabled()
                && client.application_id() == application.id()
                && client
                    .snapshot()
                    .settings
                    .grant_types
                    .contains(&GrantType::AuthorizationCode) =>
        {
            (client, application)
        }
        _ => return Err(unknown),
    };
    let redirect_uri = match parameters.given("redirect_uri") {
        Given::Once(uri) if client.accepts_redirect_uri(uri) => uri.to_owned(),
        Given::Once(_) => {
            return Err(AuthorizationRefusal::NotRedirectable(
                "oauth.authorization_redirect_uri_unregistered",
            ));
        }
        Given::Absent | Given::Repeated => {
            return Err(AuthorizationRefusal::NotRedirectable(
                "oauth.authorization_redirect_uri_missing",
            ));
        }
    };

    // From here on, errors go back to the client. Its state goes with
    // them when it can be read.
    let state = parameters
        .once("state")
        .filter(|value| value.len() <= MAX_OPAQUE_LENGTH && is_printable(value))
        .map(str::to_owned);
    let refuse = |error: &'static str, description: &'static str| {
        AuthorizationRefusal::Redirect(AuthorizationError {
            redirect_uri: redirect_uri.clone(),
            error,
            description,
            state: state.clone(),
        })
    };
    let invalid = |description: &'static str| refuse("invalid_request", description);

    if parameters.any_repeated() {
        return Err(invalid("a parameter is given more than once"));
    }
    if parameters.once("request").is_some() {
        return Err(refuse(
            "request_not_supported",
            "request objects are not supported",
        ));
    }
    if parameters.once("request_uri").is_some() {
        return Err(refuse(
            "request_uri_not_supported",
            "request objects are not supported",
        ));
    }
    if parameters
        .once("response_mode")
        .is_some_and(|mode| mode != "query")
    {
        return Err(invalid("the only response mode is query"));
    }
    match parameters.once("response_type") {
        None => return Err(invalid("response_type is required")),
        Some("code") => {}
        Some(_) => {
            return Err(refuse(
                "unsupported_response_type",
                "the only response type is code",
            ));
        }
    }

    let code_challenge = match (
        parameters.once("code_challenge"),
        parameters.once("code_challenge_method"),
    ) {
        (None, _) if client.snapshot().settings.require_pkce => {
            return Err(invalid("this client must send a code challenge"));
        }
        (None, None) => None,
        (None, Some(_)) => return Err(invalid("a method was given without a code challenge")),
        (Some(_), method) if method != Some("S256") => {
            return Err(invalid("the code challenge method must be S256"));
        }
        (Some(challenge), _) if challenge.len() != CHALLENGE_LENGTH || !is_base64url(challenge) => {
            return Err(invalid("the code challenge is not an S256 challenge"));
        }
        (Some(challenge), _) => Some(challenge.to_owned()),
    };

    if parameters
        .once("state")
        .is_some_and(|value| value.len() > MAX_OPAQUE_LENGTH || !is_printable(value))
    {
        return Err(invalid(
            "state is too long or holds characters that are not printable",
        ));
    }
    let nonce = parameters.once("nonce").map(str::to_owned);
    if nonce
        .as_deref()
        .is_some_and(|value| value.len() > MAX_OPAQUE_LENGTH || !is_printable(value))
    {
        return Err(invalid(
            "nonce is too long or holds characters that are not printable",
        ));
    }

    let prompt: Vec<String> = parameters
        .once("prompt")
        .map(|value| {
            value
                .split(' ')
                .filter(|v| !v.is_empty())
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default();
    if prompt
        .iter()
        .any(|value| !PROMPTS.contains(&value.as_str()))
        || (prompt.iter().any(|value| value == "none") && prompt.len() > 1)
    {
        return Err(invalid(
            "prompt holds an unknown value, or none with another",
        ));
    }
    let max_age = match parameters.once("max_age") {
        None => None,
        Some(value) => match value.parse::<u32>() {
            Ok(seconds)
                if seconds <= MAX_AGE_SECONDS && value.bytes().all(|b| b.is_ascii_digit()) =>
            {
                Some(seconds)
            }
            _ => return Err(invalid("max_age is not a number of seconds")),
        },
    };
    let hint = |name: &str| -> Result<Option<String>, AuthorizationRefusal> {
        match parameters.once(name) {
            Some(value) if value.len() > MAX_HINT_LENGTH || !is_printable(value) => Err(invalid(
                "login_hint, ui_locales and acr_values hold at most 255 characters",
            )),
            value => Ok(value.map(str::to_owned)),
        }
    };
    let login_hint = hint("login_hint")?;
    let ui_locales = hint("ui_locales")?;
    let acr_values = hint("acr_values")?;

    // Scopes and the resource servers they are for.
    let mut scopes: Vec<String> = Vec::new();
    for scope in parameters.once("scope").unwrap_or_default().split(' ') {
        if !scope.is_empty() && !scopes.iter().any(|known| known == scope) {
            scopes.push(scope.to_owned());
        }
    }
    let allowed = &client.snapshot().settings.allowed_scopes;
    if scopes.is_empty()
        || scopes
            .iter()
            .any(|scope| !is_scope(scope) || !allowed.contains(scope))
    {
        return Err(refuse(
            "invalid_scope",
            "a scope is missing, or one is not allowed to this client",
        ));
    }
    let resources = parameters.all("resource");
    if resources.len() > MAX_RESOURCES {
        return Err(refuse(
            "invalid_target",
            "at most 10 resources may be named",
        ));
    }
    let mut targets: Vec<&ResourceServer> = Vec::new();
    for resource in &resources {
        if !is_absolute_without_fragment(resource) {
            return Err(refuse(
                "invalid_target",
                "a resource is an absolute address without a fragment",
            ));
        }
        match servers
            .iter()
            .find(|server| server.snapshot().audience.as_str() == *resource)
        {
            Some(server) if !targets.iter().any(|t| t.id() == server.id()) => {
                targets.push(server);
            }
            Some(_) => {}
            None => {
                return Err(refuse(
                    "invalid_target",
                    "a resource is not a resource server of this tenant",
                ));
            }
        }
    }
    let own_scopes: Vec<&String> = scopes
        .iter()
        .filter(|scope| !OPENID_SCOPES.contains(&scope.as_str()))
        .collect();
    if resources.is_empty() {
        for server in servers {
            if own_scopes.iter().any(|scope| server.defines(scope)) {
                targets.push(server);
            }
        }
    }
    if own_scopes
        .iter()
        .any(|scope| !targets.iter().any(|server| server.defines(scope)))
    {
        return Err(refuse(
            "invalid_scope",
            "a scope is defined by no resource server of the request",
        ));
    }

    if !application.snapshot().settings.first_party {
        return Err(refuse(
            "access_denied",
            "only first-party applications are answered until consent can be asked",
        ));
    }

    Ok(AuthorizationRequest {
        client_id: client.id(),
        redirect_uri,
        scopes,
        audiences: targets
            .iter()
            .map(|server| server.snapshot().audience.as_str().to_owned())
            .collect(),
        code_challenge,
        state,
        nonce,
        prompt,
        max_age,
        login_hint,
        ui_locales,
        acr_values,
    })
}

/// A person signed in to the tenant, as the session context says, with
/// what the code issued for them will carry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignedInPerson {
    /// Who.
    pub user_id: UserId,
    /// In which session.
    pub session_id: SessionId,
    /// When they last proved something that counts.
    pub signed_in_at: Timestamp,
    /// The methods that count, the `amr` of the tokens.
    pub methods: Vec<String>,
    /// The tenant's level these methods reach, the `acr` of the tokens.
    pub acr: Option<String>,
}

/// One method of a session, with when it was last proven.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    /// The method.
    pub method: String,
    /// When it was last proven.
    pub proven_at: Timestamp,
}

/// What a request needs before a code can be issued.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionDecision {
    /// The session is enough: issue a code now.
    Issue,
    /// The person must sign in first.
    SignIn,
    /// The session is not enough: step it up, carrying these methods.
    StepUp {
        /// The methods of the session that still count.
        carried: Vec<String>,
    },
    /// The client asked that nobody be asked anything, and the session is
    /// not enough: `login_required`.
    LoginRequired,
}

impl AuthorizationRequest {
    fn prompts(&self, value: &str) -> bool {
        self.prompt.iter().any(|given| given == value)
    }

    /// Whether the request asks for a sign-in even when there is a session.
    fn asks_for_a_new_sign_in(&self) -> bool {
        self.prompts("login") || self.prompts("select_account")
    }

    /// The proofs of a session that count for this request: all of them,
    /// or with `max_age` those proven within it. A proof made after
    /// `received_at`, when the request was kept while the person signed in,
    /// was made for this request and always counts.
    #[must_use]
    pub fn counting<'a>(
        &self,
        proofs: &'a [Proof],
        now: Timestamp,
        received_at: Option<Timestamp>,
    ) -> Vec<&'a Proof> {
        proofs
            .iter()
            .filter(|proof| {
                received_at.is_some_and(|received| proof.proven_at >= received)
                    || self.max_age.is_none_or(|seconds| {
                        now - proof.proven_at <= Duration::seconds(i64::from(seconds))
                    })
            })
            .collect()
    }

    /// What the request needs, given the browser's session. `counting`
    /// are the methods of the session that count for the request, and
    /// `enough` says whether they reach the level it asked for. See
    /// `docs/architecture/contexts/oauth.md`, "Assurance and step-up".
    #[must_use]
    pub fn decide(&self, signed_in: bool, counting: &[String], enough: bool) -> SessionDecision {
        let none = self.prompts("none");
        if !signed_in || self.asks_for_a_new_sign_in() {
            if none {
                SessionDecision::LoginRequired
            } else {
                SessionDecision::SignIn
            }
        } else if !counting.is_empty() && enough {
            SessionDecision::Issue
        } else if none {
            SessionDecision::LoginRequired
        } else {
            SessionDecision::StepUp {
                carried: counting.to_vec(),
            }
        }
    }

    /// Whether a person who comes back to a request that arrived at
    /// `received_at` signed in as it asked: a request that asked for a new
    /// sign-in needs a session that signed in after it arrived.
    #[must_use]
    pub fn signed_in_as_asked(&self, signed_in_at: Timestamp, received_at: Timestamp) -> bool {
        !self.asks_for_a_new_sign_in() || signed_in_at >= received_at
    }
}

pub(crate) fn random_token(random: &dyn RandomSource) -> String {
    let mut bytes = [0_u8; 32];
    random.fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub(crate) fn same_bytes(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0_u8, |d, (x, y)| d | (x ^ y)) == 0
}

/// The secret that binds a pending request to its browser. Given to the
/// browser once, in a cookie; only its hash is stored.
pub struct BrowserSecret(Secret<String>);

impl BrowserSecret {
    /// The secret, for the cookie.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for BrowserSecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("BrowserSecret([REDACTED])")
    }
}

/// A checked request waiting for its person to sign in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAuthorization {
    /// Its identifier.
    pub id: PendingAuthorizationId,
    /// The SHA-256 of the browser's secret.
    pub secret_hash: [u8; 32],
    /// The request.
    pub request: AuthorizationRequest,
    /// When it arrived.
    pub received_at: Timestamp,
    /// When it can no longer be resumed.
    pub expires_at: Timestamp,
}

impl PendingAuthorization {
    /// Keeps `request` for its browser, which gets the secret.
    #[must_use]
    pub fn hold(
        request: AuthorizationRequest,
        now: Timestamp,
        random: &dyn RandomSource,
        digest: &dyn Digest,
    ) -> (Self, BrowserSecret) {
        let secret = random_token(random);
        let pending = Self {
            id: PendingAuthorizationId::generate(),
            secret_hash: digest.sha256(secret.as_bytes()),
            request,
            received_at: now,
            expires_at: now + PENDING_LIFETIME,
        };
        (pending, BrowserSecret(Secret::from(secret)))
    }

    /// Whether `presented` is the secret of the browser it was kept for.
    #[must_use]
    pub fn belongs_to(&self, presented: &str, digest: &dyn Digest) -> bool {
        let shaped = presented.len() == TOKEN_LENGTH && is_base64url(presented);
        // Computed whatever the shape, so the time taken says nothing.
        let matches = same_bytes(&digest.sha256(presented.as_bytes()), &self.secret_hash);
        shaped && matches
    }

    /// Whether it can still be resumed at `now`.
    #[must_use]
    pub fn is_live_at(&self, now: Timestamp) -> bool {
        now < self.expires_at
    }
}

/// Whether a grant still stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GrantStatus {
    /// It stands.
    Active,
    /// It was revoked, and everything issued from it with it.
    Revoked,
}

impl GrantStatus {
    /// As stored.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    /// From what was stored.
    ///
    /// # Errors
    ///
    /// Returns `oauth.stored_data_invalid` for an unknown value.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            _ => Err(DomainError::internal(
                "oauth.stored_data_invalid",
                "stored OAuth data could not be read",
            )),
        }
    }
}

/// That a person let a client act for them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Grant {
    /// Its identifier.
    pub id: GrantId,
    /// The client.
    pub client_id: ClientId,
    /// The person.
    pub user_id: UserId,
    /// The session it was made in.
    pub session_id: SessionId,
    /// The scopes.
    pub scopes: Vec<String>,
    /// The audiences.
    pub audiences: Vec<String>,
    /// Whether it stands.
    pub status: GrantStatus,
    /// When it was made.
    pub created_at: Timestamp,
    /// When it was revoked.
    pub revoked_at: Option<Timestamp>,
    /// Why it was revoked, such as `code_reused`.
    pub revocation_reason: Option<String>,
}

impl Grant {
    /// The grant for `request`, made by `person`.
    #[must_use]
    pub fn make(request: &AuthorizationRequest, person: &SignedInPerson, now: Timestamp) -> Self {
        Self {
            id: GrantId::generate(),
            client_id: request.client_id,
            user_id: person.user_id,
            session_id: person.session_id,
            scopes: request.scopes.clone(),
            audiences: request.audiences.clone(),
            status: GrantStatus::Active,
            created_at: now,
            revoked_at: None,
            revocation_reason: None,
        }
    }

    /// Revokes it. Returns the event, or `None` if it was revoked already.
    pub fn revoke(&mut self, reason: &'static str, now: Timestamp) -> Option<OauthEvent> {
        if self.status == GrantStatus::Revoked {
            return None;
        }
        self.status = GrantStatus::Revoked;
        self.revoked_at = Some(now);
        self.revocation_reason = Some(reason.to_owned());
        Some(OauthEvent::GrantRevoked {
            grant_id: self.id,
            client_id: self.client_id,
            reason,
        })
    }
}

/// The SHA-256 of an authorization code; what is stored.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct CodeHash([u8; 32]);

impl CodeHash {
    /// The hash of a code as presented, or `None` when the value does not
    /// have the shape of a code: it cannot be one, and nothing is computed.
    #[must_use]
    pub fn of_presented(value: &str, digest: &dyn Digest) -> Option<Self> {
        (value.len() == TOKEN_LENGTH && is_base64url(value))
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

impl fmt::Debug for CodeHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CodeHash(..)")
    }
}

/// An authorization code itself. Sent once, to the redirect address, and
/// stored nowhere.
pub struct CodeValue(Secret<String>);

impl CodeValue {
    /// The code, for the redirect.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for CodeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CodeValue([REDACTED])")
    }
}

/// What is stored about an authorization code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationCode {
    /// The hash of the code.
    pub hash: CodeHash,
    /// The grant it was issued under.
    pub grant_id: GrantId,
    /// The client it was issued to.
    pub client_id: ClientId,
    /// The redirect address it was sent to.
    pub redirect_uri: String,
    /// The scopes.
    pub scopes: Vec<String>,
    /// The audiences.
    pub audiences: Vec<String>,
    /// The S256 challenge the verifier must meet, if there was one.
    pub code_challenge: Option<String>,
    /// For the ID token.
    pub nonce: Option<String>,
    /// The session the person was signed in with.
    pub session_id: SessionId,
    /// The person.
    pub user_id: UserId,
    /// When they signed in.
    pub signed_in_at: Timestamp,
    /// The methods they signed in with.
    pub methods: Vec<String>,
    /// The tenant's level the methods reached, if any: the `acr` of its
    /// tokens.
    pub acr: Option<String>,
    /// When it was issued.
    pub issued_at: Timestamp,
    /// When it stops being redeemable.
    pub expires_at: Timestamp,
    /// When it was redeemed, if it was.
    pub redeemed_at: Option<Timestamp>,
}

/// What a client presents with a code at the token endpoint.
#[derive(Debug, Clone, Copy)]
pub struct CodePresentation<'a> {
    /// The client that authenticated.
    pub client_id: ClientId,
    /// The `redirect_uri` it sent.
    pub redirect_uri: Option<&'a str>,
    /// The `code_verifier` it sent.
    pub verifier: Option<&'a str>,
}

/// Why a code cannot be redeemed. The client is told `invalid_grant`
/// whatever the reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeRefusal {
    /// It was redeemed before: the grant is revoked.
    AlreadyRedeemed,
    /// Its 60 seconds are over.
    Expired,
    /// Another client presented it.
    OtherClient,
    /// The redirect address differs from the one it was sent to.
    OtherRedirectUri,
    /// It has a challenge and no verifier came.
    VerifierMissing,
    /// The verifier is not 43 to 128 unreserved characters.
    VerifierMalformed,
    /// The verifier does not meet the challenge.
    VerifierWrong,
    /// A verifier came for a code without a challenge.
    VerifierWithoutChallenge,
}

impl CodeRefusal {
    /// The reason, for logs and events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AlreadyRedeemed => "already_redeemed",
            Self::Expired => "expired",
            Self::OtherClient => "other_client",
            Self::OtherRedirectUri => "other_redirect_uri",
            Self::VerifierMissing => "verifier_missing",
            Self::VerifierMalformed => "verifier_malformed",
            Self::VerifierWrong => "verifier_wrong",
            Self::VerifierWithoutChallenge => "verifier_without_challenge",
        }
    }
}

fn is_verifier(value: &str) -> bool {
    (43..=128).contains(&value.len())
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

impl AuthorizationCode {
    /// A code for `request`, under `grant`, for `person`.
    #[must_use]
    pub fn issue(
        grant: &Grant,
        request: &AuthorizationRequest,
        person: &SignedInPerson,
        now: Timestamp,
        random: &dyn RandomSource,
        digest: &dyn Digest,
    ) -> (Self, CodeValue) {
        let value = random_token(random);
        let code = Self {
            hash: CodeHash(digest.sha256(value.as_bytes())),
            grant_id: grant.id,
            client_id: request.client_id,
            redirect_uri: request.redirect_uri.clone(),
            scopes: request.scopes.clone(),
            audiences: request.audiences.clone(),
            code_challenge: request.code_challenge.clone(),
            nonce: request.nonce.clone(),
            session_id: person.session_id,
            user_id: person.user_id,
            signed_in_at: person.signed_in_at,
            methods: person.methods.clone(),
            acr: person.acr.clone(),
            issued_at: now,
            expires_at: now + CODE_LIFETIME,
            redeemed_at: None,
        };
        (code, CodeValue(Secret::from(value)))
    }

    /// Checks a redemption against the rules, in order. Marking the code
    /// redeemed is the store's, so that two redemptions cannot both win.
    ///
    /// # Errors
    ///
    /// Returns why the code cannot be redeemed.
    pub fn check_redemption(
        &self,
        presented: CodePresentation<'_>,
        now: Timestamp,
        digest: &dyn Digest,
    ) -> Result<(), CodeRefusal> {
        if self.redeemed_at.is_some() {
            return Err(CodeRefusal::AlreadyRedeemed);
        }
        if now >= self.expires_at {
            return Err(CodeRefusal::Expired);
        }
        if presented.client_id != self.client_id {
            return Err(CodeRefusal::OtherClient);
        }
        if presented.redirect_uri != Some(self.redirect_uri.as_str()) {
            return Err(CodeRefusal::OtherRedirectUri);
        }
        match (&self.code_challenge, presented.verifier) {
            (None, None) => Ok(()),
            (None, Some(_)) => Err(CodeRefusal::VerifierWithoutChallenge),
            (Some(_), None) => Err(CodeRefusal::VerifierMissing),
            (Some(_), Some(verifier)) if !is_verifier(verifier) => {
                Err(CodeRefusal::VerifierMalformed)
            }
            (Some(challenge), Some(verifier)) => {
                let computed = URL_SAFE_NO_PAD.encode(digest.sha256(verifier.as_bytes()));
                if same_bytes(computed.as_bytes(), challenge.as_bytes()) {
                    Ok(())
                } else {
                    Err(CodeRefusal::VerifierWrong)
                }
            }
        }
    }

    /// The event that says it was issued.
    #[must_use]
    pub const fn issued_event(&self) -> OauthEvent {
        OauthEvent::AuthorizationCodeIssued {
            client_id: self.client_id,
            grant_id: self.grant_id,
            user_id: self.user_id,
        }
    }
}

/// The S256 challenge of `verifier`, as a client computes it.
#[must_use]
pub fn s256_challenge(verifier: &str, digest: &dyn Digest) -> String {
    URL_SAFE_NO_PAD.encode(digest.sha256(verifier.as_bytes()))
}

#[cfg(test)]
mod tests;
