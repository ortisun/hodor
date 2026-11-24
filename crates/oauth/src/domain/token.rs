//! The token endpoint: what a client presents there, how its assertion is
//! checked, and the access token it is given.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Token endpoint and
//! client authentication".

use crate::domain::authorization::AuthorizationCode;
use crate::domain::client::{AuthenticationMethod, Client, ClientId};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::{
    GroupId, OrganizationId, RandomSource, Secret, SignatureAlgorithm, SignatureVerifier, Timestamp,
};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::fmt;
use time::Duration;

/// The `client_assertion_type` of an assertion signed by the client
/// (RFC 7523, section 2.2).
pub const ASSERTION_TYPE: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
/// The largest assertion read.
pub const MAX_ASSERTION_BYTES: usize = 8192;
/// The furthest ahead an assertion may expire.
pub const ASSERTION_LONGEST_AHEAD: Duration = Duration::minutes(5);
/// What is allowed for the clocks of client and server to differ.
pub const CLOCK_ALLOWANCE: Duration = Duration::seconds(60);
/// The longest `jti` of an assertion.
pub const MAX_ASSERTION_ID_LENGTH: usize = 255;

/// An error the token endpoint answers with (RFC 6749, section 5.2). The
/// client is told `error` and `description`; `reason` is for Hodor's logs
/// only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenError {
    /// The OAuth error code, such as `invalid_grant`.
    pub error: &'static str,
    /// A description safe to show the client.
    pub description: &'static str,
    /// Why, for the logs.
    pub reason: &'static str,
}

impl TokenError {
    const fn new(error: &'static str, description: &'static str, reason: &'static str) -> Self {
        Self {
            error,
            description,
            reason,
        }
    }

    /// The request is malformed.
    #[must_use]
    pub const fn invalid_request(reason: &'static str) -> Self {
        Self::new("invalid_request", "the request is malformed", reason)
    }

    /// The client could not be authenticated.
    #[must_use]
    pub const fn invalid_client(reason: &'static str) -> Self {
        Self::new(
            "invalid_client",
            "the client could not be authenticated",
            reason,
        )
    }

    /// The code, or the grant behind it, cannot be used.
    #[must_use]
    pub const fn invalid_grant(reason: &'static str) -> Self {
        Self::new(
            "invalid_grant",
            "the authorization grant is not valid",
            reason,
        )
    }

    /// The client may not use this grant.
    #[must_use]
    pub const fn unauthorized_client(reason: &'static str) -> Self {
        Self::new(
            "unauthorized_client",
            "the client may not use this grant",
            reason,
        )
    }

    /// A scope asked for cannot be given.
    #[must_use]
    pub const fn invalid_scope(reason: &'static str) -> Self {
        Self::new("invalid_scope", "a scope asked for cannot be given", reason)
    }

    /// The resource asked for cannot be given (RFC 8707).
    #[must_use]
    pub const fn invalid_target(reason: &'static str) -> Self {
        Self::new(
            "invalid_target",
            "the resource asked for cannot be given",
            reason,
        )
    }

    /// The grant is not one this endpoint answers.
    #[must_use]
    pub const fn unsupported_grant_type(reason: &'static str) -> Self {
        Self::new(
            "unsupported_grant_type",
            "the grant type is not supported",
            reason,
        )
    }

    /// Hodor could not answer.
    #[must_use]
    pub const fn server_error(reason: &'static str) -> Self {
        Self::new("server_error", "the server could not answer", reason)
    }

    /// Whether it is `invalid_client`, answered with status 401.
    #[must_use]
    pub fn is_invalid_client(&self) -> bool {
        self.error == "invalid_client"
    }

    /// Whether it is `server_error`, answered with status 500.
    #[must_use]
    pub fn is_server_error(&self) -> bool {
        self.error == "server_error"
    }
}

/// How the client says who it is.
pub enum PresentedClient {
    /// A secret, in the `Authorization` header or in the form.
    Secret {
        /// The `client_id` it names.
        client_id: String,
        /// The secret.
        secret: Secret<String>,
        /// `client_secret_basic` or `client_secret_post`, by where it was.
        method: AuthenticationMethod,
    },
    /// An assertion the client signed (`private_key_jwt`).
    Assertion {
        /// The assertion.
        assertion: String,
        /// The `client_id` of the form, if one was given.
        client_id: Option<String>,
    },
    /// Only its identifier: a public client.
    Public {
        /// The `client_id` it names.
        client_id: String,
    },
}

impl fmt::Debug for PresentedClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Secret {
                client_id, method, ..
            } => f
                .debug_struct("Secret")
                .field("client_id", client_id)
                .field("method", method)
                .finish_non_exhaustive(),
            Self::Assertion { client_id, .. } => f
                .debug_struct("Assertion")
                .field("client_id", client_id)
                .finish_non_exhaustive(),
            Self::Public { client_id } => f
                .debug_struct("Public")
                .field("client_id", client_id)
                .finish(),
        }
    }
}

impl PresentedClient {
    /// The method the request used.
    #[must_use]
    pub const fn method(&self) -> AuthenticationMethod {
        match self {
            Self::Secret { method, .. } => *method,
            Self::Assertion { .. } => AuthenticationMethod::PrivateKeyJwt,
            Self::Public { .. } => AuthenticationMethod::None,
        }
    }
}

/// The grants the token endpoint answers, as the discovery document names
/// them. A grant added to [`GrantRequest`] is added here too.
pub const SUPPORTED_GRANT_TYPES: [&str; 3] =
    ["authorization_code", "refresh_token", "client_credentials"];

/// What the client asks for.
#[derive(Debug, Clone)]
pub enum GrantRequest {
    /// Tokens for an authorization code.
    AuthorizationCode {
        /// The code.
        code: String,
        /// The redirect address the code was sent to.
        redirect_uri: String,
        /// The PKCE verifier, when the code has a challenge.
        verifier: Option<String>,
    },
    /// New tokens for a refresh token.
    RefreshToken {
        /// The refresh token.
        refresh_token: Secret<String>,
        /// The scopes asked for, when fewer than the family's.
        scope: Option<String>,
        /// The one resource asked for, when fewer than the family's.
        resource: Option<String>,
    },
    /// A token for the client itself.
    ClientCredentials {
        /// The scopes asked for.
        scope: Option<String>,
        /// The one resource asked for.
        resource: Option<String>,
    },
}

impl PartialEq for GrantRequest {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::AuthorizationCode {
                    code,
                    redirect_uri,
                    verifier,
                },
                Self::AuthorizationCode {
                    code: other_code,
                    redirect_uri: other_redirect_uri,
                    verifier: other_verifier,
                },
            ) => {
                code == other_code
                    && redirect_uri == other_redirect_uri
                    && verifier == other_verifier
            }
            (
                Self::RefreshToken {
                    refresh_token,
                    scope,
                    resource,
                },
                Self::RefreshToken {
                    refresh_token: other_token,
                    scope: other_scope,
                    resource: other_resource,
                },
            ) => {
                refresh_token.expose() == other_token.expose()
                    && scope == other_scope
                    && resource == other_resource
            }
            (
                Self::ClientCredentials { scope, resource },
                Self::ClientCredentials {
                    scope: other_scope,
                    resource: other_resource,
                },
            ) => scope == other_scope && resource == other_resource,
            _ => false,
        }
    }
}

impl Eq for GrantRequest {}

/// A request to the token endpoint, read but not yet checked against any
/// client.
#[derive(Debug)]
pub struct TokenRequest {
    /// How the client says who it is.
    pub client: PresentedClient,
    /// What it asks for.
    pub grant: GrantRequest,
}

/// The identifier and the secret of an `Authorization: Basic` header,
/// already decoded by the HTTP layer.
pub struct BasicCredentials {
    /// The client identifier.
    pub client_id: String,
    /// The secret.
    pub secret: Secret<String>,
}

impl fmt::Debug for BasicCredentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BasicCredentials")
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl TokenRequest {
    /// Reads a request from its form and the credentials of its
    /// `Authorization: Basic` header.
    ///
    /// # Errors
    ///
    /// Returns the error to answer with: `invalid_request` for a malformed
    /// request, `invalid_client` for one that does not say who the client
    /// is, `unsupported_grant_type` for a grant this endpoint does not
    /// answer.
    pub fn parse(
        basic: Option<BasicCredentials>,
        pairs: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, TokenError> {
        let mut form: Map<String, Value> = Map::new();
        let mut seen = BTreeSet::new();
        for (name, value) in pairs {
            if !seen.insert(name.clone()) {
                return Err(TokenError::invalid_request("a parameter is given twice"));
            }
            form.insert(name, Value::String(value));
        }
        let text = |name: &str| form.get(name).and_then(Value::as_str).map(str::to_owned);
        let client = presented_client(basic, &text)?;
        let grant = match text("grant_type").as_deref() {
            None => return Err(TokenError::invalid_request("grant_type is missing")),
            Some("authorization_code") => GrantRequest::AuthorizationCode {
                code: text("code").ok_or(TokenError::invalid_request("code is missing"))?,
                redirect_uri: text("redirect_uri")
                    .ok_or(TokenError::invalid_request("redirect_uri is missing"))?,
                verifier: text("code_verifier"),
            },
            Some("refresh_token") => GrantRequest::RefreshToken {
                refresh_token: Secret::from(
                    text("refresh_token")
                        .ok_or(TokenError::invalid_request("refresh_token is missing"))?,
                ),
                scope: text("scope"),
                resource: text("resource"),
            },
            Some("client_credentials") => GrantRequest::ClientCredentials {
                scope: text("scope"),
                resource: text("resource"),
            },
            Some(_) => {
                return Err(TokenError::unsupported_grant_type("the grant is unknown"));
            }
        };
        Ok(Self { client, grant })
    }
}

pub(crate) fn presented_client(
    basic: Option<BasicCredentials>,
    text: &impl Fn(&str) -> Option<String>,
) -> Result<PresentedClient, TokenError> {
    let form_id = text("client_id");
    let form_secret = text("client_secret");
    let assertion = text("client_assertion");
    let assertion_type = text("client_assertion_type");
    let has_assertion = assertion.is_some() || assertion_type.is_some();
    let ways = usize::from(basic.is_some())
        + usize::from(form_secret.is_some())
        + usize::from(has_assertion);
    if ways > 1 {
        return Err(TokenError::invalid_request(
            "the client proves who it is in more than one way",
        ));
    }
    if let Some(basic) = basic {
        if form_id
            .as_deref()
            .is_some_and(|given| given != basic.client_id)
        {
            return Err(TokenError::invalid_request(
                "client_id names another client than the Authorization header",
            ));
        }
        return Ok(PresentedClient::Secret {
            client_id: basic.client_id,
            secret: basic.secret,
            method: AuthenticationMethod::ClientSecretBasic,
        });
    }
    if let Some(secret) = form_secret {
        let client_id = form_id.ok_or(TokenError::invalid_client(
            "client_secret without client_id",
        ))?;
        return Ok(PresentedClient::Secret {
            client_id,
            secret: Secret::from(secret),
            method: AuthenticationMethod::ClientSecretPost,
        });
    }
    if has_assertion {
        if assertion_type.as_deref() != Some(ASSERTION_TYPE) {
            return Err(TokenError::invalid_request(
                "client_assertion_type is missing or unknown",
            ));
        }
        let assertion =
            assertion.ok_or(TokenError::invalid_request("client_assertion is missing"))?;
        return Ok(PresentedClient::Assertion {
            assertion,
            client_id: form_id,
        });
    }
    match form_id {
        Some(client_id) => Ok(PresentedClient::Public { client_id }),
        None => Err(TokenError::invalid_client(
            "the request does not say which client it is",
        )),
    }
}

pub(crate) fn decode_json(part: &str) -> Option<Map<String, Value>> {
    let bytes = URL_SAFE_NO_PAD.decode(part).ok()?;
    match serde_json::from_slice(&bytes).ok()? {
        Value::Object(object) => Some(object),
        _ => None,
    }
}

/// The client an assertion says it is from, read before its signature is
/// checked, only to know whose keys to check it with.
#[must_use]
pub fn assertion_issuer(assertion: &str) -> Option<String> {
    if assertion.len() > MAX_ASSERTION_BYTES {
        return None;
    }
    let mut parts = assertion.split('.');
    let _header = parts.next()?;
    let claims = decode_json(parts.next()?)?;
    claims.get("iss").and_then(Value::as_str).map(str::to_owned)
}

/// An assertion whose every check passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedAssertion {
    /// Its `jti`, to be remembered until it expires.
    pub assertion_id: String,
    /// When it expires.
    pub expires_at: Timestamp,
}

fn seconds(claims: &Map<String, Value>, name: &str) -> Option<i64> {
    claims.get(name).and_then(Value::as_i64)
}

fn at(seconds: i64) -> Option<Timestamp> {
    Timestamp::from_unix_timestamp(seconds).ok()
}

/// What an assertion is checked against: who must have signed it, and for
/// whom.
#[derive(Debug, Clone, Copy)]
pub struct AssertionAudience<'a> {
    /// The tenant's issuer.
    pub issuer: &'a str,
    /// The address of the token endpoint.
    pub token_endpoint: &'a str,
    /// The address of the endpoint the assertion was sent to: the token
    /// endpoint itself, or the revocation or introspection endpoint.
    pub endpoint: &'a str,
}

/// Checks a client's assertion (RFC 7523), in the order the specification
/// gives. Nothing it says is used before its signature has been checked.
///
/// # Errors
///
/// Returns why the assertion is refused; the client is told
/// `invalid_client` whatever the reason.
pub fn check_assertion(
    assertion: &str,
    client: &Client,
    audience: AssertionAudience<'_>,
    now: Timestamp,
    verifier: &dyn SignatureVerifier,
) -> Result<CheckedAssertion, &'static str> {
    if assertion.len() > MAX_ASSERTION_BYTES {
        return Err("the assertion is too large");
    }
    let parts: Vec<&str> = assertion.split('.').collect();
    let [header_part, claims_part, signature_part] = parts.as_slice() else {
        return Err("the assertion is not three parts");
    };
    let header = decode_json(header_part).ok_or("the assertion's header is malformed")?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_part)
        .map_err(|_| "the assertion's signature is malformed")?;
    let algorithm = header
        .get("alg")
        .and_then(Value::as_str)
        .and_then(SignatureAlgorithm::from_name)
        .ok_or("the assertion names an algorithm that is not accepted")?;
    let keys = &client.snapshot().keys;
    let candidates: Vec<_> = match header.get("kid") {
        Some(Value::String(kid)) => keys
            .iter()
            .filter(|key| &key.key_id == kid)
            .filter_map(|key| key.verifying_key(algorithm))
            .collect(),
        Some(_) => return Err("the assertion's kid is not text"),
        None => keys
            .iter()
            .filter_map(|key| key.verifying_key(algorithm))
            .collect(),
    };
    let key = match candidates.as_slice() {
        [key] => key,
        [] => return Err("no key of the client fits the assertion"),
        _ => return Err("the assertion does not say which of the client's keys signed it"),
    };
    let signed = format!("{header_part}.{claims_part}");
    if !verifier.verify(algorithm, key, signed.as_bytes(), &signature) {
        return Err("the assertion's signature does not verify");
    }

    // Only now is anything the assertion says used.
    let claims = decode_json(claims_part).ok_or("the assertion's claims are malformed")?;
    let client_id = client.id().to_string();
    let text = |name: &str| claims.get(name).and_then(Value::as_str);
    if text("iss") != Some(client_id.as_str()) || text("sub") != Some(client_id.as_str()) {
        return Err("the assertion is not from this client");
    }
    let audiences: Vec<&str> = match claims.get("aud") {
        Some(Value::String(one)) => vec![one.as_str()],
        Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
        _ => Vec::new(),
    };
    if !audiences.iter().any(|given| {
        *given == audience.issuer
            || *given == audience.token_endpoint
            || *given == audience.endpoint
    }) {
        return Err("the assertion is not for this server");
    }
    let expires_at = seconds(&claims, "exp")
        .and_then(at)
        .ok_or("the assertion does not say when it expires")?;
    if expires_at + CLOCK_ALLOWANCE <= now {
        return Err("the assertion has expired");
    }
    if expires_at > now + ASSERTION_LONGEST_AHEAD + CLOCK_ALLOWANCE {
        return Err("the assertion expires too far ahead");
    }
    for name in ["nbf", "iat"] {
        if let Some(value) = claims.get(name) {
            let moment = value
                .as_i64()
                .and_then(at)
                .ok_or("the assertion has a malformed time")?;
            if moment > now + CLOCK_ALLOWANCE {
                return Err("the assertion is from the future");
            }
        }
    }
    let assertion_id = text("jti")
        .filter(|jti| !jti.is_empty() && jti.chars().count() <= MAX_ASSERTION_ID_LENGTH)
        .ok_or("the assertion has no usable jti")?
        .to_owned();
    Ok(CheckedAssertion {
        assertion_id,
        expires_at,
    })
}

/// What the access token says, before it is signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTokenClaims {
    /// Its `jti`.
    pub token_id: String,
    /// When it expires.
    pub expires_at: Timestamp,
    /// The claims, as JSON.
    pub claims: Value,
}

/// Whom an access token is about and what it allows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenSubject {
    /// Its `sub`: a user's identifier, or the client's for client
    /// credentials.
    pub subject: String,
    /// The scopes.
    pub scopes: Vec<String>,
    /// The audiences; none means the issuer itself.
    pub audiences: Vec<String>,
    /// When the person signed in; none for client credentials.
    pub signed_in_at: Option<Timestamp>,
    /// The tenant's level the sign-in reached, its `acr`; none for client
    /// credentials and for a sign-in that reached no level.
    pub acr: Option<String>,
    /// The methods of the sign-in, for its `amr`; none for client
    /// credentials.
    pub methods: Vec<String>,
    /// The organization the person signed in for, its `org_id`.
    pub organization: Option<OrganizationId>,
    /// The person's effective groups when the scopes hold `groups`; none
    /// otherwise.
    pub groups: Option<Vec<GroupId>>,
}

/// The most groups an access token names. A person in more gets a token
/// without `groups`, and reads them all at UserInfo.
pub(crate) const MOST_GROUPS_IN_A_TOKEN: usize = 100;

impl TokenSubject {
    /// The person and the grant of a redeemed `code`.
    #[must_use]
    pub fn of_code(code: &AuthorizationCode) -> Self {
        Self {
            subject: code.user_id.to_string(),
            scopes: code.scopes.clone(),
            audiences: code.audiences.clone(),
            signed_in_at: Some(code.signed_in_at),
            acr: code.acr.clone(),
            methods: code.methods.clone(),
            organization: None,
            groups: None,
        }
    }
}

/// The claims of the access token for a redeemed `code` (RFC 9068).
#[must_use]
pub fn access_token_claims(
    issuer: &str,
    code: &AuthorizationCode,
    client_id: ClientId,
    lifetime: Duration,
    now: Timestamp,
    random: &dyn RandomSource,
) -> AccessTokenClaims {
    claims_for(
        issuer,
        &TokenSubject::of_code(code),
        client_id,
        lifetime,
        now,
        random,
    )
}

/// The claims of an access token about `subject` (RFC 9068).
#[must_use]
pub fn claims_for(
    issuer: &str,
    subject: &TokenSubject,
    client_id: ClientId,
    lifetime: Duration,
    now: Timestamp,
    random: &dyn RandomSource,
) -> AccessTokenClaims {
    let mut bytes = [0_u8; 16];
    random.fill(&mut bytes);
    let token_id = URL_SAFE_NO_PAD.encode(bytes);
    let expires_at = now + lifetime;
    // With `openid`, the issuer is an audience too, so that the token
    // reads UserInfo.
    let mut audiences = subject.audiences.clone();
    if subject.scopes.iter().any(|scope| scope == "openid")
        && !audiences.iter().any(|audience| audience == issuer)
    {
        audiences.push(issuer.to_owned());
    }
    let audience = match audiences.as_slice() {
        [] => json!(issuer),
        [one] => json!(one),
        many => json!(many),
    };
    let mut claims = json!({
        "iss": issuer,
        "sub": subject.subject,
        "aud": audience,
        "client_id": client_id.to_string(),
        "scope": subject.scopes.join(" "),
        "iat": now.unix_timestamp(),
        "exp": expires_at.unix_timestamp(),
        "jti": token_id,
    });
    if let (Some(signed_in_at), Some(object)) = (subject.signed_in_at, claims.as_object_mut()) {
        object.insert("auth_time".to_owned(), json!(signed_in_at.unix_timestamp()));
    }
    // The authentication claims of RFC 9068, section 2.2.1: the level the
    // methods of the sign-in reached, and the methods.
    if let Some(acr) = &subject.acr {
        claims["acr"] = json!(acr);
    }
    let amr = crate::domain::openid::authentication_methods(&subject.methods);
    if !amr.is_empty() {
        claims["amr"] = json!(amr);
    }
    if let Some(organization) = subject.organization {
        claims["org_id"] = json!(organization.to_string());
    }
    if let Some(groups) = &subject.groups
        && groups.len() <= MOST_GROUPS_IN_A_TOKEN
    {
        let names: Vec<String> = groups.iter().map(ToString::to_string).collect();
        claims["groups"] = json!(names);
    }
    AccessTokenClaims {
        token_id,
        expires_at,
        claims,
    }
}

/// The header of an access token signed by the key version `key_id` with
/// `algorithm`.
#[must_use]
pub(crate) fn access_token_header(algorithm: &str, key_id: &str) -> Value {
    json!({"alg": algorithm, "typ": "at+jwt", "kid": key_id})
}

/// What a JSON Web Signature signs: the header and the claims, each as
/// base64url.
#[must_use]
pub(crate) fn signing_input(header: &Value, claims: &Value) -> String {
    format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(header.to_string()),
        URL_SAFE_NO_PAD.encode(claims.to_string())
    )
}

/// The compact JSON Web Signature of `signing_input` and its signature.
#[must_use]
pub(crate) fn compact(signing_input: &[u8], signature: &[u8]) -> String {
    format!(
        "{}.{}",
        String::from_utf8_lossy(signing_input),
        URL_SAFE_NO_PAD.encode(signature)
    )
}

#[cfg(test)]
mod tests;
