//! The OpenID Provider: the ID token, the methods and assurance it names,
//! the access token checked at UserInfo, the claims UserInfo answers with,
//! and the discovery document.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "OpenID Provider".

use crate::domain::authorization::AuthorizationCode;
use crate::domain::binding::{CONFIRMATION_CLAIM, CertificateThumbprint, check_confirmation};
use crate::domain::client::{ClientId, IdTokenAlgorithm, RequestObjectAlgorithm};
use crate::domain::resource_server::GROUPS_SCOPE;
use crate::domain::token::decode_json;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::{
    Digest, GroupId, OrganizationId, PublicKey, SignatureAlgorithm, SignatureVerifier, Timestamp,
};
use serde_json::{Map, Value, json};
use time::Duration;

/// The scope that makes a request an OpenID Connect one.
pub const OPENID_SCOPE: &str = "openid";
/// The languages the hosted pages are written in.
pub const UI_LOCALES: [&str; 2] = ["en", "pt-BR"];

/// The values of `amr` (RFC 8176) in the order an ID token lists them.
const AMR_ORDER: [&str; 5] = ["pwd", "otp", "pop", "user", "mfa"];

/// What a sign-in by one of Hodor's methods says, in the terms of RFC 8176.
struct MethodFacts {
    amr: &'static [&'static str],
    knows: bool,
    holds: bool,
    both: bool,
}

fn facts(method: &str) -> MethodFacts {
    let none = MethodFacts {
        amr: &[],
        knows: false,
        holds: false,
        both: false,
    };
    match method {
        "password" => MethodFacts {
            amr: &["pwd"],
            knows: true,
            ..none
        },
        "totp" | "recovery_code" => MethodFacts {
            amr: &["otp"],
            holds: true,
            ..none
        },
        "webauthn" => MethodFacts {
            amr: &["pop"],
            holds: true,
            ..none
        },
        "passkey" => MethodFacts {
            amr: &["pop", "user"],
            both: true,
            ..none
        },
        // Hodor did not see how the identity provider signed the person
        // in, so it names nothing. It still counts as something known, as
        // the authentication context's table counts it for the `acr`, so
        // that `mfa` and the `acr` of a token never disagree.
        "external" => MethodFacts {
            knows: true,
            ..none
        },
        // A code or a link sent to the person's mailbox counts as an
        // identity provider does: something known. A code is a one-time
        // password; RFC 8176 has no name for a link.
        "email_code" => MethodFacts {
            amr: &["otp"],
            knows: true,
            ..none
        },
        "email_link" => MethodFacts {
            knows: true,
            ..none
        },
        // A second factor put in use during the sign-in counts as
        // something held, as the authentication context's table counts it;
        // RFC 8176 has no name for binding a factor.
        "enrollment" => MethodFacts {
            holds: true,
            ..none
        },
        // Anything unknown: nothing is claimed about it.
        _ => none,
    }
}

/// Whether the methods of a sign-in proved two kinds of factor.
#[must_use]
pub fn is_multi_factor(methods: &[String]) -> bool {
    let all: Vec<MethodFacts> = methods.iter().map(|method| facts(method)).collect();
    all.iter().any(|fact| fact.both)
        || (all.iter().any(|fact| fact.knows) && all.iter().any(|fact| fact.holds))
}

/// The `amr` of a sign-in by `methods`: each value once, in a fixed order.
/// Empty when no method has a name in RFC 8176.
#[must_use]
pub fn authentication_methods(methods: &[String]) -> Vec<&'static str> {
    let mut named: Vec<&'static str> = methods
        .iter()
        .flat_map(|method| facts(method).amr.iter().copied())
        .collect();
    if is_multi_factor(methods) {
        named.push("mfa");
    }
    AMR_ORDER
        .iter()
        .copied()
        .filter(|value| named.contains(value))
        .collect()
}

/// `at_hash`: the base64url of the left half of the SHA-256 of the access
/// token, for an ID token signed with ES256 (OpenID Connect Core, section
/// 3.1.3.6).
#[must_use]
pub fn access_token_hash(access_token: &str, digest: &dyn Digest) -> String {
    let hash = digest.sha256(access_token.as_bytes());
    URL_SAFE_NO_PAD.encode(&hash[..16])
}

/// Whether `scopes` make an OpenID Connect request.
#[must_use]
pub fn asks_for_openid(scopes: &[String]) -> bool {
    scopes.iter().any(|scope| scope == OPENID_SCOPE)
}

/// The header of an ID token signed by the key version `key_id`.
#[must_use]
pub(crate) fn id_token_header(algorithm: &str, key_id: &str) -> Value {
    json!({"alg": algorithm, "typ": "JWT", "kid": key_id})
}

/// How an ID token names the person and the session: as the client knows
/// them, by their identifiers for a public client and by pairwise ones for
/// a pairwise client.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IdTokenNames<'a> {
    /// Its `sub`.
    pub subject: &'a str,
    /// Its `sid`.
    pub session: &'a str,
}

/// The claims of the ID token for a redeemed `code`, issued with
/// `access_token`, in the `organization` of its grant, naming the person
/// and the session as `names` says.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn id_token_claims(
    issuer: &str,
    code: &AuthorizationCode,
    names: IdTokenNames<'_>,
    organization: Option<OrganizationId>,
    client_id: ClientId,
    lifetime: Duration,
    now: Timestamp,
    access_token: &str,
    digest: &dyn Digest,
) -> Value {
    let mut claims = Map::new();
    claims.insert("iss".to_owned(), json!(issuer));
    claims.insert("sub".to_owned(), json!(names.subject));
    claims.insert("aud".to_owned(), json!(client_id.to_string()));
    claims.insert("iat".to_owned(), json!(now.unix_timestamp()));
    claims.insert("exp".to_owned(), json!((now + lifetime).unix_timestamp()));
    claims.insert(
        "auth_time".to_owned(),
        json!(code.signed_in_at.unix_timestamp()),
    );
    if let Some(nonce) = &code.nonce {
        claims.insert("nonce".to_owned(), json!(nonce));
    }
    if let Some(acr) = &code.acr {
        claims.insert("acr".to_owned(), json!(acr));
    }
    let amr = authentication_methods(&code.methods);
    if !amr.is_empty() {
        claims.insert("amr".to_owned(), json!(amr));
    }
    if let Some(organization) = organization {
        claims.insert("org_id".to_owned(), json!(organization.to_string()));
    }
    claims.insert(
        "at_hash".to_owned(),
        json!(access_token_hash(access_token, digest)),
    );
    // The session, never its token: logout needs to know whether an ID
    // token names the browser's current session.
    claims.insert("sid".to_owned(), json!(names.session));
    Value::Object(claims)
}

/// Why an access token is refused at UserInfo (RFC 6750, section 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BearerRefusal {
    /// The request carries no token: answered without an error code.
    Missing,
    /// The token cannot be used; the reason is for the logs.
    InvalidToken(&'static str),
    /// The token is good but lacks the `openid` scope.
    InsufficientScope,
}

/// An access token whose every check passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckedAccessToken {
    /// Its `sub`: the person as the client knows them. Not read as a user
    /// identifier: the person is found through the token's record.
    pub subject: String,
    /// Its scopes.
    pub scopes: Vec<String>,
    /// Its `jti`, which names its record in the register.
    pub token_id: String,
    /// The client it was issued to, as its `client_id` says.
    pub client_id: String,
    /// The organization of the sign-in, as its `org_id` says.
    pub organization: Option<OrganizationId>,
}

/// What a signed access token of the tenant says, once its shape, header,
/// key, signature, issuer and expiry have been checked. Its audience and
/// scope are not checked: those are for whoever reads it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReadAccessToken {
    /// Its `jti`.
    pub token_id: String,
    /// Its `client_id`.
    pub client_id: String,
    /// Its `sub`: a user's identifier, a pairwise one for a pairwise
    /// client, or a client's.
    pub subject: String,
    /// Its scopes.
    pub scopes: Vec<String>,
    /// Its `aud`, as it was written: one text or a list.
    pub audience: Value,
    /// Its audiences, as a list.
    pub audiences: Vec<String>,
    /// Its `iat`, in seconds.
    pub issued_at: i64,
    /// Its `exp`.
    pub expires_at: Timestamp,
    /// Its `principal_kind`, for the token of a client that acts as a
    /// workload.
    pub principal_kind: Option<String>,
    /// Its `act`, for a token made by exchange.
    pub act: Option<Value>,
    /// Its `auth_time`, in seconds.
    pub auth_time: Option<i64>,
    /// Its `acr`.
    pub acr: Option<String>,
    /// Its `amr`.
    pub amr: Option<Vec<String>>,
    /// Its `org_id`.
    pub organization: Option<OrganizationId>,
    /// Its `cnf`, for a token bound to a certificate. Any value that is
    /// not an object is kept too, so that it is refused rather than taken
    /// for no binding.
    pub confirmation: Option<Value>,
}

impl ReadAccessToken {
    /// Whether the token may be used by a request that came with the
    /// certificate of `presented`: always for a token bound to nothing.
    ///
    /// # Errors
    ///
    /// The reason it may not, for Hodor's log.
    pub fn check_certificate(
        &self,
        presented: Option<&CertificateThumbprint>,
    ) -> Result<(), &'static str> {
        check_confirmation(self.confirmation.as_ref(), presented)
    }
}

/// Reads an access token of the tenant: checks its shape, header, key,
/// signature, issuer and expiry, in that order. Nothing it says is used
/// before its signature has been checked.
///
/// # Errors
///
/// Returns why the token cannot be used, for the logs.
pub fn read_access_token(
    token: &str,
    issuer: &str,
    keys: &[PublishedKey],
    now: Timestamp,
    verifier: &dyn SignatureVerifier,
) -> Result<ReadAccessToken, &'static str> {
    if token.len() > 16 * 1024 {
        return Err("the token is too large");
    }
    let parts: Vec<&str> = token.split('.').collect();
    let [header_part, claims_part, signature_part] = parts.as_slice() else {
        return Err("the token is not three parts");
    };
    let header = decode_json(header_part).ok_or("the header is malformed")?;
    if header.get("typ").and_then(Value::as_str) != Some("at+jwt") {
        return Err("the token is not an access token");
    }
    if header.get("alg").and_then(Value::as_str) != Some("ES256") {
        return Err("the token names another algorithm");
    }
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or("the token names no key")?;
    let key = keys
        .iter()
        .find(|key| key.key_id == kid && key.algorithm == SignatureAlgorithm::Es256)
        .ok_or("the token's key is not published by this tenant")?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_part)
        .map_err(|_| "the signature is malformed")?;
    let signed = format!("{header_part}.{claims_part}");
    if !verifier.verify(key.algorithm, &key.key, signed.as_bytes(), &signature) {
        return Err("the signature does not verify");
    }

    // Only now is anything the token says used.
    let claims = decode_json(claims_part).ok_or("the claims are malformed")?;
    if claims.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err("the token is from another issuer");
    }
    let expires_at = claims
        .get("exp")
        .and_then(Value::as_i64)
        .and_then(|seconds| Timestamp::from_unix_timestamp(seconds).ok())
        .ok_or("the token does not say when it expires")?;
    if expires_at <= now {
        return Err("the token has expired");
    }
    let text = |name: &str| claims.get(name).and_then(Value::as_str).map(str::to_owned);
    let audience = claims.get("aud").cloned().unwrap_or(Value::Null);
    let audiences = match &audience {
        Value::String(one) => vec![one.clone()],
        Value::Array(many) => many
            .iter()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect(),
        _ => Vec::new(),
    };
    Ok(ReadAccessToken {
        token_id: text("jti").ok_or("the token has no jti")?,
        client_id: text("client_id").ok_or("the token names no client")?,
        subject: text("sub").ok_or("the token names no subject")?,
        scopes: text("scope")
            .unwrap_or_default()
            .split(' ')
            .filter(|scope| !scope.is_empty())
            .map(str::to_owned)
            .collect(),
        audience,
        audiences,
        issued_at: claims
            .get("iat")
            .and_then(Value::as_i64)
            .ok_or("the token does not say when it was issued")?,
        expires_at,
        principal_kind: text("principal_kind"),
        act: claims.get("act").filter(|act| act.is_object()).cloned(),
        auth_time: claims.get("auth_time").and_then(Value::as_i64),
        acr: text("acr"),
        amr: claims.get("amr").and_then(Value::as_array).map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        }),
        organization: text("org_id").and_then(|organization| organization.parse().ok()),
        confirmation: claims.get(CONFIRMATION_CLAIM).cloned(),
    })
}

/// A key the tenant publishes, by the identifier a token's `kid` names.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedKey {
    /// The key version's identifier.
    pub key_id: String,
    /// The algorithm it signs with.
    pub algorithm: SignatureAlgorithm,
    /// Its public key.
    pub key: PublicKey,
}

/// Checks an access token presented at UserInfo, by a request that came
/// with the certificate of `presented`, in the order the OAuth context
/// gives. Nothing it says is used before its signature has been checked.
///
/// # Errors
///
/// Returns why the token is refused.
pub fn check_access_token(
    token: &str,
    issuer: &str,
    keys: &[PublishedKey],
    now: Timestamp,
    verifier: &dyn SignatureVerifier,
    presented: Option<&CertificateThumbprint>,
) -> Result<CheckedAccessToken, BearerRefusal> {
    use BearerRefusal::InvalidToken;
    let read = read_access_token(token, issuer, keys, now, verifier).map_err(InvalidToken)?;
    read.check_certificate(presented).map_err(InvalidToken)?;
    if !read.audiences.iter().any(|audience| audience == issuer) {
        return Err(InvalidToken("the token is not for this server"));
    }
    if read.principal_kind.is_some() || read.subject == read.client_id {
        return Err(InvalidToken("the token names no person"));
    }
    if !asks_for_openid(&read.scopes) {
        return Err(BearerRefusal::InsufficientScope);
    }
    Ok(CheckedAccessToken {
        subject: read.subject,
        scopes: read.scopes,
        token_id: read.token_id,
        client_id: read.client_id,
        organization: read.organization,
    })
}

/// What Hodor knows of a person, for UserInfo.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PersonClaims {
    /// The display name.
    pub name: Option<String>,
    /// The primary username.
    pub preferred_username: Option<String>,
    /// The language tag the person chose.
    pub locale: Option<String>,
    /// When the person was last changed.
    pub updated_at: Option<Timestamp>,
    /// The primary email address, and whether the person proved it is
    /// theirs.
    pub email: Option<(String, bool)>,
    /// The person's effective groups, read only when the scopes hold
    /// `groups`.
    pub groups: Vec<GroupId>,
}

/// The answer of UserInfo for the person the client knows as `subject`,
/// with the claims of `scopes`.
#[must_use]
pub fn userinfo_claims(subject: &str, scopes: &[String], person: &PersonClaims) -> Value {
    let has = |scope: &str| scopes.iter().any(|given| given == scope);
    let mut claims = Map::new();
    claims.insert("sub".to_owned(), json!(subject));
    if has("profile") {
        if let Some(name) = &person.name {
            claims.insert("name".to_owned(), json!(name));
        }
        if let Some(username) = &person.preferred_username {
            claims.insert("preferred_username".to_owned(), json!(username));
        }
        if let Some(locale) = &person.locale {
            claims.insert("locale".to_owned(), json!(locale));
        }
        if let Some(updated_at) = person.updated_at {
            claims.insert("updated_at".to_owned(), json!(updated_at.unix_timestamp()));
        }
    }
    if has("email")
        && let Some((email, verified)) = &person.email
    {
        claims.insert("email".to_owned(), json!(email));
        claims.insert("email_verified".to_owned(), json!(verified));
    }
    // Every group, however many: a token holds at most a hundred, and a
    // client reads the rest here.
    if has(GROUPS_SCOPE) {
        let groups: Vec<String> = person.groups.iter().map(ToString::to_string).collect();
        claims.insert("groups".to_owned(), json!(groups));
    }
    Value::Object(claims)
}

/// The tenant's discovery document (OpenID Connect Discovery 1.0 and RFC
/// 8414). It names only what is built.
#[must_use]
pub fn discovery_document(issuer: &str, acr_values: &[&str]) -> Value {
    json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/oauth2/authorize"),
        "token_endpoint": format!("{issuer}/oauth2/token"),
        "userinfo_endpoint": format!("{issuer}/oauth2/userinfo"),
        "jwks_uri": format!("{issuer}/oauth2/jwks"),
        "revocation_endpoint": format!("{issuer}/oauth2/revoke"),
        "introspection_endpoint": format!("{issuer}/oauth2/introspect"),
        "end_session_endpoint": format!("{issuer}/oauth2/logout"),
        "response_types_supported": ["code"],
        "response_modes_supported": ["query"],
        "grant_types_supported": crate::domain::token::SUPPORTED_GRANT_TYPES,
        "code_challenge_methods_supported": ["S256"],
        // `spiffe_jwt` follows draft-ietf-oauth-spiffe-client-auth-03,
        // which asks for it in all three lists (section 4).
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic", "client_secret_post", "private_key_jwt", "spiffe_jwt", "none"
        ],
        "token_endpoint_auth_signing_alg_values_supported": ["ES256", "RS256", "PS256"],
        "revocation_endpoint_auth_methods_supported": [
            "client_secret_basic", "client_secret_post", "private_key_jwt", "spiffe_jwt", "none"
        ],
        "revocation_endpoint_auth_signing_alg_values_supported": ["ES256", "RS256", "PS256"],
        "introspection_endpoint_auth_methods_supported": [
            "client_secret_basic", "client_secret_post", "private_key_jwt", "spiffe_jwt"
        ],
        "introspection_endpoint_auth_signing_alg_values_supported": ["ES256", "RS256", "PS256"],
        "id_token_signing_alg_values_supported": IdTokenAlgorithm::ALL.map(IdTokenAlgorithm::as_str),
        "subject_types_supported": ["public", "pairwise"],
        "scopes_supported": ["openid", "profile", "email", "groups"],
        "claims_supported": [
            "iss", "sub", "aud", "exp", "iat", "auth_time", "nonce", "acr", "amr", "at_hash", "sid",
            "org_id", "name", "preferred_username", "locale", "updated_at", "email",
            "email_verified", "groups"
        ],
        "acr_values_supported": acr_values,
        "prompt_values_supported": ["none", "login", "consent", "select_account"],
        "ui_locales_supported": UI_LOCALES,
        "authorization_response_iss_parameter_supported": true,
        // Request objects by value; `none` only for a client that chose it.
        "request_parameter_supported": true,
        "request_object_signing_alg_values_supported":
            RequestObjectAlgorithm::ALL.map(RequestObjectAlgorithm::as_str),
        "request_uri_parameter_supported": false,
        "claims_parameter_supported": false,
        // Every client with a back-channel logout address is told when a
        // session it signed a person in with ends, and every logout token
        // carries `sid`.
        "backchannel_logout_supported": true,
        "backchannel_logout_session_supported": true,
    })
}

#[cfg(test)]
mod tests;
