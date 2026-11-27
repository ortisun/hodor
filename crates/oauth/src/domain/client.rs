//! Clients: what asks Hodor for tokens on behalf of an application.

use crate::domain::application::{ApplicationId, Status, stored_data_invalid};
use crate::domain::backchannel::check_backchannel_logout_uri;
use crate::domain::consent::{
    DEFAULT_CONSENT_LIFETIME, LONGEST_CONSENT_LIFETIME, SHORTEST_CONSENT_LIFETIME,
};
use crate::domain::event::OauthEvent;
use crate::domain::forwarded::{LinkerdIdentity, WorkloadIdentity, linkerd_identity_invalid};
use crate::domain::frontchannel::check_frontchannel_logout_uri;
use crate::domain::key::{ClientKey, MAX_KEYS};
use crate::domain::key_set::{check_jwks_uri, jwks_uri_not_allowed};
use crate::domain::pairwise::{
    SubjectType, check_sector_identifier_uri, sector_of, sector_required, sector_uri_invalid,
    subject_type_invalid,
};
use crate::domain::request_uri::{MAX_REQUEST_URIS, check_request_uri, request_uri_invalid};
use crate::domain::response::{ResponseType, response_types_invalid};
use crate::domain::secret::{ClientSecret, ClientSecretHash, ClientSecretId, ClientSecretValue};
use crate::domain::spiffe::SpiffeId;
use crate::domain::text;
use hodor_kernel::{Digest, DomainError, RandomSource, SignatureAlgorithm, Timestamp, UserId};
use hodor_keys::api::{KeyAlgorithm, RotationPolicy};
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies a client. Written as a UUID, it is the `client_id` of
    /// OAuth. It is not a secret.
    ClientId
);

/// The most clients an application may have.
pub const MAX_CLIENTS: usize = 20;
/// The most redirect addresses a client may have.
pub const MAX_REDIRECT_URIS: usize = 10;
/// The longest redirect address.
pub(crate) const MAX_REDIRECT_URI_LENGTH: usize = 2000;
/// The most scopes a client may ask for.
pub const MAX_SCOPES: usize = 50;
/// The largest default max age: a year, in seconds, as `max_age` at the
/// authorization endpoint.
pub(crate) const MAX_DEFAULT_MAX_AGE: u32 = 31_536_000;
/// The most default assurance levels a client may have.
pub(crate) const MAX_DEFAULT_ACR_VALUES: usize = 10;
/// The longest name of a default assurance level.
const MAX_ACR_VALUE_LENGTH: usize = 128;
/// The longest the default assurance levels may be once joined by spaces,
/// as `acr_values` at the authorization endpoint.
const MAX_ACR_VALUES_LENGTH: usize = 255;

/// How Hodor signs what it answers a client: its ID tokens, its
/// `id_token_signed_response_alg` of OpenID Connect Registration, and its
/// UserInfo answers, its `userinfo_signed_response_alg`. Every one is an
/// algorithm each tenant can sign with: both key providers make keys of
/// all four. See `docs/architecture/contexts/oauth.md`, "The ID token".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum IdTokenAlgorithm {
    /// ECDSA on P-256, the algorithm Hodor signs with unless told otherwise
    /// ([Decision 0004](../../../../docs/decisions/0004-token-formats.md)).
    #[default]
    Es256,
    /// RSA with PKCS#1 version 1.5 padding, which every OpenID Provider must
    /// offer and every relying party understands.
    Rs256,
    /// RSA with PSS padding, which FAPI asks for instead of `RS256`.
    Ps256,
    /// EdDSA on Ed25519 (RFC 8037).
    EdDsa,
}

impl IdTokenAlgorithm {
    /// Every algorithm a client may choose, as discovery lists them.
    pub const ALL: [Self; 4] = [Self::Es256, Self::Rs256, Self::Ps256, Self::EdDsa];

    /// The name JSON Web Signature gives it, which is also the stored name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        self.key_algorithm().as_str()
    }

    /// The key that signs with it.
    #[must_use]
    pub const fn key_algorithm(self) -> KeyAlgorithm {
        match self {
            Self::Es256 => KeyAlgorithm::Es256,
            Self::Rs256 => KeyAlgorithm::Rs256,
            Self::Ps256 => KeyAlgorithm::Ps256,
            Self::EdDsa => KeyAlgorithm::EdDsa,
        }
    }

    /// The signature it makes, as signatures are checked.
    #[must_use]
    pub const fn signature(self) -> SignatureAlgorithm {
        match self {
            Self::Es256 => SignatureAlgorithm::Es256,
            Self::Rs256 => SignatureAlgorithm::Rs256,
            Self::Ps256 => SignatureAlgorithm::Ps256,
            Self::EdDsa => SignatureAlgorithm::EdDsa,
        }
    }

    /// The algorithm of this name, if a client may choose it.
    #[must_use]
    pub fn from_name(value: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.as_str() == value)
    }

    /// Reads the name JSON Web Signature gives it, for a client's ID
    /// tokens.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_id_token_algorithm_invalid` for any other name.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        Self::from_name(value).ok_or_else(|| {
            DomainError::invalid(
                "oauth.client_id_token_algorithm_invalid",
                "a client's ID tokens are signed with `ES256`, `RS256`, `PS256` or `EdDSA`",
            )
        })
    }

    /// Reads the name JSON Web Signature gives it, for a client's UserInfo
    /// answers. `none` is not one: a client that wants no signature gets
    /// JSON.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_userinfo_algorithm_invalid` for any other name.
    pub fn parse_for_userinfo(value: &str) -> Result<Self, DomainError> {
        Self::from_name(value).ok_or_else(|| {
            DomainError::invalid(
                "oauth.client_userinfo_algorithm_invalid",
                "a client's UserInfo answers are signed with `ES256`, `RS256`, `PS256` or \
                 `EdDSA`, or not signed at all",
            )
        })
    }
}

/// How a client signs its request objects: its `request_object_signing_alg`
/// of OpenID Connect Registration. A client that names none accepts every
/// algorithm but `none`. See `docs/architecture/contexts/oauth.md`,
/// "Request objects".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RequestObjectAlgorithm {
    /// ECDSA on P-256 with SHA-256.
    Es256,
    /// RSA with PKCS#1 version 1.5 padding and SHA-256.
    Rs256,
    /// RSA with PSS padding and SHA-256.
    Ps256,
    /// Unsigned: the client's request objects protect nothing, and are
    /// held to every check of a request without one.
    None,
}

impl RequestObjectAlgorithm {
    /// Every algorithm a client may name, as discovery lists them.
    pub const ALL: [Self; 4] = [Self::Es256, Self::Rs256, Self::Ps256, Self::None];

    /// The name JSON Web Signature gives it, which is also the stored name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Es256 => "ES256",
            Self::Rs256 => "RS256",
            Self::Ps256 => "PS256",
            Self::None => "none",
        }
    }

    /// The signature it checks, or `None` for an unsigned object.
    #[must_use]
    pub const fn signature(self) -> Option<SignatureAlgorithm> {
        match self {
            Self::Es256 => Some(SignatureAlgorithm::Es256),
            Self::Rs256 => Some(SignatureAlgorithm::Rs256),
            Self::Ps256 => Some(SignatureAlgorithm::Ps256),
            Self::None => None,
        }
    }

    /// Reads the name JSON Web Signature gives it.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_request_object_algorithm_invalid` for any
    /// other name.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        Self::ALL
            .into_iter()
            .find(|algorithm| algorithm.as_str() == value)
            .ok_or_else(|| {
                DomainError::invalid(
                    "oauth.client_request_object_algorithm_invalid",
                    "a client's request objects are signed with `ES256`, `RS256` or `PS256`, \
                     or not signed with `none`",
                )
            })
    }
}

/// A client's `application_type` of OpenID Connect Registration: what
/// kind of application it is, which bounds its redirect addresses. See
/// `docs/architecture/contexts/oauth.md`, "What a client may be".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ApplicationType {
    /// A web application: its redirect addresses are all HTTPS.
    Web,
    /// An application on the person's own device, which may use a
    /// loopback address or a private-use scheme.
    Native,
}

impl ApplicationType {
    /// The name OpenID Connect Registration gives it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Web => "web",
            Self::Native => "native",
        }
    }

    /// Reads a name.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_application_type_invalid` for any other name.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "web" => Ok(Self::Web),
            "native" => Ok(Self::Native),
            _ => Err(application_type_invalid(
                "the application type is `web` or `native`",
            )),
        }
    }
}

fn application_type_invalid(reason: &'static str) -> DomainError {
    DomainError::invalid(
        "oauth.client_application_type_invalid",
        "a client's application type is `web` or `native`, and a web client's redirect \
         addresses are all HTTPS",
    )
    .with_detail(reason)
}

/// The longest address a person is shown.
const MAX_DISPLAY_URI_LENGTH: usize = 2000;

/// Checks one of the addresses a person is shown, `client_uri`,
/// `logo_uri`, `policy_uri` or `tos_uri`, named `member`: one absolute
/// HTTPS address with a host, without a name and password or a fragment.
/// See `docs/architecture/contexts/oauth.md`, "Addresses a person is
/// shown".
fn check_display_uri(member: &str, value: &str) -> Result<(), DomainError> {
    let invalid = |reason: &str| {
        DomainError::invalid(
            "oauth.client_display_uri_invalid",
            "an address a person is shown is one HTTPS address of at most 2000 characters, with \
             a host and without a name and password or a fragment",
        )
        .with_detail(format!("`{member}`: {reason}"))
    };
    if value.is_empty() || value.len() > MAX_DISPLAY_URI_LENGTH {
        return Err(invalid("the address is empty or too long"));
    }
    if !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(invalid(
            "the address has a space or a character outside ASCII",
        ));
    }
    if value.contains('#') || value.contains('\\') {
        return Err(invalid("the address has a fragment or a backslash"));
    }
    let Some(rest) = value.strip_prefix("https://") else {
        return Err(invalid("the address is not HTTPS"));
    };
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err(invalid("the address has a name and password"));
    }
    let (host, port) = if authority.starts_with('[') {
        match authority.split_once(']') {
            Some((inside, "")) => (inside.trim_start_matches('['), None),
            Some((inside, after)) => (
                inside.trim_start_matches('['),
                Some(after.strip_prefix(':').unwrap_or("not a port")),
            ),
            None => ("", None),
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() || port.is_some_and(|p| !is_port(p)) {
        return Err(invalid("the address has no usable host"));
    }
    Ok(())
}

/// Whether a client can keep a secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientType {
    /// It runs where it can keep a secret, such as a server.
    Confidential,
    /// It runs where it cannot, such as a browser or a mobile
    /// application.
    Public,
}

impl ClientType {
    /// The stored name, as OAuth writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Confidential => "confidential",
            Self::Public => "public",
        }
    }

    /// Reads a stored name.
    ///
    /// # Errors
    ///
    /// Returns `Internal` for an unknown name.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "confidential" => Ok(Self::Confidential),
            "public" => Ok(Self::Public),
            _ => Err(stored_data_invalid()),
        }
    }
}

/// How a client proves who it is at the token endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthenticationMethod {
    /// A secret in the `Authorization` header.
    ClientSecretBasic,
    /// A secret in the body of the request.
    ClientSecretPost,
    /// An assertion signed with the client's own private key (RFC 7523).
    PrivateKeyJwt,
    /// A JWT-SVID of the one SPIFFE identifier the client is bound to,
    /// checked against its trust domain's bundle
    /// (draft-ietf-oauth-spiffe-client-auth-03).
    SpiffeJwt,
    /// The certificate it presented to the proxy in front of Hodor, as the
    /// proxy forwards it (RFC 8705, section 2.1).
    TlsClientAuth,
    /// Its X509-SVID, as the proxy in front of Hodor forwards it
    /// (draft-ietf-oauth-spiffe-client-auth-03, section 3.3).
    SpiffeX509,
    /// The identity Linkerd's proxy asserts in `l5d-client-id`. Hodor's
    /// own name, registered nowhere.
    LinkerdIdentity,
    /// Nothing: a public client.
    None,
}

impl AuthenticationMethod {
    /// The name OAuth gives it, which is also the stored name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ClientSecretBasic => "client_secret_basic",
            Self::ClientSecretPost => "client_secret_post",
            Self::PrivateKeyJwt => "private_key_jwt",
            Self::SpiffeJwt => "spiffe_jwt",
            Self::TlsClientAuth => "tls_client_auth",
            Self::SpiffeX509 => "spiffe_x509",
            Self::LinkerdIdentity => "linkerd_identity",
            Self::None => "none",
        }
    }

    /// Reads the name OAuth gives it.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_authentication_method_invalid` for any other
    /// name.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "client_secret_basic" => Ok(Self::ClientSecretBasic),
            "client_secret_post" => Ok(Self::ClientSecretPost),
            "private_key_jwt" => Ok(Self::PrivateKeyJwt),
            "spiffe_jwt" => Ok(Self::SpiffeJwt),
            "tls_client_auth" => Ok(Self::TlsClientAuth),
            "spiffe_x509" => Ok(Self::SpiffeX509),
            "linkerd_identity" => Ok(Self::LinkerdIdentity),
            "none" => Ok(Self::None),
            _ => Err(method_invalid()),
        }
    }

    /// Whether the method proves who the client is with a secret.
    #[must_use]
    pub const fn uses_secret(self) -> bool {
        matches!(self, Self::ClientSecretBasic | Self::ClientSecretPost)
    }

    /// Whether the method proves who the client is with the credential of
    /// the one SPIFFE identifier it is bound to: a JWT-SVID, or an
    /// X509-SVID a proxy forwards.
    #[must_use]
    pub const fn uses_spiffe_id(self) -> bool {
        matches!(self, Self::SpiffeJwt | Self::SpiffeX509)
    }

    /// Whether the method proves who the client is with an identity the
    /// proxy in front of Hodor forwards.
    #[must_use]
    pub const fn uses_forwarded_identity(self) -> bool {
        matches!(
            self,
            Self::TlsClientAuth | Self::SpiffeX509 | Self::LinkerdIdentity
        )
    }

    /// Whether the method binds the client to a workload's identity, a
    /// SPIFFE identifier or a Linkerd identity, so that it acts as a
    /// service account.
    #[must_use]
    pub const fn uses_workload_identity(self) -> bool {
        self.uses_spiffe_id() || self.uses_forwarded_identity()
    }
}

fn spiffe_id_required(reason: &'static str) -> DomainError {
    DomainError::invalid(
        "oauth.client_spiffe_id_invalid",
        "a client using `spiffe_jwt` or `spiffe_x509` is bound to one SPIFFE identifier, one \
         using `tls_client_auth` to one SPIFFE identifier or one Linkerd identity, and each \
         acts as a service account; only such a client has one",
    )
    .with_detail(reason)
}

/// Checks that a client of `method` is bound to the identity its method
/// takes, and only then, and that a bound client acts as a workload.
fn check_identities(
    method: AuthenticationMethod,
    spiffe: bool,
    linkerd: bool,
    principal: bool,
) -> Result<(), DomainError> {
    const NO_SPIFFE_ID: &str = "only a client using `spiffe_jwt`, `spiffe_x509` or `tls_client_auth` has a SPIFFE \
         identifier";
    const NO_LINKERD_IDENTITY: &str =
        "only a client using `linkerd_identity` or `tls_client_auth` has a Linkerd identity";
    match method {
        AuthenticationMethod::SpiffeJwt if !spiffe => Err(spiffe_id_required(
            "a client using `spiffe_jwt` has a SPIFFE identifier",
        )),
        AuthenticationMethod::SpiffeX509 if !spiffe => Err(spiffe_id_required(
            "a client using `spiffe_x509` has a SPIFFE identifier",
        )),
        AuthenticationMethod::SpiffeJwt | AuthenticationMethod::SpiffeX509 if linkerd => {
            Err(linkerd_identity_invalid(NO_LINKERD_IDENTITY))
        }
        AuthenticationMethod::LinkerdIdentity if !linkerd => Err(linkerd_identity_invalid(
            "a client using `linkerd_identity` has a Linkerd identity",
        )),
        AuthenticationMethod::LinkerdIdentity if spiffe => Err(spiffe_id_required(NO_SPIFFE_ID)),
        AuthenticationMethod::TlsClientAuth if spiffe == linkerd => Err(spiffe_id_required(
            "a client using `tls_client_auth` has a SPIFFE identifier or a Linkerd identity, \
             not both",
        )),
        AuthenticationMethod::ClientSecretBasic
        | AuthenticationMethod::ClientSecretPost
        | AuthenticationMethod::PrivateKeyJwt
        | AuthenticationMethod::None
            if spiffe =>
        {
            Err(spiffe_id_required(NO_SPIFFE_ID))
        }
        AuthenticationMethod::ClientSecretBasic
        | AuthenticationMethod::ClientSecretPost
        | AuthenticationMethod::PrivateKeyJwt
        | AuthenticationMethod::None
            if linkerd =>
        {
            Err(linkerd_identity_invalid(NO_LINKERD_IDENTITY))
        }
        _ if spiffe && !principal => Err(spiffe_id_required(
            "a client bound to a SPIFFE identifier acts as a service account",
        )),
        _ if linkerd && !principal => Err(linkerd_identity_invalid(
            "a client bound to a Linkerd identity acts as a service account",
        )),
        _ => Ok(()),
    }
}

/// Refuses a client that asks for certificate-bound access tokens while
/// no certificate can ever come with its requests.
fn certificate_bound_invalid() -> DomainError {
    DomainError::invalid(
        "oauth.client_certificate_bound_access_tokens_invalid",
        "a client using `linkerd_identity` does not ask for certificate-bound access tokens: \
         Linkerd forwards no certificate to bind them to",
    )
}

fn method_invalid() -> DomainError {
    DomainError::invalid(
        "oauth.client_authentication_method_invalid",
        "a confidential client proves who it is with `client_secret_basic`, \
         `client_secret_post`, `private_key_jwt`, `spiffe_jwt`, `tls_client_auth`, \
         `spiffe_x509` or `linkerd_identity`; a public client with `none`",
    )
}

/// What a client may ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum GrantType {
    /// A person signs in and the client gets a code for tokens.
    AuthorizationCode,
    /// Tokens are renewed with a refresh token.
    RefreshToken,
    /// The client gets a token for itself.
    ClientCredentials,
    /// An agent's client exchanges a person's token for one it holds on
    /// the person's behalf (RFC 8693).
    TokenExchange,
}

/// The name of the token exchange grant, as RFC 8693 writes it.
pub const TOKEN_EXCHANGE_GRANT: &str = "urn:ietf:params:oauth:grant-type:token-exchange";

/// The most exchange rules a client has.
pub const MAX_EXCHANGE_RULES: usize = 20;

/// The longest audience of an exchange rule.
const MAX_EXCHANGE_AUDIENCE_LENGTH: usize = 255;

/// One rule of an agent's client: a subject token that holds
/// `subject_audience` may be exchanged for a token for `audience`.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ExchangeRule {
    /// An audience the subject token must hold.
    pub subject_audience: String,
    /// The audience the new token may be for.
    pub audience: String,
}

impl ExchangeRule {
    /// Whether this rule lets a token for `subject_audiences` become one
    /// for `audience`.
    #[must_use]
    pub fn allows(&self, subject_audiences: &[String], audience: &str) -> bool {
        self.audience == audience && subject_audiences.contains(&self.subject_audience)
    }
}

fn exchange_rules_invalid(reason: &'static str) -> DomainError {
    DomainError::invalid(
        "oauth.client_exchange_rules_invalid",
        "a client with the token exchange grant has 1 to 20 exchange rules, each a pair of \
         audiences of at most 255 printable characters, and only such a client has them",
    )
    .with_detail(reason)
}

impl GrantType {
    /// The name OAuth gives it, which is also the stored name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
            Self::ClientCredentials => "client_credentials",
            Self::TokenExchange => TOKEN_EXCHANGE_GRANT,
        }
    }

    /// Reads the name OAuth gives it.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_grants_invalid` for any other name.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "authorization_code" => Ok(Self::AuthorizationCode),
            "refresh_token" => Ok(Self::RefreshToken),
            "client_credentials" => Ok(Self::ClientCredentials),
            TOKEN_EXCHANGE_GRANT => Ok(Self::TokenExchange),
            _ => Err(grants_invalid("the grant is not one Hodor knows")),
        }
    }
}

fn grants_invalid(reason: &'static str) -> DomainError {
    DomainError::invalid(
        "oauth.client_grants_invalid",
        "a client has at least one grant; `refresh_token` comes with `authorization_code`, \
         and `client_credentials` is for confidential clients",
    )
    .with_detail(reason)
}

/// How long a client's tokens live.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TokenPolicy {
    /// How long an access token lives.
    pub access_token: Duration,
    /// How long an ID token lives.
    pub id_token: Duration,
    /// The most a refresh token family can live.
    pub refresh_token: Duration,
    /// How long a refresh token lasts unused.
    pub refresh_idle: Duration,
    /// How long a person's consent to the client lasts before they are
    /// asked again.
    pub consent: Duration,
}

impl Default for TokenPolicy {
    fn default() -> Self {
        Self {
            access_token: Duration::minutes(5),
            id_token: Duration::minutes(5),
            refresh_token: Duration::days(30),
            refresh_idle: Duration::days(7),
            consent: DEFAULT_CONSENT_LIFETIME,
        }
    }
}

impl TokenPolicy {
    /// The longest a signed token, access or ID, may live: the keys context
    /// keeps a retiring key published that long after it stops signing, so
    /// a token that outlived it could no longer be checked.
    pub const LONGEST_SIGNED_LIFETIME: Duration = RotationPolicy::LONGEST_SIGNED_LIFETIME;

    fn checked(self) -> Result<Self, DomainError> {
        let short = Duration::minutes(1)..=Self::LONGEST_SIGNED_LIFETIME;
        let long = Duration::hours(1)..=Duration::days(365);
        let fits = short.contains(&self.access_token)
            && short.contains(&self.id_token)
            && long.contains(&self.refresh_token)
            && self.refresh_idle >= Duration::hours(1)
            && self.refresh_idle <= self.refresh_token
            && (SHORTEST_CONSENT_LIFETIME..=LONGEST_CONSENT_LIFETIME).contains(&self.consent);
        if fits {
            Ok(self)
        } else {
            Err(DomainError::invalid(
                "oauth.token_policy_invalid",
                "access and ID tokens live 1 minute to 1 hour; a refresh token 1 hour to 365 \
                 days, and lasts unused from 1 hour up to its lifetime; a consent 1 to 730 days",
            ))
        }
    }
}

/// What an administrator decides about a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSettings {
    /// For administrators.
    pub name: String,
    /// How it proves who it is.
    pub authentication_method: AuthenticationMethod,
    /// What it may ask for.
    pub grant_types: Vec<GrantType>,
    /// What the authorization endpoint may answer it with: at least one
    /// with `authorization_code`, none without it.
    pub response_types: Vec<ResponseType>,
    /// Where a person may be sent back to, compared by exact equality.
    pub redirect_uris: Vec<String>,
    /// Where a person may be sent back to after signing out at Hodor's
    /// end-session endpoint, compared by exact equality.
    pub post_logout_redirect_uris: Vec<String>,
    /// The scopes it may ask for.
    pub allowed_scopes: Vec<String>,
    /// Whether it must send a code challenge. Always true for a public
    /// client.
    pub require_pkce: bool,
    /// How its ID tokens are signed.
    pub id_token_algorithm: IdTokenAlgorithm,
    /// How its UserInfo answers are signed, or `None` for answers in JSON.
    pub userinfo_algorithm: Option<IdTokenAlgorithm>,
    /// How it signs its request objects, if it named an algorithm.
    pub request_object_algorithm: Option<RequestObjectAlgorithm>,
    /// Whether every request of it must be pushed first, its
    /// `require_pushed_authorization_requests` of RFC 9126.
    pub require_pushed_requests: bool,
    /// Where it keeps request objects Hodor may fetch, its `request_uris`
    /// of OpenID Connect Registration: a `request_uri` is fetched only when
    /// it starts with one of them.
    pub request_uris: Vec<String>,
    /// Where its logout tokens are sent when a session it signed a person
    /// in with ends, if anywhere.
    pub backchannel_logout_uri: Option<String>,
    /// Whether it needs `sid` in its logout tokens. Every logout token
    /// carries it; this records what the client relies on.
    pub backchannel_logout_session_required: bool,
    /// The address the signed-out page loads in a frame when a session it
    /// signed a person in with ends in the person's browser, if any.
    pub frontchannel_logout_uri: Option<String>,
    /// Whether it needs `iss` and `sid` in the address of its frame. Every
    /// frame carries them; this records what the client relies on.
    pub frontchannel_logout_session_required: bool,
    /// How it knows a person: by the user identifier, or by an identifier
    /// of its sector alone.
    pub subject_type: SubjectType,
    /// For a pairwise client, the address whose host is its sector and
    /// which lists its redirect addresses, if it has one.
    pub sector_identifier_uri: Option<String>,
    /// For a client using `private_key_jwt`, the address where it
    /// publishes its keys itself, its `jwks_uri`, in place of keys Hodor
    /// keeps.
    pub jwks_uri: Option<String>,
    /// The `max_age` of a request that names none, its `default_max_age`.
    pub default_max_age: Option<u32>,
    /// The `acr_values` of a request that names none, in order, its
    /// `default_acr_values`.
    pub default_acr_values: Vec<String>,
    /// Whether it needs `auth_time` in its ID tokens, its
    /// `require_auth_time`. Every ID token carries it; this records what
    /// the client relies on.
    pub require_auth_time: bool,
    /// How long its tokens live.
    pub token_policy: TokenPolicy,
    /// The service account or agent it acts as, if any: its tokens are
    /// then about that workload. Whether the identifier names one is
    /// checked by whoever binds it, through the identity context.
    pub principal: Option<UserId>,
    /// What an agent's client may exchange for which audience; empty
    /// unless it has the token exchange grant.
    pub exchange_rules: Vec<ExchangeRule>,
    /// The one SPIFFE identifier whose JWT-SVIDs prove who the client is,
    /// for a client using `spiffe_jwt` only. Whether its principal is a
    /// service account is checked by whoever binds it, through the
    /// identity context.
    pub spiffe_id: Option<SpiffeId>,
    /// The one Linkerd identity Linkerd's proxy, or a certificate a proxy
    /// forwards, must name, for a client using `linkerd_identity`, or
    /// `tls_client_auth` without a SPIFFE identifier.
    pub linkerd_identity: Option<LinkerdIdentity>,
    /// Whether its access tokens, and a public client's refresh tokens, are
    /// bound to the certificate its requests come with: its
    /// `tls_client_certificate_bound_access_tokens` of RFC 8705.
    pub certificate_bound_access_tokens: bool,
    /// What kind of application it is, its `application_type`, or `None`,
    /// as for every client an administrator makes.
    pub application_type: Option<ApplicationType>,
    /// Its home page, its `client_uri`, shown to a person.
    pub client_uri: Option<String>,
    /// Its logo, its `logo_uri`, shown to a person.
    pub logo_uri: Option<String>,
    /// Its privacy policy, its `policy_uri`, shown to a person.
    pub policy_uri: Option<String>,
    /// Its terms of service, its `tos_uri`, shown to a person.
    pub tos_uri: Option<String>,
}

/// Checks a client's defaults for a sign-in: see
/// `docs/architecture/contexts/oauth.md`, "Defaults for a sign-in".
fn check_sign_in_defaults(
    has_code: bool,
    max_age: Option<u32>,
    acr_values: &[String],
    require_auth_time: bool,
) -> Result<(), DomainError> {
    let max_age_invalid = |reason: &'static str| {
        DomainError::invalid(
            "oauth.client_default_max_age_invalid",
            "a default max age is 0 to 31536000 seconds, for a client with              `authorization_code` only",
        )
        .with_detail(reason)
    };
    let acr_values_invalid = |reason: &'static str| {
        DomainError::invalid(
            "oauth.client_default_acr_values_invalid",
            "default assurance levels are at most 10 names of 1 to 128 printable characters              without spaces, 255 characters together, for a client with `authorization_code`              only",
        )
        .with_detail(reason)
    };
    if let Some(seconds) = max_age {
        if !has_code {
            return Err(max_age_invalid(
                "a client without `authorization_code` has no default max age",
            ));
        }
        if seconds > MAX_DEFAULT_MAX_AGE {
            return Err(max_age_invalid("longer than a year"));
        }
    }
    if !acr_values.is_empty() {
        if !has_code {
            return Err(acr_values_invalid(
                "a client without `authorization_code` has no default assurance levels",
            ));
        }
        let joined = acr_values.iter().map(String::len).sum::<usize>() + acr_values.len() - 1;
        if acr_values.len() > MAX_DEFAULT_ACR_VALUES
            || joined > MAX_ACR_VALUES_LENGTH
            || !acr_values.iter().all(|value| {
                !value.is_empty()
                    && value.len() <= MAX_ACR_VALUE_LENGTH
                    && value.bytes().all(|b| b.is_ascii_graphic())
            })
        {
            return Err(acr_values_invalid("too many, too long, or not printable"));
        }
    }
    if require_auth_time && !has_code {
        return Err(DomainError::invalid(
            "oauth.client_require_auth_time_invalid",
            "only a client with `authorization_code` gets ID tokens, and may require              `auth_time` in them",
        ));
    }
    Ok(())
}

fn redirect_invalid(reason: &'static str) -> DomainError {
    DomainError::invalid(
        "oauth.client_redirect_uri_invalid",
        "a redirect address is HTTPS, plain HTTP to 127.0.0.1 or [::1], or for a public client \
         a private-use scheme such as `com.example.app:/callback`; without a fragment or a `*`",
    )
    .with_detail(reason)
}

fn post_logout_invalid(reason: impl Into<String>) -> DomainError {
    DomainError::invalid(
        "oauth.client_post_logout_redirect_uri_invalid",
        "a post-logout redirect address follows the rules of a redirect address, and only a \
         client with `authorization_code` has them, at most 10",
    )
    .with_detail(reason)
}

fn backchannel_invalid(reason: &'static str) -> DomainError {
    crate::domain::backchannel::uri_invalid(reason)
}

pub(crate) fn is_port(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 5
        && value.bytes().all(|b| b.is_ascii_digit())
        && value
            .parse::<u32>()
            .is_ok_and(|port| (1..=65535).contains(&port))
}

/// Checks one redirect address against the rules of the OAuth context;
/// see `docs/architecture/contexts/oauth.md`, "Redirect addresses".
pub(crate) fn check_redirect_uri(value: &str, client_type: ClientType) -> Result<(), DomainError> {
    if value.is_empty() || value.len() > MAX_REDIRECT_URI_LENGTH {
        return Err(redirect_invalid("the address is empty or too long"));
    }
    if !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(redirect_invalid(
            "the address has a space or a character outside ASCII",
        ));
    }
    if value.contains('#') || value.contains('*') || value.contains('\\') {
        return Err(redirect_invalid(
            "the address has a fragment, a `*` or a backslash",
        ));
    }
    let authority = |rest: &str| rest.split(['/', '?']).next().unwrap_or_default().to_owned();
    if let Some(rest) = value.strip_prefix("https://") {
        let authority = authority(rest);
        // An address written in brackets has colons of its own.
        let (host, port) = if authority.starts_with('[') {
            match authority.split_once(']') {
                Some((inside, after)) => (
                    if inside.len() > 1 { inside } else { "" },
                    match after {
                        "" => None,
                        _ => Some(after.strip_prefix(':').unwrap_or("not a port")),
                    },
                ),
                None => ("", None),
            }
        } else {
            match authority.split_once(':') {
                Some((host, port)) => (host, Some(port)),
                None => (authority.as_str(), None),
            }
        };
        if host.is_empty() || authority.contains('@') || port.is_some_and(|p| !is_port(p)) {
            return Err(redirect_invalid("the address has no usable host"));
        }
        return Ok(());
    }
    if let Some(rest) = value.strip_prefix("http://") {
        let authority = authority(rest);
        let host = ["127.0.0.1", "[::1]"].into_iter().find(|loopback| {
            authority == *loopback
                || authority
                    .strip_prefix(loopback)
                    .and_then(|after| after.strip_prefix(':'))
                    .is_some_and(is_port)
        });
        return host
            .map(|_| ())
            .ok_or_else(|| redirect_invalid("plain HTTP goes only to 127.0.0.1 or [::1]"));
    }
    let Some((scheme, rest)) = value.split_once(':') else {
        return Err(redirect_invalid("the address has no scheme"));
    };
    let private_use = scheme.contains('.')
        && scheme.starts_with(|c: char| c.is_ascii_lowercase())
        && scheme.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'+' | b'.' | b'-')
        })
        && !scheme.ends_with('.')
        && !rest.is_empty();
    if !private_use {
        return Err(redirect_invalid(
            "the scheme is neither HTTPS nor a reversed domain name",
        ));
    }
    if client_type != ClientType::Public {
        return Err(redirect_invalid(
            "a private-use scheme is for a public client only",
        ));
    }
    Ok(())
}

/// Removes repeats, keeping the first of each in its place.
fn without_repeats<T: PartialEq>(values: Vec<T>) -> Vec<T> {
    let mut kept: Vec<T> = Vec::with_capacity(values.len());
    for value in values {
        if !kept.contains(&value) {
            kept.push(value);
        }
    }
    kept
}

impl ClientSettings {
    /// The workload's identity the client is bound to, if any.
    #[must_use]
    pub fn workload_identity(&self) -> Option<WorkloadIdentity> {
        match (&self.spiffe_id, &self.linkerd_identity) {
            (Some(id), _) => Some(WorkloadIdentity::Spiffe(id.clone())),
            (None, Some(id)) => Some(WorkloadIdentity::Linkerd(id.clone())),
            (None, None) => None,
        }
    }

    /// Settings for a client of `client_type` with these grants and
    /// redirect addresses, and everything else at its default: `code` as
    /// its response type with `authorization_code`, none without it.
    #[must_use]
    pub fn new(
        name: &str,
        client_type: ClientType,
        grant_types: Vec<GrantType>,
        redirect_uris: Vec<String>,
    ) -> Self {
        Self {
            name: name.to_owned(),
            authentication_method: match client_type {
                ClientType::Confidential => AuthenticationMethod::ClientSecretBasic,
                ClientType::Public => AuthenticationMethod::None,
            },
            response_types: if grant_types.contains(&GrantType::AuthorizationCode) {
                vec![ResponseType::Code]
            } else {
                Vec::new()
            },
            grant_types,
            redirect_uris,
            post_logout_redirect_uris: Vec::new(),
            allowed_scopes: Vec::new(),
            require_pkce: true,
            id_token_algorithm: IdTokenAlgorithm::default(),
            userinfo_algorithm: None,
            request_object_algorithm: None,
            require_pushed_requests: false,
            request_uris: Vec::new(),
            backchannel_logout_uri: None,
            backchannel_logout_session_required: false,
            frontchannel_logout_uri: None,
            frontchannel_logout_session_required: false,
            subject_type: SubjectType::Public,
            sector_identifier_uri: None,
            jwks_uri: None,
            default_max_age: None,
            default_acr_values: Vec::new(),
            require_auth_time: false,
            token_policy: TokenPolicy::default(),
            principal: None,
            exchange_rules: Vec::new(),
            spiffe_id: None,
            linkerd_identity: None,
            certificate_bound_access_tokens: false,
            application_type: None,
            client_uri: None,
            logo_uri: None,
            policy_uri: None,
            tos_uri: None,
        }
    }

    /// The addresses a person is shown, each with the name of its member,
    /// when the client has it.
    #[must_use]
    pub fn display_uris(&self) -> Vec<(&'static str, &str)> {
        [
            ("client_uri", &self.client_uri),
            ("logo_uri", &self.logo_uri),
            ("policy_uri", &self.policy_uri),
            ("tos_uri", &self.tos_uri),
        ]
        .into_iter()
        .filter_map(|(member, value)| value.as_deref().map(|value| (member, value)))
        .collect()
    }

    /// The settings, tidied, if they follow every rule for a client of
    /// `client_type`.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error naming the first rule broken.
    pub fn checked(self, client_type: ClientType) -> Result<Self, DomainError> {
        let name = text::name(&self.name, "oauth.client_name_invalid")?;
        match (client_type, self.authentication_method) {
            (ClientType::Public, AuthenticationMethod::None) => {}
            (ClientType::Confidential, method) if method != AuthenticationMethod::None => {}
            _ => return Err(method_invalid()),
        }
        if client_type == ClientType::Public && !self.require_pkce {
            return Err(DomainError::invalid(
                "oauth.client_pkce_required",
                "a public client always uses PKCE",
            ));
        }
        let mut grant_types = without_repeats(self.grant_types);
        grant_types.sort();
        if grant_types.is_empty() {
            return Err(grants_invalid("the client has no grant"));
        }
        let has_code = grant_types.contains(&GrantType::AuthorizationCode);
        if grant_types.contains(&GrantType::RefreshToken) && !has_code {
            return Err(grants_invalid(
                "`refresh_token` without `authorization_code`",
            ));
        }
        if grant_types.contains(&GrantType::ClientCredentials) && client_type == ClientType::Public
        {
            return Err(grants_invalid("`client_credentials` for a public client"));
        }
        let exchanges = grant_types.contains(&GrantType::TokenExchange);
        if self.principal.is_some()
            && (!grant_types.contains(&GrantType::ClientCredentials)
                || grant_types.iter().any(|grant| {
                    !matches!(
                        grant,
                        GrantType::ClientCredentials | GrantType::TokenExchange
                    )
                }))
        {
            return Err(grants_invalid(
                "a client with a principal has `client_credentials`, and may have token \
                 exchange besides, and no other grant",
            ));
        }
        if exchanges && self.principal.is_none() {
            return Err(grants_invalid(
                "the token exchange grant is for a client bound to an agent",
            ));
        }
        let exchange_rules = without_repeats(self.exchange_rules);
        let well_formed = |audience: &str| {
            !audience.is_empty()
                && audience.len() <= MAX_EXCHANGE_AUDIENCE_LENGTH
                && audience.bytes().all(|b| b.is_ascii_graphic())
        };
        match (exchanges, exchange_rules.is_empty()) {
            (true, true) => {
                return Err(exchange_rules_invalid(
                    "a client with the token exchange grant has an exchange rule",
                ));
            }
            (false, false) => {
                return Err(exchange_rules_invalid(
                    "a client without the token exchange grant has no exchange rule",
                ));
            }
            _ => {}
        }
        if exchange_rules.len() > MAX_EXCHANGE_RULES
            || !exchange_rules
                .iter()
                .all(|rule| well_formed(&rule.subject_audience) && well_formed(&rule.audience))
        {
            return Err(exchange_rules_invalid(
                "at most 20 rules, each a pair of audiences",
            ));
        }
        let mut response_types = without_repeats(self.response_types);
        response_types.sort();
        match (has_code, response_types.is_empty()) {
            (true, true) => {
                return Err(response_types_invalid(
                    "a client with `authorization_code` has a response type",
                ));
            }
            (false, false) => {
                return Err(response_types_invalid(
                    "a client without `authorization_code` has no response type",
                ));
            }
            _ => {}
        }
        let redirect_uris = without_repeats(self.redirect_uris);
        if redirect_uris.len() > MAX_REDIRECT_URIS {
            return Err(redirect_invalid(
                "a client has at most 10 redirect addresses",
            ));
        }
        match (has_code, redirect_uris.is_empty()) {
            (true, true) => {
                return Err(redirect_invalid(
                    "a client with `authorization_code` has a redirect address",
                ));
            }
            (false, false) => {
                return Err(redirect_invalid(
                    "a client without `authorization_code` has no redirect address",
                ));
            }
            _ => {}
        }
        for uri in &redirect_uris {
            check_redirect_uri(uri, client_type)?;
        }
        if self.application_type == Some(ApplicationType::Web)
            && redirect_uris.iter().any(|uri| !uri.starts_with("https://"))
        {
            return Err(application_type_invalid(
                "a web client's redirect addresses are all HTTPS",
            ));
        }
        for (member, uri) in [
            ("client_uri", &self.client_uri),
            ("logo_uri", &self.logo_uri),
            ("policy_uri", &self.policy_uri),
            ("tos_uri", &self.tos_uri),
        ] {
            if let Some(uri) = uri {
                check_display_uri(member, uri)?;
            }
        }
        let post_logout_redirect_uris = without_repeats(self.post_logout_redirect_uris);
        if post_logout_redirect_uris.len() > MAX_REDIRECT_URIS {
            return Err(post_logout_invalid(
                "a client has at most 10 post-logout redirect addresses",
            ));
        }
        if !has_code && !post_logout_redirect_uris.is_empty() {
            return Err(post_logout_invalid(
                "a client without `authorization_code` has no post-logout redirect address",
            ));
        }
        for uri in &post_logout_redirect_uris {
            check_redirect_uri(uri, client_type).map_err(|error| {
                post_logout_invalid(error.detail().unwrap_or_default().to_owned())
            })?;
        }
        let request_uris = without_repeats(self.request_uris);
        if request_uris.len() > MAX_REQUEST_URIS {
            return Err(request_uri_invalid(
                "a client has at most 10 request object addresses",
            ));
        }
        if !has_code && !request_uris.is_empty() {
            return Err(request_uri_invalid(
                "a client without `authorization_code` has no request object address",
            ));
        }
        for uri in &request_uris {
            check_request_uri(uri)?;
        }
        if let Some(uri) = &self.backchannel_logout_uri {
            if !has_code {
                return Err(backchannel_invalid(
                    "a client without `authorization_code` has no back-channel logout address",
                ));
            }
            check_backchannel_logout_uri(uri)?;
        } else if self.backchannel_logout_session_required {
            return Err(backchannel_invalid(
                "back-channel logout session required needs a back-channel logout address",
            ));
        }
        if let Some(uri) = &self.frontchannel_logout_uri {
            if !has_code {
                return Err(crate::domain::frontchannel::uri_invalid(
                    "a client without `authorization_code` has no front-channel logout address",
                ));
            }
            check_frontchannel_logout_uri(uri, &redirect_uris)?;
        } else if self.frontchannel_logout_session_required {
            return Err(crate::domain::frontchannel::uri_invalid(
                "front-channel logout session required needs a front-channel logout address",
            ));
        }
        match self.subject_type {
            SubjectType::Pairwise => {
                if !has_code {
                    return Err(subject_type_invalid(
                        "only a client with `authorization_code` may be pairwise",
                    ));
                }
                if let Some(uri) = &self.sector_identifier_uri {
                    check_sector_identifier_uri(uri)?;
                }
                if sector_of(self.sector_identifier_uri.as_deref(), &redirect_uris).is_none() {
                    return Err(sector_required());
                }
            }
            SubjectType::Public => {
                if self.sector_identifier_uri.is_some() {
                    return Err(sector_uri_invalid(
                        "only a pairwise client has a sector identifier address",
                    ));
                }
            }
        }
        if let Some(uri) = &self.jwks_uri {
            if self.authentication_method != AuthenticationMethod::PrivateKeyJwt {
                return Err(jwks_uri_not_allowed());
            }
            check_jwks_uri(uri)?;
        }
        check_identities(
            self.authentication_method,
            self.spiffe_id.is_some(),
            self.linkerd_identity.is_some(),
            self.principal.is_some(),
        )?;
        if self.certificate_bound_access_tokens
            && self.authentication_method == AuthenticationMethod::LinkerdIdentity
        {
            return Err(certificate_bound_invalid());
        }
        let default_acr_values = without_repeats(self.default_acr_values);
        check_sign_in_defaults(
            has_code,
            self.default_max_age,
            &default_acr_values,
            self.require_auth_time,
        )?;
        let allowed_scopes = without_repeats(self.allowed_scopes);
        if allowed_scopes.len() > MAX_SCOPES || !allowed_scopes.iter().all(|s| text::is_scope(s)) {
            return Err(DomainError::invalid(
                "oauth.client_scope_invalid",
                "a client asks for at most 50 scopes, each 1 to 128 printable characters \
                 without spaces, double quotes or backslashes",
            ));
        }
        Ok(Self {
            name,
            authentication_method: self.authentication_method,
            grant_types,
            response_types,
            redirect_uris,
            post_logout_redirect_uris,
            allowed_scopes,
            require_pkce: self.require_pkce,
            id_token_algorithm: self.id_token_algorithm,
            userinfo_algorithm: self.userinfo_algorithm,
            request_object_algorithm: self.request_object_algorithm,
            require_pushed_requests: self.require_pushed_requests,
            request_uris,
            backchannel_logout_uri: self.backchannel_logout_uri,
            backchannel_logout_session_required: self.backchannel_logout_session_required,
            frontchannel_logout_uri: self.frontchannel_logout_uri,
            frontchannel_logout_session_required: self.frontchannel_logout_session_required,
            subject_type: self.subject_type,
            sector_identifier_uri: self.sector_identifier_uri,
            jwks_uri: self.jwks_uri,
            default_max_age: self.default_max_age,
            default_acr_values,
            require_auth_time: self.require_auth_time,
            token_policy: self.token_policy.checked()?,
            principal: self.principal,
            exchange_rules,
            spiffe_id: self.spiffe_id,
            linkerd_identity: self.linkerd_identity,
            certificate_bound_access_tokens: self.certificate_bound_access_tokens,
            application_type: self.application_type,
            client_uri: self.client_uri,
            logo_uri: self.logo_uri,
            policy_uri: self.policy_uri,
            tos_uri: self.tos_uri,
        })
    }
}

/// What is kept of a client that registered itself at the registration
/// endpoint. See `docs/architecture/contexts/oauth.md`, "A registered
/// client".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfRegistration {
    /// The SHA-256 of the address it was registered from, as the client
    /// address reads it, if it was known: what the bound of registrations
    /// per address counts.
    pub address_hash: Option<[u8; 32]>,
}

/// Everything stored about a client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientSnapshot {
    /// Its identifier, the `client_id`.
    pub id: ClientId,
    /// The application it belongs to.
    pub application_id: ApplicationId,
    /// Whether it can keep a secret. Never changes.
    pub client_type: ClientType,
    /// What an administrator decided about it.
    pub settings: ClientSettings,
    /// Its secrets, as hashes, oldest first.
    pub secrets: Vec<ClientSecret>,
    /// Its public keys, in the order they were added.
    pub keys: Vec<ClientKey>,
    /// Whether it gets tokens.
    pub status: Status,
    /// When it was created.
    pub created_at: Timestamp,
    /// When it was last changed.
    pub updated_at: Timestamp,
    /// Incremented on every stored change, for optimistic locking.
    pub version: u32,
    /// Set when it registered itself, and never changed: a registered
    /// client is never first party.
    pub self_registration: Option<SelfRegistration>,
}

/// A client of an application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Client {
    state: ClientSnapshot,
}

fn secret_not_allowed() -> DomainError {
    DomainError::invalid(
        "oauth.client_secret_not_allowed",
        "only a confidential client using `client_secret_basic` or `client_secret_post` has \
         secrets",
    )
}

impl Client {
    /// A new client, enabled. A confidential client with a secret method
    /// gets its first secret, living for `secret_lifetime`, which is
    /// returned once.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error if a setting breaks its rule or the
    /// lifetime of the secret is not acceptable.
    pub fn create(
        application_id: ApplicationId,
        client_type: ClientType,
        settings: ClientSettings,
        secret_lifetime: Duration,
        now: Timestamp,
        random: &dyn RandomSource,
        digest: &dyn Digest,
    ) -> Result<(Self, Option<ClientSecretValue>), DomainError> {
        let settings = settings.checked(client_type)?;
        let (secrets, value) = if settings.authentication_method.uses_secret() {
            let (secret, value) = ClientSecret::make(secret_lifetime, now, random, digest)?;
            (vec![secret], Some(value))
        } else {
            (Vec::new(), None)
        };
        let client = Self {
            state: ClientSnapshot {
                id: ClientId::generate(),
                application_id,
                client_type,
                settings,
                secrets,
                keys: Vec::new(),
                status: Status::Enabled,
                created_at: now,
                updated_at: now,
                version: 0,
                self_registration: None,
            },
        };
        Ok((client, value))
    }

    /// Marks a new client as one that registered itself, from where.
    #[must_use]
    pub fn registered_from(mut self, registration: SelfRegistration) -> Self {
        self.state.self_registration = Some(registration);
        self
    }

    /// Whether it registered itself at the registration endpoint. Such a
    /// client is never first party, whatever its application says.
    #[must_use]
    pub const fn is_registered(&self) -> bool {
        self.state.self_registration.is_some()
    }

    /// Rebuilds a client from storage.
    #[must_use]
    pub const fn from_snapshot(state: ClientSnapshot) -> Self {
        Self { state }
    }

    /// Everything stored about it.
    #[must_use]
    pub const fn snapshot(&self) -> &ClientSnapshot {
        &self.state
    }

    /// Its identifier, the `client_id`.
    #[must_use]
    pub const fn id(&self) -> ClientId {
        self.state.id
    }

    /// The application it belongs to.
    #[must_use]
    pub const fn application_id(&self) -> ApplicationId {
        self.state.application_id
    }

    /// Whether it can keep a secret.
    #[must_use]
    pub const fn client_type(&self) -> ClientType {
        self.state.client_type
    }

    /// The service account or agent it acts as, if any.
    #[must_use]
    pub const fn principal(&self) -> Option<UserId> {
        self.state.settings.principal
    }

    /// Whether it gets tokens. The application must be enabled as well.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.state.status == Status::Enabled
    }

    /// Whether `presented` is, character for character, one of its
    /// redirect addresses.
    #[must_use]
    pub fn accepts_redirect_uri(&self, presented: &str) -> bool {
        self.state
            .settings
            .redirect_uris
            .iter()
            .any(|registered| registered == presented)
    }

    /// Whether `presented` is, character for character, one of its
    /// post-logout redirect addresses.
    #[must_use]
    pub fn accepts_post_logout_redirect_uri(&self, presented: &str) -> bool {
        self.state
            .settings
            .post_logout_redirect_uris
            .iter()
            .any(|registered| registered == presented)
    }

    /// Where its logout tokens are sent, if anywhere.
    #[must_use]
    pub fn backchannel_logout_uri(&self) -> Option<&str> {
        self.state.settings.backchannel_logout_uri.as_deref()
    }

    /// Where the client publishes its keys itself, if it does.
    #[must_use]
    pub fn jwks_uri(&self) -> Option<&str> {
        self.state.settings.jwks_uri.as_deref()
    }

    /// The address the signed-out page loads in a frame to tell it, if any.
    #[must_use]
    pub fn frontchannel_logout_uri(&self) -> Option<&str> {
        self.state.settings.frontchannel_logout_uri.as_deref()
    }

    /// The `max_age` of a request of this client that names none.
    #[must_use]
    pub const fn default_max_age(&self) -> Option<u32> {
        self.state.settings.default_max_age
    }

    /// The `acr_values` of a request of this client that names none, joined
    /// by spaces; `None` when it has no default assurance levels.
    #[must_use]
    pub fn default_acr_values(&self) -> Option<String> {
        let values = &self.state.settings.default_acr_values;
        (!values.is_empty()).then(|| values.join(" "))
    }

    /// How the client knows a person.
    #[must_use]
    pub const fn subject_type(&self) -> SubjectType {
        self.state.settings.subject_type
    }

    /// The client's sector, for a pairwise client: the host its pairwise
    /// identifiers are made for. None for a public client.
    #[must_use]
    pub fn sector(&self) -> Option<String> {
        let settings = &self.state.settings;
        match settings.subject_type {
            SubjectType::Public => None,
            SubjectType::Pairwise => sector_of(
                settings.sector_identifier_uri.as_deref(),
                &settings.redirect_uris,
            ),
        }
    }

    /// Whether `presented` is one of its secrets that works at `now`. A
    /// value that does not have the shape of a secret matches nothing.
    #[must_use]
    pub fn accepts_secret(&self, presented: &str, digest: &dyn Digest, now: Timestamp) -> bool {
        if !self.state.settings.authentication_method.uses_secret() {
            return false;
        }
        let Some(hash) = ClientSecretHash::of_presented(presented, digest) else {
            return false;
        };
        // Every secret is compared, so the time taken does not say which
        // one matched.
        self.state
            .secrets
            .iter()
            .filter(|secret| secret.works_at(now))
            .fold(false, |found, secret| hash.matches(&secret.hash) | found)
    }

    fn changed_event(&self) -> OauthEvent {
        OauthEvent::ClientChanged {
            client_id: self.state.id,
            application_id: self.state.application_id,
            client_type: self.state.client_type.as_str(),
            principal_id: self.state.settings.principal,
        }
    }

    /// The event that says the client was created, and the one for its
    /// first secret if it has one.
    #[must_use]
    pub fn created_events(&self) -> Vec<OauthEvent> {
        let mut events = vec![OauthEvent::ClientCreated {
            client_id: self.state.id,
            application_id: self.state.application_id,
            client_type: self.state.client_type.as_str(),
            principal_id: self.state.settings.principal,
        }];
        events.extend(
            self.state
                .secrets
                .iter()
                .map(|secret| OauthEvent::ClientSecretIssued {
                    client_id: self.state.id,
                    secret_id: secret.id,
                    expires_at: secret.expires_at,
                }),
        );
        events
    }

    /// Replaces the settings. Moving away from a secret method drops the
    /// secrets, and moving away from `private_key_jwt` drops the keys.
    /// Returns the events of the change, none if nothing changed.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error if a setting breaks its rule, and
    /// `oauth.client_jwks_uri_with_keys` for a key set address given to a
    /// client that has keys; nothing changes then.
    pub fn change(
        &mut self,
        settings: ClientSettings,
        now: Timestamp,
    ) -> Result<Vec<OauthEvent>, DomainError> {
        let settings = settings.checked(self.state.client_type)?;
        if settings == self.state.settings {
            return Ok(Vec::new());
        }
        // A client's keys are in one place: kept by Hodor, or at its
        // address.
        if settings.jwks_uri.is_some() && !self.state.keys.is_empty() {
            return Err(DomainError::conflict(
                "oauth.client_jwks_uri_with_keys",
                "a client with keys has no key set address: remove its keys first",
            ));
        }
        let method = settings.authentication_method;
        let mut events = vec![];
        if !method.uses_secret() {
            events.extend(self.state.secrets.drain(..).map(|secret| {
                OauthEvent::ClientSecretRevoked {
                    client_id: self.state.id,
                    secret_id: secret.id,
                }
            }));
        }
        if method != AuthenticationMethod::PrivateKeyJwt {
            events.extend(
                self.state
                    .keys
                    .drain(..)
                    .map(|key| OauthEvent::ClientKeyRemoved {
                        client_id: self.state.id,
                        key_id: key.key_id,
                    }),
            );
        }
        self.state.settings = settings;
        self.state.updated_at = now;
        events.insert(0, self.changed_event());
        Ok(events)
    }

    /// Makes a new secret living for `lifetime`. The newest secret that
    /// worked until now keeps working for `keep_previous_for` more, if it
    /// would not expire before; every other secret stops at once. Returns
    /// the new secret, once, with the events.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_secret_not_allowed` for a client that does
    /// not use a secret method, and `Invalid` for a lifetime or an overlap
    /// that is not acceptable.
    pub fn rotate_secret(
        &mut self,
        lifetime: Duration,
        keep_previous_for: Duration,
        now: Timestamp,
        random: &dyn RandomSource,
        digest: &dyn Digest,
    ) -> Result<(ClientSecretValue, Vec<OauthEvent>), DomainError> {
        if !self.state.settings.authentication_method.uses_secret() {
            return Err(secret_not_allowed());
        }
        if keep_previous_for < Duration::ZERO || keep_previous_for > ClientSecret::LONGEST_OVERLAP {
            return Err(DomainError::invalid(
                "oauth.client_secret_overlap_invalid",
                "a previous secret keeps working for 0 to 30 days",
            ));
        }
        let (secret, value) = ClientSecret::make(lifetime, now, random, digest)?;
        let newest_working = self
            .state
            .secrets
            .iter()
            .filter(|old| old.works_at(now))
            .max_by_key(|old| (old.created_at, old.id))
            .map(|old| old.id);
        let client_id = self.state.id;
        let mut events = vec![OauthEvent::ClientSecretIssued {
            client_id,
            secret_id: secret.id,
            expires_at: secret.expires_at,
        }];
        let mut kept = Vec::new();
        for mut old in self.state.secrets.drain(..) {
            let was_working = old.works_at(now);
            if Some(old.id) == newest_working {
                old.expires_at = old.expires_at.min(now + keep_previous_for);
                if old.works_at(now) {
                    kept.push(old);
                    continue;
                }
            }
            // A secret that had already expired is dropped without a word.
            if was_working {
                events.push(OauthEvent::ClientSecretRevoked {
                    client_id,
                    secret_id: old.id,
                });
            }
        }
        kept.push(secret);
        self.state.secrets = kept;
        self.state.updated_at = now;
        Ok((value, events))
    }

    /// Ends one secret at once.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_secret_not_found` if the client has no such
    /// secret.
    pub fn revoke_secret(
        &mut self,
        secret_id: ClientSecretId,
        now: Timestamp,
    ) -> Result<OauthEvent, DomainError> {
        let before = self.state.secrets.len();
        self.state.secrets.retain(|secret| secret.id != secret_id);
        if self.state.secrets.len() == before {
            return Err(DomainError::not_found(
                "oauth.client_secret_not_found",
                "the client has no such secret",
            ));
        }
        self.state.updated_at = now;
        Ok(OauthEvent::ClientSecretRevoked {
            client_id: self.state.id,
            secret_id,
        })
    }

    /// Adds a public key, for `private_key_jwt`.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_key_not_allowed` for a client that does not
    /// use `private_key_jwt`, `oauth.client_keys_at_address` for one with
    /// a key set address, `oauth.client_key_taken` if it has a key
    /// with the same `kid`, and `oauth.client_too_many_keys` if it has 5.
    pub fn add_key(&mut self, key: ClientKey, now: Timestamp) -> Result<OauthEvent, DomainError> {
        if self.state.settings.authentication_method != AuthenticationMethod::PrivateKeyJwt {
            return Err(DomainError::invalid(
                "oauth.client_key_not_allowed",
                "only a client using `private_key_jwt` has keys",
            ));
        }
        if self.state.settings.jwks_uri.is_some() {
            return Err(DomainError::invalid(
                "oauth.client_keys_at_address",
                "the client publishes its keys at its key set address, and has no others",
            ));
        }
        if self.state.keys.iter().any(|kept| kept.key_id == key.key_id) {
            return Err(DomainError::conflict(
                "oauth.client_key_taken",
                "the client already has a key with this `kid`",
            ));
        }
        if self.state.keys.len() >= MAX_KEYS {
            return Err(DomainError::conflict(
                "oauth.client_too_many_keys",
                "a client has at most 5 keys",
            ));
        }
        let event = OauthEvent::ClientKeyAdded {
            client_id: self.state.id,
            key_id: key.key_id.clone(),
        };
        self.state.keys.push(key);
        self.state.updated_at = now;
        Ok(event)
    }

    /// Removes the key with this `kid`.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_key_not_found` if the client has none.
    pub fn remove_key(&mut self, key_id: &str, now: Timestamp) -> Result<OauthEvent, DomainError> {
        let before = self.state.keys.len();
        self.state.keys.retain(|key| key.key_id != key_id);
        if self.state.keys.len() == before {
            return Err(DomainError::not_found(
                "oauth.client_key_not_found",
                "the client has no key with this `kid`",
            ));
        }
        self.state.updated_at = now;
        Ok(OauthEvent::ClientKeyRemoved {
            client_id: self.state.id,
            key_id: key_id.to_owned(),
        })
    }

    /// Sets the status. Returns the event if anything changed.
    pub fn set_status(&mut self, status: Status, now: Timestamp) -> Option<OauthEvent> {
        if self.state.status == status {
            return None;
        }
        self.state.status = status;
        self.state.updated_at = now;
        let client_id = self.state.id;
        Some(match status {
            Status::Enabled => OauthEvent::ClientEnabled { client_id },
            Status::Disabled => OauthEvent::ClientDisabled { client_id },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::random::testing::{CountingRandom, FakeDigest};

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn web() -> ClientSettings {
        ClientSettings::new(
            "Payroll web",
            ClientType::Confidential,
            vec![GrantType::AuthorizationCode, GrantType::RefreshToken],
            vec!["https://payroll.example.com/callback".to_owned()],
        )
    }

    #[test]
    fn a_pairwise_client_signs_people_in_and_has_a_sector() {
        let pairwise = |settings: ClientSettings| ClientSettings {
            subject_type: SubjectType::Pairwise,
            ..settings
        };
        // Its sector is the one host of its redirect addresses.
        let checked = pairwise(web())
            .checked(ClientType::Confidential)
            .expect("one host");
        let (client, _) = create(ClientType::Confidential, checked).expect("client");
        assert_eq!(client.subject_type(), SubjectType::Pairwise);
        assert_eq!(client.sector().as_deref(), Some("payroll.example.com"));
        // A public client has no sector.
        let (public, _) = create(ClientType::Confidential, web()).expect("public");
        assert_eq!(public.sector(), None);

        // Two hosts need a sector identifier address, whose host is then
        // the sector.
        let mut two_hosts = pairwise(web());
        two_hosts
            .redirect_uris
            .push("https://payroll.example.net/callback".to_owned());
        let error = two_hosts
            .clone()
            .checked(ClientType::Confidential)
            .expect_err("two hosts");
        assert_eq!(error.code(), "oauth.client_sector_identifier_uri_required");
        let named = ClientSettings {
            sector_identifier_uri: Some("https://sector.example.org/uris.json".to_owned()),
            ..two_hosts
        };
        let (client, _) = create(ClientType::Confidential, named).expect("named");
        assert_eq!(client.sector().as_deref(), Some("sector.example.org"));

        // So does a private-use scheme.
        let mobile = ClientSettings::new(
            "Payroll mobile",
            ClientType::Public,
            vec![GrantType::AuthorizationCode],
            vec!["com.example.payroll:/callback".to_owned()],
        );
        let error = pairwise(mobile)
            .checked(ClientType::Public)
            .expect_err("no host");
        assert_eq!(error.code(), "oauth.client_sector_identifier_uri_required");

        // Only a client with `authorization_code` may be pairwise.
        let service = ClientSettings::new(
            "Payroll service",
            ClientType::Confidential,
            vec![GrantType::ClientCredentials],
            Vec::new(),
        );
        let error = pairwise(service)
            .checked(ClientType::Confidential)
            .expect_err("no code");
        assert_eq!(error.code(), "oauth.client_subject_type_invalid");

        // Only a pairwise client has a sector identifier address, and it
        // has the form of an address Hodor calls.
        let public_with_address = ClientSettings {
            sector_identifier_uri: Some("https://sector.example.org/uris.json".to_owned()),
            ..web()
        };
        let error = public_with_address
            .checked(ClientType::Confidential)
            .expect_err("public");
        assert_eq!(error.code(), "oauth.client_sector_identifier_uri_invalid");
        let fragment = ClientSettings {
            sector_identifier_uri: Some("https://sector.example.org/uris.json#x".to_owned()),
            ..pairwise(web())
        };
        let error = fragment
            .checked(ClientType::Confidential)
            .expect_err("fragment");
        assert_eq!(error.code(), "oauth.client_sector_identifier_uri_invalid");
    }

    #[test]
    fn the_defaults_for_a_sign_in_are_for_a_client_that_signs_people_in() {
        let with = |settings: ClientSettings| ClientSettings {
            default_max_age: Some(3600),
            default_acr_values: vec![
                "urn:hodor:acr:mfa".to_owned(),
                "urn:hodor:acr:single-factor".to_owned(),
                "urn:hodor:acr:mfa".to_owned(),
            ],
            require_auth_time: true,
            ..settings
        };
        let (client, _) = create(ClientType::Confidential, with(web())).expect("client");
        assert_eq!(client.default_max_age(), Some(3600));
        // Kept in order, without repeats, and joined as `acr_values`.
        assert_eq!(
            client.default_acr_values().as_deref(),
            Some("urn:hodor:acr:mfa urn:hodor:acr:single-factor")
        );
        assert!(client.snapshot().settings.require_auth_time);
        let (plain, _) = create(ClientType::Confidential, web()).expect("plain");
        assert_eq!(plain.default_max_age(), None);
        assert_eq!(plain.default_acr_values(), None);
        assert!(!plain.snapshot().settings.require_auth_time);

        // Zero and a year are the bounds, as for `max_age`.
        for seconds in [0, MAX_DEFAULT_MAX_AGE] {
            let settings = ClientSettings {
                default_max_age: Some(seconds),
                ..web()
            };
            assert!(settings.checked(ClientType::Confidential).is_ok());
        }
        let error = ClientSettings {
            default_max_age: Some(MAX_DEFAULT_MAX_AGE + 1),
            ..web()
        }
        .checked(ClientType::Confidential)
        .expect_err("too long");
        assert_eq!(error.code(), "oauth.client_default_max_age_invalid");

        // Names: printable without spaces, at most 10, 255 characters
        // together.
        for values in [
            vec![String::new()],
            vec!["two words".to_owned()],
            vec!["a".repeat(129)],
            (0..11).map(|n| format!("level-{n}")).collect(),
            (0..3).map(|n| format!("{n}{}", "a".repeat(90))).collect(),
        ] {
            let error = ClientSettings {
                default_acr_values: values,
                ..web()
            }
            .checked(ClientType::Confidential)
            .expect_err("refused");
            assert_eq!(error.code(), "oauth.client_default_acr_values_invalid");
        }

        // A client that signs nobody in has none of them.
        let service = || {
            ClientSettings::new(
                "Payroll service",
                ClientType::Confidential,
                vec![GrantType::ClientCredentials],
                Vec::new(),
            )
        };
        let refused = |settings: ClientSettings| {
            settings
                .checked(ClientType::Confidential)
                .expect_err("no code")
                .code()
                .to_owned()
        };
        assert_eq!(
            refused(ClientSettings {
                default_max_age: Some(60),
                ..service()
            }),
            "oauth.client_default_max_age_invalid"
        );
        assert_eq!(
            refused(ClientSettings {
                default_acr_values: vec!["urn:hodor:acr:mfa".to_owned()],
                ..service()
            }),
            "oauth.client_default_acr_values_invalid"
        );
        assert_eq!(
            refused(ClientSettings {
                require_auth_time: true,
                ..service()
            }),
            "oauth.client_require_auth_time_invalid"
        );
    }

    fn spa() -> ClientSettings {
        ClientSettings::new(
            "Payroll in the browser",
            ClientType::Public,
            vec![GrantType::AuthorizationCode],
            vec!["https://payroll.example.com/app".to_owned()],
        )
    }

    fn create(
        client_type: ClientType,
        settings: ClientSettings,
    ) -> Result<(Client, Option<ClientSecretValue>), DomainError> {
        Client::create(
            ApplicationId::generate(),
            client_type,
            settings,
            ClientSecret::DEFAULT_LIFETIME,
            NOW,
            &CountingRandom::default(),
            &FakeDigest,
        )
    }

    fn redirect(value: &str, client_type: ClientType) -> Result<(), DomainError> {
        check_redirect_uri(value, client_type)
    }

    #[test]
    fn a_client_with_a_principal_has_client_credentials_and_no_other_grant() {
        let workload = UserId::generate();
        let mut service = ClientSettings::new(
            "Nightly export",
            ClientType::Confidential,
            vec![GrantType::ClientCredentials],
            Vec::new(),
        );
        service.principal = Some(workload);
        let (mut client, _) = create(ClientType::Confidential, service.clone()).expect("valid");
        assert_eq!(client.principal(), Some(workload));
        let events = client.created_events();
        assert!(
            matches!(&events[0], OauthEvent::ClientCreated { principal_id, .. } if *principal_id == Some(workload)),
            "{events:?}"
        );

        // An agent's client may also exchange tokens, with rules.
        let mut exchanging = service.clone();
        exchanging.grant_types = vec![GrantType::ClientCredentials, GrantType::TokenExchange];
        assert_eq!(
            create(ClientType::Confidential, exchanging.clone())
                .expect_err("no rule")
                .code(),
            "oauth.client_exchange_rules_invalid"
        );
        exchanging.exchange_rules = vec![ExchangeRule {
            subject_audience: "urn:example:assistant".to_owned(),
            audience: "https://api.example.com".to_owned(),
        }];
        let (agent_client, _) =
            create(ClientType::Confidential, exchanging.clone()).expect("valid");
        assert!(agent_client.snapshot().settings.exchange_rules[0].allows(
            &["urn:example:assistant".to_owned()],
            "https://api.example.com"
        ));
        let mut unbound = exchanging.clone();
        unbound.principal = None;
        assert_eq!(
            create(ClientType::Confidential, unbound)
                .expect_err("no principal")
                .code(),
            "oauth.client_grants_invalid"
        );
        let mut stray = service.clone();
        stray.exchange_rules = exchanging.exchange_rules.clone();
        assert_eq!(
            create(ClientType::Confidential, stray)
                .expect_err("rules without the grant")
                .code(),
            "oauth.client_exchange_rules_invalid"
        );
        assert_eq!(
            GrantType::parse(TOKEN_EXCHANGE_GRANT).expect("known"),
            GrantType::TokenExchange
        );

        let mut bound_web = web();
        bound_web.principal = Some(workload);
        assert_eq!(
            create(ClientType::Confidential, bound_web)
                .expect_err("refused")
                .code(),
            "oauth.client_grants_invalid"
        );

        // Removing the principal is a change like any other.
        let mut unbound = service;
        unbound.principal = None;
        let events = client.change(unbound, NOW).expect("changed");
        assert!(
            matches!(
                &events[0],
                OauthEvent::ClientChanged {
                    principal_id: None,
                    ..
                }
            ),
            "{events:?}"
        );
        assert_eq!(client.principal(), None);
    }

    #[test]
    fn post_logout_addresses_follow_the_rules_of_redirect_addresses() {
        let mut settings = web();
        settings.post_logout_redirect_uris = vec![
            "https://payroll.example.com/signed-out".to_owned(),
            "https://payroll.example.com/signed-out".to_owned(),
        ];
        let (client, _) = create(ClientType::Confidential, settings).expect("valid");
        assert_eq!(
            client.snapshot().settings.post_logout_redirect_uris,
            ["https://payroll.example.com/signed-out"],
            "repeats are removed"
        );
        assert!(client.accepts_post_logout_redirect_uri("https://payroll.example.com/signed-out"));
        assert!(
            !client.accepts_post_logout_redirect_uri("https://payroll.example.com/signed-out/")
        );
        assert!(
            !client.accepts_post_logout_redirect_uri("https://payroll.example.com/callback"),
            "a redirect address is not a post-logout one"
        );
        assert!(!client.accepts_redirect_uri("https://payroll.example.com/signed-out"));

        for bad in [
            "http://payroll.example.com/out",
            "https://payroll.example.com/out#here",
            "com.example.app:/out",
        ] {
            let mut settings = web();
            settings.post_logout_redirect_uris = vec![bad.to_owned()];
            let error = create(ClientType::Confidential, settings).expect_err(bad);
            assert_eq!(
                error.code(),
                "oauth.client_post_logout_redirect_uri_invalid",
                "{bad}"
            );
        }

        let mut many = web();
        many.post_logout_redirect_uris =
            (0..11).map(|n| format!("https://a.example/{n}")).collect();
        assert_eq!(
            create(ClientType::Confidential, many)
                .expect_err("too many")
                .code(),
            "oauth.client_post_logout_redirect_uri_invalid"
        );

        let mut service = ClientSettings::new(
            "Payroll batch",
            ClientType::Confidential,
            vec![GrantType::ClientCredentials],
            Vec::new(),
        );
        service.post_logout_redirect_uris = vec!["https://payroll.example.com/out".to_owned()];
        assert_eq!(
            create(ClientType::Confidential, service)
                .expect_err("no code")
                .code(),
            "oauth.client_post_logout_redirect_uri_invalid"
        );

        let mut public = spa();
        public.post_logout_redirect_uris = vec!["com.example.payroll:/signed-out".to_owned()];
        create(ClientType::Public, public).expect("a public client may use a private-use scheme");
    }

    #[test]
    fn a_confidential_client_gets_its_first_secret_once() {
        let (client, value) = create(ClientType::Confidential, web()).expect("valid");
        let value = value.expect("a secret method gets a secret");
        assert!(client.accepts_secret(value.expose(), &FakeDigest, NOW));
        assert_eq!(client.snapshot().secrets.len(), 1);
        assert_eq!(
            client
                .created_events()
                .iter()
                .map(hodor_kernel::DomainEvent::event_type)
                .collect::<Vec<_>>(),
            ["oauth.client_created", "oauth.client_secret_issued"]
        );
        let mut jwt = web();
        jwt.authentication_method = AuthenticationMethod::PrivateKeyJwt;
        let (client, value) = create(ClientType::Confidential, jwt).expect("valid");
        assert!(value.is_none());
        assert!(client.snapshot().secrets.is_empty());
    }

    #[test]
    fn an_id_token_algorithm_is_es256_unless_another_of_the_four_is_chosen() {
        assert_eq!(IdTokenAlgorithm::default(), IdTokenAlgorithm::Es256);
        assert_eq!(
            IdTokenAlgorithm::ALL.map(IdTokenAlgorithm::as_str),
            ["ES256", "RS256", "PS256", "EdDSA"]
        );
        for algorithm in IdTokenAlgorithm::ALL {
            assert_eq!(IdTokenAlgorithm::parse(algorithm.as_str()), Ok(algorithm));
            assert_eq!(
                IdTokenAlgorithm::parse_for_userinfo(algorithm.as_str()),
                Ok(algorithm)
            );
            // Each signs with a key of its own algorithm, which every
            // provider makes, and checks as that algorithm.
            assert_eq!(
                algorithm.key_algorithm().as_str(),
                algorithm.as_str(),
                "one name"
            );
            assert_eq!(
                algorithm.key_algorithm().signature(),
                Some(algorithm.signature())
            );
        }
        assert_eq!(IdTokenAlgorithm::Ps256.key_algorithm(), KeyAlgorithm::Ps256);
        assert_eq!(IdTokenAlgorithm::EdDsa.key_algorithm(), KeyAlgorithm::EdDsa);
        // Algorithms no tenant signs with: never saved.
        for refused in [
            "HS256", "none", "None", "rs256", "ES384", "RS512", "Ed25519", "Ed448", "EDDSA", "",
        ] {
            assert_eq!(
                IdTokenAlgorithm::parse(refused)
                    .expect_err("refused")
                    .code(),
                "oauth.client_id_token_algorithm_invalid"
            );
            assert_eq!(
                IdTokenAlgorithm::parse_for_userinfo(refused)
                    .expect_err("refused")
                    .code(),
                "oauth.client_userinfo_algorithm_invalid"
            );
        }
    }

    #[test]
    fn userinfo_answers_are_json_unless_an_algorithm_is_chosen() {
        assert_eq!(web().userinfo_algorithm, None);
        let mut settings = web();
        settings.userinfo_algorithm = Some(IdTokenAlgorithm::EdDsa);
        settings.id_token_algorithm = IdTokenAlgorithm::Ps256;
        let (client, _) = create(ClientType::Confidential, settings).expect("valid");
        assert_eq!(
            client.snapshot().settings.userinfo_algorithm,
            Some(IdTokenAlgorithm::EdDsa)
        );
        assert_eq!(
            client.snapshot().settings.id_token_algorithm,
            IdTokenAlgorithm::Ps256
        );
    }

    #[test]
    fn a_request_object_algorithm_is_named_as_json_web_signature_names_it() {
        assert_eq!(web().request_object_algorithm, None);
        for algorithm in RequestObjectAlgorithm::ALL {
            assert_eq!(
                RequestObjectAlgorithm::parse(algorithm.as_str()),
                Ok(algorithm)
            );
        }
        assert_eq!(
            RequestObjectAlgorithm::Ps256.signature(),
            Some(SignatureAlgorithm::Ps256)
        );
        assert_eq!(RequestObjectAlgorithm::None.signature(), None);
        for refused in ["HS256", "ES384", "EdDSA", "None", "es256", ""] {
            assert_eq!(
                RequestObjectAlgorithm::parse(refused)
                    .expect_err("refused")
                    .code(),
                "oauth.client_request_object_algorithm_invalid"
            );
        }
        // Kept as it was given through every check of the settings.
        let mut settings = web();
        settings.request_object_algorithm = Some(RequestObjectAlgorithm::None);
        let (client, _) = create(ClientType::Confidential, settings).expect("valid");
        assert_eq!(
            client.snapshot().settings.request_object_algorithm,
            Some(RequestObjectAlgorithm::None)
        );
    }

    #[test]
    fn a_public_client_has_no_secret_and_always_uses_pkce() {
        let (mut client, value) = create(ClientType::Public, spa()).expect("valid");
        assert!(value.is_none());
        let error = client
            .rotate_secret(
                ClientSecret::DEFAULT_LIFETIME,
                Duration::ZERO,
                NOW,
                &CountingRandom::default(),
                &FakeDigest,
            )
            .expect_err("a public client has no secret");
        assert_eq!(error.code(), "oauth.client_secret_not_allowed");

        for method in [
            AuthenticationMethod::ClientSecretBasic,
            AuthenticationMethod::ClientSecretPost,
            AuthenticationMethod::PrivateKeyJwt,
        ] {
            let mut settings = spa();
            settings.authentication_method = method;
            let error = create(ClientType::Public, settings).expect_err("public with a method");
            assert_eq!(error.code(), "oauth.client_authentication_method_invalid");
        }
        let mut no_pkce = spa();
        no_pkce.require_pkce = false;
        assert_eq!(
            create(ClientType::Public, no_pkce)
                .expect_err("no pkce")
                .code(),
            "oauth.client_pkce_required"
        );
        let mut confidential_without_pkce = web();
        confidential_without_pkce.require_pkce = false;
        assert!(create(ClientType::Confidential, confidential_without_pkce).is_ok());
        let mut none = web();
        none.authentication_method = AuthenticationMethod::None;
        assert_eq!(
            create(ClientType::Confidential, none)
                .expect_err("none")
                .code(),
            "oauth.client_authentication_method_invalid"
        );
    }

    #[test]
    fn grants_follow_their_rules() {
        let with = |client_type, grants: Vec<GrantType>, redirects: Vec<&str>| {
            let mut settings = if client_type == ClientType::Public {
                spa()
            } else {
                web()
            };
            settings.response_types =
                crate::domain::response::response_types_kept(&settings.response_types, &grants);
            settings.grant_types = grants;
            settings.redirect_uris = redirects.into_iter().map(str::to_owned).collect();
            create(client_type, settings).map(|(client, _)| client)
        };
        let callback = "https://payroll.example.com/callback";
        let refused = [
            with(ClientType::Confidential, vec![], vec![]),
            with(
                ClientType::Confidential,
                vec![GrantType::RefreshToken],
                vec![callback],
            ),
            with(
                ClientType::Public,
                vec![GrantType::ClientCredentials],
                vec![],
            ),
        ];
        for result in refused {
            assert_eq!(
                result.expect_err("refused").code(),
                "oauth.client_grants_invalid"
            );
        }
        let machine = with(
            ClientType::Confidential,
            vec![GrantType::ClientCredentials],
            vec![],
        )
        .expect("a service");
        assert!(machine.snapshot().settings.redirect_uris.is_empty());
        assert_eq!(
            with(
                ClientType::Confidential,
                vec![GrantType::ClientCredentials],
                vec![callback]
            )
            .expect_err("a redirect without a code")
            .code(),
            "oauth.client_redirect_uri_invalid"
        );
        assert_eq!(
            with(
                ClientType::Confidential,
                vec![GrantType::AuthorizationCode],
                vec![]
            )
            .expect_err("a code without a redirect")
            .code(),
            "oauth.client_redirect_uri_invalid"
        );
        let tidied = with(
            ClientType::Confidential,
            vec![
                GrantType::RefreshToken,
                GrantType::AuthorizationCode,
                GrantType::RefreshToken,
            ],
            vec![callback, callback],
        )
        .expect("tidied");
        assert_eq!(
            tidied.snapshot().settings.grant_types,
            [GrantType::AuthorizationCode, GrantType::RefreshToken]
        );
        assert_eq!(tidied.snapshot().settings.redirect_uris, [callback]);
    }

    #[test]
    fn response_types_belong_to_a_client_of_the_authorization_code() {
        // `code` unless chosen.
        let (client, _) = create(ClientType::Confidential, web()).expect("valid");
        assert_eq!(
            client.snapshot().settings.response_types,
            [ResponseType::Code]
        );
        let machine = ClientSettings::new(
            "Nightly export",
            ClientType::Confidential,
            vec![GrantType::ClientCredentials],
            Vec::new(),
        );
        assert!(machine.response_types.is_empty());

        // Kept once each, in a fixed order, whatever order they came in.
        let every = ClientSettings {
            response_types: vec![
                ResponseType::None,
                ResponseType::CodeIdToken,
                ResponseType::IdToken,
                ResponseType::Code,
                ResponseType::IdToken,
            ],
            ..spa()
        };
        let (client, _) = create(ClientType::Public, every).expect("valid");
        assert_eq!(client.snapshot().settings.response_types, ResponseType::ALL);

        // At least one with the grant, none without it.
        let refused = [
            (
                ClientType::Confidential,
                ClientSettings {
                    response_types: Vec::new(),
                    ..web()
                },
            ),
            (
                ClientType::Confidential,
                ClientSettings {
                    response_types: vec![ResponseType::IdToken],
                    ..machine
                },
            ),
        ];
        for (kind, settings) in refused {
            assert_eq!(
                create(kind, settings).expect_err("refused").code(),
                "oauth.client_response_types_invalid"
            );
        }
    }

    #[test]
    fn a_redirect_address_follows_the_rules() {
        use ClientType::{Confidential, Public};
        for good in [
            "https://payroll.example.com/callback",
            "https://payroll.example.com:8443/callback?tenant=a",
            "https://[2001:db8::1]/callback",
            "https://[2001:db8::1]:8443/callback",
            "http://127.0.0.1/callback",
            "http://127.0.0.1:51004/callback",
            "http://[::1]:8080",
        ] {
            assert!(redirect(good, Confidential).is_ok(), "{good}");
            assert!(redirect(good, Public).is_ok(), "{good}");
        }
        assert!(redirect("com.example.payroll:/callback", Public).is_ok());
        assert!(redirect("com.example.payroll:/callback", Confidential).is_err());
        for bad in [
            "",
            "https://",
            "https:///callback",
            "https://user:password@payroll.example.com/callback",
            "https://payroll.example.com/callback#fragment",
            "https://*.example.com/callback",
            "https://payroll.example.com/call back",
            "https://payroll.example.com:0/callback",
            "https://payroll.example.com:70000/callback",
            "https://payroll.example.com:port/callback",
            "https://payroll.example.com\\@evil.example/",
            "HTTPS://payroll.example.com/callback",
            "http://payroll.example.com/callback",
            "http://localhost:8080/callback",
            "http://127.0.0.1.evil.example/callback",
            "http://127.0.0.1:/callback",
            "http://127.0.0.2/callback",
            "javascript:alert(1)",
            "data:text/html,hi",
            "payroll:/callback",
            "com.example.:/callback",
            "com.example.payroll:",
            "Com.Example:/callback",
            "/callback",
            "https://payroll.example.com/é",
            &format!("https://payroll.example.com/{}", "a".repeat(2000)),
        ] {
            assert_eq!(
                redirect(bad, Public).expect_err(bad).code(),
                "oauth.client_redirect_uri_invalid",
                "{bad}"
            );
        }
    }

    #[test]
    fn a_redirect_address_is_compared_by_exact_equality() {
        let (client, _) = create(ClientType::Confidential, web()).expect("valid");
        assert!(client.accepts_redirect_uri("https://payroll.example.com/callback"));
        for near in [
            "https://payroll.example.com/callback/",
            "https://payroll.example.com/Callback",
            "https://PAYROLL.example.com/callback",
            "https://payroll.example.com/callback?x=1",
            "https://payroll.example.com:443/callback",
            "https://payroll.example.com/callback#",
            "https://payroll.example.com/cal",
            "",
        ] {
            assert!(!client.accepts_redirect_uri(near), "{near}");
        }
    }

    #[test]
    fn scopes_token_policy_and_limits_are_held_to_their_rules() {
        let mut scopes = web();
        scopes.allowed_scopes = vec!["openid".into(), "read".into(), "openid".into()];
        let (client, _) = create(ClientType::Confidential, scopes).expect("valid");
        assert_eq!(
            client.snapshot().settings.allowed_scopes,
            ["openid", "read"]
        );
        for bad in [
            vec!["two words".to_owned()],
            (0..51).map(|n| format!("s{n}")).collect(),
        ] {
            let mut settings = web();
            settings.allowed_scopes = bad;
            assert_eq!(
                create(ClientType::Confidential, settings)
                    .expect_err("scopes")
                    .code(),
                "oauth.client_scope_invalid"
            );
        }
        let mut redirects = web();
        redirects.redirect_uris = (0..11).map(|n| format!("https://a.example/{n}")).collect();
        assert!(create(ClientType::Confidential, redirects).is_err());

        let default = TokenPolicy::default();
        let bad_policies = [
            TokenPolicy {
                access_token: Duration::seconds(59),
                ..default
            },
            TokenPolicy {
                access_token: Duration::minutes(61),
                ..default
            },
            // No signed token may outlive the key that signed it in the
            // published key set.
            TokenPolicy {
                access_token: TokenPolicy::LONGEST_SIGNED_LIFETIME + Duration::SECOND,
                ..default
            },
            TokenPolicy {
                id_token: TokenPolicy::LONGEST_SIGNED_LIFETIME + Duration::SECOND,
                ..default
            },
            TokenPolicy {
                id_token: Duration::ZERO,
                ..default
            },
            TokenPolicy {
                refresh_token: Duration::minutes(59),
                ..default
            },
            TokenPolicy {
                refresh_token: Duration::days(366),
                ..default
            },
            TokenPolicy {
                refresh_idle: Duration::minutes(59),
                ..default
            },
            TokenPolicy {
                refresh_idle: Duration::days(31),
                ..default
            },
            TokenPolicy {
                consent: Duration::hours(23),
                ..default
            },
            TokenPolicy {
                consent: Duration::days(731),
                ..default
            },
        ];
        for policy in bad_policies {
            let mut settings = web();
            settings.token_policy = policy;
            assert_eq!(
                create(ClientType::Confidential, settings)
                    .expect_err("policy")
                    .code(),
                "oauth.token_policy_invalid"
            );
        }
        let mut name = web();
        name.name = String::new();
        assert_eq!(
            create(ClientType::Confidential, name)
                .expect_err("name")
                .code(),
            "oauth.client_name_invalid"
        );
    }

    #[test]
    fn a_rotation_keeps_only_the_newest_previous_secret_for_a_while() {
        let random = crate::testing::DistinctRandom;
        let (mut client, first) = create(ClientType::Confidential, web()).expect("valid");
        let first = first.expect("first secret");
        let day = Duration::days(1);
        let (second, events) = client
            .rotate_secret(
                ClientSecret::DEFAULT_LIFETIME,
                Duration::days(7),
                NOW + day,
                &random,
                &FakeDigest,
            )
            .expect("rotated");
        assert_eq!(events.len(), 1, "{events:?}");
        assert!(client.accepts_secret(first.expose(), &FakeDigest, NOW + day));
        assert!(client.accepts_secret(second.expose(), &FakeDigest, NOW + day));
        assert!(!client.accepts_secret(first.expose(), &FakeDigest, NOW + day * 8));
        assert!(client.accepts_secret(second.expose(), &FakeDigest, NOW + day * 8));

        // A third secret ends the first at once and keeps the second.
        let (third, events) = client
            .rotate_secret(
                ClientSecret::DEFAULT_LIFETIME,
                Duration::days(2),
                NOW + day * 2,
                &random,
                &FakeDigest,
            )
            .expect("rotated");
        let kinds: Vec<_> = events
            .iter()
            .map(hodor_kernel::DomainEvent::event_type)
            .collect();
        assert_eq!(
            kinds,
            ["oauth.client_secret_issued", "oauth.client_secret_revoked"]
        );
        let at = NOW + day * 2;
        assert!(!client.accepts_secret(first.expose(), &FakeDigest, at));
        assert!(client.accepts_secret(second.expose(), &FakeDigest, at));
        assert!(client.accepts_secret(third.expose(), &FakeDigest, at));
        assert_eq!(client.snapshot().secrets.len(), 2);

        // Without an overlap, the previous secret stops at once.
        let (fourth, _) = client
            .rotate_secret(
                ClientSecret::DEFAULT_LIFETIME,
                Duration::ZERO,
                at,
                &random,
                &FakeDigest,
            )
            .expect("rotated");
        assert!(!client.accepts_secret(third.expose(), &FakeDigest, at));
        assert!(client.accepts_secret(fourth.expose(), &FakeDigest, at));
        assert_eq!(client.snapshot().secrets.len(), 1);

        for overlap in [Duration::days(31), Duration::seconds(-1)] {
            let error = client
                .rotate_secret(
                    ClientSecret::DEFAULT_LIFETIME,
                    overlap,
                    at,
                    &random,
                    &FakeDigest,
                )
                .expect_err("overlap");
            assert_eq!(error.code(), "oauth.client_secret_overlap_invalid");
        }
    }

    #[test]
    fn a_secret_stops_when_revoked_or_expired() {
        let (mut client, value) = create(ClientType::Confidential, web()).expect("valid");
        let value = value.expect("secret");
        assert!(!client.accepts_secret(
            value.expose(),
            &FakeDigest,
            NOW + ClientSecret::DEFAULT_LIFETIME
        ));
        assert!(!client.accepts_secret("hodor_cs_not-a-secret", &FakeDigest, NOW));
        let id = client.snapshot().secrets[0].id;
        let event = client.revoke_secret(id, NOW).expect("revoked");
        assert_eq!(
            hodor_kernel::DomainEvent::event_type(&event),
            "oauth.client_secret_revoked"
        );
        assert!(!client.accepts_secret(value.expose(), &FakeDigest, NOW));
        assert_eq!(
            client.revoke_secret(id, NOW).expect_err("gone").code(),
            "oauth.client_secret_not_found"
        );
    }

    #[test]
    fn switching_the_method_drops_what_the_old_one_used() {
        let (mut client, value) = create(ClientType::Confidential, web()).expect("valid");
        let value = value.expect("secret");
        let mut jwt = web();
        jwt.authentication_method = AuthenticationMethod::PrivateKeyJwt;
        let events = client.change(jwt.clone(), NOW).expect("changed");
        let kinds: Vec<_> = events
            .iter()
            .map(hodor_kernel::DomainEvent::event_type)
            .collect();
        assert_eq!(
            kinds,
            ["oauth.client_changed", "oauth.client_secret_revoked"]
        );
        assert!(!client.accepts_secret(value.expose(), &FakeDigest, NOW));
        assert!(client.change(jwt, NOW).expect("same").is_empty());

        let key = ClientKey::parse(
            r#"{"kty":"OKP","crv":"Ed25519","kid":"one","x":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}"#,
            NOW,
        )
        .expect("key");
        client.add_key(key.clone(), NOW).expect("added");
        assert_eq!(
            client.add_key(key, NOW).expect_err("same kid").code(),
            "oauth.client_key_taken"
        );
        let events = client.change(web(), NOW).expect("back to a secret");
        let kinds: Vec<_> = events
            .iter()
            .map(hodor_kernel::DomainEvent::event_type)
            .collect();
        assert_eq!(kinds, ["oauth.client_changed", "oauth.client_key_removed"]);
        assert!(client.snapshot().keys.is_empty());
        assert!(
            client.snapshot().secrets.is_empty(),
            "a new secret is made by rotation"
        );
    }

    #[test]
    fn a_client_has_its_keys_kept_by_hodor_or_at_its_address_never_both() {
        const ADDRESS: &str = "https://payroll.example.com/jwks";
        let key = ClientKey::parse(
            r#"{"kty":"OKP","crv":"Ed25519","kid":"one","x":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}"#,
            NOW,
        )
        .expect("key");
        // Only a client using `private_key_jwt` has an address.
        let mut secret_with_address = web();
        secret_with_address.jwks_uri = Some(ADDRESS.to_owned());
        assert_eq!(
            create(ClientType::Confidential, secret_with_address)
                .expect_err("a secret method")
                .code(),
            "oauth.client_jwks_uri_invalid"
        );
        let mut jwt = web();
        jwt.authentication_method = AuthenticationMethod::PrivateKeyJwt;
        let mut bad = jwt.clone();
        bad.jwks_uri = Some("https://payroll.example.com/jwks#now".to_owned());
        assert_eq!(
            create(ClientType::Confidential, bad)
                .expect_err("a fragment")
                .code(),
            "oauth.client_jwks_uri_invalid"
        );
        let mut at_address = jwt.clone();
        at_address.jwks_uri = Some(ADDRESS.to_owned());
        let (mut client, secret) =
            create(ClientType::Confidential, at_address.clone()).expect("valid");
        assert!(secret.is_none());
        assert_eq!(client.jwks_uri(), Some(ADDRESS));
        assert_eq!(
            client
                .add_key(key.clone(), NOW)
                .expect_err("an address")
                .code(),
            "oauth.client_keys_at_address"
        );

        // Without its address the client takes keys, and with keys it takes
        // no address until they are removed.
        client.change(jwt.clone(), NOW).expect("no address");
        client.add_key(key, NOW).expect("a key");
        let error = client
            .change(at_address.clone(), NOW)
            .expect_err("keys and an address");
        assert_eq!(error.code(), "oauth.client_jwks_uri_with_keys");
        assert_eq!(client.jwks_uri(), None, "nothing changed");
        client.remove_key("one", NOW).expect("removed");
        client.change(at_address, NOW).expect("an address again");
        assert_eq!(client.jwks_uri(), Some(ADDRESS));
    }

    #[test]
    fn keys_are_for_private_key_jwt_only_and_number_at_most_five() {
        let key = |kid: &str| {
            ClientKey::parse(
                &format!(r#"{{"kty":"OKP","crv":"Ed25519","kid":"{kid}","x":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE"}}"#),
                NOW,
            )
            .expect("key")
        };
        let (mut client, _) = create(ClientType::Confidential, web()).expect("valid");
        assert_eq!(
            client
                .add_key(key("one"), NOW)
                .expect_err("secret method")
                .code(),
            "oauth.client_key_not_allowed"
        );
        let mut jwt = web();
        jwt.authentication_method = AuthenticationMethod::PrivateKeyJwt;
        client.change(jwt, NOW).expect("changed");
        for n in 0..5 {
            client.add_key(key(&format!("k{n}")), NOW).expect("added");
        }
        assert_eq!(
            client.add_key(key("k5"), NOW).expect_err("six").code(),
            "oauth.client_too_many_keys"
        );
        client.remove_key("k0", NOW).expect("removed");
        assert_eq!(
            client.remove_key("k0", NOW).expect_err("gone").code(),
            "oauth.client_key_not_found"
        );
        assert_eq!(client.snapshot().keys.len(), 4);
    }

    #[test]
    fn any_client_but_a_linkerd_one_may_ask_for_certificate_bound_tokens() {
        let mut public = spa();
        public.certificate_bound_access_tokens = true;
        let (client, _) = create(ClientType::Public, public).expect("a public client may");
        assert!(client.snapshot().settings.certificate_bound_access_tokens);
        let mut secret = web();
        secret.certificate_bound_access_tokens = true;
        create(ClientType::Confidential, secret).expect("a client of a secret may");

        let mut linkerd = ClientSettings::new(
            "Linkerd workload",
            ClientType::Confidential,
            vec![GrantType::ClientCredentials],
            Vec::new(),
        );
        linkerd.authentication_method = AuthenticationMethod::LinkerdIdentity;
        linkerd.linkerd_identity = Some(
            LinkerdIdentity::parse("web.shop.serviceaccount.identity.linkerd.cluster.local")
                .expect("an identity"),
        );
        linkerd.principal = Some(UserId::generate());
        create(ClientType::Confidential, linkerd.clone()).expect("unbound");
        linkerd.certificate_bound_access_tokens = true;
        assert_eq!(
            create(ClientType::Confidential, linkerd)
                .expect_err("no certificate to bind to")
                .code(),
            "oauth.client_certificate_bound_access_tokens_invalid"
        );
    }

    #[test]
    fn a_status_is_set_once() {
        let (mut client, _) = create(ClientType::Public, spa()).expect("valid");
        assert!(client.set_status(Status::Enabled, NOW).is_none());
        assert!(client.set_status(Status::Disabled, NOW).is_some());
        assert!(!client.is_enabled());
    }
}
