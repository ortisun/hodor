//! Clients: what asks Hodor for tokens on behalf of an application.

use crate::domain::application::{ApplicationId, Status, stored_data_invalid};
use crate::domain::event::OauthEvent;
use crate::domain::key::{ClientKey, MAX_KEYS};
use crate::domain::secret::{ClientSecret, ClientSecretHash, ClientSecretId, ClientSecretValue};
use crate::domain::text;
use hodor_kernel::{Digest, DomainError, RandomSource, Timestamp};
use hodor_keys::api::RotationPolicy;
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
            "none" => Ok(Self::None),
            _ => Err(method_invalid()),
        }
    }

    /// Whether the method proves who the client is with a secret.
    #[must_use]
    pub const fn uses_secret(self) -> bool {
        matches!(self, Self::ClientSecretBasic | Self::ClientSecretPost)
    }
}

fn method_invalid() -> DomainError {
    DomainError::invalid(
        "oauth.client_authentication_method_invalid",
        "a confidential client proves who it is with `client_secret_basic`, \
         `client_secret_post` or `private_key_jwt`; a public client with `none`",
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
}

impl GrantType {
    /// The name OAuth gives it, which is also the stored name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorizationCode => "authorization_code",
            Self::RefreshToken => "refresh_token",
            Self::ClientCredentials => "client_credentials",
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
}

impl Default for TokenPolicy {
    fn default() -> Self {
        Self {
            access_token: Duration::minutes(5),
            id_token: Duration::minutes(5),
            refresh_token: Duration::days(30),
            refresh_idle: Duration::days(7),
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
            && self.refresh_idle <= self.refresh_token;
        if fits {
            Ok(self)
        } else {
            Err(DomainError::invalid(
                "oauth.token_policy_invalid",
                "access and ID tokens live 1 minute to 1 hour; a refresh token 1 hour to 365 \
                 days, and lasts unused from 1 hour up to its lifetime",
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
    /// How long its tokens live.
    pub token_policy: TokenPolicy,
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

fn is_port(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 5
        && value.bytes().all(|b| b.is_ascii_digit())
        && value
            .parse::<u32>()
            .is_ok_and(|port| (1..=65535).contains(&port))
}

/// Checks one redirect address against the rules of the OAuth context;
/// see `docs/architecture/contexts/oauth.md`, "Redirect addresses".
fn check_redirect_uri(value: &str, client_type: ClientType) -> Result<(), DomainError> {
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
    /// Settings for a client of `client_type` with these grants and
    /// redirect addresses, and everything else at its default.
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
            grant_types,
            redirect_uris,
            post_logout_redirect_uris: Vec::new(),
            allowed_scopes: Vec::new(),
            require_pkce: true,
            token_policy: TokenPolicy::default(),
        }
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
            redirect_uris,
            post_logout_redirect_uris,
            allowed_scopes,
            require_pkce: self.require_pkce,
            token_policy: self.token_policy.checked()?,
        })
    }
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
            },
        };
        Ok((client, value))
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
    /// Returns an `Invalid` error if a setting breaks its rule; nothing
    /// changes then.
    pub fn change(
        &mut self,
        settings: ClientSettings,
        now: Timestamp,
    ) -> Result<Vec<OauthEvent>, DomainError> {
        let settings = settings.checked(self.state.client_type)?;
        if settings == self.state.settings {
            return Ok(Vec::new());
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
    /// use `private_key_jwt`, `oauth.client_key_taken` if it has a key
    /// with the same `kid`, and `oauth.client_too_many_keys` if it has 5.
    pub fn add_key(&mut self, key: ClientKey, now: Timestamp) -> Result<OauthEvent, DomainError> {
        if self.state.settings.authentication_method != AuthenticationMethod::PrivateKeyJwt {
            return Err(DomainError::invalid(
                "oauth.client_key_not_allowed",
                "only a client using `private_key_jwt` has keys",
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
    fn a_status_is_set_once() {
        let (mut client, _) = create(ClientType::Public, spa()).expect("valid");
        assert!(client.set_status(Status::Enabled, NOW).is_none());
        assert!(client.set_status(Status::Disabled, NOW).is_some());
        assert!(!client.is_enabled());
    }
}
