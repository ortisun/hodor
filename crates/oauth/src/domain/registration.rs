//! The registration settings of a tenant: whether clients may register
//! themselves, the application they belong to, the ways a registration is
//! allowed, and the policy that bounds every registration.
//!
//! See `docs/architecture/contexts/oauth.md`, "Client registration", and
//! Decision 0075.

use crate::domain::application::{ApplicationId, stored_data_invalid};
use crate::domain::client::{AuthenticationMethod, GrantType};
use crate::domain::event::OauthEvent;
use crate::domain::pairwise::{SubjectType, host_of};
use crate::domain::response::ResponseType;
use crate::domain::text::is_scope;
use hodor_kernel::{DomainError, Timestamp};
use serde_json::{Value, json};

/// The most clients the application of registered clients may hold.
pub const MOST_REGISTERED_CLIENTS: u32 = 1000;
/// How many clients the application of registered clients may hold
/// unless an administrator says.
pub const DEFAULT_MOST_REGISTERED_CLIENTS: u32 = 100;
/// The most scopes a policy lists.
pub const MAX_POLICY_SCOPES: usize = 50;
/// The most hosts a policy lists.
pub const MAX_POLICY_HOSTS: usize = 50;
/// The longest host a policy lists.
const MAX_HOST_LENGTH: usize = 253;
/// The longest label of a host name.
const MAX_LABEL_LENGTH: usize = 63;

/// Every authentication method a policy may allow. The methods of
/// workloads are never registered.
pub const REGISTERABLE_METHODS: [AuthenticationMethod; 4] = [
    AuthenticationMethod::ClientSecretBasic,
    AuthenticationMethod::ClientSecretPost,
    AuthenticationMethod::PrivateKeyJwt,
    AuthenticationMethod::None,
];

/// A way a registration may be allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RegistrationWay {
    /// An initial access token an administrator made (RFC 7591, section 3).
    InitialAccessToken,
    /// A software statement of an issuer the tenant trusts (RFC 7591,
    /// section 2.3). Issue-135 reads them.
    SoftwareStatement,
    /// Nothing: anyone may register, within the policy.
    Open,
}

impl RegistrationWay {
    /// Every way, in the order they are written.
    pub const ALL: [Self; 3] = [
        Self::InitialAccessToken,
        Self::SoftwareStatement,
        Self::Open,
    ];

    /// The name the interfaces and the storage write.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InitialAccessToken => "initial_access_token",
            Self::SoftwareStatement => "software_statement",
            Self::Open => "open",
        }
    }

    /// Reads a name.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_registration_ways_invalid` for any other name.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        Self::ALL
            .into_iter()
            .find(|way| way.as_str() == value)
            .ok_or_else(|| {
                ways_invalid().with_detail(format!("`{value}` is not a way Hodor knows"))
            })
    }
}

fn ways_invalid() -> DomainError {
    DomainError::invalid(
        "oauth.client_registration_ways_invalid",
        "registration is allowed by one or more of `initial_access_token`, \
         `software_statement` and `open`, at least one while it is on",
    )
}

fn policy_invalid(detail: impl Into<String>) -> DomainError {
    DomainError::invalid(
        "oauth.client_registration_policy_invalid",
        "a limit of the registration policy breaks its rule",
    )
    .with_detail(detail)
}

/// The error for an application the settings may not name: none while
/// registration is on, not one of the tenant's, or first party.
pub(crate) fn application_invalid(detail: &'static str) -> DomainError {
    DomainError::invalid(
        "oauth.client_registration_application_invalid",
        "registered clients belong to one application of the tenant, which is not first party, \
         named while registration is on",
    )
    .with_detail(detail)
}

/// Each value once, in the order first given.
fn once<T: PartialEq>(values: Vec<T>) -> Vec<T> {
    let mut kept: Vec<T> = Vec::with_capacity(values.len());
    for value in values {
        if !kept.contains(&value) {
            kept.push(value);
        }
    }
    kept
}

/// Whether `value` is a host as a policy lists it: a name of lowercase
/// letters, digits, `.` and `-` of at most 253 characters with no empty
/// label, or an IP address of version 6 in brackets.
#[must_use]
pub fn is_policy_host(value: &str) -> bool {
    if let Some(inside) = value
        .strip_prefix('[')
        .and_then(|rest| rest.strip_suffix(']'))
    {
        return inside.contains(':')
            && inside.bytes().all(|b| {
                b.is_ascii_digit() || (b'a'..=b'f').contains(&b) || b == b':' || b == b'.'
            });
    }
    !value.is_empty()
        && value.len() <= MAX_HOST_LENGTH
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= MAX_LABEL_LENGTH
                && label
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        })
}

/// What a registration may name: the limits an administrator writes,
/// checked against every registration and every change of one, whichever
/// way allowed it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationPolicy {
    /// The grants a registration may name: `authorization_code` and
    /// `refresh_token` only.
    pub grant_types: Vec<GrantType>,
    /// The response types it may name, among those Hodor answers, never
    /// one that returns an access token.
    pub response_types: Vec<ResponseType>,
    /// The scopes it may ask for.
    pub scopes: Vec<String>,
    /// The authentication methods it may name.
    pub authentication_methods: Vec<AuthenticationMethod>,
    /// The subject types it may name.
    pub subject_types: Vec<SubjectType>,
    /// The hosts every address of a registration must name, or `None` for
    /// any host.
    pub hosts: Option<Vec<String>>,
}

impl Default for RegistrationPolicy {
    fn default() -> Self {
        Self {
            grant_types: vec![GrantType::AuthorizationCode],
            response_types: vec![ResponseType::Code],
            scopes: ["openid", "profile", "email"]
                .into_iter()
                .map(str::to_owned)
                .collect(),
            authentication_methods: vec![
                AuthenticationMethod::ClientSecretBasic,
                AuthenticationMethod::PrivateKeyJwt,
            ],
            subject_types: vec![SubjectType::Public],
            hosts: None,
        }
    }
}

impl RegistrationPolicy {
    /// The policy, each value once, if every limit follows its rule.
    ///
    /// # Errors
    ///
    /// `oauth.client_registration_policy_invalid`, whose detail names the
    /// rule broken.
    pub fn checked(self) -> Result<Self, DomainError> {
        let grant_types = once(self.grant_types);
        if grant_types.is_empty() {
            return Err(policy_invalid("the policy allows at least one grant"));
        }
        if grant_types.iter().any(|grant| {
            !matches!(
                grant,
                GrantType::AuthorizationCode | GrantType::RefreshToken
            )
        }) {
            return Err(policy_invalid(
                "a registered client never has `client_credentials` or the token exchange grant",
            ));
        }
        if grant_types.contains(&GrantType::RefreshToken)
            && !grant_types.contains(&GrantType::AuthorizationCode)
        {
            return Err(policy_invalid(
                "`refresh_token` comes with `authorization_code`",
            ));
        }
        let response_types = once(self.response_types);
        if response_types.is_empty() {
            return Err(policy_invalid(
                "the policy allows at least one response type",
            ));
        }
        // Those need an administrator's mark, which a client that
        // registers itself never has (Decision 0083).
        if response_types
            .iter()
            .any(|kind| kind.returns_access_token())
        {
            return Err(policy_invalid(
                "a registered client never has a response type that returns an access token",
            ));
        }
        let scopes = once(self.scopes);
        if scopes.is_empty() || scopes.len() > MAX_POLICY_SCOPES {
            return Err(policy_invalid("the policy allows 1 to 50 scopes"));
        }
        if let Some(bad) = scopes.iter().find(|scope| !is_scope(scope)) {
            return Err(policy_invalid(format!(
                "`{bad}` is not written as a scope is"
            )));
        }
        let authentication_methods = once(self.authentication_methods);
        if authentication_methods.is_empty() {
            return Err(policy_invalid(
                "the policy allows at least one authentication method",
            ));
        }
        if let Some(method) = authentication_methods
            .iter()
            .find(|method| !REGISTERABLE_METHODS.contains(method))
        {
            return Err(policy_invalid(format!(
                "`{}` is never registered",
                method.as_str()
            )));
        }
        let subject_types = once(self.subject_types);
        if subject_types.is_empty() {
            return Err(policy_invalid(
                "the policy allows at least one subject type",
            ));
        }
        let hosts = match self.hosts {
            None => None,
            Some(hosts) => {
                let hosts = once(hosts);
                if hosts.is_empty() || hosts.len() > MAX_POLICY_HOSTS {
                    return Err(policy_invalid(
                        "the policy lists 1 to 50 hosts, or allows any host",
                    ));
                }
                if let Some(bad) = hosts.iter().find(|host| !is_policy_host(host)) {
                    return Err(policy_invalid(format!(
                        "`{bad}` is not a host written in lowercase without a port"
                    )));
                }
                Some(hosts)
            }
        };
        Ok(Self {
            grant_types,
            response_types,
            scopes,
            authentication_methods,
            subject_types,
            hosts,
        })
    }

    /// The policy as the administration interface and the storage write it.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "grant_types": self.grant_types.iter().map(|grant| grant.as_str()).collect::<Vec<_>>(),
            "response_types": self.response_types.iter().map(|kind| kind.as_str()).collect::<Vec<_>>(),
            "scopes": self.scopes,
            "token_endpoint_auth_methods": self
                .authentication_methods
                .iter()
                .map(|method| method.as_str())
                .collect::<Vec<_>>(),
            "subject_types": self.subject_types.iter().map(|subject| subject.as_str()).collect::<Vec<_>>(),
            "hosts": self.hosts,
        })
    }

    /// Reads a policy as [`Self::to_json`] writes it. A member left out
    /// takes its default; the result is not yet [checked](Self::checked).
    ///
    /// # Errors
    ///
    /// `oauth.client_registration_policy_invalid` for a document of
    /// another shape, or a value that is not a word Hodor knows.
    pub fn from_json(value: &Value) -> Result<Self, DomainError> {
        let object = value
            .as_object()
            .ok_or_else(|| policy_invalid("the policy is an object"))?;
        const KNOWN: [&str; 6] = [
            "grant_types",
            "response_types",
            "scopes",
            "token_endpoint_auth_methods",
            "subject_types",
            "hosts",
        ];
        if let Some(unknown) = object.keys().find(|key| !KNOWN.contains(&key.as_str())) {
            return Err(policy_invalid(format!(
                "`{unknown}` is not a limit of the policy"
            )));
        }
        let texts = |name: &str| -> Result<Option<Vec<String>>, DomainError> {
            match object.get(name) {
                None => Ok(None),
                Some(Value::Array(items)) => items
                    .iter()
                    .map(|item| {
                        item.as_str()
                            .map(str::to_owned)
                            .ok_or_else(|| policy_invalid(format!("`{name}` is a list of texts")))
                    })
                    .collect::<Result<Vec<_>, _>>()
                    .map(Some),
                Some(_) => Err(policy_invalid(format!("`{name}` is a list of texts"))),
            }
        };
        let defaults = Self::default();
        let grant_types = match texts("grant_types")? {
            None => defaults.grant_types,
            Some(names) => names
                .iter()
                .map(|name| {
                    GrantType::parse(name)
                        .map_err(|_| policy_invalid(format!("`{name}` is not a grant Hodor knows")))
                })
                .collect::<Result<_, _>>()?,
        };
        let authentication_methods = match texts("token_endpoint_auth_methods")? {
            None => defaults.authentication_methods,
            Some(names) => names
                .iter()
                .map(|name| {
                    AuthenticationMethod::parse(name).map_err(|_| {
                        policy_invalid(format!("`{name}` is not a method Hodor knows"))
                    })
                })
                .collect::<Result<_, _>>()?,
        };
        let subject_types = match texts("subject_types")? {
            None => defaults.subject_types,
            Some(names) => names
                .iter()
                .map(|name| {
                    SubjectType::parse(name).map_err(|_| {
                        policy_invalid(format!("`{name}` is not a subject type Hodor knows"))
                    })
                })
                .collect::<Result<_, _>>()?,
        };
        let response_types = match texts("response_types")? {
            None => defaults.response_types,
            Some(names) => names
                .iter()
                .map(|name| {
                    ResponseType::read(name).offered().ok_or_else(|| {
                        policy_invalid(format!("`{name}` is not a response type Hodor answers"))
                    })
                })
                .collect::<Result<_, _>>()?,
        };
        let hosts = match object.get("hosts") {
            None | Some(Value::Null) => None,
            Some(_) => texts("hosts")?,
        };
        Ok(Self {
            grant_types,
            response_types,
            scopes: texts("scopes")?.unwrap_or(defaults.scopes),
            authentication_methods,
            subject_types,
            hosts,
        })
    }

    /// Whether an address may be named: any address where any host is
    /// allowed, otherwise one whose host the policy lists.
    #[must_use]
    pub fn allows_address(&self, address: &str) -> bool {
        match &self.hosts {
            None => true,
            Some(hosts) => host_of(address).is_some_and(|host| hosts.contains(&host)),
        }
    }
}

/// What a registration names that the policy limits, for
/// [`check_registration`].
#[derive(Debug, Clone, Copy)]
pub struct RegistrationRequest<'a> {
    /// Its `grant_types`.
    pub grant_types: &'a [GrantType],
    /// Its `response_types`, read as the types Hodor answers; a type it
    /// does not answer is the registration endpoint's to refuse first.
    pub response_types: &'a [ResponseType],
    /// The scopes it may ask for.
    pub scopes: &'a [String],
    /// Its `token_endpoint_auth_method`.
    pub authentication_method: AuthenticationMethod,
    /// Its `subject_type`.
    pub subject_type: SubjectType,
    /// Every address it names, whatever its member.
    pub addresses: &'a [&'a str],
}

fn not_allowed(code: &'static str, message: &'static str, detail: String) -> DomainError {
    DomainError::invalid(code, message).with_detail(detail)
}

/// Checks what a registration names against the policy, limit by limit,
/// and refuses with the first limit it breaks: what Issue-133 asks of
/// every registration and every change of one.
///
/// # Errors
///
/// `oauth.registration_grant_not_allowed`,
/// `oauth.registration_response_type_not_allowed`,
/// `oauth.registration_scope_not_allowed`,
/// `oauth.registration_method_not_allowed`,
/// `oauth.registration_subject_type_not_allowed` or
/// `oauth.registration_host_not_allowed`, whose detail names the value.
pub fn check_registration(
    policy: &RegistrationPolicy,
    request: &RegistrationRequest<'_>,
) -> Result<(), DomainError> {
    if let Some(grant) = request
        .grant_types
        .iter()
        .find(|grant| !policy.grant_types.contains(grant))
    {
        return Err(not_allowed(
            "oauth.registration_grant_not_allowed",
            "the tenant's registration policy does not allow this grant",
            format!("`{}`", grant.as_str()),
        ));
    }
    if let Some(response_type) = request
        .response_types
        .iter()
        .find(|kind| !policy.response_types.contains(kind))
    {
        return Err(not_allowed(
            "oauth.registration_response_type_not_allowed",
            "the tenant's registration policy does not allow this response type",
            format!("`{}`", response_type.as_str()),
        ));
    }
    if let Some(scope) = request
        .scopes
        .iter()
        .find(|scope| !policy.scopes.contains(scope))
    {
        return Err(not_allowed(
            "oauth.registration_scope_not_allowed",
            "the tenant's registration policy does not allow this scope",
            format!("`{scope}`"),
        ));
    }
    if !policy
        .authentication_methods
        .contains(&request.authentication_method)
    {
        return Err(not_allowed(
            "oauth.registration_method_not_allowed",
            "the tenant's registration policy does not allow this authentication method",
            format!("`{}`", request.authentication_method.as_str()),
        ));
    }
    if !policy.subject_types.contains(&request.subject_type) {
        return Err(not_allowed(
            "oauth.registration_subject_type_not_allowed",
            "the tenant's registration policy does not allow this subject type",
            format!("`{}`", request.subject_type.as_str()),
        ));
    }
    if let Some(address) = request
        .addresses
        .iter()
        .find(|address| !policy.allows_address(address))
    {
        return Err(not_allowed(
            "oauth.registration_host_not_allowed",
            "the tenant's registration policy does not allow an address of this host",
            format!("`{address}`"),
        ));
    }
    Ok(())
}

/// Checks the hosts of a registration's redirect addresses against the
/// policy, before [`check_registration`] checks every address, so that the
/// registration endpoint can answer a redirect address it refuses with
/// `invalid_redirect_uri`, as RFC 7591 asks.
///
/// # Errors
///
/// `oauth.registration_redirect_host_not_allowed`, whose detail names the
/// address.
pub fn check_redirect_hosts(
    policy: &RegistrationPolicy,
    redirect_uris: &[String],
) -> Result<(), DomainError> {
    match redirect_uris
        .iter()
        .find(|address| !policy.allows_address(address))
    {
        Some(address) => Err(not_allowed(
            "oauth.registration_redirect_host_not_allowed",
            "the tenant's registration policy does not allow a redirect address of this host",
            format!("`{address}`"),
        )),
        None => Ok(()),
    }
}

/// What an administrator sets about client registration in a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RegistrationSettings {
    /// Whether clients may register themselves.
    pub enabled: bool,
    /// The application every registered client belongs to.
    pub application_id: Option<ApplicationId>,
    /// The ways a registration may be allowed.
    pub ways: Vec<RegistrationWay>,
    /// How many clients the application of registered clients may hold.
    pub max_clients: u32,
    /// What a registration may name.
    pub policy: RegistrationPolicy,
}

impl Default for RegistrationSettings {
    /// Off, as a tenant that never set them reads.
    fn default() -> Self {
        Self {
            enabled: false,
            application_id: None,
            ways: vec![RegistrationWay::InitialAccessToken],
            max_clients: DEFAULT_MOST_REGISTERED_CLIENTS,
            policy: RegistrationPolicy::default(),
        }
    }
}

impl RegistrationSettings {
    /// The settings, each value once, if they follow every rule that does
    /// not need the store: whether the application is one of the tenant's
    /// and is not first party is the use case's to check.
    ///
    /// # Errors
    ///
    /// `oauth.client_registration_application_invalid`,
    /// `oauth.client_registration_ways_invalid`,
    /// `oauth.client_registration_most_clients_invalid` or
    /// `oauth.client_registration_policy_invalid`.
    pub fn checked(self) -> Result<Self, DomainError> {
        let ways = once(self.ways);
        if self.enabled && self.application_id.is_none() {
            return Err(application_invalid(
                "registration is on, and names no application",
            ));
        }
        if self.enabled && ways.is_empty() {
            return Err(ways_invalid());
        }
        if !(1..=MOST_REGISTERED_CLIENTS).contains(&self.max_clients) {
            return Err(DomainError::invalid(
                "oauth.client_registration_most_clients_invalid",
                "the application of registered clients holds 1 to 1000 clients",
            ));
        }
        Ok(Self {
            enabled: self.enabled,
            application_id: self.application_id,
            ways,
            max_clients: self.max_clients,
            policy: self.policy.checked()?,
        })
    }

    /// Whether registration is on and allows `way`.
    #[must_use]
    pub fn allows(&self, way: RegistrationWay) -> bool {
        self.enabled && self.ways.contains(&way)
    }

    /// The names of its ways, in order.
    #[must_use]
    pub fn way_names(&self) -> Vec<&'static str> {
        self.ways.iter().map(|way| way.as_str()).collect()
    }
}

/// Everything stored about the registration settings of a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRegistrationSnapshot {
    /// The settings.
    pub settings: RegistrationSettings,
    /// When they were first set.
    pub created_at: Timestamp,
    /// When they were last replaced.
    pub updated_at: Timestamp,
    /// Incremented on every stored change, for optimistic locking.
    pub version: u32,
}

/// The registration settings a tenant set: one per tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientRegistration {
    state: ClientRegistrationSnapshot,
}

impl ClientRegistration {
    /// The first settings a tenant sets, checked.
    ///
    /// # Errors
    ///
    /// As [`RegistrationSettings::checked`].
    pub fn create(
        settings: RegistrationSettings,
        now: Timestamp,
    ) -> Result<(Self, OauthEvent), DomainError> {
        let registration = Self {
            state: ClientRegistrationSnapshot {
                settings: settings.checked()?,
                created_at: now,
                updated_at: now,
                version: 0,
            },
        };
        let event = registration.changed();
        Ok((registration, event))
    }

    /// Replaces the settings as a whole. Settings equal to the current
    /// ones change nothing, and say so with `None`.
    ///
    /// # Errors
    ///
    /// As [`RegistrationSettings::checked`].
    pub fn replace(
        &mut self,
        settings: RegistrationSettings,
        now: Timestamp,
    ) -> Result<Option<OauthEvent>, DomainError> {
        let settings = settings.checked()?;
        if settings == self.state.settings {
            return Ok(None);
        }
        self.state.settings = settings;
        self.state.updated_at = now;
        Ok(Some(self.changed()))
    }

    fn changed(&self) -> OauthEvent {
        let settings = &self.state.settings;
        OauthEvent::ClientRegistrationChanged {
            enabled: settings.enabled,
            application_id: settings.application_id,
            ways: settings.way_names(),
            max_clients: settings.max_clients,
            policy: settings.policy.to_json(),
        }
    }

    /// Rebuilds the settings from storage.
    #[must_use]
    pub const fn from_snapshot(state: ClientRegistrationSnapshot) -> Self {
        Self { state }
    }

    /// Everything stored about them.
    #[must_use]
    pub const fn snapshot(&self) -> &ClientRegistrationSnapshot {
        &self.state
    }

    /// The settings.
    #[must_use]
    pub const fn settings(&self) -> &RegistrationSettings {
        &self.state.settings
    }
}

/// Reads the stored names of the ways.
///
/// # Errors
///
/// `oauth.stored_data_invalid` for a name that is not a way.
pub fn ways_from_stored(names: &[String]) -> Result<Vec<RegistrationWay>, DomainError> {
    names
        .iter()
        .map(|name| RegistrationWay::parse(name).map_err(|_| stored_data_invalid()))
        .collect()
}

#[cfg(test)]
mod tests;
