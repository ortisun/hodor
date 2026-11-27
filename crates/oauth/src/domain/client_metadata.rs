//! The metadata a client registers itself with, as RFC 7591 and OpenID
//! Connect Dynamic Client Registration write it: read into the settings of
//! a client, and written back as the answer of a registration.
//!
//! See `docs/architecture/contexts/oauth.md`, "The registration endpoint",
//! and Decision 0080.

use crate::domain::client::{
    ApplicationType, AuthenticationMethod, Client, ClientId, ClientSettings, ClientType, GrantType,
    IdTokenAlgorithm, RequestObjectAlgorithm,
};
use crate::domain::pairwise::SubjectType;
use crate::domain::registration::RegistrationPolicy;
use crate::domain::response::ResponseType;
use crate::domain::secret::ClientSecretValue;
use hodor_kernel::DomainError;
use serde_json::{Map, Value, json};

/// The name of a registered client that names none.
pub const DEFAULT_REGISTERED_CLIENT_NAME: &str = "Registered client";

/// The algorithms a client assertion may be signed with, which
/// `token_endpoint_auth_signing_alg` may name.
const ASSERTION_ALGORITHMS: [&str; 3] = ["ES256", "RS256", "PS256"];

/// The members Hodor would need and does not have yet, refused so that a
/// client that relies on one is not made without it.
const NOT_SUPPORTED: [&str; 8] = [
    "id_token_encrypted_response_alg",
    "id_token_encrypted_response_enc",
    "userinfo_encrypted_response_alg",
    "userinfo_encrypted_response_enc",
    "request_object_encryption_alg",
    "request_object_encryption_enc",
    "authorization_encrypted_response_alg",
    "authorization_encrypted_response_enc",
];

fn metadata_invalid(detail: impl Into<String>) -> DomainError {
    DomainError::invalid(
        "oauth.client_metadata_invalid",
        "the registration is a JSON object whose members have the kinds their specifications \
         give them",
    )
    .with_detail(detail)
}

fn not_supported(member: &str) -> DomainError {
    DomainError::invalid(
        "oauth.registration_member_not_supported",
        "the registration names a member Hodor does not support yet",
    )
    .with_detail(format!("`{member}`"))
}

/// A client's registration, read: what the client asks to be, not yet
/// checked by the rules of a client or by the policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClientMetadata {
    /// Public for `none`, confidential for any other method.
    pub client_type: ClientType,
    /// Its settings, unchecked.
    pub settings: ClientSettings,
    /// Its keys, each a JSON Web Key written as JSON, to be checked as an
    /// administrator's key is.
    pub keys: Vec<String>,
}

/// The members of a registration, read one by one.
struct Members<'a>(&'a Map<String, Value>);

impl<'a> Members<'a> {
    /// A member, `None` when it is left out or `null`.
    fn get(&self, name: &str) -> Option<&'a Value> {
        self.0.get(name).filter(|value| !value.is_null())
    }

    fn text(&self, name: &str) -> Result<Option<String>, DomainError> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::String(text)) => Ok(Some(text.clone())),
            Some(_) => Err(metadata_invalid(format!("`{name}` is a text"))),
        }
    }

    fn texts(&self, name: &str) -> Result<Option<Vec<String>>, DomainError> {
        match self.get(name) {
            None => Ok(None),
            Some(Value::Array(items)) => items
                .iter()
                .map(|item| {
                    item.as_str()
                        .map(str::to_owned)
                        .ok_or_else(|| metadata_invalid(format!("`{name}` is a list of texts")))
                })
                .collect::<Result<Vec<_>, _>>()
                .map(Some),
            Some(_) => Err(metadata_invalid(format!("`{name}` is a list of texts"))),
        }
    }

    fn boolean(&self, name: &str) -> Result<bool, DomainError> {
        match self.get(name) {
            None => Ok(false),
            Some(Value::Bool(value)) => Ok(*value),
            Some(_) => Err(metadata_invalid(format!("`{name}` is `true` or `false`"))),
        }
    }

    fn seconds(&self, name: &str) -> Result<Option<u32>, DomainError> {
        match self.get(name) {
            None => Ok(None),
            Some(value) => value
                .as_u64()
                .and_then(|seconds| u32::try_from(seconds).ok())
                .map(Some)
                .ok_or_else(|| metadata_invalid(format!("`{name}` is a whole number of seconds"))),
        }
    }
}

/// Whether the registration carries a software statement, which Issue-135
/// reads; until then every one is refused.
#[must_use]
pub(crate) fn has_software_statement(body: &Value) -> bool {
    body.get("software_statement")
        .is_some_and(|value| !value.is_null())
}

/// The refusal of a software statement while the tenant trusts no issuer.
#[must_use]
pub(crate) fn software_statement_unapproved() -> DomainError {
    DomainError::invalid(
        "oauth.software_statement_unapproved",
        "this tenant trusts no issuer of software statements",
    )
}

/// Reads what a change of a registration says of the client it changes,
/// beside its members (RFC 7592, section 2.2): `client_id` must be the
/// client's own. Answers the `client_secret` it sent, if any, which must be
/// a secret of the client that works. `registration_access_token`,
/// `registration_client_uri`, `client_id_issued_at` and
/// `client_secret_expires_at` are ignored.
///
/// # Errors
///
/// `oauth.client_metadata_invalid` for a body that is not an object or a
/// member of the wrong kind, and `oauth.registration_client_id_mismatch`
/// for a `client_id` left out or not the client's.
pub fn read_change(body: &Value, client_id: ClientId) -> Result<Option<String>, DomainError> {
    let object = body
        .as_object()
        .ok_or_else(|| metadata_invalid("the registration is a JSON object"))?;
    let members = Members(object);
    if members.text("client_id")?.as_deref() != Some(client_id.to_string().as_str()) {
        return Err(DomainError::invalid(
            "oauth.registration_client_id_mismatch",
            "a change of a registration names the client's own `client_id`",
        ));
    }
    members.text("client_secret")
}

/// The refusal of a `client_secret` sent with a change that is not a
/// secret of the client that works.
#[must_use]
pub(crate) fn client_secret_mismatch() -> DomainError {
    DomainError::invalid(
        "oauth.registration_client_secret_mismatch",
        "a change of a registration that names `client_secret` names a secret of the client that \
         works",
    )
}

/// Reads a registration's members into what the client asks to be. A
/// member left out takes the default of its specification; `scope` left
/// out is every scope `policy` allows. Members Hodor does not keep are
/// ignored. Nothing is checked here that the rules of a client or the
/// policy check.
///
/// # Errors
///
/// `oauth.client_metadata_invalid` for a body that is not an object or a
/// member of the wrong kind or value, and
/// `oauth.registration_member_not_supported` for a member Hodor would need
/// and does not have; the errors of the names of grants, methods, subject
/// types, algorithms and application types.
pub fn read_client_metadata(
    body: &Value,
    policy: &RegistrationPolicy,
) -> Result<ClientMetadata, DomainError> {
    let object = body
        .as_object()
        .ok_or_else(|| metadata_invalid("the registration is a JSON object"))?;
    let members = Members(object);
    if members.get("jwks_uri").is_some() && members.get("jwks").is_some() {
        return Err(metadata_invalid(
            "`jwks` and `jwks_uri` are never given together",
        ));
    }
    if let Some(member) = NOT_SUPPORTED
        .iter()
        .find(|member| members.get(member).is_some())
    {
        return Err(not_supported(member));
    }

    // `implicit`, which OpenID Connect Registration names for a client of
    // `id_token`, is read as `authorization_code`: no request to the token
    // endpoint uses it, and the code grant is what lets a client send
    // people to the authorization endpoint (Decision 0072).
    let mut grant_types: Vec<GrantType> = match members.texts("grant_types")? {
        None => vec![GrantType::AuthorizationCode],
        Some(names) => names
            .iter()
            .map(|name| {
                if name == "implicit" {
                    Ok(GrantType::AuthorizationCode)
                } else {
                    GrantType::parse(name)
                }
            })
            .collect::<Result<_, _>>()?,
    };
    grant_types.dedup();
    let response_types = members
        .texts("response_types")?
        .map(|names| {
            names
                .iter()
                .map(|name| ResponseType::parse(name))
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()?;

    let method = match members.text("token_endpoint_auth_method")? {
        None => AuthenticationMethod::ClientSecretBasic,
        Some(name) => AuthenticationMethod::parse(&name)?,
    };
    if let Some(algorithm) = members.text("token_endpoint_auth_signing_alg")? {
        if method != AuthenticationMethod::PrivateKeyJwt {
            return Err(metadata_invalid(
                "`token_endpoint_auth_signing_alg` goes with `private_key_jwt` only",
            ));
        }
        if !ASSERTION_ALGORITHMS.contains(&algorithm.as_str()) {
            return Err(metadata_invalid(format!(
                "`{algorithm}` is not an algorithm a client assertion may be signed with: \
                 `ES256`, `RS256` or `PS256`"
            )));
        }
    }
    let client_type = if method == AuthenticationMethod::None {
        ClientType::Public
    } else {
        ClientType::Confidential
    };

    // Hodor reads a client's keys only to check what it signs, and only a
    // client of `private_key_jwt` has keys: those of any other client are
    // ignored, and left out of the answer (Decision 0084).
    let keys = match members.get("jwks") {
        None => Vec::new(),
        Some(_) if method != AuthenticationMethod::PrivateKeyJwt => Vec::new(),
        Some(jwks) => jwks
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| metadata_invalid("`jwks` is an object with a list `keys`"))?
            .iter()
            .map(|key| {
                if key.is_object() {
                    Ok(key.to_string())
                } else {
                    Err(metadata_invalid("each of `jwks.keys` is a JSON Web Key"))
                }
            })
            .collect::<Result<Vec<_>, _>>()?,
    };
    let jwks_uri = members.text("jwks_uri")?;
    if method == AuthenticationMethod::PrivateKeyJwt && keys.is_empty() && jwks_uri.is_none() {
        return Err(metadata_invalid(
            "a client using `private_key_jwt` registers its keys in `jwks` or at `jwks_uri`",
        ));
    }

    let name = members
        .text("client_name")?
        .unwrap_or_else(|| DEFAULT_REGISTERED_CLIENT_NAME.to_owned());
    let mut settings = ClientSettings::new(
        &name,
        client_type,
        grant_types,
        members.texts("redirect_uris")?.unwrap_or_default(),
    );
    settings.authentication_method = method;
    settings.post_logout_redirect_uris = members
        .texts("post_logout_redirect_uris")?
        .unwrap_or_default();
    settings.allowed_scopes = match members.text("scope")? {
        None => policy.scopes.clone(),
        Some(scope) => scope
            .split(' ')
            .filter(|scope| !scope.is_empty())
            .map(str::to_owned)
            .collect(),
    };
    settings.application_type = Some(match members.text("application_type")? {
        None => ApplicationType::Web,
        Some(name) => ApplicationType::parse(&name)?,
    });
    settings.client_uri = members.text("client_uri")?;
    settings.logo_uri = members.text("logo_uri")?;
    settings.policy_uri = members.text("policy_uri")?;
    settings.tos_uri = members.text("tos_uri")?;
    settings.initiate_login_uri = members.text("initiate_login_uri")?;
    settings.subject_type = match members.text("subject_type")? {
        None => SubjectType::Public,
        Some(name) => SubjectType::parse(&name)?,
    };
    settings.sector_identifier_uri = members.text("sector_identifier_uri")?;
    settings.jwks_uri = jwks_uri;
    settings.request_uris = members.texts("request_uris")?.unwrap_or_default();
    settings.require_pushed_requests = members.boolean("require_pushed_authorization_requests")?;
    // OpenID Connect Registration's default, where an administrator's
    // client gets Hodor's.
    settings.id_token_algorithm = match members.text("id_token_signed_response_alg")? {
        None => IdTokenAlgorithm::Rs256,
        Some(name) => IdTokenAlgorithm::parse(&name)?,
    };
    settings.userinfo_algorithm = members
        .text("userinfo_signed_response_alg")?
        .map(|name| IdTokenAlgorithm::parse_for_userinfo(&name))
        .transpose()?;
    settings.request_object_algorithm = members
        .text("request_object_signing_alg")?
        .map(|name| RequestObjectAlgorithm::parse(&name))
        .transpose()?;
    settings.default_max_age = members.seconds("default_max_age")?;
    settings.default_acr_values = members.texts("default_acr_values")?.unwrap_or_default();
    settings.require_auth_time = members.boolean("require_auth_time")?;
    settings.backchannel_logout_uri = members.text("backchannel_logout_uri")?;
    settings.backchannel_logout_session_required =
        members.boolean("backchannel_logout_session_required")?;
    settings.certificate_bound_access_tokens =
        members.boolean("tls_client_certificate_bound_access_tokens")?;
    // `code` unless named, as for every client of the code grant; checked
    // by the rules of every client.
    if let Some(response_types) = response_types {
        settings.response_types = response_types;
    }
    // A registered client always uses PKCE; nothing of a registration says
    // otherwise.
    settings.require_pkce = true;

    Ok(ClientMetadata {
        client_type,
        settings,
        keys,
    })
}

/// What a client is given to manage its registration with, in the answer of
/// its registration, a read and a change (RFC 7592, section 3).
#[derive(Debug, Clone, Copy)]
pub struct Management<'a> {
    /// Its registration access token: new at a registration and a change,
    /// the one presented at a read.
    pub access_token: &'a str,
    /// Its registration client address, `{issuer}/oauth2/register/{client_id}`.
    pub client_uri: &'a str,
}

/// What the registration endpoint answers for a client it registered, and
/// what its registration client address answers: its identifier, a secret
/// once when one was just made, every member kept (RFC 7591, section
/// 3.2.1), and what it manages its registration with (RFC 7592, section
/// 3). A member without a value, or an empty list, is left out.
#[must_use]
pub fn registration_answer(
    client: &Client,
    secret: Option<&ClientSecretValue>,
    management: Option<Management<'_>>,
) -> Value {
    let state = client.snapshot();
    let settings = &state.settings;
    let mut answer = Map::new();
    let mut put = |name: &str, value: Value| {
        let empty = value.is_null() || value.as_array().is_some_and(Vec::is_empty);
        if !empty {
            answer.insert(name.to_owned(), value);
        }
    };
    put("client_id", json!(state.id.to_string()));
    put(
        "client_id_issued_at",
        json!(state.created_at.unix_timestamp()),
    );
    if let Some(secret) = secret {
        put("client_secret", json!(secret.expose()));
        put(
            "client_secret_expires_at",
            json!(
                state
                    .secrets
                    .last()
                    .map_or(0, |kept| kept.expires_at.unix_timestamp())
            ),
        );
    }
    put("client_name", json!(settings.name));
    put(
        "application_type",
        json!(settings.application_type.map(ApplicationType::as_str)),
    );
    put("redirect_uris", json!(settings.redirect_uris));
    put(
        "post_logout_redirect_uris",
        json!(settings.post_logout_redirect_uris),
    );
    put(
        "grant_types",
        json!(
            settings
                .grant_types
                .iter()
                .map(|grant| grant.as_str())
                .collect::<Vec<_>>()
        ),
    );
    put(
        "response_types",
        json!(
            settings
                .response_types
                .iter()
                .map(|kind| kind.as_str())
                .collect::<Vec<_>>()
        ),
    );
    put(
        "token_endpoint_auth_method",
        json!(settings.authentication_method.as_str()),
    );
    if !settings.allowed_scopes.is_empty() {
        put("scope", json!(settings.allowed_scopes.join(" ")));
    }
    let keys: Vec<Value> = state
        .keys
        .iter()
        .filter_map(|key| serde_json::from_str(&key.jwk).ok())
        .collect();
    if !keys.is_empty() {
        put("jwks", json!({ "keys": keys }));
    }
    put("jwks_uri", json!(settings.jwks_uri));
    put("subject_type", json!(settings.subject_type.as_str()));
    put(
        "sector_identifier_uri",
        json!(settings.sector_identifier_uri),
    );
    put("request_uris", json!(settings.request_uris));
    put(
        "require_pushed_authorization_requests",
        json!(settings.require_pushed_requests),
    );
    put(
        "id_token_signed_response_alg",
        json!(settings.id_token_algorithm.as_str()),
    );
    put(
        "userinfo_signed_response_alg",
        json!(settings.userinfo_algorithm.map(IdTokenAlgorithm::as_str)),
    );
    put(
        "request_object_signing_alg",
        json!(
            settings
                .request_object_algorithm
                .map(RequestObjectAlgorithm::as_str)
        ),
    );
    put("default_max_age", json!(settings.default_max_age));
    put("default_acr_values", json!(settings.default_acr_values));
    put("require_auth_time", json!(settings.require_auth_time));
    put(
        "backchannel_logout_uri",
        json!(settings.backchannel_logout_uri),
    );
    put(
        "backchannel_logout_session_required",
        json!(settings.backchannel_logout_session_required),
    );
    put(
        "tls_client_certificate_bound_access_tokens",
        json!(settings.certificate_bound_access_tokens),
    );
    for (member, uri) in settings.display_uris() {
        put(member, json!(uri));
    }
    put("initiate_login_uri", json!(settings.initiate_login_uri));
    if let Some(management) = management {
        put("registration_access_token", json!(management.access_token));
        put("registration_client_uri", json!(management.client_uri));
    }
    Value::Object(answer)
}

#[cfg(test)]
mod tests;
