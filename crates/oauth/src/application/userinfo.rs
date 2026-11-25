//! UserInfo: the claims of the person an access token was issued for.

use crate::application::claim_mapper::{ClaimMapping, MappedToken};
use crate::application::introspection::AccessTokenRegister;
use crate::application::ports::PersonMemberships;
use crate::domain::claim_mapper::{ClaimTarget, add_mapped_claims};
use crate::domain::client::ClientId;
use crate::domain::openid::{
    BearerRefusal, PersonClaims, PublishedKey, check_access_token, userinfo_claims,
};
use crate::domain::resource_server::GROUPS_SCOPE;
use hodor_identity::api::{IdentifierKind, IdentityService};
use hodor_kernel::{
    Clock, DomainError, ErrorKind, SignatureAlgorithm, SignatureVerifier, TenantContext,
};
use hodor_keys::api::KeyService;
use serde_json::Value;
use std::fmt;
use std::sync::Arc;

/// The tenant's published signing keys, as the checks of tokens it issued
/// need them.
///
/// # Errors
///
/// Returns an error if storage fails.
pub(crate) async fn published_keys(
    keys: &KeyService,
    tenant: &TenantContext,
) -> Result<Vec<PublishedKey>, DomainError> {
    Ok(keys
        .published_keys(tenant)
        .await?
        .iter()
        .filter_map(|version| {
            let algorithm = SignatureAlgorithm::from_name(version.algorithm().as_str())?;
            Some(PublishedKey {
                key_id: version.id().to_string(),
                algorithm,
                key: version.public_key()?.clone(),
            })
        })
        .collect())
}

/// The ports [`UserInfoService`] works through.
#[derive(Clone)]
pub struct UserInfoPorts {
    /// Lists the tenant's published keys.
    pub keys: KeyService,
    /// Checks the access token's signature.
    pub verifier: Arc<dyn SignatureVerifier>,
    /// Reads the person.
    pub identity: IdentityService,
    /// Whether the token is still in force.
    pub register: AccessTokenRegister,
    /// The person's groups, for the scope `groups`.
    pub memberships: Arc<dyn PersonMemberships>,
    /// The claims the mappers of the token's client add.
    pub mapping: ClaimMapping,
    /// The time.
    pub clock: Arc<dyn Clock>,
}

impl fmt::Debug for UserInfoPorts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserInfoPorts").finish_non_exhaustive()
    }
}

/// The use case of UserInfo.
#[derive(Clone)]
pub struct UserInfoService {
    ports: UserInfoPorts,
}

impl fmt::Debug for UserInfoService {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UserInfoService").finish_non_exhaustive()
    }
}

impl UserInfoService {
    /// Wires the use case to its ports.
    #[must_use]
    pub const fn new(ports: UserInfoPorts) -> Self {
        Self { ports }
    }

    /// The claims of the person `token` was issued for, by its scopes.
    ///
    /// # Errors
    ///
    /// The outer error is a failure of storage; the inner one is why the
    /// token is refused.
    pub async fn claims(
        &self,
        tenant: &TenantContext,
        issuer: &str,
        token: Option<&str>,
    ) -> Result<Result<Value, BearerRefusal>, DomainError> {
        let Some(token) = token else {
            return Ok(Err(BearerRefusal::Missing));
        };
        let keys = published_keys(&self.ports.keys, tenant).await?;
        let checked = match check_access_token(
            token,
            issuer,
            &keys,
            self.ports.clock.now(),
            self.ports.verifier.as_ref(),
        ) {
            Ok(checked) => checked,
            Err(refusal) => return Ok(Err(refusal)),
        };
        // The person is the one of the token's grant, never read from its
        // `sub`, which a pairwise client's token gives as a pairwise
        // identifier.
        let Some(person) = self
            .ports
            .register
            .person_in_force(tenant, &checked.token_id, &checked.client_id)
            .await?
        else {
            return Ok(Err(BearerRefusal::InvalidToken(
                "the token is not in force, or is about no person",
            )));
        };
        let user = match self.ports.identity.get(tenant, person).await {
            Ok(user) => user,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(Err(BearerRefusal::InvalidToken(
                    "the person does not exist",
                )));
            }
            Err(error) => return Err(error),
        };
        // Only an active person: a service account or an agent has no
        // claims of a person to read.
        if !user.may_sign_in() {
            return Ok(Err(BearerRefusal::InvalidToken(
                "the user is not an active person",
            )));
        }
        let snapshot = user.snapshot();
        let groups = if checked.scopes.iter().any(|scope| scope == GROUPS_SCOPE) {
            self.ports
                .memberships
                .effective_groups(tenant, person)
                .await?
        } else {
            Vec::new()
        };
        let person = PersonClaims {
            name: snapshot.profile.display_name.clone(),
            preferred_username: user
                .primary_identifier(IdentifierKind::Username)
                .map(|identifier| identifier.value.display().to_owned()),
            locale: snapshot.profile.locale.clone(),
            updated_at: Some(snapshot.updated_at),
            email: user
                .primary_identifier(IdentifierKind::Email)
                .map(|identifier| {
                    (
                        identifier.value.display().to_owned(),
                        identifier.is_verified(),
                    )
                }),
            groups,
        };
        let mut claims = userinfo_claims(&checked.subject, &checked.scopes, &person);
        if let Ok(client_id) = checked.client_id.parse::<ClientId>() {
            let mapped = self
                .ports
                .mapping
                .read(
                    tenant,
                    MappedToken {
                        client_id,
                        user_id: user.id(),
                        scopes: &checked.scopes,
                        organization: checked.organization,
                    },
                    &[ClaimTarget::UserInfo],
                )
                .await?;
            add_mapped_claims(&mut claims, &mapped.of(ClaimTarget::UserInfo));
        }
        Ok(Ok(claims))
    }
}
