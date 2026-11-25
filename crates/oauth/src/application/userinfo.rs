//! UserInfo: the claims of the person an access token was issued for, in
//! JSON or signed for the client, as the client chose.

use crate::application::claim_mapper::{ClaimMapping, MappedToken};
use crate::application::introspection::AccessTokenRegister;
use crate::application::ports::{ClientStore, PersonMemberships};
use crate::application::token::signed_with_active_key;
use crate::domain::claim_mapper::{ClaimTarget, add_mapped_claims};
use crate::domain::client::{ClientId, IdTokenAlgorithm};
use crate::domain::forwarded::{ForwardedIdentity, presented_thumbprint};
use crate::domain::openid::{
    BearerRefusal, PersonClaims, PublishedKey, check_access_token, signed_userinfo_claims,
    userinfo_claims, userinfo_header,
};
use crate::domain::resource_server::GROUPS_SCOPE;
use crate::domain::token::{compact, signing_input};
use hodor_identity::api::{IdentifierKind, IdentityService};
use hodor_kernel::{
    Clock, Digest, DomainError, ErrorKind, SignatureVerifier, TenantContext, UnitOfWorkFactory,
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
            let algorithm = version.algorithm().signature()?;
            Some(PublishedKey {
                key_id: version.id().to_string(),
                algorithm,
                key: version.public_key()?.clone(),
            })
        })
        .collect())
}

/// What UserInfo answers a request whose token passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UserInfoAnswer {
    /// The claims, as JSON: the answer of a client that chose no UserInfo
    /// algorithm.
    Json(Value),
    /// The claims as a compact JSON Web Signature, signed for a client
    /// that chose an algorithm, answered as `application/jwt`.
    Signed(String),
}

/// The ports [`UserInfoService`] works through.
#[derive(Clone)]
pub struct UserInfoPorts {
    /// Starts units of work, to read the token's client.
    pub units_of_work: Arc<dyn UnitOfWorkFactory>,
    /// Reads the token's client, for its UserInfo algorithm.
    pub clients: Arc<dyn ClientStore>,
    /// Lists the tenant's published keys, and signs a signed answer.
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
    /// SHA-256, for the thumbprint of a forwarded certificate.
    pub digest: Arc<dyn Digest>,
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

    /// The answer for the person `token` was issued for: the claims of its
    /// scopes and of its client's mappers, in JSON, or signed with the
    /// client's UserInfo algorithm when it chose one. A token bound to a
    /// certificate must come with the one a trusted proxy `forwarded`,
    /// whichever the answer.
    ///
    /// # Errors
    ///
    /// The outer error is a failure of storage, or of the key provider
    /// asked to sign; the inner one is why the token is refused.
    pub async fn answer(
        &self,
        tenant: &TenantContext,
        issuer: &str,
        token: Option<&str>,
        forwarded: Option<&ForwardedIdentity>,
    ) -> Result<Result<UserInfoAnswer, BearerRefusal>, DomainError> {
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
            presented_thumbprint(forwarded, self.ports.digest.as_ref()).as_ref(),
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
            claims: snapshot.claims.clone(),
            groups,
        };
        let mut claims = userinfo_claims(&checked.subject, &checked.scopes, &person);
        let Ok(client_id) = checked.client_id.parse::<ClientId>() else {
            return Ok(Ok(UserInfoAnswer::Json(claims)));
        };
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
        let Some(algorithm) = self.userinfo_algorithm(tenant, client_id).await? else {
            return Ok(Ok(UserInfoAnswer::Json(claims)));
        };
        let claims = signed_userinfo_claims(claims, issuer, &checked.client_id);
        let key_algorithm = algorithm.key_algorithm();
        let signed = signed_with_active_key(&self.ports.keys, tenant, key_algorithm, |key_id| {
            let header = userinfo_header(algorithm.as_str(), &key_id.to_string());
            signing_input(&header, &claims).into_bytes()
        })
        .await?;
        match signed {
            Some((message, signature)) => Ok(Ok(UserInfoAnswer::Signed(compact(
                &message,
                &signature.bytes,
            )))),
            // Never an unsigned answer in place of a signed one.
            None => Err(DomainError::internal(
                "oauth.userinfo_not_signed",
                "the tenant has no key to sign the answer with",
            )),
        }
    }

    /// The UserInfo algorithm of the token's client, read in the token's
    /// tenant: `None` for a client that chose none, or that no longer
    /// exists, whose answer is JSON.
    async fn userinfo_algorithm(
        &self,
        tenant: &TenantContext,
        client_id: ClientId,
    ) -> Result<Option<IdTokenAlgorithm>, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        Ok(self
            .ports
            .clients
            .get(uow.as_mut(), client_id)
            .await?
            .and_then(|client| client.snapshot().settings.userinfo_algorithm))
    }
}
