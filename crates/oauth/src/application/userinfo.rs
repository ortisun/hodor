//! UserInfo: the claims of the person an access token was issued for.

use crate::domain::openid::{
    BearerRefusal, PersonClaims, PublishedKey, check_access_token, userinfo_claims,
};
use hodor_identity::api::{IdentifierKind, IdentityService, UserStatus};
use hodor_kernel::{
    Clock, DomainError, ErrorKind, SignatureAlgorithm, SignatureVerifier, TenantContext,
};
use hodor_keys::api::KeyService;
use serde_json::Value;
use std::fmt;
use std::sync::Arc;

/// The ports [`UserInfoService`] works through.
#[derive(Clone)]
pub struct UserInfoPorts {
    /// Lists the tenant's published keys.
    pub keys: KeyService,
    /// Checks the access token's signature.
    pub verifier: Arc<dyn SignatureVerifier>,
    /// Reads the person.
    pub identity: IdentityService,
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
        let keys: Vec<PublishedKey> = self
            .ports
            .keys
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
            .collect();
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
        let user = match self.ports.identity.get(tenant, checked.user_id).await {
            Ok(user) => user,
            Err(error) if error.kind() == ErrorKind::NotFound => {
                return Ok(Err(BearerRefusal::InvalidToken(
                    "the person does not exist",
                )));
            }
            Err(error) => return Err(error),
        };
        if user.status() != UserStatus::Active {
            return Ok(Err(BearerRefusal::InvalidToken("the person is not active")));
        }
        let snapshot = user.snapshot();
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
        };
        Ok(Ok(userinfo_claims(
            checked.user_id,
            &checked.scopes,
            &person,
        )))
    }
}
