//! What the authorization context knows about a subject, answered by the
//! identity and OAuth contexts: the authorization context depends on
//! neither.
//!
//! See `docs/architecture/contexts/authorization.md`, "What Hodor knows
//! about a subject".

use hodor_authorization::api::{Attributes, Subject, SubjectAttributeSource, SubjectKind};
use hodor_identity::api::IdentityService;
use hodor_kernel::{DomainError, ErrorKind, TenantContext, UserId};
use hodor_oauth::api::{ApplicationService, ClientId};
use serde_json::{Value, json};

/// [`SubjectAttributeSource`] over the identity and OAuth contexts.
#[derive(Clone)]
pub(crate) struct ServerSubjects {
    /// The users.
    pub(crate) identity: IdentityService,
    /// The clients.
    pub(crate) applications: ApplicationService,
}

impl std::fmt::Debug for ServerSubjects {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServerSubjects").finish_non_exhaustive()
    }
}

fn attributes(values: &[(&str, Value)]) -> Result<Attributes, DomainError> {
    Attributes::new(
        values
            .iter()
            .map(|(name, value)| ((*name).to_owned(), value.clone())),
    )
}

#[async_trait::async_trait]
impl SubjectAttributeSource for ServerSubjects {
    async fn attributes_of(
        &self,
        tenant: &TenantContext,
        subject: &Subject,
    ) -> Result<Attributes, DomainError> {
        // A subject Hodor does not know has none: not told apart from one
        // that has none, so that the answer does not say who exists.
        match subject.kind() {
            SubjectKind::User => {
                let Ok(id) = subject.id().parse::<UserId>() else {
                    return Ok(Attributes::none());
                };
                match self.identity.get(tenant, id).await {
                    Ok(user) => {
                        let snapshot = user.snapshot();
                        attributes(&[
                            ("status", json!(snapshot.status.as_str())),
                            ("kind", json!(snapshot.kind.as_str())),
                        ])
                    }
                    Err(error) if error.kind() == ErrorKind::NotFound => Ok(Attributes::none()),
                    Err(error) => Err(error),
                }
            }
            SubjectKind::Client => {
                let Ok(id) = subject.id().parse::<ClientId>() else {
                    return Ok(Attributes::none());
                };
                match self.applications.client(tenant, id).await {
                    Ok(client) => {
                        let snapshot = client.snapshot();
                        attributes(&[
                            ("application", json!(snapshot.application_id.to_string())),
                            ("client_type", json!(snapshot.client_type.as_str())),
                            ("enabled", json!(client.is_enabled())),
                        ])
                    }
                    Err(error) if error.kind() == ErrorKind::NotFound => Ok(Attributes::none()),
                    Err(error) => Err(error),
                }
            }
        }
    }
}
