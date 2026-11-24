//! Invitations to an organization: sending the link and accepting it.
//!
//! See `docs/architecture/contexts/authentication.md`, "Invitations to an
//! organization". The invitation itself is the identity context's; this
//! module makes its secret, queues the message and accepts.

use crate::application::account::{locale_of, password_rules, written};
use crate::domain::verification::{VerificationSecret, VerificationTokenHash};
use hodor_credential::api::{CredentialService, NewPassword, check_acceptable};
use hodor_identity::api::{
    CreateUser, IdentifierKind, IdentityService, InvitationFound, NormalizedIdentifier,
    OrganizationService, Profile, UnitId, UserKind,
};
use hodor_kernel::{
    Caller, Digest, DomainError, ErrorKind, OrganizationId, RandomSource, Secret, TenantContext,
    Timestamp, UnitOfWorkFactory, UserId,
};
use hodor_notification::api::{EnqueueMessage, Notifier, Template};
use hodor_tenant::api::TenantService;
use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

/// What an invitation is for, as its holder may see it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvitationDescription {
    /// The organization's name.
    pub organization_name: String,
    /// The address the invitation was sent to.
    pub email: String,
    /// Whether that address has an account in the tenant.
    pub has_account: bool,
    /// When the invitation stops being good.
    pub expires_at: Timestamp,
}

/// The use cases of invitations.
#[derive(Clone)]
pub struct InvitationService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    organizations: OrganizationService,
    identity: IdentityService,
    credentials: CredentialService,
    tenants: TenantService,
    notifier: Notifier,
    digest: Arc<dyn Digest>,
    random: Arc<dyn RandomSource>,
    public_url: String,
}

impl std::fmt::Debug for InvitationService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvitationService").finish_non_exhaustive()
    }
}

/// The contexts invitations need, so that the constructor stays short.
#[derive(Clone)]
pub struct InvitationContexts {
    /// Where invitations and memberships are kept.
    pub organizations: OrganizationService,
    /// Where users are found and created.
    pub identity: IdentityService,
    /// Where a new account's password is set.
    pub credentials: CredentialService,
    /// Where the tenant's name and password policy are read.
    pub tenants: TenantService,
    /// Where the message is queued.
    pub notifier: Notifier,
}

impl std::fmt::Debug for InvitationContexts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("InvitationContexts").finish_non_exhaustive()
    }
}

fn invitation_invalid() -> DomainError {
    DomainError::not_found(
        "identity.invitation_invalid",
        "the invitation is unknown, accepted, withdrawn or expired",
    )
}

impl InvitationService {
    /// Wires the use cases. `public_url` is the address people reach the
    /// installation at, without a path; links start with it.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        contexts: InvitationContexts,
        digest: Arc<dyn Digest>,
        random: Arc<dyn RandomSource>,
        public_url: &str,
    ) -> Self {
        Self {
            units_of_work,
            organizations: contexts.organizations,
            identity: contexts.identity,
            credentials: contexts.credentials,
            tenants: contexts.tenants,
            notifier: contexts.notifier,
            digest,
            random,
            public_url: public_url.trim_end_matches('/').to_owned(),
        }
    }

    /// Invites an address to an organization: makes the invitation and
    /// queues its message, in one transaction.
    ///
    /// # Errors
    ///
    /// `NotFound` for an organization or a unit it does not have, and
    /// `Invalid` for an address that is not one.
    pub async fn invite(
        &self,
        tenant: &TenantContext,
        organization: OrganizationId,
        email: &str,
        units: BTreeSet<UnitId>,
        locale: Option<&str>,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let settings = self.tenants.get(tenant).await?;
        let settings = settings.snapshot();
        let secret = VerificationSecret::generate(self.random.as_ref());
        let hash = self.digest.sha256(secret.expose().as_bytes());
        let mut uow = self.units_of_work.begin(tenant).await?;
        let (invitation, found) = self
            .organizations
            .invite_in(uow.as_mut(), organization, email, units, hash, caller)
            .await?;
        let link = format!(
            "{}/t/{}/account/accept-invitation#token={}",
            self.public_url,
            settings.slug,
            secret.expose()
        );
        let variables: BTreeMap<String, String> = [
            ("link", link),
            ("tenant_name", settings.display_name.clone()),
            ("organization_name", found.name().as_str().to_owned()),
            ("expires_at", written(invitation.expires_at)),
        ]
        .into_iter()
        .map(|(name, value)| (name.to_owned(), value))
        .collect();
        let recipient = NormalizedIdentifier::parse(IdentifierKind::Email, email)?;
        self.notifier
            .enqueue(
                uow.as_mut(),
                EnqueueMessage {
                    recipient: recipient.display().to_owned(),
                    template: Template::OrganizationInvitation,
                    locale: locale_of(&[locale]),
                    variables,
                    expires_at: invitation.expires_at,
                },
            )
            .await?;
        uow.commit().await
    }

    /// What an invitation is for, for whoever holds its link.
    ///
    /// # Errors
    ///
    /// `NotFound` with code `identity.invitation_invalid` for a token that
    /// is unknown, accepted, withdrawn or expired.
    pub async fn describe(
        &self,
        tenant: &TenantContext,
        token: &str,
    ) -> Result<InvitationDescription, DomainError> {
        let found = self.good(tenant, token).await?;
        let has_account = self
            .identity
            .find_by_login(tenant, &found.invitation.email)
            .await?
            .is_some();
        Ok(InvitationDescription {
            organization_name: found.organization.name().as_str().to_owned(),
            email: found.invitation.email,
            has_account,
            expires_at: found.invitation.expires_at,
        })
    }

    /// Accepts an invitation for an address that has no account: creates
    /// the account, already active with the address verified, uses the
    /// invitation up and makes the membership, all in one transaction,
    /// then sets the password.
    ///
    /// # Errors
    ///
    /// `NotFound` with code `identity.invitation_invalid`; `Conflict` with
    /// code `authentication.invitation_needs_sign_in` when the address has
    /// an account; `Invalid` for a password or a name that is not
    /// acceptable, the invitation staying good.
    pub async fn accept_as_new(
        &self,
        tenant: &TenantContext,
        token: &str,
        password: &Secret<String>,
        display_name: Option<String>,
        caller: Caller,
    ) -> Result<UserId, DomainError> {
        let found = self.good(tenant, token).await?;
        let email = found.invitation.email.clone();
        if self.identity.find_by_login(tenant, &email).await?.is_some() {
            return Err(needs_sign_in());
        }
        let settings = self.tenants.get(tenant).await?;
        let rules = password_rules(settings.snapshot());
        // Everything that can be refused is checked before anything is
        // stored, so that the person can correct it and try again.
        check_acceptable(password, &rules, &[email.as_str()])?;
        let display_name = display_name
            .map(|name| name.trim().to_owned())
            .filter(|name| !name.is_empty());
        if display_name
            .as_ref()
            .is_some_and(|name| name.chars().count() > Profile::MAX_DISPLAY_NAME_LENGTH)
        {
            return Err(DomainError::invalid(
                "identity.display_name_invalid",
                "a display name has at most 200 characters",
            ));
        }

        let mut uow = self.units_of_work.begin(tenant).await?;
        let command = CreateUser {
            kind: UserKind::Human,
            identifiers: vec![(IdentifierKind::Email, email.clone())],
            profile: Profile {
                display_name,
                locale: None,
            },
            confirmed: true,
        };
        let user = self
            .identity
            .create_in(uow.as_mut(), command, true, caller)
            .await
            .map_err(|error| {
                if error.code() == "identity.identifier_taken" {
                    needs_sign_in()
                } else {
                    error
                }
            })?;
        self.organizations
            .accept_in(uow.as_mut(), &found.invitation, user.id(), caller)
            .await?;
        uow.commit().await?;

        let new = NewPassword {
            password,
            rules,
            own_names: &[email.as_str()],
        };
        self.credentials
            .set_password(tenant, user.id(), new, false, caller)
            .await?;
        Ok(user.id())
    }

    /// Accepts an invitation as a signed-in user who has the invited
    /// address, and marks the address verified.
    ///
    /// # Errors
    ///
    /// `NotFound` with code `identity.invitation_invalid`, and `Forbidden`
    /// with code `authentication.invitation_for_someone_else` for a user
    /// who does not have the address, the invitation staying good.
    pub async fn accept_signed_in(
        &self,
        tenant: &TenantContext,
        token: &str,
        user: UserId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let found = self.good(tenant, token).await?;
        let invited = NormalizedIdentifier::parse(IdentifierKind::Email, &found.invitation.email)?;
        let account = self.identity.get(tenant, user).await?;
        let Some(identifier) = account.identifier_matching(&invited) else {
            return Err(DomainError::new(
                ErrorKind::Forbidden,
                "authentication.invitation_for_someone_else",
                "this invitation was sent to an address of another account",
            ));
        };
        let identifier = identifier.id;
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.organizations
            .accept_in(uow.as_mut(), &found.invitation, user, caller)
            .await?;
        uow.commit().await?;
        // The person just proved they read the message.
        self.identity
            .verify_identifier(tenant, user, identifier, caller)
            .await?;
        Ok(())
    }

    async fn good(
        &self,
        tenant: &TenantContext,
        token: &str,
    ) -> Result<InvitationFound, DomainError> {
        let Some(hash) = VerificationTokenHash::of_presented(token, self.digest.as_ref()) else {
            return Err(invitation_invalid());
        };
        self.organizations
            .good_invitation(tenant, hash.as_bytes())
            .await
    }
}

fn needs_sign_in() -> DomainError {
    DomainError::conflict(
        "authentication.invitation_needs_sign_in",
        "the invited address has an account: sign in as it and accept",
    )
}
