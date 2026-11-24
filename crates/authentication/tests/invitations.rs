//! Invitations to an organization through the use cases, over the real
//! contexts running on their in-memory ports.

use hodor_authentication::api::{InvitationContexts, InvitationService};
use hodor_credential::api::{CredentialService, PasswordCheck};
use hodor_credential::testing::{FakeHasher, InMemoryPasswords};
use hodor_identity::api::{
    CreateUser, IdentifierKind, IdentityService, OrganizationService, Profile, UnitKind, UserKind,
};
use hodor_identity::testing::{InMemoryInvitations, InMemoryOrganizations, InMemoryUsers};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, OrganizationId, Secret, TenantContext, Timestamp, UserId};
use hodor_notification::api::{Notifier, Template};
use hodor_notification::testing::InMemoryMessages;
use hodor_session::testing::SequentialRandom;
use hodor_tenant::api::{CreateTenant, TenantService};
use hodor_tenant::testing::InMemoryTenants;
use std::collections::BTreeSet;
use std::sync::Arc;
use time::Duration;

const PASSWORD: &str = "correct horse battery staple";

struct World {
    invitations: InvitationService,
    organizations: OrganizationService,
    identity: IdentityService,
    credentials: CredentialService,
    messages: InMemoryMessages,
    clock: Arc<FixedClock>,
    tenant: TenantContext,
    acme: OrganizationId,
}

async fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let factory = || Arc::new(units_of_work.clone());
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let tenant_rows = InMemoryTenants::default();
    let tenants = TenantService::new(
        factory(),
        Arc::new(tenant_rows.clone()),
        Arc::new(tenant_rows),
        clock.clone(),
    );
    let users = Arc::new(InMemoryUsers::default());
    let identity = IdentityService::new(factory(), users.clone(), clock.clone());
    let credentials = CredentialService::new(
        factory(),
        Arc::new(InMemoryPasswords::default()),
        Arc::new(FakeHasher::default()),
        clock.clone(),
    );
    let organizations = OrganizationService::new(
        factory(),
        Arc::new(InMemoryOrganizations::default()),
        Arc::new(InMemoryInvitations::default()),
        users,
        clock.clone(),
    );
    let messages = InMemoryMessages::default();
    let invitations = InvitationService::new(
        factory(),
        InvitationContexts {
            organizations: organizations.clone(),
            identity: identity.clone(),
            credentials: credentials.clone(),
            tenants: tenants.clone(),
            notifier: Notifier::new(Arc::new(messages.clone()), clock.clone()),
        },
        Arc::new(FakeDigest),
        Arc::new(SequentialRandom::default()),
        "https://login.example.com/",
    );
    let created = tenants
        .create(
            CreateTenant {
                slug: "initech".to_owned(),
                display_name: "Initech".to_owned(),
                open_registration: false,
                system: false,
            },
            Caller::system(),
        )
        .await
        .expect("a tenant");
    let tenant = TenantContext::assume(created.id());
    let acme = organizations
        .create(&tenant, "Acme", None, Caller::system())
        .await
        .expect("an organization")
        .id();
    World {
        invitations,
        organizations,
        identity,
        credentials,
        messages,
        clock,
        tenant,
        acme,
    }
}

impl World {
    async fn invite(&self, email: &str) -> String {
        let engineering = self
            .organizations
            .create_unit(
                &self.tenant,
                self.acme,
                None,
                &format!(
                    "Engineering {}",
                    self.messages.of_tenant(self.tenant.tenant_id()).len()
                ),
                UnitKind::Department,
                Caller::system(),
            )
            .await
            .expect("a unit");
        self.invitations
            .invite(
                &self.tenant,
                self.acme,
                email,
                BTreeSet::from([engineering.id]),
                Some("pt-BR"),
                Caller::system(),
            )
            .await
            .expect("invited");
        let message = self
            .messages
            .of_tenant(self.tenant.tenant_id())
            .pop()
            .expect("a message");
        assert_eq!(
            message.snapshot().template,
            Template::OrganizationInvitation
        );
        let link = message.snapshot().variables["link"].clone();
        assert!(
            link.starts_with(
                "https://login.example.com/t/initech/account/accept-invitation#token="
            ),
            "{link}"
        );
        link.split_once("#token=").expect("a token").1.to_owned()
    }

    async fn person(&self, email: &str) -> UserId {
        self.identity
            .create(
                &self.tenant,
                CreateUser {
                    kind: UserKind::Human,
                    identifiers: vec![(IdentifierKind::Email, email.to_owned())],
                    profile: Profile::default(),
                    confirmed: true,
                },
                Caller::system(),
            )
            .await
            .expect("a person")
            .id()
    }

    async fn accept_as_new(
        &self,
        token: &str,
        password: &str,
    ) -> Result<UserId, hodor_kernel::DomainError> {
        self.invitations
            .accept_as_new(
                &self.tenant,
                token,
                &Secret::from(password.to_owned()),
                Some("Ana".to_owned()),
                Caller::system(),
            )
            .await
    }
}

#[tokio::test]
async fn a_person_with_no_account_accepts_by_choosing_a_password() {
    let world = world().await;
    let token = world.invite("Ana@Example.com").await;
    let described = world
        .invitations
        .describe(&world.tenant, &token)
        .await
        .expect("described");
    assert_eq!(described.organization_name, "Acme");
    assert_eq!(described.email, "ana@example.com");
    assert!(!described.has_account);

    let user = world
        .accept_as_new(&token, PASSWORD)
        .await
        .expect("accepted");
    let account = world
        .identity
        .get(&world.tenant, user)
        .await
        .expect("the account");
    assert!(
        account.identifiers()[0].verified_at.is_some(),
        "the address is verified"
    );
    let checked = world
        .credentials
        .verify_password(
            &world.tenant,
            Some(user),
            &Secret::from(PASSWORD.to_owned()),
        )
        .await
        .expect("checked");
    assert!(
        matches!(checked, PasswordCheck::Verified { .. }),
        "{checked:?}"
    );
    let of = world
        .organizations
        .organizations_of(&world.tenant, user)
        .await
        .expect("of");
    assert_eq!(of.len(), 1);
    assert_eq!(of[0].units.len(), 1, "with the invitation's unit");

    let again = world
        .accept_as_new(&token, PASSWORD)
        .await
        .expect_err("once");
    assert_eq!(again.code(), "identity.invitation_invalid");
}

#[tokio::test]
async fn a_password_that_is_not_acceptable_leaves_the_invitation_good() {
    let world = world().await;
    let token = world.invite("ana@example.com").await;
    let refused = world
        .accept_as_new(&token, "short")
        .await
        .expect_err("too short");
    assert_eq!(refused.code(), "credential.password_too_short");
    world
        .accept_as_new(&token, PASSWORD)
        .await
        .expect("still good");
}

#[tokio::test]
async fn an_address_with_an_account_accepts_only_as_that_account() {
    let world = world().await;
    let ana = world.person("ana@example.com").await;
    let bruno = world.person("bruno@example.com").await;
    let token = world.invite("ana@example.com").await;
    assert!(
        world
            .invitations
            .describe(&world.tenant, &token)
            .await
            .expect("described")
            .has_account
    );

    let refused = world
        .accept_as_new(&token, PASSWORD)
        .await
        .expect_err("has an account");
    assert_eq!(refused.code(), "authentication.invitation_needs_sign_in");
    let refused = world
        .invitations
        .accept_signed_in(&world.tenant, &token, bruno, Caller::system())
        .await
        .expect_err("someone else");
    assert_eq!(refused.code(), "authentication.invitation_for_someone_else");
    world
        .invitations
        .accept_signed_in(&world.tenant, &token, ana, Caller::system())
        .await
        .expect("accepted as Ana");
    assert_eq!(
        world
            .organizations
            .organizations_of(&world.tenant, ana)
            .await
            .expect("of")
            .len(),
        1
    );
    assert!(
        world
            .organizations
            .organizations_of(&world.tenant, bruno)
            .await
            .expect("of")
            .is_empty()
    );
}

#[tokio::test]
async fn only_the_newest_link_works_and_only_for_seven_days() {
    let world = world().await;
    let first = world.invite("ana@example.com").await;
    let second = world.invite("ana@example.com").await;
    let refused = world
        .invitations
        .describe(&world.tenant, &first)
        .await
        .expect_err("replaced");
    assert_eq!(refused.code(), "identity.invitation_invalid");
    world
        .invitations
        .describe(&world.tenant, &second)
        .await
        .expect("the newest");

    world.clock.advance(Duration::days(7));
    let refused = world
        .invitations
        .describe(&world.tenant, &second)
        .await
        .expect_err("expired");
    assert_eq!(refused.code(), "identity.invitation_invalid");
    for nonsense in ["", "not a token", &"g".repeat(64)] {
        let refused = world
            .invitations
            .describe(&world.tenant, nonsense)
            .await
            .expect_err("nothing");
        assert_eq!(refused.code(), "identity.invitation_invalid");
    }
}
