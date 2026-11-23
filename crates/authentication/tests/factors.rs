//! A person's own factors: listing them, adding an authenticator
//! application with the recovery codes that come with a first factor,
//! renaming and removing keys, the rule of the last second factor, and
//! what an administrator may do. The real credential, identity and tenant
//! contexts run on their in-memory ports.

use hodor_authentication::api::{
    FactorService, RECENT_SIGN_IN, Remover, recent_sign_in_until, signed_in_recently,
};
use hodor_credential::api::{
    RecoveryCodeService, RelyingParty, STEP_SECONDS, TotpEnrollment, TotpService,
    WebAuthnCredential, WebAuthnService, WebAuthnStore as _, totp_code_at,
};
use hodor_credential::testing::{
    FakeHmacSha1, InMemoryRecoveryCodes, InMemoryTotps, InMemoryWebAuthn, base32_secret,
    stored_credential,
};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_identity::testing::InMemoryUsers;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::{CountingRandom, FakeDigest};
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, PublicKey, Secret, SignatureAlgorithm, SignatureVerifier, TenantContext,
    Timestamp, UnitOfWorkFactory as _, UserId,
};
use hodor_tenant::api::{CreateTenant, SecondFactorPolicy, TenantService};
use hodor_tenant::testing::InMemoryTenants;
use std::sync::Arc;
use time::Duration;

/// No signature is checked here: keys are stored as a finished
/// registration would store them.
struct RefusingVerifier;

impl SignatureVerifier for RefusingVerifier {
    fn verify(&self, _: SignatureAlgorithm, _: &PublicKey, _: &[u8], _: &[u8]) -> bool {
        false
    }
}

struct World {
    factors: FactorService,
    without_totp: FactorService,
    tenants: TenantService,
    keys: InMemoryWebAuthn,
    units_of_work: InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    tenant: TenantContext,
    other_tenant: TenantContext,
    ana: UserId,
    bruno: UserId,
}

async fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::seconds(STEP_SECONDS * 60_000_000),
    ));
    let factory = || Arc::new(units_of_work.clone());
    let tenant_rows = InMemoryTenants::default();
    let tenants = TenantService::new(
        factory(),
        Arc::new(tenant_rows.clone()),
        Arc::new(tenant_rows),
        clock.clone(),
    );
    let identity =
        IdentityService::new(factory(), Arc::new(InMemoryUsers::default()), clock.clone());
    let keys = InMemoryWebAuthn::default();
    let webauthn = WebAuthnService::new(
        factory(),
        Arc::new(keys.clone()),
        RelyingParty::from_public_address("https://id.example.com").expect("relying party"),
        Arc::new(FakeDigest),
        Arc::new(RefusingVerifier),
        Arc::new(CountingRandom::default()),
        clock.clone(),
    );
    let recovery_codes = RecoveryCodeService::new(
        factory(),
        Arc::new(InMemoryRecoveryCodes::default()),
        Arc::new(FakeDigest),
        Arc::new(CountingRandom::default()),
        clock.clone(),
    );
    let totp = TotpService::new(
        factory(),
        Arc::new(InMemoryTotps::default()),
        Arc::new(FakeSecretBox),
        Arc::new(FakeHmacSha1),
        Arc::new(CountingRandom::default()),
        clock.clone(),
    );
    let without_totp = FactorService::new(
        identity.clone(),
        tenants.clone(),
        webauthn.clone(),
        recovery_codes.clone(),
    );
    let factors = without_totp.clone().with_totp(totp);

    let mut contexts = Vec::new();
    for slug in ["acme", "globex"] {
        let created = tenants
            .create(
                CreateTenant {
                    slug: slug.to_owned(),
                    display_name: slug.to_uppercase(),
                    open_registration: false,
                    system: false,
                },
                Caller::system(),
            )
            .await
            .expect("tenant");
        contexts.push(TenantContext::assume(created.id()));
    }
    let tenant = contexts[0].clone();
    let mut people = Vec::new();
    for email in ["ana@example.com", "bruno@example.com"] {
        people.push(
            identity
                .create(
                    &tenant,
                    CreateUser {
                        kind: UserKind::Human,
                        identifiers: vec![(IdentifierKind::Email, email.to_owned())],
                        profile: Profile::default(),
                        confirmed: true,
                    },
                    Caller::system(),
                )
                .await
                .expect("user")
                .id(),
        );
    }
    World {
        factors,
        without_totp,
        tenants,
        keys,
        units_of_work,
        clock,
        other_tenant: contexts[1].clone(),
        tenant,
        ana: people[0],
        bruno: people[1],
    }
}

impl World {
    /// Gives a person a key, as a finished registration would.
    async fn give_key(&self, user: UserId) -> WebAuthnCredential {
        let key = stored_credential(user, uuid_bytes(), self.clock.now());
        let mut uow = self.units_of_work.begin(&self.tenant).await.expect("begin");
        self.keys.insert(uow.as_mut(), &key).await.expect("insert");
        uow.commit().await.expect("commit");
        key
    }

    /// Begins and confirms an authenticator application for Ana, as her
    /// pages would, and answers the recovery codes that came with it.
    async fn enroll_ana(&self) -> Option<Vec<String>> {
        let enrollment = self
            .factors
            .begin_authenticator_application(&self.tenant, self.ana)
            .await
            .expect("begin");
        let codes = self
            .factors
            .confirm_authenticator_application(
                &self.tenant,
                self.ana,
                &Secret::from(self.phone(&enrollment)),
                Caller::system(),
            )
            .await
            .expect("confirm");
        self.clock.advance(Duration::seconds(STEP_SECONDS));
        codes.map(|codes| codes.codes().map(str::to_owned).collect())
    }

    fn phone(&self, enrollment: &TotpEnrollment) -> String {
        totp_code_at(
            &FakeHmacSha1,
            &base32_secret(enrollment.secret()),
            self.clock.now(),
        )
    }

    async fn require_second_factor(&self) {
        let mut settings = self
            .tenants
            .get(&self.tenant)
            .await
            .expect("tenant")
            .snapshot()
            .settings
            .clone();
        settings.authentication.second_factor = SecondFactorPolicy::Required;
        self.tenants
            .change_settings(&self.tenant, settings, Caller::system())
            .await
            .expect("settings");
    }
}

fn uuid_bytes() -> Vec<u8> {
    hodor_credential::api::WebAuthnCredentialId::generate()
        .as_uuid()
        .as_bytes()
        .to_vec()
}

#[test]
fn a_sign_in_is_recent_for_five_minutes_and_never_from_the_future() {
    let at = Timestamp::UNIX_EPOCH + Duration::days(20_000);
    assert!(signed_in_recently(at, at));
    assert!(signed_in_recently(at, at + RECENT_SIGN_IN));
    assert!(!signed_in_recently(
        at,
        at + RECENT_SIGN_IN + Duration::seconds(1)
    ));
    assert!(!signed_in_recently(at + Duration::seconds(1), at));
    assert_eq!(recent_sign_in_until(at, at), Some(at + RECENT_SIGN_IN));
    assert_eq!(recent_sign_in_until(at, at + Duration::minutes(6)), None);
}

#[tokio::test]
async fn a_person_without_factors_has_nothing_to_list() {
    let world = world().await;
    let factors = world
        .factors
        .factors(&world.tenant, world.ana)
        .await
        .expect("factors");
    assert_eq!(factors.authenticator_application, Some(false));
    assert!(factors.keys.is_empty());
    assert_eq!(factors.recovery_codes_remaining, 0);
    assert!(!factors.second_factor_required);
    assert_eq!(factors.second_factors(), 0);
    // An installation that cannot keep secrets offers no application.
    let offered = world
        .without_totp
        .factors(&world.tenant, world.ana)
        .await
        .expect("factors");
    assert_eq!(offered.authenticator_application, None);
    let error = world
        .without_totp
        .begin_authenticator_application(&world.tenant, world.ana)
        .await
        .expect_err("none offered");
    assert_eq!(error.code(), "credential.totp_unavailable");
}

#[tokio::test]
async fn the_first_factor_comes_with_recovery_codes_and_the_next_does_not() {
    let world = world().await;
    let codes = world
        .enroll_ana()
        .await
        .expect("codes with the first factor");
    assert_eq!(codes.len(), 10);
    let factors = world
        .factors
        .factors(&world.tenant, world.ana)
        .await
        .expect("factors");
    assert_eq!(factors.authenticator_application, Some(true));
    assert_eq!(factors.recovery_codes_remaining, 10);
    // Enrolling again, in place of the application, makes no new set.
    assert_eq!(world.enroll_ana().await, None);
}

#[tokio::test]
async fn the_application_is_named_after_the_tenant_and_the_persons_address() {
    let world = world().await;
    let enrollment = world
        .factors
        .begin_authenticator_application(&world.tenant, world.ana)
        .await
        .expect("begin");
    assert!(
        enrollment
            .address()
            .starts_with("otpauth://totp/ACME:ana%40example.com?"),
        "{}",
        enrollment.address()
    );
    // A wrong code confirms nothing.
    let error = world
        .factors
        .confirm_authenticator_application(
            &world.tenant,
            world.ana,
            &Secret::from("000000".to_owned()),
            Caller::system(),
        )
        .await
        .expect_err("a wrong code");
    assert_eq!(error.code(), "credential.totp_code_wrong");
}

#[tokio::test]
async fn keys_are_renamed_and_removed_by_their_owner_only() {
    let world = world().await;
    let key = world.give_key(world.ana).await;
    let renamed = world
        .factors
        .rename_key(
            &world.tenant,
            world.ana,
            key.id(),
            "  Office key ",
            Caller::system(),
        )
        .await
        .expect("rename");
    assert_eq!(renamed.snapshot().name, "Office key");
    for bad in ["", "   ", "a\u{7}bell", &"x".repeat(65)] {
        let error = world
            .factors
            .rename_key(&world.tenant, world.ana, key.id(), bad, Caller::system())
            .await
            .expect_err("a bad name");
        assert_eq!(error.code(), "credential.webauthn_name_invalid");
    }
    // Bruno cannot rename or remove Ana's key, nor can anyone from another
    // tenant: it is not found.
    let error = world
        .factors
        .rename_key(
            &world.tenant,
            world.bruno,
            key.id(),
            "Mine",
            Caller::system(),
        )
        .await
        .expect_err("not Bruno's");
    assert_eq!(error.code(), "credential.webauthn_credential_not_found");
    let error = world
        .factors
        .remove_key(
            &world.tenant,
            world.bruno,
            key.id(),
            Remover::Person,
            Caller::system(),
        )
        .await
        .expect_err("not Bruno's");
    assert_eq!(error.code(), "credential.webauthn_credential_not_found");
    let error = world
        .factors
        .remove_key(
            &world.other_tenant,
            world.ana,
            key.id(),
            Remover::Administrator,
            Caller::system(),
        )
        .await
        .expect_err("not in another tenant");
    assert_eq!(error.code(), "identity.user_not_found");
    world
        .factors
        .remove_key(
            &world.tenant,
            world.ana,
            key.id(),
            Remover::Person,
            Caller::system(),
        )
        .await
        .expect("remove");
    assert!(
        world
            .factors
            .factors(&world.tenant, world.ana)
            .await
            .expect("factors")
            .keys
            .is_empty()
    );
}

#[tokio::test]
async fn under_the_policy_the_person_cannot_remove_their_last_second_factor() {
    let world = world().await;
    world.enroll_ana().await;
    let key = world.give_key(world.ana).await;
    world.require_second_factor().await;
    // With two factors, one may go.
    world
        .factors
        .remove_authenticator_application(
            &world.tenant,
            world.ana,
            Remover::Person,
            Caller::system(),
        )
        .await
        .expect("one of two");
    // The last one may not, for the person.
    let error = world
        .factors
        .remove_key(
            &world.tenant,
            world.ana,
            key.id(),
            Remover::Person,
            Caller::system(),
        )
        .await
        .expect_err("the last one");
    assert_eq!(error.code(), "authentication.last_second_factor");
    let left = world
        .factors
        .factors(&world.tenant, world.ana)
        .await
        .expect("factors");
    assert_eq!(left.second_factors(), 1);
    assert_eq!(left.recovery_codes_remaining, 10);
    // An administrator may remove it; the recovery codes go with it.
    world
        .factors
        .remove_key(
            &world.tenant,
            world.ana,
            key.id(),
            Remover::Administrator,
            Caller::system(),
        )
        .await
        .expect("an administrator");
    let left = world
        .factors
        .factors(&world.tenant, world.ana)
        .await
        .expect("factors");
    assert_eq!(left.second_factors(), 0);
    assert_eq!(left.recovery_codes_remaining, 0);
}

#[tokio::test]
async fn without_the_policy_removing_the_last_factor_takes_the_recovery_codes_with_it() {
    let world = world().await;
    world.enroll_ana().await;
    let key = world.give_key(world.ana).await;
    world
        .factors
        .remove_key(
            &world.tenant,
            world.ana,
            key.id(),
            Remover::Person,
            Caller::system(),
        )
        .await
        .expect("one of two");
    assert_eq!(
        world
            .factors
            .factors(&world.tenant, world.ana)
            .await
            .expect("factors")
            .recovery_codes_remaining,
        10,
        "the codes stay while a factor is left"
    );
    world
        .factors
        .remove_authenticator_application(
            &world.tenant,
            world.ana,
            Remover::Person,
            Caller::system(),
        )
        .await
        .expect("the last one");
    let left = world
        .factors
        .factors(&world.tenant, world.ana)
        .await
        .expect("factors");
    assert_eq!(left.second_factors(), 0);
    assert_eq!(left.recovery_codes_remaining, 0);
    let error = world
        .factors
        .remove_authenticator_application(
            &world.tenant,
            world.ana,
            Remover::Person,
            Caller::system(),
        )
        .await
        .expect_err("none in use");
    assert_eq!(error.code(), "credential.totp_not_found");
}

#[tokio::test]
async fn recovery_codes_are_generated_again_only_with_a_second_factor() {
    let world = world().await;
    let error = world
        .factors
        .generate_recovery_codes(&world.tenant, world.ana, Caller::system())
        .await
        .expect_err("no second factor");
    assert_eq!(error.code(), "authentication.second_factor_missing");
    let first = world.enroll_ana().await.expect("first set");
    let second: Vec<String> = world
        .factors
        .generate_recovery_codes(&world.tenant, world.ana, Caller::system())
        .await
        .expect("again")
        .codes()
        .map(str::to_owned)
        .collect();
    assert_eq!(second.len(), 10);
    assert_ne!(first, second);
    // An administrator removes them; removing what is not there says so.
    world
        .factors
        .remove_recovery_codes(&world.tenant, world.ana, Caller::system())
        .await
        .expect("remove");
    let error = world
        .factors
        .remove_recovery_codes(&world.tenant, world.ana, Caller::system())
        .await
        .expect_err("none left");
    assert_eq!(error.code(), "credential.recovery_codes_not_found");
    let error = world
        .factors
        .remove_recovery_codes(&world.tenant, UserId::generate(), Caller::system())
        .await
        .expect_err("nobody");
    assert_eq!(error.code(), "identity.user_not_found");
}
