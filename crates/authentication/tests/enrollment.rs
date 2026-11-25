//! Enrolling a second factor during a sign-in: the enrollment step of the
//! built-in flow, its authenticator and the use cases, over the real
//! identity, credential, session and tenant contexts running on their
//! in-memory ports.
//!
//! Specified in `docs/architecture/contexts/authentication.md`, "Enrolling
//! a second factor during a sign-in".

use hodor_authentication::api::{
    AttemptGuard, AuthFlow, AuthTransaction, AuthenticationService, Authenticator,
    AuthenticatorTraits, Condition, EnrollmentAuthenticator, ExternalInput, Factor, FactorService,
    FlowEngine, IdentifierAuthenticator, PasswordAuthenticator, RecoveryCodeAuthenticator,
    Requirement, SignIn, StepInput, StepOutcome, StepUp, StepUpRequest, TotpAuthenticator,
    TransactionId, WebAuthnAuthenticator,
};
use hodor_authentication::testing::{InMemoryAttempts, InMemoryTransactions};
use hodor_credential::api::{
    CredentialService, NewPassword, PasswordRules, RecoveryCodeService, RelyingParty, STEP_SECONDS,
    TotpService, WebAuthnService, totp_code_at,
};
use hodor_credential::testing::{
    FakeHasher, FakeHmacSha1, InMemoryPasswords, InMemoryRecoveryCodes, InMemoryTotps,
    InMemoryWebAuthn, base32_secret,
};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_identity::testing::InMemoryUsers;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::{CountingRandom, FakeDigest};
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Clock as _, DomainError, PublicKey, Secret, SignatureAlgorithm, SignatureVerifier,
    TenantContext, Timestamp, UserId,
};
use hodor_session::api::{Assurance, ClientInfo, SessionService};
use hodor_session::testing::{InMemorySessions, SequentialRandom};
use hodor_tenant::api::{CreateTenant, SecondFactorPolicy, TenantService};
use hodor_tenant::testing::InMemoryTenants;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use time::Duration;

const PASSWORD: &str = "correct horse battery staple";
const ENROLLMENT: &str = EnrollmentAuthenticator::KIND;

/// No signature is checked here: no key ever signs in.
struct RefusingVerifier;

impl SignatureVerifier for RefusingVerifier {
    fn verify(&self, _: SignatureAlgorithm, _: &PublicKey, _: &[u8], _: &[u8]) -> bool {
        false
    }
}

/// Stands for an identity provider: whoever brings the word "ana" is Ana,
/// something known, and nobody typed an identifier.
struct Outside {
    identity: IdentityService,
}

#[async_trait::async_trait]
impl Authenticator for Outside {
    fn kind(&self) -> &'static str {
        "outside"
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: true,
            factor: Some(Factor::Knowledge),
            second_factor: None,
            method: Some("outside"),
        }
    }

    async fn perform(
        &self,
        tenant: &TenantContext,
        _transaction: &AuthTransaction,
        input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        let StepInput::External(input) = input else {
            return Ok(StepOutcome::Rejected);
        };
        if input.field("who").map(|who| who.expose().as_str()) != Some("ana") {
            return Ok(StepOutcome::Rejected);
        }
        let ana = self
            .identity
            .find_by_login(tenant, "ana@example.com")
            .await?
            .expect("ana");
        Ok(StepOutcome::Authenticated { user: ana.id() })
    }
}

struct World {
    service: AuthenticationService,
    factors: FactorService,
    totp: TotpService,
    identity: IdentityService,
    tenants: TenantService,
    units_of_work: InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
    tenant: TenantContext,
    ana: UserId,
    secrets: Mutex<HashMap<TransactionId, String>>,
}

async fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::seconds(STEP_SECONDS * 60_000_000),
    ));
    let digest = Arc::new(FakeDigest);
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
    let credentials = CredentialService::new(
        factory(),
        Arc::new(InMemoryPasswords::default()),
        Arc::new(FakeHasher::default()),
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
    let recovery_codes = RecoveryCodeService::new(
        factory(),
        Arc::new(InMemoryRecoveryCodes::default()),
        digest.clone(),
        Arc::new(CountingRandom::default()),
        clock.clone(),
    );
    let webauthn = WebAuthnService::new(
        factory(),
        Arc::new(InMemoryWebAuthn::default()),
        RelyingParty::from_public_address("https://id.example.com").expect("relying party"),
        digest.clone(),
        Arc::new(RefusingVerifier),
        Arc::new(CountingRandom::default()),
        clock.clone(),
    );
    let factors = FactorService::new(
        identity.clone(),
        tenants.clone(),
        webauthn.clone(),
        recovery_codes.clone(),
    )
    .with_totp(totp.clone());
    let sessions = SessionService::new(
        factory(),
        Arc::new(InMemorySessions::default()),
        digest.clone(),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
    );
    let guard = AttemptGuard::new(
        factory(),
        Arc::new(InMemoryAttempts::default()),
        digest.clone(),
        clock.clone(),
    );
    let engine = FlowEngine::new()
        .with(Arc::new(IdentifierAuthenticator::new(
            identity.clone(),
            digest,
        )))
        .with(Arc::new(PasswordAuthenticator::new(
            credentials.clone(),
            identity.clone(),
            tenants.clone(),
            guard.clone(),
        )))
        .with(Arc::new(WebAuthnAuthenticator::new(webauthn)))
        .with(Arc::new(TotpAuthenticator::new(
            totp.clone(),
            tenants.clone(),
            guard.clone(),
        )))
        .with(Arc::new(RecoveryCodeAuthenticator::new(
            recovery_codes,
            tenants.clone(),
            guard,
        )))
        .with(Arc::new(EnrollmentAuthenticator::new(
            factors.clone(),
            identity.clone(),
        )))
        .with(Arc::new(Outside {
            identity: identity.clone(),
        }));
    // The built-in flow of the server.
    let flow = AuthFlow::built_in()
        .with_step(
            WebAuthnAuthenticator::KIND,
            WebAuthnAuthenticator::KIND,
            Requirement::Conditional(Condition::StrongerAssuranceNeeded),
        )
        .with_substitute(WebAuthnAuthenticator::KIND, RecoveryCodeAuthenticator::KIND)
        .with_step(
            TotpAuthenticator::KIND,
            TotpAuthenticator::KIND,
            Requirement::Conditional(Condition::MultiFactorNotReached),
        )
        .with_substitute(TotpAuthenticator::KIND, RecoveryCodeAuthenticator::KIND)
        .with_step(
            ENROLLMENT,
            ENROLLMENT,
            Requirement::Conditional(Condition::AssuranceNotReached),
        )
        .with_alternative("outside", "outside");
    let service = AuthenticationService::new(
        factory(),
        Arc::new(InMemoryTransactions::default()),
        engine,
        flow,
        identity.clone(),
        sessions,
        tenants.clone(),
        Arc::new(FakeDigest),
        Arc::new(SequentialRandom::default()),
        clock.clone(),
    )
    .expect("the flow with the enrollment step is valid");

    let created = tenants
        .create(
            CreateTenant {
                slug: "acme".to_owned(),
                display_name: "Acme".to_owned(),
                open_registration: false,
                system: false,
            },
            Caller::system(),
        )
        .await
        .expect("tenant");
    let tenant = TenantContext::assume(created.id());
    let ana = identity
        .create(
            &tenant,
            CreateUser {
                kind: UserKind::Human,
                identifiers: vec![(IdentifierKind::Email, "ana@example.com".to_owned())],
                profile: Profile::default(),
                confirmed: true,
            },
            Caller::system(),
        )
        .await
        .expect("user")
        .id();
    credentials
        .set_password(
            &tenant,
            ana,
            NewPassword {
                password: &Secret::from(PASSWORD.to_owned()),
                rules: PasswordRules {
                    min_length: 12,
                    max_length: 128,
                    history_depth: 5,
                },
                own_names: &[],
            },
            false,
            Caller::system(),
        )
        .await
        .expect("password");

    World {
        service,
        factors,
        totp,
        identity,
        tenants,
        units_of_work,
        clock,
        tenant,
        ana,
        secrets: Mutex::new(HashMap::new()),
    }
}

fn kind(value: &str) -> ExternalInput {
    ExternalInput {
        step: ENROLLMENT.to_owned(),
        fields: vec![("kind".to_owned(), Secret::from(value.to_owned()))],
    }
}

fn enrollment_input(fields: &[(&str, &str)]) -> StepInput {
    StepInput::External(ExternalInput {
        step: ENROLLMENT.to_owned(),
        fields: fields
            .iter()
            .map(|(name, value)| ((*name).to_owned(), Secret::from((*value).to_owned())))
            .collect(),
    })
}

fn step_of(answer: &SignIn) -> Option<&str> {
    match answer {
        SignIn::Pending { step, .. } | SignIn::Rejected { step, .. } => Some(step),
        _ => None,
    }
}

impl World {
    async fn start(&self) -> TransactionId {
        let started = self
            .service
            .start(
                &self.tenant,
                ClientInfo {
                    address: Some("203.0.113.1".to_owned()),
                    description: Some("Example Browser".to_owned()),
                },
            )
            .await
            .expect("start");
        self.secrets
            .lock()
            .expect("secrets")
            .insert(started.transaction_id, started.secret.expose().clone());
        started.transaction_id
    }

    fn secret(&self, id: TransactionId) -> String {
        self.secrets.lock().expect("secrets")[&id].clone()
    }

    async fn submit(&self, id: TransactionId, input: StepInput) -> Result<SignIn, DomainError> {
        self.service
            .submit(&self.tenant, id, &self.secret(id), input)
            .await
    }

    async fn begin(&self, id: TransactionId, what: &str) -> Result<serde_json::Value, DomainError> {
        self.service
            .challenge(&self.tenant, id, &self.secret(id), kind(what))
            .await
    }

    /// Starts a sign-in and gets through the identifier and the password.
    async fn after_password(&self) -> (TransactionId, SignIn) {
        let id = self.start().await;
        self.submit(id, StepInput::Identifier("ana@example.com".to_owned()))
            .await
            .expect("identifier");
        let answer = self
            .submit(id, StepInput::Password(Secret::from(PASSWORD.to_owned())))
            .await
            .expect("password");
        (id, answer)
    }

    /// What the application set up from `secret` shows now.
    fn phone(&self, secret: &str) -> String {
        totp_code_at(&FakeHmacSha1, &base32_secret(secret), self.clock.now())
    }

    /// Begins an authenticator application and answers its secret.
    async fn begin_application(&self, id: TransactionId) -> String {
        let options = self
            .begin(id, "authenticator_application")
            .await
            .expect("begin");
        assert_eq!(options["kind"], "authenticator_application");
        assert!(
            options["uri"]
                .as_str()
                .expect("uri")
                .starts_with("otpauth://totp/Acme:ana%40example.com?secret="),
            "{options}"
        );
        options["secret"].as_str().expect("secret").to_owned()
    }

    async fn finish_with(&self, id: TransactionId, code: &str) -> Result<SignIn, DomainError> {
        self.submit(id, enrollment_input(&[("code", code)])).await
    }

    async fn set_policy(&self, policy: SecondFactorPolicy) {
        let mut settings = self
            .tenants
            .get(&self.tenant)
            .await
            .expect("tenant")
            .snapshot()
            .settings
            .clone();
        settings.authentication.second_factor = policy;
        self.tenants
            .change_settings(&self.tenant, settings, Caller::system())
            .await
            .expect("settings");
    }

    async fn second_factors(&self) -> usize {
        self.factors
            .factors(&self.tenant, self.ana)
            .await
            .expect("factors")
            .second_factors()
    }

    fn events(&self, event_type: &str) -> Vec<serde_json::Value> {
        self.units_of_work
            .committed_events()
            .into_iter()
            .filter(|event| event.event_type == event_type)
            .map(|event| event.payload)
            .collect()
    }
}

#[tokio::test]
async fn a_person_without_a_factor_sets_up_an_application_and_signs_in_at_multi_factor() {
    let world = world().await;
    world.set_policy(SecondFactorPolicy::Required).await;

    let (id, answer) = world.after_password().await;
    assert_eq!(step_of(&answer), Some(ENROLLMENT), "{answer:?}");
    let described = world
        .service
        .describe(&world.tenant, id, &world.secret(id))
        .await
        .expect("describe");
    assert_eq!(step_of(&described), Some(ENROLLMENT));

    let secret = world.begin_application(id).await;
    let answer = world
        .finish_with(id, &world.phone(&secret))
        .await
        .expect("finish");
    let SignIn::Completed {
        session,
        recovery_codes,
        ..
    } = answer
    else {
        panic!("expected completion, got {answer:?}");
    };
    assert_eq!(session.snapshot().assurance, Assurance::MultiFactor);
    assert_eq!(session.snapshot().methods, ["password", "enrollment"]);
    assert_eq!(
        recovery_codes.len(),
        10,
        "a set comes with the first factor"
    );
    assert_eq!(world.second_factors().await, 1);

    assert_eq!(
        world.events("authentication.second_factor_enrolled"),
        [serde_json::json!({ "user_id": world.ana, "kind": "authenticator_application" })]
    );
    assert_eq!(world.events("credential.totp_enrolled").len(), 1);
    assert_eq!(world.events("authentication.succeeded").len(), 1);

    // The next sign-in asks for the application, and offers nothing to
    // enroll.
    world.clock.advance(Duration::seconds(STEP_SECONDS));
    let (next, answer) = world.after_password().await;
    assert_eq!(step_of(&answer), Some(TotpAuthenticator::KIND));
    let error = world
        .begin(next, "authenticator_application")
        .await
        .expect_err("not offered");
    assert_eq!(error.code(), "authentication.unexpected_step");
    let answer = world
        .submit(next, StepInput::Totp(Secret::from(world.phone(&secret))))
        .await
        .expect("code");
    let SignIn::Completed { session, .. } = answer else {
        panic!("expected completion, got {answer:?}");
    };
    assert_eq!(session.snapshot().methods, ["password", "totp"]);
}

#[tokio::test]
async fn with_the_policy_off_nobody_is_asked_to_enroll() {
    let world = world().await;
    let (id, answer) = world.after_password().await;
    assert!(matches!(answer, SignIn::Completed { .. }), "{answer:?}");
    let error = world
        .begin(id, "authenticator_application")
        .await
        .expect_err("ended");
    assert_eq!(error.code(), "authentication.transaction_not_active");
    assert_eq!(world.second_factors().await, 0);
}

#[tokio::test]
async fn a_person_who_has_a_factor_is_asked_for_it_and_never_offered_enrollment() {
    let world = world().await;
    world.set_policy(SecondFactorPolicy::Required).await;
    let enrollment = world
        .factors
        .begin_authenticator_application(&world.tenant, world.ana)
        .await
        .expect("begin");
    world
        .factors
        .confirm_authenticator_application(
            &world.tenant,
            world.ana,
            &Secret::from(world.phone(enrollment.secret())),
            Caller::system(),
        )
        .await
        .expect("confirm");
    world.clock.advance(Duration::seconds(STEP_SECONDS));

    let (id, answer) = world.after_password().await;
    assert_eq!(step_of(&answer), Some(TotpAuthenticator::KIND));
    for what in ["authenticator_application", "security_key", "passkey"] {
        let error = world.begin(id, what).await.expect_err("not offered");
        assert_eq!(error.code(), "authentication.unexpected_step");
    }
    let error = world
        .finish_with(id, &world.phone(enrollment.secret()))
        .await
        .expect_err("not the step");
    assert_eq!(error.code(), "authentication.unexpected_step");
    let answer = world
        .submit(
            id,
            StepInput::Totp(Secret::from(world.phone(enrollment.secret()))),
        )
        .await
        .expect("code");
    let SignIn::Completed { session, .. } = answer else {
        panic!("expected completion, got {answer:?}");
    };
    assert_eq!(session.snapshot().methods, ["password", "totp"]);
    assert!(
        world
            .events("authentication.second_factor_enrolled")
            .is_empty()
    );
}

#[tokio::test]
async fn enrolling_is_offered_only_after_the_first_factor() {
    let world = world().await;
    world.set_policy(SecondFactorPolicy::Required).await;
    let id = world.start().await;
    let refused = |error: DomainError| assert_eq!(error.code(), "authentication.unexpected_step");

    // Before anything, after the identifier, and after a wrong password.
    refused(
        world
            .begin(id, "authenticator_application")
            .await
            .expect_err("first step"),
    );
    refused(
        world
            .finish_with(id, "123456")
            .await
            .expect_err("first step"),
    );
    world
        .submit(id, StepInput::Identifier("ana@example.com".to_owned()))
        .await
        .expect("identifier");
    refused(
        world
            .begin(id, "security_key")
            .await
            .expect_err("password step"),
    );
    let answer = world
        .submit(id, StepInput::Password(Secret::from("wrong".to_owned())))
        .await
        .expect("wrong password");
    assert_eq!(step_of(&answer), Some("password"));
    refused(
        world
            .begin(id, "passkey")
            .await
            .expect_err("still the password"),
    );
    refused(
        world
            .finish_with(id, "123456")
            .await
            .expect_err("still the password"),
    );
    assert_eq!(world.second_factors().await, 0);

    // The right password reaches it.
    let answer = world
        .submit(id, StepInput::Password(Secret::from(PASSWORD.to_owned())))
        .await
        .expect("password");
    assert_eq!(step_of(&answer), Some(ENROLLMENT));
}

#[tokio::test]
async fn after_an_identity_provider_the_person_sets_up_a_factor_too() {
    let world = world().await;
    world.set_policy(SecondFactorPolicy::Required).await;
    let id = world.start().await;
    let answer = world
        .submit(
            id,
            StepInput::External(ExternalInput {
                step: "outside".to_owned(),
                fields: vec![("who".to_owned(), Secret::from("ana".to_owned()))],
            }),
        )
        .await
        .expect("outside");
    assert_eq!(step_of(&answer), Some(ENROLLMENT));
    let secret = world.begin_application(id).await;
    let answer = world
        .finish_with(id, &world.phone(&secret))
        .await
        .expect("finish");
    let SignIn::Completed { session, .. } = answer else {
        panic!("expected completion, got {answer:?}");
    };
    assert_eq!(session.snapshot().methods, ["outside", "enrollment"]);
    assert_eq!(session.snapshot().assurance, Assurance::MultiFactor);
}

#[tokio::test]
async fn a_mistyped_code_is_typed_again_without_a_new_secret() {
    let world = world().await;
    world.set_policy(SecondFactorPolicy::Required).await;
    let (id, _) = world.after_password().await;
    let secret = world.begin_application(id).await;
    for wrong in ["000000", "not a code", ""] {
        let answer = world.finish_with(id, wrong).await.expect("mistyped");
        assert!(
            matches!(answer, SignIn::Rejected { ref step, .. } if step == ENROLLMENT),
            "{answer:?}"
        );
    }
    assert_eq!(world.second_factors().await, 0);
    let answer = world
        .finish_with(id, &world.phone(&secret))
        .await
        .expect("finish");
    assert!(matches!(answer, SignIn::Completed { .. }), "{answer:?}");
}

#[tokio::test]
async fn the_sign_in_cannot_be_completed_by_skipping_or_abandoning_the_enrollment() {
    let world = world().await;
    world.set_policy(SecondFactorPolicy::Required).await;
    let (id, _) = world.after_password().await;

    // Nothing begun: even a code of nothing is a rejection.
    let answer = world
        .finish_with(id, "123456")
        .await
        .expect("nothing begun");
    assert!(matches!(answer, SignIn::Rejected { .. }), "{answer:?}");

    let secret = world.begin_application(id).await;
    // No other step stands in for it.
    for input in [
        StepInput::Password(Secret::from(PASSWORD.to_owned())),
        StepInput::Totp(Secret::from(world.phone(&secret))),
        StepInput::RecoveryCode(Secret::from("7K2M-QX9D-4HVN-R8TA".to_owned())),
        StepInput::Identifier("ana@example.com".to_owned()),
    ] {
        let error = world.submit(id, input).await.expect_err("not the step");
        assert_eq!(error.code(), "authentication.unexpected_step");
    }
    let error = world
        .submit(
            id,
            StepInput::External(ExternalInput {
                step: "outside".to_owned(),
                fields: vec![("who".to_owned(), Secret::from("ana".to_owned()))],
            }),
        )
        .await
        .expect_err("no alternative after the first step");
    assert_eq!(error.code(), "authentication.unexpected_step");

    // An empty answer is a rejection, and five of them end the sign-in.
    let mut last = None;
    for _ in 0..4 {
        last = Some(
            world
                .submit(id, enrollment_input(&[]))
                .await
                .expect("empty"),
        );
    }
    assert!(matches!(last, Some(SignIn::Failed)), "{last:?}");
    assert_eq!(world.second_factors().await, 0);
    assert!(world.events("authentication.succeeded").is_empty());

    // Abandoned while waiting at the step, nothing completes either.
    world.clock.advance(Duration::seconds(STEP_SECONDS));
    let (other, _) = world.after_password().await;
    let secret = world.begin_application(other).await;
    world
        .service
        .cancel(&world.tenant, other, &world.secret(other))
        .await
        .expect("cancel");
    let error = world
        .finish_with(other, &world.phone(&secret))
        .await
        .expect_err("abandoned");
    assert_eq!(error.code(), "authentication.transaction_not_active");
    assert_eq!(world.second_factors().await, 0);
    assert!(
        !world
            .totp
            .has_totp(&world.tenant, world.ana)
            .await
            .expect("has"),
        "the secret of an abandoned enrollment is never put in use"
    );
    assert!(world.events("authentication.succeeded").is_empty());
}

#[tokio::test]
async fn an_enrollment_begun_elsewhere_cannot_be_finished_here() {
    let world = world().await;
    world.set_policy(SecondFactorPolicy::Required).await;
    let (first, _) = world.after_password().await;
    let (second, _) = world.after_password().await;

    // The first sign-in begins; the second has begun nothing, so a code of
    // the first's secret finishes nothing there.
    let first_secret = world.begin_application(first).await;
    let answer = world
        .finish_with(second, &world.phone(&first_secret))
        .await
        .expect("begun elsewhere");
    assert!(matches!(answer, SignIn::Rejected { .. }), "{answer:?}");

    // The second begins its own, which replaces the first's: the first
    // can finish neither.
    let second_secret = world.begin_application(second).await;
    for code in [world.phone(&first_secret), world.phone(&second_secret)] {
        let answer = world.finish_with(first, &code).await.expect("replaced");
        assert!(matches!(answer, SignIn::Rejected { .. }), "{answer:?}");
    }

    // An enrollment begun on the security page meanwhile replaces the
    // second's as well.
    let page = world
        .factors
        .begin_authenticator_application(&world.tenant, world.ana)
        .await
        .expect("security page");
    for code in [world.phone(&second_secret), world.phone(page.secret())] {
        let answer = world.finish_with(second, &code).await.expect("replaced");
        assert!(matches!(answer, SignIn::Rejected { .. }), "{answer:?}");
    }
    assert_eq!(world.second_factors().await, 0);

    // Beginning again in the sign-in is what finishes it.
    let again = world.begin_application(second).await;
    let answer = world
        .finish_with(second, &world.phone(&again))
        .await
        .expect("finish");
    assert!(matches!(answer, SignIn::Completed { .. }), "{answer:?}");
}

#[tokio::test]
async fn a_finished_enrollment_cannot_be_replayed() {
    let world = world().await;
    world.set_policy(SecondFactorPolicy::Required).await;
    let (id, _) = world.after_password().await;
    let secret = world.begin_application(id).await;
    let code = world.phone(&secret);
    let answer = world.finish_with(id, &code).await.expect("finish");
    assert!(matches!(answer, SignIn::Completed { .. }), "{answer:?}");
    let error = world.finish_with(id, &code).await.expect_err("replayed");
    assert_eq!(error.code(), "authentication.transaction_not_active");
    let error = world
        .begin(id, "authenticator_application")
        .await
        .expect_err("ended");
    assert_eq!(error.code(), "authentication.transaction_not_active");
    assert_eq!(world.events("authentication.succeeded").len(), 1);
    assert_eq!(
        world.events("authentication.second_factor_enrolled").len(),
        1
    );
}

#[tokio::test]
async fn a_factor_put_in_use_meanwhile_ends_the_offer() {
    let world = world().await;
    world.set_policy(SecondFactorPolicy::Required).await;
    let (slow, _) = world.after_password().await;
    let begun_slowly = world.begin_application(slow).await;
    let (quick, _) = world.after_password().await;
    let secret = world.begin_application(quick).await;
    let answer = world
        .finish_with(quick, &world.phone(&secret))
        .await
        .expect("finish");
    assert!(matches!(answer, SignIn::Completed { .. }), "{answer:?}");

    // The slow sign-in neither finishes what it began nor begins anew: the
    // person is to be asked for the factor they have now.
    let error = world
        .finish_with(slow, &world.phone(&begun_slowly))
        .await
        .expect_err("not needed");
    assert_eq!(error.code(), "authentication.enrollment_not_needed");
    for what in ["authenticator_application", "security_key", "passkey"] {
        let error = world.begin(slow, what).await.expect_err("not needed");
        assert_eq!(error.code(), "authentication.enrollment_not_needed");
    }
    assert_eq!(world.second_factors().await, 1);
    assert_eq!(world.events("authentication.succeeded").len(), 1);
}

#[tokio::test]
async fn a_person_who_may_no_longer_sign_in_puts_nothing_in_use() {
    let world = world().await;
    world.set_policy(SecondFactorPolicy::Required).await;
    let (id, _) = world.after_password().await;
    let secret = world.begin_application(id).await;
    world
        .identity
        .suspend(
            &world.tenant,
            world.ana,
            "left the company",
            Caller::system(),
        )
        .await
        .expect("suspend");
    let answer = world
        .finish_with(id, &world.phone(&secret))
        .await
        .expect("suspended");
    assert!(matches!(answer, SignIn::Rejected { .. }), "{answer:?}");
    assert_eq!(world.second_factors().await, 0);
}

#[tokio::test]
async fn a_security_key_is_begun_with_options_for_the_browser_and_a_bad_answer_is_a_rejection() {
    let world = world().await;
    world.set_policy(SecondFactorPolicy::Required).await;
    let (id, _) = world.after_password().await;
    for (what, resident_key) in [("security_key", "preferred"), ("passkey", "required")] {
        let options = world.begin(id, what).await.expect("begin");
        assert_eq!(options["kind"], what);
        assert_eq!(options["public_key"]["user"]["name"], "ana@example.com");
        assert_eq!(
            options["public_key"]["authenticatorSelection"]["residentKey"], resident_key,
            "{options}"
        );
        assert!(
            options.get("registration_id").is_none(),
            "the sign-in keeps which registration it began"
        );
    }
    // A code where a key's answer is due, an answer that is not one, and
    // an answer that fails the checks of a registration.
    for fields in [
        vec![("code", "123456")],
        vec![("client_data", "not base64url!")],
        vec![("client_data", "e30"), ("attestation_object", "oA")],
        vec![("client_data", "e30"), ("attestation_object", "oA")],
    ] {
        let answer = world
            .submit(id, enrollment_input(&fields))
            .await
            .expect("answer");
        assert!(matches!(answer, SignIn::Rejected { .. }), "{answer:?}");
    }
    assert_eq!(world.second_factors().await, 0);
}

#[tokio::test]
async fn an_unknown_kind_begins_nothing() {
    let world = world().await;
    world.set_policy(SecondFactorPolicy::Required).await;
    let (id, _) = world.after_password().await;
    for what in ["sms", "totp", ""] {
        let error = world.begin(id, what).await.expect_err("unknown");
        assert_eq!(error.code(), "authentication.enrollment_kind_unknown");
    }
}

#[tokio::test]
async fn an_installation_that_keeps_no_secrets_offers_keys_only() {
    let world = world().await;
    assert_eq!(
        world.factors.enrollable().len(),
        3,
        "an application, a security key and a passkey"
    );
    let without = FactorService::new(
        world.identity.clone(),
        world.tenants.clone(),
        WebAuthnService::new(
            Arc::new(world.units_of_work.clone()),
            Arc::new(InMemoryWebAuthn::default()),
            RelyingParty::from_public_address("https://id.example.com").expect("relying party"),
            Arc::new(FakeDigest),
            Arc::new(RefusingVerifier),
            Arc::new(CountingRandom::default()),
            world.clock.clone(),
        ),
        RecoveryCodeService::new(
            Arc::new(world.units_of_work.clone()),
            Arc::new(InMemoryRecoveryCodes::default()),
            Arc::new(FakeDigest),
            Arc::new(CountingRandom::default()),
            world.clock.clone(),
        ),
    );
    let kinds: Vec<&str> = without
        .enrollable()
        .into_iter()
        .map(|kind| kind.as_str())
        .collect();
    assert_eq!(kinds, ["security_key", "passkey"]);
}

#[tokio::test]
async fn a_step_up_never_offers_enrollment() {
    let world = world().await;
    let (_, answer) = world.after_password().await;
    let SignIn::Completed { session, .. } = answer else {
        panic!("expected completion, got {answer:?}");
    };
    // An application asks a person who has no factor for multi-factor:
    // nothing they can be asked for reaches it, and enrolling is not
    // offered in a step-up.
    let started = world
        .service
        .start_step_up(
            &world.tenant,
            ClientInfo::default(),
            StepUpRequest {
                session_id: session.id(),
                user_id: world.ana,
                carried: vec!["password".to_owned()],
                demanded: Some(Assurance::MultiFactor),
            },
        )
        .await
        .expect("step-up");
    assert!(matches!(started, StepUp::Unreachable), "{started:?}");

    // Nor under the policy.
    world.set_policy(SecondFactorPolicy::Required).await;
    let started = world
        .service
        .start_step_up(
            &world.tenant,
            ClientInfo::default(),
            StepUpRequest {
                session_id: session.id(),
                user_id: world.ana,
                carried: vec!["password".to_owned()],
                demanded: None,
            },
        )
        .await
        .expect("step-up");
    assert!(matches!(started, StepUp::Unreachable), "{started:?}");
    assert_eq!(world.second_factors().await, 0);
}
