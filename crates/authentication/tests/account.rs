//! Registration and password recovery through the use cases, over the
//! real contexts running on their in-memory ports.

use hodor_authentication::api::{AccountRequest, AccountService, AttemptGuard, LockoutRules};
use hodor_authentication::testing::{
    InMemoryAttempts, InMemoryVerificationTokens, VerificationTokenPorts,
    run_verification_token_contract,
};
use hodor_credential::api::{CredentialService, PasswordCheck};
use hodor_credential::testing::{FakeHasher, InMemoryPasswords};
use hodor_identity::api::{IdentityService, User, UserStatus};
use hodor_identity::testing::InMemoryUsers;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{
    Caller, Digest, DomainError, ErrorKind, Secret, TenantContext, Timestamp, UserId,
};
use hodor_notification::api::{Message, Notifier, Template};
use hodor_notification::testing::InMemoryMessages;
use hodor_session::api::{Assurance, ClientInfo, SessionService, SessionTimeouts, StartSession};
use hodor_session::testing::{InMemorySessions, SequentialRandom};
use hodor_tenant::api::{CreateTenant, TenantService};
use hodor_tenant::testing::InMemoryTenants;
use std::sync::Arc;
use time::Duration;

const PASSWORD: &str = "correct horse battery staple";
const NEW_PASSWORD: &str = "a different long passphrase";

struct World {
    accounts: AccountService,
    identity: IdentityService,
    credentials: CredentialService,
    sessions: SessionService,
    guard: AttemptGuard,
    messages: InMemoryMessages,
    clock: Arc<FixedClock>,
    units_of_work: InMemoryUnitOfWorkFactory,
    /// A tenant that accepts registrations.
    open: TenantContext,
    /// A tenant that does not.
    closed: TenantContext,
}

async fn world() -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
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
    let messages = InMemoryMessages::default();
    let accounts = AccountService::new(
        factory(),
        Arc::new(InMemoryVerificationTokens::default()),
        identity.clone(),
        credentials.clone(),
        sessions.clone(),
        tenants.clone(),
        Notifier::new(Arc::new(messages.clone()), clock.clone()),
        guard.clone(),
        digest,
        Arc::new(SequentialRandom::default()),
        clock.clone(),
        "https://login.example.com/",
    );

    let mut created = Vec::new();
    for (slug, name, open_registration) in [("acme", "Acme", true), ("closed", "Closed", false)] {
        let tenant = tenants
            .create(
                CreateTenant {
                    slug: slug.to_owned(),
                    display_name: name.to_owned(),
                    open_registration,
                    system: false,
                },
                Caller::system(),
            )
            .await
            .expect("tenant");
        created.push(TenantContext::assume(tenant.id()));
    }

    World {
        accounts,
        identity,
        credentials,
        sessions,
        guard,
        messages,
        clock,
        units_of_work,
        closed: created.remove(1),
        open: created.remove(0),
    }
}

fn request(email: &str) -> AccountRequest<'_> {
    AccountRequest {
        email,
        locale: Some("pt-BR"),
        address: Some("203.0.113.1"),
    }
}

fn secret(value: &str) -> Secret<String> {
    Secret::from(value.to_owned())
}

/// The token a message's link carries, as the page would read it.
fn token_in(message: &Message) -> String {
    let link = &message.snapshot().variables["link"];
    link.split_once("#token=")
        .expect("a link with a token")
        .1
        .to_owned()
}

impl World {
    fn messages(&self) -> Vec<Message> {
        self.messages.of_tenant(self.open.tenant_id())
    }

    fn last_message(&self) -> Message {
        self.messages().pop().expect("a message was queued")
    }

    async fn ask_to_register(&self, email: &str) -> Result<(), DomainError> {
        self.accounts
            .request_registration(&self.open, request(email), Caller::system())
            .await
    }

    async fn finish_registration(
        &self,
        token: &str,
        password: &str,
    ) -> Result<UserId, DomainError> {
        self.accounts
            .complete_registration(
                &self.open,
                token,
                &secret(password),
                Some("Ana".to_owned()),
                Caller::system(),
            )
            .await
    }

    /// Registers a person from asking to finishing.
    async fn register(&self, email: &str) -> UserId {
        self.ask_to_register(email).await.expect("asked");
        self.finish_registration(&token_in(&self.last_message()), PASSWORD)
            .await
            .expect("registered")
    }

    async fn ask_to_recover(&self, email: &str) -> Result<(), DomainError> {
        self.accounts
            .request_recovery(&self.open, request(email), Caller::system())
            .await
    }

    async fn reset(&self, token: &str, password: &str) -> Result<UserId, DomainError> {
        self.accounts
            .reset_password(&self.open, token, &secret(password), Caller::system())
            .await
    }

    async fn user(&self, email: &str) -> Option<User> {
        self.identity
            .find_by_login(&self.open, email)
            .await
            .expect("find")
    }

    async fn verifies(&self, user: UserId, password: &str) -> bool {
        let check = self
            .credentials
            .verify_password(&self.open, Some(user), &secret(password))
            .await
            .expect("verify");
        matches!(check, PasswordCheck::Verified { .. })
    }

    fn announced(&self) -> Vec<String> {
        self.units_of_work.committed_event_types()
    }
}

fn invalid_token(result: Result<UserId, DomainError>) {
    let error = result.expect_err("refused");
    assert_eq!(error.kind(), ErrorKind::NotFound);
    assert_eq!(error.code(), "authentication.verification_token_invalid");
}

#[tokio::test]
async fn the_in_memory_token_store_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let tokens = InMemoryVerificationTokens::default();
    run_verification_token_contract(VerificationTokenPorts {
        units_of_work: &units_of_work,
        tokens: &tokens,
    })
    .await;
}

#[tokio::test]
async fn asking_to_register_sends_a_link_and_creates_nobody() {
    let world = world().await;

    world
        .ask_to_register("Ana@Example.com")
        .await
        .expect("asked");

    assert!(world.user("ana@example.com").await.is_none());
    let messages = world.messages();
    assert_eq!(messages.len(), 1);
    let message = messages[0].snapshot();
    assert_eq!(message.template, Template::EmailVerification);
    assert_eq!(message.locale.as_str(), "pt-BR");
    assert_eq!(message.variables["tenant_name"], "Acme");
    assert_eq!(message.variables["expires_at"], "1970-01-02 00:00 UTC");
    assert_eq!(
        message.expires_at,
        Timestamp::UNIX_EPOCH + Duration::hours(24)
    );
    let link = &message.variables["link"];
    let (page, token) = link.split_once("#token=").expect("token in the fragment");
    assert_eq!(
        page,
        "https://login.example.com/t/acme/account/complete-registration"
    );
    assert_eq!(token.len(), 64);
    // Asking announces nothing: no event could say anything without
    // saying whether the address has an account.
    assert!(
        !world
            .announced()
            .iter()
            .any(|event| event.starts_with("authentication."))
    );
}

#[tokio::test]
async fn finishing_creates_an_active_user_with_a_verified_address_and_the_chosen_password() {
    let world = world().await;
    world
        .ask_to_register("ana@example.com")
        .await
        .expect("asked");
    let token = token_in(&world.last_message());

    let user_id = world
        .finish_registration(&token, PASSWORD)
        .await
        .expect("registered");

    let user = world.user("ana@example.com").await.expect("exists");
    assert_eq!(user.id(), user_id);
    assert_eq!(user.status(), UserStatus::Active);
    assert!(user.identifiers()[0].verified_at.is_some());
    assert_eq!(user.snapshot().profile.display_name.as_deref(), Some("Ana"));
    assert_eq!(user.snapshot().profile.locale.as_deref(), Some("pt-BR"));
    assert!(world.verifies(user_id, PASSWORD).await);
    assert!(
        world
            .announced()
            .contains(&"authentication.registration_completed".to_owned())
    );

    // The link works once.
    invalid_token(world.finish_registration(&token, PASSWORD).await);
}

#[tokio::test]
async fn asking_for_an_address_that_has_an_account_answers_the_same_and_only_tells_the_owner() {
    let world = world().await;
    let user = world.register("ana@example.com").await;
    let before = world.messages().len();

    world
        .ask_to_register("ana@example.com")
        .await
        .expect("the same answer");

    let messages = world.messages();
    assert_eq!(messages.len(), before + 1);
    let message = world.last_message();
    assert_eq!(message.snapshot().template, Template::AlreadyRegistered);
    assert_eq!(message.snapshot().recipient, "ana@example.com");
    assert!(!message.snapshot().variables.contains_key("link"));
    // Nothing about the account changed.
    assert!(world.verifies(user, PASSWORD).await);
}

#[tokio::test]
async fn asking_with_something_that_is_not_an_address_answers_the_same_and_sends_nothing() {
    let world = world().await;

    world
        .ask_to_register("not an address")
        .await
        .expect("the same answer");
    world
        .ask_to_recover("not an address")
        .await
        .expect("the same answer");

    assert!(world.messages().is_empty());
}

#[tokio::test]
async fn a_tenant_that_does_not_accept_registrations_refuses_and_says_so() {
    let world = world().await;

    let error = world
        .accounts
        .request_registration(&world.closed, request("ana@example.com"), Caller::system())
        .await
        .expect_err("refused");

    assert_eq!(error.kind(), ErrorKind::Forbidden);
    assert_eq!(error.code(), "authentication.registration_closed");
    assert!(
        world
            .messages
            .of_tenant(world.closed.tenant_id())
            .is_empty()
    );
}

#[tokio::test]
async fn a_password_that_is_not_acceptable_is_refused_and_the_link_stays_good() {
    let world = world().await;
    world
        .ask_to_register("ana@example.com")
        .await
        .expect("asked");
    let token = token_in(&world.last_message());

    for unacceptable in ["short", "ana@example.com"] {
        let error = world
            .finish_registration(&token, unacceptable)
            .await
            .expect_err("refused");
        assert_eq!(error.kind(), ErrorKind::Invalid, "{unacceptable}");
    }
    assert!(world.user("ana@example.com").await.is_none());

    world
        .finish_registration(&token, PASSWORD)
        .await
        .expect("the same link still works");
}

#[tokio::test]
async fn asking_again_makes_the_earlier_link_stop_working() {
    let world = world().await;
    world
        .ask_to_register("ana@example.com")
        .await
        .expect("asked");
    let first = token_in(&world.last_message());
    world
        .ask_to_register("ana@example.com")
        .await
        .expect("asked again");
    let second = token_in(&world.last_message());
    assert_ne!(first, second);

    invalid_token(world.finish_registration(&first, PASSWORD).await);
    world
        .finish_registration(&second, PASSWORD)
        .await
        .expect("the newest link works");
}

#[tokio::test]
async fn a_link_stops_working_when_it_expires() {
    let world = world().await;
    world
        .ask_to_register("ana@example.com")
        .await
        .expect("asked");
    let registration = token_in(&world.last_message());
    world.clock.advance(Duration::hours(24));
    invalid_token(world.finish_registration(&registration, PASSWORD).await);

    let user = world.register("bia@example.com").await;
    world
        .ask_to_recover("bia@example.com")
        .await
        .expect("asked");
    let recovery = token_in(&world.last_message());
    world.clock.advance(Duration::hours(1));
    invalid_token(world.reset(&recovery, NEW_PASSWORD).await);
    assert!(world.verifies(user, PASSWORD).await);
}

#[tokio::test]
async fn a_token_works_only_for_what_it_was_made_for() {
    let world = world().await;
    world.register("ana@example.com").await;
    world
        .ask_to_recover("ana@example.com")
        .await
        .expect("asked");
    let recovery = token_in(&world.last_message());
    world
        .ask_to_register("bia@example.com")
        .await
        .expect("asked");
    let registration = token_in(&world.last_message());

    invalid_token(world.finish_registration(&recovery, PASSWORD).await);
    invalid_token(world.reset(&registration, NEW_PASSWORD).await);
    for malformed in ["", "abc", &"z".repeat(64)] {
        invalid_token(world.reset(malformed, NEW_PASSWORD).await);
        invalid_token(world.finish_registration(malformed, PASSWORD).await);
    }
}

#[tokio::test]
async fn an_address_that_acquired_an_account_in_the_meantime_cannot_be_registered_again() {
    let world = world().await;
    world
        .ask_to_register("ana@example.com")
        .await
        .expect("asked");
    let token = token_in(&world.last_message());
    // Someone creates the account another way before the link is used.
    world
        .identity
        .create(
            &world.open,
            hodor_identity::api::CreateUser {
                kind: hodor_identity::api::UserKind::Human,
                identifiers: vec![(
                    hodor_identity::api::IdentifierKind::Email,
                    "ana@example.com".to_owned(),
                )],
                profile: hodor_identity::api::Profile::default(),
                confirmed: true,
            },
            Caller::system(),
        )
        .await
        .expect("created");

    invalid_token(world.finish_registration(&token, PASSWORD).await);
}

#[tokio::test]
async fn asking_to_recover_sends_a_link_only_to_a_user_who_may_sign_in() {
    let world = world().await;
    let ana = world.register("ana@example.com").await;
    let bia = world.register("bia@example.com").await;
    world
        .identity
        .suspend(&world.open, bia, "left the company", Caller::system())
        .await
        .expect("suspended");
    let before = world.messages().len();

    // The answer is the same for all three.
    world
        .ask_to_recover("ana@example.com")
        .await
        .expect("asked");
    world
        .ask_to_recover("bia@example.com")
        .await
        .expect("asked");
    world
        .ask_to_recover("nobody@example.com")
        .await
        .expect("asked");

    let sent = world.messages().split_off(before);
    assert_eq!(sent.len(), 1);
    let message = sent[0].snapshot();
    assert_eq!(message.template, Template::PasswordRecovery);
    assert_eq!(message.recipient, "ana@example.com");
    assert_eq!(
        message.expires_at,
        Timestamp::UNIX_EPOCH + Duration::hours(1)
    );
    assert!(
        message.variables["link"]
            .starts_with("https://login.example.com/t/acme/account/reset-password#token=")
    );
    assert!(world.verifies(ana, PASSWORD).await);
    let requested = world
        .announced()
        .iter()
        .filter(|event| *event == "authentication.recovery_requested")
        .count();
    assert_eq!(requested, 1);
}

#[tokio::test]
async fn resetting_sets_the_password_ends_every_session_and_tells_the_owner() {
    let world = world().await;
    let ana = world.register("ana@example.com").await;
    let (_, session_token) = world
        .sessions
        .start(
            &world.open,
            StartSession {
                user_id: ana,
                assurance: Assurance::SingleFactor,
                methods: vec!["password".to_owned()],
                timeouts: SessionTimeouts {
                    idle: Duration::minutes(30),
                    absolute: Duration::hours(12),
                },
                client: ClientInfo {
                    address: None,
                    description: None,
                },
            },
            Caller::system(),
        )
        .await
        .expect("session");
    world
        .ask_to_recover("ana@example.com")
        .await
        .expect("asked");
    let token = token_in(&world.last_message());

    let user = world.reset(&token, NEW_PASSWORD).await.expect("reset");

    assert_eq!(user, ana);
    assert!(world.verifies(ana, NEW_PASSWORD).await);
    assert!(!world.verifies(ana, PASSWORD).await);
    let session = world
        .sessions
        .find_by_token(&world.open, session_token.expose())
        .await
        .expect("find");
    assert!(session.is_none(), "the session should have been ended");
    let notice = world.last_message();
    assert_eq!(notice.snapshot().template, Template::PasswordChanged);
    assert_eq!(notice.snapshot().recipient, "ana@example.com");
    assert!(
        world
            .announced()
            .contains(&"authentication.password_reset".to_owned())
    );

    // The link works once.
    invalid_token(world.reset(&token, "yet another long passphrase").await);
    assert!(world.verifies(ana, NEW_PASSWORD).await);
}

#[tokio::test]
async fn a_new_password_that_is_not_acceptable_is_refused_and_the_link_stays_good() {
    let world = world().await;
    let ana = world.register("ana@example.com").await;
    world
        .ask_to_recover("ana@example.com")
        .await
        .expect("asked");
    let token = token_in(&world.last_message());

    // Too short, the person's own address, and the password they have now.
    for unacceptable in ["short", "ana@example.com", PASSWORD] {
        let error = world
            .reset(&token, unacceptable)
            .await
            .expect_err("refused");
        assert_eq!(error.kind(), ErrorKind::Invalid, "{unacceptable}");
    }
    assert!(world.verifies(ana, PASSWORD).await);

    world
        .reset(&token, NEW_PASSWORD)
        .await
        .expect("the same link still works");
}

#[tokio::test]
async fn a_user_who_may_no_longer_sign_in_cannot_finish_a_recovery() {
    let world = world().await;
    let ana = world.register("ana@example.com").await;
    world
        .ask_to_recover("ana@example.com")
        .await
        .expect("asked");
    let token = token_in(&world.last_message());
    world
        .identity
        .suspend(&world.open, ana, "left the company", Caller::system())
        .await
        .expect("suspended");

    invalid_token(world.reset(&token, NEW_PASSWORD).await);
    assert!(world.verifies(ana, PASSWORD).await);
}

#[tokio::test]
async fn asking_is_limited_per_address_asked_about_and_the_limit_reveals_nothing() {
    let world = world().await;
    world.register("ana@example.com").await;

    // The default policy allows five in the window, for an address with
    // an account and for one without alike.
    for email in ["ana@example.com", "nobody@example.com"] {
        let before = world.messages().len();
        for _ in 0..5 {
            world.ask_to_recover(email).await.expect("admitted");
        }
        let error = world.ask_to_recover(email).await.expect_err("limited");
        assert_eq!(error.kind(), ErrorKind::RateLimited, "{email}");
        assert_eq!(error.code(), "authentication.too_many_attempts");
        assert!(error.retry_after_seconds().is_some());
        let sent = world.messages().len() - before;
        assert!(sent <= 5, "{email}: {sent} messages");
    }

    // Recovery and registration are counted apart.
    world
        .ask_to_register("nobody@example.com")
        .await
        .expect("registration has its own count");
}

#[tokio::test]
async fn resetting_clears_a_sign_in_lockout_on_the_address() {
    let world = world().await;
    world.register("ana@example.com").await;
    let rules = LockoutRules {
        max_failures: 3,
        window: Duration::minutes(15),
        first_lockout: Duration::minutes(10),
        longest_lockout: Duration::hours(1),
    };
    // The key the identifier step of a sign-in counts by.
    let key = FakeDigest.sha256(b"email:ana@example.com");
    let admit = || {
        world
            .guard
            .admit(&world.open, &rules, key, None, Caller::system())
    };
    for _ in 0..3 {
        admit().await.expect("admitted");
    }
    assert!(admit().await.is_err(), "locked out");

    world
        .ask_to_recover("ana@example.com")
        .await
        .expect("asked");
    world
        .reset(&token_in(&world.last_message()), NEW_PASSWORD)
        .await
        .expect("reset");

    admit().await.expect("the lockout is gone");
}

#[tokio::test]
async fn nothing_announced_contains_an_address_a_token_or_a_password() {
    let world = world().await;
    world
        .ask_to_register("ana@example.com")
        .await
        .expect("asked");
    let registration = token_in(&world.last_message());
    world
        .finish_registration(&registration, PASSWORD)
        .await
        .expect("registered");
    world
        .ask_to_recover("ana@example.com")
        .await
        .expect("asked");
    let recovery = token_in(&world.last_message());
    world.reset(&recovery, NEW_PASSWORD).await.expect("reset");

    let announced: Vec<_> = world
        .units_of_work
        .committed_events()
        .into_iter()
        .filter(|event| event.event_type.starts_with("authentication."))
        .map(|event| event.payload.to_string())
        .collect();
    assert_eq!(announced.len(), 3);
    let announced = announced.join("\n");
    for secret in [
        "ana@example.com",
        &registration,
        &recovery,
        PASSWORD,
        NEW_PASSWORD,
    ] {
        assert!(!announced.contains(secret), "{announced}");
    }
}

#[tokio::test]
async fn finishing_clears_the_count_of_how_often_the_address_was_asked_about() {
    let world = world().await;
    world.register("ana@example.com").await;
    for _ in 0..5 {
        world
            .ask_to_recover("ana@example.com")
            .await
            .expect("admitted");
    }
    assert!(world.ask_to_recover("ana@example.com").await.is_err());

    // The newest link still works, and using it clears the count.
    world
        .reset(&token_in(&world.last_message()), NEW_PASSWORD)
        .await
        .expect("reset");

    world
        .ask_to_recover("ana@example.com")
        .await
        .expect("counted from nothing again");
}
