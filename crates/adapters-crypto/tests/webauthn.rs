//! WebAuthn registration and challenges with real keys and real signatures:
//! the use cases of the credential context, the in-memory store, and the
//! verifier and digest of this crate.

use hodor_adapters_crypto::testing::webauthn::SoftwareAuthenticator;
use hodor_adapters_crypto::{AwsLcVerifier, OsRandom, Sha256Digest};
use hodor_credential::api::{
    AssertionResponse, Challenge, RegistrationResponse, RelyingParty, WebAuthnRegistrationId,
    WebAuthnService,
};
use hodor_credential::testing::{InMemoryWebAuthn, WebAuthnPorts, run_webauthn_contract};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, TenantContext, TenantId, Timestamp, UserId};
use serde_json::Value;
use std::sync::Arc;
use time::Duration;

const ORIGIN: &str = "https://id.example.com";

struct Fixture {
    service: WebAuthnService,
    units_of_work: InMemoryUnitOfWorkFactory,
    clock: Arc<FixedClock>,
}

fn fixture() -> Fixture {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let service = WebAuthnService::new(
        Arc::new(units_of_work.clone()),
        Arc::new(InMemoryWebAuthn::default()),
        RelyingParty::from_public_address(ORIGIN).expect("valid"),
        Arc::new(Sha256Digest),
        Arc::new(AwsLcVerifier),
        Arc::new(OsRandom),
        clock.clone(),
    );
    Fixture {
        service,
        units_of_work,
        clock,
    }
}

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

fn decode(value: &Value) -> Vec<u8> {
    use base64::Engine as _;
    base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(value.as_str().expect("text"))
        .expect("base64url")
}

fn registration_response(body: &Value) -> RegistrationResponse {
    RegistrationResponse {
        client_data: decode(&body["client_data"]),
        attestation_object: decode(&body["attestation_object"]),
        transports: vec!["usb".to_owned()],
        discoverable: Some(false),
        name: Some("Software key".to_owned()),
    }
}

fn assertion(body: &Value) -> AssertionResponse {
    AssertionResponse::from_base64url(
        body["credential_id"].as_str().expect("text"),
        body["client_data"].as_str().expect("text"),
        body["authenticator_data"].as_str().expect("text"),
        body["signature"].as_str().expect("text"),
        body["user_handle"].as_str(),
    )
    .expect("base64url")
}

async fn register(
    fixture: &Fixture,
    tenant: &TenantContext,
    user: UserId,
    authenticator: &SoftwareAuthenticator,
) {
    let begun = fixture
        .service
        .begin_registration(tenant, user, "ana@example.com", "Ana")
        .await
        .expect("begin");
    let options = serde_json::to_value(&begun.options).expect("json");
    fixture
        .service
        .finish_registration(
            tenant,
            user,
            begun.id,
            registration_response(&authenticator.register(&options)),
            Caller::system(),
        )
        .await
        .expect("registered");
}

async fn answer(
    fixture: &Fixture,
    tenant: &TenantContext,
    user: UserId,
    authenticator: &SoftwareAuthenticator,
) -> bool {
    let challenge = fixture
        .service
        .challenge(tenant, user)
        .await
        .expect("challenge");
    let options = serde_json::to_value(&challenge.options).expect("json");
    fixture
        .service
        .verify(
            tenant,
            user,
            &challenge.challenge,
            &assertion(&authenticator.answer(&options)),
        )
        .await
        .expect("verify")
}

#[tokio::test]
async fn a_registered_key_answers_its_challenges() {
    let fixture = fixture();
    let tenant = tenant();
    let user = UserId::generate();
    let key = SoftwareAuthenticator::new(ORIGIN);
    assert!(
        !fixture
            .service
            .has_credentials(&tenant, user)
            .await
            .expect("has")
    );
    register(&fixture, &tenant, user, &key).await;
    assert!(
        fixture
            .service
            .has_credentials(&tenant, user)
            .await
            .expect("has")
    );
    assert_eq!(
        fixture.units_of_work.committed_event_types(),
        vec!["credential.webauthn_registered"]
    );

    for _ in 0..3 {
        assert!(answer(&fixture, &tenant, user, &key).await);
    }
    let stored = &fixture.service.list(&tenant, user).await.expect("list")[0];
    assert_eq!(stored.snapshot().sign_count, 3);
    assert!(stored.snapshot().last_used_at.is_some());
    assert_eq!(stored.snapshot().name, "Software key");
}

#[tokio::test]
async fn an_answer_to_another_challenge_or_by_another_key_is_refused() {
    let fixture = fixture();
    let tenant = tenant();
    let user = UserId::generate();
    let key = SoftwareAuthenticator::new(ORIGIN);
    register(&fixture, &tenant, user, &key).await;

    // An answer to a challenge Hodor did not make for this check.
    let challenge = fixture
        .service
        .challenge(&tenant, user)
        .await
        .expect("challenge");
    let options = serde_json::to_value(&challenge.options).expect("json");
    let answered = assertion(&key.answer(&options));
    assert!(
        !fixture
            .service
            .verify(&tenant, user, &Challenge([0; 32]), &answered)
            .await
            .expect("verify")
    );

    // A key that was never registered.
    let stranger = SoftwareAuthenticator::new(ORIGIN);
    assert!(!answer(&fixture, &tenant, user, &stranger).await);

    // The registered key, used by a page of another site.
    let phished = key.at_origin("https://id.example.com.evil.example.net");
    assert!(!answer(&fixture, &tenant, user, &phished).await);
    // The key itself still works.
    assert!(answer(&fixture, &tenant, user, &key).await);
}

#[tokio::test]
async fn a_key_registered_by_another_site_is_refused() {
    let fixture = fixture();
    let tenant = tenant();
    let user = UserId::generate();
    let begun = fixture
        .service
        .begin_registration(&tenant, user, "ana@example.com", "Ana")
        .await
        .expect("begin");
    let options = serde_json::to_value(&begun.options).expect("json");
    let elsewhere = SoftwareAuthenticator::new("https://evil.example.net");
    let error = fixture
        .service
        .finish_registration(
            &tenant,
            user,
            begun.id,
            registration_response(&elsewhere.register(&options)),
            Caller::system(),
        )
        .await
        .expect_err("refused");
    assert_eq!(error.code(), "credential.webauthn_registration_refused");
    assert!(
        !fixture
            .service
            .has_credentials(&tenant, user)
            .await
            .expect("has")
    );
}

#[tokio::test]
async fn a_copied_key_is_caught_by_its_counter() {
    let fixture = fixture();
    let tenant = tenant();
    let user = UserId::generate();
    let key = SoftwareAuthenticator::new(ORIGIN);
    register(&fixture, &tenant, user, &key).await;
    assert!(answer(&fixture, &tenant, user, &key).await);
    assert!(answer(&fixture, &tenant, user, &key).await);

    // A copy made earlier still counts from where the original was then.
    key.set_counter(1);
    assert!(!answer(&fixture, &tenant, user, &key).await);
    assert!(
        fixture
            .units_of_work
            .committed_event_types()
            .contains(&"credential.webauthn_counter_not_increased".to_owned())
    );
}

#[tokio::test]
async fn a_registration_is_finished_once_by_whoever_asked_within_five_minutes() {
    let fixture = fixture();
    let tenant = tenant();
    let user = UserId::generate();
    let key = SoftwareAuthenticator::new(ORIGIN);
    let finish = |id: WebAuthnRegistrationId, who: UserId, body: Value| {
        let fixture = &fixture;
        let tenant = tenant.clone();
        async move {
            fixture
                .service
                .finish_registration(
                    &tenant,
                    who,
                    id,
                    registration_response(&body),
                    Caller::system(),
                )
                .await
        }
    };

    let begun = fixture
        .service
        .begin_registration(&tenant, user, "ana@example.com", "Ana")
        .await
        .expect("begin");
    let body = key.register(&serde_json::to_value(&begun.options).expect("json"));
    // Another person cannot finish it, and trying uses it up.
    let error = finish(begun.id, UserId::generate(), body.clone())
        .await
        .expect_err("another user");
    assert_eq!(error.code(), "credential.webauthn_registration_not_found");
    let error = finish(begun.id, user, body).await.expect_err("used up");
    assert_eq!(error.code(), "credential.webauthn_registration_not_found");

    let begun = fixture
        .service
        .begin_registration(&tenant, user, "ana@example.com", "Ana")
        .await
        .expect("begin");
    let body = key.register(&serde_json::to_value(&begun.options).expect("json"));
    fixture.clock.advance(Duration::minutes(5));
    let error = finish(begun.id, user, body).await.expect_err("expired");
    assert_eq!(error.code(), "credential.webauthn_registration_not_found");

    let begun = fixture
        .service
        .begin_registration(&tenant, user, "ana@example.com", "Ana")
        .await
        .expect("begin");
    let options = serde_json::to_value(&begun.options).expect("json");
    let body = key.register(&options);
    finish(begun.id, user, body.clone())
        .await
        .expect("registered");
    let error = finish(begun.id, user, body).await.expect_err("used up");
    assert_eq!(error.code(), "credential.webauthn_registration_not_found");

    // The same key again: the options name it, and the tenant refuses it.
    let begun = fixture
        .service
        .begin_registration(&tenant, user, "ana@example.com", "Ana")
        .await
        .expect("begin");
    let options = serde_json::to_value(&begun.options).expect("json");
    assert_eq!(options["excludeCredentials"][0]["id"], key.credential_id());
    let error = finish(begun.id, user, key.register(&options))
        .await
        .expect_err("a duplicate");
    assert_eq!(error.code(), "credential.webauthn_credential_exists");
}

#[tokio::test]
async fn a_key_of_one_tenant_is_unknown_in_another() {
    let fixture = fixture();
    let (home, other) = (tenant(), tenant());
    let user = UserId::generate();
    let key = SoftwareAuthenticator::new(ORIGIN);
    register(&fixture, &home, user, &key).await;
    assert!(
        !fixture
            .service
            .has_credentials(&other, user)
            .await
            .expect("has")
    );
    assert!(!answer(&fixture, &other, user, &key).await);
    assert!(answer(&fixture, &home, user, &key).await);
}

#[tokio::test]
async fn the_in_memory_store_passes_the_contract() {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let store = InMemoryWebAuthn::default();
    run_webauthn_contract(WebAuthnPorts {
        units_of_work: &units_of_work,
        store: &store,
    })
    .await;
}
