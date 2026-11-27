//! Secrets at rest under the tenants' data keys, on PostgreSQL, with the
//! real local key provider: sealing, the first data key made by two
//! sealings at once, and moving the secrets of 0.1.0 with `reseal_tenant`.
//! See `docs/security/secrets-at-rest.md`.

use hodor_adapters_crypto::{LocalKeyProvider, OsRandom, SecretKeys};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgKeyStore, PgLinkStore, PgProviderStore, PgSealingStateStore, PgTotpStore, reseal_tenant,
};
use hodor_credential::api::{STEP_SECONDS, TotpCheck, TotpService, totp_code_at};
use hodor_credential::testing::{FakeHmacSha1, base32_secret};
use hodor_federation::api::{
    CLIENT_SECRET_PURPOSE, CreateProvider, FederationService, ProviderKind, ProviderSettings,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::CountingRandom;
use hodor_kernel::{
    Caller, Clock, DomainError, SealedSecret, Secret, SecretBox, SystemClock, TenantContext,
    TenantId, Timestamp, UserId,
};
use hodor_keys::api::{KeyService, KeyState, KeyUse, SEALED_FORMAT, TenantSecretBox};
use std::sync::Arc;

fn root_keys() -> Arc<SecretKeys> {
    let setting = Secret::new(format!("root:{}", SecretKeys::generate(&OsRandom).expose()));
    Arc::new(SecretKeys::parse(&setting).expect("root keys"))
}

fn tenant_box(database: &TestDatabase, root: &Arc<SecretKeys>) -> TenantSecretBox {
    TenantSecretBox::new(
        Arc::new(database.app().clone()),
        Arc::new(PgKeyStore),
        Arc::new(LocalKeyProvider::new(root.clone())),
        Arc::new(PgSealingStateStore),
        Some(root.clone()),
        Arc::new(SystemClock),
    )
}

/// Seals as 0.1.0 did: directly with a root key.
struct FirstFormat(Arc<SecretKeys>);

#[async_trait::async_trait]
impl SecretBox for FirstFormat {
    async fn seal(
        &self,
        tenant: &TenantContext,
        purpose: &str,
        secret: &Secret<Vec<u8>>,
    ) -> Result<SealedSecret, DomainError> {
        self.0.seal(tenant, purpose, secret)
    }

    async fn open(
        &self,
        tenant: &TenantContext,
        purpose: &str,
        sealed: &SealedSecret,
    ) -> Result<Secret<Vec<u8>>, DomainError> {
        self.0.open(tenant, purpose, sealed)
    }

    async fn needs_resealing(
        &self,
        _tenant: &TenantContext,
        _sealed: &SealedSecret,
    ) -> Result<bool, DomainError> {
        Ok(false)
    }
}

fn secret(text: &str) -> Secret<Vec<u8>> {
    Secret::new(text.as_bytes().to_vec())
}

async fn data_versions(database: &TestDatabase, tenant: &TenantContext) -> Vec<KeyState> {
    let service = KeyService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgKeyStore),
        Arc::new(LocalKeyProvider::new(root_keys())),
        Arc::new(SystemClock),
    );
    service
        .key_set(tenant, KeyUse::Data)
        .await
        .expect("key set")
        .versions()
        .iter()
        .map(|version| version.state())
        .collect()
}

#[tokio::test]
async fn a_secret_is_sealed_under_the_tenants_data_key_and_only_opens_there() {
    let database = TestDatabase::start().await;
    let root = root_keys();
    let secrets = tenant_box(&database, &root);
    let tenant = TenantContext::assume(TenantId::generate());
    let other = TenantContext::assume(TenantId::generate());

    let sealed = secrets
        .seal(&tenant, "a.purpose", &secret("the secret"))
        .await
        .expect("seal");
    assert_eq!(sealed.as_bytes()[0], SEALED_FORMAT);
    assert_eq!(data_versions(&database, &tenant).await, [KeyState::Active]);
    assert!(
        !secrets
            .needs_resealing(&tenant, &sealed)
            .await
            .expect("check")
    );

    let opened = secrets
        .open(&tenant, "a.purpose", &sealed)
        .await
        .expect("open");
    assert_eq!(opened.expose(), b"the secret");
    for (where_, purpose) in [(&other, "a.purpose"), (&tenant, "another.purpose")] {
        let error = secrets
            .open(where_, purpose, &sealed)
            .await
            .expect_err("refused");
        assert_eq!(error.code(), "secret.unreadable");
    }

    // A bit changed anywhere in what is stored is refused.
    for index in [0, 1, 17, 20, sealed.as_bytes().len() - 1] {
        let mut bytes = sealed.as_bytes().to_vec();
        bytes[index] ^= 0x01;
        let error = secrets
            .open(&tenant, "a.purpose", &SealedSecret::from_stored(bytes))
            .await
            .expect_err("a changed bit is refused");
        assert_eq!(error.code(), "secret.unreadable", "byte {index}");
    }
}

#[tokio::test]
async fn two_sealings_in_a_new_tenant_at_once_end_with_one_data_key() {
    let database = TestDatabase::start().await;
    let root = root_keys();
    let (first, second) = (tenant_box(&database, &root), tenant_box(&database, &root));
    let tenant = TenantContext::assume(TenantId::generate());

    let (one, two) = (secret("one"), secret("two"));
    let (one, two) = tokio::join!(
        first.seal(&tenant, "a.purpose", &one),
        second.seal(&tenant, "a.purpose", &two),
    );
    let (one, two) = (one.expect("first seal"), two.expect("second seal"));

    let states = data_versions(&database, &tenant).await;
    assert_eq!(
        states
            .iter()
            .filter(|state| **state == KeyState::Active)
            .count(),
        1,
        "{states:?}"
    );
    assert!(
        states
            .iter()
            .all(|state| matches!(state, KeyState::Active | KeyState::Revoked)),
        "{states:?}"
    );
    assert_eq!(
        first
            .open(&tenant, "a.purpose", &one)
            .await
            .expect("one")
            .expose(),
        b"one"
    );
    assert_eq!(
        first
            .open(&tenant, "a.purpose", &two)
            .await
            .expect("two")
            .expose(),
        b"two"
    );
}

fn provider() -> CreateProvider {
    CreateProvider {
        alias: "example".to_owned(),
        kind: ProviderKind::OpenIdConnect,
        settings: ProviderSettings {
            saml: None,
            display_name: "Example".to_owned(),
            issuer: "https://accounts.example.com".to_owned(),
            client_id: "hodor".to_owned(),
            scopes: ProviderSettings::default_scopes(),
            creates_users: true,
            trusts_email: false,
            directory: None,
        },
        client_secret: Secret::from("the-client-secret".to_owned()),
    }
}

#[tokio::test]
async fn the_secrets_of_0_1_0_are_sealed_again_and_then_the_first_format_is_refused() {
    let database = TestDatabase::start().await;
    let root = root_keys();
    let old: Arc<dyn SecretBox> = Arc::new(FirstFormat(root.clone()));
    let secrets = Arc::new(tenant_box(&database, &root));
    let tenant = TenantContext::assume(TenantId::generate());
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + time::Duration::seconds(STEP_SECONDS * 60_000_000),
    ));

    // What 0.1.0 left: a provider's secret and an authenticator
    // application's secret, both sealed directly with the root key.
    let federation = |secrets: Arc<dyn SecretBox>| {
        FederationService::new(
            Arc::new(database.app().clone()),
            Arc::new(PgProviderStore),
            Arc::new(PgLinkStore),
            secrets,
            Arc::new(SystemClock),
        )
    };
    let totp = |secrets: Arc<dyn SecretBox>| {
        TotpService::new(
            Arc::new(database.app().clone()),
            Arc::new(PgTotpStore),
            secrets,
            Arc::new(FakeHmacSha1),
            Arc::new(CountingRandom::default()),
            clock.clone(),
        )
    };
    let made = federation(old.clone())
        .create_provider(&tenant, provider(), Caller::system())
        .await
        .expect("provider");
    let user = UserId::generate();
    let enrollment = totp(old.clone())
        .begin_enrollment(&tenant, user, "Acme", "ana@example.com")
        .await
        .expect("begin");
    let shared = base32_secret(enrollment.secret());
    let phone = |moment| Secret::from(totp_code_at(&FakeHmacSha1, &shared, moment));
    totp(old)
        .confirm_enrollment(&tenant, user, &phone(clock.now()), Caller::system())
        .await
        .expect("confirm");

    // Before resealing, the new box still opens both.
    let federation_now = federation(secrets.clone());
    assert_eq!(
        federation_now
            .client_secret(&tenant, &made)
            .await
            .expect("still opens")
            .expose(),
        "the-client-secret"
    );

    let report = reseal_tenant(database.app(), secrets.as_ref(), &tenant)
        .await
        .expect("reseal");
    assert_eq!(report.resealed, 2, "{report:?}");
    assert_eq!(report.unreadable, 0, "{report:?}");
    assert!(report.complete());
    secrets.refuse_first_format(&tenant).await.expect("refuse");
    assert!(secrets.first_format_refused(&tenant).await.expect("state"));

    // Every stored secret is now of the second format.
    let stored: Vec<Vec<u8>> = sqlx::query_scalar(
        "SELECT client_secret FROM federation.identity_provider
         UNION ALL SELECT sealed_secret FROM credential.totp",
    )
    .fetch_all(database.owner())
    .await
    .expect("stored");
    assert_eq!(stored.len(), 2);
    assert!(stored.iter().all(|bytes| bytes[0] == SEALED_FORMAT));

    // Both still work, through the new box only, as read again.
    let made = federation_now
        .provider(&tenant, made.id())
        .await
        .expect("read again");
    assert_eq!(
        federation_now
            .client_secret(&tenant, &made)
            .await
            .expect("opens")
            .expose(),
        "the-client-secret"
    );
    clock.advance(time::Duration::seconds(STEP_SECONDS));
    assert!(matches!(
        totp(secrets.clone())
            .verify(&tenant, Some(user), &phone(clock.now()))
            .await,
        Ok(TotpCheck::Verified)
    ));

    // Running it again does nothing, and a first-format secret no longer
    // opens in this tenant, even with the root key that sealed it.
    let again = reseal_tenant(database.app(), secrets.as_ref(), &tenant)
        .await
        .expect("again");
    assert_eq!((again.resealed, again.current), (0, 2), "{again:?}");
    let first_format = root
        .seal(&tenant, CLIENT_SECRET_PURPOSE, &secret("old"))
        .expect("seal as 0.1.0 did");
    let error = secrets
        .open(&tenant, CLIENT_SECRET_PURPOSE, &first_format)
        .await
        .expect_err("refused once the tenant refuses the first format");
    assert_eq!(error.code(), "secret.unreadable");
}

/// The `bytea` columns that hold no secret sealed with the secret box,
/// each with the reason.
const NOT_SEALED_SECRETS: &[(&str, &str, &str)] = &[
    (
        "authorization.policy_version",
        "digest",
        "the SHA-256 of a policy version's files",
    ),
    ("session.session", "token_hash", "a hash of a random token"),
    (
        "oauth.refresh_token_family",
        "current_hash",
        "a hash of the newest refresh token",
    ),
    (
        "oauth.refresh_token",
        "token_hash",
        "a hash of a refresh token",
    ),
    (
        "credential.access_token",
        "token_hash",
        "a hash of a random token",
    ),
    ("credential.api_key", "key_hash", "a hash of a random key"),
    (
        "oauth.initial_access_token",
        "token_hash",
        "the SHA-256 of a random initial access token, never the token",
    ),
    (
        "oauth.client",
        "registered_from",
        "the SHA-256 of the address a client registered itself from",
    ),
    (
        "oauth.frontchannel_logout",
        "handle_hash",
        "the SHA-256 of the random handle of a signed-out page's frames, never the handle",
    ),
    (
        "authentication.attempt_counter",
        "subject_key",
        "a hash of an identifier or an address",
    ),
    (
        "authentication.transaction",
        "binding",
        "a hash binding the sign-in to its browser",
    ),
    (
        "authentication.transaction",
        "identifier_key",
        "a hash of an identifier",
    ),
    (
        "authentication.verification_token",
        "token_hash",
        "a hash of a random token",
    ),
    (
        "authentication.email_sign_in",
        "secret_hash",
        "the SHA-256 of a code or a link's token, good only within its sign-in",
    ),
    (
        "authentication.email_sign_in",
        "identifier_key",
        "a hash of an identifier",
    ),
    (
        "audit.record",
        "previous_hash",
        "a link of the chain of hashes",
    ),
    ("audit.record", "hash", "a link of the chain of hashes"),
    (
        "audit.chain_head",
        "hash",
        "the latest link of the chain of hashes",
    ),
    (
        "federation.pending_authorization",
        "state_hash",
        "a hash of a random state",
    ),
    (
        "federation.pending_authorization",
        "saml_receipt_hash",
        "a hash of a random receipt",
    ),
    (
        "oauth.client_secret",
        "secret_hash",
        "a hash of a random client secret",
    ),
    (
        "oauth.authorization_code",
        "code_hash",
        "a hash of a random code",
    ),
    (
        "keys.key_version",
        "key_material",
        "sealed by the key provider, not the secret box",
    ),
    ("keys.key_version", "public_rsa_modulus", "a public key"),
    ("keys.key_version", "public_rsa_exponent", "a public key"),
    ("keys.key_version", "public_p256_x", "a public key"),
    ("keys.key_version", "public_p256_y", "a public key"),
    ("keys.key_version", "public_ed25519", "a public key"),
    (
        "keys.certificate_authority",
        "key_material",
        "what the key provider handed back for the authority's key, as for a key version",
    ),
    (
        "keys.certificate_authority",
        "public_p256_x",
        "a public key",
    ),
    (
        "keys.certificate_authority",
        "public_p256_y",
        "a public key",
    ),
    (
        "keys.certificate_authority",
        "certificate_signing_request",
        "a request holding a public key, made to be sent to the tenant's root",
    ),
    (
        "keys.certificate_authority",
        "certificate",
        "a certificate, published in the authority's bundle",
    ),
    (
        "keys.intermediate",
        "certificate",
        "an intermediate's certificate, handed to its mesh, which publishes it",
    ),
    (
        "credential.webauthn_credential",
        "credential_id",
        "the identifier the authenticator made",
    ),
    (
        "credential.webauthn_credential",
        "public_key",
        "a public key",
    ),
    (
        "credential.webauthn_registration",
        "challenge",
        "a random challenge, good for one registration",
    ),
    (
        "authentication.transaction",
        "challenge",
        "a random challenge, good for one step",
    ),
    (
        "oauth.authorization_request",
        "secret_hash",
        "a hash of the secret the browser holds",
    ),
    (
        "oauth.authorization_request",
        "reference_hash",
        "the SHA-256 of a pushed request's reference, never the reference",
    ),
    (
        "credential.recovery_code",
        "code_hash",
        "the SHA-256 of a recovery code, never the code",
    ),
    (
        "public._sqlx_migrations",
        "checksum",
        "the checksum of a migration",
    ),
    (
        "platform.policy_agent_instance",
        "credential_digest",
        "the SHA-256 of an instance's credential, never the credential",
    ),
    (
        "authorization.policy_bundle",
        "archive",
        "a signed bundle of policies, which holds no secret",
    ),
    (
        "authorization.policy_bundle",
        "digest",
        "the SHA-256 of a bundle's archive",
    ),
    (
        "identity.organization_invitation",
        "token_hash",
        "the SHA-256 of an invitation's secret, never the secret",
    ),
    (
        "oauth.refresh_token_family",
        "certificate_thumbprint",
        "the SHA-256 of the certificate a family is bound to, which is public",
    ),
];

#[tokio::test]
async fn every_bytea_column_is_known_to_hold_sealed_secrets_or_not() {
    use hodor_adapters_postgres::SEALED_COLUMNS;

    let database = TestDatabase::start().await;
    let columns: Vec<(String, String)> = sqlx::query_as(
        "SELECT table_schema || '.' || table_name, column_name
         FROM information_schema.columns
         WHERE data_type = 'bytea'
           AND table_schema NOT IN ('pg_catalog', 'information_schema')
         ORDER BY 1, 2",
    )
    .fetch_all(database.owner())
    .await
    .expect("columns");

    let unknown: Vec<String> = columns
        .iter()
        .filter(|(table, column)| {
            let sealed = SEALED_COLUMNS
                .iter()
                .any(|known| known.table == table && known.column == column);
            let not_sealed = NOT_SEALED_SECRETS
                .iter()
                .any(|(known_table, known_column, _)| {
                    known_table == table && known_column == column
                });
            !sealed && !not_sealed
        })
        .map(|(table, column)| format!("{table}.{column}"))
        .collect();
    assert!(
        unknown.is_empty(),
        "a bytea column is in neither SEALED_COLUMNS nor the list of columns without sealed \
         secrets; if it holds a sealed secret, add it to SEALED_COLUMNS so that \
         `hodor-cli secrets reseal` seals it again: {unknown:?}"
    );

    // And every listed column exists.
    for known in SEALED_COLUMNS {
        assert!(
            columns
                .iter()
                .any(|(table, column)| table == known.table && column == known.column),
            "{}.{} is listed but does not exist",
            known.table,
            known.column
        );
    }
}

#[tokio::test]
async fn the_pairwise_secret_is_sealed_again_and_every_identifier_stays_the_same() {
    use hodor_adapters_crypto::AwsLcHmacSha256;
    use hodor_adapters_postgres::PgPairwiseSecretStore;
    use hodor_oauth::api::{
        ApplicationId, Client, ClientSecret, ClientSettings, ClientType, GrantType, PairwisePorts,
        PairwiseSubjects, SubjectType,
    };
    let database = TestDatabase::start().await;
    let root = root_keys();
    let secrets = Arc::new(tenant_box(&database, &root));
    let tenant = TenantContext::assume(TenantId::generate());
    let pairwise = |secret_box: Arc<dyn SecretBox>| {
        PairwiseSubjects::new(PairwisePorts {
            units_of_work: Arc::new(database.app().clone()),
            secrets: Arc::new(PgPairwiseSecretStore),
            secret_box,
            mac: Arc::new(AwsLcHmacSha256),
            random: Arc::new(OsRandom),
            clock: Arc::new(SystemClock),
        })
    };
    let mut settings = ClientSettings::new(
        "Payroll web",
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec!["https://payroll.example.com/callback".to_owned()],
    );
    settings.subject_type = SubjectType::Pairwise;
    let client = Client::create(
        ApplicationId::generate(),
        ClientType::Confidential,
        settings,
        ClientSecret::DEFAULT_LIFETIME,
        Timestamp::UNIX_EPOCH,
        &OsRandom,
        &hodor_kernel::random::testing::FakeDigest,
    )
    .expect("client")
    .0;
    let person = UserId::generate();

    // A secret made by an earlier version, sealed with the root key.
    let before = pairwise(Arc::new(FirstFormat(root.clone())))
        .subject(&tenant, &client, person)
        .await
        .expect("made");
    let report = reseal_tenant(database.app(), secrets.as_ref(), &tenant)
        .await
        .expect("reseal");
    assert_eq!(report.resealed, 1, "{report:?}");
    secrets.refuse_first_format(&tenant).await.expect("refuse");
    let stored: Vec<u8> = sqlx::query_scalar("SELECT sealed_secret FROM oauth.pairwise_secret")
        .fetch_one(database.owner())
        .await
        .expect("stored");
    assert_eq!(stored[0], SEALED_FORMAT);
    let after = pairwise(secrets.clone())
        .subject(&tenant, &client, person)
        .await
        .expect("opens");
    assert_eq!(before, after, "the identifier a client was given stays");
    // The secret is stored only sealed: the identifier cannot be made
    // from what the row holds without opening it.
    assert_ne!(stored.len(), 32);
}
