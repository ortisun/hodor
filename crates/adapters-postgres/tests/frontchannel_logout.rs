//! Front-channel logout on PostgreSQL: the contract of its store, the
//! frames of a real session's clients, and what only a real database can
//! show: the rules it keeps itself, row-level security between tenants,
//! and the cleanup of expired frames.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    Database, ExpiredKind, ExpiredRowCleanup, PgApplicationStore, PgClientStore,
    PgFrontChannelLogoutStore, PgGrantStore, PgPairwiseSecretStore, PgResourceServerStore,
    PgSessionClients,
};
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{
    Caller, Clock as _, SystemClock, TenantContext, TenantId, UnitOfWorkFactory, UserId,
};
use hodor_oauth::api::{
    ApplicationPorts, ApplicationService, ApplicationSettings, Client, ClientSettings, ClientType,
    CreateClient, FrontChannelLogoutPorts, FrontChannelLogoutService, Grant, GrantClaims, GrantId,
    GrantStatus, GrantStore as _, GrantType, SubjectType,
};
use hodor_oauth::testing::{
    DistinctRandom, FakeDestinations, FrontChannelLogoutStorePorts, pairwise_subjects,
    run_frontchannel_logout_contract,
};
use hodor_session::api::SessionId;
use std::sync::Arc;
use time::Duration;

const ISSUER: &str = "https://id.example.com/t/acme";

#[tokio::test]
async fn the_postgres_store_passes_the_contract() {
    let database = TestDatabase::start().await;
    run_frontchannel_logout_contract(FrontChannelLogoutStorePorts {
        units_of_work: database.app(),
        store: &PgFrontChannelLogoutStore,
        random: &DistinctRandom,
    })
    .await;
}

fn applications(database: &Database) -> ApplicationService {
    ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(database.clone()),
        applications: Arc::new(PgApplicationStore),
        clients: Arc::new(PgClientStore),
        resource_servers: Arc::new(PgResourceServerStore),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: Arc::new(SystemClock),
    })
    .with_destinations(Arc::new(FakeDestinations))
}

fn service(database: &TestDatabase) -> FrontChannelLogoutService {
    FrontChannelLogoutService::new(FrontChannelLogoutPorts {
        units_of_work: Arc::new(database.app().clone()),
        sessions: Arc::new(PgSessionClients),
        clients: Arc::new(PgClientStore),
        applications: Arc::new(PgApplicationStore),
        store: Arc::new(PgFrontChannelLogoutStore),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: Arc::new(SystemClock),
    })
    .with_pairwise_subjects(pairwise_subjects(
        Arc::new(database.app().clone()),
        Arc::new(PgPairwiseSecretStore),
    ))
}

/// A client of a new application on `host`, with a front-channel logout
/// address there.
async fn client(
    database: &TestDatabase,
    tenant: &TenantContext,
    host: &str,
    subject_type: SubjectType,
) -> Client {
    let service = applications(database.app());
    let application = service
        .create_application(
            tenant,
            ApplicationSettings {
                name: host.to_owned(),
                first_party: true,
            },
            Caller::system(),
        )
        .await
        .expect("application");
    let mut settings = ClientSettings::new(
        host,
        ClientType::Confidential,
        vec![GrantType::AuthorizationCode],
        vec![format!("https://{host}/callback")],
    );
    settings.frontchannel_logout_uri = Some(format!("https://{host}/frontchannel-logout"));
    settings.frontchannel_logout_session_required = true;
    settings.subject_type = subject_type;
    service
        .create_client(
            tenant,
            CreateClient {
                application_id: application.id(),
                client_type: ClientType::Confidential,
                settings,
                secret_lifetime: None,
            },
            Caller::system(),
        )
        .await
        .expect("client")
        .0
}

/// A code was issued to `client` in `session` with `openid`.
async fn signed_in(
    database: &TestDatabase,
    tenant: &TenantContext,
    client: &Client,
    session: SessionId,
) {
    let mut uow = UnitOfWorkFactory::begin(database.app(), tenant)
        .await
        .expect("begin");
    PgGrantStore
        .insert(
            uow.as_mut(),
            &Grant {
                id: GrantId::generate(),
                client_id: client.id(),
                user_id: UserId::generate(),
                session_id: session,
                scopes: vec!["openid".to_owned()],
                audiences: Vec::new(),
                organization: None,
                claims: GrantClaims::default(),
                status: GrantStatus::Active,
                created_at: SystemClock.now(),
                revoked_at: None,
                revocation_reason: None,
            },
        )
        .await
        .expect("grant");
    uow.commit().await.expect("commit");
}

#[tokio::test]
async fn a_sign_out_keeps_one_frame_per_client_of_the_session_readable_in_its_tenant_only() {
    let database = TestDatabase::start().await;
    let acme = TenantContext::assume(TenantId::generate());
    let globex = TenantContext::assume(TenantId::generate());
    let payroll = client(&database, &acme, "payroll.example.com", SubjectType::Public).await;
    let reports = client(
        &database,
        &acme,
        "reports.example.com",
        SubjectType::Pairwise,
    )
    .await;
    let theirs = client(
        &database,
        &globex,
        "payroll.example.com",
        SubjectType::Public,
    )
    .await;
    let session = SessionId::generate();
    signed_in(&database, &acme, &payroll, session).await;
    signed_in(&database, &acme, &reports, session).await;
    // A grant of the other tenant that names the same session identifier.
    signed_in(&database, &globex, &theirs, session).await;
    // The client is read back with its address.
    let stored = applications(database.app())
        .client(&acme, payroll.id())
        .await
        .expect("client");
    assert_eq!(
        stored.frontchannel_logout_uri(),
        Some("https://payroll.example.com/frontchannel-logout")
    );
    assert!(
        stored
            .snapshot()
            .settings
            .frontchannel_logout_session_required
    );

    let service = service(&database);
    let handle = service
        .sign_out(&acme, ISSUER, session)
        .await
        .expect("signed out")
        .expect("a handle");
    let frames = service
        .frames(&acme, handle.expose())
        .await
        .expect("frames");
    assert_eq!(
        frames.len(),
        2,
        "acme's two clients and no other: {frames:?}"
    );
    assert!(
        frames
            .iter()
            .any(|frame| frame
                == &format!(
                    "https://payroll.example.com/frontchannel-logout?iss=https%3A%2F%2Fid.example.com%2Ft%2Facme&sid={session}"
                )),
        "{frames:?}"
    );
    let pairwise = frames
        .iter()
        .find(|frame| frame.starts_with("https://reports.example.com/"))
        .expect("the pairwise client's frame");
    assert!(
        !pairwise.contains(&session.to_string()),
        "a pairwise client never gets the public sid: {pairwise}"
    );
    assert!(
        service
            .frames(&globex, handle.expose())
            .await
            .expect("frames")
            .is_empty(),
        "the handle finds nothing in another tenant"
    );
    // The other tenant's own sign-out of the same session identifier
    // frames its own client only.
    let theirs_handle = service
        .sign_out(&globex, "https://id.example.com/t/globex", session)
        .await
        .expect("signed out")
        .expect("a handle");
    let theirs_frames = service
        .frames(&globex, theirs_handle.expose())
        .await
        .expect("frames");
    assert_eq!(theirs_frames.len(), 1);
    assert!(theirs_frames[0].contains("iss=https%3A%2F%2Fid.example.com%2Ft%2Fglobex"));
    assert!(
        service
            .frames(&acme, theirs_handle.expose())
            .await
            .expect("frames")
            .is_empty()
    );
}

#[tokio::test]
async fn the_database_keeps_the_rules_of_an_address_and_of_the_frames() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let payroll = client(
        &database,
        &tenant,
        "payroll.example.com",
        SubjectType::Public,
    )
    .await;
    for (change, constraint) in [
        (
            "UPDATE oauth.client SET grant_types = ARRAY['client_credentials'],
                 redirect_uris = '{}' WHERE id = $1",
            "client_frontchannel_logout_needs_code",
        ),
        (
            "UPDATE oauth.client SET frontchannel_logout_uri = 'javascript:alert(1)' WHERE id = $1",
            "client_frontchannel_logout_uri_form",
        ),
        (
            "UPDATE oauth.client SET frontchannel_logout_uri = NULL,
                 frontchannel_logout_session_required = true WHERE id = $1",
            "client_frontchannel_logout_session_needs_uri",
        ),
    ] {
        let error = sqlx::query(change)
            .bind(payroll.id().as_uuid())
            .execute(database.owner())
            .await
            .expect_err(constraint);
        assert!(
            error.to_string().contains(constraint),
            "{constraint}: {error}"
        );
    }
    for (hash, frames, expires, constraint) in [
        (
            vec![1_u8; 31],
            vec!["https://a.example.com/".to_owned()],
            "120 seconds",
            "frontchannel_logout_handle_is_sha256",
        ),
        (
            vec![2_u8; 32],
            Vec::new(),
            "120 seconds",
            "frontchannel_logout_has_frames",
        ),
        (
            vec![3_u8; 32],
            vec!["https://a.example.com/".to_owned()],
            "1 day",
            "frontchannel_logout_lives_two_minutes",
        ),
    ] {
        let insert = format!(
            "INSERT INTO oauth.frontchannel_logout
                 (tenant_id, id, handle_hash, session_id, frames, created_at, expires_at)
             VALUES ($1, gen_random_uuid(), $2, gen_random_uuid(), $3, now(),
                     now() + interval '{expires}')"
        );
        let error = sqlx::query(sqlx::AssertSqlSafe(insert))
            .bind(tenant.tenant_id().as_uuid())
            .bind(hash)
            .bind(frames)
            .execute(database.owner())
            .await
            .expect_err(constraint);
        assert!(
            error.to_string().contains(constraint),
            "{constraint}: {error}"
        );
    }
}

#[tokio::test]
async fn expired_frames_are_removed_at_the_next_pass_and_live_ones_stay() {
    let database = TestDatabase::start().await;
    let tenant = TenantContext::assume(TenantId::generate());
    let now = SystemClock.now();
    let insert = "INSERT INTO oauth.frontchannel_logout
         (tenant_id, id, handle_hash, session_id, frames, created_at, expires_at)
         VALUES ($1, gen_random_uuid(), $2, gen_random_uuid(), ARRAY['https://a.example.com/'],
                 $3, $3 + interval '120 seconds')";
    for (seed, created) in [
        (1_u8, now - Duration::minutes(10)),
        (2, now - Duration::seconds(121)),
        (3, now - Duration::seconds(30)),
    ] {
        sqlx::query(insert)
            .bind(tenant.tenant_id().as_uuid())
            .bind(vec![seed; 32])
            .bind(created)
            .execute(database.owner())
            .await
            .expect("frames");
    }
    let report = ExpiredRowCleanup::new(
        ExpiredKind::FrontChannelLogouts,
        ExpiredKind::FrontChannelLogouts.default_retention_days(),
        database.platform().clone(),
        database.app().clone(),
    )
    .run(now, 100)
    .await
    .expect("cleanup");
    assert_eq!(report.removed, 2);
    let left: (i64,) = sqlx::query_as("SELECT count(*) FROM oauth.frontchannel_logout")
        .fetch_one(database.owner())
        .await
        .expect("left");
    assert_eq!(left.0, 1, "the live frames stay");
    assert_eq!(
        ExpiredKind::FrontChannelLogouts.name(),
        "frontchannel_logouts"
    );
    assert_eq!(ExpiredKind::FrontChannelLogouts.default_retention_days(), 0);
}
