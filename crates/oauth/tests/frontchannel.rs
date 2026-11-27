//! Front-channel logout on the in-memory stores: the frames a session that
//! ended in its browser makes, the `sid` each client is given, and the
//! frames read back by the handle the browser holds.

use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, Clock as _, TenantContext, TenantId, Timestamp, UnitOfWorkFactory};
use hodor_oauth::api::{
    ApplicationId, ApplicationPorts, ApplicationService, ApplicationSettings, Client,
    ClientSettings, ClientType, CreateClient, FrontChannelLogoutPorts, FrontChannelLogoutService,
    Grant, GrantClaims, GrantId, GrantStatus, GrantStore, GrantType, Status, SubjectType,
};
use hodor_oauth::testing::{
    DistinctRandom, FakeDestinations, FrontChannelLogoutStorePorts, InMemoryFrontChannelLogouts,
    InMemoryGrants, InMemoryPairwiseSecrets, InMemorySessionClients, InMemoryStores,
    pairwise_subjects, run_frontchannel_logout_contract,
};
use hodor_session::api::SessionId;
use std::collections::BTreeMap;
use std::sync::Arc;
use time::Duration;

const ISSUER: &str = "https://id.example.com/t/acme";

struct World {
    units: InMemoryUnitOfWorkFactory,
    grants: InMemoryGrants,
    kept: InMemoryFrontChannelLogouts,
    applications: ApplicationService,
    clock: Arc<FixedClock>,
    service: FrontChannelLogoutService,
    without_pairwise: FrontChannelLogoutService,
    pairwise: hodor_oauth::api::PairwiseSubjects,
}

fn world() -> World {
    let units = InMemoryUnitOfWorkFactory::default();
    let stores = InMemoryStores::default();
    let grants = InMemoryGrants::new(&stores.clients);
    let kept = InMemoryFrontChannelLogouts::default();
    let clock = Arc::new(FixedClock::at(
        Timestamp::UNIX_EPOCH + Duration::days(20_000),
    ));
    let applications = ApplicationService::new(ApplicationPorts {
        units_of_work: Arc::new(units.clone()),
        applications: Arc::new(stores.applications.clone()),
        clients: Arc::new(stores.clients.clone()),
        resource_servers: Arc::new(stores.resource_servers.clone()),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    })
    .with_destinations(Arc::new(FakeDestinations));
    let without_pairwise = FrontChannelLogoutService::new(FrontChannelLogoutPorts {
        units_of_work: Arc::new(units.clone()),
        sessions: Arc::new(InMemorySessionClients::new(&grants)),
        clients: Arc::new(stores.clients.clone()),
        applications: Arc::new(stores.applications.clone()),
        store: Arc::new(kept.clone()),
        digest: Arc::new(FakeDigest),
        random: Arc::new(DistinctRandom),
        clock: clock.clone(),
    });
    let pairwise = pairwise_subjects(
        Arc::new(units.clone()),
        Arc::new(InMemoryPairwiseSecrets::default()),
    );
    let service = without_pairwise
        .clone()
        .with_pairwise_subjects(pairwise.clone());
    World {
        units,
        grants,
        kept,
        applications,
        clock,
        service,
        without_pairwise,
        pairwise,
    }
}

impl World {
    async fn application(&self, tenant: &TenantContext, name: &str) -> ApplicationId {
        self.applications
            .create_application(
                tenant,
                ApplicationSettings {
                    name: name.to_owned(),
                    first_party: true,
                },
                Caller::system(),
            )
            .await
            .expect("application")
            .id()
    }

    async fn client(
        &self,
        tenant: &TenantContext,
        application: ApplicationId,
        host: &str,
        address: Option<&str>,
        subject_type: SubjectType,
    ) -> Client {
        let mut settings = ClientSettings::new(
            host,
            ClientType::Public,
            vec![GrantType::AuthorizationCode],
            vec![format!("https://{host}/callback")],
        );
        settings.frontchannel_logout_uri = address.map(str::to_owned);
        settings.subject_type = subject_type;
        self.applications
            .create_client(
                tenant,
                CreateClient {
                    application_id: application,
                    client_type: ClientType::Public,
                    settings,
                    secret_lifetime: None,
                },
                Caller::system(),
            )
            .await
            .expect("client")
            .0
    }

    /// A code was issued to `client` in `session` for these scopes.
    async fn signed_in(
        &self,
        tenant: &TenantContext,
        client: &Client,
        session: SessionId,
        scopes: &[&str],
    ) {
        let mut uow = self.units.begin(tenant).await.expect("begin");
        self.grants
            .insert(
                uow.as_mut(),
                &Grant {
                    id: GrantId::generate(),
                    client_id: client.id(),
                    user_id: hodor_kernel::UserId::generate(),
                    session_id: session,
                    scopes: scopes.iter().map(|scope| (*scope).to_owned()).collect(),
                    audiences: Vec::new(),
                    organization: None,
                    claims: GrantClaims::default(),
                    status: GrantStatus::Active,
                    created_at: self.clock.now(),
                    revoked_at: None,
                    revocation_reason: None,
                },
            )
            .await
            .expect("grant");
        uow.commit().await.expect("commit");
    }
}

fn a_tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

/// The query of a frame's address, by name.
fn query_of(frame: &str) -> BTreeMap<String, String> {
    let (_, query) = frame.split_once('?').expect("a query");
    query
        .split('&')
        .filter_map(|pair| pair.split_once('='))
        .map(|(name, value)| {
            (
                name.to_owned(),
                value.replace("%3A", ":").replace("%2F", "/"),
            )
        })
        .collect()
}

#[tokio::test]
async fn the_store_contract_holds_in_memory() {
    run_frontchannel_logout_contract(FrontChannelLogoutStorePorts {
        units_of_work: &InMemoryUnitOfWorkFactory::default(),
        store: &InMemoryFrontChannelLogouts::default(),
        random: &DistinctRandom,
    })
    .await;
}

#[tokio::test]
async fn every_client_of_the_session_with_an_address_gets_one_frame_with_its_own_sid() {
    let world = world();
    let tenant = a_tenant();
    let payroll_app = world.application(&tenant, "Payroll").await;
    let reports_app = world.application(&tenant, "Reports").await;
    let payroll = world
        .client(
            &tenant,
            payroll_app,
            "payroll.example.com",
            Some("https://payroll.example.com/fc?from=hodor"),
            SubjectType::Public,
        )
        .await;
    let reports = world
        .client(
            &tenant,
            reports_app,
            "reports.example.com",
            Some("https://reports.example.com/fc"),
            SubjectType::Pairwise,
        )
        .await;
    let without_address = world
        .client(
            &tenant,
            payroll_app,
            "billing.example.com",
            None,
            SubjectType::Public,
        )
        .await;
    let without_openid = world
        .client(
            &tenant,
            payroll_app,
            "invoices.example.com",
            Some("https://invoices.example.com/fc"),
            SubjectType::Public,
        )
        .await;
    let session = SessionId::generate();
    let other_session = SessionId::generate();
    // Two codes in the session: still one frame.
    world
        .signed_in(&tenant, &payroll, session, &["openid"])
        .await;
    world
        .signed_in(&tenant, &payroll, session, &["openid", "email"])
        .await;
    world
        .signed_in(&tenant, &reports, session, &["openid"])
        .await;
    world
        .signed_in(&tenant, &without_address, session, &["openid"])
        .await;
    world
        .signed_in(&tenant, &without_openid, session, &["invoices:read"])
        .await;
    world
        .signed_in(&tenant, &without_openid, other_session, &["openid"])
        .await;

    let frames = world
        .service
        .frames_for(&tenant, ISSUER, session)
        .await
        .expect("frames");
    assert_eq!(frames.len(), 2, "{frames:?}");
    let payroll_frame = frames
        .iter()
        .find(|frame| frame.starts_with("https://payroll.example.com/fc?from=hodor&iss="))
        .expect("payroll's frame, its own query kept");
    let reports_frame = frames
        .iter()
        .find(|frame| frame.starts_with("https://reports.example.com/fc?iss="))
        .expect("reports' frame");
    let public = query_of(payroll_frame);
    assert_eq!(public["iss"], ISSUER);
    assert_eq!(public["sid"], session.to_string(), "a public client's sid");
    let pairwise = query_of(reports_frame);
    assert_eq!(pairwise["iss"], ISSUER);
    assert_ne!(
        pairwise["sid"],
        session.to_string(),
        "a pairwise client never gets the sid others know"
    );
    // The same pairwise `sid` its ID tokens carry.
    assert_eq!(
        pairwise["sid"],
        world
            .pairwise
            .session(&tenant, &reports, session)
            .await
            .expect("pairwise sid")
    );
    let again = world
        .service
        .frames_for(&tenant, ISSUER, session)
        .await
        .expect("frames");
    assert_eq!(again, frames, "the same sid every time");

    // Without pairwise identifiers, a pairwise client is left out rather
    // than given the public one.
    let frames = world
        .without_pairwise
        .frames_for(&tenant, ISSUER, session)
        .await
        .expect("frames");
    assert_eq!(frames.len(), 1);
    assert!(frames[0].starts_with("https://payroll.example.com/"));
}

#[tokio::test]
async fn a_disabled_client_or_application_and_another_tenant_get_no_frame() {
    let world = world();
    let tenant = a_tenant();
    let other = a_tenant();
    let payroll_app = world.application(&tenant, "Payroll").await;
    let reports_app = world.application(&tenant, "Reports").await;
    let payroll = world
        .client(
            &tenant,
            payroll_app,
            "payroll.example.com",
            Some("https://payroll.example.com/fc"),
            SubjectType::Public,
        )
        .await;
    let reports = world
        .client(
            &tenant,
            reports_app,
            "reports.example.com",
            Some("https://reports.example.com/fc"),
            SubjectType::Public,
        )
        .await;
    let other_app = world.application(&other, "Elsewhere").await;
    let elsewhere = world
        .client(
            &other,
            other_app,
            "payroll.example.com",
            Some("https://payroll.example.com/fc"),
            SubjectType::Public,
        )
        .await;
    let session = SessionId::generate();
    world
        .signed_in(&tenant, &payroll, session, &["openid"])
        .await;
    world
        .signed_in(&tenant, &reports, session, &["openid"])
        .await;
    world
        .signed_in(&other, &elsewhere, session, &["openid"])
        .await;

    world
        .applications
        .set_client_status(&tenant, payroll.id(), Status::Disabled, Caller::system())
        .await
        .expect("disabled");
    world
        .applications
        .set_application_status(&tenant, reports_app, Status::Disabled, Caller::system())
        .await
        .expect("disabled");
    assert!(
        world
            .service
            .frames_for(&tenant, ISSUER, session)
            .await
            .expect("frames")
            .is_empty()
    );
    // The other tenant's client of the same session identifier is framed
    // only by a sign-out in its own tenant.
    let theirs = world
        .service
        .frames_for(&other, "https://id.example.com/t/globex", session)
        .await
        .expect("frames");
    assert_eq!(theirs.len(), 1);
    assert!(theirs[0].contains("iss=https%3A%2F%2Fid.example.com%2Ft%2Fglobex"));
}

#[tokio::test]
async fn the_frames_are_kept_for_their_handle_in_their_tenant_for_two_minutes() {
    let world = world();
    let tenant = a_tenant();
    let application = world.application(&tenant, "Payroll").await;
    let payroll = world
        .client(
            &tenant,
            application,
            "payroll.example.com",
            Some("https://payroll.example.com/fc"),
            SubjectType::Public,
        )
        .await;
    let session = SessionId::generate();

    // Nobody to tell: nothing kept, no handle.
    assert!(
        world
            .service
            .sign_out(&tenant, ISSUER, session)
            .await
            .expect("signed out")
            .is_none()
    );
    assert!(world.kept.all(tenant.tenant_id()).is_empty());

    world
        .signed_in(&tenant, &payroll, session, &["openid"])
        .await;
    let handle = world
        .service
        .sign_out(&tenant, ISSUER, session)
        .await
        .expect("signed out")
        .expect("a handle");
    let kept = world.kept.all(tenant.tenant_id());
    assert_eq!(kept.len(), 1);
    assert!(
        kept[0].frames[0].starts_with("https://payroll.example.com/fc?iss="),
        "{:?}",
        kept[0].frames
    );
    let frames = world
        .service
        .frames(&tenant, handle.expose())
        .await
        .expect("frames");
    assert_eq!(frames, kept[0].frames);
    // Read again: the page may be loaded again.
    assert_eq!(
        world
            .service
            .frames(&tenant, handle.expose())
            .await
            .expect("frames"),
        frames
    );

    // Another tenant, another handle, or no handle at all: nothing.
    assert!(
        world
            .service
            .frames(&a_tenant(), handle.expose())
            .await
            .expect("frames")
            .is_empty()
    );
    for presented in ["", "not a handle", &"A".repeat(43)] {
        assert!(
            world
                .service
                .frames(&tenant, presented)
                .await
                .expect("frames")
                .is_empty(),
            "{presented}"
        );
    }

    // Two minutes later, nothing either.
    world.clock.advance(Duration::seconds(120));
    assert!(
        world
            .service
            .frames(&tenant, handle.expose())
            .await
            .expect("frames")
            .is_empty()
    );
}
