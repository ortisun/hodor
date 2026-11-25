//! Accepting an invitation over HTTP, on the in-memory contexts.

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use hodor_authentication::api::{InvitationContexts, InvitationService};
use hodor_credential::api::CredentialService;
use hodor_credential::testing::{FakeHasher, InMemoryPasswords};
use hodor_identity::api::{
    CreateUser, IdentifierKind, IdentityService, OrganizationService, Profile, UserKind,
};
use hodor_identity::testing::{InMemoryInvitations, InMemoryOrganizations, InMemoryUsers};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, Digest, DomainError, OrganizationId, TenantContext, Timestamp, UserId};
use hodor_notification::api::Notifier;
use hodor_notification::testing::InMemoryMessages;
use hodor_protocol_http::{
    InvitationState, Limits, ResolvedTenant, TenantResolver, TenantStatus, invitation_routes,
    public_router,
};
use hodor_session::api::{Assurance, ClientInfo, SessionService, SessionTimeouts, StartSession};
use hodor_session::testing::{InMemorySessions, SequentialRandom};
use hodor_tenant::api::{CreateTenant, TenantService};
use hodor_tenant::testing::InMemoryTenants;
use http_body_util::BodyExt as _;
use std::collections::BTreeSet;
use std::sync::Arc;
use time::Duration;
use tower::ServiceExt as _;

const HOST: &str = "login.example.com";

struct Tenants(TenantContext);

#[async_trait::async_trait]
impl TenantResolver for Tenants {
    async fn resolve(&self, slug: &str) -> Result<Option<ResolvedTenant>, DomainError> {
        Ok((slug == "acme").then(|| ResolvedTenant {
            context: self.0.clone(),
            status: TenantStatus::Active,
        }))
    }
}

struct World {
    router: Router,
    invitations: InvitationService,
    identity: IdentityService,
    sessions: SessionService,
    messages: InMemoryMessages,
    tenant: TenantContext,
    organization: OrganizationId,
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
        .expect("a tenant");
    let tenant = TenantContext::assume(created.id());
    let users = Arc::new(InMemoryUsers::default());
    let identity = IdentityService::new(factory(), users.clone(), clock.clone());
    let organizations = OrganizationService::new(
        factory(),
        Arc::new(InMemoryOrganizations::default()),
        Arc::new(InMemoryInvitations::default()),
        users,
        clock.clone(),
    );
    let organization = organizations
        .create(&tenant, "Initech", None, Caller::system())
        .await
        .expect("an organization")
        .id();
    let messages = InMemoryMessages::default();
    let digest: Arc<dyn Digest> = Arc::new(FakeDigest);
    let invitations = InvitationService::new(
        factory(),
        InvitationContexts {
            organizations,
            identity: identity.clone(),
            credentials: CredentialService::new(
                factory(),
                Arc::new(InMemoryPasswords::default()),
                Arc::new(FakeHasher::default()),
                clock.clone(),
            ),
            tenants,
            notifier: Notifier::new(Arc::new(messages.clone()), clock.clone()),
        },
        digest.clone(),
        Arc::new(SequentialRandom::default()),
        "https://login.example.com",
    );
    let sessions = SessionService::new(
        factory(),
        Arc::new(InMemorySessions::default()),
        digest.clone(),
        Arc::new(SequentialRandom::default()),
        clock,
    );
    let router = public_router(
        Arc::new(Tenants(tenant.clone())),
        Router::new().nest(
            "/interaction",
            invitation_routes(InvitationState {
                invitations: invitations.clone(),
                sessions: sessions.clone(),
                digest,
            }),
        ),
        Router::new(),
        Limits::default(),
    );
    World {
        router,
        invitations,
        identity,
        sessions,
        messages,
        tenant,
        organization,
    }
}

struct Reply {
    status: StatusCode,
    body: serde_json::Value,
}

impl Reply {
    fn code(&self) -> &str {
        self.body["code"].as_str().unwrap_or_default()
    }
}

impl World {
    async fn invite(&self, email: &str) -> String {
        self.invitations
            .invite(
                &self.tenant,
                self.organization,
                email,
                BTreeSet::new(),
                None,
                Caller::system(),
            )
            .await
            .expect("invited");
        let message = self
            .messages
            .of_tenant(self.tenant.tenant_id())
            .pop()
            .expect("a message");
        let link = message.snapshot().variables["link"].clone();
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

    /// A session of `user`: its cookie and its CSRF token.
    async fn session_of(&self, user: UserId) -> (String, String) {
        let (_, token) = self
            .sessions
            .start(
                &self.tenant,
                StartSession {
                    user_id: user,
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
            .expect("a session");
        let mut input = b"csrf:".to_vec();
        input.extend_from_slice(token.expose().as_bytes());
        let csrf = FakeDigest
            .sha256(&input)
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect();
        (token.expose().to_owned(), csrf)
    }

    async fn post(
        &self,
        path: &str,
        body: serde_json::Value,
        session: Option<&(String, String)>,
        origin: Option<&str>,
    ) -> Reply {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(format!("/t/acme/interaction/invitations/{path}"))
            .header(header::HOST, HOST)
            .header(header::CONTENT_TYPE, "application/json");
        if let Some((cookie, csrf)) = session {
            request = request
                .header(header::COOKIE, format!("__Secure-hodor_session={cookie}"))
                .header("x-csrf-token", csrf);
        }
        if let Some(origin) = origin {
            request = request.header(header::ORIGIN, origin);
        }
        let response = self
            .router
            .clone()
            .oneshot(request.body(Body::from(body.to_string())).expect("request"))
            .await
            .expect("response");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        Reply {
            status,
            body: serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        }
    }
}

#[tokio::test]
async fn an_invitation_is_described_and_accepted_with_a_new_account() {
    let world = world().await;
    let token = world.invite("ana@example.com").await;

    let described = world
        .post(
            "describe",
            serde_json::json!({ "token": token }),
            None,
            None,
        )
        .await;
    assert_eq!(described.status, StatusCode::OK);
    assert_eq!(described.body["organization_name"], "Initech");
    assert_eq!(described.body["email"], "ana@example.com");
    assert_eq!(described.body["has_account"], false);
    assert!(
        described.body["expires_at"]
            .as_str()
            .is_some_and(|at| at.ends_with('Z'))
    );

    let without = world
        .post("accept", serde_json::json!({ "token": token }), None, None)
        .await;
    assert_eq!(without.status, StatusCode::UNPROCESSABLE_ENTITY);
    let accepted = world
        .post("accept", serde_json::json!({ "token": token, "password": "correct horse battery staple", "display_name": "Ana" }), None, None)
        .await;
    assert_eq!(accepted.status, StatusCode::NO_CONTENT);
    let again = world
        .post(
            "accept",
            serde_json::json!({ "token": token, "password": "correct horse battery staple" }),
            None,
            None,
        )
        .await;
    assert_eq!(again.status, StatusCode::NOT_FOUND);
    assert_eq!(again.code(), "identity.invitation_invalid");
}

#[tokio::test]
async fn an_address_with_an_account_accepts_signed_in_as_it() {
    let world = world().await;
    let ana = world.person("ana@example.com").await;
    let bruno = world.person("bruno@example.com").await;
    let token = world.invite("ana@example.com").await;

    let anonymous = world
        .post(
            "accept",
            serde_json::json!({ "token": token, "password": "correct horse battery staple" }),
            None,
            None,
        )
        .await;
    assert_eq!(anonymous.status, StatusCode::CONFLICT);
    assert_eq!(anonymous.code(), "authentication.invitation_needs_sign_in");

    let (cookie, _) = world.session_of(bruno).await;
    let forged = world
        .post(
            "accept",
            serde_json::json!({ "token": token }),
            Some(&(cookie, "0".repeat(64))),
            None,
        )
        .await;
    assert_eq!(forged.status, StatusCode::FORBIDDEN);
    assert_eq!(forged.code(), "request.csrf_token_invalid");
    let bruno_session = world.session_of(bruno).await;
    let other = world
        .post(
            "accept",
            serde_json::json!({ "token": token }),
            Some(&bruno_session),
            None,
        )
        .await;
    assert_eq!(other.status, StatusCode::FORBIDDEN);
    assert_eq!(other.code(), "authentication.invitation_for_someone_else");

    let ana_session = world.session_of(ana).await;
    let elsewhere = world
        .post(
            "accept",
            serde_json::json!({ "token": token }),
            Some(&ana_session),
            Some("https://evil.example"),
        )
        .await;
    assert_eq!(
        elsewhere.status,
        StatusCode::FORBIDDEN,
        "another site's page cannot accept for her"
    );
    let accepted = world
        .post(
            "accept",
            serde_json::json!({ "token": token }),
            Some(&ana_session),
            None,
        )
        .await;
    assert_eq!(accepted.status, StatusCode::NO_CONTENT);
}
