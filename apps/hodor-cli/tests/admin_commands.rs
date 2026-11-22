//! The bootstrap command, run as the real binary against a real database.

use hodor_adapters_crypto::{OsRandom, Sha256Digest};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgAccessTokenStore, PgRoleAssignmentStore, PgTenantDirectory, PgTenantRepository,
    PgUserRepository,
};
use hodor_authorization::api::{AuthorizationService, Permission};
use hodor_credential::api::AccessTokenService;
use hodor_identity::api::IdentityService;
use hodor_kernel::{Actor, Caller, CorrelationId, SystemClock, TenantContext, UserId};
use hodor_tenant::api::TenantService;
use std::collections::BTreeMap;
use std::process::{Command, Output};
use std::sync::Arc;

fn cli(database: &TestDatabase, arguments: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_hodor-cli"))
        .args(arguments)
        .env("HODOR_DATABASE_URL", database.app_url())
        .output()
        .expect("the command-line tool should run")
}

fn text(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).trim().to_owned()
}

/// What a successful bootstrap printed, by the first word of each line.
fn printed(output: &Output) -> BTreeMap<String, String> {
    assert!(output.status.success(), "{}", text(&output.stderr));
    text(&output.stdout)
        .lines()
        .filter_map(|line| line.split_once(' '))
        .map(|(name, value)| (name.to_owned(), value.to_owned()))
        .collect()
}

fn bootstrap(database: &TestDatabase, tenant: &str, email: &str) -> Output {
    cli(
        database,
        &["admin", "bootstrap", "--tenant", tenant, "--email", email],
    )
}

struct Services {
    tokens: AccessTokenService,
    authorization: AuthorizationService,
    identity: IdentityService,
    tenants: TenantService,
}

fn services(database: &TestDatabase) -> Services {
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(SystemClock);
    Services {
        tokens: AccessTokenService::new(
            units(),
            Arc::new(PgAccessTokenStore),
            Arc::new(Sha256Digest),
            Arc::new(OsRandom),
            clock.clone(),
        ),
        authorization: AuthorizationService::new(
            units(),
            Arc::new(PgRoleAssignmentStore),
            clock.clone(),
        ),
        identity: IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone()),
        tenants: TenantService::new(
            units(),
            Arc::new(PgTenantRepository),
            Arc::new(PgTenantDirectory::new(database.app().clone())),
            clock,
        ),
    }
}

impl Services {
    async fn tenant(&self, slug: &str) -> TenantContext {
        let entry = self
            .tenants
            .find_by_slug(slug)
            .await
            .expect("lookup")
            .expect("the tenant exists");
        TenantContext::assume(entry.tenant_id)
    }

    /// The user a token belongs to in a tenant, if it is good there.
    async fn user_of(&self, tenant: &TenantContext, token: &str) -> Option<UserId> {
        self.tokens
            .authenticate(tenant, token)
            .await
            .expect("authenticate")
            .map(|token| token.user_id())
    }

    async fn may(&self, tenant: &TenantContext, user: UserId, permission: Permission) -> bool {
        self.authorization
            .check(tenant, user, permission)
            .await
            .expect("check")
            .is_allowed()
    }
}

fn create_tenants(database: &TestDatabase) {
    for slug in ["acme", "globex"] {
        let created = cli(
            database,
            &["tenant", "create", "--slug", slug, "--name", slug],
        );
        assert!(created.status.success(), "{}", text(&created.stderr));
    }
}

#[tokio::test]
async fn the_first_administrator_gets_a_role_and_a_token_that_work_in_their_tenant_only() {
    let database = TestDatabase::start().await;
    create_tenants(&database);

    let output = printed(&bootstrap(&database, "acme", "Ana@Example.com"));

    assert_eq!(output["role"], "tenant_administrator");
    let token = &output["token"];
    assert!(
        token.starts_with("hodor_at_") && token.len() == 73,
        "{token}"
    );
    assert!(
        output["user"].ends_with(" Ana@Example.com"),
        "{}",
        output["user"]
    );
    // To the second, in the form `2026-11-21T15:03:11Z`.
    assert_eq!(output["expires"].len(), 20, "{}", output["expires"]);
    assert!(output["expires"].ends_with('Z'), "{}", output["expires"]);
    let user: UserId = output["user"]
        .split(' ')
        .next()
        .expect("identifier")
        .parse()
        .expect("a user identifier");

    let services = services(&database);
    let (acme, globex) = (
        services.tenant("acme").await,
        services.tenant("globex").await,
    );
    // In its own tenant the token names the user, who may do everything.
    assert_eq!(services.user_of(&acme, token).await, Some(user));
    for permission in Permission::ALL {
        assert!(services.may(&acme, user, permission).await);
    }
    // In another tenant the token is not known, and neither the role nor
    // the user exists there.
    assert_eq!(services.user_of(&globex, token).await, None);
    assert!(!services.may(&globex, user, Permission::UsersRead).await);
    assert!(services.identity.get(&globex, user).await.is_err());

    // The token is stored only as a hash, and what happened was announced
    // with Hodor itself as the actor.
    let (stored, announced): (String, String) = sqlx::query_as(
        "SELECT (SELECT string_agg(to_jsonb(t)::text, '') FROM credential.access_token t),
                (SELECT string_agg(event_type || ' ' || actor::text, ';' ORDER BY created_at, id)
                 FROM platform.outbox WHERE event_type NOT LIKE 'tenant.%')",
    )
    .fetch_one(database.owner())
    .await
    .expect("read");
    assert!(!stored.contains(token.as_str()) && !stored.contains(&token[9..]));
    for event in [
        "identity.user_created",
        "authorization.role_assigned",
        "credential.access_token_issued",
    ] {
        assert!(announced.contains(event), "{announced}");
    }
    assert!(!announced.contains("\"user\""), "{announced}");
    assert!(!announced.contains(token.as_str()));
}

#[tokio::test]
async fn running_it_again_issues_another_token_for_the_same_user() {
    let database = TestDatabase::start().await;
    create_tenants(&database);

    let first = printed(&bootstrap(&database, "acme", "ana@example.com"));
    let second = printed(&bootstrap(&database, "acme", "ANA@example.com"));

    assert_eq!(
        first["user"].split(' ').next(),
        second["user"].split(' ').next(),
        "the same person"
    );
    assert_ne!(first["token"], second["token"]);
    let services = services(&database);
    let acme = services.tenant("acme").await;
    assert!(services.user_of(&acme, &first["token"]).await.is_some());
    assert!(services.user_of(&acme, &second["token"]).await.is_some());
    let (users, roles, tokens): (i64, i64, i64) = sqlx::query_as(
        "SELECT (SELECT count(*) FROM identity.\"user\"),
                (SELECT count(*) FROM \"authorization\".role_assignment),
                (SELECT count(*) FROM credential.access_token)",
    )
    .fetch_one(database.owner())
    .await
    .expect("count");
    assert_eq!((users, roles, tokens), (1, 1, 2));
}

#[tokio::test]
async fn the_token_lives_as_long_as_asked_within_the_limits() {
    let database = TestDatabase::start().await;
    create_tenants(&database);
    let with_minutes = |minutes: &'static str| {
        cli(
            &database,
            &[
                "admin",
                "bootstrap",
                "--tenant",
                "acme",
                "--email",
                "ana@example.com",
                "--token-minutes",
                minutes,
            ],
        )
    };

    printed(&with_minutes("5"));
    let lifetime: f64 = sqlx::query_scalar(
        "SELECT extract(epoch FROM expires_at - created_at)::float8 FROM credential.access_token",
    )
    .fetch_one(database.owner())
    .await
    .expect("read");
    assert!((lifetime - 300.0).abs() < 1.0, "{lifetime}");

    for minutes in ["0", "43201"] {
        let refused = with_minutes(minutes);
        assert!(!refused.status.success(), "{minutes} minutes");
        assert!(
            text(&refused.stderr).contains("credential.access_token_lifetime_invalid"),
            "{}",
            text(&refused.stderr)
        );
    }
}

#[tokio::test]
async fn what_cannot_work_is_refused_with_the_reason() {
    let database = TestDatabase::start().await;
    create_tenants(&database);

    let unknown = bootstrap(&database, "nobody", "ana@example.com");
    assert!(!unknown.status.success());
    assert!(text(&unknown.stderr).contains("tenant.not_found"));

    let not_an_address = bootstrap(&database, "acme", "ana");
    assert!(!not_an_address.status.success());
    assert!(text(&not_an_address.stdout).is_empty());

    // A user who may not sign in gets no token: it would not work.
    let created = printed(&bootstrap(&database, "acme", "ana@example.com"));
    let user: UserId = created["user"]
        .split(' ')
        .next()
        .expect("identifier")
        .parse()
        .expect("a user identifier");
    let services = services(&database);
    let acme = services.tenant("acme").await;
    let caller = Caller {
        actor: Actor::System,
        correlation_id: CorrelationId::generate(),
    };
    services
        .identity
        .suspend(&acme, user, "left the company", caller)
        .await
        .expect("suspended");
    let suspended = bootstrap(&database, "acme", "ana@example.com");
    assert!(!suspended.status.success());
    assert!(
        text(&suspended.stderr).contains("identity.user_may_not_sign_in"),
        "{}",
        text(&suspended.stderr)
    );
    assert!(!text(&suspended.stdout).contains("hodor_at_"));
}
