//! The server binary resolving tenants from a real database.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{PgTenantDirectory, PgTenantRepository};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{Actor, CorrelationId, TenantContext, Timestamp};
use hodor_tenant::api::{Caller, CreateTenant, TenantService};
use std::sync::Arc;

mod support;
use support::{Server, start_server};

async fn answer(server: &Server, path: &str) -> (u16, String) {
    let response = reqwest::get(format!("{}{path}", server.base))
        .await
        .expect("response");
    let status = response.status().as_u16();
    let body: serde_json::Value = response.json().await.expect("problem document");
    (status, body["code"].as_str().unwrap_or_default().to_owned())
}

fn caller() -> Caller {
    Caller {
        actor: Actor::System,
        correlation_id: CorrelationId::generate(),
    }
}

#[tokio::test]
async fn requests_are_answered_according_to_the_tenant_status() {
    let database = TestDatabase::start().await;
    let service = TenantService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH)),
    );
    let create = |slug: &str| CreateTenant {
        slug: slug.to_owned(),
        display_name: "Example".to_owned(),
        open_registration: false,
        system: false,
    };
    let server = start_server(&database).await;

    // Unknown before it is created.
    assert_eq!(
        answer(&server, "/t/acme/anything").await,
        (404, "tenant.not_found".to_owned())
    );

    // Active: the tenant is found, and only the route is missing.
    let acme = service
        .create(create("acme"), caller())
        .await
        .expect("create");
    let context = TenantContext::assume(acme.id());
    assert_eq!(
        answer(&server, "/t/acme/anything").await,
        (404, "route.not_found".to_owned())
    );

    // Suspended: refused with a distinct error.
    service
        .suspend(&context, "unpaid", caller())
        .await
        .expect("suspend");
    assert_eq!(
        answer(&server, "/t/acme/anything").await,
        (403, "tenant.suspended".to_owned())
    );

    // Reactivated: served again.
    service
        .reactivate(&context, caller())
        .await
        .expect("reactivate");
    assert_eq!(
        answer(&server, "/t/acme/anything").await,
        (404, "route.not_found".to_owned())
    );

    // Pending deletion: refused like a suspended tenant.
    service
        .schedule_deletion(&context, None, caller())
        .await
        .expect("schedule deletion");
    assert_eq!(
        answer(&server, "/t/acme/anything").await,
        (403, "tenant.suspended".to_owned())
    );

    // Another tenant is unaffected.
    service
        .create(create("globex"), caller())
        .await
        .expect("create");
    assert_eq!(
        answer(&server, "/t/globex/anything").await,
        (404, "route.not_found".to_owned())
    );
}
