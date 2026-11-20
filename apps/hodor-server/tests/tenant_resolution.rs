//! The server binary resolving tenants from a real database.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{PgTenantDirectory, PgTenantRepository};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{Actor, CorrelationId, TenantContext, Timestamp};
use hodor_tenant::api::{Caller, CreateTenant, TenantService};
use std::net::TcpListener;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

struct Server {
    process: Child,
    base: String,
}

impl Drop for Server {
    fn drop(&mut self) {
        let _ = self.process.kill();
        let _ = self.process.wait();
    }
}

fn free_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .and_then(|listener| listener.local_addr())
        .expect("a free port")
        .port()
}

async fn start_server(database: &TestDatabase) -> Server {
    let (public, ops) = (free_port(), free_port());
    let process = Command::new(env!("CARGO_BIN_EXE_hodor-server"))
        .env("HODOR_DATABASE_URL", database.app_url())
        .env("HODOR_LISTEN_ADDR", format!("127.0.0.1:{public}"))
        .env("HODOR_OPS_ADDR", format!("127.0.0.1:{ops}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("the server should start");
    let server = Server {
        process,
        base: format!("http://127.0.0.1:{public}"),
    };
    let ready = format!("http://127.0.0.1:{ops}/readyz");
    for _ in 0..100 {
        if reqwest::get(&ready)
            .await
            .is_ok_and(|r| r.status().is_success())
        {
            return server;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("the server did not become ready");
}

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
