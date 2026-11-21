//! The server binary serving the hosted pages from the directory it is
//! told about. The application itself is not needed: the test makes a
//! directory that looks like a built one.

use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{PgTenantDirectory, PgTenantRepository};
use hodor_kernel::{Caller, SystemClock, TenantId};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::StatusCode;
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Arc;

mod support;
use support::{start_server, start_server_with};

const INDEX: &str = "<!doctype html><title>the application</title>";

/// A directory in the shape the build of the pages leaves, removed when
/// the test ends.
struct Built(PathBuf);

impl Built {
    fn new() -> Self {
        let directory =
            std::env::temp_dir().join(format!("hodor-server-pages-{}", TenantId::generate()));
        std::fs::create_dir_all(directory.join("assets")).expect("directory");
        std::fs::write(directory.join("index.html"), INDEX).expect("index");
        std::fs::write(directory.join("assets/index-abc123.js"), "void 0;").expect("script");
        Self(directory)
    }

    fn path(&self) -> &str {
        self.0.to_str().expect("a UTF-8 path")
    }
}

impl Drop for Built {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

async fn create_tenant(database: &TestDatabase, slug: &str) {
    TenantService::new(
        Arc::new(database.app().clone()),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        Arc::new(SystemClock),
    )
    .create(
        CreateTenant {
            slug: slug.to_owned(),
            display_name: "Acme".to_owned(),
            open_registration: true,
            system: false,
        },
        Caller::system(),
    )
    .await
    .expect("tenant");
}

#[tokio::test]
async fn the_server_serves_the_pages_of_the_directory_it_is_given() {
    let database = TestDatabase::start().await;
    create_tenant(&database, "acme").await;
    let built = Built::new();
    let server = start_server_with(&database, &[("HODOR_PAGES_DIRECTORY", built.path())]).await;

    let page = reqwest::get(format!("{}/t/acme/account/sign-in", server.base))
        .await
        .expect("response");
    assert_eq!(page.status(), StatusCode::OK);
    let policy = page.headers()["content-security-policy"]
        .to_str()
        .expect("policy")
        .to_owned();
    assert!(policy.contains("script-src 'self'"), "{policy}");
    assert!(
        policy.contains("require-trusted-types-for 'script'"),
        "{policy}"
    );
    assert_eq!(page.text().await.expect("body"), INDEX);

    let script = reqwest::get(format!("{}/auth-ui/assets/index-abc123.js", server.base))
        .await
        .expect("response");
    assert_eq!(script.status(), StatusCode::OK);
    assert!(
        script.headers()["cache-control"]
            .to_str()
            .expect("caching")
            .contains("immutable")
    );

    // A tenant that does not exist has no pages, like it has nothing else.
    let nobody = reqwest::get(format!("{}/t/nobody/account/sign-in", server.base))
        .await
        .expect("response");
    assert_eq!(nobody.status(), StatusCode::NOT_FOUND);

    // The interaction interface the pages call is on the same origin.
    let session = reqwest::get(format!("{}/t/acme/interaction/session", server.base))
        .await
        .expect("response");
    assert_eq!(session.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn without_a_directory_the_server_serves_no_pages() {
    let database = TestDatabase::start().await;
    create_tenant(&database, "acme").await;
    let server = start_server(&database).await;

    for path in ["/t/acme/account/sign-in", "/auth-ui/assets/index-abc123.js"] {
        let answer = reqwest::get(format!("{}{path}", server.base))
            .await
            .expect("response");
        assert_eq!(answer.status(), StatusCode::NOT_FOUND, "{path}");
    }
}

#[tokio::test]
async fn a_directory_without_the_application_stops_the_server_at_startup() {
    let database = TestDatabase::start().await;
    let output = Command::new(env!("CARGO_BIN_EXE_hodor-server"))
        .env("HODOR_DATABASE_URL", database.app_url())
        .env("HODOR_LISTEN_ADDR", "127.0.0.1:0")
        .env("HODOR_OPS_ADDR", "127.0.0.1:0")
        .env("HODOR_PAGES_DIRECTORY", "/nonexistent/hodor-pages")
        .stdin(Stdio::null())
        .output()
        .expect("the server should run");

    assert!(!output.status.success(), "the server must not start");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(said.contains("/nonexistent/hodor-pages"), "{said}");
}
