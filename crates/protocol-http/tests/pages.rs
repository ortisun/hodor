//! How the hosted pages are served, exercised through the router with a
//! directory the test makes. The application itself is not needed.

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use hodor_kernel::{DomainError, TenantContext, TenantId};
use hodor_protocol_http::{
    CONSOLE_ASSETS_PATH, CONSOLE_CONTENT_SECURITY_POLICY, CONSOLE_PATHS, Limits, PAGE_PATHS,
    PAGES_CONTENT_SECURITY_POLICY, Pages, ResolvedTenant, SIGNED_OUT_PAGE, TenantResolver, TenantStatus,
    public_router,
};
use http_body_util::BodyExt as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tower::ServiceExt as _;

const INDEX: &str = "<!doctype html><title>the application</title>";
const SCRIPT: &str = "console.log('the application');";
const SECRET: &str = "outside the directory";

struct Tenants;

#[async_trait::async_trait]
impl TenantResolver for Tenants {
    async fn resolve(&self, slug: &str) -> Result<Option<ResolvedTenant>, DomainError> {
        Ok(match slug {
            "acme" => Some(ResolvedTenant {
                context: TenantContext::assume(TenantId::generate()),
                status: TenantStatus::Active,
            }),
            "frozen" => Some(ResolvedTenant {
                context: TenantContext::assume(TenantId::generate()),
                status: TenantStatus::Suspended,
            }),
            _ => None,
        })
    }
}

/// A built application on disk, removed when the test ends. Next to it,
/// outside the directory the server is given, lies a file that must never
/// be served.
struct Built {
    root: PathBuf,
}

impl Built {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("hodor-pages-{}", TenantId::generate()));
        let assets = root.join("dist").join("assets");
        std::fs::create_dir_all(assets.join("deeper")).expect("directories");
        std::fs::write(root.join("dist").join("index.html"), INDEX).expect("index");
        std::fs::write(assets.join("index-abc123.js"), SCRIPT).expect("script");
        std::fs::write(assets.join("index-abc123.css"), "body{}").expect("style sheet");
        std::fs::write(assets.join("font-abc123.woff2"), [0_u8; 4]).expect("font");
        std::fs::write(root.join("secret.txt"), SECRET).expect("secret");
        Self { root }
    }

    fn directory(&self) -> PathBuf {
        self.root.join("dist")
    }

    fn router(&self) -> Router {
        let pages = Pages::load(&self.directory()).expect("pages");
        public_router(
            Arc::new(Tenants),
            pages.page_routes(),
            pages.asset_routes(),
            Limits::default(),
        )
    }
}

impl Drop for Built {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: String,
}

impl Reply {
    fn header(&self, name: header::HeaderName) -> &str {
        self.headers
            .get(&name)
            .map_or("", |value| value.to_str().expect("ASCII header"))
    }

    fn code(&self) -> String {
        let body: serde_json::Value = serde_json::from_str(&self.body).expect("JSON body");
        body["code"].as_str().unwrap_or_default().to_owned()
    }
}

async fn send(router: &Router, method: Method, path: &str) -> Reply {
    let request = Request::builder()
        .method(method)
        .uri(path)
        .body(Body::empty())
        .expect("request");
    let response = router.clone().oneshot(request).await.expect("response");
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.expect("body").to_bytes();
    Reply {
        status: parts.status,
        headers: parts.headers,
        body: String::from_utf8_lossy(&bytes).into_owned(),
    }
}

async fn get(router: &Router, path: &str) -> Reply {
    send(router, Method::GET, path).await
}

#[tokio::test]
async fn every_page_is_answered_with_the_application_and_its_policy() {
    let built = Built::new();
    let router = built.router();

    for path in PAGE_PATHS {
        let reply = get(&router, &format!("/t/acme{path}")).await;
        assert_eq!(reply.status, StatusCode::OK, "{path}");
        assert_eq!(reply.body, INDEX, "{path}");
        assert_eq!(
            reply.header(header::CONTENT_TYPE),
            "text/html; charset=utf-8"
        );
        assert_eq!(
            reply.header(header::CONTENT_SECURITY_POLICY),
            PAGES_CONTENT_SECURITY_POLICY
        );
        assert_eq!(reply.header(header::CACHE_CONTROL), "no-cache");
        // What every response carries is still there.
        assert_eq!(reply.header(header::X_CONTENT_TYPE_OPTIONS), "nosniff");
        assert_eq!(reply.header(header::X_FRAME_OPTIONS), "DENY");
        assert_eq!(reply.header(header::REFERRER_POLICY), "no-referrer");
        assert!(!reply.header(header::STRICT_TRANSPORT_SECURITY).is_empty());
    }
}

/// The signed-out page is the application too. Without front-channel
/// logout it is sent with the pages' own policy, which allows no frame, and
/// never kept by a cache: it is made for one browser's sign-out.
#[tokio::test]
async fn the_signed_out_page_is_the_application_and_allows_no_frame_by_itself() {
    let built = Built::new();
    let router = built.router();
    let reply = get(&router, &format!("/t/acme{SIGNED_OUT_PAGE}")).await;
    assert_eq!(reply.status, StatusCode::OK);
    assert_eq!(reply.body, INDEX);
    assert_eq!(
        reply.header(header::CONTENT_SECURITY_POLICY),
        PAGES_CONTENT_SECURITY_POLICY
    );
    assert!(
        !reply
            .header(header::CONTENT_SECURITY_POLICY)
            .contains("frame-src")
    );
    assert_eq!(reply.header(header::CACHE_CONTROL), "no-store");
    assert_eq!(reply.header(header::X_FRAME_OPTIONS), "DENY");
    // The console has no such page.
    let console = Pages::load_console(&built.directory()).expect("console");
    let console = public_router(
        Arc::new(Tenants),
        console.page_routes(),
        console.asset_routes(),
        Limits::default(),
    );
    assert_eq!(
        get(&console, &format!("/t/acme{SIGNED_OUT_PAGE}"))
            .await
            .status,
        StatusCode::NOT_FOUND
    );
}

/// The directives of a content security policy, by name.
fn directives(policy: &str) -> Vec<(&str, &str)> {
    policy
        .split(';')
        .map(|directive| {
            let directive = directive.trim();
            directive.split_once(' ').unwrap_or((directive, ""))
        })
        .collect()
}

fn directive<'a>(directives: &[(&'a str, &'a str)], name: &str) -> Option<&'a str> {
    directives
        .iter()
        .find(|(directive, _)| *directive == name)
        .map(|(_, value)| *value)
}

fn assert_nothing_inline(policy: &str, images: &str) {
    let directives = directives(policy);
    let value = |name: &str| directive(&directives, name);
    assert_eq!(value("default-src"), Some("'none'"));
    for name in ["script-src", "style-src", "font-src", "connect-src"] {
        assert_eq!(value(name), Some("'self'"), "{name}");
    }
    assert_eq!(value("img-src"), Some(images));
    assert_eq!(value("form-action"), Some("'none'"));
    assert_eq!(value("base-uri"), Some("'none'"));
    assert_eq!(value("frame-ancestors"), Some("'none'"));
    assert_eq!(value("require-trusted-types-for"), Some("'script'"));
    assert_eq!(value("trusted-types"), Some("'none'"));
    for forbidden in ["unsafe", "http:", "data:", "blob:", "*"] {
        assert!(!policy.contains(forbidden), "{forbidden}");
    }
}

#[test]
fn the_policy_allows_nothing_inline_and_nothing_from_elsewhere() {
    // The hosted pages load images from any HTTPS address, for the logo of
    // a client that registered itself on the consent page; nothing else
    // comes from elsewhere.
    assert_nothing_inline(PAGES_CONTENT_SECURITY_POLICY, "'self' https:");
    assert_eq!(PAGES_CONTENT_SECURITY_POLICY.matches("https:").count(), 1);
    // The console loads nothing from elsewhere, images included.
    assert_nothing_inline(CONSOLE_CONTENT_SECURITY_POLICY, "'self'");
    assert!(!CONSOLE_CONTENT_SECURITY_POLICY.contains("https:"));
}

#[tokio::test]
async fn the_page_a_provider_sends_people_back_to_is_the_application_too() {
    let built = Built::new();
    let router = built.router();

    // Whatever the provider added to the address, the page is the same.
    for path in [
        "/t/acme/account/providers/example/callback",
        "/t/acme/account/providers/example/callback?code=abc&state=def",
        "/t/acme/account/providers/example/callback?error=access_denied",
    ] {
        let reply = get(&router, path).await;
        assert_eq!(reply.status, StatusCode::OK, "{path}");
        assert_eq!(reply.body, INDEX, "{path}");
        assert_eq!(
            reply.header(header::CONTENT_SECURITY_POLICY),
            PAGES_CONTENT_SECURITY_POLICY
        );
        // The address carries a code: it is sent to no other site.
        assert_eq!(reply.header(header::REFERRER_POLICY), "no-referrer");
    }
    for path in [
        "/t/acme/account/providers/example",
        "/t/acme/account/providers/example/callback/more",
        "/t/acme/account/providers/a/b/callback",
    ] {
        let reply = get(&router, path).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
    }
    let post = send(
        &router,
        Method::POST,
        "/t/acme/account/providers/example/callback",
    )
    .await;
    assert_eq!(post.status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn other_paths_under_account_are_not_found() {
    let built = Built::new();
    let router = built.router();

    for path in [
        "/t/acme/account/elsewhere",
        "/t/acme/account/sign-in/more",
        "/t/acme/account/index.html",
        "/t/acme/accounts",
        "/t/acme/index.html",
        "/account/sign-in",
        "/index.html",
    ] {
        let reply = get(&router, path).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(reply.code(), "route.not_found", "{path}");
    }
}

#[tokio::test]
async fn a_page_is_only_read_never_written_to() {
    let built = Built::new();
    let router = built.router();
    let reply = send(&router, Method::POST, "/t/acme/account/sign-in").await;
    assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn tenants_that_do_not_serve_get_no_page() {
    let built = Built::new();
    let router = built.router();

    let unknown = get(&router, "/t/nobody/account/sign-in").await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
    assert_eq!(unknown.code(), "tenant.not_found");
    assert!(!unknown.body.contains("the application"));

    let suspended = get(&router, "/t/frozen/account/sign-in").await;
    assert_eq!(suspended.status, StatusCode::FORBIDDEN);
    assert_eq!(suspended.code(), "tenant.suspended");
}

#[tokio::test]
async fn files_are_served_with_their_kind_and_kept_for_good() {
    let built = Built::new();
    let router = built.router();

    for (file, kind) in [
        ("index-abc123.js", "text/javascript"),
        ("index-abc123.css", "text/css"),
        ("font-abc123.woff2", "font/woff2"),
    ] {
        let reply = get(&router, &format!("/auth-ui/assets/{file}")).await;
        assert_eq!(reply.status, StatusCode::OK, "{file}");
        assert!(
            reply.header(header::CONTENT_TYPE).starts_with(kind),
            "{file}: {}",
            reply.header(header::CONTENT_TYPE)
        );
        assert_eq!(
            reply.header(header::CACHE_CONTROL),
            "public, max-age=31536000, immutable",
            "{file}"
        );
        // A file opened on its own does nothing: it carries the policy of
        // every other response, which allows nothing.
        assert_eq!(
            reply.header(header::CONTENT_SECURITY_POLICY),
            "default-src 'none'; frame-ancestors 'none'"
        );
        assert_eq!(reply.header(header::X_CONTENT_TYPE_OPTIONS), "nosniff");
    }
    let script = get(&router, "/auth-ui/assets/index-abc123.js").await;
    assert_eq!(script.body, SCRIPT);
}

#[tokio::test]
async fn what_is_not_a_file_of_the_application_is_not_found() {
    let built = Built::new();
    let router = built.router();

    for path in [
        "/auth-ui/assets/missing.js",
        "/auth-ui/assets/",
        "/auth-ui/assets",
        "/auth-ui/assets/deeper",
        "/auth-ui/assets/deeper/",
        "/auth-ui/index.html",
        "/auth-ui/",
    ] {
        let reply = get(&router, path).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
        assert_eq!(reply.code(), "route.not_found", "{path}");
        assert_eq!(reply.header(header::CACHE_CONTROL), "no-store", "{path}");
    }
}

#[tokio::test]
async fn a_path_cannot_climb_out_of_the_directory() {
    let built = Built::new();
    let router = built.router();

    for path in [
        "/auth-ui/assets/../index.html",
        "/auth-ui/assets/../../secret.txt",
        "/auth-ui/assets/%2e%2e/%2e%2e/secret.txt",
        "/auth-ui/assets/..%2f..%2fsecret.txt",
        "/auth-ui/assets/%2e%2e%5c%2e%2e%5csecret.txt",
        "/auth-ui/assets//etc/passwd",
        "/auth-ui/assets/deeper/../../../secret.txt",
    ] {
        let reply = get(&router, path).await;
        assert_eq!(reply.status, StatusCode::NOT_FOUND, "{path}");
        assert!(!reply.body.contains(SECRET), "{path}");
        assert!(!reply.body.contains("the application"), "{path}");
    }
}

#[tokio::test]
async fn a_file_is_only_read_never_written_to() {
    let built = Built::new();
    let router = built.router();
    for method in [Method::POST, Method::PUT, Method::DELETE] {
        let reply = send(&router, method.clone(), "/auth-ui/assets/index-abc123.js").await;
        assert_eq!(reply.status, StatusCode::METHOD_NOT_ALLOWED, "{method}");
    }
    assert!(built.directory().join("assets/index-abc123.js").exists());
}

#[test]
fn a_directory_without_the_application_is_refused_by_name() {
    let missing = Path::new("/nonexistent/hodor-pages");
    let error = Pages::load(missing).expect_err("no index.html");
    assert!(
        error.to_string().contains("/nonexistent/hodor-pages"),
        "{error}"
    );
}

/// The admin console is served as the hosted pages are, at its own
/// addresses, and the two applications stay apart.
#[tokio::test]
async fn the_console_is_another_application_at_its_own_addresses() {
    let built = Built::new();
    let pages = Pages::load(&built.directory()).expect("pages");
    let console_built = Built::new();
    std::fs::write(
        console_built.directory().join("index.html"),
        "<p>console</p>",
    )
    .expect("index");
    let console = Pages::load_console(&console_built.directory()).expect("console");
    let router = public_router(
        Arc::new(Tenants),
        pages.page_routes().merge(console.page_routes()),
        pages.asset_routes().merge(console.asset_routes()),
        Limits::default(),
    );

    for path in CONSOLE_PATHS {
        let path = path
            .replace("{user}", "0193f1c2-0000-7000-8000-000000000001")
            .replace("{provider}", "0193f1c2-0000-7000-8000-000000000002")
            .replace("{application}", "0193f1c2-0000-7000-8000-000000000003")
            .replace("{client}", "0193f1c2-0000-7000-8000-000000000004")
            .replace("{group}", "0193f1c2-0000-7000-8000-000000000005")
            .replace("{organization}", "0193f1c2-0000-7000-8000-000000000006")
            .replace("{service_account}", "0193f1c2-0000-7000-8000-000000000007")
            .replace("{agent}", "0193f1c2-0000-7000-8000-000000000008")
            .replace("{endpoint}", "0193f1c2-0000-7000-8000-000000000009")
            .replace("{trust_domain}", "0193f1c2-0000-7000-8000-00000000000a");
        assert!(
            !path.contains('{'),
            "{path} names a part the test does not fill"
        );
        let reply = get(&router, &format!("/t/acme{path}")).await;
        assert_eq!(reply.status, StatusCode::OK, "{path}");
        assert_eq!(reply.body, "<p>console</p>", "{path}");
        assert_eq!(
            reply.header(header::CONTENT_SECURITY_POLICY),
            CONSOLE_CONTENT_SECURITY_POLICY,
            "{path}"
        );
        assert_eq!(reply.header(header::CACHE_CONTROL), "no-cache", "{path}");
    }

    // A screen the console does not have is not found, and the hosted
    // pages still answer with their own application.
    let reply = get(&router, "/t/acme/console/keys").await;
    assert_eq!(reply.status, StatusCode::NOT_FOUND);
    assert_eq!(get(&router, "/t/acme/account/sign-in").await.body, INDEX);

    let file = get(&router, &format!("{CONSOLE_ASSETS_PATH}/index-abc123.js")).await;
    assert_eq!(file.status, StatusCode::OK);
    assert_eq!(file.body, SCRIPT);
}
