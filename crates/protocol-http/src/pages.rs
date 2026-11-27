//! Applications of static files, built elsewhere and served from a
//! directory: the hosted pages (`docs/architecture/hosted-pages.md`) and
//! the admin console (`docs/architecture/admin-console.md`).
//!
//! The same `index.html` answers for every page of every tenant; the
//! application reads the tenant and the page from the address. Its other
//! files are the same for all tenants and are served outside `/t/{slug}`.

use crate::problem::Problem;
use crate::signed_out::{FrontChannel, SIGNED_OUT_PAGE, SignedOutPage, signed_out_page};
use axum::Router;
use axum::extract::{Request, State};
use axum::http::header::{self, HeaderValue};
use axum::http::{Method, StatusCode};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tower_http::services::ServeDir;

/// The paths, under `/t/{slug}`, that are answered with the application.
/// Each is a page the application has; anything else under `/account` is
/// not found. The signed-out page, [`SIGNED_OUT_PAGE`], is answered with
/// the application too, with a policy of its own.
pub const PAGE_PATHS: &[&str] = &[
    "/account",
    "/account/sign-in",
    "/account/register",
    "/account/complete-registration",
    "/account/recover",
    "/account/reset-password",
    "/account/sign-out",
    "/account/security",
    "/account/profile",
    "/account/consent",
    "/account/accept-invitation",
    "/account/sign-in-link",
];

/// The page an identity provider sends a person back to. It is the one
/// page whose path has a part that varies: the provider's alias.
pub const PROVIDER_CALLBACK_PAGE: &str = "/account/providers/{alias}/callback";

/// Where the files of the hosted pages are served, outside any tenant.
pub const PAGE_ASSETS_PATH: &str = "/auth-ui/assets";

/// The paths, under `/t/{slug}`, that are answered with the admin console.
/// Each is a screen the console has.
pub const CONSOLE_PATHS: &[&str] = &[
    "/console",
    "/console/users",
    "/console/users/{user}",
    "/console/audit",
    "/console/identity-providers",
    "/console/identity-providers/{provider}",
    "/console/applications",
    "/console/applications/{application}",
    "/console/clients/{client}",
    "/console/authorization",
    "/console/groups",
    "/console/groups/{group}",
    "/console/organizations",
    "/console/organizations/{organization}",
    "/console/service-accounts",
    "/console/service-accounts/{service_account}",
    "/console/agents",
    "/console/agents/{agent}",
    "/console/webhooks",
    "/console/webhooks/{endpoint}",
    "/console/trust-domains",
    "/console/trust-domains/{trust_domain}",
];

/// Where the files of the admin console are served, outside any tenant.
pub const CONSOLE_ASSETS_PATH: &str = "/admin-console/assets";

/// The policy sent with the page. Everything the page loads comes from
/// files served by this server, but the logo of a client that registered
/// itself, an image at an HTTPS address of its choosing, which the consent
/// page shows; no inline script or style, no `eval`, and no way to turn
/// text into markup or script.
pub const PAGES_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; \
     script-src 'self'; \
     style-src 'self'; \
     font-src 'self'; \
     img-src 'self' https:; \
     connect-src 'self'; \
     form-action 'none'; \
     base-uri 'none'; \
     frame-ancestors 'none'; \
     require-trusted-types-for 'script'; \
     trusted-types 'none'";

/// The policy sent with the admin console: everything it loads comes from
/// files served by this server, images included.
pub const CONSOLE_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; \
     script-src 'self'; \
     style-src 'self'; \
     font-src 'self'; \
     img-src 'self'; \
     connect-src 'self'; \
     form-action 'none'; \
     base-uri 'none'; \
     frame-ancestors 'none'; \
     require-trusted-types-for 'script'; \
     trusted-types 'none'";

/// A changed file has another name, so a browser may keep each one for good.
const ASSET_CACHE_CONTROL: &str = "public, max-age=31536000, immutable";

/// The application, as found in a directory when the server started.
#[derive(Debug, Clone)]
pub struct Pages {
    index: Arc<str>,
    assets: PathBuf,
    paths: &'static [&'static str],
    /// Pages whose path has a part that varies, beside the fixed ones.
    varying: &'static [&'static str],
    assets_path: &'static str,
    policy: &'static str,
    /// Whether the application has the signed-out page: the hosted pages
    /// have it, the console does not.
    signed_out: bool,
    /// What the signed-out page reads its frames through, when this
    /// installation tells clients through the browser.
    front_channel: Option<FrontChannel>,
}

impl Pages {
    /// Reads the hosted pages from `directory`: their `index.html`, kept
    /// in memory, and the place of their other files, `assets`.
    ///
    /// # Errors
    ///
    /// Returns an error naming the directory if `index.html` cannot be
    /// read from it.
    pub fn load(directory: &Path) -> io::Result<Self> {
        let mut pages = Self::read(
            directory,
            PAGE_PATHS,
            &[PROVIDER_CALLBACK_PAGE],
            PAGE_ASSETS_PATH,
            PAGES_CONTENT_SECURITY_POLICY,
        )?;
        pages.signed_out = true;
        Ok(pages)
    }

    /// Sends the signed-out page with a policy that allows the frames the
    /// server kept for the browser's sign-out, read through
    /// `front_channel`. Without it the page is sent with the pages' own
    /// policy, which allows no frame.
    #[must_use]
    pub fn with_front_channel(mut self, front_channel: FrontChannel) -> Self {
        self.front_channel = Some(front_channel);
        self
    }

    /// Reads the admin console from `directory`, as [`Pages::load`] reads
    /// the hosted pages.
    ///
    /// # Errors
    ///
    /// Returns an error naming the directory if `index.html` cannot be
    /// read from it.
    pub fn load_console(directory: &Path) -> io::Result<Self> {
        Self::read(
            directory,
            CONSOLE_PATHS,
            &[],
            CONSOLE_ASSETS_PATH,
            CONSOLE_CONTENT_SECURITY_POLICY,
        )
    }

    fn read(
        directory: &Path,
        paths: &'static [&'static str],
        varying: &'static [&'static str],
        assets_path: &'static str,
        policy: &'static str,
    ) -> io::Result<Self> {
        let index = std::fs::read_to_string(directory.join("index.html")).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!(
                    "the pages directory {} has no readable index.html: {error}",
                    directory.display()
                ),
            )
        })?;
        Ok(Self {
            index: index.into(),
            assets: directory.join("assets"),
            paths,
            varying,
            assets_path,
            policy,
            signed_out: false,
            front_channel: None,
        })
    }

    /// The routes of the pages, to be mounted under `/t/{slug}`.
    pub fn page_routes(&self) -> Router {
        let mut router = Router::new();
        for path in self.paths.iter().chain(self.varying) {
            router = router.route(path, get(page));
        }
        let router = router.with_state((self.index.clone(), self.policy));
        if self.signed_out {
            router.merge(
                Router::new()
                    .route(SIGNED_OUT_PAGE, get(signed_out_page))
                    .with_state(SignedOutPage {
                        index: self.index.clone(),
                        front_channel: self.front_channel.clone(),
                    }),
            )
        } else {
            router
        }
    }

    /// The routes of the application's files, to be mounted at the root.
    pub fn asset_routes(&self) -> Router {
        // A directory is never listed and never answered with a file of
        // its own; `ServeDir` refuses paths that climb out of it.
        let files = ServeDir::new(&self.assets).append_index_html_on_directories(false);
        Router::new()
            .nest_service(self.assets_path, files)
            .layer(middleware::from_fn(asset_answer))
    }
}

async fn page(State((index, policy)): State<(Arc<str>, &'static str)>) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/html; charset=utf-8"),
            (header::CONTENT_SECURITY_POLICY, policy),
            // The browser asks every time whether the page changed: it
            // names the files to load, and those names change.
            (header::CACHE_CONTROL, "no-cache"),
        ],
        index.to_string(),
    )
        .into_response()
}

/// Gives a file its caching, and anything that is not a file the same
/// answer as every other missing route.
async fn asset_answer(request: Request, next: Next) -> Response {
    let reads = matches!(*request.method(), Method::GET | Method::HEAD);
    let mut response = next.run(request).await;
    let status = response.status();
    if reads && (status.is_success() || status == StatusCode::NOT_MODIFIED) {
        response.headers_mut().insert(
            header::CACHE_CONTROL,
            HeaderValue::from_static(ASSET_CACHE_CONTROL),
        );
        return response;
    }
    if status == StatusCode::METHOD_NOT_ALLOWED {
        return response;
    }
    Problem::new(
        StatusCode::NOT_FOUND,
        "route.not_found",
        "the requested resource does not exist",
    )
    .into_response()
}
