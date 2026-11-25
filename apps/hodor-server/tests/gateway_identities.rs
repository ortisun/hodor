//! Hodor inside a service mesh, against the real server binary and a real
//! database: behind the proxy beside Hodor, the forwarded address is read
//! only from a request whose caller is one of the ingress gateways the
//! operator names, and the server refuses gateways it could never
//! recognize.
//!
//! The tests connect from 127.0.0.1, which plays the proxy in Hodor's pod:
//! the server trusts it, and the tests write the header of the caller's
//! identity as that proxy would.
//!
//! Specified in `docs/api/api-spec.md`, "Behind the proxy of a service
//! mesh", and Decision 0061.

use hodor_adapters_crypto::{Argon2Parameters, Argon2idHasher, HashingLimits, OsRandom};
use hodor_adapters_postgres::testing::TestDatabase;
use hodor_adapters_postgres::{
    PgPasswordStore, PgTenantDirectory, PgTenantRepository, PgUserRepository,
};
use hodor_credential::api::{CredentialService, NewPassword, PasswordRules};
use hodor_identity::api::{CreateUser, IdentifierKind, IdentityService, Profile, UserKind};
use hodor_kernel::{Caller, Secret, SystemClock, TenantContext};
use hodor_tenant::api::{CreateTenant, TenantService};
use reqwest::StatusCode;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use std::process::{Command, Stdio};
use std::sync::Arc;
use std::time::Duration;

mod support;
use support::{Browser, MEMORY_KIBIBYTES, PASSES, Server, start_server_with};

const PASSWORD: &str = "correct horse battery staple";
const ISTIO_GATEWAY: &str =
    "spiffe://cluster.local/ns/istio-system/sa/istio-ingressgateway-service-account";
const ISTIO_WORKLOAD: &str = "spiffe://cluster.local/ns/shop/sa/web";
const LINKERD_GATEWAY: &str = "gateway.edge.serviceaccount.identity.linkerd.cluster.local";
const LINKERD_WORKLOAD: &str = "web.shop.serviceaccount.identity.linkerd.cluster.local";
/// More failed attempts than any one address may make: ten times the
/// identifier's five, with room to spare.
const MOST_ATTEMPTS: usize = 80;

/// A tenant `acme` with one confirmed person, Ana, who has a password.
async fn tenant_with_ana(database: &TestDatabase) {
    let units = || Arc::new(database.app().clone());
    let clock = Arc::new(SystemClock);
    let created = TenantService::new(
        units(),
        Arc::new(PgTenantRepository),
        Arc::new(PgTenantDirectory::new(database.app().clone())),
        clock.clone(),
    )
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
    .expect("tenant");
    let tenant = TenantContext::assume(created.id());
    let ana = IdentityService::new(units(), Arc::new(PgUserRepository), clock.clone())
        .create(
            &tenant,
            CreateUser {
                kind: UserKind::Human,
                identifiers: vec![(IdentifierKind::Email, "ana@example.com".to_owned())],
                profile: Profile::default(),
                confirmed: true,
            },
            Caller::system(),
        )
        .await
        .expect("user")
        .id();
    let hasher = Argon2idHasher::new(
        Argon2Parameters {
            memory_kibibytes: MEMORY_KIBIBYTES,
            passes: PASSES,
            lanes: 1,
        },
        HashingLimits {
            concurrent: 2,
            queued: 8,
        },
        Arc::new(OsRandom),
    )
    .expect("hasher");
    let password = Secret::from(PASSWORD.to_owned());
    CredentialService::new(units(), Arc::new(PgPasswordStore), Arc::new(hasher), clock)
        .set_password(
            &tenant,
            ana,
            NewPassword {
                password: &password,
                rules: PasswordRules {
                    min_length: 12,
                    max_length: 128,
                    history_depth: 5,
                },
                own_names: &[],
            },
            false,
            Caller::system(),
        )
        .await
        .expect("password");
}

/// How the proxy in Hodor's pod names the caller.
#[derive(Clone, Copy)]
enum Mesh {
    /// Istio's sidecar: an `X-Forwarded-Client-Cert` element of its own.
    Istio,
    /// Linkerd's proxy: `l5d-client-id`.
    Linkerd,
}

impl Mesh {
    const fn identity_header(self) -> &'static str {
        match self {
            Self::Istio => "x-forwarded-client-cert",
            Self::Linkerd => "l5d-client-id",
        }
    }

    const fn gateway(self) -> &'static str {
        match self {
            Self::Istio => ISTIO_GATEWAY,
            Self::Linkerd => LINKERD_GATEWAY,
        }
    }

    const fn workload(self) -> &'static str {
        match self {
            Self::Istio => ISTIO_WORKLOAD,
            Self::Linkerd => LINKERD_WORKLOAD,
        }
    }

    /// The header the proxy writes for a caller of this identity, as it
    /// would arrive: with Istio, after an element the caller forged naming
    /// the gateway, which must never be read.
    fn caller(self, identity: &str) -> (HeaderName, HeaderValue) {
        let value = match self {
            Self::Istio => format!(
                "URI={ISTIO_GATEWAY},By=spiffe://cluster.local/ns/hodor/sa/hodor;Hash=00;\
                 Subject=\"\";URI={identity}"
            ),
            Self::Linkerd => identity.to_owned(),
        };
        (
            HeaderName::from_static(self.identity_header()),
            HeaderValue::from_str(&value).expect("a value"),
        )
    }

    /// Serves Hodor behind this mesh's proxy, with its gateway named.
    async fn serve(self, database: &TestDatabase) -> Server {
        start_server_with(
            database,
            &[
                ("HODOR_TRUSTED_PROXIES", "127.0.0.1"),
                ("HODOR_FORWARDED_HEADER", "x-forwarded-for"),
                ("HODOR_CLIENT_IDENTITY_HEADER", self.identity_header()),
                ("HODOR_GATEWAY_IDENTITIES", self.gateway()),
            ],
        )
        .await
    }
}

/// A browser whose every request carries `X-Forwarded-For: forwarded` and,
/// when given, the header of the caller's identity.
fn browser(server: &Server, forwarded: &str, caller: Option<(HeaderName, HeaderValue)>) -> Browser {
    let mut headers = HeaderMap::new();
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_str(forwarded).expect("a value"),
    );
    if let Some((name, value)) = caller {
        headers.insert(name, value);
    }
    let mut browser = Browser::new(server);
    browser.client = reqwest::Client::builder()
        .default_headers(headers)
        .build()
        .expect("client");
    browser
}

/// Fails passwords, each time for another identifier so that no identifier
/// is locked out, until the address they are counted against is. Answers
/// how many attempts that took.
async fn fail_until_locked_out(make: impl Fn(usize) -> Browser) -> usize {
    for attempt in 1..=MOST_ATTEMPTS {
        let (status, body) = make(attempt)
            .sign_in(
                "acme",
                &format!("nobody{attempt}@example.com"),
                "a wrong guess",
            )
            .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(body["code"], "authentication.too_many_attempts");
            return attempt;
        }
        assert_eq!(
            body["status"], "rejected",
            "attempt {attempt}: {status} {body}"
        );
    }
    panic!("never locked out after {MOST_ATTEMPTS} attempts");
}

/// Signs Ana in with her own password, answering the status.
async fn ana_signs_in(mut browser: Browser) -> StatusCode {
    let (status, body) = browser.sign_in("acme", "ana@example.com", PASSWORD).await;
    if status == StatusCode::OK {
        assert_eq!(body["status"], "completed", "{body}");
    }
    status
}

/// The acceptance of Issue-112 for one mesh: behind its gateway two clients
/// have separate lockouts; a forwarded address sent by any other workload
/// is ignored; the forwarded address is ignored when the identity header
/// is absent.
async fn each_client_is_limited_apart_behind(mesh: Mesh) {
    let database = TestDatabase::start().await;
    tenant_with_ana(&database).await;
    let server = mesh.serve(&database).await;
    let through_gateway =
        |client: &str| browser(&server, client, Some(mesh.caller(mesh.gateway())));

    // Behind the gateway, one client fails until its address is locked
    // out, and stays locked out even with the right password.
    let attempts = fail_until_locked_out(|_| through_gateway("203.0.113.7")).await;
    assert!(
        attempts > 5,
        "the address, not an identifier, was locked out"
    );
    assert_eq!(
        ana_signs_in(through_gateway("203.0.113.7")).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    // Another client behind the same gateway has a lockout of its own.
    assert_eq!(
        ana_signs_in(through_gateway("203.0.113.8")).await,
        StatusCode::OK
    );

    // Any other workload of the mesh writes a new address on every
    // attempt. It is ignored: every attempt counts against the proxy's
    // address, which is locked out as one client.
    let workload = |attempt: usize| {
        browser(
            &server,
            &format!("198.51.100.{attempt}"),
            Some(mesh.caller(mesh.workload())),
        )
    };
    let attempts = fail_until_locked_out(workload).await;
    assert!(
        attempts > 5,
        "the address, not an identifier, was locked out"
    );

    // With no header of the caller's identity, the forwarded address is
    // ignored too: a fresh address is the proxy's, locked out.
    assert_eq!(
        ana_signs_in(browser(&server, "192.0.2.99", None)).await,
        StatusCode::TOO_MANY_REQUESTS
    );
    // The clients behind the gateway are not touched by it.
    assert_eq!(
        ana_signs_in(through_gateway("203.0.113.9")).await,
        StatusCode::OK
    );
}

#[tokio::test]
async fn behind_istio_each_client_of_the_gateway_is_limited_apart() {
    each_client_is_limited_apart_behind(Mesh::Istio).await;
}

#[tokio::test]
async fn behind_linkerd_each_client_of_the_gateway_is_limited_apart() {
    each_client_is_limited_apart_behind(Mesh::Linkerd).await;
}

/// Starts the server with `settings` and answers what it wrote, once it has
/// stopped by itself. It must stop before it connects to any database.
fn refused(settings: &[(&str, &str)]) -> String {
    let mut process = Command::new(env!("CARGO_BIN_EXE_hodor-server"))
        .envs(settings.iter().copied())
        .env(
            "HODOR_DATABASE_URL",
            "postgres://nobody:nothing@127.0.0.1:1/none",
        )
        .env("HODOR_LISTEN_ADDR", "127.0.0.1:0")
        .env("HODOR_OPS_ADDR", "127.0.0.1:0")
        .env("HODOR_LOG_FORMAT", "pretty")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("the server should start");
    for _ in 0..300 {
        if process.try_wait().expect("status").is_some() {
            let output = process.wait_with_output().expect("output");
            assert!(!output.status.success(), "the server started");
            return format!(
                "{}{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    let _ = process.kill();
    panic!("the server did not stop by itself");
}

#[test]
fn the_server_refuses_gateways_it_could_never_recognize() {
    let usable = [
        ("HODOR_TRUSTED_PROXIES", "127.0.0.6"),
        ("HODOR_CLIENT_IDENTITY_HEADER", "x-forwarded-client-cert"),
        ("HODOR_GATEWAY_IDENTITIES", ISTIO_GATEWAY),
    ];
    let without = |name: &str, value: &str| -> Vec<(String, String)> {
        usable
            .iter()
            .map(|(setting, given)| {
                let given = if *setting == name { value } else { given };
                ((*setting).to_owned(), given.to_owned())
            })
            .collect()
    };
    for (settings, said) in [
        (
            without(
                "HODOR_GATEWAY_IDENTITIES",
                "spiffe://cluster.local/ns/istio-system/sa/*",
            ),
            "HODOR_GATEWAY_IDENTITIES: `spiffe://cluster.local/ns/istio-system/sa/*`",
        ),
        (
            without(
                "HODOR_GATEWAY_IDENTITIES",
                "istio-ingressgateway.istio-system",
            ),
            "is neither a SPIFFE identifier nor a Linkerd identity",
        ),
        (without("HODOR_TRUSTED_PROXIES", ""), "no proxy is trusted"),
        (
            without("HODOR_CLIENT_IDENTITY_HEADER", ""),
            "no header of the caller's identity is named",
        ),
        (
            [
                without("HODOR_FORWARDED_HEADER", "").as_slice(),
                &[("HODOR_FORWARDED_HEADER".to_owned(), "none".to_owned())],
            ]
            .concat(),
            "HODOR_FORWARDED_HEADER is none",
        ),
    ] {
        let settings: Vec<(&str, &str)> = settings
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let written = refused(&settings);
        assert!(
            written.contains(said),
            "{settings:?} should say {said:?}, and said:\n{written}"
        );
    }
}
