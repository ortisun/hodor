//! The published key set, over HTTP, with the keys context on its
//! in-memory store and the stand-in provider.

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, DomainError, TenantContext, TenantId, Timestamp};
use hodor_keys::api::{KeyAlgorithm, KeyService, RotationPolicy};
use hodor_keys::testing::{FakeKeyProvider, InMemoryKeys};
use hodor_protocol_http::{
    Limits, ResolvedTenant, TenantResolver, TenantStatus, key_set_routes, public_router,
};
use http_body_util::BodyExt as _;
use std::sync::Arc;
use tower::ServiceExt as _;

struct Tenants {
    acme: TenantContext,
    globex: TenantContext,
}

#[async_trait::async_trait]
impl TenantResolver for Tenants {
    async fn resolve(&self, slug: &str) -> Result<Option<ResolvedTenant>, DomainError> {
        let context = match slug {
            "acme" => self.acme.clone(),
            "globex" => self.globex.clone(),
            _ => return Ok(None),
        };
        Ok(Some(ResolvedTenant {
            context,
            status: TenantStatus::Active,
        }))
    }
}

struct World {
    router: Router,
    keys: KeyService,
    clock: Arc<FixedClock>,
    acme: TenantContext,
    globex: TenantContext,
}

fn world() -> World {
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    let keys = KeyService::new(
        Arc::new(InMemoryUnitOfWorkFactory::default()),
        Arc::new(InMemoryKeys::default()),
        Arc::new(FakeKeyProvider),
        clock.clone(),
    );
    let acme = TenantContext::assume(TenantId::generate());
    let globex = TenantContext::assume(TenantId::generate());
    let router = public_router(
        Arc::new(Tenants {
            acme: acme.clone(),
            globex: globex.clone(),
        }),
        key_set_routes(keys.clone()),
        Router::new(),
        Limits::default(),
    );
    World {
        router,
        keys,
        clock,
        acme,
        globex,
    }
}

struct Reply {
    status: StatusCode,
    headers: HeaderMap,
    body: serde_json::Value,
}

impl World {
    async fn get(&self, path: &str) -> Reply {
        let request = Request::builder()
            .method(Method::GET)
            .uri(path)
            .header(header::HOST, "auth.example")
            .body(Body::empty())
            .expect("request");
        let response = self
            .router
            .clone()
            .oneshot(request)
            .await
            .expect("response");
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.expect("body").to_bytes();
        Reply {
            status: parts.status,
            headers: parts.headers,
            body: serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null),
        }
    }

    /// The key identifiers a tenant publishes, in order.
    async fn published(&self, slug: &str) -> Vec<String> {
        self.published_of(slug, None).await
    }

    /// The identifiers of the ES256 keys a tenant publishes, in order.
    async fn published_es256(&self, slug: &str) -> Vec<String> {
        self.published_of(slug, Some("ES256")).await
    }

    async fn published_of(&self, slug: &str, algorithm: Option<&str>) -> Vec<String> {
        let reply = self.get(&format!("/t/{slug}/oauth2/jwks")).await;
        assert_eq!(reply.status, StatusCode::OK);
        reply.body["keys"]
            .as_array()
            .expect("keys")
            .iter()
            .filter(|key| algorithm.is_none_or(|wanted| key["alg"] == wanted))
            .map(|key| key["kid"].as_str().expect("kid").to_owned())
            .collect()
    }
}

#[tokio::test]
async fn a_tenant_without_keys_gets_one_for_each_token_algorithm_on_the_first_read_of_its_set() {
    let world = world();
    let reply = world.get("/t/acme/oauth2/jwks").await;
    assert_eq!(reply.status, StatusCode::OK);
    let mut algorithms: Vec<_> = reply.body["keys"]
        .as_array()
        .expect("keys")
        .iter()
        .map(|key| key["alg"].as_str().expect("alg").to_owned())
        .collect();
    algorithms.sort();
    assert_eq!(
        algorithms,
        ["ES256", "EdDSA", "PS256", "RS256"],
        "the key of the first token is known before it, whichever algorithm signs it"
    );
    assert_eq!(
        world.published("acme").await.len(),
        4,
        "a second read makes nothing more"
    );
    assert_eq!(
        reply.headers[header::CACHE_CONTROL],
        "public, max-age=300",
        "the age the rotation policy counts on"
    );
    assert_eq!(reply.headers[header::ACCESS_CONTROL_ALLOW_ORIGIN], "*");
    assert_eq!(reply.headers[header::CONTENT_TYPE], "application/json");
}

#[tokio::test]
async fn each_key_is_published_with_its_numbers_and_nothing_else() {
    let world = world();
    let es256 = world
        .keys
        .rotate_now(
            &world.acme,
            KeyAlgorithm::Es256,
            &RotationPolicy::DEFAULT,
            Caller::system(),
        )
        .await
        .expect("ES256");
    let rs256 = world
        .keys
        .rotate_now(
            &world.acme,
            KeyAlgorithm::Rs256,
            &RotationPolicy::DEFAULT,
            Caller::system(),
        )
        .await
        .expect("RS256");
    let ps256 = world
        .keys
        .rotate_now(
            &world.acme,
            KeyAlgorithm::Ps256,
            &RotationPolicy::DEFAULT,
            Caller::system(),
        )
        .await
        .expect("PS256");
    let eddsa = world
        .keys
        .rotate_now(
            &world.acme,
            KeyAlgorithm::EdDsa,
            &RotationPolicy::DEFAULT,
            Caller::system(),
        )
        .await
        .expect("EdDSA");

    let reply = world.get("/t/acme/oauth2/jwks").await;
    // The stand-in provider's made-up public keys, newest first; an
    // Ed25519 key as RFC 8037 writes an octet key pair.
    assert_eq!(
        reply.body,
        serde_json::json!({ "keys": [
            {
                "kid": eddsa.id().to_string(),
                "kty": "OKP",
                "use": "sig",
                "alg": "EdDSA",
                "crv": "Ed25519",
                "x": URL_SAFE_NO_PAD.encode([4_u8; 32]),
            },
            {
                "kid": ps256.id().to_string(),
                "kty": "RSA",
                "use": "sig",
                "alg": "PS256",
                "n": URL_SAFE_NO_PAD.encode([3_u8; 256]),
                "e": "AQAB",
            },
            {
                "kid": rs256.id().to_string(),
                "kty": "RSA",
                "use": "sig",
                "alg": "RS256",
                "n": URL_SAFE_NO_PAD.encode([3_u8; 256]),
                "e": "AQAB",
            },
            {
                "kid": es256.id().to_string(),
                "kty": "EC",
                "use": "sig",
                "alg": "ES256",
                "crv": "P-256",
                "x": URL_SAFE_NO_PAD.encode([1_u8; 32]),
                "y": URL_SAFE_NO_PAD.encode([2_u8; 32]),
            },
        ]})
    );
}

#[tokio::test]
async fn pending_active_and_retiring_keys_are_published_and_retired_and_revoked_ones_are_not() {
    let world = world();
    let policy = RotationPolicy::DEFAULT;
    world
        .keys
        .rotate_due(&world.acme, &policy, Caller::system())
        .await
        .expect("first key");
    let first = world.published_es256("acme").await;
    assert_eq!(first.len(), 1);

    // The next key is published a day ahead of signing.
    world.clock.advance(policy.period() - policy.publication());
    world
        .keys
        .rotate_due(&world.acme, &policy, Caller::system())
        .await
        .expect("prepare");
    let both = world.published_es256("acme").await;
    assert_eq!(both.len(), 2);
    assert_eq!(both[1], first[0]);

    // It signs; the first is retiring and still published.
    world.clock.advance(policy.publication());
    world
        .keys
        .rotate_due(&world.acme, &policy, Caller::system())
        .await
        .expect("activate");
    assert_eq!(world.published_es256("acme").await, both);

    // Retired after the overlap: gone.
    world.clock.advance(policy.overlap());
    world
        .keys
        .rotate_due(&world.acme, &policy, Caller::system())
        .await
        .expect("retire");
    assert_eq!(world.published_es256("acme").await, vec![both[0].clone()]);

    // Revoked: gone at once, and a new key is published in its place, never
    // the revoked one.
    let revoked = both[0].parse().expect("identifier");
    world
        .keys
        .revoke(&world.acme, revoked, "leaked", Caller::system())
        .await
        .expect("revoke");
    let replaced = world.published_es256("acme").await;
    assert_eq!(replaced.len(), 1);
    assert!(!both.contains(&replaced[0]));
}

#[tokio::test]
async fn a_tenant_publishes_only_its_own_keys() {
    let world = world();
    let policy = RotationPolicy::DEFAULT;
    world
        .keys
        .rotate_due(&world.acme, &policy, Caller::system())
        .await
        .expect("acme");
    world
        .keys
        .rotate_due(&world.globex, &policy, Caller::system())
        .await
        .expect("globex");
    let acme = world.published("acme").await;
    let globex = world.published("globex").await;
    assert_eq!(
        (acme.len(), globex.len()),
        (4, 4),
        "ES256, RS256, PS256 and EdDSA each"
    );
    assert!(
        acme.iter().all(|key| !globex.contains(key)),
        "no key of one tenant is in the other's set"
    );

    let unknown = world.get("/t/initech/oauth2/jwks").await;
    assert_eq!(unknown.status, StatusCode::NOT_FOUND);
}
