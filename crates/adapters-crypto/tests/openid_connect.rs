//! The OpenID Connect relying party against a provider that publishes
//! real keys and signs real tokens. Nothing about signatures is faked;
//! only the network is replaced by the provider itself.

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hodor_adapters_crypto::testing::{CLIENT_ID, CLIENT_SECRET, SigningKey, TestProvider};
use hodor_adapters_crypto::{AwsLcVerifier, OsRandom, Sha256Digest};
use hodor_federation::api::{
    Alias, IdentityProvider, OpenIdClient, ProviderKind, ProviderSettings, VerifiedIdentity,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{Digest as _, DomainError, SealedSecret, Secret, Timestamp};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use time::Duration;

const ISSUER: &str = "https://provider.example.com/realms/acme";
const REDIRECT: &str =
    "https://hodor.example.com/t/acme/interaction/sign-in/providers/example/callback";
const NOW: i64 = 1_800_000_000;

/// A change to the claims of a token.
type Change = Box<dyn Fn(&mut Value)>;
/// A change to what a provider says about itself.
type Rewrite = fn(&mut Value);

struct World {
    provider: TestProvider,
    client: OpenIdClient,
    clock: Arc<FixedClock>,
    configured: IdentityProvider,
    rsa: SigningKey,
    ec: SigningKey,
}

fn configured(issuer: &str) -> IdentityProvider {
    IdentityProvider::create(
        Alias::parse("example").expect("alias"),
        ProviderKind::OpenIdConnect,
        ProviderSettings {
            display_name: "Example".to_owned(),
            issuer: issuer.to_owned(),
            client_id: CLIENT_ID.to_owned(),
            scopes: ProviderSettings::default_scopes(),
            creates_users: true,
        },
        SealedSecret::from_stored(vec![1]),
        &[],
        Timestamp::UNIX_EPOCH,
    )
    .expect("provider")
}

fn world() -> World {
    let (rsa, ec) = (SigningKey::rsa(), SigningKey::p256());
    let provider = TestProvider::new(ISSUER, &[("rsa-1", &rsa), ("ec-1", &ec)]);
    let clock = Arc::new(FixedClock::at(
        Timestamp::from_unix_timestamp(NOW).expect("a time"),
    ));
    let client = OpenIdClient::new(
        Arc::new(provider.clone()),
        Arc::new(AwsLcVerifier),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        clock.clone(),
    );
    World {
        provider,
        client,
        clock,
        configured: configured(ISSUER),
        rsa,
        ec,
    }
}

/// The claims of a token nothing is wrong with.
fn claims(nonce: &str) -> Value {
    json!({
        "iss": ISSUER,
        "aud": CLIENT_ID,
        "sub": "subject-of-ana",
        "exp": NOW + 300,
        "iat": NOW - 5,
        "nonce": nonce,
        "email": "ana@example.com",
        "email_verified": true,
        "name": "Ana Example",
        "locale": "pt-BR",
    })
}

fn header(algorithm: &str, key_id: &str) -> Value {
    json!({ "alg": algorithm, "typ": "JWT", "kid": key_id })
}

impl World {
    /// One whole exchange: start it, let `token` make the ID token for its
    /// nonce, and finish it.
    async fn sign_in(
        &self,
        token: impl FnOnce(&Self, &str) -> String,
    ) -> Result<VerifiedIdentity, DomainError> {
        let request = self
            .client
            .begin(&self.configured, REDIRECT)
            .await
            .expect("begin");
        self.provider
            .answer_code("the-code", &token(self, &request.nonce));
        self.client
            .finish(
                &self.configured,
                &Secret::from(CLIENT_SECRET.to_owned()),
                REDIRECT,
                "the-code",
                &request.code_verifier,
                &request.nonce,
            )
            .await
    }

    /// An exchange whose token has these changes to the good claims.
    async fn with_claims(
        &self,
        change: impl FnOnce(&mut Value),
    ) -> Result<VerifiedIdentity, DomainError> {
        self.sign_in(|world, nonce| {
            let mut claims = claims(nonce);
            change(&mut claims);
            world.rsa.token(&header("RS256", "rsa-1"), &claims)
        })
        .await
    }
}

#[track_caller]
fn refused(result: Result<VerifiedIdentity, DomainError>, reason: &str) {
    let error = result.expect_err(reason);
    assert_eq!(
        error.code(),
        "federation.identity_not_verified",
        "{error:?}"
    );
    let detail = error.detail().unwrap_or_default();
    assert!(
        detail.contains(reason),
        "expected `{reason}`, got `{detail}`"
    );
    // What a person would be shown says nothing of the reason.
    assert!(!error.message().contains(reason));
}

#[tokio::test]
async fn a_good_token_is_accepted_with_each_algorithm() {
    let world = world();
    for (algorithm, key_id) in [("RS256", "rsa-1"), ("PS256", "rsa-1"), ("ES256", "ec-1")] {
        let identity = world
            .sign_in(|world, nonce| {
                let key = if key_id == "ec-1" {
                    &world.ec
                } else {
                    &world.rsa
                };
                key.token(&header(algorithm, key_id), &claims(nonce))
            })
            .await
            .unwrap_or_else(|error| panic!("{algorithm}: {error:?}"));
        assert_eq!(identity.subject.expose(), "subject-of-ana");
        assert_eq!(identity.email.as_deref(), Some("ana@example.com"));
        assert!(identity.email_verified);
        assert_eq!(identity.name.as_deref(), Some("Ana Example"));
        assert_eq!(identity.locale.as_deref(), Some("pt-BR"));
    }
}

#[tokio::test]
async fn the_trip_is_started_with_everything_the_specification_asks() {
    let world = world();
    let first = world
        .client
        .begin(&world.configured, REDIRECT)
        .await
        .expect("begin");
    let second = world
        .client
        .begin(&world.configured, REDIRECT)
        .await
        .expect("begin");

    let (address, query) = first.url.split_once('?').expect("a query");
    assert_eq!(address, format!("{ISSUER}/authorize"));
    let sent: HashMap<String, String> = form_urlencoded::parse(query.as_bytes())
        .into_owned()
        .collect();
    assert_eq!(sent["response_type"], "code");
    assert_eq!(sent["client_id"], CLIENT_ID);
    assert_eq!(sent["redirect_uri"], REDIRECT);
    assert_eq!(sent["scope"], "openid email profile");
    assert_eq!(sent["state"], first.state);
    assert_eq!(sent["nonce"], first.nonce);
    assert_eq!(sent["code_challenge_method"], "S256");
    // The challenge is the hash of the verifier, which itself is not sent.
    let expected =
        URL_SAFE_NO_PAD.encode(Sha256Digest.sha256(first.code_verifier.expose().as_bytes()));
    assert_eq!(sent["code_challenge"], expected);
    assert!(!first.url.contains(first.code_verifier.expose().as_str()));
    assert!(!first.url.contains(CLIENT_SECRET));
    assert_eq!(sent.len(), 8, "nothing else is sent: {sent:?}");

    // 256 random bits each, new for every request.
    assert_eq!(first.state.len(), 64);
    assert_eq!(first.nonce.len(), 64);
    assert_eq!(first.code_verifier.expose().len(), 43);
    assert_ne!(first.state, first.nonce);
    assert_ne!(first.state, second.state);
    assert_ne!(first.nonce, second.nonce);
    assert_ne!(first.code_verifier.expose(), second.code_verifier.expose());
}

#[tokio::test]
async fn the_code_is_exchanged_with_the_secret_in_the_header_and_the_verifier() {
    let world = world();
    world.with_claims(|_| {}).await.expect("sign in");

    let exchange = world
        .provider
        .requests()
        .into_iter()
        .find(|request| request.url.ends_with("/token"))
        .expect("the exchange");
    let body = String::from_utf8(exchange.body.clone().expect("body")).expect("text");
    let form: HashMap<String, String> = form_urlencoded::parse(body.as_bytes())
        .into_owned()
        .collect();
    assert_eq!(form["grant_type"], "authorization_code");
    assert_eq!(form["code"], "the-code");
    assert_eq!(form["redirect_uri"], REDIRECT);
    assert_eq!(form["code_verifier"].len(), 43);
    assert!(
        !form.contains_key("client_secret"),
        "the secret is not in the body"
    );

    let authorization = exchange
        .headers
        .iter()
        .find(|(name, _)| name == "authorization")
        .map(|(_, value)| value.clone())
        .expect("an authorization header");
    let decoded = STANDARD
        .decode(authorization.strip_prefix("Basic ").expect("basic"))
        .expect("Base64");
    let decoded = String::from_utf8(decoded).expect("text");
    let (id, secret) = decoded.split_once(':').expect("id and secret");
    let plain = |part: &str| -> String {
        form_urlencoded::parse(format!("x={part}").as_bytes())
            .next()
            .expect("a pair")
            .1
            .into_owned()
    };
    assert_eq!(plain(id), CLIENT_ID);
    assert_eq!(
        plain(secret),
        CLIENT_SECRET,
        "encoded on the way, whole on arrival"
    );
}

#[tokio::test]
async fn the_secret_goes_in_the_body_only_for_a_provider_that_asks_for_that() {
    let world = world();
    world.provider.describe(json!({
        "issuer": ISSUER,
        "authorization_endpoint": format!("{ISSUER}/authorize"),
        "token_endpoint": format!("{ISSUER}/token"),
        "jwks_uri": format!("{ISSUER}/keys"),
        "token_endpoint_auth_methods_supported": ["client_secret_post"],
    }));
    world.with_claims(|_| {}).await.expect("sign in");

    let exchange = world
        .provider
        .requests()
        .into_iter()
        .find(|request| request.url.ends_with("/token"))
        .expect("the exchange");
    let body = exchange.body.clone().expect("body");
    let form: HashMap<String, String> = form_urlencoded::parse(&body).into_owned().collect();
    assert_eq!(form["client_id"], CLIENT_ID);
    assert_eq!(form["client_secret"], CLIENT_SECRET);
    assert!(
        exchange
            .headers
            .iter()
            .all(|(name, _)| name != "authorization")
    );
}

#[tokio::test]
async fn a_token_without_a_real_signature_is_refused() {
    let world = world();
    let unsigned = |algorithm: &'static str| {
        move |_: &World, nonce: &str| {
            let encode = |value: &Value| URL_SAFE_NO_PAD.encode(value.to_string());
            format!(
                "{}.{}.{}",
                encode(&json!({ "alg": algorithm, "kid": "rsa-1" })),
                encode(&claims(nonce)),
                if algorithm == "none" {
                    String::new()
                } else {
                    URL_SAFE_NO_PAD.encode([7_u8; 32])
                }
            )
        }
    };
    // No signature at all, and the algorithms that sign with a value
    // anyone may know.
    for algorithm in ["none", "None", "NONE", "HS256", "HS384", "HS512"] {
        refused(
            world.sign_in(unsigned(algorithm)).await,
            "algorithm that is not accepted",
        );
    }
    // Algorithms that exist and are simply not offered.
    for algorithm in ["RS384", "RS512", "ES384", "EdDSA", "RS1", ""] {
        refused(
            world.sign_in(unsigned(algorithm)).await,
            "algorithm that is not accepted",
        );
    }
}

#[tokio::test]
async fn a_token_signed_by_anyone_but_the_provider_is_refused() {
    let world = world();
    let stranger = SigningKey::rsa();
    // Signed by another key, under the name of the provider's.
    refused(
        world
            .sign_in(|_, nonce| stranger.token(&header("RS256", "rsa-1"), &claims(nonce)))
            .await,
        "does not verify",
    );
    // Signed by the provider, then changed.
    refused(
        world
            .sign_in(|world, nonce| {
                let token = world.rsa.token(&header("RS256", "rsa-1"), &claims(nonce));
                let parts: Vec<&str> = token.split('.').collect();
                let mut changed = claims(nonce);
                changed["sub"] = json!("subject-of-somebody-else");
                format!(
                    "{}.{}.{}",
                    parts[0],
                    URL_SAFE_NO_PAD.encode(changed.to_string()),
                    parts[2]
                )
            })
            .await,
        "does not verify",
    );
    // A signature of one algorithm presented as another's.
    refused(
        world
            .sign_in(|world, nonce| {
                let token = world.rsa.token(&header("RS256", "rsa-1"), &claims(nonce));
                let parts: Vec<&str> = token.split('.').collect();
                let relabeled = URL_SAFE_NO_PAD.encode(header("PS256", "rsa-1").to_string());
                format!("{relabeled}.{}.{}", parts[1], parts[2])
            })
            .await,
        "does not verify",
    );
}

#[tokio::test]
async fn a_token_must_name_a_key_the_provider_publishes_for_its_algorithm() {
    let world = world();
    // A key nobody published.
    refused(
        world
            .sign_in(|world, nonce| {
                world
                    .rsa
                    .token(&header("RS256", "unknown-key"), &claims(nonce))
            })
            .await,
        "names a key the provider does not publish",
    );
    // A real key of the wrong kind for the algorithm named.
    refused(
        world
            .sign_in(|world, nonce| world.ec.token(&header("ES256", "rsa-1"), &claims(nonce)))
            .await,
        "names a key the provider does not publish",
    );
    // No key named, and two would fit.
    let second = SigningKey::rsa();
    world
        .provider
        .publish(&[("rsa-1", &world.rsa), ("rsa-2", &second)]);
    world.clock.advance(Duration::hours(2));
    refused(
        world
            .sign_in(|world, nonce| {
                let mut claims = claims(nonce);
                claims["exp"] = json!(NOW + 3 * 3600);
                world.rsa.token(&json!({ "alg": "RS256" }), &claims)
            })
            .await,
        "does not say which of the provider's keys",
    );
}

#[tokio::test]
async fn a_token_that_names_no_key_is_accepted_when_only_one_fits() {
    let world = world();
    // One RSA key and one P-256 key are published: for ES256 only one fits.
    let identity = world
        .sign_in(|world, nonce| world.ec.token(&json!({ "alg": "ES256" }), &claims(nonce)))
        .await
        .expect("accepted");
    assert_eq!(identity.subject.expose(), "subject-of-ana");
}

#[tokio::test]
async fn keys_marked_for_something_else_than_signatures_are_not_used() {
    let world = world();
    let mut published = world.rsa.published("rsa-1");
    published["use"] = json!("enc");
    world
        .provider
        .publish_raw(json!({ "keys": [published, world.ec.published("ec-1")] }));
    refused(
        world
            .sign_in(|world, nonce| world.rsa.token(&header("RS256", "rsa-1"), &claims(nonce)))
            .await,
        "names a key the provider does not publish",
    );
    // A key published for another algorithm does not fit either.
    let fresh = self::world();
    let mut published = fresh.rsa.published("rsa-1");
    published["alg"] = json!("PS256");
    fresh.provider.publish_raw(json!({ "keys": [published] }));
    refused(
        fresh
            .sign_in(|world, nonce| world.rsa.token(&header("RS256", "rsa-1"), &claims(nonce)))
            .await,
        "names a key the provider does not publish",
    );
}

#[tokio::test]
async fn every_claim_is_held_to_its_rule() {
    let world = world();
    let cases: Vec<(&str, Change)> = vec![
        (
            "from another issuer",
            Box::new(|c| c["iss"] = json!("https://evil.example.com")),
        ),
        // The same issuer in another spelling is another issuer.
        (
            "from another issuer",
            Box::new(|c| c["iss"] = json!(format!("{ISSUER}/"))),
        ),
        (
            "from another issuer",
            Box::new(|c| c["iss"] = json!(ISSUER.to_uppercase())),
        ),
        (
            "from another issuer",
            Box::new(|c| {
                c.as_object_mut().expect("object").remove("iss");
            }),
        ),
        (
            "not issued for this client",
            Box::new(|c| c["aud"] = json!("another-client")),
        ),
        (
            "not issued for this client",
            Box::new(|c| c["aud"] = json!(["one", "two"])),
        ),
        (
            "not issued for this client",
            Box::new(|c| c["aud"] = json!([])),
        ),
        (
            "not issued for this client",
            Box::new(|c| {
                c.as_object_mut().expect("object").remove("aud");
            }),
        ),
        (
            "several audiences",
            Box::new(|c| c["aud"] = json!([CLIENT_ID, "another-client"])),
        ),
        (
            "another client to use",
            Box::new(|c| c["azp"] = json!("another-client")),
        ),
        (
            "another client to use",
            Box::new(|c| {
                c["aud"] = json!([CLIENT_ID, "another-client"]);
                c["azp"] = json!("another-client");
            }),
        ),
        ("has expired", Box::new(|c| c["exp"] = json!(NOW - 61))),
        (
            "does not say when it expires",
            Box::new(|c| {
                c.as_object_mut().expect("object").remove("exp");
            }),
        ),
        (
            "does not say when it expires",
            Box::new(|c| c["exp"] = json!("tomorrow")),
        ),
        (
            "issued in the future",
            Box::new(|c| c["iat"] = json!(NOW + 61)),
        ),
        (
            "does not say when it was issued",
            Box::new(|c| {
                c.as_object_mut().expect("object").remove("iat");
            }),
        ),
        ("not valid yet", Box::new(|c| c["nbf"] = json!(NOW + 61))),
        (
            "not issued for this request",
            Box::new(|c| c["nonce"] = json!("another-request")),
        ),
        (
            "not issued for this request",
            Box::new(|c| {
                c.as_object_mut().expect("object").remove("nonce");
            }),
        ),
        (
            "not issued for this request",
            Box::new(|c| c["nonce"] = json!("")),
        ),
        (
            "no usable subject",
            Box::new(|c| {
                c.as_object_mut().expect("object").remove("sub");
            }),
        ),
        ("no usable subject", Box::new(|c| c["sub"] = json!(""))),
        ("no usable subject", Box::new(|c| c["sub"] = json!(12345))),
        (
            "no usable subject",
            Box::new(|c| c["sub"] = json!("a".repeat(256))),
        ),
    ];
    for (reason, change) in cases {
        refused(world.with_claims(|claims| change(claims)).await, reason);
    }
}

#[tokio::test]
async fn clocks_may_disagree_by_a_minute_and_no_more() {
    let world = world();
    world
        .with_claims(|c| c["exp"] = json!(NOW - 59))
        .await
        .expect("just expired, within a minute");
    world
        .with_claims(|c| c["iat"] = json!(NOW + 59))
        .await
        .expect("issued a moment ahead");
    world
        .with_claims(|c| c["nbf"] = json!(NOW + 59))
        .await
        .expect("valid a moment from now");
    // Times written as fractions are read as whole seconds.
    world
        .with_claims(|c| c["exp"] = json!(NOW as f64 + 120.75))
        .await
        .expect("a fraction");
}

#[tokio::test]
async fn several_audiences_are_accepted_when_this_client_is_the_one_meant() {
    let world = world();
    world
        .with_claims(|c| {
            c["aud"] = json!([CLIENT_ID, "another-client"]);
            c["azp"] = json!(CLIENT_ID);
        })
        .await
        .expect("accepted");
}

#[tokio::test]
async fn a_token_of_another_trip_cannot_be_used_for_this_one() {
    let world = world();
    let earlier = world
        .client
        .begin(&world.configured, REDIRECT)
        .await
        .expect("begin");
    let replayed = world
        .rsa
        .token(&header("RS256", "rsa-1"), &claims(&earlier.nonce));
    refused(
        world.sign_in(|_, _| replayed.clone()).await,
        "not issued for this request",
    );
}

#[tokio::test]
async fn what_is_not_a_token_is_refused() {
    let world = world();
    let good =
        |world: &World, nonce: &str| world.rsa.token(&header("RS256", "rsa-1"), &claims(nonce));
    refused(
        world.sign_in(|_, _| "not-a-token".to_owned()).await,
        "not three parts",
    );
    refused(
        world.sign_in(|w, n| format!("{}.extra", good(w, n))).await,
        "not three parts",
    );
    refused(world.sign_in(|_, _| "a.b.c".to_owned()).await, "malformed");
    refused(
        world.sign_in(|_, _| "!!!.???.***".to_owned()).await,
        "malformed",
    );
    refused(
        world.sign_in(|w, n| good(w, n).replace('.', "=.")).await,
        "malformed",
    );
    refused(
        world.sign_in(|_, _| "a".repeat(17 * 1024)).await,
        "too large",
    );
    // A header that is JSON but not an object.
    refused(
        world
            .sign_in(|_, _| format!("{}.e30.AAAA", URL_SAFE_NO_PAD.encode("[1,2,3]")))
            .await,
        "malformed",
    );
}

#[tokio::test]
async fn only_the_exact_value_true_means_the_address_is_vouched_for() {
    let world = world();
    for not_true in [
        json!("true"),
        json!(1),
        json!("yes"),
        Value::Null,
        json!(false),
    ] {
        let identity = world
            .with_claims(|c| c["email_verified"] = not_true.clone())
            .await
            .expect("accepted");
        assert!(!identity.email_verified, "{not_true}");
        assert_eq!(identity.email.as_deref(), Some("ana@example.com"));
    }
    let identity = world
        .with_claims(|c| {
            let object = c.as_object_mut().expect("object");
            object.remove("email_verified");
            object.remove("email");
            object.remove("name");
        })
        .await
        .expect("accepted");
    assert!(!identity.email_verified);
    assert_eq!(identity.email, None);
    assert_eq!(identity.name, None);
}

#[tokio::test]
async fn a_refused_code_signs_nobody_in() {
    let world = world();
    let request = world
        .client
        .begin(&world.configured, REDIRECT)
        .await
        .expect("begin");
    world.provider.refuse_code("stolen-code");
    let result = world
        .client
        .finish(
            &world.configured,
            &Secret::from(CLIENT_SECRET.to_owned()),
            REDIRECT,
            "stolen-code",
            &request.code_verifier,
            &request.nonce,
        )
        .await;
    refused(result, "refused the code with status 400: invalid_grant");
}

#[track_caller]
fn unavailable<T: std::fmt::Debug>(result: Result<T, DomainError>, reason: &str) {
    let error = result.expect_err(reason);
    assert_eq!(error.code(), "federation.provider_unavailable", "{error:?}");
    let detail = error.detail().unwrap_or_default();
    assert!(
        detail.contains(reason),
        "expected `{reason}`, got `{detail}`"
    );
}

#[tokio::test]
async fn a_provider_that_describes_itself_wrongly_is_not_used() {
    let description = |change: Rewrite| {
        let mut description = json!({
            "issuer": ISSUER,
            "authorization_endpoint": format!("{ISSUER}/authorize"),
            "token_endpoint": format!("{ISSUER}/token"),
            "jwks_uri": format!("{ISSUER}/keys"),
        });
        change(&mut description);
        description
    };
    let cases: [(&str, Rewrite); 7] = [
        ("names another issuer", |d| {
            d["issuer"] = json!("https://evil.example.com")
        }),
        ("names another issuer", |d| {
            d["issuer"] = json!(format!("{ISSUER}/"))
        }),
        ("no usable `authorization_endpoint`", |d| {
            d["authorization_endpoint"] = json!("http://provider.example.com/authorize")
        }),
        ("no usable `token_endpoint`", |d| {
            d.as_object_mut().expect("object").remove("token_endpoint");
        }),
        ("no usable `jwks_uri`", |d| {
            d["jwks_uri"] = json!("file:///etc/passwd")
        }),
        ("no usable `jwks_uri`", |d| d["jwks_uri"] = json!(42)),
        ("accepts no way of presenting a client secret", |d| {
            d["token_endpoint_auth_methods_supported"] = json!(["private_key_jwt"])
        }),
    ];
    for (reason, change) in cases {
        let world = self::world();
        world.provider.describe(description(change));
        unavailable(
            world.client.begin(&world.configured, REDIRECT).await,
            reason,
        );
    }

    let world = self::world();
    world
        .provider
        .publish_raw(json!({ "keys": [{ "kty": "oct", "k": "c2VjcmV0" }] }));
    unavailable(
        world.client.begin(&world.configured, REDIRECT).await,
        "publishes no key",
    );

    let world = self::world();
    world.provider.set_down(true);
    unavailable(
        world.client.begin(&world.configured, REDIRECT).await,
        "could not be fetched",
    );

    // A provider configured under an issuer it does not answer for.
    let world = self::world();
    let elsewhere = configured("https://provider.example.com/realms/other");
    unavailable(world.client.begin(&elsewhere, REDIRECT).await, "status 404");
}

#[tokio::test]
async fn the_description_and_the_keys_are_fetched_once_and_kept_for_an_hour() {
    let world = world();
    for _ in 0..3 {
        world.with_claims(|_| {}).await.expect("sign in");
    }
    assert_eq!(
        world
            .provider
            .requests_to("/.well-known/openid-configuration"),
        1
    );
    assert_eq!(world.provider.requests_to("/keys"), 1);
    assert_eq!(world.provider.requests_to("/token"), 3);

    world.clock.advance(Duration::minutes(61));
    world
        .with_claims(|c| c["exp"] = json!(NOW + 2 * 3600))
        .await
        .expect("sign in");
    assert_eq!(
        world
            .provider
            .requests_to("/.well-known/openid-configuration"),
        2
    );
    assert_eq!(world.provider.requests_to("/keys"), 2);
}

#[tokio::test]
async fn a_new_key_of_the_provider_is_picked_up_and_unknown_keys_cause_one_fetch_a_minute() {
    let world = world();
    world.with_claims(|_| {}).await.expect("sign in");
    assert_eq!(world.provider.requests_to("/keys"), 1);

    // The provider starts signing with a new key.
    let renewed = SigningKey::rsa();
    world
        .provider
        .publish(&[("rsa-2", &renewed), ("ec-1", &world.ec)]);
    let with_new_key =
        |_: &World, nonce: &str| renewed.token(&header("RS256", "rsa-2"), &claims(nonce));

    // Within a minute of the last fetch nothing is fetched: refused.
    refused(
        world.sign_in(with_new_key).await,
        "names a key the provider does not publish",
    );
    assert_eq!(world.provider.requests_to("/keys"), 1);

    // After a minute the keys are fetched again and the token is good.
    world.clock.advance(Duration::seconds(61));
    world
        .sign_in(with_new_key)
        .await
        .expect("the new key is known now");
    assert_eq!(world.provider.requests_to("/keys"), 2);
    // The key that was withdrawn no longer signs anyone in.
    world.clock.advance(Duration::seconds(61));
    refused(
        world
            .sign_in(|world, nonce| world.rsa.token(&header("RS256", "rsa-1"), &claims(nonce)))
            .await,
        "names a key the provider does not publish",
    );
    assert_eq!(world.provider.requests_to("/keys"), 3);

    // A flood of tokens naming keys that do not exist causes no flood of requests.
    for number in 0..20 {
        let made_up = format!("made-up-{number}");
        refused(
            world
                .sign_in(|world, nonce| world.ec.token(&header("ES256", &made_up), &claims(nonce)))
                .await,
            "names a key the provider does not publish",
        );
    }
    assert_eq!(world.provider.requests_to("/keys"), 3);
}

#[tokio::test]
async fn one_provider_is_never_checked_with_the_keys_of_another() {
    // Two providers behind one client, each with its own keys.
    let world = world();
    let other_key = SigningKey::rsa();
    let other = TestProvider::new("https://other.example.com", &[("rsa-1", &other_key)]);
    let client = OpenIdClient::new(
        Arc::new(other.clone()),
        Arc::new(AwsLcVerifier),
        Arc::new(Sha256Digest),
        Arc::new(OsRandom),
        world.clock.clone(),
    );
    // A token the other provider really signed, for the same client and
    // subject, but naming this provider as its issuer.
    let configured_other = configured("https://other.example.com");
    let request = client
        .begin(&configured_other, REDIRECT)
        .await
        .expect("begin");
    let forged = other_key.token(&header("RS256", "rsa-1"), &claims(&request.nonce));
    other.answer_code("the-code", &forged);
    let result = client
        .finish(
            &configured_other,
            &Secret::from(CLIENT_SECRET.to_owned()),
            REDIRECT,
            "the-code",
            &request.code_verifier,
            &request.nonce,
        )
        .await;
    refused(result, "from another issuer");

    // And presented to this provider's configuration, its signature fails.
    refused(
        world
            .sign_in(|_, nonce| other_key.token(&header("RS256", "rsa-1"), &claims(nonce)))
            .await,
        "does not verify",
    );
}

#[tokio::test]
async fn plain_http_endpoints_are_used_only_at_a_development_host() {
    let world = world();
    world.provider.describe(json!({
        "issuer": ISSUER,
        // Where the browser is sent: the provider as the person's machine sees it.
        "authorization_endpoint": "http://localhost:9000/authorize",
        "token_endpoint": format!("{ISSUER}/token"),
        "jwks_uri": format!("{ISSUER}/keys"),
    }));
    unavailable(
        world.client.begin(&world.configured, REDIRECT).await,
        "no usable `authorization_endpoint`",
    );

    let allowing = world
        .client
        .clone()
        .allowing_development_hosts(&["localhost:9000".to_owned()]);
    let request = allowing
        .begin(&world.configured, REDIRECT)
        .await
        .expect("a development host");
    assert!(request.url.starts_with("http://localhost:9000/authorize?"));

    // Another port of the same host is not the development host. Asked of
    // a client that has not kept the description yet.
    let fresh = self::world();
    fresh.provider.describe(json!({
        "issuer": ISSUER,
        "authorization_endpoint": "http://localhost:9000/authorize",
        "token_endpoint": format!("{ISSUER}/token"),
        "jwks_uri": format!("{ISSUER}/keys"),
    }));
    let other = fresh
        .client
        .clone()
        .allowing_development_hosts(&["localhost:9001".to_owned()]);
    unavailable(
        other.begin(&fresh.configured, REDIRECT).await,
        "no usable `authorization_endpoint`",
    );
}
