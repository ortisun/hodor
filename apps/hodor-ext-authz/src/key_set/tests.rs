//! The key set and the signatures, against a key set served on a port of
//! the test's own that counts its fetches.

use super::*;
use aws_lc_rs::hmac;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, Ed25519KeyPair, KeyPair as _, RSA_PKCS1_SHA256,
    RSA_PSS_SHA256, RsaKeyPair,
};
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode as HttpStatus;
use axum::routing::get;
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use tokio::net::TcpListener;

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A key of one of the four algorithms, published under `kid`.
enum Pair {
    Es256(EcdsaKeyPair),
    Rsa(RsaKeyPair, Algorithm),
    EdDsa(Ed25519KeyPair),
}

struct Signer {
    kid: String,
    pair: Pair,
}

impl Signer {
    fn new(kid: &str, algorithm: Algorithm) -> Self {
        let pair = match algorithm {
            Algorithm::Es256 => Pair::Es256(
                EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).expect("an EC key"),
            ),
            Algorithm::Rs256 | Algorithm::Ps256 => Pair::Rsa(
                RsaKeyPair::generate(KeySize::Rsa2048).expect("an RSA key"),
                algorithm,
            ),
            Algorithm::EdDsa => Pair::EdDsa(Ed25519KeyPair::generate().expect("an Ed25519 key")),
        };
        Self {
            kid: kid.to_owned(),
            pair,
        }
    }

    fn algorithm(&self) -> Algorithm {
        match &self.pair {
            Pair::Es256(_) => Algorithm::Es256,
            Pair::Rsa(_, algorithm) => *algorithm,
            Pair::EdDsa(_) => Algorithm::EdDsa,
        }
    }

    fn name(&self) -> &'static str {
        match self.algorithm() {
            Algorithm::Es256 => "ES256",
            Algorithm::Rs256 => "RS256",
            Algorithm::Ps256 => "PS256",
            Algorithm::EdDsa => "EdDSA",
        }
    }

    /// The key as Hodor publishes it.
    fn jwk(&self) -> Value {
        match &self.pair {
            Pair::Es256(pair) => {
                let point = pair.public_key().as_ref();
                json!({ "kid": self.kid, "kty": "EC", "use": "sig", "alg": "ES256", "crv": "P-256",
                        "x": encode(&point[1..33]), "y": encode(&point[33..65]) })
            }
            Pair::Rsa(pair, _) => {
                let public = pair.public_key();
                json!({ "kid": self.kid, "kty": "RSA", "use": "sig", "alg": self.name(),
                        "n": encode(public.modulus().big_endian_without_leading_zero()),
                        "e": encode(public.exponent().big_endian_without_leading_zero()) })
            }
            Pair::EdDsa(pair) => {
                json!({ "kid": self.kid, "kty": "OKP", "use": "sig", "alg": "EdDSA", "crv": "Ed25519",
                        "x": encode(pair.public_key().as_ref()) })
            }
        }
    }

    /// The signature of `message` with this key, with `padding` for an
    /// RSA key: PSS when true.
    fn signature(&self, message: &[u8], pss: bool) -> Vec<u8> {
        match &self.pair {
            Pair::Es256(pair) => pair
                .sign(&SystemRandom::new(), message)
                .expect("signed")
                .as_ref()
                .to_vec(),
            Pair::Rsa(pair, _) => {
                let mut signature = vec![0; pair.public_modulus_len()];
                let padding = if pss {
                    &RSA_PSS_SHA256
                } else {
                    &RSA_PKCS1_SHA256
                };
                pair.sign(padding, &SystemRandom::new(), message, &mut signature)
                    .expect("signed");
                signature
            }
            Pair::EdDsa(pair) => pair.sign(message).as_ref().to_vec(),
        }
    }

    /// A token of `claims` with `header`, signed by this key.
    fn token_with(&self, header: &Value, claims: &Value, pss: bool) -> String {
        let signed = format!(
            "{}.{}",
            encode(&serde_json::to_vec(header).expect("json")),
            encode(&serde_json::to_vec(claims).expect("json"))
        );
        let signature = self.signature(signed.as_bytes(), pss);
        format!("{signed}.{}", encode(&signature))
    }

    /// A token of `claims` as Hodor signs one with this key.
    fn token(&self, claims: &Value) -> String {
        self.token_with(
            &json!({ "alg": self.name(), "kid": self.kid, "typ": "at+jwt" }),
            claims,
            self.algorithm() == Algorithm::Ps256,
        )
    }
}

fn claims() -> Value {
    json!({ "iss": "https://login.example.com/t/acme", "sub": "user-1", "aud": "https://orders.example.com" })
}

/// What the test's key set address answers, and how often it was asked.
struct Served {
    answer: Mutex<(HttpStatus, String)>,
    fetches: AtomicUsize,
}

impl Served {
    fn answer(&self, status: HttpStatus, body: String) {
        *self.answer.lock().expect("answer") = (status, body);
    }

    fn keys(&self, signers: &[&Signer]) {
        let keys: Vec<Value> = signers.iter().map(|signer| signer.jwk()).collect();
        self.answer(HttpStatus::OK, json!({ "keys": keys }).to_string());
    }

    fn fetches(&self) -> usize {
        self.fetches.load(Ordering::SeqCst)
    }
}

/// A key set served at `/t/acme/oauth2/jwks` on a port of its own, and
/// the adapter's set reading it.
async fn served(signers: &[&Signer]) -> (Arc<Served>, KeySet) {
    let state = Arc::new(Served {
        answer: Mutex::new((HttpStatus::OK, String::new())),
        fetches: AtomicUsize::new(0),
    });
    state.keys(signers);
    let router = Router::new()
        .route(
            "/t/acme/oauth2/jwks",
            get(|State(state): State<Arc<Served>>| async move {
                state.fetches.fetch_add(1, Ordering::SeqCst);
                state.answer.lock().expect("answer").clone()
            }),
        )
        .with_state(state.clone());
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    tokio::spawn(async move { axum::serve(listener, router).await });
    let settings = Settings::from_json(&format!(
        r#"{{ "hodor": {{ "url": "http://{address}", "tenant": "acme",
                          "issuer": "https://login.example.com/t/acme" }},
             "token": "bearer" }}"#
    ))
    .expect("settings");
    (state, KeySet::new(&settings, reqwest::Client::new()))
}

const SIGNATURE_FAILS: Denial = Denial("the token's signature does not hold");
const UNKNOWN_KEY: Denial = Denial("the token's key is not in the tenant's key set");
const REFUSED_ALGORITHM: Denial = Denial("the token's algorithm is not one Hodor signs with");

#[tokio::test]
async fn a_good_token_holds_with_each_algorithm_hodor_signs_with() {
    let signers = [
        Signer::new("es256-1", Algorithm::Es256),
        Signer::new("rs256-1", Algorithm::Rs256),
        Signer::new("ps256-1", Algorithm::Ps256),
        Signer::new("eddsa-1", Algorithm::EdDsa),
    ];
    let (served, keys) = served(&signers.iter().collect::<Vec<_>>()).await;
    for signer in &signers {
        assert_eq!(
            keys.verify(&signer.token(&claims())).await,
            Ok(claims().as_object().expect("object").clone()),
            "{}",
            signer.name()
        );
    }
    assert_eq!(served.fetches(), 1, "one fetch for all four");
}

#[tokio::test]
async fn a_bad_signature_is_denied() {
    let signer = Signer::new("es256-1", Algorithm::Es256);
    let (served, keys) = served(&[&signer]).await;
    let good = signer.token(&claims());
    assert!(keys.verify(&good).await.is_ok());

    // The claims changed after signing: another subject.
    let parts: Vec<&str> = good.split('.').collect();
    let mut forged = claims();
    forged["sub"] = json!("administrator");
    let changed = format!(
        "{}.{}.{}",
        parts[0],
        encode(&serde_json::to_vec(&forged).expect("json")),
        parts[2]
    );
    assert_eq!(keys.verify(&changed).await, Err(SIGNATURE_FAILS));

    // Signed by a key of the forger's own, under the published `kid`.
    let impostor = Signer::new("es256-1", Algorithm::Es256);
    assert_eq!(
        keys.verify(&impostor.token(&forged)).await,
        Err(SIGNATURE_FAILS)
    );

    // A signature cut short, and one of the right length but zero.
    let short = format!("{}.{}.{}", parts[0], parts[1], &parts[2][..40]);
    assert_eq!(keys.verify(&short).await, Err(SIGNATURE_FAILS));
    let zero = format!("{}.{}.{}", parts[0], parts[1], encode(&[0; 64]));
    assert_eq!(keys.verify(&zero).await, Err(SIGNATURE_FAILS));
    assert_eq!(served.fetches(), 1, "a known key fetches nothing more");
}

#[tokio::test]
async fn an_unknown_kid_fetches_the_set_again_once() {
    let first = Signer::new("es256-1", Algorithm::Es256);
    let (served, keys) = served(&[&first]).await;
    assert!(keys.verify(&first.token(&claims())).await.is_ok());
    assert_eq!(served.fetches(), 1);

    // Hodor rotated at once: the new key is fetched for its first token,
    // once ten seconds have passed since the last fetch, and not before.
    let second = Signer::new("es256-2", Algorithm::Es256);
    served.keys(&[&second, &first]);
    assert_eq!(
        keys.verify(&second.token(&claims())).await,
        Err(UNKNOWN_KEY)
    );
    assert_eq!(served.fetches(), 1);
    keys.age(KEY_SET_REFETCH_AFTER);
    assert!(keys.verify(&second.token(&claims())).await.is_ok());
    assert_eq!(served.fetches(), 2);

    // A `kid` Hodor never published: no fetch within ten seconds of the
    // last, however many tokens name it, at once or one after another.
    let stranger = Signer::new("made-up", Algorithm::Es256);
    assert_eq!(
        keys.verify(&stranger.token(&claims())).await,
        Err(UNKNOWN_KEY)
    );
    assert_eq!(served.fetches(), 2);

    keys.age(KEY_SET_REFETCH_AFTER);
    let keys = Arc::new(keys);
    let token = stranger.token(&claims());
    let burst: Vec<_> = (0..20)
        .map(|_| {
            let keys = keys.clone();
            let token = token.clone();
            tokio::spawn(async move { keys.verify(&token).await })
        })
        .collect();
    for check in burst {
        assert_eq!(check.await.expect("joined"), Err(UNKNOWN_KEY));
    }
    assert_eq!(served.fetches(), 3, "one fetch for the whole burst");
    // The set it fetched is used, without another fetch.
    assert!(keys.verify(&first.token(&claims())).await.is_ok());
    assert_eq!(served.fetches(), 3);
}

#[tokio::test]
async fn none_and_algorithms_hodor_does_not_sign_with_are_refused_before_any_fetch() {
    let signer = Signer::new("es256-1", Algorithm::Es256);
    let (served, keys) = served(&[&signer]).await;
    let payload = encode(&serde_json::to_vec(&claims()).expect("json"));
    for header in [
        json!({ "alg": "none", "kid": "es256-1" }),
        json!({ "alg": "None", "kid": "es256-1" }),
        json!({ "alg": "es256", "kid": "es256-1" }),
        json!({ "alg": "ES384", "kid": "es256-1" }),
        json!({ "alg": "HS256", "kid": "es256-1" }),
        json!({ "kid": "es256-1" }),
    ] {
        let header = encode(&serde_json::to_vec(&header).expect("json"));
        for signature in ["", "c2lnbmF0dXJl"] {
            assert_eq!(
                keys.verify(&format!("{header}.{payload}.{signature}"))
                    .await,
                Err(REFUSED_ALGORITHM),
                "{header} {signature}"
            );
        }
    }
    assert_eq!(served.fetches(), 0);
}

#[tokio::test]
async fn hs256_with_the_public_key_as_the_secret_is_refused() {
    let signer = Signer::new("rs256-1", Algorithm::Rs256);
    let (served, keys) = served(&[&signer]).await;
    let header =
        encode(&serde_json::to_vec(&json!({ "alg": "HS256", "kid": "rs256-1" })).expect("json"));
    let payload = encode(&serde_json::to_vec(&claims()).expect("json"));
    let signed = format!("{header}.{payload}");
    // Every form of the public key a confused library might take as the
    // secret: the published key, its modulus, its DER encoding.
    let jwk = signer.jwk();
    let Pair::Rsa(pair, _) = &signer.pair else {
        unreachable!("an RSA key")
    };
    for secret in [
        jwk.to_string().into_bytes(),
        URL_SAFE_NO_PAD
            .decode(jwk["n"].as_str().expect("n"))
            .expect("modulus"),
        pair.public_key().as_ref().to_vec(),
    ] {
        let tag = hmac::sign(
            &hmac::Key::new(hmac::HMAC_SHA256, &secret),
            signed.as_bytes(),
        );
        assert_eq!(
            keys.verify(&format!("{signed}.{}", encode(tag.as_ref())))
                .await,
            Err(REFUSED_ALGORITHM)
        );
    }
    assert_eq!(served.fetches(), 0);
}

#[tokio::test]
async fn a_key_is_used_with_its_own_algorithm_only() {
    // One RSA key published for PS256; a token naming it with RS256, and
    // signed so, is refused although the key made the signature.
    let signer = Signer::new("ps256-1", Algorithm::Ps256);
    let (_, keys) = served(&[&signer]).await;
    let token = signer.token_with(
        &json!({ "alg": "RS256", "kid": "ps256-1" }),
        &claims(),
        false,
    );
    assert_eq!(
        keys.verify(&token).await,
        Err(Denial("the token's algorithm is not its key's"))
    );
    assert!(keys.verify(&signer.token(&claims())).await.is_ok());
}

#[tokio::test]
async fn an_expired_key_set_is_never_used() {
    let signer = Signer::new("es256-1", Algorithm::Es256);
    let (served, keys) = served(&[&signer]).await;
    let token = signer.token(&claims());
    assert!(keys.verify(&token).await.is_ok());

    // A fetch that fails within the five minutes keeps the set.
    keys.age(KEY_SET_REFETCH_AFTER);
    served.answer(HttpStatus::SERVICE_UNAVAILABLE, String::new());
    let other = Signer::new("es256-2", Algorithm::Es256);
    assert_eq!(keys.verify(&other.token(&claims())).await, Err(UNKNOWN_KEY));
    assert_eq!(served.fetches(), 2);
    assert!(keys.verify(&token).await.is_ok());

    // Five minutes on, Hodor does not answer: the set is not used.
    keys.age(KEY_SET_KEPT_FOR);
    assert_eq!(keys.verify(&token).await, Err(UNKNOWN_KEY));
    assert_eq!(served.fetches(), 3);
    // Nor within ten seconds of that fetch, even once Hodor answers.
    served.keys(&[&signer]);
    assert_eq!(keys.verify(&token).await, Err(UNKNOWN_KEY));
    assert_eq!(served.fetches(), 3);
    // Then a fetch answers, and the set is used again.
    keys.age(KEY_SET_REFETCH_AFTER);
    assert!(keys.verify(&token).await.is_ok());
    assert_eq!(served.fetches(), 4);
}

#[tokio::test]
async fn an_answer_that_is_not_a_set_within_the_bounds_gives_no_key() {
    let signer = Signer::new("es256-1", Algorithm::Es256);
    let (served, keys) = served(&[]).await;
    let token = signer.token(&claims());
    let too_long = json!({ "keys": [signer.jwk()], "padding": "x".repeat(MAX_KEY_SET_BYTES) });
    for (status, body) in [
        (HttpStatus::OK, too_long.to_string()),
        (HttpStatus::OK, "not json".to_owned()),
        (HttpStatus::OK, json!([signer.jwk()]).to_string()),
        (
            HttpStatus::FOUND,
            json!({ "keys": [signer.jwk()] }).to_string(),
        ),
    ] {
        served.answer(status, body);
        keys.age(KEY_SET_REFETCH_AFTER);
        assert_eq!(keys.verify(&token).await, Err(UNKNOWN_KEY), "{status}");
    }
    assert_eq!(served.fetches(), 4);
}

#[test]
fn only_the_keys_hodor_publishes_are_read() {
    let es256 = Signer::new("es256-1", Algorithm::Es256).jwk();
    let eddsa = Signer::new("eddsa-1", Algorithm::EdDsa).jwk();
    let with = |key: &Value, member: &str, value: Value| {
        let mut key = key.clone();
        key[member] = value;
        key
    };
    let without = |key: &Value, member: &str| {
        let mut key = key.clone();
        key.as_object_mut().expect("object").remove(member);
        key
    };
    let read = |keys: Vec<Value>| {
        published_keys(json!({ "keys": keys }).to_string().as_bytes())
            .expect("a set")
            .len()
    };
    assert_eq!(read(vec![es256.clone(), eddsa.clone()]), 2);
    for refused in [
        with(&es256, "d", json!("c2VjcmV0")),
        with(&es256, "use", json!("enc")),
        with(&es256, "alg", json!("ES384")),
        with(&es256, "alg", json!("HS256")),
        with(&es256, "crv", json!("P-384")),
        with(&es256, "kty", json!("RSA")),
        with(&es256, "x", json!("c2hvcnQ")),
        with(&es256, "kid", json!("")),
        without(&es256, "kid"),
        without(&es256, "alg"),
        with(&eddsa, "alg", json!("ES256")),
        with(&eddsa, "crv", json!("X25519")),
        json!({ "kid": "hmac", "kty": "oct", "alg": "HS256", "k": "c2VjcmV0" }),
        json!({ "kid": "small", "kty": "RSA", "alg": "RS256", "n": encode(&[0xC5; 128]), "e": "AQAB" }),
        json!("a text"),
    ] {
        assert_eq!(read(vec![refused.clone()]), 0, "{refused}");
    }
    // At most 32 keys are read.
    assert_eq!(read(vec![es256.clone(); MAX_KEYS + 5]), MAX_KEYS);
    assert!(published_keys(b"{}").is_none());
    assert!(published_keys(b"[]").is_none());
}

#[tokio::test]
async fn a_header_that_breaks_a_rule_is_refused_before_any_fetch() {
    let signer = Signer::new("es256-1", Algorithm::Es256);
    let (served, keys) = served(&[&signer]).await;
    for (header, denial) in [
        (
            json!({ "alg": "ES256", "kid": "es256-1", "crit": ["exp"] }),
            Denial("the token's header names extensions"),
        ),
        (
            json!({ "alg": "ES256" }),
            Denial("the token's header names no key"),
        ),
        (
            json!({ "alg": "ES256", "kid": "" }),
            Denial("the token's header names no key"),
        ),
        (
            json!({ "alg": "ES256", "kid": 7 }),
            Denial("the token's header names no key"),
        ),
    ] {
        assert_eq!(
            keys.verify(&signer.token_with(&header, &claims(), false))
                .await,
            Err(denial),
            "{header}"
        );
    }
    let good = signer.token(&claims());
    let parts: Vec<&str> = good.split('.').collect();
    let not_a_token = Denial("the bearer token is not a JSON Web Token");
    for token in [
        "opaque".to_owned(),
        format!("{}.{}", parts[0], parts[1]),
        format!("{good}.more"),
        format!("{}.{}.", parts[0], parts[1]),
        format!("%%%.{}.{}", parts[1], parts[2]),
    ] {
        assert_eq!(keys.verify(&token).await, Err(not_a_token), "{token}");
    }
    let text = format!("{}.{}.{}", parts[0], encode(b"\"a text\""), parts[2]);
    assert_eq!(
        keys.verify(&text).await,
        Err(Denial("the token's claims are not a JSON object"))
    );
    assert_eq!(
        keys.verify(&"a".repeat(MAX_TOKEN_BYTES + 1)).await,
        Err(Denial("the bearer token is too long"))
    );
    assert_eq!(served.fetches(), 0);
}
