//! An OpenID Connect provider for tests: it publishes real keys and signs
//! real tokens, and answers the requests a relying party makes without
//! any network. Never use outside tests.

use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _, RSA_PKCS1_SHA256, RSA_PSS_SHA256,
    RsaKeyPair,
};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::{DomainError, HttpClient, HttpRequest, HttpResponse};
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

pub mod certificates;
pub mod webauthn;

/// The client the test provider knows.
pub const CLIENT_ID: &str = "hodor-under-test";
/// Its secret. It has characters that must be encoded on the way.
pub const CLIENT_SECRET: &str = "s3cret/with+odd:chars and space";

fn encode(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// A key the provider signs with.
pub enum SigningKey {
    /// An RSA key of 2048 bits.
    Rsa(RsaKeyPair),
    /// A key on the P-256 curve.
    P256(EcdsaKeyPair),
}

impl std::fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::Rsa(_) => "SigningKey::Rsa",
            Self::P256(_) => "SigningKey::P256",
        })
    }
}

impl SigningKey {
    /// A new RSA key.
    ///
    /// # Panics
    ///
    /// Panics if the key cannot be generated.
    #[must_use]
    pub fn rsa() -> Self {
        Self::Rsa(RsaKeyPair::generate(KeySize::Rsa2048).expect("an RSA key"))
    }

    /// A new P-256 key.
    ///
    /// # Panics
    ///
    /// Panics if the key cannot be generated.
    #[must_use]
    pub fn p256() -> Self {
        Self::P256(EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING).expect("a P-256 key"))
    }

    /// The key as a provider publishes it, under `id`.
    ///
    #[must_use]
    pub fn published(&self, id: &str) -> Value {
        match self {
            Self::Rsa(pair) => {
                let public = pair.public_key();
                let modulus = public.modulus().big_endian_without_leading_zero();
                let exponent = public.exponent().big_endian_without_leading_zero();
                json!({
                    "kty": "RSA", "kid": id, "use": "sig",
                    "n": encode(modulus), "e": encode(exponent),
                })
            }
            Self::P256(pair) => {
                // An uncompressed point: 0x04, then x, then y.
                let point = pair.public_key().as_ref();
                json!({
                    "kty": "EC", "crv": "P-256", "kid": id, "use": "sig",
                    "x": encode(&point[1..33]), "y": encode(&point[33..65]),
                })
            }
        }
    }

    /// Signs `message` with the algorithm of this name.
    ///
    /// # Panics
    ///
    /// Panics if the algorithm does not fit the key.
    #[must_use]
    pub fn sign(&self, algorithm: &str, message: &[u8]) -> Vec<u8> {
        let random = SystemRandom::new();
        match (self, algorithm) {
            (Self::Rsa(pair), "RS256" | "PS256") => {
                let padding: &dyn aws_lc_rs::signature::RsaEncoding = if algorithm == "RS256" {
                    &RSA_PKCS1_SHA256
                } else {
                    &RSA_PSS_SHA256
                };
                let mut signature = vec![0; pair.public_modulus_len()];
                pair.sign(padding, &random, message, &mut signature)
                    .expect("an RSA signature");
                signature
            }
            (Self::P256(pair), "ES256") => pair
                .sign(&random, message)
                .expect("an ECDSA signature")
                .as_ref()
                .to_vec(),
            _ => panic!("{algorithm} does not fit this key"),
        }
    }

    /// A signed token with this header and these claims.
    #[must_use]
    pub fn token(&self, header: &Value, claims: &Value) -> String {
        let algorithm = header["alg"].as_str().unwrap_or_default();
        let signed = format!(
            "{}.{}",
            encode(header.to_string().as_bytes()),
            encode(claims.to_string().as_bytes())
        );
        let signature = self.sign(algorithm, signed.as_bytes());
        format!("{signed}.{}", encode(&signature))
    }
}

/// What the token endpoint answers for a code.
#[derive(Debug, Clone)]
enum CodeAnswer {
    Token(String),
    Refused,
}

#[derive(Debug, Default)]
struct State {
    description: Value,
    keys: Value,
    codes: HashMap<String, CodeAnswer>,
    requests: Vec<HttpRequest>,
    down: bool,
}

/// The provider. It is the HTTP client of the code under test: every
/// request that code makes arrives here.
#[derive(Debug, Clone)]
pub struct TestProvider {
    /// The provider's issuer.
    pub issuer: String,
    state: Arc<Mutex<State>>,
}

impl TestProvider {
    /// A provider at `issuer` that publishes these keys by their names.
    #[must_use]
    pub fn new(issuer: &str, keys: &[(&str, &SigningKey)]) -> Self {
        let provider = Self {
            issuer: issuer.to_owned(),
            state: Arc::default(),
        };
        provider.describe(json!({
            "issuer": issuer,
            "authorization_endpoint": format!("{issuer}/authorize"),
            "token_endpoint": format!("{issuer}/token"),
            "jwks_uri": format!("{issuer}/keys"),
        }));
        provider.publish(keys);
        provider
    }

    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Replaces what the provider says about itself.
    pub fn describe(&self, description: Value) {
        self.state().description = description;
    }

    /// Replaces the keys the provider publishes.
    pub fn publish(&self, keys: &[(&str, &SigningKey)]) {
        let published: Vec<Value> = keys.iter().map(|(id, key)| key.published(id)).collect();
        self.state().keys = json!({ "keys": published });
    }

    /// Replaces the published keys with a document given as it is.
    pub fn publish_raw(&self, document: Value) {
        self.state().keys = document;
    }

    /// Makes the token endpoint answer `code` with this ID token.
    pub fn answer_code(&self, code: &str, id_token: &str) {
        self.state()
            .codes
            .insert(code.to_owned(), CodeAnswer::Token(id_token.to_owned()));
    }

    /// Makes the token endpoint refuse `code`.
    pub fn refuse_code(&self, code: &str) {
        self.state()
            .codes
            .insert(code.to_owned(), CodeAnswer::Refused);
    }

    /// Makes every request fail, as when the provider is down.
    pub fn set_down(&self, down: bool) {
        self.state().down = down;
    }

    /// The requests that arrived, in order.
    #[must_use]
    pub fn requests(&self) -> Vec<HttpRequest> {
        self.state().requests.clone()
    }

    /// How many requests arrived for addresses ending in `suffix`.
    #[must_use]
    pub fn requests_to(&self, suffix: &str) -> usize {
        self.state()
            .requests
            .iter()
            .filter(|request| request.url.ends_with(suffix))
            .count()
    }
}

fn answer(status: u16, body: &Value) -> HttpResponse {
    HttpResponse {
        status,
        headers: vec![("content-type".to_owned(), "application/json".to_owned())],
        body: body.to_string().into_bytes(),
    }
}

#[async_trait::async_trait]
impl HttpClient for TestProvider {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, DomainError> {
        let mut state = self.state();
        state.requests.push(request.clone());
        if state.down {
            return Err(DomainError::new(
                hodor_kernel::ErrorKind::Unavailable,
                "http.unreachable",
                "the address did not answer",
            ));
        }
        let path = request
            .url
            .strip_prefix(&self.issuer)
            .unwrap_or(&request.url);
        Ok(match path {
            "/.well-known/openid-configuration" => answer(200, &state.description),
            "/keys" => answer(200, &state.keys),
            "/token" => {
                let form: HashMap<String, String> =
                    form_urlencoded::parse(request.body.as_deref().unwrap_or_default())
                        .into_owned()
                        .collect();
                match form.get("code").and_then(|code| state.codes.get(code)) {
                    Some(CodeAnswer::Token(token)) => answer(
                        200,
                        &json!({ "access_token": "unused", "token_type": "Bearer", "id_token": token }),
                    ),
                    Some(CodeAnswer::Refused) | None => {
                        answer(400, &json!({ "error": "invalid_grant" }))
                    }
                }
            }
            _ => answer(404, &json!({ "error": "not_found" })),
        })
    }
}
