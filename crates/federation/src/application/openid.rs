//! Hodor as an OpenID Connect relying party: what it asks a provider and
//! what it believes of the answer.
//!
//! See `docs/architecture/contexts/federation.md`, "Asking an OpenID
//! Connect provider who somebody is". Nothing in an ID token is believed
//! before every check there has passed.

use crate::domain::link::Subject;
use crate::domain::provider::IdentityProvider;
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hodor_kernel::{
    Clock, Digest, DomainError, ErrorKind, HttpClient, HttpRequest, PublicKey, RandomSource,
    Secret, SignatureAlgorithm, SignatureVerifier,
};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};

/// How long a provider's description and keys are kept.
const KEPT_FOR_SECONDS: i64 = 3600;
/// The shortest time between two fetches of one provider's keys caused by
/// tokens that name a key Hodor does not have.
const REFETCH_AFTER_SECONDS: i64 = 60;
/// How far two clocks may disagree.
const CLOCK_SKEW_SECONDS: i64 = 60;
const MAX_TOKEN_BYTES: usize = 16 * 1024;

fn unavailable(detail: impl Into<String>) -> DomainError {
    DomainError::new(
        ErrorKind::Unavailable,
        "federation.provider_unavailable",
        "the identity provider cannot be used right now",
    )
    .with_detail(detail)
}

fn not_verified(detail: impl Into<String>) -> DomainError {
    DomainError::new(
        ErrorKind::Unauthenticated,
        "federation.identity_not_verified",
        "the identity provider did not establish who you are",
    )
    .with_detail(detail)
}

/// What a provider says about itself, as far as Hodor uses it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Description {
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
    /// Whether the client secret goes in the body instead of the header.
    secret_in_body: bool,
}

/// One key a provider publishes.
#[derive(Debug, Clone, PartialEq, Eq)]
struct PublishedKey {
    id: Option<String>,
    algorithm: Option<String>,
    key: PublicKey,
}

#[derive(Debug, Clone)]
struct Kept {
    description: Description,
    described_at: i64,
    keys: Vec<PublishedKey>,
    keys_at: i64,
}

/// Where to send a person, and what to remember until they come back.
#[derive(Debug)]
pub struct AuthorizationRequest {
    /// The address at the provider to send the person to.
    pub url: String,
    /// Returned by the provider untouched; recognizes this trip.
    pub state: String,
    /// Put by the provider inside the token; ties the token to this trip.
    pub nonce: String,
    /// Proves, when the code is exchanged, that the exchange is made by
    /// whoever started the trip. Never sent to the browser.
    pub code_verifier: Secret<String>,
}

/// Who a provider says a person is, after every check has passed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedIdentity {
    /// The provider's own identifier for the person.
    pub subject: Subject,
    /// An email address, if the provider gave one.
    pub email: Option<String>,
    /// Whether the provider vouches for the address.
    pub email_verified: bool,
    /// A name, if the provider gave one.
    pub name: Option<String>,
    /// A preferred language, if the provider gave one.
    pub locale: Option<String>,
}

/// Talks to OpenID Connect providers.
#[derive(Clone)]
pub struct OpenIdClient {
    http: Arc<dyn HttpClient>,
    verifier: Arc<dyn SignatureVerifier>,
    digest: Arc<dyn Digest>,
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
    /// By issuer. Each server instance keeps its own.
    kept: Arc<Mutex<HashMap<String, Kept>>>,
}

impl std::fmt::Debug for OpenIdClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenIdClient").finish_non_exhaustive()
    }
}

fn text<'a>(object: &'a Value, name: &str) -> Option<&'a str> {
    object.get(name).and_then(Value::as_str)
}

fn https_address(description: &Value, name: &str) -> Result<String, DomainError> {
    text(description, name)
        .filter(|address| address.starts_with("https://") && address.len() <= 2048)
        .map(str::to_owned)
        .ok_or_else(|| unavailable(format!("the provider's description has no usable `{name}`")))
}

fn decode(part: &str) -> Option<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(part).ok()
}

fn number(claims: &Value, name: &str) -> Option<i64> {
    let value = claims.get(name)?;
    value.as_i64().or_else(|| {
        value
            .as_f64()
            .filter(|seconds| seconds.is_finite())
            // Whole seconds are all that is compared.
            .map(|seconds| seconds.trunc() as i64)
    })
}

fn published_keys(document: &Value) -> Vec<PublishedKey> {
    let Some(keys) = document.get("keys").and_then(Value::as_array) else {
        return Vec::new();
    };
    keys.iter()
        .filter(|key| text(key, "use").is_none_or(|purpose| purpose == "sig"))
        .filter_map(|key| {
            let part = |name: &str| text(key, name).and_then(decode);
            let public = match (text(key, "kty")?, text(key, "crv")) {
                ("RSA", _) => PublicKey::Rsa {
                    modulus: part("n")?,
                    exponent: part("e")?,
                },
                ("EC", Some("P-256")) => PublicKey::P256 {
                    x: part("x")?,
                    y: part("y")?,
                },
                _ => return None,
            };
            Some(PublishedKey {
                id: text(key, "kid").map(str::to_owned),
                algorithm: text(key, "alg").map(str::to_owned),
                key: public,
            })
        })
        .collect()
}

/// The keys that can have signed a token with this header.
fn fitting<'a>(
    keys: &'a [PublishedKey],
    key_id: Option<&str>,
    algorithm_name: &str,
    algorithm: SignatureAlgorithm,
) -> Vec<&'a PublishedKey> {
    keys.iter()
        .filter(|key| key_id.is_none() || key.id.as_deref() == key_id)
        .filter(|key| {
            key.algorithm
                .as_deref()
                .is_none_or(|named| named == algorithm_name)
        })
        .filter(|key| algorithm.fits(&key.key))
        .collect()
}

impl OpenIdClient {
    /// Wires the client to its ports.
    #[must_use]
    pub fn new(
        http: Arc<dyn HttpClient>,
        verifier: Arc<dyn SignatureVerifier>,
        digest: Arc<dyn Digest>,
        random: Arc<dyn RandomSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            http,
            verifier,
            digest,
            random,
            clock,
            kept: Arc::default(),
        }
    }

    fn now(&self) -> i64 {
        self.clock.now().unix_timestamp()
    }

    fn kept(&self) -> std::sync::MutexGuard<'_, HashMap<String, Kept>> {
        self.kept.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn random_hex(&self) -> String {
        let mut bytes = [0_u8; 32];
        self.random.fill(&mut bytes);
        bytes.iter().map(|byte| format!("{byte:02x}")).collect()
    }

    async fn fetch_json(&self, url: &str, what: &str) -> Result<Value, DomainError> {
        let response = self
            .http
            .send(HttpRequest::get(url).header("accept", "application/json"))
            .await
            .map_err(|error| {
                unavailable(format!("{what} could not be fetched: {}", error.code()))
            })?;
        if response.status != 200 {
            return Err(unavailable(format!(
                "{what} was answered with status {}",
                response.status
            )));
        }
        serde_json::from_slice::<Value>(&response.body)
            .ok()
            .filter(Value::is_object)
            .ok_or_else(|| unavailable(format!("{what} is not a JSON object")))
    }

    async fn describe(&self, issuer: &str) -> Result<Description, DomainError> {
        let url = format!(
            "{}/.well-known/openid-configuration",
            issuer.trim_end_matches('/')
        );
        let document = self.fetch_json(&url, "the provider's description").await?;
        if text(&document, "issuer") != Some(issuer) {
            return Err(unavailable(
                "the provider's description names another issuer than the configured one",
            ));
        }
        let methods = document
            .get("token_endpoint_auth_methods_supported")
            .and_then(Value::as_array);
        let supports = |method: &str| {
            methods.is_some_and(|all| all.iter().any(|named| named.as_str() == Some(method)))
        };
        // The header is the default of the specification.
        let secret_in_body =
            methods.is_some() && !supports("client_secret_basic") && supports("client_secret_post");
        if methods.is_some() && !supports("client_secret_basic") && !secret_in_body {
            return Err(unavailable(
                "the provider accepts no way of presenting a client secret that Hodor has",
            ));
        }
        Ok(Description {
            authorization_endpoint: https_address(&document, "authorization_endpoint")?,
            token_endpoint: https_address(&document, "token_endpoint")?,
            jwks_uri: https_address(&document, "jwks_uri")?,
            secret_in_body,
        })
    }

    async fn fetch_keys(&self, jwks_uri: &str) -> Result<Vec<PublishedKey>, DomainError> {
        let document = self.fetch_json(jwks_uri, "the provider's keys").await?;
        let keys = published_keys(&document);
        if keys.is_empty() {
            return Err(unavailable("the provider publishes no key Hodor can use"));
        }
        Ok(keys)
    }

    /// What is known about a provider, fetched if it is not kept or was
    /// kept for too long.
    async fn known(&self, issuer: &str) -> Result<Kept, DomainError> {
        let now = self.now();
        let kept = self.kept().get(issuer).cloned();
        if let Some(kept) = kept
            && now - kept.described_at < KEPT_FOR_SECONDS
            && now - kept.keys_at < KEPT_FOR_SECONDS
            && now >= kept.described_at
        {
            return Ok(kept);
        }
        let description = self.describe(issuer).await?;
        let keys = self.fetch_keys(&description.jwks_uri).await?;
        let fresh = Kept {
            description,
            described_at: now,
            keys,
            keys_at: now,
        };
        self.kept().insert(issuer.to_owned(), fresh.clone());
        Ok(fresh)
    }

    /// Fetches a provider's keys again because a token named one Hodor
    /// does not have, unless that was done for this provider a moment ago.
    async fn keys_again(
        &self,
        issuer: &str,
        known: &Kept,
    ) -> Result<Option<Vec<PublishedKey>>, DomainError> {
        let now = self.now();
        if (0..REFETCH_AFTER_SECONDS).contains(&(now - known.keys_at)) {
            return Ok(None);
        }
        // Marked before fetching: a provider that fails to answer is not
        // asked again for a minute either.
        if let Some(kept) = self.kept().get_mut(issuer) {
            kept.keys_at = now;
        }
        let keys = self.fetch_keys(&known.description.jwks_uri).await?;
        if let Some(kept) = self.kept().get_mut(issuer) {
            kept.keys.clone_from(&keys);
        }
        Ok(Some(keys))
    }

    /// Prepares one trip to the provider: the address to send the person
    /// to, and the three values made for this trip.
    ///
    /// # Errors
    ///
    /// Returns `federation.provider_unavailable` if the provider's
    /// description cannot be had or cannot be used.
    pub async fn begin(
        &self,
        provider: &IdentityProvider,
        redirect_uri: &str,
    ) -> Result<AuthorizationRequest, DomainError> {
        let settings = &provider.snapshot().settings;
        let known = self.known(&settings.issuer).await?;

        let state = self.random_hex();
        let nonce = self.random_hex();
        let mut verifier_bytes = [0_u8; 32];
        self.random.fill(&mut verifier_bytes);
        let code_verifier = URL_SAFE_NO_PAD.encode(verifier_bytes);
        let challenge = URL_SAFE_NO_PAD.encode(self.digest.sha256(code_verifier.as_bytes()));

        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("response_type", "code")
            .append_pair("client_id", &settings.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &settings.scopes.join(" "))
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256")
            .finish();
        let endpoint = &known.description.authorization_endpoint;
        let joint = if endpoint.contains('?') { '&' } else { '?' };
        Ok(AuthorizationRequest {
            url: format!("{endpoint}{joint}{query}"),
            state,
            nonce,
            code_verifier: Secret::new(code_verifier),
        })
    }

    /// Exchanges the code a person came back with and checks the ID
    /// token it yields against everything this trip was made with.
    ///
    /// # Errors
    ///
    /// Returns `federation.identity_not_verified` if the code is refused
    /// or the token fails any check, with the reason as the error's
    /// detail, and `federation.provider_unavailable` if the provider
    /// cannot be reached or used.
    pub async fn finish(
        &self,
        provider: &IdentityProvider,
        client_secret: &Secret<String>,
        redirect_uri: &str,
        code: &str,
        code_verifier: &Secret<String>,
        nonce: &str,
    ) -> Result<VerifiedIdentity, DomainError> {
        let settings = &provider.snapshot().settings;
        let known = self.known(&settings.issuer).await?;

        // Built in a scope of its own: the form encoder must not live
        // across the request.
        let request = {
            let mut form = form_urlencoded::Serializer::new(String::new());
            form.append_pair("grant_type", "authorization_code")
                .append_pair("code", code)
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("code_verifier", code_verifier.expose());
            let mut request_headers = Vec::new();
            if known.description.secret_in_body {
                form.append_pair("client_id", &settings.client_id)
                    .append_pair("client_secret", client_secret.expose());
            } else {
                // Each part is form-encoded before the two are joined, as
                // RFC 6749, section 2.3.1, asks.
                let encode = |part: &str| -> String {
                    form_urlencoded::byte_serialize(part.as_bytes()).collect()
                };
                let pair = format!(
                    "{}:{}",
                    encode(&settings.client_id),
                    encode(client_secret.expose())
                );
                request_headers.push(("authorization", format!("Basic {}", STANDARD.encode(pair))));
            }
            let mut request = HttpRequest::post(
                known.description.token_endpoint.clone(),
                "application/x-www-form-urlencoded",
                form.finish().into_bytes(),
            )
            .header("accept", "application/json");
            for (name, value) in request_headers {
                request = request.header(name, value);
            }
            request
        };
        let response = self.http.send(request).await.map_err(|error| {
            unavailable(format!("the code could not be exchanged: {}", error.code()))
        })?;
        let answer: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
        if response.status != 200 {
            // The provider's own error name, as far as it is a plain word.
            let named: String = text(&answer, "error")
                .unwrap_or("no reason given")
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .take(64)
                .collect();
            return Err(not_verified(format!(
                "the provider refused the code with status {}: {named}",
                response.status
            )));
        }
        let token = text(&answer, "id_token")
            .ok_or_else(|| not_verified("the provider's answer carries no ID token"))?;

        self.check(&settings.issuer, &settings.client_id, &known, token, nonce)
            .await
    }

    /// Every check of an ID token, in the order of the specification's
    /// table. Nothing of the token is used before the last one passed.
    async fn check(
        &self,
        issuer: &str,
        client_id: &str,
        known: &Kept,
        token: &str,
        nonce: &str,
    ) -> Result<VerifiedIdentity, DomainError> {
        // Shape.
        if token.len() > MAX_TOKEN_BYTES {
            return Err(not_verified("the ID token is too large"));
        }
        let parts: Vec<&str> = token.split('.').collect();
        let [header_part, claims_part, signature_part] = parts.as_slice() else {
            return Err(not_verified("the ID token is not three parts"));
        };
        let malformed = || not_verified("the ID token is malformed");
        let header: Value = decode(header_part)
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .filter(Value::is_object)
            .ok_or_else(malformed)?;
        let signature = decode(signature_part).ok_or_else(malformed)?;

        // Algorithm.
        let algorithm_name = text(&header, "alg").ok_or_else(malformed)?;
        let algorithm = SignatureAlgorithm::from_name(algorithm_name)
            .ok_or_else(|| not_verified("the ID token names an algorithm that is not accepted"))?;

        // Key.
        let key_id = text(&header, "kid");
        let refetched;
        let mut candidates = fitting(&known.keys, key_id, algorithm_name, algorithm);
        if candidates.is_empty()
            && let Some(keys) = self.keys_again(issuer, known).await?
        {
            refetched = keys;
            candidates = fitting(&refetched, key_id, algorithm_name, algorithm);
        }
        let key = match candidates.as_slice() {
            [key] => key,
            [] => {
                return Err(not_verified(
                    "the ID token names a key the provider does not publish for this algorithm",
                ));
            }
            _ => {
                return Err(not_verified(
                    "the ID token does not say which of the provider's keys signed it",
                ));
            }
        };

        // Signature, over the first two parts exactly as they arrived.
        let signed = format!("{header_part}.{claims_part}");
        if !self
            .verifier
            .verify(algorithm, &key.key, signed.as_bytes(), &signature)
        {
            return Err(not_verified(
                "the signature of the ID token does not verify",
            ));
        }

        // Only now is anything the token says read.
        let claims: Value = decode(claims_part)
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .filter(Value::is_object)
            .ok_or_else(malformed)?;

        // Issuer.
        if text(&claims, "iss") != Some(issuer) {
            return Err(not_verified("the ID token is from another issuer"));
        }

        // Audience.
        let audiences: Vec<&str> = match claims.get("aud") {
            Some(Value::String(one)) => vec![one.as_str()],
            Some(Value::Array(many)) => many.iter().filter_map(Value::as_str).collect(),
            _ => Vec::new(),
        };
        if !audiences.contains(&client_id) {
            return Err(not_verified("the ID token was not issued for this client"));
        }
        let authorized_party = claims.get("azp");
        if audiences.len() > 1 && authorized_party.is_none() {
            return Err(not_verified(
                "the ID token has several audiences and does not say which may use it",
            ));
        }
        if authorized_party.is_some_and(|party| party.as_str() != Some(client_id)) {
            return Err(not_verified(
                "the ID token was issued for another client to use",
            ));
        }

        // Time.
        let now = self.now();
        let expires = number(&claims, "exp")
            .ok_or_else(|| not_verified("the ID token does not say when it expires"))?;
        let issued = number(&claims, "iat")
            .ok_or_else(|| not_verified("the ID token does not say when it was issued"))?;
        if expires.saturating_add(CLOCK_SKEW_SECONDS) <= now {
            return Err(not_verified("the ID token has expired"));
        }
        if issued > now.saturating_add(CLOCK_SKEW_SECONDS) {
            return Err(not_verified("the ID token was issued in the future"));
        }
        if number(&claims, "nbf")
            .is_some_and(|start| start > now.saturating_add(CLOCK_SKEW_SECONDS))
        {
            return Err(not_verified("the ID token is not valid yet"));
        }

        // Nonce.
        if nonce.is_empty() || text(&claims, "nonce") != Some(nonce) {
            return Err(not_verified("the ID token was not issued for this trip"));
        }

        // Subject.
        let subject = text(&claims, "sub")
            .and_then(|subject| Subject::parse(subject).ok())
            .ok_or_else(|| not_verified("the ID token names no usable subject"))?;

        let short = |name: &str, limit: usize| {
            text(&claims, name)
                .map(str::trim)
                .filter(|value| !value.is_empty() && value.chars().count() <= limit)
                .map(str::to_owned)
        };
        Ok(VerifiedIdentity {
            subject,
            email: short("email", 254),
            // Exactly the JSON value `true`; the text "true" is not it.
            email_verified: claims.get("email_verified") == Some(&Value::Bool(true)),
            name: short("name", 200),
            locale: short("locale", 35),
        })
    }
}
