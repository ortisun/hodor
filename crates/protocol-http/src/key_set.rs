//! The published key set: a tenant's signing keys, for those who check
//! the signatures of its tokens.
//!
//! Specified in `docs/architecture/contexts/keys.md`, "The published key
//! set". The answer is a JSON Web Key Set (RFC 7517) with the pending,
//! active and retiring signing versions, and nothing else of them.

use crate::problem::Problem;
use axum::extract::State;
use axum::http::header::{self, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::get;
use axum::{Extension, Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::{Caller, PublicKey, TenantContext};
use hodor_keys::api::{KeyService, KeyVersion, RotationPolicy};
use hodor_oauth::api::IdTokenAlgorithm;
use serde::Serialize;

/// One key of the set. Members that do not apply to a key's kind are left
/// out.
#[derive(Debug, Serialize)]
struct JsonWebKey {
    kid: String,
    kty: &'static str,
    #[serde(rename = "use")]
    key_use: &'static str,
    alg: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    crv: Option<&'static str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    x: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    y: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    n: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    e: Option<String>,
}

#[derive(Debug, Serialize)]
struct JsonWebKeySet {
    keys: Vec<JsonWebKey>,
}

fn encoded(bytes: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(bytes)
}

/// The key of a signing version, or nothing for a version without a public
/// key, which a signing version always has.
fn json_web_key(version: &KeyVersion) -> Option<JsonWebKey> {
    let key = JsonWebKey {
        kid: version.id().to_string(),
        kty: "",
        key_use: "sig",
        alg: version.algorithm().as_str(),
        crv: None,
        x: None,
        y: None,
        n: None,
        e: None,
    };
    match version.public_key()? {
        PublicKey::P256 { x, y } => Some(JsonWebKey {
            kty: "EC",
            crv: Some("P-256"),
            x: Some(encoded(x)),
            y: Some(encoded(y)),
            ..key
        }),
        PublicKey::Rsa { modulus, exponent } => Some(JsonWebKey {
            kty: "RSA",
            n: Some(encoded(modulus)),
            e: Some(encoded(exponent)),
            ..key
        }),
        // An octet key pair, as RFC 8037 writes an Ed25519 key.
        PublicKey::Ed25519 { x } => Some(JsonWebKey {
            kty: "OKP",
            crv: Some("Ed25519"),
            x: Some(encoded(x)),
            ..key
        }),
    }
}

/// The route of the published key set, to be mounted under a tenant: it
/// answers `GET /oauth2/jwks`.
pub fn key_set_routes(keys: KeyService) -> Router {
    Router::new()
        .route("/oauth2/jwks", get(published))
        .with_state(keys)
}

async fn published(
    State(keys): State<KeyService>,
    Extension(tenant): Extension<TenantContext>,
) -> Response {
    // The set names a key for every algorithm a token or an answer of the
    // tenant may be signed with, the four a client may choose, before the
    // first such token: a relying party that read the set of a tenant made
    // a moment ago must find the key of the first token it gets.
    for algorithm in IdTokenAlgorithm::ALL {
        if let Err(error) = keys
            .ensure_active(&tenant, algorithm.key_algorithm(), Caller::system())
            .await
        {
            return Problem::from(error).into_response();
        }
    }
    let versions = match keys.published_keys(&tenant).await {
        Ok(versions) => versions,
        Err(error) => return Problem::from(error).into_response(),
    };
    let set = JsonWebKeySet {
        keys: versions.iter().filter_map(json_web_key).collect(),
    };
    let mut response = Json(set).into_response();
    let headers = response.headers_mut();
    // As long as the rotation policy counts on, and no longer: a new
    // version is published for at least this before it signs.
    let max_age = RotationPolicy::PUBLISHED_FOR.whole_seconds();
    if let Ok(value) = HeaderValue::from_str(&format!("public, max-age={max_age}")) {
        headers.insert(header::CACHE_CONTROL, value);
    }
    // Public keys: any page may read them, to check an ID token itself.
    headers.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        HeaderValue::from_static("*"),
    );
    response
}
