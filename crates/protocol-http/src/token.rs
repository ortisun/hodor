//! The token endpoint of OAuth 2.x, where a client proves who it is and
//! exchanges a grant for tokens, and the revocation and introspection
//! endpoints, where it ends a token or asks about one.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Token endpoint and
//! client authentication" and "Revocation, introspection and metadata".
//! These handlers translate between HTTP and the OAuth context; the rules
//! are the context's.

use crate::tenant::TenantSlug;
use axum::body::Bytes;
use axum::extract::State;
use axum::http::StatusCode;
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Extension, Json, Router};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hodor_kernel::{CorrelationId, Secret, TenantContext};
use hodor_oauth::api::{
    BasicCredentials, ForwardedIdentity, IssuedTokens, Issuer, TokenError, TokenQuery,
    TokenRequest, TokenService,
};
use serde::Serialize;

/// What the token endpoint needs.
#[derive(Clone)]
pub struct TokenState {
    /// The use cases of the endpoint.
    pub tokens: TokenService,
    /// The address people reach this installation at, without a path. The
    /// issuer of a tenant is this address followed by `/t/{slug}`.
    pub public_url: String,
}

impl std::fmt::Debug for TokenState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TokenState").finish_non_exhaustive()
    }
}

/// The routes of the token, revocation and introspection endpoints, to be
/// mounted under a tenant at `/oauth2`.
pub fn token_routes(state: TokenState) -> Router {
    Router::new()
        .route("/token", post(token))
        .route("/revoke", post(revoke))
        .route("/introspect", post(introspect))
        .with_state(state)
}

#[derive(Serialize)]
struct TokenAnswer<'a> {
    access_token: &'a str,
    token_type: &'static str,
    expires_in: i64,
    #[serde(skip_serializing_if = "str::is_empty")]
    scope: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    refresh_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    id_token: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    issued_token_type: Option<&'static str>,
}

#[derive(Serialize)]
struct ErrorAnswer {
    error: &'static str,
    error_description: &'static str,
}

/// No answer of the token endpoint may be kept by a cache (RFC 6749,
/// section 5.1).
fn not_cached(mut response: Response) -> Response {
    let headers = response.headers_mut();
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    response
}

fn refused(error: TokenError, used_basic: bool, issuer: &str) -> Response {
    let status = if error.is_invalid_client() {
        StatusCode::UNAUTHORIZED
    } else if error.is_server_error() {
        StatusCode::INTERNAL_SERVER_ERROR
    } else {
        StatusCode::BAD_REQUEST
    };
    tracing::info!(
        error = error.error,
        reason = error.reason,
        "OAuth request refused"
    );
    let mut response = (
        status,
        Json(ErrorAnswer {
            error: error.error,
            error_description: error.description,
        }),
    )
        .into_response();
    if error.is_invalid_client()
        && used_basic
        && let Ok(challenge) = HeaderValue::from_str(&format!("Basic realm=\"{issuer}\""))
    {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, challenge);
    }
    not_cached(response)
}

fn answered(tokens: &IssuedTokens) -> Response {
    not_cached(
        Json(TokenAnswer {
            access_token: tokens.access_token.expose(),
            token_type: tokens.token_type,
            expires_in: tokens.expires_in,
            scope: &tokens.scope,
            refresh_token: tokens
                .refresh_token
                .as_ref()
                .map(|token| token.expose().as_str()),
            id_token: tokens
                .id_token
                .as_ref()
                .map(|token| token.expose().as_str()),
            issued_token_type: tokens.issued_token_type,
        })
        .into_response(),
    )
}

/// Undoes the form encoding of one part of `Basic` credentials (RFC 6749,
/// appendix B): `+` is a space and `%XX` a byte.
fn form_decoded(part: &str) -> Option<String> {
    let bytes = part.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => decoded.push(b' '),
            b'%' => {
                let pair = bytes.get(index + 1..index + 3)?;
                let text = std::str::from_utf8(pair).ok()?;
                decoded.push(u8::from_str_radix(text, 16).ok()?);
                index += 2;
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }
    String::from_utf8(decoded).ok()
}

/// The client identifier and secret of an `Authorization: Basic` header.
fn basic_credentials(value: &str) -> Option<BasicCredentials> {
    let (scheme, encoded) = value.trim().split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return None;
    }
    let pair = String::from_utf8(STANDARD.decode(encoded.trim()).ok()?).ok()?;
    let (client_id, secret) = pair.split_once(':')?;
    Some(BasicCredentials {
        client_id: form_decoded(client_id)?,
        secret: Secret::from(form_decoded(secret)?),
    })
}

enum Authorization {
    None,
    Basic(BasicCredentials),
    Malformed,
    OtherScheme,
}

fn authorization(headers: &HeaderMap) -> Authorization {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Authorization::None;
    };
    let Ok(value) = value.to_str() else {
        return Authorization::Malformed;
    };
    let is_basic = value
        .trim_start()
        .get(..6)
        .is_some_and(|scheme| scheme.eq_ignore_ascii_case("basic "));
    if !is_basic {
        return Authorization::OtherScheme;
    }
    basic_credentials(value).map_or(Authorization::Malformed, Authorization::Basic)
}

/// What every one of these endpoints reads first: that the body is a form,
/// and the `Basic` credentials if any.
struct FormRequest {
    basic: Option<BasicCredentials>,
    used_basic: bool,
}

/// The form request, or the refusal to answer with and whether `Basic` was
/// used.
fn read_form(headers: &HeaderMap) -> Result<FormRequest, (TokenError, bool)> {
    let is_form = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(';').next())
        .is_some_and(|kind| {
            kind.trim()
                .eq_ignore_ascii_case("application/x-www-form-urlencoded")
        });
    if !is_form {
        return Err((TokenError::invalid_request("the body is not a form"), false));
    }
    match authorization(headers) {
        Authorization::None => Ok(FormRequest {
            basic: None,
            used_basic: false,
        }),
        Authorization::Basic(credentials) => Ok(FormRequest {
            basic: Some(credentials),
            used_basic: true,
        }),
        Authorization::Malformed => Err((
            TokenError::invalid_client("the Authorization header is malformed"),
            true,
        )),
        Authorization::OtherScheme => Err((
            TokenError::invalid_request("the Authorization header is not Basic"),
            false,
        )),
    }
}

fn issuer_of(public_url: &str, slug: &str) -> String {
    format!("{}/t/{slug}", public_url.trim_end_matches('/'))
}

async fn token(
    State(state): State<TokenState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    forwarded: Option<Extension<ForwardedIdentity>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let issuer = issuer_of(&state.public_url, &slug);
    let token_endpoint = format!("{issuer}/oauth2/token");
    let FormRequest { basic, used_basic } = match read_form(&headers) {
        Ok(form) => form,
        Err((error, used_basic)) => return refused(error, used_basic, &issuer),
    };
    let request = match TokenRequest::parse(basic, form_urlencoded::parse(&body).into_owned()) {
        Ok(request) => request.with_forwarded(forwarded.map(|Extension(found)| found)),
        Err(error) => return refused(error, used_basic, &issuer),
    };
    let correlation_id = CorrelationId::generate();
    let answer = state
        .tokens
        .token(
            &tenant,
            Issuer {
                issuer: &issuer,
                token_endpoint: &token_endpoint,
            },
            request,
            correlation_id,
        )
        .await;
    match answer {
        Ok(Ok(tokens)) => answered(&tokens),
        Ok(Err(error)) => refused(error, used_basic, &issuer),
        Err(error) => {
            tracing::error!(%error, "the token endpoint could not answer");
            refused(
                TokenError::server_error("storage or signing failed"),
                used_basic,
                &issuer,
            )
        }
    }
}

async fn revoke(
    State(state): State<TokenState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    forwarded: Option<Extension<ForwardedIdentity>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let issuer = issuer_of(&state.public_url, &slug);
    let token_endpoint = format!("{issuer}/oauth2/token");
    let endpoint = format!("{issuer}/oauth2/revoke");
    let FormRequest { basic, used_basic } = match read_form(&headers) {
        Ok(form) => form,
        Err((error, used_basic)) => return refused(error, used_basic, &issuer),
    };
    let mut query = match TokenQuery::parse(basic, form_urlencoded::parse(&body).into_owned()) {
        Ok(query) => query,
        Err(error) => return refused(error, used_basic, &issuer),
    };
    query.client = query
        .client
        .with_forwarded(forwarded.map(|Extension(found)| found));
    let answer = state
        .tokens
        .revoke(
            &tenant,
            Issuer {
                issuer: &issuer,
                token_endpoint: &token_endpoint,
            },
            &endpoint,
            query,
            CorrelationId::generate(),
        )
        .await;
    match answer {
        // Whatever the token was, a client that proved who it is is
        // answered the same (RFC 7009, section 2.2).
        Ok(Ok(())) => not_cached(StatusCode::OK.into_response()),
        Ok(Err(error)) => refused(error, used_basic, &issuer),
        Err(error) => {
            tracing::error!(%error, "the revocation endpoint could not answer");
            refused(
                TokenError::server_error("storage failed"),
                used_basic,
                &issuer,
            )
        }
    }
}

async fn introspect(
    State(state): State<TokenState>,
    Extension(tenant): Extension<TenantContext>,
    Extension(TenantSlug(slug)): Extension<TenantSlug>,
    forwarded: Option<Extension<ForwardedIdentity>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    let issuer = issuer_of(&state.public_url, &slug);
    let token_endpoint = format!("{issuer}/oauth2/token");
    let endpoint = format!("{issuer}/oauth2/introspect");
    let FormRequest { basic, used_basic } = match read_form(&headers) {
        Ok(form) => form,
        Err((error, used_basic)) => return refused(error, used_basic, &issuer),
    };
    let mut query = match TokenQuery::parse(basic, form_urlencoded::parse(&body).into_owned()) {
        Ok(query) => query,
        Err(error) => return refused(error, used_basic, &issuer),
    };
    query.client = query
        .client
        .with_forwarded(forwarded.map(|Extension(found)| found));
    let answer = state
        .tokens
        .introspect(
            &tenant,
            Issuer {
                issuer: &issuer,
                token_endpoint: &token_endpoint,
            },
            &endpoint,
            query,
        )
        .await;
    match answer {
        Ok(Ok(answer)) => not_cached(Json(answer).into_response()),
        Ok(Err(error)) => refused(error, used_basic, &issuer),
        Err(error) => {
            tracing::error!(%error, "the introspection endpoint could not answer");
            refused(
                TokenError::server_error("storage or the keys failed"),
                used_basic,
                &issuer,
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basic_credentials_are_form_decoded() {
        let encoded = STANDARD.encode("a%20client:p%40ss+word%3A");
        let credentials = basic_credentials(&format!("Basic {encoded}")).expect("read");
        assert_eq!(credentials.client_id, "a client");
        assert_eq!(credentials.secret.expose(), "p@ss word:");
        let lower = basic_credentials(&format!("basic {encoded}")).expect("any case");
        assert_eq!(lower.client_id, "a client");
    }

    #[test]
    fn malformed_basic_credentials_are_refused() {
        for value in [
            "Basic".to_owned(),
            "Basic ***".to_owned(),
            format!("Basic {}", STANDARD.encode("no colon")),
            format!("Basic {}", STANDARD.encode("bad%zz:secret")),
            format!("Basic {}", STANDARD.encode("cut%2:secret")),
            format!("Bearer {}", STANDARD.encode("a:b")),
        ] {
            assert!(basic_credentials(&value).is_none(), "{value}");
        }
    }
}
