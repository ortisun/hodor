//! Access tokens presented with `Authorization: Bearer` (RFC 6750), and
//! the refusals the resource servers of Hodor answer with.

use axum::http::StatusCode;
use axum::http::header::{self, HeaderMap, HeaderValue};
use axum::response::{IntoResponse, Response};
use hodor_oauth::api::BearerRefusal;

/// The token of `Authorization: Bearer`, or nothing. A header with another
/// scheme carries no bearer token.
pub(crate) fn bearer(headers: &HeaderMap) -> Result<Option<&str>, ()> {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return Ok(None);
    };
    let value = value.to_str().map_err(|_| ())?;
    let (scheme, token) = value.trim().split_once(' ').ok_or(())?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return Err(());
    }
    let token = token.trim();
    if token.is_empty() {
        return Err(());
    }
    Ok(Some(token))
}

/// The response, never to be kept by a cache.
pub(crate) fn not_cached(mut response: Response) -> Response {
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}

/// The answer to a refused token: `401` with the challenge, or `403` when
/// the token lacks `scope`. `surface` names the resource server in the log.
pub(crate) fn refused(refusal: BearerRefusal, scope: &str, surface: &str) -> Response {
    let (status, challenge) = challenge(refusal, scope, surface);
    let mut response = status.into_response();
    if let Ok(value) = HeaderValue::from_str(&challenge) {
        response
            .headers_mut()
            .insert(header::WWW_AUTHENTICATE, value);
    }
    not_cached(response)
}

/// The status and the `WWW-Authenticate` challenge of a refused token,
/// for a surface that writes its own body. `surface` names the resource
/// server in the log.
pub(crate) fn challenge(
    refusal: BearerRefusal,
    scope: &str,
    surface: &str,
) -> (StatusCode, String) {
    match refusal {
        BearerRefusal::Missing => (StatusCode::UNAUTHORIZED, "Bearer".to_owned()),
        BearerRefusal::InvalidToken(reason) => {
            tracing::info!(reason, surface, "a bearer token was refused");
            (
                StatusCode::UNAUTHORIZED,
                "Bearer error=\"invalid_token\"".to_owned(),
            )
        }
        BearerRefusal::InsufficientScope => (
            StatusCode::FORBIDDEN,
            format!("Bearer error=\"insufficient_scope\", scope=\"{scope}\""),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with(value: &str) -> HeaderMap {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(value).expect("header"),
        );
        headers
    }

    #[test]
    fn a_bearer_token_is_read_from_its_header_only() {
        assert_eq!(bearer(&HeaderMap::new()), Ok(None));
        assert_eq!(bearer(&with("Bearer abc.def.ghi")), Ok(Some("abc.def.ghi")));
        assert_eq!(bearer(&with("bearer abc")), Ok(Some("abc")));
        assert_eq!(bearer(&with("Basic abc")), Err(()));
        assert_eq!(bearer(&with("Bearer ")), Err(()));
        assert_eq!(bearer(&with("Bearer")), Err(()));
    }

    #[test]
    fn a_missing_scope_is_named_in_the_challenge() {
        let response = refused(BearerRefusal::InsufficientScope, "authz:evaluate", "test");
        assert_eq!(response.status(), StatusCode::FORBIDDEN);
        assert_eq!(
            response.headers()[header::WWW_AUTHENTICATE],
            "Bearer error=\"insufficient_scope\", scope=\"authz:evaluate\""
        );
        assert_eq!(response.headers()[header::CACHE_CONTROL], "no-store");
    }
}
