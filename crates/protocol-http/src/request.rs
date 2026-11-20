//! Per-request context: identifier, tracing span and security headers.

use axum::extract::Request;
use axum::http::header::{self, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use hodor_kernel::CorrelationId;
use tracing::Instrument as _;

tokio::task_local! {
    static REQUEST_ID: CorrelationId;
}

const X_REQUEST_ID: HeaderName = HeaderName::from_static("x-request-id");

/// Headers added to every response that does not set them itself. The
/// defaults suit JSON APIs; HTML routes override the content security
/// policy.
const SECURITY_HEADERS: &[(HeaderName, &str)] = &[
    (header::X_CONTENT_TYPE_OPTIONS, "nosniff"),
    (header::X_FRAME_OPTIONS, "DENY"),
    (header::REFERRER_POLICY, "no-referrer"),
    (
        header::CONTENT_SECURITY_POLICY,
        "default-src 'none'; frame-ancestors 'none'",
    ),
    (header::CACHE_CONTROL, "no-store"),
    (
        header::STRICT_TRANSPORT_SECURITY,
        "max-age=63072000; includeSubDomains",
    ),
];

/// The identifier of the request being handled, if any.
pub(crate) fn current_request_id() -> Option<CorrelationId> {
    REQUEST_ID.try_with(|id| *id).ok()
}

/// Outermost middleware: gives the request an identifier and a span, and
/// stamps the response with the identifier and the security headers.
///
/// The identifier is always generated here. Identifiers sent by the client
/// are ignored, so they cannot be used to forge log correlation. Only the
/// path is recorded, never the query string, which may carry codes or
/// tokens.
pub(crate) async fn request_context(mut request: Request, next: Next) -> Response {
    let request_id = CorrelationId::generate();
    let span = tracing::info_span!(
        "http.request",
        http.method = %request.method(),
        http.path = %request.uri().path(),
        http.status = tracing::field::Empty,
        request_id = %request_id,
        tenant_id = tracing::field::Empty,
    );
    request.extensions_mut().insert(request_id);

    let mut response = REQUEST_ID
        .scope(request_id, next.run(request))
        .instrument(span.clone())
        .await;
    span.record("http.status", response.status().as_u16());

    let headers = response.headers_mut();
    if let Ok(value) = HeaderValue::from_str(&request_id.to_string()) {
        headers.insert(X_REQUEST_ID, value);
    }
    for (name, value) in SECURITY_HEADERS {
        if !headers.contains_key(name) {
            headers.insert(name.clone(), HeaderValue::from_static(value));
        }
    }
    response
}
