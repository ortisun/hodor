//! Per-request context: identifier, tracing span and security headers.

use crate::client_address::TrustedProxies;
use crate::forwarded_identity::{IdentityHeader, Read};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::header::{self, HeaderName, HeaderValue};
use axum::middleware::Next;
use axum::response::Response;
use hodor_kernel::CorrelationId;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, OnceLock};
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

/// The network address a request came from.
///
/// This is the address of the connection, or the address a trusted proxy
/// forwarded when the connection comes from one: see
/// [`TrustedProxies::resolve`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientAddress(pub Option<IpAddr>);

/// Counts the forwarded headers of trusted proxies that could not be read.
fn unreadable_forwarded_addresses() -> &'static Counter<u64> {
    static COUNTER: OnceLock<Counter<u64>> = OnceLock::new();
    COUNTER.get_or_init(|| {
        opentelemetry::global::meter("hodor.server")
            .u64_counter("hodor.http.forwarded_address.unreadable")
            .with_description(
                "Forwarded headers of trusted proxies that could not be read, by reason",
            )
            .build()
    })
}

/// Counts the headers of the caller's identity that trusted proxies sent
/// and that could not be read.
fn unreadable_forwarded_identities() -> &'static Counter<u64> {
    static COUNTER: OnceLock<Counter<u64>> = OnceLock::new();
    COUNTER.get_or_init(|| {
        opentelemetry::global::meter("hodor.server")
            .u64_counter("hodor.http.forwarded_identity.unreadable")
            .with_description(
                "Headers of the caller's identity from trusted proxies that could not be read, \
                 by header",
            )
            .build()
    })
}

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
///
/// The client address is set here too, once, before anything reads it,
/// and the caller's identity a trusted proxy forwarded, as a
/// `ForwardedIdentity` extension, when it holds one.
pub(crate) async fn request_context(
    State(proxies): State<Arc<TrustedProxies>>,
    mut request: Request,
    next: Next,
) -> Response {
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
    let peer = request
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|connection| connection.0.ip());
    let resolved = proxies.resolve(peer, request.headers());
    if let Some(unreadable) = resolved.unreadable {
        unreadable_forwarded_addresses().add(1, &[KeyValue::new("reason", unreadable.as_str())]);
        tracing::debug!(
            reason = unreadable.as_str(),
            "the forwarded header of a trusted proxy could not be read; the connection's address is used"
        );
    }
    request
        .extensions_mut()
        .insert(ClientAddress(resolved.address));
    match proxies.forwarded_identity(peer, request.headers()) {
        Read::Identity(identity) => {
            request.extensions_mut().insert(identity);
        }
        Read::Unreadable => {
            let header = proxies.identity_header().map_or("", IdentityHeader::as_str);
            unreadable_forwarded_identities().add(1, &[KeyValue::new("header", header)]);
            tracing::debug!(
                header,
                "the header of the caller's identity from a trusted proxy could not be read; \
                 no identity is forwarded"
            );
        }
        Read::Absent => {}
    }

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
