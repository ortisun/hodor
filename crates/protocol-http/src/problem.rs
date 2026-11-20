//! Error responses as RFC 9457 problem documents.

use crate::request::current_request_id;
use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use holdor_kernel::{DomainError, ErrorKind};
use serde::Serialize;

const GENERIC_INTERNAL_DETAIL: &str = "the request could not be completed";

/// An error response body (`application/problem+json`).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Problem {
    /// URI identifying the problem type.
    #[serde(rename = "type")]
    type_uri: String,
    /// Short summary of the status.
    title: &'static str,
    /// HTTP status code.
    status: u16,
    /// Explanation safe to show to the caller.
    detail: String,
    /// Stable machine-readable code.
    code: String,
    /// Identifier to quote when reporting the problem.
    #[serde(skip_serializing_if = "Option::is_none")]
    request_id: Option<String>,
}

impl Problem {
    /// Creates a problem document.
    #[must_use]
    pub fn new(status: StatusCode, code: impl Into<String>, detail: impl Into<String>) -> Self {
        let code = code.into();
        Self {
            type_uri: format!("urn:holdor:error:{code}"),
            title: status.canonical_reason().unwrap_or("Error"),
            status: status.as_u16(),
            detail: detail.into(),
            code,
            request_id: None,
        }
    }

    /// The HTTP status of this problem.
    #[must_use]
    pub fn status(&self) -> StatusCode {
        StatusCode::from_u16(self.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR)
    }
}

impl From<DomainError> for Problem {
    fn from(error: DomainError) -> Self {
        let status = match error.kind() {
            ErrorKind::NotFound => StatusCode::NOT_FOUND,
            ErrorKind::Conflict => StatusCode::CONFLICT,
            ErrorKind::Invalid => StatusCode::UNPROCESSABLE_ENTITY,
            ErrorKind::Forbidden => StatusCode::FORBIDDEN,
            ErrorKind::Unauthenticated => StatusCode::UNAUTHORIZED,
            ErrorKind::RateLimited => StatusCode::TOO_MANY_REQUESTS,
            ErrorKind::Unavailable => StatusCode::SERVICE_UNAVAILABLE,
            // `ErrorKind` is non-exhaustive: anything unknown is treated as
            // an internal error rather than leaked.
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        if status.is_server_error() {
            // Operators get the full story in the log; callers get a
            // generic message for internal errors.
            tracing::error!(
                code = error.code(),
                message = error.message(),
                detail = error.detail(),
                "request failed"
            );
        }
        let detail = if status == StatusCode::INTERNAL_SERVER_ERROR {
            GENERIC_INTERNAL_DETAIL
        } else {
            error.message()
        };
        Self::new(status, error.code(), detail)
    }
}

impl IntoResponse for Problem {
    fn into_response(mut self) -> Response {
        self.request_id = current_request_id().map(|id| id.to_string());
        let status = self.status();
        let body = serde_json::to_vec(&self).unwrap_or_else(|_| b"{}".to_vec());
        let mut response = (status, body).into_response();
        response.headers_mut().insert(
            header::CONTENT_TYPE,
            HeaderValue::from_static("application/problem+json"),
        );
        response
    }
}
