//! Envoy's `envoy.service.auth.v3.Authorization`, answered by Hodor.
//!
//! Every check is one `evaluate`; every failure is a denial, answered as a
//! well-formed `CheckResponse` and never as a gRPC error, so that the
//! proxy's own failure mode is never reached. Specified in
//! `docs/operations/hodor-ext-authz.md`, "When it denies".

use crate::check::{Denial, question};
use crate::config::Settings;
use crate::hodor::Hodor;
use envoy_types::ext_authz::v3::pb::{
    Authorization, AuthorizationServer, CheckRequest, CheckResponse, HttpStatusCode,
};
use envoy_types::ext_authz::v3::{
    CheckResponseExt as _, DeniedHttpResponseBuilder, OkHttpResponseBuilder,
};
use opentelemetry::KeyValue;
use opentelemetry::metrics::{Counter, Histogram};
use std::sync::Arc;
use std::time::Instant;
use tonic::{Request, Response, Status};

/// How a check ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// Hodor answered `ALLOW`.
    Allowed,
    /// Hodor answered something else, or the check was denied before
    /// Hodor was asked.
    Denied,
    /// Hodor gave no decision; denied.
    Failed,
}

impl Outcome {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Allowed => "allowed",
            Self::Denied => "denied",
            Self::Failed => "failed",
        }
    }
}

struct Metrics {
    checks: Counter<u64>,
    duration: Histogram<f64>,
}

struct Inner {
    settings: Settings,
    hodor: Hodor,
    metrics: Metrics,
}

/// The adapter: its settings and the way to Hodor.
#[derive(Clone)]
pub struct ExtAuthz {
    inner: Arc<Inner>,
}

impl std::fmt::Debug for ExtAuthz {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ExtAuthz").finish_non_exhaustive()
    }
}

impl ExtAuthz {
    /// The adapter for `settings`, reaching Hodor through `http`.
    #[must_use]
    pub fn new(settings: Settings, http: reqwest::Client) -> Self {
        let meter = opentelemetry::global::meter("hodor-ext-authz");
        let metrics = Metrics {
            checks: meter
                .u64_counter("hodor.ext_authz.checks")
                .with_description("Checks answered, by outcome: allowed, denied or failed")
                .build(),
            duration: meter
                .f64_histogram("hodor.ext_authz.check.duration")
                .with_unit("s")
                .with_description("How long a check took, Hodor's answer included")
                .build(),
        };
        let hodor = Hodor::new(&settings, http);
        Self {
            inner: Arc::new(Inner {
                settings,
                hodor,
                metrics,
            }),
        }
    }

    /// The gRPC service.
    #[must_use]
    pub fn service(self) -> AuthorizationServer<Self> {
        AuthorizationServer::new(self)
    }

    /// How a check ends, without the answer to the proxy.
    pub async fn decide(&self, check: &CheckRequest) -> Outcome {
        let inner = &self.inner;
        let asked = match question(&inner.settings, check) {
            Ok(asked) => asked,
            Err(Denial(reason)) => {
                tracing::info!(reason, "denied before asking Hodor");
                return Outcome::Denied;
            }
        };
        let destination = &inner.settings.applications[asked.application].destination;
        match inner.hodor.evaluate(asked.application, &asked.body).await {
            Ok(decided) if decided.allowed => Outcome::Allowed,
            Ok(decided) => {
                tracing::info!(
                    destination = %destination,
                    decision = %decided.decision,
                    decision_id = decided.decision_id.as_deref().unwrap_or_default(),
                    "denied by Hodor"
                );
                Outcome::Denied
            }
            Err(failure) => {
                tracing::warn!(
                    destination = %destination,
                    reason = %failure.0,
                    "denied: Hodor gave no decision"
                );
                Outcome::Failed
            }
        }
    }
}

/// The answer to the proxy: `OK`, or `PERMISSION_DENIED` with an HTTP 403
/// and no body.
fn response(outcome: Outcome) -> CheckResponse {
    if outcome == Outcome::Allowed {
        let mut response = CheckResponse::with_status(Status::ok("allowed"));
        response.set_http_response(OkHttpResponseBuilder::new());
        response
    } else {
        let mut response = CheckResponse::with_status(Status::permission_denied("denied"));
        let mut denied = DeniedHttpResponseBuilder::new();
        denied.set_http_status(HttpStatusCode::Forbidden);
        response.set_http_response(denied);
        response
    }
}

#[tonic::async_trait]
impl Authorization for ExtAuthz {
    async fn check(
        &self,
        request: Request<CheckRequest>,
    ) -> Result<Response<CheckResponse>, Status> {
        let started = Instant::now();
        let outcome = self.decide(request.get_ref()).await;
        let attributes = [KeyValue::new("outcome", outcome.as_str())];
        self.inner.metrics.checks.add(1, &attributes);
        self.inner
            .metrics
            .duration
            .record(started.elapsed().as_secs_f64(), &attributes);
        Ok(Response::new(response(outcome)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_denial_is_permission_denied_with_a_403_never_an_error() {
        use envoy_types::ext_authz::v3::pb::HttpResponse;
        let denied = response(Outcome::Failed);
        assert_eq!(response(Outcome::Denied), denied);
        assert_eq!(
            denied.status.as_ref().map(|status| status.code),
            Some(tonic::Code::PermissionDenied as i32)
        );
        match denied.http_response {
            Some(HttpResponse::DeniedResponse(answer)) => {
                assert_eq!(
                    answer.status.map(|status| status.code),
                    Some(HttpStatusCode::Forbidden as i32)
                );
                assert!(answer.body.is_empty());
            }
            other => panic!("not a denial: {other:?}"),
        }
        let allowed = response(Outcome::Allowed);
        assert_eq!(
            allowed.status.as_ref().map(|status| status.code),
            Some(tonic::Code::Ok as i32)
        );
        assert!(matches!(
            allowed.http_response,
            Some(HttpResponse::OkResponse(_))
        ));
    }
}
