//! What the issuer does with one `CertificateRequest`: the order of
//! "What it signs", and the answers of "What it writes back", in
//! `docs/operations/hodor-cert-manager-issuer.md`.
//!
//! The cluster and Hodor are reached through two ports, so that the order
//! is tested without either.

use crate::hodor::{Failure, Signer};
use crate::request::{
    Addressed, CertificateRequestSpec, CertificateRequestStatus, Outcome, Prepared, Step, prepare,
    step,
};
use async_trait::async_trait;
use opentelemetry::KeyValue;
use opentelemetry::metrics::Counter;
use serde_json::Value;
use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The first wait before a pending request is looked at again.
pub const FIRST_WAIT: Duration = Duration::from_secs(10);
/// The longest wait before a pending request is looked at again.
pub const LONGEST_WAIT: Duration = Duration::from_secs(300);

/// Why the cluster could not be read or written.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClusterError(pub String);

impl fmt::Display for ClusterError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "the cluster could not be read or written: {}", self.0)
    }
}

impl std::error::Error for ClusterError {}

/// One `CertificateRequest`, as read.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Its namespace.
    pub namespace: String,
    /// Its name.
    pub name: String,
    /// Its unique identifier, which names it across renames and
    /// recreations.
    pub uid: String,
    /// The version it was read at, which a change must name.
    pub resource_version: Option<String>,
    /// Its `spec`.
    pub spec: CertificateRequestSpec,
    /// Its `status`.
    pub status: Option<CertificateRequestStatus>,
}

/// The cluster, as the issuer reads and writes it.
#[async_trait]
pub trait Cluster: Send + Sync {
    /// Whether the issuer a request in `namespace` is addressed to exists.
    async fn issuer_exists(
        &self,
        namespace: &str,
        addressed: &Addressed,
    ) -> Result<bool, ClusterError>;

    /// Merges `status` into the request's status, if it is still at the
    /// version it was read at.
    async fn write_status(&self, request: &Request, status: Value) -> Result<(), ClusterError>;
}

/// When to look at a request again.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Next {
    /// When it changes.
    WhenChanged,
    /// After this wait, or when it changes, whichever comes first.
    After(Duration),
}

/// How long the issuer waits, per pending request.
#[derive(Debug, Clone, Copy)]
struct Waiting {
    attempts: u32,
    until: Instant,
}

/// Does what the issuer does with each request.
pub struct Reconciler {
    cluster: Arc<dyn Cluster>,
    signer: Arc<dyn Signer>,
    waiting: Mutex<HashMap<String, Waiting>>,
    first_wait: Duration,
    requests: Counter<u64>,
}

impl fmt::Debug for Reconciler {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Reconciler").finish_non_exhaustive()
    }
}

/// The wait after `attempts` failed tries: 10 seconds, doubling, at most 5
/// minutes.
#[must_use]
pub fn wait_after(attempts: u32) -> Duration {
    waits_from(FIRST_WAIT, attempts)
}

fn waits_from(first: Duration, attempts: u32) -> Duration {
    let doubled = first.saturating_mul(2_u32.saturating_pow(attempts.saturating_sub(1)));
    doubled.min(LONGEST_WAIT)
}

impl Reconciler {
    /// The issuer over `cluster` and `signer`.
    #[must_use]
    pub fn new(cluster: Arc<dyn Cluster>, signer: Arc<dyn Signer>) -> Self {
        let requests = opentelemetry::global::meter("hodor-cert-manager-issuer")
            .u64_counter("hodor.cert_manager_issuer.requests")
            .with_description("Certificate requests the issuer acted on, by outcome")
            .build();
        Self {
            cluster,
            signer,
            waiting: Mutex::new(HashMap::new()),
            first_wait: FIRST_WAIT,
            requests,
        }
    }

    /// The same, with another first wait than 10 seconds: for tests, which
    /// do not wait that long.
    #[must_use]
    pub const fn with_first_wait(mut self, first_wait: Duration) -> Self {
        self.first_wait = first_wait;
        self
    }

    fn forget(&self, request: &Request) {
        self.waiting
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&request.uid);
    }

    /// The wait left before a pending request may be tried again, if any.
    fn still_waiting(&self, request: &Request) -> Option<Duration> {
        let waiting = self.waiting.lock().unwrap_or_else(PoisonError::into_inner);
        let left = waiting
            .get(&request.uid)?
            .until
            .checked_duration_since(Instant::now())?;
        (!left.is_zero()).then_some(left)
    }

    /// Counts one more failed try of a request, and says how long to wait.
    fn wait(&self, request: &Request) -> Duration {
        let mut waiting = self.waiting.lock().unwrap_or_else(PoisonError::into_inner);
        let attempts = waiting
            .get(&request.uid)
            .map_or(0, |waiting| waiting.attempts)
            .saturating_add(1);
        let wait = waits_from(self.first_wait, attempts);
        waiting.insert(
            request.uid.clone(),
            Waiting {
                attempts,
                until: Instant::now() + wait,
            },
        );
        wait
    }

    /// Does what the issuer does with `request`, at `now`, as RFC 3339
    /// text, and says when to look at it again.
    ///
    /// # Errors
    ///
    /// Returns a [`ClusterError`] when the cluster could not be read or
    /// written; the request is then looked at again.
    pub async fn reconcile(&self, request: &Request, now: &str) -> Result<Next, ClusterError> {
        let addressed = match step(&request.spec, request.status.as_ref()) {
            Step::NotOurs | Step::AwaitApproval => return Ok(Next::WhenChanged),
            Step::Finished => {
                self.forget(request);
                return Ok(Next::WhenChanged);
            }
            Step::Deny => {
                let outcome = Outcome::Finished {
                    reason: "Denied",
                    message: "The CertificateRequest was denied by an approval controller, and \
                              was not sent to Hodor"
                        .to_owned(),
                };
                self.write(request, &outcome, "denied", now).await?;
                self.forget(request);
                return Ok(Next::WhenChanged);
            }
            Step::Approved(addressed) => addressed,
        };
        if let Some(left) = self.still_waiting(request) {
            return Ok(Next::After(left));
        }
        if !self
            .cluster
            .issuer_exists(&request.namespace, &addressed)
            .await?
        {
            let message = match &addressed {
                Addressed::Issuer(name) => format!(
                    "The HodorIssuer {name} does not exist in the namespace {}",
                    request.namespace
                ),
                Addressed::ClusterIssuer(name) => {
                    format!("The HodorClusterIssuer {name} does not exist")
                }
            };
            return self.pending(request, message, now).await;
        }
        let (pem, lifetime_days) = match prepare(&request.spec) {
            Prepared::NotAnAuthority => {
                let outcome = Outcome::Finished {
                    reason: "Failed",
                    message: "The request is not for an authority (spec.isCA is not true): \
                              Hodor's certificate authority signs only the intermediates of \
                              meshes, and it was not sent to Hodor"
                        .to_owned(),
                };
                self.write(request, &outcome, "not_an_authority", now)
                    .await?;
                self.forget(request);
                return Ok(Next::WhenChanged);
            }
            Prepared::Unreadable => {
                let outcome = Outcome::Finished {
                    reason: "Failed",
                    message: "The request's spec.request is not base64 text, and was not sent \
                              to Hodor"
                        .to_owned(),
                };
                self.write(request, &outcome, "refused", now).await?;
                self.forget(request);
                return Ok(Next::WhenChanged);
            }
            Prepared::Send {
                request: pem,
                lifetime_days,
            } => (pem, lifetime_days),
        };
        match self.signer.sign(&pem, lifetime_days).await {
            Ok(signed) => {
                let outcome = Outcome::issued(&signed);
                self.write(request, &outcome, "issued", now).await?;
                self.forget(request);
                Ok(Next::WhenChanged)
            }
            Err(refusal @ Failure::Refused { .. }) => {
                let outcome = Outcome::Finished {
                    reason: "Failed",
                    message: refusal.to_string(),
                };
                self.write(request, &outcome, "refused", now).await?;
                self.forget(request);
                Ok(Next::WhenChanged)
            }
            Err(unavailable @ Failure::Unavailable(_)) => {
                self.pending(request, unavailable.to_string(), now).await
            }
        }
    }

    /// Marks a request pending, unless it says so already, and waits.
    async fn pending(
        &self,
        request: &Request,
        message: String,
        now: &str,
    ) -> Result<Next, ClusterError> {
        let wait = self.wait(request);
        let said = request.status.as_ref().is_some_and(|status| {
            status.conditions.iter().any(|condition| {
                condition.kind == "Ready"
                    && condition.status == "False"
                    && condition.reason.as_deref() == Some("Pending")
                    && condition.message.as_deref() == Some(message.as_str())
            })
        });
        let outcome = Outcome::Pending { message };
        if said {
            self.count(request, &outcome, "pending");
        } else {
            self.write(request, &outcome, "pending", now).await?;
        }
        Ok(Next::After(wait))
    }

    fn count(&self, request: &Request, outcome: &Outcome, name: &'static str) {
        self.requests.add(1, &[KeyValue::new("outcome", name)]);
        let message = match outcome {
            Outcome::Issued { message, .. }
            | Outcome::Finished { message, .. }
            | Outcome::Pending { message } => message.as_str(),
        };
        match outcome {
            Outcome::Pending { .. } => tracing::warn!(
                namespace = %request.namespace,
                name = %request.name,
                outcome = name,
                message,
                "certificate request pending"
            ),
            _ => tracing::info!(
                namespace = %request.namespace,
                name = %request.name,
                outcome = name,
                message,
                "certificate request done"
            ),
        }
    }

    async fn write(
        &self,
        request: &Request,
        outcome: &Outcome,
        name: &'static str,
        now: &str,
    ) -> Result<(), ClusterError> {
        let conditions = request
            .status
            .as_ref()
            .map_or(&[][..], |status| status.conditions.as_slice());
        self.cluster
            .write_status(request, outcome.status_patch(conditions, now))
            .await?;
        self.count(request, outcome, name);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::{LONGEST_WAIT, wait_after};
    use std::time::Duration;

    #[test]
    fn the_wait_doubles_from_ten_seconds_to_five_minutes() {
        let waits: Vec<u64> = (1..=8)
            .map(|attempts| wait_after(attempts).as_secs())
            .collect();
        assert_eq!(waits, vec![10, 20, 40, 80, 160, 300, 300, 300]);
        assert_eq!(wait_after(u32::MAX), LONGEST_WAIT);
        assert_eq!(wait_after(0), Duration::from_secs(10));
    }
}
