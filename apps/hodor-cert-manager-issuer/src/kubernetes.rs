//! The cluster, through the Kubernetes client for Rust: the
//! `CertificateRequest`s watched and written, the issuer's two kinds read,
//! and their `Ready` condition kept.
//!
//! Specified in `docs/operations/hodor-cert-manager-issuer.md`, "Its
//! kinds" and "What it may do in the cluster".

use crate::hodor::Signer;
use crate::reconcile::{Cluster, ClusterError, Next, Reconciler, Request};
use crate::request::{
    Addressed, CLUSTER_ISSUER_KIND, CertificateRequestSpec, CertificateRequestStatus, GROUP,
    ISSUER_KIND, VERSION,
};
use async_trait::async_trait;
use futures::StreamExt as _;
use kube::api::{Api, ListParams, Patch, PatchParams};
use kube::core::{ApiResource, DynamicObject, GroupVersionKind, Object};
use kube::runtime::controller::{Action, Controller};
use kube::runtime::watcher;
use kube::{Client, ResourceExt as _};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

/// How often the issuer's kinds are told whether Hodor gives a token.
pub const ISSUER_CHECK_INTERVAL: Duration = Duration::from_secs(60);
/// How long before a request the cluster could not be written for is
/// looked at again.
const AFTER_CLUSTER_ERROR: Duration = Duration::from_secs(5);

/// cert-manager's `CertificateRequest`, as the issuer reads it.
pub type CertificateRequest = Object<CertificateRequestSpec, CertificateRequestStatus>;

/// cert-manager's `CertificateRequest`.
#[must_use]
pub fn certificate_requests() -> ApiResource {
    ApiResource::from_gvk_with_plural(
        &GroupVersionKind::gvk("cert-manager.io", "v1", "CertificateRequest"),
        "certificaterequests",
    )
}

/// The issuer's kind for one namespace.
#[must_use]
pub fn issuers() -> ApiResource {
    ApiResource::from_gvk_with_plural(
        &GroupVersionKind::gvk(GROUP, VERSION, ISSUER_KIND),
        "hodorissuers",
    )
}

/// The issuer's kind for every namespace.
#[must_use]
pub fn cluster_issuers() -> ApiResource {
    ApiResource::from_gvk_with_plural(
        &GroupVersionKind::gvk(GROUP, VERSION, CLUSTER_ISSUER_KIND),
        "hodorclusterissuers",
    )
}

/// The present moment, as RFC 3339 text in seconds, as Kubernetes writes
/// times.
#[must_use]
pub fn now() -> String {
    let now = OffsetDateTime::now_utc();
    now.replace_nanosecond(0)
        .unwrap_or(now)
        .format(&Rfc3339)
        .unwrap_or_default()
}

fn cluster_error(error: &kube::Error) -> ClusterError {
    ClusterError(error.to_string())
}

/// The cluster through a Kubernetes client.
#[derive(Clone)]
pub struct Kubernetes {
    client: Client,
}

impl std::fmt::Debug for Kubernetes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Kubernetes").finish_non_exhaustive()
    }
}

impl Kubernetes {
    /// The cluster `client` reaches.
    #[must_use]
    pub const fn new(client: Client) -> Self {
        Self { client }
    }
}

#[async_trait]
impl Cluster for Kubernetes {
    async fn issuer_exists(
        &self,
        namespace: &str,
        addressed: &Addressed,
    ) -> Result<bool, ClusterError> {
        let (api, name): (Api<DynamicObject>, &str) = match addressed {
            Addressed::Issuer(name) => (
                Api::namespaced_with(self.client.clone(), namespace, &issuers()),
                name,
            ),
            Addressed::ClusterIssuer(name) => {
                (Api::all_with(self.client.clone(), &cluster_issuers()), name)
            }
        };
        if name.is_empty() {
            return Ok(false);
        }
        api.get_opt(name)
            .await
            .map(|found| found.is_some())
            .map_err(|error| cluster_error(&error))
    }

    async fn write_status(&self, request: &Request, status: Value) -> Result<(), ClusterError> {
        let api: Api<CertificateRequest> = Api::namespaced_with(
            self.client.clone(),
            &request.namespace,
            &certificate_requests(),
        );
        // Naming the version read makes the server refuse the change if
        // the request changed since.
        let mut patch = json!({ "status": status });
        if let (Some(version), Some(object)) = (&request.resource_version, patch.as_object_mut()) {
            object.insert("metadata".to_owned(), json!({ "resourceVersion": version }));
        }
        api.patch_status(
            &request.name,
            &PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await
        .map(|_| ())
        .map_err(|error| cluster_error(&error))
    }
}

/// Watches every `CertificateRequest` of the cluster and does with each
/// what `reconciler` says, until `stop` resolves.
pub async fn run(
    client: Client,
    reconciler: Arc<Reconciler>,
    stop: impl std::future::Future<Output = ()> + Send + Sync + 'static,
) {
    let requests: Api<CertificateRequest> = Api::all_with(client, &certificate_requests());
    Controller::new_with(requests, watcher::Config::default(), certificate_requests())
        .graceful_shutdown_on(stop)
        .run(reconcile, after_error, reconciler)
        .for_each(|done| async move {
            if let Err(error) = done {
                tracing::debug!(%error, "a certificate request was not reconciled");
            }
        })
        .await;
}

async fn reconcile(
    object: Arc<CertificateRequest>,
    reconciler: Arc<Reconciler>,
) -> Result<Action, ClusterError> {
    let request = Request {
        namespace: object.namespace().unwrap_or_default(),
        name: object.name_any(),
        uid: object.uid().unwrap_or_else(|| object.name_any()),
        resource_version: object.resource_version(),
        spec: object.spec.clone(),
        status: object.status.clone(),
    };
    match reconciler.reconcile(&request, &now()).await? {
        Next::WhenChanged => Ok(Action::await_change()),
        Next::After(wait) => Ok(Action::requeue(wait)),
    }
}

fn after_error(
    object: Arc<CertificateRequest>,
    error: &ClusterError,
    _: Arc<Reconciler>,
) -> Action {
    tracing::warn!(
        namespace = %object.namespace().unwrap_or_default(),
        name = %object.name_any(),
        %error,
        "a certificate request could not be written; it is looked at again"
    );
    Action::requeue(AFTER_CLUSTER_ERROR)
}

/// Sets the `Ready` condition of every `HodorIssuer` and
/// `HodorClusterIssuer` from whether Hodor gives the issuer a token, every
/// `interval`, until the process stops.
pub async fn keep_issuers_ready(client: Client, signer: Arc<dyn Signer>, interval: Duration) {
    let mut ticks = tokio::time::interval(interval);
    loop {
        ticks.tick().await;
        let (status, reason, message) = match signer.check_access().await {
            Ok(()) => (
                "True",
                "Ready",
                "Hodor gives the issuer an access token for its certificate authority".to_owned(),
            ),
            Err(failure) => ("False", "Unavailable", failure.to_string()),
        };
        for resource in [issuers(), cluster_issuers()] {
            let api: Api<DynamicObject> = Api::all_with(client.clone(), &resource);
            let found = match api.list(&ListParams::default()).await {
                Ok(found) => found,
                Err(error) => {
                    tracing::debug!(kind = %resource.kind, %error, "the issuers could not be listed");
                    continue;
                }
            };
            for issuer in found {
                set_ready(&client, &resource, &issuer, status, reason, &message).await;
            }
        }
    }
}

async fn set_ready(
    client: &Client,
    resource: &ApiResource,
    issuer: &DynamicObject,
    status: &str,
    reason: &str,
    message: &str,
) {
    let previous = issuer
        .data
        .pointer("/status/conditions")
        .and_then(Value::as_array)
        .and_then(|conditions| {
            conditions
                .iter()
                .find(|condition| condition.get("type") == Some(&json!("Ready")))
        });
    let same = previous.is_some_and(|previous| {
        previous.get("status") == Some(&json!(status))
            && previous.get("reason") == Some(&json!(reason))
            && previous.get("message") == Some(&json!(message))
    });
    if same {
        return;
    }
    let changed_at = previous
        .filter(|previous| previous.get("status") == Some(&json!(status)))
        .and_then(|previous| previous.get("lastTransitionTime").cloned())
        .unwrap_or_else(|| json!(now()));
    let patch = json!({
        "status": {
            "conditions": [{
                "type": "Ready",
                "status": status,
                "reason": reason,
                "message": message,
                "lastTransitionTime": changed_at,
            }]
        }
    });
    let api: Api<DynamicObject> = match issuer.namespace() {
        Some(namespace) => Api::namespaced_with(client.clone(), &namespace, resource),
        None => Api::all_with(client.clone(), resource),
    };
    if let Err(error) = api
        .patch_status(
            &issuer.name_any(),
            &PatchParams::default(),
            &Patch::Merge(&patch),
        )
        .await
    {
        tracing::debug!(name = %issuer.name_any(), %error, "an issuer's condition could not be written");
    }
}
