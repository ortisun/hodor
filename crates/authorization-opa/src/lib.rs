//! Open Policy Agent as an engine of the authorization context, and the
//! bundles that bring it its policies.
//!
//! `OpenPolicyAgentEngine` answers a request by asking an Open Policy
//! Agent instance through its Data API, on a path built from the tenant
//! and the binding alone. Every failure is indeterminate, with its own
//! reason. `BundleService` registers instances, publishes signed bundles
//! and takes what instances pull and report. The authorization context
//! does not know Open Policy Agent exists (Decision 0010).
//!
//! The specification of what is built is
//! `docs/architecture/contexts/authorization.md`, "Open Policy Agent as an
//! engine" and "Bundles"; this crate follows it.

mod answer;
mod archive;
mod breaker;
mod bundle;
mod canonical;
mod engine;
mod instance;
mod instances;
mod path;
mod ports;
mod reports;
mod service;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this engine.
pub mod api {
    pub use crate::archive::gzip;
    pub use crate::breaker::BreakerSettings;
    pub use crate::bundle::{
        Author, BundleFile, BundleSigner, PublishedBundle, bundle_name, tenant_of, tenant_root,
    };
    pub use crate::canonical::to_canonical;
    pub use crate::engine::{ENGINE, OpenPolicyAgentEngine};
    pub use crate::instance::{CREDENTIAL_PREFIX, Instance, InstanceId, InstanceName};
    pub use crate::instances::Instances;
    pub use crate::path::decision_path;
    pub use crate::ports::{
        BundleStore, InstanceStatus, InstanceStatusStore, InstanceStore, UploadedDecision,
        UploadedDecisionStore,
    };
    pub use crate::service::{BundleEvent, BundleService, MAX_EXPANDED_UPLOAD_BYTES, Pull};
}
