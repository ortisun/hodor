//! Open Policy Agent as an engine of the authorization context.
//!
//! `OpenPolicyAgentEngine` answers a request by asking an Open Policy
//! Agent instance through its Data API, on a path built from the tenant
//! and the binding alone. Every failure is indeterminate, with its own
//! reason. The authorization context does not know Open Policy Agent
//! exists (Decision 0010).
//!
//! The specification of what is built is
//! `docs/architecture/contexts/authorization.md`, "Open Policy Agent as an
//! engine"; this crate follows it.

mod answer;
mod breaker;
mod engine;
mod instances;
mod path;

/// What other crates may use from this engine.
pub mod api {
    pub use crate::breaker::BreakerSettings;
    pub use crate::engine::{ENGINE, OpenPolicyAgentEngine};
    pub use crate::instances::Instances;
    pub use crate::path::decision_path;
}
