//! The audit context.
//!
//! Keeps the record of what happened: every event any context announces
//! becomes one audit record, written once and never changed. The records
//! of a tenant are chained, so that changing or removing one of them can
//! be noticed.
//!
//! The specification is `docs/architecture/contexts/audit.md`; this crate
//! follows it.

mod application;
mod domain;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this context.
pub mod api {
    pub use crate::application::ports::AuditLog;
    pub use crate::application::service::{AuditHandler, AuditService};
    pub use crate::domain::record::{AuditRecord, ChainBreak, ChainHead, Verification, Verifier};
}
