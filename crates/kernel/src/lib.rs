//! Shared kernel of Hodor.
//!
//! A type belongs here only if at least three bounded contexts need it and it
//! carries no business rule owned by a single context. See
//! `docs/adr/0002-crate-consolidation.md`.

pub mod clock;
pub mod error;
pub mod event;
pub mod id;
pub mod page;
pub mod random;
pub mod secret;
pub mod tenant;

pub use clock::{Clock, SystemClock, Timestamp};
pub use error::{DomainError, ErrorKind};
pub use event::{Actor, DomainEvent, EventMetadata};
pub use id::{CorrelationId, EventId, ParseIdError, TenantId, UserId};
pub use page::{Cursor, Page, PageRequest};
pub use random::RandomSource;
pub use secret::Secret;
pub use tenant::TenantContext;

/// Re-exports used by this crate's macros. Not part of the public API.
#[doc(hidden)]
pub mod __private {
    pub use serde;
    pub use uuid;
}
