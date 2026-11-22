//! Outbound HTTP adapter.
//!
//! The implementations of the kernel's `HttpClient` port, and the one
//! place in Hodor that opens an HTTP connection. `GuardedHttpClient` calls
//! addresses somebody else chose, and decides whether the destination may
//! be called at all; `ServiceHttpClient` calls only the services the
//! operator configured. See `docs/security/outbound-http.md`.

mod address;
mod client;
mod service;

pub use address::is_public;
pub use client::{GuardedHttpClient, OutboundPolicy};
pub use service::ServiceHttpClient;
