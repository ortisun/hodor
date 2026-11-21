//! Outbound HTTP adapter.
//!
//! The one implementation of the kernel's `HttpClient` port, and the one
//! place in Hodor that opens a connection to an address somebody else
//! chose. It decides whether the destination may be called at all. See
//! `docs/security/outbound-http.md`.

mod address;
mod client;

pub use address::is_public;
pub use client::{GuardedHttpClient, OutboundPolicy};
