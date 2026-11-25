//! Back-channel logout: the outbox handler that makes a delivery for every
//! client signed in to with a session that ended, and the worker's use case
//! that signs and sends them.
//!
//! See `docs/architecture/contexts/oauth.md`, "Back-channel logout".

pub(crate) mod fan_out;
pub(crate) mod ports;
pub(crate) mod sender;
