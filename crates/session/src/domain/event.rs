//! What happens to sessions, as other contexts hear about it.
//!
//! Events carry identifiers and never a token or its hash.

use crate::domain::session::SessionId;
use hodor_kernel::{DomainEvent, UserId};
use serde::Serialize;

/// An event of the session context.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum SessionEvent {
    /// A session started.
    Started {
        /// The session.
        session_id: SessionId,
        /// Whose session it is.
        user_id: UserId,
        /// `single_factor` or `multi_factor`.
        assurance: &'static str,
        /// The methods used to sign in.
        methods: Vec<String>,
    },
    /// A session was ended on purpose.
    Revoked {
        /// The session.
        session_id: SessionId,
        /// Whose session it was.
        user_id: UserId,
        /// Why.
        reason: String,
    },
}

impl DomainEvent for SessionEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Started { .. } => "session.started",
            Self::Revoked { .. } => "session.revoked",
        }
    }
}
