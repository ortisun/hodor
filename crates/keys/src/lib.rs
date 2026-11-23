//! The keys context.
//!
//! Owns the keys a tenant's tokens are signed with and its secrets are
//! encrypted under: key sets per use, key versions and their lifecycle.
//! It holds no cryptography: keys are made, kept and used by a
//! [`api::KeyProvider`].
//!
//! The specification is `docs/architecture/contexts/keys.md`; this crate
//! follows it.

mod application;
mod domain;
#[cfg(any(test, feature = "testing"))]
pub mod testing;

/// What other crates may use from this context.
pub mod api {
    pub use crate::application::ports::{
        FirstFormatSecrets, KeyProvider, KeyStore, SealingStateStore,
    };
    pub use crate::application::secret_box::{FORMAT as SEALED_FORMAT, LOST_RACE, TenantSecretBox};
    pub use crate::application::service::{KeyService, LOST_FIRST_RACE, RotationReport, Signature};
    pub use crate::domain::event::KeyEvent;
    pub use crate::domain::key::{
        GeneratedKey, KeyAlgorithm, KeyMaterial, KeyState, KeyUse, KeyVersion, KeyVersionId,
        KeyVersionSnapshot, MAX_REASON_LENGTH,
    };
    pub use crate::domain::key_set::{Activation, KeySet};
    pub use crate::domain::rotation::{RotationChange, RotationPolicy};
}
