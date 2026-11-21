//! The trip of one sign-in to a provider and back.

use crate::domain::provider::ProviderId;
use hodor_authentication::api::TransactionId;
use hodor_kernel::{SealedSecret, Timestamp};

/// What Hodor remembers while a person is away at a provider. It belongs
/// to one sign-in in progress and is used once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Trip {
    /// The sign-in the trip belongs to.
    pub transaction_id: TransactionId,
    /// The provider the answer will be checked against.
    pub provider_id: ProviderId,
    /// The SHA-256 hash of the state sent to the provider.
    pub state_hash: [u8; 32],
    /// The nonce the provider must put in its token.
    pub nonce: String,
    /// The PKCE verifier, sealed.
    pub code_verifier: SealedSecret,
    /// The address the provider sends the person back to.
    pub redirect_uri: String,
    /// When the trip can no longer be finished.
    pub expires_at: Timestamp,
}
