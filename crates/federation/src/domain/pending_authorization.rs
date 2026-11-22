//! The pending authorization of one sign-in to a provider and back.

use crate::domain::link::Subject;
use crate::domain::provider::ProviderId;
use hodor_authentication::api::TransactionId;
use hodor_kernel::{SealedSecret, Timestamp};

/// What Hodor remembers while a person is away at a provider. It belongs
/// to one sign-in in progress and is used once.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PendingAuthorization {
    /// The sign-in the pending authorization belongs to.
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
    /// When the pending authorization can no longer be finished.
    pub expires_at: Timestamp,
    /// What the response a SAML identity provider posted said, checked when
    /// it arrived. Kept once; `None` until then, and for every other kind.
    /// The response itself is never kept.
    pub saml_answer: Option<SamlAnswer>,
    /// The SHA-256 of the receipt given to the browser that posted the
    /// response. Kept with the answer: only that browser can finish with it.
    pub saml_receipt_hash: Option<[u8; 32]>,
}

/// What a SAML response said, once it was checked on arrival.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SamlAnswer {
    /// It passed every check: who the person is.
    Verified {
        /// The `NameID`.
        subject: Subject,
        /// The address, if the identity provider gave one.
        email: Option<String>,
        /// The name, if the identity provider gave one.
        name: Option<String>,
    },
    /// It was refused, for this reason.
    Refused {
        /// The fixed name of the reason, such as `signature`.
        reason: &'static str,
    },
}

/// Reasons a SAML response is refused for that are not the checks of
/// `hodor-saml`.
const OTHER_REFUSALS: [&str; 2] = ["certificate_unusable", "subject"];

impl SamlAnswer {
    /// The reason of a refusal read from storage, as its fixed name.
    #[must_use]
    pub fn refusal_named(name: &str) -> Option<&'static str> {
        hodor_saml::Reason::from_name(name)
            .map(hodor_saml::Reason::as_str)
            .or_else(|| OTHER_REFUSALS.into_iter().find(|other| *other == name))
    }
}
