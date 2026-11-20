//! Authenticators: what performs one step of a flow.
//!
//! This trait is the context's extension point. The built-in
//! authenticators live in this context; federation and plugins add theirs
//! by implementing it.

use crate::domain::transaction::AuthTransaction;
use hodor_kernel::{DomainError, Secret, TenantContext, UserId};

/// The kind of evidence a step provides.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Factor {
    /// Something the person knows, such as a password.
    Knowledge,
    /// Something the person has, such as a phone or a security key.
    Possession,
    /// Something the person is, such as a fingerprint.
    Inherence,
}

/// What an authenticator contributes to a flow. Used to check a flow
/// before it runs and to work out the assurance of a completed sign-in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AuthenticatorTraits {
    /// Whether the step establishes who is trying to sign in.
    pub identifies: bool,
    /// The kind of evidence the step provides, if it proves anything.
    pub factor: Option<Factor>,
    /// The name recorded in the session for a satisfied step, if any.
    pub method: Option<&'static str>,
}

/// What a person submitted for a step.
#[derive(Debug)]
pub enum StepInput {
    /// The login identifier, as typed.
    Identifier(String),
    /// The password, as typed.
    Password(Secret<String>),
}

impl StepInput {
    /// The key of the step this input is for.
    #[must_use]
    pub const fn step_key(&self) -> &'static str {
        match self {
            Self::Identifier(_) => "identifier",
            Self::Password(_) => "password",
        }
    }
}

/// The answer of an authenticator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StepOutcome {
    /// The step established who is trying to sign in.
    ///
    /// `candidate` is empty when the identifier belongs to nobody. The
    /// flow continues in the same way, so that the person signing in
    /// cannot tell.
    Identified {
        /// The user the identifier belongs to, if any.
        candidate: Option<UserId>,
        /// A digest of the normalized identifier, for counting attempts.
        identifier_key: [u8; 32],
    },
    /// The step proved the candidate's identity by this authenticator's
    /// factor.
    Proven,
    /// The step was not satisfied. No reason is given, on purpose.
    Rejected,
}

/// Performs one step of a flow.
#[async_trait::async_trait]
pub trait Authenticator: Send + Sync {
    /// The name flows use to refer to this authenticator.
    fn kind(&self) -> &'static str;

    /// What this authenticator contributes.
    fn traits(&self) -> AuthenticatorTraits;

    /// Performs the step for the given transaction.
    ///
    /// # Errors
    ///
    /// Returns an error when the step could not be performed at all, for
    /// example because of too many attempts or an unavailable dependency.
    /// A wrong secret is not an error: it is [`StepOutcome::Rejected`].
    async fn perform(
        &self,
        tenant: &TenantContext,
        transaction: &AuthTransaction,
        input: &StepInput,
    ) -> Result<StepOutcome, DomainError>;
}
