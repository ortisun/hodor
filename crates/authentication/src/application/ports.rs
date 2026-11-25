//! What the authentication context needs from storage.

use crate::domain::attempt::{AttemptCounter, AttemptSubject};
use crate::domain::email::{EmailMethod, EmailSecretHash, EmailSignIn, EmailUse};
use crate::domain::transaction::{AuthTransaction, TransactionId};
use crate::domain::verification::{TokenPurpose, VerificationToken, VerificationTokenHash};
use hodor_kernel::{DomainError, Timestamp, UnitOfWork};

/// Keeps the attempt counters of a tenant. Every method works inside the
/// tenant the unit of work is bound to.
#[async_trait::async_trait]
pub trait AttemptStore: Send + Sync {
    /// Loads the counter of a subject, creating an empty one if there is
    /// none, and keeps it to itself until the unit of work ends.
    ///
    /// Two units of work asking for the same subject are served one after
    /// the other. That is what makes the limit exact when many attempts
    /// arrive at once.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        subject: &AttemptSubject,
        now: Timestamp,
    ) -> Result<AttemptCounter, DomainError>;

    /// Stores a counter obtained from [`AttemptStore::lock`] in the same
    /// unit of work.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn save(
        &self,
        uow: &mut dyn UnitOfWork,
        counter: &AttemptCounter,
    ) -> Result<(), DomainError>;

    /// Forgets everything counted against a subject.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn clear(
        &self,
        uow: &mut dyn UnitOfWork,
        subject: &AttemptSubject,
    ) -> Result<(), DomainError>;
}

/// Stores sign-ins in progress. Every method works inside the tenant the
/// unit of work is bound to.
#[async_trait::async_trait]
pub trait TransactionStore: Send + Sync {
    /// Stores a new transaction.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction: &AuthTransaction,
    ) -> Result<(), DomainError>;

    /// Loads a transaction of the tenant.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TransactionId,
    ) -> Result<Option<AuthTransaction>, DomainError>;

    /// Stores changes to a transaction loaded earlier.
    ///
    /// The transaction's version must be the one that was loaded. This is
    /// what makes completion happen once: of two requests that try to
    /// complete the same transaction, the second finds a newer version.
    ///
    /// # Errors
    ///
    /// Returns `Conflict` with code
    /// `authentication.transaction_modified_concurrently` if the stored
    /// version differs, and `NotFound` if the tenant has no such
    /// transaction.
    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction: &AuthTransaction,
    ) -> Result<(), DomainError>;
}

/// Stores verification tokens. Every method works inside the tenant the
/// unit of work is bound to.
#[async_trait::async_trait]
pub trait VerificationTokenStore: Send + Sync {
    /// Stores a new token.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        token: &VerificationToken,
    ) -> Result<(), DomainError>;

    /// Marks every unused token of the purpose for the email address as
    /// replaced, so that only a token made afterwards is good.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn replace_earlier(
        &self,
        uow: &mut dyn UnitOfWork,
        purpose: TokenPurpose,
        email: &str,
        now: Timestamp,
    ) -> Result<(), DomainError>;

    /// Loads the token of the tenant with the given hash and purpose,
    /// whether or not it is still good.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &VerificationTokenHash,
        purpose: TokenPurpose,
    ) -> Result<Option<VerificationToken>, DomainError>;

    /// Uses the token up if it is good at `now`, and returns it. Of any
    /// number of calls made at the same moment for one token, exactly one
    /// gets it; the others, and every later call, get nothing.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn use_up(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &VerificationTokenHash,
        purpose: TokenPurpose,
        now: Timestamp,
    ) -> Result<Option<VerificationToken>, DomainError>;
}

/// Keeps what was sent to sign in by email: one code or link per sign-in.
/// Every method works inside the tenant the unit of work is bound to.
#[async_trait::async_trait]
pub trait EmailSignInStore: Send + Sync {
    /// Stores what was sent for a sign-in, in place of whatever was sent
    /// for it before.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn replace(
        &self,
        uow: &mut dyn UnitOfWork,
        sent: &EmailSignIn,
    ) -> Result<(), DomainError>;

    /// Loads what was sent for a sign-in of the tenant, whether or not it
    /// is still good.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction: TransactionId,
    ) -> Result<Option<EmailSignIn>, DomainError>;

    /// Uses up what was sent for a sign-in if it accepts `presented` for
    /// `method` at `now` ([`EmailSignIn::accepts`]). Of any number of calls
    /// made at the same moment with the right secret, exactly one gets
    /// [`EmailUse::Accepted`]; the others get [`EmailUse::AlreadyUsed`].
    /// Anything else is [`EmailUse::Refused`].
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    async fn use_up(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction: TransactionId,
        method: EmailMethod,
        presented: &EmailSecretHash,
        now: Timestamp,
    ) -> Result<EmailUse, DomainError>;
}
