//! PostgreSQL adapter.
//!
//! Tenant data is reached only through a [`TenantTransaction`], which binds
//! the transaction to one tenant so that the row-level security policies
//! created by `platform.enable_tenant_rls` apply. Queries still filter by
//! `tenant_id` explicitly; row-level security is the second line of defence.

mod audit;
mod authentication;
mod authorization;
mod cleanup;
mod credential;
mod database;
mod federation;
mod identity;
mod key_rotation;
mod keys;
mod migrate;
mod notification;
mod oauth;
mod oauth_authorization;
mod oauth_token;
mod outbox;
mod policy_bundles;
mod resealing;
mod session;
mod tenant;
#[cfg(feature = "testing")]
pub mod testing;
mod uow;

pub use audit::PgAuditLog;
pub use authentication::{PgAttemptStore, PgTransactionStore, PgVerificationTokenStore};
pub use authorization::{PgEngineBindingStore, PgNativeRoleStore, PgRoleAssignmentStore};
pub use cleanup::{CleanupReport, PendingAuthorizationCleanup};
pub use credential::{
    PgAccessTokenStore, PgPasswordStore, PgRecoveryCodeStore, PgTotpStore, PgWebAuthnStore,
};
pub use database::{Database, TenantTransaction, connect_pool, ping_pool};
pub use federation::{PgLinkStore, PgPendingAuthorizationStore, PgProviderStore};
pub use identity::PgUserRepository;
pub use key_rotation::{KeyRotationJob, RotationPass};
pub use keys::{PgKeyStore, PgSealingStateStore};
pub use migrate::migrate;
pub use notification::{PgMessageQueue, PgPendingMessages};
pub use oauth::{PgApplicationStore, PgClientStore, PgResourceServerStore};
pub use oauth_authorization::{
    PgAuthorizationCodeStore, PgAuthorizationRequestStore, PgGrantStore,
};
pub use oauth_token::PgClientAssertionStore;
pub use outbox::{DispatchReport, OutboxDispatcher};
pub use policy_bundles::{
    PgBundleStore, PgInstanceStatusStore, PgInstanceStore, PgUploadedDecisionStore,
};
pub use resealing::{ResealReport, SEALED_COLUMNS, SealedColumn, reseal_tenant};
pub use session::PgSessionStore;
pub use sqlx::migrate::MigrateError;
pub use sqlx::{Error, PgPool};
pub use tenant::{PgTenantDirectory, PgTenantRepository};
pub use uow::{PgUnitOfWork, connection};
