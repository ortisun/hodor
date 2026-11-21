//! PostgreSQL adapter.
//!
//! Tenant data is reached only through a [`TenantTransaction`], which binds
//! the transaction to one tenant so that the row-level security policies
//! created by `platform.enable_tenant_rls` apply. Queries still filter by
//! `tenant_id` explicitly; row-level security is the second line of defence.

mod authentication;
mod credential;
mod database;
mod identity;
mod migrate;
mod notification;
mod outbox;
mod session;
mod tenant;
#[cfg(feature = "testing")]
pub mod testing;
mod uow;

pub use authentication::{PgAttemptStore, PgTransactionStore};
pub use credential::PgPasswordStore;
pub use database::{Database, TenantTransaction, connect_pool, ping_pool};
pub use identity::PgUserRepository;
pub use migrate::migrate;
pub use notification::{PgMessageQueue, PgPendingMessages};
pub use outbox::{DispatchReport, OutboxDispatcher};
pub use session::PgSessionStore;
pub use sqlx::migrate::MigrateError;
pub use sqlx::{Error, PgPool};
pub use tenant::{PgTenantDirectory, PgTenantRepository};
pub use uow::{PgUnitOfWork, connection};
