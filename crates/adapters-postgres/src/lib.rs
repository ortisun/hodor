//! PostgreSQL adapter.
//!
//! Tenant data is reached only through a [`TenantTransaction`], which binds
//! the transaction to one tenant so that the row-level security policies
//! created by `platform.enable_tenant_rls` apply. Queries still filter by
//! `tenant_id` explicitly; row-level security is the second line of defence.

mod access_list;
mod api_key;
mod audit;
mod authentication;
mod authorization;
mod certificate_authority;
mod cleanup;
mod credential;
mod database;
mod decision_log;
mod federation;
mod group;
mod identity;
mod intermediates;
mod invitation;
mod key_rotation;
mod keys;
mod migrate;
mod notification;
mod oauth;
mod oauth_access_token;
mod oauth_authorization;
mod oauth_claim_mapper;
mod oauth_consent;
mod oauth_logout;
mod oauth_pairwise;
mod oauth_refresh;
mod oauth_registration;
mod oauth_token;
mod organization;
mod outbox;
mod policy_bundles;
mod policy_lifecycle;
mod provisioning;
mod resealing;
mod session;
mod tenant;
#[cfg(feature = "testing")]
pub mod testing;
mod trust_domain;
mod uow;
mod webhooks;

pub use access_list::PgAccessListStore;
pub use api_key::PgApiKeyStore;
pub use audit::PgAuditLog;
pub use authentication::{
    PgAttemptStore, PgEmailSignInStore, PgTransactionStore, PgVerificationTokenStore,
};
pub use authorization::{PgEngineBindingStore, PgNativeRoleStore, PgRoleAssignmentStore};
pub use certificate_authority::PgAuthorityStore;
pub use cleanup::{
    AccessTokenCleanup, CleanupReport, ExpiredKind, ExpiredRowCleanup, PendingAuthorizationCleanup,
};
pub use credential::{
    PgAccessTokenStore, PgPasswordStore, PgRecoveryCodeStore, PgTotpStore, PgWebAuthnStore,
};
pub use database::{Database, TenantTransaction, connect_pool, ping_pool};
pub use decision_log::{
    DAYS_PREPARED_AHEAD, DecisionLogMaintenance, DecisionLogMaintenanceReport, PgDecisionLogStore,
};
pub use federation::{PgLinkStore, PgPendingAuthorizationStore, PgProviderStore};
pub use group::{PgGroupPolicy, PgGroupRepository};
pub use identity::{PgUserRepository, PgWorkloadRepository};
pub use intermediates::PgIntermediateStore;
pub use invitation::PgInvitationRepository;
pub use key_rotation::{KeyRotationJob, RotationPass};
pub use keys::{PgKeyStore, PgSealingStateStore};
pub use migrate::migrate;
pub use notification::{PgMessageQueue, PgPendingMessages};
pub use oauth::{PgApplicationStore, PgClientStore, PgResourceServerStore};
pub use oauth_access_token::PgAccessTokenRecordStore;
pub use oauth_authorization::{
    PgAuthorizationCodeStore, PgAuthorizationRequestStore, PgGrantStore,
};
pub use oauth_claim_mapper::PgClaimMapperStore;
pub use oauth_consent::PgConsentStore;
pub use oauth_logout::{PgDueLogoutDeliveries, PgLogoutDeliveryStore, PgSessionClients};
pub use oauth_pairwise::PgPairwiseSecretStore;
pub use oauth_refresh::PgRefreshTokenStore;
pub use oauth_registration::{PgClientRegistrationStore, PgInitialAccessTokenStore};
pub use oauth_token::PgClientAssertionStore;
pub use organization::PgOrganizationRepository;
pub use outbox::{DispatchReport, OutboxDispatcher};
pub use policy_bundles::{
    PgBundleStore, PgInstanceStatusStore, PgInstanceStore, PgUploadedDecisionStore,
};
pub use policy_lifecycle::{
    PgPolicyVersionStore, PgPublicationStore, PgSimulationStore, PolicyCheckJob, PolicyCheckPass,
};
pub use provisioning::{
    PgDeprovisioningPolicy, PgProvisionedGroupRepository, PgProvisionedUserRepository,
};
pub use resealing::{ResealReport, SEALED_COLUMNS, SealedColumn, reseal_tenant};
pub use session::PgSessionStore;
pub use sqlx::migrate::MigrateError;
pub use sqlx::{Error, PgPool};
pub use tenant::{PgTenantDirectory, PgTenantRepository};
pub use trust_domain::{PgDueRefreshes, PgTrustDomainStore};
pub use uow::{PgUnitOfWork, connection};
pub use webhooks::{PgDeliveryStore, PgDueDeliveries, PgEndpointStore};
