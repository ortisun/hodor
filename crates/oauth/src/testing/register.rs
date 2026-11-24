//! The register of access tokens kept in memory, and the contract every
//! store of it passes.

use super::{InMemoryClients, lock};
use crate::api::{
    AccessTokenRecord, AccessTokenRecordStore, Application, ApplicationSettings, ApplicationStore,
    Client, ClientId, ClientSecret, ClientSettings, ClientStore, ClientType, GrantType,
};
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{
    DomainError, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use time::Duration;

/// The records of every tenant, by tenant and `jti`.
type RecordRows = BTreeMap<(TenantId, String), AccessTokenRecord>;

/// The register kept in memory. It knows the clients its records are
/// stored against, as the database knows its references; the references to
/// grants and families are the database's to keep.
#[derive(Debug, Clone)]
pub struct InMemoryAccessTokenRecords {
    clients: InMemoryClients,
    rows: Arc<Mutex<RecordRows>>,
}

impl InMemoryAccessTokenRecords {
    /// The register of the clients in `clients`.
    #[must_use]
    pub fn new(clients: &InMemoryClients) -> Self {
        Self {
            clients: clients.clone(),
            rows: Arc::default(),
        }
    }

    /// Every record of `tenant`, for tests that look behind the use cases.
    #[must_use]
    pub fn all(&self, tenant: TenantId) -> Vec<AccessTokenRecord> {
        lock(&self.rows)
            .iter()
            .filter(|((owner, _), _)| *owner == tenant)
            .map(|(_, record)| record.clone())
            .collect()
    }
}

#[async_trait::async_trait]
impl AccessTokenRecordStore for InMemoryAccessTokenRecords {
    async fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        record: &AccessTokenRecord,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        if !self.clients.exists(tenant, record.client_id) {
            return Err(DomainError::not_found(
                "oauth.client_not_found",
                "there is no such client",
            ));
        }
        lock(&self.rows).insert((tenant, record.token_id.clone()), record.clone());
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        token_id: &str,
    ) -> Result<Option<AccessTokenRecord>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(lock(&self.rows)
            .get(&(tenant, token_id.to_owned()))
            .cloned())
    }

    async fn revoke(
        &self,
        uow: &mut dyn UnitOfWork,
        client: ClientId,
        token_id: &str,
        at: Timestamp,
        reason: &str,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = lock(&self.rows);
        let Some(record) = rows.get_mut(&(tenant, token_id.to_owned())) else {
            return Ok(false);
        };
        if record.client_id != client || record.revoked_at.is_some() {
            return Ok(false);
        }
        record.revoked_at = Some(at);
        record.revocation_reason = Some(reason.to_owned());
        Ok(true)
    }

    async fn revoke_for_principal(
        &self,
        uow: &mut dyn UnitOfWork,
        principal: UserId,
        at: Timestamp,
        reason: &str,
    ) -> Result<Vec<(ClientId, String)>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut revoked = Vec::new();
        for ((owner, token_id), record) in lock(&self.rows).iter_mut() {
            if *owner == tenant
                && record.principal_id == Some(principal)
                && record.revoked_at.is_none()
            {
                record.revoked_at = Some(at);
                record.revocation_reason = Some(reason.to_owned());
                revoked.push((record.client_id, token_id.clone()));
            }
        }
        Ok(revoked)
    }

    async fn remove_expired(
        &self,
        uow: &mut dyn UnitOfWork,
        now: Timestamp,
        batch: u32,
    ) -> Result<u64, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = lock(&self.rows);
        let expired: Vec<(TenantId, String)> = rows
            .iter()
            .filter(|((owner, _), record)| *owner == tenant && record.expires_at <= now)
            .map(|(key, _)| key.clone())
            .take(batch as usize)
            .collect();
        for key in &expired {
            rows.remove(key);
        }
        Ok(expired.len() as u64)
    }
}

/// The ports of the register contract.
#[derive(Clone, Copy)]
pub struct AccessTokenRecordStorePorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// Where the applications of the clients are stored.
    pub applications: &'a dyn ApplicationStore,
    /// Where the clients of the records are stored.
    pub clients: &'a dyn ClientStore,
    /// The store under test.
    pub access_tokens: &'a dyn AccessTokenRecordStore,
}

impl std::fmt::Debug for AccessTokenRecordStorePorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccessTokenRecordStorePorts")
            .finish_non_exhaustive()
    }
}

/// A moment whole to the microsecond, as PostgreSQL keeps it.
fn moment() -> Timestamp {
    Timestamp::UNIX_EPOCH + Duration::days(20_000)
}

async fn a_client(ports: AccessTokenRecordStorePorts<'_>, tenant: &TenantContext) -> Client {
    let application = Application::create(
        ApplicationSettings {
            name: "Payroll".to_owned(),
            first_party: true,
        },
        moment(),
    )
    .expect("application");
    let client = Client::create(
        application.id(),
        ClientType::Public,
        ClientSettings::new(
            "Payroll mobile",
            ClientType::Public,
            vec![GrantType::AuthorizationCode],
            vec!["com.example.payroll:/callback".to_owned()],
        ),
        ClientSecret::DEFAULT_LIFETIME,
        moment(),
        &super::DistinctRandom,
        &FakeDigest,
    )
    .expect("client")
    .0;
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .applications
        .insert(uow.as_mut(), &application)
        .await
        .expect("application");
    ports
        .clients
        .insert(uow.as_mut(), &client)
        .await
        .expect("client");
    uow.commit().await.expect("commit");
    client
}

fn record_of(client: ClientId, token_id: &str, expires_at: Timestamp) -> AccessTokenRecord {
    AccessTokenRecord::issued(token_id.to_owned(), client, None, None, expires_at)
}

/// Runs every rule a store of the register must obey. Each case uses
/// tenants of its own, so runs can share one database.
///
/// # Panics
///
/// Panics when an implementation breaks a rule.
pub async fn run_access_token_record_contract(ports: AccessTokenRecordStorePorts<'_>) {
    a_record_is_kept_whole_and_found_by_its_jti(ports).await;
    a_record_is_revoked_once_and_only_by_its_client(ports).await;
    records_of_expired_tokens_are_removed(ports).await;
    records_belong_to_their_own_tenant(ports).await;
    the_records_of_a_principal_are_revoked_together(ports).await;
}

async fn the_records_of_a_principal_are_revoked_together(ports: AccessTokenRecordStorePorts<'_>) {
    let (tenant, elsewhere) = (
        TenantContext::assume(TenantId::generate()),
        TenantContext::assume(TenantId::generate()),
    );
    let client = a_client(ports, &tenant).await;
    let theirs = a_client(ports, &elsewhere).await;
    let (workload, other) = (UserId::generate(), UserId::generate());
    let later = moment() + Duration::minutes(5);
    let records = [
        (
            &tenant,
            record_of(client.id(), "jti-one", later).for_principal(Some(workload)),
        ),
        (
            &tenant,
            record_of(client.id(), "jti-two", later).for_principal(Some(workload)),
        ),
        (
            &tenant,
            record_of(client.id(), "jti-other", later).for_principal(Some(other)),
        ),
        (&tenant, record_of(client.id(), "jti-client", later)),
        (
            &elsewhere,
            record_of(theirs.id(), "jti-theirs", later).for_principal(Some(workload)),
        ),
    ];
    for (owner, record) in &records {
        let mut uow = ports.units_of_work.begin(owner).await.expect("begin");
        ports
            .access_tokens
            .record(uow.as_mut(), record)
            .await
            .expect("record");
        uow.commit().await.expect("commit");
    }
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let found = ports
        .access_tokens
        .find(uow.as_mut(), "jti-one")
        .await
        .expect("find")
        .expect("recorded");
    assert_eq!(found.principal_id, Some(workload), "the principal is kept");
    let mut revoked = ports
        .access_tokens
        .revoke_for_principal(uow.as_mut(), workload, moment(), "workload_disabled")
        .await
        .expect("revoke");
    uow.commit().await.expect("commit");
    revoked.sort();
    assert_eq!(
        revoked,
        vec![
            (client.id(), "jti-one".to_owned()),
            (client.id(), "jti-two".to_owned())
        ]
    );
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let again = ports
        .access_tokens
        .revoke_for_principal(uow.as_mut(), workload, moment(), "workload_disabled")
        .await
        .expect("revoke");
    assert!(again.is_empty(), "a revoked record is not revoked again");
    for (token_id, revoked) in [
        ("jti-one", true),
        ("jti-other", false),
        ("jti-client", false),
    ] {
        let record = ports
            .access_tokens
            .find(uow.as_mut(), token_id)
            .await
            .expect("find")
            .expect("kept");
        assert_eq!(record.revoked_at.is_some(), revoked, "{token_id}");
        if revoked {
            assert_eq!(
                record.revocation_reason.as_deref(),
                Some("workload_disabled")
            );
        }
    }
    drop(uow);
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    let record = ports
        .access_tokens
        .find(uow.as_mut(), "jti-theirs")
        .await
        .expect("find")
        .expect("kept");
    assert!(
        record.revoked_at.is_none(),
        "another tenant's record is untouched"
    );
}

async fn a_record_is_kept_whole_and_found_by_its_jti(ports: AccessTokenRecordStorePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let client = a_client(ports, &tenant).await;
    let record = record_of(client.id(), "jti-kept", moment() + Duration::minutes(5));
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .access_tokens
        .record(uow.as_mut(), &record)
        .await
        .expect("record");
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .access_tokens
            .find(uow.as_mut(), "jti-kept")
            .await
            .expect("find"),
        Some(record)
    );
    assert!(
        ports
            .access_tokens
            .find(uow.as_mut(), "jti-unknown")
            .await
            .expect("find")
            .is_none()
    );
}

async fn a_record_is_revoked_once_and_only_by_its_client(ports: AccessTokenRecordStorePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let client = a_client(ports, &tenant).await;
    let other = a_client(ports, &tenant).await;
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .access_tokens
        .record(
            uow.as_mut(),
            &record_of(client.id(), "jti-revoked", moment() + Duration::minutes(5)),
        )
        .await
        .expect("record");
    uow.commit().await.expect("commit");

    let at = moment() + Duration::minutes(1);
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        !ports
            .access_tokens
            .revoke(
                uow.as_mut(),
                other.id(),
                "jti-revoked",
                at,
                "revoked_by_client"
            )
            .await
            .expect("revoke"),
        "another client cannot revoke it"
    );
    assert!(
        ports
            .access_tokens
            .revoke(
                uow.as_mut(),
                client.id(),
                "jti-revoked",
                at,
                "revoked_by_client"
            )
            .await
            .expect("revoke")
    );
    assert!(
        !ports
            .access_tokens
            .revoke(
                uow.as_mut(),
                client.id(),
                "jti-revoked",
                at,
                "revoked_by_client"
            )
            .await
            .expect("revoke again"),
        "revoked once"
    );
    assert!(
        !ports
            .access_tokens
            .revoke(
                uow.as_mut(),
                client.id(),
                "jti-unknown",
                at,
                "revoked_by_client"
            )
            .await
            .expect("unknown")
    );
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    let found = ports
        .access_tokens
        .find(uow.as_mut(), "jti-revoked")
        .await
        .expect("find")
        .expect("found");
    assert_eq!(found.revoked_at, Some(at));
    assert_eq!(
        found.revocation_reason.as_deref(),
        Some("revoked_by_client")
    );
}

async fn records_of_expired_tokens_are_removed(ports: AccessTokenRecordStorePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let client = a_client(ports, &tenant).await;
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    for (token_id, expires_at) in [
        ("jti-old-1", moment() - Duration::minutes(2)),
        ("jti-old-2", moment() - Duration::minutes(1)),
        ("jti-old-3", moment()),
        ("jti-young", moment() + Duration::minutes(5)),
    ] {
        ports
            .access_tokens
            .record(uow.as_mut(), &record_of(client.id(), token_id, expires_at))
            .await
            .expect("record");
    }
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .access_tokens
            .remove_expired(uow.as_mut(), moment(), 2)
            .await
            .expect("remove"),
        2,
        "at most a batch"
    );
    assert_eq!(
        ports
            .access_tokens
            .remove_expired(uow.as_mut(), moment(), 2)
            .await
            .expect("remove"),
        1,
        "the rest, a token that expires at the moment included"
    );
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    for token_id in ["jti-old-1", "jti-old-2", "jti-old-3"] {
        assert!(
            ports
                .access_tokens
                .find(uow.as_mut(), token_id)
                .await
                .expect("find")
                .is_none(),
            "{token_id} removed"
        );
    }
    assert!(
        ports
            .access_tokens
            .find(uow.as_mut(), "jti-young")
            .await
            .expect("find")
            .is_some(),
        "a token still in its lifetime stays"
    );
}

async fn records_belong_to_their_own_tenant(ports: AccessTokenRecordStorePorts<'_>) {
    let acme = TenantContext::assume(TenantId::generate());
    let globex = TenantContext::assume(TenantId::generate());
    let client = a_client(ports, &acme).await;
    let record = record_of(client.id(), "jti-acme", moment() + Duration::minutes(5));

    let mut uow = ports.units_of_work.begin(&globex).await.expect("begin");
    assert_eq!(
        ports
            .access_tokens
            .record(uow.as_mut(), &record)
            .await
            .expect_err("another tenant's client")
            .code(),
        "oauth.client_not_found"
    );
    drop(uow);

    let mut uow = ports.units_of_work.begin(&acme).await.expect("begin");
    ports
        .access_tokens
        .record(uow.as_mut(), &record)
        .await
        .expect("record");
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&globex).await.expect("begin");
    assert!(
        ports
            .access_tokens
            .find(uow.as_mut(), "jti-acme")
            .await
            .expect("find")
            .is_none(),
        "another tenant does not see it"
    );
    assert!(
        !ports
            .access_tokens
            .revoke(
                uow.as_mut(),
                client.id(),
                "jti-acme",
                moment(),
                "revoked_by_client"
            )
            .await
            .expect("revoke"),
        "nor revoke it"
    );
    assert_eq!(
        ports
            .access_tokens
            .remove_expired(uow.as_mut(), moment() + Duration::hours(1), 10)
            .await
            .expect("remove"),
        0,
        "nor remove it"
    );
}
