//! Claim mappers kept in memory, what they read of people answered from
//! what a test sets, and the contract every store of mappers passes.

use super::{InMemoryClients, lock, modified};
use crate::api::{
    ApplicationStore, ClaimMapper, ClaimMapperId, ClaimMapperSettings, ClaimMapperSnapshot,
    ClaimMapperStore, ClaimSource, ClaimTarget, ClientId, ClientStore, OrganizationAttribute,
    PersonAttribute, PersonAttributes, PersonClaimSources,
};
use hodor_kernel::{
    DomainError, GroupId, OrganizationId, TenantContext, TenantId, Timestamp, UnitOfWork,
    UnitOfWorkFactory, UserId,
};
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use time::Duration;

/// The mappers of every tenant, by tenant and identifier.
type MapperRows = BTreeMap<(TenantId, ClaimMapperId), ClaimMapper>;

fn name_taken() -> DomainError {
    DomainError::conflict(
        "oauth.claim_mapper_name_taken",
        "the client already has a mapper of this claim",
    )
}

/// Claim mappers kept in memory. They know the clients they are stored
/// against, as the database knows its references.
#[derive(Debug, Clone)]
pub struct InMemoryClaimMappers {
    clients: InMemoryClients,
    rows: Arc<Mutex<MapperRows>>,
}

impl InMemoryClaimMappers {
    /// The mappers of the clients in `clients`.
    #[must_use]
    pub fn new(clients: &InMemoryClients) -> Self {
        Self {
            clients: clients.clone(),
            rows: Arc::default(),
        }
    }

    fn taken(rows: &MapperRows, tenant: TenantId, mapper: &ClaimMapper) -> bool {
        rows.iter().any(|((owner, id), other)| {
            *owner == tenant
                && *id != mapper.id()
                && other.client_id() == mapper.client_id()
                && other
                    .settings()
                    .claim
                    .eq_ignore_ascii_case(&mapper.settings().claim)
        })
    }
}

#[async_trait::async_trait]
impl ClaimMapperStore for InMemoryClaimMappers {
    async fn lock_client(
        &self,
        uow: &mut dyn UnitOfWork,
        client_id: ClientId,
    ) -> Result<bool, DomainError> {
        Ok(self.clients.exists(uow.tenant().tenant_id(), client_id))
    }

    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        mapper: &ClaimMapper,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        if !self.clients.exists(tenant, mapper.client_id()) {
            return Err(DomainError::not_found(
                "oauth.client_not_found",
                "there is no such client",
            ));
        }
        let mut rows = lock(&self.rows);
        if Self::taken(&rows, tenant, mapper) {
            return Err(name_taken());
        }
        rows.insert((tenant, mapper.id()), mapper.clone());
        Ok(())
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        mapper: &ClaimMapper,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let key = (tenant, mapper.id());
        let mut rows = lock(&self.rows);
        let version = mapper.snapshot().version;
        match rows.get(&key) {
            Some(stored)
                if stored.snapshot().version == version
                    && stored.client_id() == mapper.client_id() =>
            {
                if Self::taken(&rows, tenant, mapper) {
                    return Err(name_taken());
                }
                rows.insert(
                    key,
                    ClaimMapper::from_snapshot(ClaimMapperSnapshot {
                        version: version + 1,
                        ..mapper.snapshot().clone()
                    }),
                );
                Ok(())
            }
            _ => Err(modified("oauth.claim_mapper_modified_concurrently")),
        }
    }

    async fn delete(
        &self,
        uow: &mut dyn UnitOfWork,
        client_id: ClientId,
        id: ClaimMapperId,
    ) -> Result<bool, DomainError> {
        let key = (uow.tenant().tenant_id(), id);
        let mut rows = lock(&self.rows);
        if rows
            .get(&key)
            .is_some_and(|mapper| mapper.client_id() == client_id)
        {
            rows.remove(&key);
            return Ok(true);
        }
        Ok(false)
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        client_id: ClientId,
        id: ClaimMapperId,
    ) -> Result<Option<ClaimMapper>, DomainError> {
        Ok(lock(&self.rows)
            .get(&(uow.tenant().tenant_id(), id))
            .filter(|mapper| mapper.client_id() == client_id)
            .cloned())
    }

    async fn list_for_client(
        &self,
        uow: &mut dyn UnitOfWork,
        client_id: ClientId,
    ) -> Result<Vec<ClaimMapper>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut found: Vec<ClaimMapper> = lock(&self.rows)
            .iter()
            .filter(|((owner, _), mapper)| *owner == tenant && mapper.client_id() == client_id)
            .map(|(_, mapper)| mapper.clone())
            .collect();
        found.sort_by(|one, other| one.settings().claim.cmp(&other.settings().claim));
        Ok(found)
    }
}

/// [`PersonClaimSources`] answered from what a test sets, for one tenant
/// or several: nobody has an attribute and no organization has a name
/// until a test says so.
#[derive(Debug, Clone, Default)]
pub struct ClaimSourcesOf {
    people: Arc<Mutex<BTreeMap<(TenantId, UserId), PersonAttributes>>>,
    organizations: Arc<Mutex<BTreeMap<(TenantId, OrganizationId), String>>>,
}

impl ClaimSourcesOf {
    /// Sets the attributes of `user` in `tenant`.
    pub fn set_attributes(&self, tenant: TenantId, user: UserId, attributes: PersonAttributes) {
        lock(&self.people).insert((tenant, user), attributes);
    }

    /// Names `organization` of `tenant`.
    pub fn name_organization(&self, tenant: TenantId, organization: OrganizationId, name: &str) {
        lock(&self.organizations).insert((tenant, organization), name.to_owned());
    }
}

#[async_trait::async_trait]
impl PersonClaimSources for ClaimSourcesOf {
    async fn attributes(
        &self,
        tenant: &TenantContext,
        user: UserId,
    ) -> Result<PersonAttributes, DomainError> {
        Ok(lock(&self.people)
            .get(&(tenant.tenant_id(), user))
            .cloned()
            .unwrap_or_default())
    }

    async fn organization_name(
        &self,
        tenant: &TenantContext,
        organization: OrganizationId,
    ) -> Result<Option<String>, DomainError> {
        Ok(lock(&self.organizations)
            .get(&(tenant.tenant_id(), organization))
            .cloned())
    }
}

/// The ports of the claim mapper contract.
#[derive(Clone, Copy)]
pub struct ClaimMapperStorePorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// Where the applications of the clients are stored.
    pub applications: &'a dyn ApplicationStore,
    /// Where the clients of the mappers are stored.
    pub clients: &'a dyn ClientStore,
    /// The store under test.
    pub mappers: &'a dyn ClaimMapperStore,
}

impl std::fmt::Debug for ClaimMapperStorePorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ClaimMapperStorePorts")
            .finish_non_exhaustive()
    }
}

/// A moment whole to the microsecond, as PostgreSQL keeps it.
fn moment() -> Timestamp {
    Timestamp::UNIX_EPOCH + Duration::days(20_000)
}

/// A new client of a new application of `tenant`, stored.
async fn a_client(ports: ClaimMapperStorePorts<'_>, tenant: &TenantContext) -> ClientId {
    let application = super::application("Payroll", moment());
    let client = super::client(application.id(), moment());
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
    client.id()
}

fn a_mapper(client_id: ClientId, claim: &str, source: ClaimSource) -> ClaimMapper {
    ClaimMapper::create(
        client_id,
        ClaimMapperSettings {
            claim: claim.to_owned(),
            targets: vec![ClaimTarget::IdToken, ClaimTarget::UserInfo],
            scope: Some("openid".to_owned()),
            source,
        },
        &["openid".to_owned()],
        moment(),
    )
    .expect("a mapper")
    .0
}

async fn insert(
    ports: ClaimMapperStorePorts<'_>,
    tenant: &TenantContext,
    mapper: &ClaimMapper,
) -> Result<(), DomainError> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports.mappers.insert(uow.as_mut(), mapper).await?;
    uow.commit().await.expect("commit");
    Ok(())
}

async fn list(
    ports: ClaimMapperStorePorts<'_>,
    tenant: &TenantContext,
    client_id: ClientId,
) -> Vec<ClaimMapper> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .mappers
        .list_for_client(uow.as_mut(), client_id)
        .await
        .expect("list")
}

/// Runs every rule a store of claim mappers must obey. Each case uses
/// tenants of its own, so runs can share one database.
///
/// # Panics
///
/// Panics when an implementation breaks a rule.
pub async fn run_claim_mapper_contract(ports: ClaimMapperStorePorts<'_>) {
    every_source_is_stored_and_read_back_by_claim_name(ports).await;
    a_mapper_belongs_to_a_client_of_its_tenant(ports).await;
    a_claim_is_mapped_once_per_client_without_regard_to_case(ports).await;
    a_stale_mapper_is_not_stored(ports).await;
    a_deleted_mapper_is_gone(ports).await;
    another_tenant_sees_nothing(ports).await;
}

async fn every_source_is_stored_and_read_back_by_claim_name(ports: ClaimMapperStorePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let client = a_client(ports, &tenant).await;
    let mappers = [
        a_mapper(
            client,
            "plan",
            ClaimSource::Constant(json!({"tier": "gold", "seats": [1, 2]})),
        ),
        a_mapper(
            client,
            "full_name",
            ClaimSource::Attribute(PersonAttribute::DisplayName),
        ),
        a_mapper(client, "teams", ClaimSource::Groups),
        a_mapper(
            client,
            "in_finance",
            ClaimSource::GroupMember(GroupId::generate()),
        ),
        a_mapper(
            client,
            "company",
            ClaimSource::Organization(OrganizationAttribute::Name),
        ),
    ];
    for mapper in &mappers {
        insert(ports, &tenant, mapper).await.expect("stored");
    }
    let mut expected = mappers.to_vec();
    expected.sort_by(|one, other| one.settings().claim.cmp(&other.settings().claim));
    assert_eq!(
        list(ports, &tenant, client).await,
        expected,
        "by claim name"
    );
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .mappers
            .get(uow.as_mut(), client, mappers[0].id())
            .await
            .expect("get"),
        Some(mappers[0].clone())
    );
    assert!(
        ports
            .mappers
            .lock_client(uow.as_mut(), client)
            .await
            .expect("lock")
    );
    assert!(
        !ports
            .mappers
            .lock_client(uow.as_mut(), ClientId::generate())
            .await
            .expect("lock"),
        "an unknown client is not there to lock"
    );
}

async fn a_mapper_belongs_to_a_client_of_its_tenant(ports: ClaimMapperStorePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let client = a_client(ports, &tenant).await;
    let unknown = a_mapper(ClientId::generate(), "teams", ClaimSource::Groups);
    assert_eq!(
        insert(ports, &tenant, &unknown)
            .await
            .expect_err("refused")
            .code(),
        "oauth.client_not_found"
    );
    let mapper = a_mapper(client, "teams", ClaimSource::Groups);
    insert(ports, &tenant, &mapper).await.expect("stored");
    let other_client = a_client(ports, &tenant).await;
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .mappers
            .get(uow.as_mut(), other_client, mapper.id())
            .await
            .expect("get"),
        None,
        "not a mapper of another client"
    );
    assert!(
        !ports
            .mappers
            .delete(uow.as_mut(), other_client, mapper.id())
            .await
            .expect("delete"),
        "not deleted through another client"
    );
    drop(uow);
    assert_eq!(list(ports, &tenant, client).await, [mapper]);
}

async fn a_claim_is_mapped_once_per_client_without_regard_to_case(
    ports: ClaimMapperStorePorts<'_>,
) {
    let tenant = TenantContext::assume(TenantId::generate());
    let client = a_client(ports, &tenant).await;
    insert(
        ports,
        &tenant,
        &a_mapper(client, "Teams", ClaimSource::Groups),
    )
    .await
    .expect("stored");
    assert_eq!(
        insert(
            ports,
            &tenant,
            &a_mapper(client, "teams", ClaimSource::Groups)
        )
        .await
        .expect_err("refused")
        .code(),
        "oauth.claim_mapper_name_taken"
    );
    let elsewhere = a_client(ports, &tenant).await;
    insert(
        ports,
        &tenant,
        &a_mapper(elsewhere, "teams", ClaimSource::Groups),
    )
    .await
    .expect("another client maps it too");
    let second = a_mapper(client, "squads", ClaimSource::Groups);
    insert(ports, &tenant, &second).await.expect("stored");
    let mut renamed = second.clone();
    renamed
        .replace(
            ClaimMapperSettings {
                claim: "TEAMS".to_owned(),
                ..second.settings().clone()
            },
            &["openid".to_owned()],
            moment(),
        )
        .expect("valid");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .mappers
            .update(uow.as_mut(), &renamed)
            .await
            .expect_err("refused")
            .code(),
        "oauth.claim_mapper_name_taken"
    );
}

async fn a_stale_mapper_is_not_stored(ports: ClaimMapperStorePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let client = a_client(ports, &tenant).await;
    let mapper = a_mapper(client, "teams", ClaimSource::Groups);
    insert(ports, &tenant, &mapper).await.expect("stored");
    let mut changed = mapper.clone();
    changed
        .replace(
            ClaimMapperSettings {
                targets: vec![ClaimTarget::AccessToken],
                scope: None,
                ..mapper.settings().clone()
            },
            &[],
            moment() + Duration::minutes(1),
        )
        .expect("valid");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .mappers
        .update(uow.as_mut(), &changed)
        .await
        .expect("stored");
    uow.commit().await.expect("commit");
    let stored = list(ports, &tenant, client).await;
    assert_eq!(stored[0].settings(), changed.settings());
    assert_eq!(stored[0].snapshot().version, 1);
    assert_eq!(
        stored[0].snapshot().updated_at,
        moment() + Duration::minutes(1)
    );
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert_eq!(
        ports
            .mappers
            .update(uow.as_mut(), &changed)
            .await
            .expect_err("stale")
            .code(),
        "oauth.claim_mapper_modified_concurrently"
    );
}

async fn a_deleted_mapper_is_gone(ports: ClaimMapperStorePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let client = a_client(ports, &tenant).await;
    let mapper = a_mapper(client, "teams", ClaimSource::Groups);
    insert(ports, &tenant, &mapper).await.expect("stored");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        ports
            .mappers
            .delete(uow.as_mut(), client, mapper.id())
            .await
            .expect("delete")
    );
    uow.commit().await.expect("commit");
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        !ports
            .mappers
            .delete(uow.as_mut(), client, mapper.id())
            .await
            .expect("delete")
    );
    drop(uow);
    assert!(list(ports, &tenant, client).await.is_empty());
}

async fn another_tenant_sees_nothing(ports: ClaimMapperStorePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let other = TenantContext::assume(TenantId::generate());
    let client = a_client(ports, &tenant).await;
    let mapper = a_mapper(client, "teams", ClaimSource::Groups);
    insert(ports, &tenant, &mapper).await.expect("stored");
    assert!(list(ports, &other, client).await.is_empty());
    let mut uow = ports.units_of_work.begin(&other).await.expect("begin");
    assert_eq!(
        ports
            .mappers
            .get(uow.as_mut(), client, mapper.id())
            .await
            .expect("get"),
        None
    );
    assert!(
        !ports
            .mappers
            .lock_client(uow.as_mut(), client)
            .await
            .expect("lock")
    );
    assert!(
        !ports
            .mappers
            .delete(uow.as_mut(), client, mapper.id())
            .await
            .expect("delete")
    );
    assert_eq!(
        ports
            .mappers
            .insert(
                uow.as_mut(),
                &a_mapper(client, "squads", ClaimSource::Groups)
            )
            .await
            .expect_err("refused")
            .code(),
        "oauth.client_not_found",
        "another tenant's client is unknown"
    );
    drop(uow);
    assert_eq!(list(ports, &tenant, client).await, [mapper]);
}
