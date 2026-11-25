//! In-memory stores, stand-ins for the outbound ports, and the contract
//! every implementation of the stores passes.

use crate::api::{
    Delivery, DeliveryId, DeliveryQuery, DeliveryStatus, DeliveryStore, DueDeliveries, Endpoint,
    EndpointId, EndpointStore, HmacSha256, RetryPolicy, SigningSecret, SigningSecretId,
};
use hodor_kernel::{
    DestinationCheck, DomainError, ErrorKind, EventId, HttpClient, HttpRequest, HttpResponse,
    SealedSecret, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};
use time::Duration;

#[derive(Debug, Default)]
struct Rows {
    endpoints: BTreeMap<(TenantId, EndpointId), Endpoint>,
    secrets: BTreeMap<(TenantId, SigningSecretId), SigningSecret>,
    deliveries: BTreeMap<(TenantId, DeliveryId), Delivery>,
}

/// Endpoints, secrets and deliveries kept in memory. Implements the three
/// storage ports. Changes apply at once: the in-memory unit of work has no
/// transaction to roll back.
#[derive(Debug, Clone, Default)]
pub struct InMemoryWebhooks {
    rows: Arc<Mutex<Rows>>,
}

impl InMemoryWebhooks {
    fn rows(&self) -> MutexGuard<'_, Rows> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Every delivery of a tenant, oldest first.
    #[must_use]
    pub fn deliveries_of(&self, tenant: TenantId) -> Vec<Delivery> {
        let mut found: Vec<Delivery> = self
            .rows()
            .deliveries
            .iter()
            .filter(|((owner, _), _)| *owner == tenant)
            .map(|(_, delivery)| delivery.clone())
            .collect();
        found.sort_by_key(Delivery::id);
        found
    }

    /// Every stored secret of a tenant.
    #[must_use]
    pub fn secrets_of(&self, tenant: TenantId) -> Vec<SigningSecret> {
        self.rows()
            .secrets
            .iter()
            .filter(|((owner, _), _)| *owner == tenant)
            .map(|(_, secret)| secret.clone())
            .collect()
    }
}

fn tenant_of(uow: &dyn UnitOfWork) -> TenantId {
    uow.tenant().tenant_id()
}

fn endpoint_not_found() -> DomainError {
    DomainError::not_found(
        "webhooks.endpoint_not_found",
        "there is no such webhook endpoint",
    )
}

#[async_trait::async_trait]
impl EndpointStore for InMemoryWebhooks {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        endpoint: &Endpoint,
    ) -> Result<(), DomainError> {
        self.rows()
            .endpoints
            .insert((tenant_of(uow), endpoint.id()), endpoint.clone());
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: EndpointId,
    ) -> Result<Option<Endpoint>, DomainError> {
        Ok(self.rows().endpoints.get(&(tenant_of(uow), id)).cloned())
    }

    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        id: EndpointId,
    ) -> Result<Option<Endpoint>, DomainError> {
        EndpointStore::get(self, uow, id).await
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        after: Option<EndpointId>,
        limit: u32,
    ) -> Result<Vec<Endpoint>, DomainError> {
        let tenant = tenant_of(uow);
        Ok(self
            .rows()
            .endpoints
            .iter()
            .filter(|((owner, id), _)| *owner == tenant && after.is_none_or(|after| *id > after))
            .take(limit as usize)
            .map(|(_, endpoint)| endpoint.clone())
            .collect())
    }

    async fn count(&self, uow: &mut dyn UnitOfWork) -> Result<u32, DomainError> {
        let tenant = tenant_of(uow);
        let count = self
            .rows()
            .endpoints
            .keys()
            .filter(|(owner, _)| *owner == tenant)
            .count();
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        endpoint: &Endpoint,
    ) -> Result<(), DomainError> {
        let key = (tenant_of(uow), endpoint.id());
        let mut rows = self.rows();
        let stored = rows.endpoints.get(&key).ok_or_else(endpoint_not_found)?;
        if stored.snapshot().version != endpoint.snapshot().version {
            return Err(changed());
        }
        let mut state = endpoint.snapshot().clone();
        state.version += 1;
        rows.endpoints.insert(key, Endpoint::from_snapshot(state));
        Ok(())
    }

    async fn remove(&self, uow: &mut dyn UnitOfWork, id: EndpointId) -> Result<bool, DomainError> {
        let tenant = tenant_of(uow);
        let mut rows = self.rows();
        let removed = rows.endpoints.remove(&(tenant, id)).is_some();
        rows.secrets
            .retain(|(owner, _), secret| !(*owner == tenant && secret.endpoint_id == id));
        rows.deliveries.retain(|(owner, _), delivery| {
            !(*owner == tenant && delivery.snapshot().endpoint_id == id)
        });
        Ok(removed)
    }

    async fn subscribed_to(
        &self,
        uow: &mut dyn UnitOfWork,
        event_type: &str,
    ) -> Result<Vec<EndpointId>, DomainError> {
        let tenant = tenant_of(uow);
        Ok(self
            .rows()
            .endpoints
            .iter()
            .filter(|((owner, _), endpoint)| {
                *owner == tenant && endpoint.is_subscribed_to(event_type)
            })
            .map(|((_, id), _)| *id)
            .collect())
    }

    async fn add_secret(
        &self,
        uow: &mut dyn UnitOfWork,
        secret: &SigningSecret,
    ) -> Result<(), DomainError> {
        let tenant = tenant_of(uow);
        let mut rows = self.rows();
        if !rows.endpoints.contains_key(&(tenant, secret.endpoint_id)) {
            return Err(endpoint_not_found());
        }
        rows.secrets.insert((tenant, secret.id), secret.clone());
        Ok(())
    }

    async fn secrets(
        &self,
        uow: &mut dyn UnitOfWork,
        endpoint: EndpointId,
    ) -> Result<Vec<SigningSecret>, DomainError> {
        let tenant = tenant_of(uow);
        let mut found: Vec<SigningSecret> = self
            .rows()
            .secrets
            .iter()
            .filter(|((owner, _), secret)| *owner == tenant && secret.endpoint_id == endpoint)
            .map(|(_, secret)| secret.clone())
            .collect();
        found.sort_by_key(|secret| std::cmp::Reverse((secret.created_at, secret.id)));
        Ok(found)
    }

    async fn end_secret(
        &self,
        uow: &mut dyn UnitOfWork,
        id: SigningSecretId,
        expires_at: Timestamp,
    ) -> Result<(), DomainError> {
        if let Some(secret) = self.rows().secrets.get_mut(&(tenant_of(uow), id)) {
            secret.expires_at = Some(expires_at);
        }
        Ok(())
    }

    async fn remove_ended_secrets(
        &self,
        uow: &mut dyn UnitOfWork,
        endpoint: EndpointId,
        now: Timestamp,
    ) -> Result<u64, DomainError> {
        let tenant = tenant_of(uow);
        let mut rows = self.rows();
        let before = rows.secrets.len();
        rows.secrets.retain(|(owner, _), secret| {
            !(*owner == tenant && secret.endpoint_id == endpoint && !secret.is_in_force(now))
        });
        Ok((before - rows.secrets.len()) as u64)
    }
}

fn changed() -> DomainError {
    DomainError::conflict(
        "webhooks.endpoint_changed",
        "the endpoint changed meanwhile; read it again",
    )
}

#[async_trait::async_trait]
impl DeliveryStore for InMemoryWebhooks {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        delivery: &Delivery,
    ) -> Result<bool, DomainError> {
        let tenant = tenant_of(uow);
        let state = delivery.snapshot();
        let mut rows = self.rows();
        if !rows.endpoints.contains_key(&(tenant, state.endpoint_id)) {
            return Err(endpoint_not_found());
        }
        let exists = rows.deliveries.iter().any(|((owner, _), stored)| {
            *owner == tenant
                && stored.snapshot().endpoint_id == state.endpoint_id
                && stored.snapshot().event_id == state.event_id
        });
        if exists {
            return Ok(false);
        }
        rows.deliveries
            .insert((tenant, delivery.id()), delivery.clone());
        Ok(true)
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: DeliveryId,
    ) -> Result<Option<Delivery>, DomainError> {
        Ok(self.rows().deliveries.get(&(tenant_of(uow), id)).cloned())
    }

    async fn take(
        &self,
        uow: &mut dyn UnitOfWork,
        id: DeliveryId,
    ) -> Result<Option<Delivery>, DomainError> {
        DeliveryStore::get(self, uow, id).await
    }

    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        id: DeliveryId,
    ) -> Result<Option<Delivery>, DomainError> {
        DeliveryStore::get(self, uow, id).await
    }

    async fn leased(
        &self,
        uow: &mut dyn UnitOfWork,
        endpoint: EndpointId,
        now: Timestamp,
    ) -> Result<u32, DomainError> {
        let tenant = tenant_of(uow);
        let count = self
            .rows()
            .deliveries
            .iter()
            .filter(|((owner, _), delivery)| {
                *owner == tenant
                    && delivery.snapshot().endpoint_id == endpoint
                    && delivery.is_leased(now)
            })
            .count();
        Ok(u32::try_from(count).unwrap_or(u32::MAX))
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        delivery: &Delivery,
    ) -> Result<(), DomainError> {
        let key = (tenant_of(uow), delivery.id());
        let mut rows = self.rows();
        if !rows.deliveries.contains_key(&key) {
            return Err(DomainError::not_found(
                "webhooks.delivery_not_found",
                "there is no such webhook delivery",
            ));
        }
        rows.deliveries.insert(key, delivery.clone());
        Ok(())
    }

    async fn list(
        &self,
        uow: &mut dyn UnitOfWork,
        query: DeliveryQuery,
        after: Option<DeliveryId>,
        limit: u32,
    ) -> Result<Vec<Delivery>, DomainError> {
        let tenant = tenant_of(uow);
        Ok(self
            .rows()
            .deliveries
            .iter()
            .rev()
            .filter(|((owner, id), delivery)| {
                *owner == tenant
                    && after.is_none_or(|after| *id < after)
                    && query
                        .endpoint
                        .is_none_or(|endpoint| delivery.snapshot().endpoint_id == endpoint)
                    && query
                        .status
                        .is_none_or(|status| delivery.status() == status)
            })
            .take(limit as usize)
            .map(|(_, delivery)| delivery.clone())
            .collect())
    }
}

#[async_trait::async_trait]
impl DueDeliveries for InMemoryWebhooks {
    async fn due(
        &self,
        now: Timestamp,
        limit: u32,
    ) -> Result<Vec<(TenantId, DeliveryId)>, DomainError> {
        let mut due: Vec<(Timestamp, DeliveryId, TenantId)> = self
            .rows()
            .deliveries
            .iter()
            .filter(|(_, delivery)| delivery.is_due(now))
            .map(|((tenant, id), delivery)| (delivery.snapshot().next_attempt_at, *id, *tenant))
            .collect();
        due.sort();
        Ok(due
            .into_iter()
            .take(limit as usize)
            .map(|(_, id, tenant)| (tenant, id))
            .collect())
    }
}

/// A stand-in for HMAC-SHA256 in tests of use cases: deterministic and
/// different for different keys and messages, but not a MAC. Never use
/// outside tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct FakeHmac;

impl HmacSha256 for FakeHmac {
    fn mac(&self, key: &[u8], message: &[u8]) -> [u8; 32] {
        let mut output = [0_u8; 32];
        for (chunk, seed) in output.chunks_mut(8).zip(1_u64..) {
            let mut hash = 0xcbf2_9ce4_8422_2325_u64.wrapping_mul(seed);
            for byte in key.iter().chain(&[0xff]).chain(message) {
                hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
            }
            chunk.copy_from_slice(&hash.to_be_bytes());
        }
        output
    }
}

/// A destination check without a resolver: HTTPS only, and these hosts
/// are what names resolve to. `localhost`, `internal.example` and literal
/// addresses of private and reserved ranges may not be called;
/// `nowhere.example` resolves to nothing; every other host is public.
#[derive(Debug, Clone, Copy, Default)]
pub struct FakeDestinations;

fn host_of(url: &str) -> Option<&str> {
    let rest = url.strip_prefix("https://")?;
    let authority = rest.split(['/', '?']).next()?;
    let host = match authority.rsplit_once(':') {
        Some((host, port)) if !host.ends_with(':') && port.bytes().all(|b| b.is_ascii_digit()) => {
            host
        }
        _ => authority,
    };
    Some(host.trim_start_matches('[').trim_end_matches(']'))
}

#[async_trait::async_trait]
impl DestinationCheck for FakeDestinations {
    async fn check(&self, url: &str) -> Result<(), DomainError> {
        let Some(host) = host_of(url) else {
            return Err(DomainError::invalid(
                "http.url_invalid",
                "the address cannot be called",
            ));
        };
        let private = host == "localhost"
            || host == "internal.example"
            || host == "::1"
            || ["127.", "10.", "169.254.", "192.168.", "0."]
                .iter()
                .any(|start| host.starts_with(start));
        if private {
            return Err(DomainError::new(
                ErrorKind::Forbidden,
                "http.destination_forbidden",
                "the address may not be called",
            ));
        }
        if host == "nowhere.example" {
            return Err(DomainError::new(
                ErrorKind::Unavailable,
                "http.unreachable",
                "the address did not answer",
            ));
        }
        Ok(())
    }
}

/// How a [`RecordingEndpoints`] answers an address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Answer {
    /// With this status and no body.
    Status(u16),
    /// With this error of the outbound client, such as `http.timed_out`.
    Failure(&'static str),
}

/// An outbound client for tests: keeps every request and answers each
/// address as it was told, `204` unless told otherwise.
#[derive(Debug, Clone, Default)]
pub struct RecordingEndpoints {
    requests: Arc<Mutex<Vec<HttpRequest>>>,
    answers: Arc<Mutex<BTreeMap<String, Answer>>>,
}

impl RecordingEndpoints {
    /// From now on, answer `url` with `answer`.
    pub fn answer(&self, url: &str, answer: Answer) {
        self.answers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(url.to_owned(), answer);
    }

    /// Every request sent so far, oldest first.
    #[must_use]
    pub fn requests(&self) -> Vec<HttpRequest> {
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

#[async_trait::async_trait]
impl HttpClient for RecordingEndpoints {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, DomainError> {
        let answer = self
            .answers
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&request.url)
            .cloned()
            .unwrap_or(Answer::Status(204));
        self.requests
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(request);
        match answer {
            Answer::Status(status) => Ok(HttpResponse {
                status,
                headers: Vec::new(),
                body: Vec::new(),
            }),
            Answer::Failure(code) => Err(DomainError::new(
                ErrorKind::Unavailable,
                code,
                "the address did not answer",
            )),
        }
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct Ports<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The endpoints under test.
    pub endpoints: &'a dyn EndpointStore,
    /// The deliveries under test.
    pub deliveries: &'a dyn DeliveryStore,
    /// The search across tenants under test.
    pub due: &'a dyn DueDeliveries,
}

impl std::fmt::Debug for Ports<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports").finish_non_exhaustive()
    }
}

/// A fixed, whole-second moment, so that stored timestamps compare equal
/// after a round trip through any storage.
const MOMENT: Timestamp = Timestamp::UNIX_EPOCH;

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

fn at(seconds: i64) -> Timestamp {
    MOMENT + Duration::seconds(seconds)
}

/// A valid endpoint at `url`, subscribed to `session.started` and
/// `identity.user_created`.
///
/// # Panics
///
/// Never: the endpoint is valid.
#[must_use]
pub fn endpoint(url: &str) -> Endpoint {
    Endpoint::register(
        url,
        Some("A receiver".to_owned()),
        &["session.started", "identity.user_created"],
        MOMENT,
    )
    .expect("valid endpoint")
}

/// A secret of `endpoint` made at `created`, sealed as `bytes`.
#[must_use]
pub fn secret(endpoint: EndpointId, created: Timestamp, bytes: &[u8]) -> SigningSecret {
    SigningSecret {
        id: SigningSecretId::generate(),
        endpoint_id: endpoint,
        sealed: SealedSecret::from_stored(bytes.to_vec()),
        created_at: created,
        expires_at: None,
    }
}

fn delivery_of(endpoint: EndpointId, made: Timestamp) -> Delivery {
    Delivery::make(
        endpoint,
        EventId::generate(),
        "session.started",
        r#"{"type":"session.started"}"#.to_owned(),
        made,
    )
    .0
}

/// Runs `$body` in a unit of work of `$tenant`, with `$uow` bound to it,
/// and commits if it succeeded.
macro_rules! in_tenant {
    ($ports:expr, $tenant:expr, |$uow:ident| $body:expr) => {{
        let mut unit = $ports.units_of_work.begin($tenant).await.expect("begin");
        let result: Result<_, DomainError> = async {
            let $uow: &mut dyn UnitOfWork = unit.as_mut();
            $body
        }
        .await;
        if result.is_ok() {
            unit.commit().await.expect("commit");
        }
        result
    }};
}

/// Runs every rule a webhooks store must obey.
///
/// # Panics
///
/// Panics if the implementation breaks a rule.
pub async fn run_contract(ports: Ports<'_>) {
    an_endpoint_comes_back_as_it_was_and_only_in_its_tenant(&ports).await;
    endpoints_are_listed_in_order_and_counted(&ports).await;
    a_change_on_a_stale_version_is_refused(&ports).await;
    removing_an_endpoint_removes_its_secrets_and_deliveries(&ports).await;
    the_fan_out_finds_only_subscribed_endpoints_of_the_tenant(&ports).await;
    secrets_are_kept_newest_first_ended_and_removed(&ports).await;
    a_delivery_is_made_once_per_endpoint_and_event(&ports).await;
    a_delivery_comes_back_as_it_was_after_every_change(&ports).await;
    leased_deliveries_are_counted_per_endpoint(&ports).await;
    deliveries_are_listed_newest_first_by_endpoint_and_status(&ports).await;
    due_deliveries_are_found_across_tenants_longest_waiting_first(&ports).await;
}

async fn insert_endpoint(ports: &Ports<'_>, tenant: &TenantContext, endpoint: &Endpoint) {
    let store = ports.endpoints;
    let endpoint = endpoint.clone();
    in_tenant!(ports, tenant, |uow| store.insert(uow, &endpoint).await).expect("insert endpoint");
}

async fn get_endpoint(
    ports: &Ports<'_>,
    tenant: &TenantContext,
    id: EndpointId,
) -> Option<Endpoint> {
    let store = ports.endpoints;
    in_tenant!(ports, tenant, |uow| store.get(uow, id).await).expect("get endpoint")
}

async fn insert_delivery(ports: &Ports<'_>, tenant: &TenantContext, delivery: &Delivery) -> bool {
    let store = ports.deliveries;
    let delivery = delivery.clone();
    in_tenant!(ports, tenant, |uow| store.insert(uow, &delivery).await).expect("insert delivery")
}

async fn update_delivery(ports: &Ports<'_>, tenant: &TenantContext, delivery: &Delivery) {
    let store = ports.deliveries;
    let delivery = delivery.clone();
    in_tenant!(ports, tenant, |uow| store.update(uow, &delivery).await).expect("update delivery");
}

async fn get_delivery(
    ports: &Ports<'_>,
    tenant: &TenantContext,
    id: DeliveryId,
) -> Option<Delivery> {
    let store = ports.deliveries;
    in_tenant!(ports, tenant, |uow| store.get(uow, id).await).expect("get delivery")
}

async fn an_endpoint_comes_back_as_it_was_and_only_in_its_tenant(ports: &Ports<'_>) {
    let (owner, other) = (tenant(), tenant());
    let endpoint = endpoint("https://hooks.example.com/in?token=a1");
    insert_endpoint(ports, &owner, &endpoint).await;
    assert_eq!(
        get_endpoint(ports, &owner, endpoint.id()).await,
        Some(endpoint.clone())
    );
    let store = ports.endpoints;
    let id = endpoint.id();
    let locked = in_tenant!(ports, &owner, |uow| store.lock(uow, id).await).expect("lock");
    assert_eq!(locked, Some(endpoint.clone()));

    assert_eq!(get_endpoint(ports, &other, endpoint.id()).await, None);
    let removed = in_tenant!(ports, &other, |uow| store.remove(uow, id).await).expect("remove");
    assert!(!removed, "another tenant removes nothing");
    assert!(get_endpoint(ports, &owner, endpoint.id()).await.is_some());
}

async fn endpoints_are_listed_in_order_and_counted(ports: &Ports<'_>) {
    let tenant = tenant();
    let mut made = Vec::new();
    for number in 0..3 {
        let endpoint = endpoint(&format!("https://hooks.example.com/{number}"));
        insert_endpoint(ports, &tenant, &endpoint).await;
        made.push(endpoint.id());
    }
    insert_endpoint(
        ports,
        &self::tenant(),
        &endpoint("https://elsewhere.example/"),
    )
    .await;
    let store = ports.endpoints;
    let (count, first, rest) = in_tenant!(ports, &tenant, |uow| {
        let count = store.count(uow).await?;
        let first = store.list(uow, None, 2).await?;
        let rest = store.list(uow, Some(first[1].id()), 10).await?;
        Ok((count, first, rest))
    })
    .expect("list");
    assert_eq!(count, 3);
    let listed: Vec<EndpointId> = first.iter().chain(&rest).map(Endpoint::id).collect();
    let mut expected = made;
    expected.sort();
    assert_eq!(listed, expected);
}

async fn a_change_on_a_stale_version_is_refused(ports: &Ports<'_>) {
    let tenant = tenant();
    let endpoint = endpoint("https://hooks.example.com/");
    insert_endpoint(ports, &tenant, &endpoint).await;
    let store = ports.endpoints;

    let mut changed = endpoint.clone();
    changed
        .replace_subscriptions(&["session.revoked"], at(5))
        .expect("valid");
    let first = changed.clone();
    in_tenant!(ports, &tenant, |uow| store.update(uow, &first).await).expect("first change");
    let stored = get_endpoint(ports, &tenant, endpoint.id())
        .await
        .expect("stored");
    assert_eq!(stored.snapshot().version, 1);
    assert!(stored.is_subscribed_to("session.revoked"));
    assert!(!stored.is_subscribed_to("session.started"));
    assert_eq!(stored.snapshot().updated_at, at(5));

    let stale = changed.clone();
    let error =
        in_tenant!(ports, &tenant, |uow| store.update(uow, &stale).await).expect_err("stale");
    assert_eq!(error.code(), "webhooks.endpoint_changed");

    let missing = self::endpoint("https://hooks.example.com/missing");
    let error =
        in_tenant!(ports, &tenant, |uow| store.update(uow, &missing).await).expect_err("missing");
    assert_eq!(error.code(), "webhooks.endpoint_not_found");
}

async fn removing_an_endpoint_removes_its_secrets_and_deliveries(ports: &Ports<'_>) {
    let tenant = tenant();
    let (gone, kept) = (
        endpoint("https://hooks.example.com/gone"),
        endpoint("https://hooks.example.com/kept"),
    );
    insert_endpoint(ports, &tenant, &gone).await;
    insert_endpoint(ports, &tenant, &kept).await;
    let store = ports.endpoints;
    for owner in [gone.id(), kept.id()] {
        let secret = secret(owner, MOMENT, b"sealed");
        in_tenant!(ports, &tenant, |uow| store.add_secret(uow, &secret).await).expect("secret");
        assert!(insert_delivery(ports, &tenant, &delivery_of(owner, MOMENT)).await);
    }
    let id = gone.id();
    let (removed, again) = in_tenant!(ports, &tenant, |uow| Ok((
        store.remove(uow, id).await?,
        store.remove(uow, id).await?
    )))
    .expect("remove");
    assert!(removed);
    assert!(!again);
    let deliveries = ports.deliveries;
    let (secrets_gone, secrets_kept, left) = in_tenant!(ports, &tenant, |uow| {
        Ok((
            store.secrets(uow, id).await?,
            store.secrets(uow, kept.id()).await?,
            deliveries
                .list(uow, DeliveryQuery::default(), None, 10)
                .await?,
        ))
    })
    .expect("read");
    assert!(secrets_gone.is_empty());
    assert_eq!(secrets_kept.len(), 1);
    assert_eq!(left.len(), 1);
    assert_eq!(left[0].snapshot().endpoint_id, secrets_kept[0].endpoint_id);
}

async fn the_fan_out_finds_only_subscribed_endpoints_of_the_tenant(ports: &Ports<'_>) {
    let (tenant, other) = (self::tenant(), self::tenant());
    let subscribed = endpoint("https://hooks.example.com/a");
    let mut elsewhere = endpoint("https://hooks.example.com/b");
    elsewhere
        .replace_subscriptions(&["session.revoked"], MOMENT)
        .expect("valid");
    insert_endpoint(ports, &tenant, &subscribed).await;
    insert_endpoint(ports, &tenant, &elsewhere).await;
    insert_endpoint(ports, &other, &endpoint("https://hooks.example.com/c")).await;
    let store = ports.endpoints;
    let (started, revoked, nothing) = in_tenant!(ports, &tenant, |uow| {
        Ok((
            store.subscribed_to(uow, "session.started").await?,
            store.subscribed_to(uow, "session.revoked").await?,
            store.subscribed_to(uow, "oauth.grant_revoked").await?,
        ))
    })
    .expect("subscribed");
    assert_eq!(started, [subscribed.id()]);
    assert_eq!(revoked, [elsewhere.id()]);
    assert!(nothing.is_empty());
}

async fn secrets_are_kept_newest_first_ended_and_removed(ports: &Ports<'_>) {
    let tenant = tenant();
    let endpoint = endpoint("https://hooks.example.com/");
    insert_endpoint(ports, &tenant, &endpoint).await;
    let store = ports.endpoints;
    let id = endpoint.id();
    let old = secret(id, at(0), b"old");
    let new = secret(id, at(10), b"new");
    let (stored_old, stored_new) = (old.clone(), new.clone());
    let listed = in_tenant!(ports, &tenant, |uow| {
        store.add_secret(uow, &stored_old).await?;
        store.add_secret(uow, &stored_new).await?;
        store.end_secret(uow, stored_old.id, at(20)).await?;
        store.secrets(uow, id).await
    })
    .expect("secrets");
    let mut ended = old.clone();
    ended.expires_at = Some(at(20));
    assert_eq!(listed, [new.clone(), ended]);

    let (early, late) = in_tenant!(ports, &tenant, |uow| {
        let early = store.remove_ended_secrets(uow, id, at(19)).await?;
        let late = store.remove_ended_secrets(uow, id, at(20)).await?;
        Ok((early, late))
    })
    .expect("remove");
    assert_eq!((early, late), (0, 1));
    let left = in_tenant!(ports, &tenant, |uow| store.secrets(uow, id).await).expect("secrets");
    assert_eq!(left, [new]);
    assert_eq!(left[0].sealed.as_bytes(), b"new");
}

async fn a_delivery_is_made_once_per_endpoint_and_event(ports: &Ports<'_>) {
    let (tenant, other) = (self::tenant(), self::tenant());
    let (first, second) = (
        endpoint("https://hooks.example.com/1"),
        endpoint("https://hooks.example.com/2"),
    );
    insert_endpoint(ports, &tenant, &first).await;
    insert_endpoint(ports, &tenant, &second).await;
    let delivery = delivery_of(first.id(), MOMENT);
    let event = delivery.snapshot().event_id;
    assert!(insert_delivery(ports, &tenant, &delivery).await);
    let (again, _) = Delivery::make(first.id(), event, "session.started", "{}".into(), MOMENT);
    assert!(!insert_delivery(ports, &tenant, &again).await, "once");
    let (to_second, _) = Delivery::make(second.id(), event, "session.started", "{}".into(), MOMENT);
    assert!(
        insert_delivery(ports, &tenant, &to_second).await,
        "another endpoint"
    );

    assert_eq!(
        get_delivery(ports, &tenant, delivery.id()).await,
        Some(delivery.clone())
    );
    assert_eq!(get_delivery(ports, &other, delivery.id()).await, None);
    let store = ports.deliveries;
    let foreign = delivery_of(first.id(), MOMENT);
    let refused = in_tenant!(ports, &other, |uow| store.insert(uow, &foreign).await);
    assert!(
        refused.is_err(),
        "another tenant's endpoint cannot be named"
    );
}

async fn a_delivery_comes_back_as_it_was_after_every_change(ports: &Ports<'_>) {
    let tenant = tenant();
    let endpoint = endpoint("https://hooks.example.com/");
    insert_endpoint(ports, &tenant, &endpoint).await;
    let policy = RetryPolicy::new(2, Duration::seconds(30)).expect("policy");
    let mut delivery = delivery_of(endpoint.id(), MOMENT);
    insert_delivery(ports, &tenant, &delivery).await;

    delivery.lease(at(0), at(70)).expect("due");
    update_delivery(ports, &tenant, &delivery).await;
    assert_eq!(
        get_delivery(ports, &tenant, delivery.id()).await,
        Some(delivery.clone())
    );
    delivery.record_failure(at(5), Some(503), "the endpoint answered 503", &policy);
    update_delivery(ports, &tenant, &delivery).await;
    assert_eq!(
        get_delivery(ports, &tenant, delivery.id()).await,
        Some(delivery.clone())
    );
    delivery.lease(at(35), at(105)).expect("due");
    delivery.record_failure(at(40), None, "http.timed_out: no", &policy);
    assert_eq!(delivery.status(), DeliveryStatus::SetAside);
    update_delivery(ports, &tenant, &delivery).await;
    assert_eq!(
        get_delivery(ports, &tenant, delivery.id()).await,
        Some(delivery.clone())
    );
    delivery.redeliver(at(50)).expect("again");
    delivery.lease(at(50), at(120)).expect("due");
    delivery.record_success(at(51), 200);
    update_delivery(ports, &tenant, &delivery).await;
    assert_eq!(
        get_delivery(ports, &tenant, delivery.id()).await,
        Some(delivery.clone())
    );

    let store = ports.deliveries;
    let id = delivery.id();
    let (taken, locked) = in_tenant!(ports, &tenant, |uow| {
        Ok((store.take(uow, id).await?, store.lock(uow, id).await?))
    })
    .expect("take");
    assert!(taken.is_some() && locked.is_some());

    let missing = delivery_of(endpoint.id(), MOMENT);
    let error =
        in_tenant!(ports, &tenant, |uow| store.update(uow, &missing).await).expect_err("missing");
    assert_eq!(error.code(), "webhooks.delivery_not_found");
}

async fn leased_deliveries_are_counted_per_endpoint(ports: &Ports<'_>) {
    let tenant = tenant();
    let (busy, idle) = (
        endpoint("https://hooks.example.com/busy"),
        endpoint("https://hooks.example.com/idle"),
    );
    insert_endpoint(ports, &tenant, &busy).await;
    insert_endpoint(ports, &tenant, &idle).await;
    for until in [at(30), at(90)] {
        let mut delivery = delivery_of(busy.id(), MOMENT);
        insert_delivery(ports, &tenant, &delivery).await;
        delivery.lease(MOMENT, until).expect("due");
        update_delivery(ports, &tenant, &delivery).await;
    }
    insert_delivery(ports, &tenant, &delivery_of(busy.id(), MOMENT)).await;
    let store = ports.deliveries;
    let counts = in_tenant!(ports, &tenant, |uow| {
        Ok((
            store.leased(uow, busy.id(), at(10)).await?,
            store.leased(uow, busy.id(), at(30)).await?,
            store.leased(uow, busy.id(), at(90)).await?,
            store.leased(uow, idle.id(), at(10)).await?,
        ))
    })
    .expect("count");
    assert_eq!(counts, (2, 1, 0, 0));
}

async fn deliveries_are_listed_newest_first_by_endpoint_and_status(ports: &Ports<'_>) {
    let tenant = tenant();
    let (one, two) = (
        endpoint("https://hooks.example.com/one"),
        endpoint("https://hooks.example.com/two"),
    );
    insert_endpoint(ports, &tenant, &one).await;
    insert_endpoint(ports, &tenant, &two).await;
    let policy = RetryPolicy::new(1, Duration::seconds(1)).expect("policy");
    let mut made = Vec::new();
    for owner in [one.id(), two.id(), one.id()] {
        let delivery = delivery_of(owner, MOMENT);
        insert_delivery(ports, &tenant, &delivery).await;
        made.push(delivery);
    }
    made[2].lease(MOMENT, at(60)).expect("due");
    made[2].record_failure(at(1), Some(500), "no", &policy);
    update_delivery(ports, &tenant, &made[2]).await;

    let store = ports.deliveries;
    let ids: Vec<DeliveryId> = made.iter().map(Delivery::id).collect();
    let (all, of_one, set_aside, pending_of_one, after) = in_tenant!(ports, &tenant, |uow| {
        let all = store.list(uow, DeliveryQuery::default(), None, 10).await?;
        let of_one = DeliveryQuery {
            endpoint: Some(one.id()),
            status: None,
        };
        let set_aside = DeliveryQuery {
            endpoint: None,
            status: Some(DeliveryStatus::SetAside),
        };
        let pending_of_one = DeliveryQuery {
            endpoint: Some(one.id()),
            status: Some(DeliveryStatus::Pending),
        };
        Ok((
            all,
            store.list(uow, of_one, None, 10).await?,
            store.list(uow, set_aside, None, 10).await?,
            store.list(uow, pending_of_one, None, 10).await?,
            store
                .list(uow, DeliveryQuery::default(), Some(ids[2]), 1)
                .await?,
        ))
    })
    .expect("list");
    let ids_of = |found: &[Delivery]| found.iter().map(Delivery::id).collect::<Vec<_>>();
    assert_eq!(ids_of(&all), [ids[2], ids[1], ids[0]]);
    assert_eq!(ids_of(&of_one), [ids[2], ids[0]]);
    assert_eq!(ids_of(&set_aside), [ids[2]]);
    assert_eq!(ids_of(&pending_of_one), [ids[0]]);
    assert_eq!(ids_of(&after), [ids[1]]);
}

async fn due_deliveries_are_found_across_tenants_longest_waiting_first(ports: &Ports<'_>) {
    // Far from every other case's moments, so that only these are due.
    let base = MOMENT - Duration::days(3_650);
    let (first, second) = (tenant(), tenant());
    let (a, b) = (
        endpoint("https://hooks.example.com/a"),
        endpoint("https://hooks.example.com/b"),
    );
    insert_endpoint(ports, &first, &a).await;
    insert_endpoint(ports, &second, &b).await;
    let oldest = delivery_of(a.id(), base);
    let newer = delivery_of(b.id(), base + Duration::seconds(5));
    let mut leased = delivery_of(a.id(), base);
    let mut later = delivery_of(b.id(), base);
    let mut delivered = delivery_of(a.id(), base);
    for (tenant, delivery) in [
        (&first, &oldest),
        (&second, &newer),
        (&first, &leased),
        (&second, &later),
        (&first, &delivered),
    ] {
        insert_delivery(ports, tenant, delivery).await;
    }
    leased
        .lease(base, base + Duration::seconds(60))
        .expect("due");
    update_delivery(ports, &first, &leased).await;
    later.lease(base, base).expect("due");
    later.record_failure(
        base,
        None,
        "no",
        &RetryPolicy::new(5, Duration::hours(1)).expect("policy"),
    );
    update_delivery(ports, &second, &later).await;
    delivered.lease(base, base).expect("due");
    delivered.record_success(base, 204);
    update_delivery(ports, &first, &delivered).await;

    let now = base + Duration::seconds(10);
    let due = ports.due.due(now, 100).await.expect("due");
    assert_eq!(
        due,
        [
            (first.tenant_id(), oldest.id()),
            (second.tenant_id(), newer.id())
        ]
    );
    assert_eq!(ports.due.due(now, 1).await.expect("due").len(), 1);
    let after_the_lease = ports
        .due
        .due(base + Duration::seconds(60), 100)
        .await
        .expect("due");
    assert!(after_the_lease.contains(&(first.tenant_id(), leased.id())));
}
