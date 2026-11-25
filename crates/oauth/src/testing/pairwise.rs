//! The pairwise secret kept in memory, a stand-in for HMAC-SHA-256, and the
//! contract every store of pairwise secrets passes.

use super::{DistinctRandom, lock};
use crate::api::{HmacSha256, PairwisePorts, PairwiseSecretStore, PairwiseSubjects};
use hodor_kernel::sealing::testing::FakeSecretBox;
use hodor_kernel::{
    DomainError, ErrorKind, HttpClient, HttpMethod, HttpRequest, HttpResponse, SealedSecret,
    SystemClock, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

/// A stand-in for HMAC-SHA-256 in tests of use cases: deterministic and
/// different for different keys and messages, but not a MAC. Never use
/// outside tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct FakeHmac;

impl HmacSha256 for FakeHmac {
    fn mac(&self, key: &[u8], message: &[u8]) -> [u8; 32] {
        let mut output = [0_u8; 32];
        for (chunk, seed) in output.chunks_mut(8).zip(1_u64..) {
            // FNV-1a with a different starting value per chunk.
            let mut hash = 0xcbf2_9ce4_8422_2325_u64.wrapping_mul(seed);
            for byte in key.iter().chain(&[0xff]).chain(message) {
                hash = (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3);
            }
            chunk.copy_from_slice(&hash.to_be_bytes());
        }
        output
    }
}

/// Pairwise secrets kept in memory, one per tenant.
#[derive(Debug, Clone, Default)]
pub struct InMemoryPairwiseSecrets {
    rows: Arc<Mutex<BTreeMap<TenantId, Vec<u8>>>>,
}

impl InMemoryPairwiseSecrets {
    /// Replaces a tenant's stored secret, as damage to storage would.
    pub fn damage(&self, tenant: TenantId) {
        lock(&self.rows).insert(tenant, b"damaged".to_vec());
    }

    /// How many tenants have a secret.
    #[must_use]
    pub fn len(&self) -> usize {
        lock(&self.rows).len()
    }

    /// Whether no tenant has a secret.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        lock(&self.rows).is_empty()
    }
}

#[async_trait::async_trait]
impl PairwiseSecretStore for InMemoryPairwiseSecrets {
    async fn find(&self, uow: &mut dyn UnitOfWork) -> Result<Option<SealedSecret>, DomainError> {
        Ok(lock(&self.rows)
            .get(&uow.tenant().tenant_id())
            .map(|bytes| SealedSecret::from_stored(bytes.clone())))
    }

    async fn insert_unless_present(
        &self,
        uow: &mut dyn UnitOfWork,
        sealed: &SealedSecret,
        _created_at: Timestamp,
    ) -> Result<(), DomainError> {
        lock(&self.rows)
            .entry(uow.tenant().tenant_id())
            .or_insert_with(|| sealed.as_bytes().to_vec());
        Ok(())
    }
}

/// What each address answers: its status and its body.
type Answers = BTreeMap<String, (u16, Vec<u8>)>;

/// Sector identifier addresses and what each answers, in place of the
/// guarded outbound client: an address given no answer does not answer.
/// Every fetch is counted. Never use outside tests.
#[derive(Debug, Clone, Default)]
pub struct SectorDocuments {
    answers: Arc<Mutex<Answers>>,
    fetched: Arc<Mutex<Vec<String>>>,
}

impl SectorDocuments {
    /// Makes `url` answer `status` with `body`.
    pub fn answer(&self, url: &str, status: u16, body: &str) {
        lock(&self.answers).insert(url.to_owned(), (status, body.as_bytes().to_vec()));
    }

    /// How many times an address was fetched.
    #[must_use]
    pub fn fetched(&self) -> usize {
        lock(&self.fetched).len()
    }
}

#[async_trait::async_trait]
impl HttpClient for SectorDocuments {
    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, DomainError> {
        lock(&self.fetched).push(request.url.clone());
        if request.method != HttpMethod::Get {
            return Err(DomainError::invalid(
                "http.url_invalid",
                "a sector identifier document is read with GET",
            ));
        }
        let answer = lock(&self.answers).get(&request.url).cloned();
        answer
            .map(|(status, body)| HttpResponse {
                status,
                headers: vec![("content-type".to_owned(), "application/json".to_owned())],
                body,
            })
            .ok_or_else(|| {
                DomainError::new(
                    ErrorKind::Unavailable,
                    "http.unreachable",
                    "the address did not answer",
                )
            })
    }
}

/// [`PairwiseSubjects`] on `secrets`, with the stand-ins of the kernel for
/// sealing and of this module for the HMAC.
#[must_use]
pub fn pairwise_subjects(
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    secrets: Arc<dyn PairwiseSecretStore>,
) -> PairwiseSubjects {
    PairwiseSubjects::new(PairwisePorts {
        units_of_work,
        secrets,
        secret_box: Arc::new(FakeSecretBox),
        mac: Arc::new(FakeHmac),
        random: Arc::new(DistinctRandom),
        clock: Arc::new(SystemClock),
    })
}

/// What the contract of pairwise secrets needs.
#[derive(Clone, Copy)]
pub struct PairwiseSecretStorePorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub secrets: &'a dyn PairwiseSecretStore,
}

impl std::fmt::Debug for PairwiseSecretStorePorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PairwiseSecretStorePorts")
            .finish_non_exhaustive()
    }
}

fn moment() -> Timestamp {
    Timestamp::UNIX_EPOCH + time::Duration::days(20_000)
}

/// The contract every [`PairwiseSecretStore`] must pass.
///
/// # Panics
///
/// Panics when the store breaks a rule.
pub async fn run_pairwise_secret_contract(ports: PairwiseSecretStorePorts<'_>) {
    a_tenant_keeps_the_first_secret_stored(ports).await;
    a_secret_is_the_tenants_own(ports).await;
}

async fn found(ports: PairwiseSecretStorePorts<'_>, tenant: &TenantContext) -> Option<Vec<u8>> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .secrets
        .find(uow.as_mut())
        .await
        .expect("find")
        .map(|sealed| sealed.as_bytes().to_vec())
}

async fn insert(ports: PairwiseSecretStorePorts<'_>, tenant: &TenantContext, bytes: &[u8]) {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .secrets
        .insert_unless_present(
            uow.as_mut(),
            &SealedSecret::from_stored(bytes.to_vec()),
            moment(),
        )
        .await
        .expect("insert");
    uow.commit().await.expect("commit");
}

async fn a_tenant_keeps_the_first_secret_stored(ports: PairwiseSecretStorePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    assert_eq!(found(ports, &tenant).await, None, "a new tenant has none");
    insert(ports, &tenant, b"first sealed secret").await;
    assert_eq!(
        found(ports, &tenant).await.as_deref(),
        Some(&b"first sealed secret"[..])
    );
    // Never replaced: a second secret leaves the first.
    insert(ports, &tenant, b"second sealed secret").await;
    assert_eq!(
        found(ports, &tenant).await.as_deref(),
        Some(&b"first sealed secret"[..]),
        "the first secret stored stays"
    );
}

async fn a_secret_is_the_tenants_own(ports: PairwiseSecretStorePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let other = TenantContext::assume(TenantId::generate());
    insert(ports, &tenant, b"a tenant's sealed secret").await;
    assert_eq!(found(ports, &other).await, None, "another tenant has none");
    insert(ports, &other, b"the other tenant's").await;
    assert_eq!(
        found(ports, &tenant).await.as_deref(),
        Some(&b"a tenant's sealed secret"[..])
    );
    assert_eq!(
        found(ports, &other).await.as_deref(),
        Some(&b"the other tenant's"[..])
    );
}
