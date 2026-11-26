//! In-memory stores of the token endpoint, a stand-in for signature
//! checking, and the contract every store of client assertions passes.

use super::{InMemoryClients, lock};
use crate::api::{
    Application, ApplicationSettings, ApplicationStore, Client, ClientAssertionStore, ClientId,
    ClientSecret, ClientSettings, ClientStore, ClientType, GrantType,
};
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{
    Digest, DomainError, PublicKey, SignatureAlgorithm, SignatureVerifier, TenantContext, TenantId,
    Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
use time::Duration;

/// The assertions of every tenant, by tenant, client and `jti`.
type AssertionRows = BTreeMap<(TenantId, ClientId, String), Timestamp>;

/// Assertions remembered in memory. They know the clients they are stored
/// against, as the database knows its references.
#[derive(Debug, Clone)]
pub struct InMemoryClientAssertions {
    clients: InMemoryClients,
    rows: Arc<Mutex<AssertionRows>>,
}

impl InMemoryClientAssertions {
    /// Assertions of the clients in `clients`.
    #[must_use]
    pub fn new(clients: &InMemoryClients) -> Self {
        Self {
            clients: clients.clone(),
            rows: Arc::default(),
        }
    }
}

#[async_trait::async_trait]
impl ClientAssertionStore for InMemoryClientAssertions {
    async fn remember(
        &self,
        uow: &mut dyn UnitOfWork,
        client: ClientId,
        assertion_id: &str,
        expires_at: Timestamp,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        if !self.clients.exists(tenant, client) {
            return Err(DomainError::not_found(
                "oauth.client_not_found",
                "there is no such client",
            ));
        }
        let mut rows = lock(&self.rows);
        let key = (tenant, client, assertion_id.to_owned());
        if rows.contains_key(&key) {
            return Ok(false);
        }
        rows.insert(key, expires_at);
        Ok(true)
    }
}

fn key_bytes(key: &PublicKey) -> Vec<u8> {
    match key {
        PublicKey::P256 { x, y } => [x.as_slice(), y.as_slice()].concat(),
        PublicKey::Rsa { modulus, exponent } => [modulus.as_slice(), exponent.as_slice()].concat(),
        PublicKey::Ed25519 { x } => x.clone(),
    }
}

/// A stand-in for signature checking in tests of use cases: the
/// "signature" of a message by a key is [`fake_signature`] of both. Never
/// use outside tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct FakeVerifier;

/// What [`FakeVerifier`] accepts as the signature of `message` by `key`
/// with `algorithm`.
#[must_use]
pub fn fake_signature(algorithm: SignatureAlgorithm, key: &PublicKey, message: &[u8]) -> Vec<u8> {
    let name = match algorithm {
        SignatureAlgorithm::Es256 => "ES256",
        SignatureAlgorithm::Rs256 => "RS256",
        SignatureAlgorithm::Ps256 => "PS256",
        SignatureAlgorithm::EdDsa => "EdDSA",
    };
    FakeDigest
        .sha256(&[name.as_bytes(), &key_bytes(key), message].concat())
        .to_vec()
}

impl SignatureVerifier for FakeVerifier {
    fn verify(
        &self,
        algorithm: SignatureAlgorithm,
        key: &PublicKey,
        message: &[u8],
        signature: &[u8],
    ) -> bool {
        algorithm.fits(key) && fake_signature(algorithm, key, message) == signature
    }
}

/// The ports of the assertion contract.
#[derive(Clone, Copy)]
pub struct AssertionStorePorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// Where the applications of the clients are stored.
    pub applications: &'a dyn ApplicationStore,
    /// Where the clients the rows reference are stored.
    pub clients: &'a dyn ClientStore,
    /// The store under test.
    pub assertions: &'a dyn ClientAssertionStore,
}

impl std::fmt::Debug for AssertionStorePorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AssertionStorePorts")
            .finish_non_exhaustive()
    }
}

fn moment() -> Timestamp {
    Timestamp::UNIX_EPOCH + Duration::days(20_000)
}

async fn a_client(ports: AssertionStorePorts<'_>, tenant: &TenantContext) -> Client {
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

/// Runs every rule a store of client assertions must obey. Each case uses
/// tenants of its own, so runs can share one database.
///
/// # Panics
///
/// Panics when an implementation breaks a rule.
pub async fn run_assertion_contract(ports: AssertionStorePorts<'_>) {
    an_assertion_is_remembered_once(ports).await;
    assertions_reference_their_own_tenant(ports).await;
}

async fn an_assertion_is_remembered_once(ports: AssertionStorePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let client = a_client(ports, &tenant).await;
    let other = a_client(ports, &tenant).await;
    let expires = moment() + Duration::minutes(5);

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        ports
            .assertions
            .remember(uow.as_mut(), client.id(), "first", expires)
            .await
            .expect("remember")
    );
    uow.commit().await.expect("commit");

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        !ports
            .assertions
            .remember(uow.as_mut(), client.id(), "first", expires)
            .await
            .expect("remember again"),
        "the same assertion is remembered once"
    );
    assert!(
        ports
            .assertions
            .remember(uow.as_mut(), other.id(), "first", expires)
            .await
            .expect("another client"),
        "the same jti of another client is another assertion"
    );
    assert!(
        ports
            .assertions
            .remember(uow.as_mut(), client.id(), "second", expires)
            .await
            .expect("another jti")
    );
    uow.commit().await.expect("commit");
}

async fn assertions_reference_their_own_tenant(ports: AssertionStorePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let client = a_client(ports, &tenant).await;
    let elsewhere = TenantContext::assume(TenantId::generate());
    let mut uow = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert_eq!(
        ports
            .assertions
            .remember(uow.as_mut(), client.id(), "one", moment())
            .await
            .expect_err("another tenant's client")
            .code(),
        "oauth.client_not_found"
    );
    drop(uow);

    // What one tenant remembered says nothing to another.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    assert!(
        ports
            .assertions
            .remember(uow.as_mut(), client.id(), "one", moment())
            .await
            .expect("remember")
    );
    uow.commit().await.expect("commit");
}
