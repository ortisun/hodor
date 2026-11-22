//! In-memory stores and the contracts every implementation of them passes.

use crate::api::{
    AttemptCounter, AttemptStore, AttemptSubject, AuthFlow, AuthTransaction, Authenticator,
    AuthenticatorTraits, Factor, LockoutRules, StepInput, StepOutcome, TokenPurpose, TransactionId,
    TransactionStore, VerificationSecret, VerificationToken, VerificationTokenHash,
    VerificationTokenId, VerificationTokenStore,
};
use hodor_kernel::random::testing::FakeDigest;
use hodor_kernel::{
    DomainError, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use hodor_kernel::{RandomSource, UserId};
use hodor_session::api::ClientInfo;
use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};
use time::Duration;

/// A stand-in second factor, until real ones exist: something the person
/// has, which only the people enrolled in it have the means for. It is
/// satisfied by the field `code` holding [`TestSecondFactor::CODE`].
#[derive(Debug, Clone, Default)]
pub struct TestSecondFactor {
    enrolled: Arc<Mutex<BTreeSet<UserId>>>,
}

impl TestSecondFactor {
    /// The kind flows name it by.
    pub const KIND: &'static str = "test-second-factor";
    /// The method recorded for a satisfied step.
    pub const METHOD: &'static str = "test-second-factor";
    /// The one code it accepts.
    pub const CODE: &'static str = "246810";

    /// Gives a person the means for this factor.
    ///
    /// # Panics
    ///
    /// Panics if the lock is poisoned.
    pub fn enroll(&self, user: UserId) {
        self.enrolled.lock().expect("enrolled").insert(user);
    }

    fn is_enrolled(&self, user: Option<UserId>) -> bool {
        user.is_some_and(|user| self.enrolled.lock().expect("enrolled").contains(&user))
    }
}

#[async_trait::async_trait]
impl Authenticator for TestSecondFactor {
    fn kind(&self) -> &'static str {
        Self::KIND
    }

    fn traits(&self) -> AuthenticatorTraits {
        AuthenticatorTraits {
            identifies: false,
            factor: Some(Factor::Possession),
            method: Some(Self::METHOD),
        }
    }

    async fn perform(
        &self,
        _tenant: &TenantContext,
        transaction: &AuthTransaction,
        input: &StepInput,
    ) -> Result<StepOutcome, DomainError> {
        let right = matches!(
            input,
            StepInput::External(external)
                if external.field("code").is_some_and(|code| code.expose() == Self::CODE)
        );
        Ok(if right && self.is_enrolled(transaction.candidate()) {
            StepOutcome::Proven
        } else {
            StepOutcome::Rejected
        })
    }

    async fn has_means(
        &self,
        _tenant: &TenantContext,
        transaction: &AuthTransaction,
    ) -> Result<bool, DomainError> {
        Ok(self.is_enrolled(transaction.candidate()))
    }
}

/// Attempt counters kept in memory. It does not serialize concurrent
/// access; tests that need that run against PostgreSQL.
#[derive(Debug, Clone, Default)]
pub struct InMemoryAttempts {
    rows: Arc<Mutex<BTreeMap<(TenantId, AttemptSubject), AttemptCounter>>>,
}

impl InMemoryAttempts {
    fn rows(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<(TenantId, AttemptSubject), AttemptCounter>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl AttemptStore for InMemoryAttempts {
    async fn lock(
        &self,
        uow: &mut dyn UnitOfWork,
        subject: &AttemptSubject,
        now: Timestamp,
    ) -> Result<AttemptCounter, DomainError> {
        Ok(self
            .rows()
            .entry((uow.tenant().tenant_id(), *subject))
            .or_insert_with(|| AttemptCounter::new(*subject, now))
            .clone())
    }

    async fn save(
        &self,
        uow: &mut dyn UnitOfWork,
        counter: &AttemptCounter,
    ) -> Result<(), DomainError> {
        self.rows().insert(
            (uow.tenant().tenant_id(), *counter.subject()),
            counter.clone(),
        );
        Ok(())
    }

    async fn clear(
        &self,
        uow: &mut dyn UnitOfWork,
        subject: &AttemptSubject,
    ) -> Result<(), DomainError> {
        self.rows().remove(&(uow.tenant().tenant_id(), *subject));
        Ok(())
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct AttemptPorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub attempts: &'a dyn AttemptStore,
}

impl std::fmt::Debug for AttemptPorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AttemptPorts").finish_non_exhaustive()
    }
}

/// A fixed, whole-second moment, so that stored timestamps compare equal
/// after a round trip through any storage.
const MOMENT: Timestamp = Timestamp::UNIX_EPOCH;
const RULES: LockoutRules = LockoutRules {
    max_failures: 3,
    window: Duration::minutes(15),
    first_lockout: Duration::minutes(1),
    longest_lockout: Duration::hours(1),
};

async fn lock(
    ports: &AttemptPorts<'_>,
    tenant: &TenantContext,
    subject: &AttemptSubject,
) -> AttemptCounter {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    let counter = ports
        .attempts
        .lock(uow.as_mut(), subject, MOMENT)
        .await
        .expect("lock");
    uow.commit().await.expect("commit");
    counter
}

async fn count(
    ports: &AttemptPorts<'_>,
    tenant: &TenantContext,
    subject: &AttemptSubject,
) -> AttemptCounter {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    let mut counter = ports
        .attempts
        .lock(uow.as_mut(), subject, MOMENT)
        .await
        .expect("lock");
    counter.count(&RULES, MOMENT);
    ports
        .attempts
        .save(uow.as_mut(), &counter)
        .await
        .expect("save");
    uow.commit().await.expect("commit");
    counter
}

/// Runs the whole contract of an attempt store. Each case uses a tenant of
/// its own, so runs can share one database.
///
/// # Panics
///
/// Panics when the implementation breaks the contract.
pub async fn run_attempt_contract(ports: AttemptPorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let identifier = AttemptSubject::Identifier([1; 32]);
    let address = AttemptSubject::Address([1; 32]);

    // A subject never seen before has an empty counter.
    let fresh = lock(&ports, &tenant, &identifier).await;
    assert_eq!(fresh, AttemptCounter::new(identifier, MOMENT));

    // What is saved is what is loaded next, lockout included.
    count(&ports, &tenant, &identifier).await;
    count(&ports, &tenant, &identifier).await;
    let locked = count(&ports, &tenant, &identifier).await;
    assert_eq!(locked.lockouts(), 1);
    assert_eq!(lock(&ports, &tenant, &identifier).await, locked);
    assert_eq!(
        locked.locked_until(MOMENT),
        Some(MOMENT + Duration::minutes(1))
    );

    // An identifier and an address with the same digest are different
    // subjects.
    assert_eq!(lock(&ports, &tenant, &address).await.failures(), 0);

    // Another tenant has its own counters.
    let elsewhere = TenantContext::assume(TenantId::generate());
    assert_eq!(lock(&ports, &elsewhere, &identifier).await.lockouts(), 0);

    // Clearing forgets everything about one subject and nothing else.
    count(&ports, &tenant, &address).await;
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .attempts
        .clear(uow.as_mut(), &identifier)
        .await
        .expect("clear");
    uow.commit().await.expect("commit");
    assert_eq!(
        lock(&ports, &tenant, &identifier).await,
        AttemptCounter::new(identifier, MOMENT)
    );
    assert_eq!(lock(&ports, &tenant, &address).await.failures(), 1);
}

/// Sign-ins in progress kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryTransactions {
    rows: Arc<Mutex<BTreeMap<(TenantId, TransactionId), AuthTransaction>>>,
}

impl InMemoryTransactions {
    fn rows(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<(TenantId, TransactionId), AuthTransaction>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn next_version(transaction: &AuthTransaction) -> AuthTransaction {
    let mut state = transaction.snapshot().clone();
    state.version += 1;
    AuthTransaction::from_snapshot(state)
}

#[async_trait::async_trait]
impl TransactionStore for InMemoryTransactions {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction: &AuthTransaction,
    ) -> Result<(), DomainError> {
        self.rows().insert(
            (uow.tenant().tenant_id(), transaction.id()),
            transaction.clone(),
        );
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: TransactionId,
    ) -> Result<Option<AuthTransaction>, DomainError> {
        Ok(self.rows().get(&(uow.tenant().tenant_id(), id)).cloned())
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction: &AuthTransaction,
    ) -> Result<(), DomainError> {
        let key = (uow.tenant().tenant_id(), transaction.id());
        let mut rows = self.rows();
        let stored = rows.get(&key).ok_or_else(|| {
            DomainError::not_found(
                "authentication.transaction_not_found",
                "this sign-in does not exist; start again",
            )
        })?;
        if stored.snapshot().version != transaction.snapshot().version {
            return Err(DomainError::conflict(
                "authentication.transaction_modified_concurrently",
                "this sign-in was advanced by another request",
            ));
        }
        rows.insert(key, next_version(transaction));
        Ok(())
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct TransactionPorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub transactions: &'a dyn TransactionStore,
}

impl std::fmt::Debug for TransactionPorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TransactionPorts").finish_non_exhaustive()
    }
}

async fn stored(
    ports: &TransactionPorts<'_>,
    tenant: &TenantContext,
    id: TransactionId,
) -> Option<AuthTransaction> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports.transactions.get(uow.as_mut(), id).await.expect("get")
}

async fn update(
    ports: &TransactionPorts<'_>,
    tenant: &TenantContext,
    transaction: &AuthTransaction,
) -> Result<(), DomainError> {
    let mut uow = ports.units_of_work.begin(tenant).await?;
    ports.transactions.update(uow.as_mut(), transaction).await?;
    uow.commit().await
}

/// Runs the whole contract of a transaction store. Each run uses tenants
/// of its own, so runs can share one database.
///
/// # Panics
///
/// Panics when the implementation breaks the contract.
pub async fn run_transaction_contract(ports: TransactionPorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let elsewhere = TenantContext::assume(TenantId::generate());
    let flow = AuthFlow::built_in();
    let client = ClientInfo {
        address: Some("203.0.113.9".to_owned()),
        description: Some("Example Browser 1.0".to_owned()),
    };
    let transaction = AuthTransaction::start(&flow, client, [9; 32], MOMENT);

    // A stored transaction is loaded unchanged, within its tenant only.
    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .transactions
        .insert(uow.as_mut(), &transaction)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");
    assert_eq!(
        stored(&ports, &tenant, transaction.id()).await,
        Some(transaction.clone())
    );
    assert_eq!(stored(&ports, &elsewhere, transaction.id()).await, None);
    assert_eq!(
        stored(&ports, &tenant, TransactionId::generate()).await,
        None
    );

    // Progress is stored, and raises the version.
    let mut advanced = transaction.clone();
    advanced.record_identified(Some(hodor_kernel::UserId::generate()), [5; 32]);
    advanced.record_rejection();
    update(&ports, &tenant, &advanced).await.expect("update");
    let reloaded = stored(&ports, &tenant, transaction.id())
        .await
        .expect("exists");
    assert_eq!(reloaded.snapshot().version, 1);
    assert_eq!(reloaded.snapshot().current_step, 1);
    assert_eq!(reloaded.snapshot().candidate, advanced.snapshot().candidate);
    assert_eq!(reloaded.snapshot().identifier_key, Some([5; 32]));
    assert_eq!(reloaded.snapshot().rejections, 1);
    assert!(reloaded.snapshot().identified);
    assert!(reloaded.is_bound_to(&[9; 32]), "the binding is stored");

    // A challenge is stored, and its removal too.
    let mut challenged = reloaded.clone();
    challenged.record_challenge([6; 32]);
    update(&ports, &tenant, &challenged).await.expect("update");
    let reloaded = stored(&ports, &tenant, transaction.id())
        .await
        .expect("exists");
    assert_eq!(reloaded.challenge(), Some(&[6; 32]));
    let mut answered = reloaded.clone();
    answered.record_rejection();
    update(&ports, &tenant, &answered).await.expect("update");
    let reloaded = stored(&ports, &tenant, transaction.id())
        .await
        .expect("exists");
    assert_eq!(reloaded.challenge(), None);
    assert_eq!(reloaded.snapshot().version, 3);

    // Of two requests working from the same version, the second is
    // refused. This is what makes completion happen once.
    let (mut first, mut second) = (reloaded.clone(), reloaded.clone());
    first.record_satisfied(Some("password"));
    second.record_satisfied(Some("password"));
    first.complete(&flow, MOMENT).expect("complete");
    second.complete(&flow, MOMENT).expect("complete");
    update(&ports, &tenant, &first).await.expect("first");
    let error = update(&ports, &tenant, &second).await.expect_err("second");
    assert_eq!(
        error.code(),
        "authentication.transaction_modified_concurrently"
    );
    let ended = stored(&ports, &tenant, transaction.id())
        .await
        .expect("exists");
    assert_eq!(ended.snapshot().satisfied_methods, ["password"]);
    assert_eq!(ended.snapshot().status, first.snapshot().status);

    // A transaction cannot be updated from another tenant.
    let error = update(&ports, &elsewhere, &ended)
        .await
        .expect_err("cross-tenant");
    assert_eq!(error.code(), "authentication.transaction_not_found");
}

/// Verification tokens kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryVerificationTokens {
    rows: Arc<Mutex<BTreeMap<(TenantId, VerificationTokenId), VerificationToken>>>,
}

impl InMemoryVerificationTokens {
    fn rows(
        &self,
    ) -> std::sync::MutexGuard<'_, BTreeMap<(TenantId, VerificationTokenId), VerificationToken>>
    {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl VerificationTokenStore for InMemoryVerificationTokens {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        token: &VerificationToken,
    ) -> Result<(), DomainError> {
        self.rows()
            .insert((uow.tenant().tenant_id(), token.id()), token.clone());
        Ok(())
    }

    async fn replace_earlier(
        &self,
        uow: &mut dyn UnitOfWork,
        purpose: TokenPurpose,
        email: &str,
        now: Timestamp,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        for ((owner, _), token) in self.rows().iter_mut() {
            let state = token.snapshot();
            if *owner == tenant
                && state.purpose == purpose
                && state.email == email
                && state.used_at.is_none()
                && state.replaced_at.is_none()
            {
                token.mark_replaced(now);
            }
        }
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &VerificationTokenHash,
        purpose: TokenPurpose,
    ) -> Result<Option<VerificationToken>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .rows()
            .iter()
            .find(|((owner, _), token)| {
                *owner == tenant
                    && token.snapshot().purpose == purpose
                    && &token.snapshot().token_hash == hash
            })
            .map(|(_, token)| token.clone()))
    }

    async fn use_up(
        &self,
        uow: &mut dyn UnitOfWork,
        hash: &VerificationTokenHash,
        purpose: TokenPurpose,
        now: Timestamp,
    ) -> Result<Option<VerificationToken>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.rows();
        let found = rows.iter_mut().find(|((owner, _), token)| {
            *owner == tenant
                && token.snapshot().purpose == purpose
                && &token.snapshot().token_hash == hash
                && token.is_good_at(now)
        });
        Ok(found.map(|(_, token)| {
            token.mark_used(now);
            token.clone()
        }))
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct VerificationTokenPorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub tokens: &'a dyn VerificationTokenStore,
}

impl std::fmt::Debug for VerificationTokenPorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VerificationTokenPorts")
            .finish_non_exhaustive()
    }
}

/// A random source for the contract whose every call gives different
/// bytes, so that every token made with it is different.
struct ContractRandom;

impl RandomSource for ContractRandom {
    fn fill(&self, buffer: &mut [u8]) {
        let unique = VerificationTokenId::generate().as_uuid();
        for (byte, source) in buffer
            .iter_mut()
            .zip(unique.as_bytes().iter().rev().cycle())
        {
            *byte = *source;
        }
    }
}

fn issue(
    purpose: TokenPurpose,
    email: &str,
    user_id: Option<UserId>,
) -> (VerificationToken, VerificationSecret) {
    VerificationToken::issue(
        purpose,
        email,
        user_id,
        "pt-BR",
        MOMENT,
        &ContractRandom,
        &FakeDigest,
    )
}

fn hash_of(secret: &VerificationSecret) -> VerificationTokenHash {
    VerificationTokenHash::of_presented(secret.expose(), &FakeDigest).expect("well formed")
}

async fn store_token(
    ports: &VerificationTokenPorts<'_>,
    tenant: &TenantContext,
    token: &VerificationToken,
) {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .tokens
        .insert(uow.as_mut(), token)
        .await
        .expect("insert");
    uow.commit().await.expect("commit");
}

async fn find_token(
    ports: &VerificationTokenPorts<'_>,
    tenant: &TenantContext,
    secret: &VerificationSecret,
    purpose: TokenPurpose,
) -> Option<VerificationToken> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .tokens
        .find(uow.as_mut(), &hash_of(secret), purpose)
        .await
        .expect("find")
}

async fn use_token(
    ports: &VerificationTokenPorts<'_>,
    tenant: &TenantContext,
    secret: &VerificationSecret,
    purpose: TokenPurpose,
    now: Timestamp,
) -> Option<VerificationToken> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    let used = ports
        .tokens
        .use_up(uow.as_mut(), &hash_of(secret), purpose, now)
        .await
        .expect("use up");
    uow.commit().await.expect("commit");
    used
}

/// Runs the whole contract of a verification token store. Each run uses
/// tenants of its own, so runs can share one database.
///
/// # Panics
///
/// Panics when the implementation breaks the contract.
pub async fn run_verification_token_contract(ports: VerificationTokenPorts<'_>) {
    use TokenPurpose::{PasswordRecovery, Registration};
    let tenant = TenantContext::assume(TenantId::generate());
    let elsewhere = TenantContext::assume(TenantId::generate());
    let soon = MOMENT + Duration::minutes(5);

    // A stored token is loaded unchanged, by its own tenant and purpose only.
    let user = UserId::generate();
    let (recovery, recovery_secret) = issue(PasswordRecovery, "ana@example.com", Some(user));
    store_token(&ports, &tenant, &recovery).await;
    assert_eq!(
        find_token(&ports, &tenant, &recovery_secret, PasswordRecovery).await,
        Some(recovery.clone())
    );
    assert_eq!(
        find_token(&ports, &tenant, &recovery_secret, Registration).await,
        None
    );
    assert_eq!(
        find_token(&ports, &elsewhere, &recovery_secret, PasswordRecovery).await,
        None
    );

    // It cannot be used up by another tenant or for another purpose.
    assert_eq!(
        use_token(&ports, &elsewhere, &recovery_secret, PasswordRecovery, soon).await,
        None
    );
    assert_eq!(
        use_token(&ports, &tenant, &recovery_secret, Registration, soon).await,
        None
    );

    // It is used up once, and the use is remembered.
    let used = use_token(&ports, &tenant, &recovery_secret, PasswordRecovery, soon)
        .await
        .expect("good");
    assert_eq!(used.snapshot().user_id, Some(user));
    assert_eq!(used.snapshot().used_at, Some(soon));
    assert_eq!(
        use_token(&ports, &tenant, &recovery_secret, PasswordRecovery, soon).await,
        None
    );
    let stored = find_token(&ports, &tenant, &recovery_secret, PasswordRecovery)
        .await
        .expect("still stored");
    assert_eq!(stored.snapshot().used_at, Some(soon));

    // An expired token cannot be used up, and stays unused.
    let (expiring, expiring_secret) = issue(Registration, "bia@example.com", None);
    store_token(&ports, &tenant, &expiring).await;
    let too_late = MOMENT + Registration.lifetime();
    assert_eq!(
        use_token(&ports, &tenant, &expiring_secret, Registration, too_late).await,
        None
    );
    assert!(
        use_token(
            &ports,
            &tenant,
            &expiring_secret,
            Registration,
            too_late - Duration::seconds(1)
        )
        .await
        .is_some()
    );

    // Replacing touches only unused tokens of the same purpose and address,
    // in the same tenant.
    let (first, first_secret) = issue(Registration, "caio@example.com", None);
    let (other_address, other_address_secret) = issue(Registration, "dora@example.com", None);
    let (other_purpose, other_purpose_secret) =
        issue(PasswordRecovery, "caio@example.com", Some(user));
    let (other_tenant, other_tenant_secret) = issue(Registration, "caio@example.com", None);
    for token in [&first, &other_address, &other_purpose] {
        store_token(&ports, &tenant, token).await;
    }
    store_token(&ports, &elsewhere, &other_tenant).await;

    let mut uow = ports.units_of_work.begin(&tenant).await.expect("begin");
    ports
        .tokens
        .replace_earlier(uow.as_mut(), Registration, "caio@example.com", soon)
        .await
        .expect("replace");
    uow.commit().await.expect("commit");

    let replaced = find_token(&ports, &tenant, &first_secret, Registration)
        .await
        .expect("still stored");
    assert_eq!(replaced.snapshot().replaced_at, Some(soon));
    assert_eq!(
        use_token(&ports, &tenant, &first_secret, Registration, soon).await,
        None
    );
    assert!(
        use_token(&ports, &tenant, &other_address_secret, Registration, soon)
            .await
            .is_some()
    );
    assert!(
        use_token(
            &ports,
            &tenant,
            &other_purpose_secret,
            PasswordRecovery,
            soon
        )
        .await
        .is_some()
    );
    assert!(
        use_token(&ports, &elsewhere, &other_tenant_secret, Registration, soon)
            .await
            .is_some()
    );

    // A token made after the replacement is good.
    let (second, second_secret) = issue(Registration, "caio@example.com", None);
    store_token(&ports, &tenant, &second).await;
    assert!(
        use_token(&ports, &tenant, &second_secret, Registration, soon)
            .await
            .is_some()
    );
}
