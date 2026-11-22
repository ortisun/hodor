//! In-memory stores, stand-in engines and attribute sources, and the
//! contracts every store passes.

use crate::api::{
    Action, Attributes, AuthorizationEngine, BindingSettings, EngineAnswer, EngineBinding,
    EngineBindingStore, EngineCapabilities, EngineId, EvaluationInput, Namespace, PolicySelection,
    PolicySimulator, Role, RoleAssignmentStore, SimulationAnswer, Subject, SubjectAttributeSource,
};
use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::{
    DomainError, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Mutex};
use std::time::Duration;

/// Role assignments kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryRoleAssignments {
    rows: Arc<Mutex<BTreeSet<(TenantId, UserId, Role)>>>,
}

impl InMemoryRoleAssignments {
    fn rows(&self) -> std::sync::MutexGuard<'_, BTreeSet<(TenantId, UserId, Role)>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

#[async_trait::async_trait]
impl RoleAssignmentStore for InMemoryRoleAssignments {
    async fn assign(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        role: Role,
        _now: Timestamp,
    ) -> Result<bool, DomainError> {
        Ok(self
            .rows()
            .insert((uow.tenant().tenant_id(), user_id, role)))
    }

    async fn revoke(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        role: Role,
    ) -> Result<bool, DomainError> {
        Ok(self
            .rows()
            .remove(&(uow.tenant().tenant_id(), user_id, role)))
    }

    async fn roles_of(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Vec<Role>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .rows()
            .iter()
            .filter(|(owner, user, _)| *owner == tenant && *user == user_id)
            .map(|(_, _, role)| *role)
            .collect())
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct Ports<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub assignments: &'a dyn RoleAssignmentStore,
}

impl std::fmt::Debug for Ports<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports").finish_non_exhaustive()
    }
}

async fn assign(ports: &Ports<'_>, tenant: &TenantContext, user: UserId, role: Role) -> bool {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    let changed = ports
        .assignments
        .assign(uow.as_mut(), user, role, Timestamp::UNIX_EPOCH)
        .await
        .expect("assign");
    uow.commit().await.expect("commit");
    changed
}

async fn revoke(ports: &Ports<'_>, tenant: &TenantContext, user: UserId, role: Role) -> bool {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    let changed = ports
        .assignments
        .revoke(uow.as_mut(), user, role)
        .await
        .expect("revoke");
    uow.commit().await.expect("commit");
    changed
}

async fn roles(ports: &Ports<'_>, tenant: &TenantContext, user: UserId) -> Vec<Role> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .assignments
        .roles_of(uow.as_mut(), user)
        .await
        .expect("roles")
}

/// Runs every rule a role assignment store must obey. Each run uses
/// tenants of its own, so runs can share one database.
///
/// # Panics
///
/// Panics if the implementation breaks a rule.
pub async fn run_contract(ports: Ports<'_>) {
    use Role::{TenantAdministrator, TenantAuditor};
    let tenant = TenantContext::assume(TenantId::generate());
    let elsewhere = TenantContext::assume(TenantId::generate());
    let (ana, bia) = (UserId::generate(), UserId::generate());

    // Nobody holds a role to begin with.
    assert!(roles(&ports, &tenant, ana).await.is_empty());

    // Assigning says whether anything changed, and is safe to repeat.
    assert!(assign(&ports, &tenant, ana, TenantAuditor).await);
    assert!(!assign(&ports, &tenant, ana, TenantAuditor).await);
    assert!(assign(&ports, &tenant, ana, TenantAdministrator).await);
    assert_eq!(
        roles(&ports, &tenant, ana).await,
        [TenantAdministrator, TenantAuditor]
    );

    // A role belongs to one user in one tenant.
    assert!(roles(&ports, &tenant, bia).await.is_empty());
    assert!(roles(&ports, &elsewhere, ana).await.is_empty());
    assert!(assign(&ports, &elsewhere, ana, TenantAuditor).await);
    assert!(!revoke(&ports, &elsewhere, ana, TenantAdministrator).await);

    // Revoking says whether anything changed, and is safe to repeat.
    assert!(revoke(&ports, &tenant, ana, TenantAdministrator).await);
    assert!(!revoke(&ports, &tenant, ana, TenantAdministrator).await);
    assert_eq!(roles(&ports, &tenant, ana).await, [TenantAuditor]);
    assert_eq!(roles(&ports, &elsewhere, ana).await, [TenantAuditor]);
}

/// Bindings kept in memory.
#[derive(Debug, Clone, Default)]
pub struct InMemoryEngineBindings {
    rows: Arc<Mutex<BTreeMap<(TenantId, Namespace), EngineBinding>>>,
    failing: Arc<Mutex<bool>>,
}

impl InMemoryEngineBindings {
    fn rows(&self) -> std::sync::MutexGuard<'_, BTreeMap<(TenantId, Namespace), EngineBinding>> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Makes every later call fail, as storage that is down would.
    pub fn fail(&self, failing: bool) {
        *self.failing.lock().unwrap_or_else(|e| e.into_inner()) = failing;
    }

    fn check(&self) -> Result<(), DomainError> {
        if *self.failing.lock().unwrap_or_else(|e| e.into_inner()) {
            Err(DomainError::internal(
                "test.storage_down",
                "storage is down",
            ))
        } else {
            Ok(())
        }
    }
}

#[async_trait::async_trait]
impl EngineBindingStore for InMemoryEngineBindings {
    async fn put(
        &self,
        uow: &mut dyn UnitOfWork,
        binding: &EngineBinding,
    ) -> Result<(), DomainError> {
        self.check()?;
        let key = (uow.tenant().tenant_id(), binding.namespace().clone());
        self.rows().insert(key, binding.clone());
        Ok(())
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        namespace: &Namespace,
    ) -> Result<Option<EngineBinding>, DomainError> {
        self.check()?;
        let key = (uow.tenant().tenant_id(), namespace.clone());
        Ok(self.rows().get(&key).cloned())
    }

    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<EngineBinding>, DomainError> {
        self.check()?;
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .rows()
            .iter()
            .filter(|((owner, _), _)| *owner == tenant)
            .map(|(_, binding)| binding.clone())
            .collect())
    }

    async fn remove(
        &self,
        uow: &mut dyn UnitOfWork,
        namespace: &Namespace,
    ) -> Result<bool, DomainError> {
        self.check()?;
        let key = (uow.tenant().tenant_id(), namespace.clone());
        Ok(self.rows().remove(&key).is_some())
    }
}

/// Attributes of subjects set by a test, per tenant.
#[derive(Debug, Clone, Default)]
pub struct StaticSubjectAttributes {
    known: Arc<Mutex<BTreeMap<(TenantId, Subject), Attributes>>>,
    failing: Arc<Mutex<bool>>,
}

impl StaticSubjectAttributes {
    /// Says what is known about a subject in a tenant.
    pub fn set(&self, tenant: &TenantContext, subject: &Subject, attributes: Attributes) {
        self.known
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert((tenant.tenant_id(), subject.clone()), attributes);
    }

    /// Makes every later call fail.
    pub fn fail(&self, failing: bool) {
        *self.failing.lock().unwrap_or_else(|e| e.into_inner()) = failing;
    }
}

#[async_trait::async_trait]
impl SubjectAttributeSource for StaticSubjectAttributes {
    async fn attributes_of(
        &self,
        tenant: &TenantContext,
        subject: &Subject,
    ) -> Result<Attributes, DomainError> {
        if *self.failing.lock().unwrap_or_else(|e| e.into_inner()) {
            return Err(DomainError::internal(
                "test.source_down",
                "the source is down",
            ));
        }
        Ok(self
            .known
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(&(tenant.tenant_id(), subject.clone()))
            .cloned()
            .unwrap_or_default())
    }
}

/// How long a slow engine takes, on which clock.
type Slowness = Option<(Arc<FixedClock>, Duration)>;

type Script =
    dyn Fn(&TenantContext, &EvaluationInput) -> Result<EngineAnswer, DomainError> + Send + Sync;

/// An engine whose answers a test writes, and which remembers what it was
/// given.
#[derive(Clone)]
pub struct ScriptedEngine {
    id: EngineId,
    script: Arc<Script>,
    seen: Arc<Mutex<Vec<(TenantId, EvaluationInput)>>>,
    batches: Arc<Mutex<Vec<usize>>>,
    slowness: Arc<Mutex<Slowness>>,
    answers_short: Arc<Mutex<bool>>,
}

impl std::fmt::Debug for ScriptedEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScriptedEngine")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

impl ScriptedEngine {
    /// An engine called `id` that answers with `script`.
    ///
    /// # Panics
    ///
    /// Panics if `id` is not an engine name.
    pub fn new(
        id: &str,
        script: impl Fn(&TenantContext, &EvaluationInput) -> Result<EngineAnswer, DomainError>
        + Send
        + Sync
        + 'static,
    ) -> Self {
        Self {
            id: EngineId::parse(id).expect("an engine name"),
            script: Arc::new(script),
            seen: Arc::default(),
            batches: Arc::default(),
            slowness: Arc::default(),
            answers_short: Arc::default(),
        }
    }

    /// Makes every call move `clock` forward by `by`, as a slow engine
    /// would take that long.
    pub fn take(&self, clock: Arc<FixedClock>, by: Duration) {
        *self.slowness.lock().unwrap_or_else(|e| e.into_inner()) = Some((clock, by));
    }

    /// Makes a batch answer one answer fewer than it was asked.
    pub fn answer_short(&self, short: bool) {
        *self.answers_short.lock().unwrap_or_else(|e| e.into_inner()) = short;
    }

    /// Everything it was asked to decide, in order, with the tenant.
    #[must_use]
    pub fn seen(&self) -> Vec<(TenantId, EvaluationInput)> {
        self.seen.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The size of every batch it was sent.
    #[must_use]
    pub fn batches(&self) -> Vec<usize> {
        self.batches
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    fn answer(
        &self,
        tenant: &TenantContext,
        input: &EvaluationInput,
    ) -> Result<EngineAnswer, DomainError> {
        self.seen
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push((tenant.tenant_id(), input.clone()));
        (self.script)(tenant, input)
    }

    fn wait(&self) {
        let slowness = self
            .slowness
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        if let Some((clock, by)) = slowness {
            clock.advance(time::Duration::try_from(by).unwrap_or(time::Duration::ZERO));
        }
    }
}

#[async_trait::async_trait]
impl AuthorizationEngine for ScriptedEngine {
    fn id(&self) -> EngineId {
        self.id.clone()
    }

    fn capabilities(&self) -> EngineCapabilities {
        EngineCapabilities {
            simulation: true,
            explanation: true,
        }
    }

    async fn evaluate(
        &self,
        tenant: &TenantContext,
        input: &EvaluationInput,
    ) -> Result<EngineAnswer, DomainError> {
        self.wait();
        self.answer(tenant, input)
    }

    async fn evaluate_batch(
        &self,
        tenant: &TenantContext,
        inputs: &[EvaluationInput],
    ) -> Vec<Result<EngineAnswer, DomainError>> {
        self.batches
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .push(inputs.len());
        self.wait();
        let mut answers: Vec<_> = inputs
            .iter()
            .map(|input| self.answer(tenant, input))
            .collect();
        if *self.answers_short.lock().unwrap_or_else(|e| e.into_inner()) {
            answers.pop();
        }
        answers
    }
}

#[async_trait::async_trait]
impl PolicySimulator for ScriptedEngine {
    async fn simulate(
        &self,
        tenant: &TenantContext,
        input: &EvaluationInput,
        against: &PolicySelection,
    ) -> Result<SimulationAnswer, DomainError> {
        let answer = self.answer(tenant, input)?;
        Ok(SimulationAnswer {
            answer,
            trace: vec![format!("simulated against {against:?}")],
        })
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct BindingPorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub bindings: &'a dyn EngineBindingStore,
}

impl std::fmt::Debug for BindingPorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BindingPorts").finish_non_exhaustive()
    }
}

async fn put_binding(ports: &BindingPorts<'_>, tenant: &TenantContext, binding: &EngineBinding) {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .bindings
        .put(uow.as_mut(), binding)
        .await
        .expect("put");
    uow.commit().await.expect("commit");
}

async fn find_binding(
    ports: &BindingPorts<'_>,
    tenant: &TenantContext,
    namespace: &Namespace,
) -> Option<EngineBinding> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports
        .bindings
        .find(uow.as_mut(), namespace)
        .await
        .expect("find")
}

async fn list_bindings(ports: &BindingPorts<'_>, tenant: &TenantContext) -> Vec<EngineBinding> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    ports.bindings.list(uow.as_mut()).await.expect("list")
}

async fn remove_binding(
    ports: &BindingPorts<'_>,
    tenant: &TenantContext,
    namespace: &Namespace,
) -> bool {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    let removed = ports
        .bindings
        .remove(uow.as_mut(), namespace)
        .await
        .expect("remove");
    uow.commit().await.expect("commit");
    removed
}

/// Runs every rule a binding store must obey. Each run uses tenants of its
/// own, so runs can share one database.
///
/// # Panics
///
/// Panics if the implementation breaks a rule.
pub async fn run_binding_contract(ports: BindingPorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let elsewhere = TenantContext::assume(TenantId::generate());
    let documents = Namespace::parse("https://documents.example.com").expect("namespace");
    let billing = Namespace::parse("urn:example:billing").expect("namespace");
    // Times with whole microseconds, as storage keeps them.
    let created = Timestamp::UNIX_EPOCH + time::Duration::days(20_000);
    let changed = created + time::Duration::minutes(5);

    // Nothing is bound to begin with.
    assert_eq!(find_binding(&ports, &tenant, &documents).await, None);
    assert!(list_bindings(&ports, &tenant).await.is_empty());

    // Every setting is kept as it was given.
    let mut settings = BindingSettings::new(
        documents.clone(),
        EngineId::parse("open_policy_agent").expect("engine"),
    );
    settings.time_limit = Duration::from_millis(750);
    settings.trust_asserted = true;
    settings
        .fail_open_actions
        .extend(["read", "list"].map(|name| Action::parse(name).expect("action")));
    let binding = EngineBinding::new(settings, created).expect("binding");
    put_binding(&ports, &tenant, &binding).await;
    assert_eq!(
        find_binding(&ports, &tenant, &documents).await.as_ref(),
        Some(&binding)
    );

    // A sensitive binding with the defaults.
    let mut sensitive = BindingSettings::new(billing.clone(), EngineId::native());
    sensitive.sensitive = true;
    let sensitive = EngineBinding::new(sensitive, created).expect("binding");
    put_binding(&ports, &tenant, &sensitive).await;
    assert_eq!(
        find_binding(&ports, &tenant, &billing).await.as_ref(),
        Some(&sensitive)
    );

    // The list is ordered by namespace.
    let listed = list_bindings(&ports, &tenant).await;
    let namespaces: Vec<&str> = listed.iter().map(|b| b.namespace().as_str()).collect();
    assert_eq!(
        namespaces,
        ["https://documents.example.com", "urn:example:billing"]
    );

    // Putting again replaces the binding of the same namespace.
    let mut slower = binding.settings().clone();
    slower.time_limit = Duration::from_millis(1500);
    slower.fail_open_actions.clear();
    let slower = binding.changed(slower, changed).expect("changed");
    put_binding(&ports, &tenant, &slower).await;
    assert_eq!(
        find_binding(&ports, &tenant, &documents).await.as_ref(),
        Some(&slower)
    );
    assert_eq!(list_bindings(&ports, &tenant).await.len(), 2);

    // A binding belongs to its tenant.
    assert_eq!(find_binding(&ports, &elsewhere, &documents).await, None);
    assert!(list_bindings(&ports, &elsewhere).await.is_empty());
    assert!(!remove_binding(&ports, &elsewhere, &documents).await);
    let theirs = EngineBinding::new(
        BindingSettings::new(documents.clone(), EngineId::native()),
        created,
    )
    .expect("binding");
    put_binding(&ports, &elsewhere, &theirs).await;
    assert_eq!(
        find_binding(&ports, &tenant, &documents).await.as_ref(),
        Some(&slower)
    );

    // Removing says whether there was one, and is safe to repeat.
    assert!(remove_binding(&ports, &tenant, &documents).await);
    assert!(!remove_binding(&ports, &tenant, &documents).await);
    assert_eq!(find_binding(&ports, &tenant, &documents).await, None);
    assert_eq!(
        find_binding(&ports, &elsewhere, &documents).await.as_ref(),
        Some(&theirs)
    );
}
