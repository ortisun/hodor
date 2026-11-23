//! In-memory stores, stand-in engines and attribute sources, and the
//! contracts every store passes.

use crate::api::{
    Action, ApplicationReference, AssignmentScope, Attributes, AuthorizationEngine,
    BindingSettings, EngineAnswer, EngineBinding, EngineBindingStore, EngineCapabilities, EngineId,
    EvaluationInput, Namespace, NativeRoleStore, PermissionDefinition, PermissionName,
    PolicySelection, PolicySimulator, Role, RoleAssignment, RoleAssignmentStore, RoleContents,
    RoleDefinition, RoleKey, RoleName, SimulationAnswer, Subject, SubjectAttributeSource,
    SubjectKind,
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

#[derive(Debug, Default)]
struct NativeRows {
    revisions: BTreeMap<TenantId, u64>,
    permissions: BTreeMap<(TenantId, Namespace, PermissionName), PermissionDefinition>,
    roles: BTreeMap<(TenantId, RoleKey), RoleDefinition>,
    assignments: BTreeMap<(TenantId, Subject, RoleKey, AssignmentScope), RoleAssignment>,
}

/// Permissions, roles and assignments kept in memory. Like the database,
/// it refuses a role that names a permission or a role that does not
/// exist, and the removal of a role another role includes.
#[derive(Debug, Clone, Default)]
pub struct InMemoryNativeRoles {
    rows: Arc<Mutex<NativeRows>>,
}

impl InMemoryNativeRoles {
    fn rows(&self) -> std::sync::MutexGuard<'_, NativeRows> {
        self.rows.lock().unwrap_or_else(|e| e.into_inner())
    }
}

fn missing_reference() -> DomainError {
    DomainError::internal("database.error", "the operation could not be completed")
        .with_detail("a role names a permission or a role that does not exist")
}

#[async_trait::async_trait]
impl NativeRoleStore for InMemoryNativeRoles {
    async fn raise_revision(&self, uow: &mut dyn UnitOfWork) -> Result<u64, DomainError> {
        let mut rows = self.rows();
        let revision = rows.revisions.entry(uow.tenant().tenant_id()).or_default();
        *revision += 1;
        Ok(*revision)
    }

    async fn revision(&self, uow: &mut dyn UnitOfWork) -> Result<u64, DomainError> {
        Ok(self
            .rows()
            .revisions
            .get(&uow.tenant().tenant_id())
            .copied()
            .unwrap_or(0))
    }

    async fn put_permission(
        &self,
        uow: &mut dyn UnitOfWork,
        permission: &PermissionDefinition,
    ) -> Result<(), DomainError> {
        self.rows().permissions.insert(
            (
                uow.tenant().tenant_id(),
                permission.namespace().clone(),
                permission.name().clone(),
            ),
            permission.clone(),
        );
        Ok(())
    }

    async fn remove_permission(
        &self,
        uow: &mut dyn UnitOfWork,
        namespace: &Namespace,
        permission: &PermissionName,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.rows();
        let removed = rows
            .permissions
            .remove(&(tenant, namespace.clone(), permission.clone()))
            .is_some();
        for ((owner, key), role) in &mut rows.roles {
            if *owner == tenant
                && &key.namespace == namespace
                && role.contents().permissions.contains(permission)
            {
                let mut contents = role.contents().clone();
                contents.permissions.remove(permission);
                *role = RoleDefinition::restore(
                    key.clone(),
                    contents,
                    role.created_at(),
                    role.updated_at(),
                )?;
            }
        }
        Ok(removed)
    }

    async fn permissions(
        &self,
        uow: &mut dyn UnitOfWork,
        namespace: &Namespace,
    ) -> Result<Vec<PermissionDefinition>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .rows()
            .permissions
            .iter()
            .filter(|((owner, space, _), _)| *owner == tenant && space == namespace)
            .map(|(_, permission)| permission.clone())
            .collect())
    }

    async fn put_role(
        &self,
        uow: &mut dyn UnitOfWork,
        role: &RoleDefinition,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.rows();
        let key = role.key();
        let declared = role.contents().permissions.iter().all(|permission| {
            rows.permissions
                .contains_key(&(tenant, key.namespace.clone(), permission.clone()))
        });
        let included = role.contents().includes.iter().all(|included| {
            included == key || rows.roles.contains_key(&(tenant, included.clone()))
        });
        if !declared || !included {
            return Err(missing_reference());
        }
        rows.roles.insert((tenant, key.clone()), role.clone());
        Ok(())
    }

    async fn roles(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<RoleDefinition>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .rows()
            .roles
            .iter()
            .filter(|((owner, _), _)| *owner == tenant)
            .map(|(_, role)| role.clone())
            .collect())
    }

    async fn remove_role(
        &self,
        uow: &mut dyn UnitOfWork,
        key: &RoleKey,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.rows();
        let included = rows.roles.iter().any(|((owner, other), role)| {
            *owner == tenant && other != key && role.contents().includes.contains(key)
        });
        if included {
            return Err(DomainError::conflict(
                "authorization.role_in_use",
                "a role that another role includes cannot be removed",
            ));
        }
        let removed = rows.roles.remove(&(tenant, key.clone())).is_some();
        rows.assignments
            .retain(|(owner, _, role, _), _| !(*owner == tenant && role == key));
        Ok(removed)
    }

    async fn put_assignment(
        &self,
        uow: &mut dyn UnitOfWork,
        assignment: &RoleAssignment,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.rows();
        if !rows
            .roles
            .contains_key(&(tenant, assignment.role().clone()))
        {
            return Err(missing_reference());
        }
        rows.assignments.insert(
            (
                tenant,
                assignment.principal().clone(),
                assignment.role().clone(),
                assignment.scope().clone(),
            ),
            assignment.clone(),
        );
        Ok(())
    }

    async fn remove_assignment(
        &self,
        uow: &mut dyn UnitOfWork,
        principal: &Subject,
        role: &RoleKey,
        scope: &AssignmentScope,
    ) -> Result<bool, DomainError> {
        Ok(self
            .rows()
            .assignments
            .remove(&(
                uow.tenant().tenant_id(),
                principal.clone(),
                role.clone(),
                scope.clone(),
            ))
            .is_some())
    }

    async fn assignments_of(
        &self,
        uow: &mut dyn UnitOfWork,
        principal: &Subject,
    ) -> Result<Vec<RoleAssignment>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .rows()
            .assignments
            .iter()
            .filter(|((owner, held_by, _, _), _)| *owner == tenant && held_by == principal)
            .map(|(_, assignment)| assignment.clone())
            .collect())
    }
}

/// The ports under test.
#[derive(Clone)]
pub struct NativeRolePorts<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The store under test.
    pub roles: &'a dyn NativeRoleStore,
}

impl std::fmt::Debug for NativeRolePorts<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("NativeRolePorts").finish_non_exhaustive()
    }
}

/// Runs `work` in a unit of work of `tenant` and commits it.
async fn in_tenant<T>(
    ports: &NativeRolePorts<'_>,
    tenant: &TenantContext,
    work: impl for<'u> FnOnce(
        &'u dyn NativeRoleStore,
        &'u mut dyn UnitOfWork,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<T, DomainError>> + Send + 'u>,
    >,
) -> Result<T, DomainError> {
    let mut uow = ports.units_of_work.begin(tenant).await.expect("begin");
    let result = work(ports.roles, uow.as_mut()).await;
    if result.is_ok() {
        uow.commit().await.expect("commit");
    }
    result
}

fn contract_key(namespace: &str, name: &str) -> RoleKey {
    RoleKey::new(
        Namespace::parse(namespace).expect("namespace"),
        RoleName::parse(name).expect("name"),
    )
}

fn contract_permission(value: &str) -> PermissionName {
    PermissionName::parse(value).expect("permission")
}

fn contract_role(
    key: RoleKey,
    permissions: &[&str],
    includes: &[RoleKey],
    at: Timestamp,
) -> RoleDefinition {
    RoleDefinition::new(
        key,
        RoleContents {
            description: "a role".to_owned(),
            permissions: permissions.iter().map(|p| contract_permission(p)).collect(),
            includes: includes.iter().cloned().collect(),
        },
        at,
    )
    .expect("role")
}

/// Runs every rule a native role store must obey. Each run uses tenants of
/// its own, so runs can share one database.
///
/// # Panics
///
/// Panics if the implementation breaks a rule.
#[allow(clippy::too_many_lines)]
pub async fn run_native_role_contract(ports: NativeRolePorts<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let elsewhere = TenantContext::assume(TenantId::generate());
    let documents = Namespace::parse("urn:example:documents").expect("namespace");
    let billing = Namespace::parse("https://billing.example.com").expect("namespace");
    // Times with whole microseconds, as storage keeps them.
    let at = Timestamp::UNIX_EPOCH + time::Duration::days(20_000);

    // The revision starts at zero and every raise is one more.
    let revision = in_tenant(&ports, &tenant, |s, u| s.revision(u)).await;
    assert_eq!(revision.ok(), Some(0));
    assert_eq!(
        in_tenant(&ports, &tenant, |s, u| s.raise_revision(u))
            .await
            .ok(),
        Some(1)
    );
    assert_eq!(
        in_tenant(&ports, &tenant, |s, u| s.raise_revision(u))
            .await
            .ok(),
        Some(2)
    );
    assert_eq!(
        in_tenant(&ports, &tenant, |s, u| s.revision(u)).await.ok(),
        Some(2)
    );
    assert_eq!(
        in_tenant(&ports, &elsewhere, |s, u| s.revision(u))
            .await
            .ok(),
        Some(0)
    );

    // Permissions are listed by name, and putting again describes again.
    for (name, description) in [
        ("document:write", "change documents"),
        ("document:read", "see documents"),
    ] {
        let permission =
            PermissionDefinition::new(documents.clone(), contract_permission(name), description)
                .expect("permission");
        in_tenant(&ports, &tenant, |s, u| {
            Box::pin(async move { s.put_permission(u, &permission).await })
        })
        .await
        .expect("put permission");
    }
    let payment =
        PermissionDefinition::new(billing.clone(), contract_permission("invoice:pay"), "")
            .expect("permission");
    in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move { s.put_permission(u, &payment).await })
    })
    .await
    .expect("put permission");
    let described = PermissionDefinition::new(
        documents.clone(),
        contract_permission("document:read"),
        "read documents",
    )
    .expect("permission");
    let again = described.clone();
    in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move { s.put_permission(u, &again).await })
    })
    .await
    .expect("describe again");
    let space = documents.clone();
    let listed = in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move { s.permissions(u, &space).await })
    })
    .await
    .expect("permissions");
    let names: Vec<&str> = listed.iter().map(|p| p.name().as_str()).collect();
    assert_eq!(names, ["document:read", "document:write"]);
    assert_eq!(listed[0], described);
    let space = documents.clone();
    let theirs = in_tenant(&ports, &elsewhere, |s, u| {
        Box::pin(async move { s.permissions(u, &space).await })
    })
    .await
    .expect("permissions");
    assert!(theirs.is_empty());

    // Roles keep what they hold and include, and are listed by namespace and name.
    let viewer = contract_role(
        contract_key("urn:example:documents", "viewer"),
        &["document:read"],
        &[],
        at,
    );
    let editor = contract_role(
        contract_key("urn:example:documents", "editor"),
        &["document:write"],
        &[viewer.key().clone()],
        at,
    );
    let support = contract_role(
        contract_key("https://billing.example.com", "support"),
        &["invoice:pay"],
        &[editor.key().clone()],
        at,
    );
    for role in [viewer.clone(), editor.clone(), support.clone()] {
        in_tenant(&ports, &tenant, |s, u| {
            Box::pin(async move { s.put_role(u, &role).await })
        })
        .await
        .expect("put role");
    }
    let roles = in_tenant(&ports, &tenant, |s, u| s.roles(u))
        .await
        .expect("roles");
    assert_eq!(roles, [support.clone(), editor.clone(), viewer.clone()]);
    assert!(
        in_tenant(&ports, &elsewhere, |s, u| s.roles(u))
            .await
            .expect("roles")
            .is_empty()
    );

    // A role that names a permission or a role that does not exist is refused.
    let undeclared = contract_role(
        contract_key("urn:example:documents", "odd"),
        &["document:delete"],
        &[],
        at,
    );
    assert!(
        in_tenant(&ports, &tenant, |s, u| Box::pin(async move {
            s.put_role(u, &undeclared).await
        }))
        .await
        .is_err()
    );
    let dangling = contract_role(
        contract_key("urn:example:documents", "odd"),
        &[],
        &[contract_key("urn:example:documents", "missing")],
        at,
    );
    assert!(
        in_tenant(&ports, &tenant, |s, u| Box::pin(async move {
            s.put_role(u, &dangling).await
        }))
        .await
        .is_err()
    );
    // Nor in another tenant, where the permissions are not declared.
    let foreign = viewer.clone();
    assert!(
        in_tenant(&ports, &elsewhere, |s, u| Box::pin(async move {
            s.put_role(u, &foreign).await
        }))
        .await
        .is_err()
    );

    // Putting a role again replaces what it holds and includes.
    let later = at + time::Duration::minutes(5);
    let replaced = editor
        .replaced(
            RoleContents {
                description: "edits".to_owned(),
                permissions: [
                    contract_permission("document:read"),
                    contract_permission("document:write"),
                ]
                .into(),
                includes: std::collections::BTreeSet::new(),
            },
            later,
        )
        .expect("replaced");
    let put = replaced.clone();
    in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move { s.put_role(u, &put).await })
    })
    .await
    .expect("replace role");
    let roles = in_tenant(&ports, &tenant, |s, u| s.roles(u))
        .await
        .expect("roles");
    assert_eq!(roles[1], replaced);
    let back = editor.clone();
    in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move { s.put_role(u, &back).await })
    })
    .await
    .expect("restore role");

    // Removing a permission removes it from every role.
    let space = documents.clone();
    let removed = in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move {
            s.remove_permission(u, &space, &contract_permission("document:read"))
                .await
        })
    })
    .await;
    assert_eq!(removed.ok(), Some(true));
    let space = documents.clone();
    let removed = in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move {
            s.remove_permission(u, &space, &contract_permission("document:read"))
                .await
        })
    })
    .await;
    assert_eq!(removed.ok(), Some(false));
    let roles = in_tenant(&ports, &tenant, |s, u| s.roles(u))
        .await
        .expect("roles");
    assert!(
        roles[2].contents().permissions.is_empty(),
        "the viewer lost its permission"
    );

    // Assignments: by principal, role and scope; putting again replaces the start and end.
    let ana =
        Subject::new(SubjectKind::User, "0190f5b2-6a3e-7c1d-9b2a-1f2e3d4c5b6a").expect("user");
    let billing_client = Subject::new(SubjectKind::Client, "billing-service").expect("client");
    let portal = ApplicationReference::parse("portal").expect("application");
    let whole = RoleAssignment::new(
        ana.clone(),
        editor.key().clone(),
        AssignmentScope::Tenant,
        None,
        None,
        at,
    )
    .expect("assignment");
    let scoped = RoleAssignment::new(
        ana.clone(),
        viewer.key().clone(),
        AssignmentScope::Application(portal.clone()),
        Some(at),
        Some(later),
        at,
    )
    .expect("assignment");
    let for_client = RoleAssignment::new(
        billing_client.clone(),
        support.key().clone(),
        AssignmentScope::Tenant,
        None,
        Some(later),
        at,
    )
    .expect("assignment");
    for assignment in [whole.clone(), scoped.clone(), for_client.clone()] {
        in_tenant(&ports, &tenant, |s, u| {
            Box::pin(async move { s.put_assignment(u, &assignment).await })
        })
        .await
        .expect("put assignment");
    }
    let principal = ana.clone();
    let held = in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move { s.assignments_of(u, &principal).await })
    })
    .await
    .expect("assignments");
    assert_eq!(held, [whole.clone(), scoped.clone()]);
    let ended = RoleAssignment::new(
        ana.clone(),
        editor.key().clone(),
        AssignmentScope::Tenant,
        None,
        Some(later),
        later,
    )
    .expect("assignment");
    let put = ended.clone();
    in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move { s.put_assignment(u, &put).await })
    })
    .await
    .expect("replace assignment");
    let principal = ana.clone();
    let held = in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move { s.assignments_of(u, &principal).await })
    })
    .await
    .expect("assignments");
    assert_eq!(held, [ended, scoped.clone()]);
    let principal = billing_client.clone();
    let held = in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move { s.assignments_of(u, &principal).await })
    })
    .await
    .expect("assignments");
    assert_eq!(held, [for_client]);
    // An assignment of a role that does not exist is refused.
    let nowhere = RoleAssignment::new(
        ana.clone(),
        contract_key("urn:example:documents", "missing"),
        AssignmentScope::Tenant,
        None,
        None,
        at,
    )
    .expect("assignment");
    assert!(
        in_tenant(&ports, &tenant, |s, u| Box::pin(async move {
            s.put_assignment(u, &nowhere).await
        }))
        .await
        .is_err()
    );
    // Another tenant sees none of them.
    let principal = ana.clone();
    let theirs = in_tenant(&ports, &elsewhere, |s, u| {
        Box::pin(async move { s.assignments_of(u, &principal).await })
    })
    .await
    .expect("assignments");
    assert!(theirs.is_empty());

    // Removing an assignment says whether there was one.
    let (principal, role, scope) = (ana.clone(), viewer.key().clone(), scoped.scope().clone());
    let removed = in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move { s.remove_assignment(u, &principal, &role, &scope).await })
    })
    .await;
    assert_eq!(removed.ok(), Some(true));
    let (principal, role, scope) = (ana.clone(), viewer.key().clone(), scoped.scope().clone());
    let removed = in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move { s.remove_assignment(u, &principal, &role, &scope).await })
    })
    .await;
    assert_eq!(removed.ok(), Some(false));

    // A role another role includes cannot be removed; removing a role
    // removes its assignments.
    let key = editor.key().clone();
    let refused = in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move { s.remove_role(u, &key).await })
    })
    .await;
    assert_eq!(
        refused.map_err(|e| e.code().to_owned()),
        Err("authorization.role_in_use".to_owned())
    );
    let key = support.key().clone();
    let removed = in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move { s.remove_role(u, &key).await })
    })
    .await;
    assert_eq!(removed.ok(), Some(true));
    let key = editor.key().clone();
    let removed = in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move { s.remove_role(u, &key).await })
    })
    .await;
    assert_eq!(removed.ok(), Some(true));
    let key = editor.key().clone();
    let removed = in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move { s.remove_role(u, &key).await })
    })
    .await;
    assert_eq!(removed.ok(), Some(false));
    let principal = ana.clone();
    let held = in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move { s.assignments_of(u, &principal).await })
    })
    .await
    .expect("assignments");
    assert!(held.is_empty());
    let principal = billing_client;
    let held = in_tenant(&ports, &tenant, |s, u| {
        Box::pin(async move { s.assignments_of(u, &principal).await })
    })
    .await
    .expect("assignments");
    assert!(held.is_empty());
    let roles = in_tenant(&ports, &tenant, |s, u| s.roles(u))
        .await
        .expect("roles");
    assert_eq!(roles.len(), 1);
    // The built-in roles are not among the stored ones.
    assert!(
        roles
            .iter()
            .all(|role| role.key() != &RoleKey::built_in(Role::TenantAdministrator))
    );
}
