//! `PolicyService`: drafting, checking, testing, simulating, publishing
//! and rolling back a tenant's policy.
//!
//! Specified in `docs/architecture/contexts/authorization.md`, "The policy
//! lifecycle".

use crate::bundle::{Author, BundleFile, BundleSigner, normalize};
use crate::path::decision_package;
use crate::policy::{
    PolicyVersion, Report, Simulation, SimulationId, SimulationState, VersionState, check_inputs,
    compare, hexadecimal, version_digest,
};
use crate::ports::{PolicyChecker, PolicyVersionStore, PublicationStore, SimulationStore};
use crate::service::BundleService;
use hodor_authorization::api::Namespace;
use hodor_kernel::{
    Caller, Clock, Digest, DomainError, DomainEvent, EventEnvelope, EventMetadata, TenantContext,
    Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use serde::Serialize;
use serde_json::Value;
use std::sync::Arc;

/// At most this many versions or simulations are worked on in one pass of
/// a tenant.
const PER_PASS: u32 = 10;

/// An event of the lifecycle. None carries a file, an input or a result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum LifecycleEvent {
    /// A version was drafted.
    Drafted {
        /// Its number.
        version: u64,
        /// Who wrote it: `operator` or `tenant`.
        written_by: &'static str,
        /// The SHA-256 of its files' document, in hexadecimal.
        digest: String,
    },
    /// The worker validated or tested a version.
    Checked {
        /// Its number.
        version: u64,
        /// The state it reached.
        state: &'static str,
    },
    /// A version was published.
    Published {
        /// Its number.
        version: u64,
        /// The revision it was published as.
        revision: u64,
        /// Whether it was a rollback.
        rollback: bool,
    },
}

impl DomainEvent for LifecycleEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Drafted { .. } => "authorization.policy_version_drafted",
            Self::Checked { .. } => "authorization.policy_version_checked",
            Self::Published { .. } => "authorization.policy_version_published",
        }
    }
}

/// A revision published from a version.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Publication {
    /// The revision.
    pub revision: u64,
    /// The version it was built from.
    pub version: u64,
    /// The bundle's entity tag.
    pub entity_tag: String,
    /// Whether it was a rollback.
    pub rollback: bool,
}

/// What one instance that should run a tenant's bundle last reported.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activation {
    /// The instance's name.
    pub instance: String,
    /// Whether it is an instance of the tenant's own.
    pub own: bool,
    /// The revision it runs, if it reported one.
    pub active_revision: Option<String>,
    /// When it last reported, if it did.
    pub reported_at: Option<Timestamp>,
    /// Its last error, if it reported one.
    pub error: Option<String>,
    /// Whether it runs the latest revision.
    pub current: bool,
}

/// The state of a tenant's policy.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyStatus {
    /// The latest revision, when it was published and the version it was
    /// built from, if any.
    pub latest: Option<(u64, Author, Timestamp, Option<u64>)>,
    /// The latest publications as (revision, version), newest first.
    pub publications: Vec<(u64, u64)>,
    /// The instances that should run the latest revision.
    pub instances: Vec<Activation>,
    /// Whether one of them does not run it yet.
    pub pending_activation: bool,
}

/// What a pass of the worker did in one tenant.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct WaitingWork {
    /// Versions validated or tested.
    pub versions: u64,
    /// Simulations done or failed.
    pub simulations: u64,
}

impl WaitingWork {
    /// Whether the pass did as much as it may, so that more may wait.
    #[must_use]
    pub const fn was_full(&self) -> bool {
        self.versions >= PER_PASS as u64 || self.simulations >= PER_PASS as u64
    }
}

fn not_found() -> DomainError {
    DomainError::not_found(
        "authorization.policy_version_not_found",
        "the tenant has no policy version of this number",
    )
}

fn in_wrong_state(wanted: &str, version: &PolicyVersion) -> DomainError {
    DomainError::conflict(
        "authorization.policy_version_state",
        "the version is not in the state this step needs",
    )
    .with_detail(format!(
        "version {} is {}; this step needs it {wanted}",
        version.number,
        version.state.as_str()
    ))
}

/// A tenant's policy versions, their checks, simulations and
/// publications.
#[derive(Clone)]
pub struct PolicyService {
    versions: Arc<dyn PolicyVersionStore>,
    publications: Arc<dyn PublicationStore>,
    simulations: Arc<dyn SimulationStore>,
    bundles: BundleService,
    units: Arc<dyn UnitOfWorkFactory>,
    digest: Arc<dyn Digest>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for PolicyService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PolicyService").finish_non_exhaustive()
    }
}

impl PolicyService {
    /// A service over its stores, publishing through `bundles`, whose
    /// units of work must be `units`.
    #[must_use]
    pub fn new(
        versions: Arc<dyn PolicyVersionStore>,
        publications: Arc<dyn PublicationStore>,
        simulations: Arc<dyn SimulationStore>,
        bundles: BundleService,
        units: Arc<dyn UnitOfWorkFactory>,
        digest: Arc<dyn Digest>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            versions,
            publications,
            simulations,
            bundles,
            units,
            digest,
            clock,
        }
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        event: &LifecycleEvent,
    ) -> Result<(), DomainError> {
        let metadata = EventMetadata::new(
            uow.tenant().tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.clock.as_ref(),
        );
        uow.record_event(EventEnvelope::new(metadata, event)?);
        Ok(())
    }

    /// Checks `files` as a bundle's are and stores them as the tenant's
    /// next version, a draft.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`normalize`], `authorization.policy_version_taken`
    /// when another draft took the number, or an error if storage fails.
    pub async fn draft(
        &self,
        tenant: &TenantContext,
        author: Author,
        files: &[BundleFile],
        caller: Caller,
    ) -> Result<PolicyVersion, DomainError> {
        let files = normalize(tenant.tenant_id(), files)?;
        let mut uow = self.units.begin(tenant).await?;
        let number = self
            .versions
            .latest_number(uow.as_mut())
            .await?
            .map_or(1, |latest| latest + 1);
        let now = self.clock.now();
        let version = PolicyVersion {
            number,
            author,
            digest: version_digest(&files, self.digest.as_ref()),
            files,
            state: VersionState::Draft,
            report: None,
            drafted_at: now,
            changed_at: now,
        };
        self.versions.create(uow.as_mut(), &version).await?;
        self.record(
            uow.as_mut(),
            caller,
            &LifecycleEvent::Drafted {
                version: number,
                written_by: author.as_str(),
                digest: hexadecimal(&version.digest),
            },
        )?;
        uow.commit().await?;
        Ok(version)
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        number: u64,
    ) -> Result<PolicyVersion, DomainError> {
        self.versions.find(uow, number).await?.ok_or_else(not_found)
    }

    /// The version of `number`.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_version_not_found`, or an error if
    /// storage fails.
    pub async fn version(
        &self,
        tenant: &TenantContext,
        number: u64,
    ) -> Result<PolicyVersion, DomainError> {
        let mut uow = self.units.begin(tenant).await?;
        let version = self.find(uow.as_mut(), number).await?;
        uow.commit().await?;
        Ok(version)
    }

    /// The latest `limit` versions, newest first, without their files.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn versions(
        &self,
        tenant: &TenantContext,
        limit: u32,
    ) -> Result<Vec<PolicyVersion>, DomainError> {
        let mut uow = self.units.begin(tenant).await?;
        let versions = self.versions.list(uow.as_mut(), limit).await?;
        uow.commit().await?;
        Ok(versions)
    }

    /// Moves a version from `from` to `to`, asked by `caller`.
    async fn ask(
        &self,
        tenant: &TenantContext,
        number: u64,
        from: VersionState,
        to: VersionState,
    ) -> Result<PolicyVersion, DomainError> {
        let mut uow = self.units.begin(tenant).await?;
        let version = self.find(uow.as_mut(), number).await?;
        if version.state != from {
            return Err(in_wrong_state(from.as_str(), &version));
        }
        let now = self.clock.now();
        if !self
            .versions
            .transition(uow.as_mut(), number, from, to, None, now)
            .await?
        {
            return Err(in_wrong_state(from.as_str(), &version));
        }
        uow.commit().await?;
        Ok(PolicyVersion {
            state: to,
            report: None,
            changed_at: now,
            ..version
        })
    }

    /// Asks the worker to check a draft.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_version_not_found`,
    /// `authorization.policy_version_state` for a version that is not a
    /// draft, or an error if storage fails.
    pub async fn validate(
        &self,
        tenant: &TenantContext,
        number: u64,
    ) -> Result<PolicyVersion, DomainError> {
        self.ask(
            tenant,
            number,
            VersionState::Draft,
            VersionState::Validating,
        )
        .await
    }

    /// Asks the worker to run the tests of a validated version.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_version_not_found`,
    /// `authorization.policy_version_state` for a version that is not
    /// validated, or an error if storage fails.
    pub async fn test(
        &self,
        tenant: &TenantContext,
        number: u64,
    ) -> Result<PolicyVersion, DomainError> {
        self.ask(
            tenant,
            number,
            VersionState::Validated,
            VersionState::Testing,
        )
        .await
    }

    /// Asks the worker to simulate version `number` on the rule
    /// `decision` of `namespace`'s package, for each of `inputs`.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_simulation_inputs_invalid`,
    /// `authorization.policy_version_not_found`,
    /// `authorization.policy_version_state` for a version that is neither
    /// validated nor tested, or an error if storage fails.
    pub async fn simulate(
        &self,
        tenant: &TenantContext,
        number: u64,
        namespace: &Namespace,
        inputs: Vec<Value>,
    ) -> Result<Simulation, DomainError> {
        check_inputs(&inputs)?;
        let mut uow = self.units.begin(tenant).await?;
        let version = self.find(uow.as_mut(), number).await?;
        if !version.state.may_simulate() {
            return Err(in_wrong_state("validated or tested", &version));
        }
        let simulation = Simulation {
            id: SimulationId::generate(),
            version: number,
            namespace: namespace.as_str().to_owned(),
            inputs,
            compared_with: None,
            results: Vec::new(),
            report: None,
            state: SimulationState::Waiting,
            asked_at: self.clock.now(),
            done_at: None,
        };
        self.simulations.create(uow.as_mut(), &simulation).await?;
        uow.commit().await?;
        Ok(simulation)
    }

    /// The simulation of `id`.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_simulation_not_found`, or an error if
    /// storage fails.
    pub async fn simulation(
        &self,
        tenant: &TenantContext,
        id: SimulationId,
    ) -> Result<Simulation, DomainError> {
        let mut uow = self.units.begin(tenant).await?;
        let simulation = self.simulations.find(uow.as_mut(), id).await?;
        uow.commit().await?;
        simulation.ok_or_else(|| {
            DomainError::not_found(
                "authorization.policy_simulation_not_found",
                "the tenant has no simulation of this identifier",
            )
        })
    }

    /// Checks, tests and simulates what waits in `tenant`, with `checker`.
    ///
    /// # Errors
    ///
    /// Returns the checker's error when a run could not start: what it was
    /// working on keeps waiting. Returns an error if storage fails.
    pub async fn run_waiting(
        &self,
        tenant: &TenantContext,
        checker: &dyn PolicyChecker,
    ) -> Result<WaitingWork, DomainError> {
        let mut work = WaitingWork::default();
        let mut uow = self.units.begin(tenant).await?;
        let versions = self.versions.waiting(uow.as_mut(), PER_PASS).await?;
        let simulations = self.simulations.waiting(uow.as_mut(), PER_PASS).await?;
        uow.commit().await?;

        for version in versions {
            let (report, passed_to) = match version.state {
                VersionState::Validating => (
                    checker.check(tenant.tenant_id(), &version.files).await?,
                    VersionState::Validated,
                ),
                VersionState::Testing => (
                    checker.test(tenant.tenant_id(), &version.files).await?,
                    VersionState::Tested,
                ),
                _ => continue,
            };
            let report = report.bounded();
            let to = if report.passed() {
                passed_to
            } else {
                VersionState::Rejected
            };
            let mut uow = self.units.begin(tenant).await?;
            if self
                .versions
                .transition(
                    uow.as_mut(),
                    version.number,
                    version.state,
                    to,
                    Some(&report),
                    self.clock.now(),
                )
                .await?
            {
                self.record(
                    uow.as_mut(),
                    Caller::system(),
                    &LifecycleEvent::Checked {
                        version: version.number,
                        state: to.as_str(),
                    },
                )?;
                work.versions += 1;
            }
            uow.commit().await?;
        }

        for simulation in simulations {
            self.run_simulation(tenant, checker, &simulation).await?;
            work.simulations += 1;
        }
        Ok(work)
    }

    async fn run_simulation(
        &self,
        tenant: &TenantContext,
        checker: &dyn PolicyChecker,
        simulation: &Simulation,
    ) -> Result<(), DomainError> {
        let mut uow = self.units.begin(tenant).await?;
        let candidate = self.versions.find(uow.as_mut(), simulation.version).await?;
        let published = match self.bundles_latest_version(uow.as_mut()).await? {
            Some(number) => self.versions.find(uow.as_mut(), number).await?,
            None => None,
        };
        uow.commit().await?;
        let failed = |report: Report| (SimulationState::Failed, None, Vec::new(), Some(report));
        let outcome = match (candidate, Namespace::parse(&simulation.namespace)) {
            (Some(candidate), Ok(namespace)) => {
                let package = decision_package(tenant, &namespace, self.digest.as_ref());
                match checker
                    .evaluate(
                        tenant.tenant_id(),
                        &candidate.published_files(),
                        &package,
                        &simulation.inputs,
                    )
                    .await?
                {
                    Err(report) => failed(report.bounded()),
                    Ok(answers) => {
                        let (compared_with, published_answers) = match &published {
                            Some(published) => (
                                Some(published.number),
                                checker
                                    .evaluate(
                                        tenant.tenant_id(),
                                        &published.published_files(),
                                        &package,
                                        &simulation.inputs,
                                    )
                                    .await?
                                    .unwrap_or_default(),
                            ),
                            None => (None, Vec::new()),
                        };
                        (
                            SimulationState::Done,
                            compared_with,
                            compare(&answers, &published_answers),
                            None,
                        )
                    }
                }
            }
            _ => failed(Report {
                diagnostics: vec![crate::policy::Diagnostic::general(
                    "policy_simulation_invalid",
                    "the version or the resource server of the simulation is gone",
                )],
                tests: Vec::new(),
            }),
        };
        let (state, compared_with, results, report) = outcome;
        let mut uow = self.units.begin(tenant).await?;
        self.simulations
            .finish(
                uow.as_mut(),
                simulation.id,
                state,
                compared_with,
                &results,
                report.as_ref(),
                self.clock.now(),
            )
            .await?;
        uow.commit().await
    }

    /// The version the tenant's latest bundle was built from, if it was.
    async fn bundles_latest_version(
        &self,
        uow: &mut dyn UnitOfWork,
    ) -> Result<Option<u64>, DomainError> {
        match self.bundles.latest_revision_in(uow).await? {
            Some(revision) => self.publications.version_of(uow, revision).await,
            None => Ok(None),
        }
    }

    async fn publish_version(
        &self,
        tenant: &TenantContext,
        number: u64,
        signer: &dyn BundleSigner,
        caller: Caller,
        rollback: bool,
    ) -> Result<Publication, DomainError> {
        let mut uow = self.units.begin(tenant).await?;
        let version = self.find(uow.as_mut(), number).await?;
        if version.state != VersionState::Tested {
            return Err(in_wrong_state("tested", &version));
        }
        let bundle = self
            .bundles
            .publish_in(
                uow.as_mut(),
                version.author,
                &version.published_files(),
                signer,
                caller,
            )
            .await?;
        self.publications
            .record(uow.as_mut(), bundle.revision, number)
            .await?;
        self.record(
            uow.as_mut(),
            caller,
            &LifecycleEvent::Published {
                version: number,
                revision: bundle.revision,
                rollback,
            },
        )?;
        uow.commit().await?;
        Ok(Publication {
            revision: bundle.revision,
            version: number,
            entity_tag: bundle.entity_tag(),
            rollback,
        })
    }

    /// Publishes a tested version as the tenant's next revision.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_version_not_found`,
    /// `authorization.policy_version_state` for a version that is not
    /// tested, the errors of publishing a bundle, or an error if storage
    /// fails.
    pub async fn publish(
        &self,
        tenant: &TenantContext,
        number: u64,
        signer: &dyn BundleSigner,
        caller: Caller,
    ) -> Result<Publication, DomainError> {
        self.publish_version(tenant, number, signer, caller, false)
            .await
    }

    /// Publishes the version `revision` was built from as the tenant's
    /// next revision.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_revision_without_version` for a
    /// revision that does not exist or was not built from a version, the
    /// errors of [`Self::publish`], or an error if storage fails.
    pub async fn roll_back(
        &self,
        tenant: &TenantContext,
        revision: u64,
        signer: &dyn BundleSigner,
        caller: Caller,
    ) -> Result<Publication, DomainError> {
        let mut uow = self.units.begin(tenant).await?;
        let version = self.publications.version_of(uow.as_mut(), revision).await?;
        uow.commit().await?;
        let version = version.ok_or_else(|| {
            DomainError::not_found(
                "authorization.policy_revision_without_version",
                "the revision does not exist or was not built from a policy version",
            )
        })?;
        self.publish_version(tenant, version, signer, caller, true)
            .await
    }

    /// The latest revisions, what each instance that should run them runs,
    /// and whether activation is pending.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn status(&self, tenant: &TenantContext) -> Result<PolicyStatus, DomainError> {
        let mut uow = self.units.begin(tenant).await?;
        let publications = self.publications.list(uow.as_mut(), 20).await?;
        uow.commit().await?;
        let Some(latest) = self.bundles.latest(tenant).await? else {
            return Ok(PolicyStatus {
                latest: None,
                publications,
                instances: Vec::new(),
                pending_activation: false,
            });
        };
        let version = publications
            .iter()
            .find(|(revision, _)| *revision == latest.revision)
            .map(|(_, version)| *version);
        let wanted = latest.revision.to_string();
        let instances: Vec<Activation> = self
            .bundles
            .expected_instances(tenant, latest.author)
            .await?
            .into_iter()
            .map(|(instance, status)| {
                let active_revision = status.as_ref().and_then(|s| s.active_revision.clone());
                Activation {
                    instance: instance.name().as_str().to_owned(),
                    own: instance.tenant().is_some(),
                    current: active_revision.as_deref() == Some(wanted.as_str()),
                    active_revision,
                    reported_at: status.as_ref().map(|s| s.reported_at),
                    error: status.and_then(|s| s.error),
                }
            })
            .collect();
        let pending_activation = instances.iter().any(|i| !i.current);
        Ok(PolicyStatus {
            latest: Some((latest.revision, latest.author, latest.published_at, version)),
            publications,
            instances,
            pending_activation,
        })
    }
}
