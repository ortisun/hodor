//! `BundleService`: registering instances, publishing bundles, and what
//! instances pull and report.

use crate::archive::gunzip;
use crate::bundle::{Author, BundleFile, BundleSigner, PublishedBundle, build, tenant_of};
use crate::instance::{Instance, InstanceName, credential_digest, new_credential};
use crate::ports::{
    BundleStore, InstanceStatus, InstanceStatusStore, InstanceStore, UploadedDecision,
    UploadedDecisionStore,
};
use crate::reports::{read_decisions, read_status};
use hodor_kernel::{
    Caller, Clock, Digest, DomainError, DomainEvent, ErrorKind, EventEnvelope, EventMetadata,
    RandomSource, Secret, TenantContext, TenantId, UnitOfWorkFactory,
};
use serde::Serialize;
use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::sync::Arc;

/// At most this many bytes of an upload of decisions once expanded.
pub const MAX_EXPANDED_UPLOAD_BYTES: usize = 8 * 1024 * 1024;

/// An event of the bundles.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum BundleEvent {
    /// A bundle was published.
    Published {
        /// Its revision.
        revision: u64,
        /// Who wrote it: `operator` or `tenant`.
        written_by: &'static str,
        /// The SHA-256 of the archive, in hexadecimal.
        digest: String,
    },
}

impl DomainEvent for BundleEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Published { .. } => "authorization.policy_bundle_published",
        }
    }
}

/// What a pull of a bundle is answered with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pull {
    /// Nothing the instance may pull: no bundle, or not one of its own.
    NotFound,
    /// The instance has the latest revision already.
    NotModified {
        /// The bundle's entity tag.
        entity_tag: String,
    },
    /// The latest revision.
    Bundle {
        /// The bundle's entity tag.
        entity_tag: String,
        /// The archive.
        archive: Vec<u8>,
    },
}

/// The instances, their bundles and their reports.
#[derive(Clone)]
pub struct BundleService {
    instances: Arc<dyn InstanceStore>,
    bundles: Arc<dyn BundleStore>,
    statuses: Arc<dyn InstanceStatusStore>,
    decisions: Arc<dyn UploadedDecisionStore>,
    units: Arc<dyn UnitOfWorkFactory>,
    digest: Arc<dyn Digest>,
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for BundleService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleService").finish_non_exhaustive()
    }
}

fn unauthenticated() -> DomainError {
    DomainError::new(
        ErrorKind::Unauthenticated,
        "authorization.policy_agent_unauthenticated",
        "the instance's credential is missing, unknown or disabled",
    )
}

impl BundleService {
    /// A service over its stores.
    #[allow(clippy::too_many_arguments)]
    #[must_use]
    pub fn new(
        instances: Arc<dyn InstanceStore>,
        bundles: Arc<dyn BundleStore>,
        statuses: Arc<dyn InstanceStatusStore>,
        decisions: Arc<dyn UploadedDecisionStore>,
        units: Arc<dyn UnitOfWorkFactory>,
        digest: Arc<dyn Digest>,
        random: Arc<dyn RandomSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            instances,
            bundles,
            statuses,
            decisions,
            units,
            digest,
            random,
            clock,
        }
    }

    /// Registers an instance, shared without a tenant or of `tenant`'s
    /// own, and returns it with its credential, which is shown once.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_agent_instance_name_invalid` or
    /// `authorization.policy_agent_instance_exists`, or an error if
    /// storage fails.
    pub async fn register(
        &self,
        name: &str,
        tenant: Option<TenantId>,
    ) -> Result<(Instance, Secret<String>), DomainError> {
        let instance = Instance::new(InstanceName::parse(name)?, tenant, self.clock.now());
        let credential = new_credential(self.random.as_ref());
        let digest =
            credential_digest(credential.expose(), self.digest.as_ref()).ok_or_else(|| {
                DomainError::internal(
                    "authorization.policy_agent_credential",
                    "the operation could not be completed",
                )
            })?;
        self.instances.add(&instance, digest).await?;
        Ok((instance, credential))
    }

    /// Disables an instance. Returns whether it was enabled.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_agent_instance_name_invalid`, or an
    /// error if storage fails.
    pub async fn disable(&self, name: &str) -> Result<bool, DomainError> {
        self.instances
            .disable(&InstanceName::parse(name)?, self.clock.now())
            .await
    }

    /// Every instance, by name.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn instances(&self) -> Result<Vec<Instance>, DomainError> {
        self.instances.list().await
    }

    /// Checks `files`, builds and signs `tenant`'s next bundle, and stores
    /// it.
    ///
    /// # Errors
    ///
    /// Returns the errors of [`build`], `authorization.bundle_revision_taken`
    /// when another publication won the same revision, or an error if
    /// storage fails.
    pub async fn publish(
        &self,
        tenant: &TenantContext,
        author: Author,
        files: &[BundleFile],
        signer: &dyn BundleSigner,
        caller: Caller,
    ) -> Result<PublishedBundle, DomainError> {
        let mut uow = self.units.begin(tenant).await?;
        let revision = self
            .bundles
            .latest(uow.as_mut())
            .await?
            .map_or(1, |latest| latest.revision + 1);
        let archive = build(
            tenant.tenant_id(),
            revision,
            files,
            signer,
            self.digest.as_ref(),
        )?;
        let bundle = PublishedBundle {
            revision,
            author,
            digest: self.digest.sha256(&archive),
            archive,
            published_at: self.clock.now(),
        };
        self.bundles.append(uow.as_mut(), &bundle).await?;
        let mut digest = String::with_capacity(64);
        for byte in bundle.digest {
            // Writing to a `String` cannot fail.
            let _ = write!(digest, "{byte:02x}");
        }
        let event = BundleEvent::Published {
            revision,
            written_by: author.as_str(),
            digest,
        };
        let metadata = EventMetadata::new(
            tenant.tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.clock.as_ref(),
        );
        uow.record_event(EventEnvelope::new(metadata, &event)?);
        uow.commit().await?;
        Ok(bundle)
    }

    /// The enabled instance a credential belongs to.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_agent_unauthenticated` for a missing,
    /// unknown or disabled credential, or an error if storage fails.
    pub async fn authenticate(&self, credential: Option<&str>) -> Result<Instance, DomainError> {
        let digest = credential
            .and_then(|credential| credential_digest(credential, self.digest.as_ref()))
            .ok_or_else(unauthenticated)?;
        match self.instances.find_by_credential(digest).await? {
            Some(instance) if instance.disabled_at().is_none() => Ok(instance),
            _ => Err(unauthenticated()),
        }
    }

    /// What `instance` gets when it pulls the bundle `name`, given the
    /// entity tag it has.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn pull(
        &self,
        instance: &Instance,
        name: &str,
        if_none_match: Option<&str>,
    ) -> Result<Pull, DomainError> {
        let Some(tenant) = tenant_of(name) else {
            return Ok(Pull::NotFound);
        };
        if !instance.serves(tenant) {
            return Ok(Pull::NotFound);
        }
        let mut uow = self.units.begin(&TenantContext::assume(tenant)).await?;
        let latest = self.bundles.latest(uow.as_mut()).await?;
        uow.commit().await?;
        let Some(bundle) = latest.filter(|bundle| instance.may_pull(tenant, bundle.author)) else {
            return Ok(Pull::NotFound);
        };
        let entity_tag = bundle.entity_tag();
        let held = if_none_match.is_some_and(|given| {
            given
                .split(',')
                .any(|tag| tag.trim().trim_start_matches("W/") == entity_tag)
        });
        if held {
            Ok(Pull::NotModified { entity_tag })
        } else {
            Ok(Pull::Bundle {
                entity_tag,
                archive: bundle.archive,
            })
        }
    }

    /// Keeps what `instance` reports about the bundles of tenants it
    /// serves, from a body that is gzip-compressed when `compressed`.
    /// Returns how many tenants' statuses were kept.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_agent_report_invalid` for a report
    /// that is not one, or an error if storage fails.
    pub async fn report_status(
        &self,
        instance: &Instance,
        body: &[u8],
        compressed: bool,
    ) -> Result<usize, DomainError> {
        let reported = if compressed {
            read_status(&gunzip(body, MAX_EXPANDED_UPLOAD_BYTES)?)?
        } else {
            read_status(body)?
        };
        let now = self.clock.now();
        let mut kept = 0;
        for (tenant, bundle) in reported {
            if !instance.serves(tenant) {
                continue;
            }
            let status = InstanceStatus {
                instance: instance.id(),
                active_revision: bundle.active_revision,
                last_activation: bundle.last_activation,
                error: bundle.error,
                reported_at: now,
            };
            let mut uow = self.units.begin(&TenantContext::assume(tenant)).await?;
            self.statuses.record(uow.as_mut(), &status).await?;
            uow.commit().await?;
            kept += 1;
        }
        Ok(kept)
    }

    /// Keeps the decisions `instance` uploaded for the tenants it serves,
    /// from a body that is gzip-compressed when `compressed`, as Open
    /// Policy Agent sends it. Returns how many were new.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_agent_report_invalid` for an upload
    /// that is not one or expands beyond 8 mebibytes, or an error if
    /// storage fails.
    pub async fn upload_decisions(
        &self,
        instance: &Instance,
        body: &[u8],
        compressed: bool,
    ) -> Result<u64, DomainError> {
        let expanded;
        let body = if compressed {
            expanded = gunzip(body, MAX_EXPANDED_UPLOAD_BYTES)?;
            expanded.as_slice()
        } else {
            body
        };
        let now = self.clock.now();
        let mut by_tenant: BTreeMap<TenantId, Vec<UploadedDecision>> = BTreeMap::new();
        for decision in read_decisions(body)? {
            if !instance.serves(decision.tenant) {
                continue;
            }
            by_tenant
                .entry(decision.tenant)
                .or_default()
                .push(UploadedDecision {
                    instance: instance.id(),
                    decision_id: decision.decision_id,
                    path: decision.path,
                    revision: decision.revision,
                    allowed: decision.allowed,
                    decided_at: decision.decided_at,
                    received_at: now,
                });
        }
        let mut new = 0;
        for (tenant, decisions) in by_tenant {
            let mut uow = self.units.begin(&TenantContext::assume(tenant)).await?;
            new += self.decisions.record(uow.as_mut(), &decisions).await?;
            uow.commit().await?;
        }
        Ok(new)
    }

    /// The last status every instance reported for `tenant`.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn statuses(
        &self,
        tenant: &TenantContext,
    ) -> Result<Vec<InstanceStatus>, DomainError> {
        let mut uow = self.units.begin(tenant).await?;
        let statuses = self.statuses.list(uow.as_mut()).await?;
        uow.commit().await?;
        Ok(statuses)
    }

    /// The latest `limit` decisions instances uploaded for `tenant`.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn uploaded_decisions(
        &self,
        tenant: &TenantContext,
        limit: u32,
    ) -> Result<Vec<UploadedDecision>, DomainError> {
        let mut uow = self.units.begin(tenant).await?;
        let decisions = self.decisions.latest(uow.as_mut(), limit).await?;
        uow.commit().await?;
        Ok(decisions)
    }
}
