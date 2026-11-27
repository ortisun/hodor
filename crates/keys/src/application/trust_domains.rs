//! The use cases of trust domains: what administrators do, and the
//! worker's refreshing of bundles from their endpoints.
//!
//! See `docs/architecture/contexts/keys.md`, "Trust domains".

use crate::application::ports::{DueRefreshes, IntermediateStore, TrustDomainStore};
use crate::domain::event::{BundleSummary, TrustDomainEvent};
use crate::domain::trust_domain::{
    CheckedSource, FETCH_TIME_LIMIT, FetchOutcome, LEASE_MARGIN, MAX_BUNDLE_BYTES,
    MAX_TRUST_DOMAINS, SvidKind, TrustBundle, TrustDomain, TrustDomainId, TrustSource,
    check_bundle_endpoint, source_invalid,
};
use hodor_kernel::{
    Caller, Clock, Cursor, DestinationCheck, Digest, DomainError, EventEnvelope, EventMetadata,
    HttpClient, HttpRequest, Page, PageRequest, TenantContext, TenantId, UnitOfWork,
    UnitOfWorkFactory,
};
use std::fmt::Write as _;
use std::sync::Arc;

/// A source as an administrator gives it, before it is checked.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TrustSourceRequest {
    /// A bundle, as its JSON text.
    Uploaded {
        /// The bundle document.
        bundle: Vec<u8>,
    },
    /// The address of a SPIFFE bundle endpoint.
    BundleEndpoint {
        /// The address.
        url: String,
    },
    /// Checked by the mesh in front of Hodor.
    Mesh,
}

impl TrustSourceRequest {
    /// Reads a source by its name and what comes with it: `uploaded` with
    /// a bundle, `bundle_endpoint` with an address, `mesh` with neither.
    ///
    /// # Errors
    ///
    /// Returns `keys.trust_domain_source_invalid`.
    pub fn from_parts(
        source: &str,
        bundle: Option<Vec<u8>>,
        url: Option<String>,
    ) -> Result<Self, DomainError> {
        match (source, bundle, url) {
            ("uploaded", Some(bundle), None) => Ok(Self::Uploaded { bundle }),
            ("bundle_endpoint", None, Some(url)) => Ok(Self::BundleEndpoint { url }),
            ("mesh", None, None) => Ok(Self::Mesh),
            _ => Err(source_invalid()),
        }
    }
}

/// The ports trust domains work through.
#[derive(Clone)]
pub struct TrustDomainPorts {
    /// Starts units of work.
    pub units_of_work: Arc<dyn UnitOfWorkFactory>,
    /// Stores trust domains.
    pub store: Arc<dyn TrustDomainStore>,
    /// Whether a bundle endpoint could be called now.
    pub destinations: Arc<dyn DestinationCheck>,
    /// Fetches bundles: the guarded outbound client.
    pub http: Arc<dyn HttpClient>,
    /// SHA-256, to name a bundle in events.
    pub digest: Arc<dyn Digest>,
    /// The time.
    pub clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for TrustDomainPorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustDomainPorts").finish_non_exhaustive()
    }
}

/// The use cases of trust domains.
#[derive(Clone)]
pub struct TrustDomainService {
    ports: TrustDomainPorts,
    intermediates: Option<Arc<dyn IntermediateStore>>,
}

impl std::fmt::Debug for TrustDomainService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TrustDomainService").finish_non_exhaustive()
    }
}

fn not_found() -> DomainError {
    DomainError::not_found(
        "keys.trust_domain_not_found",
        "there is no such trust domain",
    )
}

/// What the destination check said of a bundle endpoint, in this
/// context's words. The message never repeats what the name resolved to.
fn refused_address(error: DomainError) -> DomainError {
    match error.code() {
        "http.url_invalid" => crate::domain::trust_domain::bundle_endpoint_invalid(),
        "http.destination_forbidden" => forbidden(),
        "http.unreachable" => DomainError::invalid(
            "keys.bundle_endpoint_unresolvable",
            "the bundle endpoint's name does not resolve to any address",
        ),
        _ => error,
    }
}

/// What fetching a bundle failed with, in this context's words.
fn refused_fetch(error: DomainError) -> DomainError {
    match error.code() {
        "http.url_invalid" => crate::domain::trust_domain::bundle_endpoint_invalid(),
        "http.destination_forbidden" => forbidden(),
        _ => unreachable_endpoint(),
    }
}

fn forbidden() -> DomainError {
    DomainError::invalid(
        "keys.bundle_endpoint_forbidden",
        "the bundle endpoint leads somewhere Hodor may not call: it must be public",
    )
}

fn unreachable_endpoint() -> DomainError {
    DomainError::invalid(
        "keys.bundle_endpoint_unreachable",
        "the bundle endpoint did not answer a bundle: no answer in 10 seconds, a status other \
         than 2xx, a redirect, or more than 64 kibibytes",
    )
}

fn page_after(page: &PageRequest) -> Result<Option<TrustDomainId>, DomainError> {
    page.cursor()
        .map(|cursor| {
            cursor.as_str().parse().map_err(|_| {
                DomainError::invalid("request.cursor_invalid", "the cursor is not valid")
            })
        })
        .transpose()
}

impl TrustDomainService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub const fn new(ports: TrustDomainPorts) -> Self {
        Self {
            ports,
            intermediates: None,
        }
    }

    /// Reads the withdrawn keys of the intermediates the tenant's
    /// certificate authority signed from `intermediates`. Without it there
    /// are none.
    #[must_use]
    pub fn with_intermediates(mut self, intermediates: Arc<dyn IntermediateStore>) -> Self {
        self.intermediates = Some(intermediates);
        self
    }

    /// The SHA-256 of the subject public key info of every intermediate
    /// of the tenant's authority that was withdrawn and has not expired:
    /// no certificate path in the tenant may go through one.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn withdrawn_keys(&self, tenant: &TenantContext) -> Result<Vec<String>, DomainError> {
        let Some(intermediates) = &self.intermediates else {
            return Ok(Vec::new());
        };
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        intermediates
            .withdrawn_keys(uow.as_mut(), self.ports.clock.now())
            .await
    }

    /// What an event says of a bundle.
    fn summary(&self, bundle: &TrustBundle) -> BundleSummary {
        bundle_summary(self.ports.digest.as_ref(), bundle)
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        event: &TrustDomainEvent,
    ) -> Result<(), DomainError> {
        let metadata = EventMetadata::new(
            uow.tenant().tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.ports.clock.as_ref(),
        );
        uow.record_event(EventEnvelope::new(metadata, event)?);
        Ok(())
    }

    /// Fetches a bundle through the guarded client and reads it.
    async fn fetch(&self, url: &str) -> Result<TrustBundle, DomainError> {
        let request = HttpRequest::get(url)
            .header("accept", "application/json")
            .within(FETCH_TIME_LIMIT);
        let response = self.ports.http.send(request).await.map_err(refused_fetch)?;
        if !response.is_success() || response.body.len() > MAX_BUNDLE_BYTES {
            return Err(unreachable_endpoint());
        }
        TrustBundle::parse(&response.body)
    }

    /// Checks a source: reads a bundle given, or checks a bundle endpoint
    /// and fetches its bundle once.
    async fn check(&self, source: TrustSourceRequest) -> Result<CheckedSource, DomainError> {
        match source {
            TrustSourceRequest::Uploaded { bundle } => {
                Ok(CheckedSource::Uploaded(TrustBundle::parse(&bundle)?))
            }
            TrustSourceRequest::BundleEndpoint { url } => {
                check_bundle_endpoint(&url)?;
                self.ports
                    .destinations
                    .check(&url)
                    .await
                    .map_err(refused_address)?;
                let bundle = self.fetch(&url).await?;
                Ok(CheckedSource::BundleEndpoint { url, bundle })
            }
            TrustSourceRequest::Mesh => Ok(CheckedSource::Mesh),
        }
    }

    /// Adds a trust domain. Its source is checked, and a bundle endpoint
    /// fetched once, before anything is stored.
    ///
    /// # Errors
    ///
    /// Returns `keys.trust_domain_name_invalid`,
    /// `keys.trust_domain_name_taken`, `keys.too_many_trust_domains`,
    /// `keys.trust_bundle_invalid`, or a refusal of the bundle endpoint:
    /// `keys.bundle_endpoint_invalid`, `_forbidden`, `_unresolvable` or
    /// `_unreachable`.
    pub async fn add(
        &self,
        tenant: &TenantContext,
        name: &str,
        source: TrustSourceRequest,
        caller: Caller,
    ) -> Result<TrustDomain, DomainError> {
        // The name is read before anything is fetched.
        crate::domain::trust_domain::TrustDomainName::parse(name)?;
        let checked = self.check(source).await?;
        let domain = TrustDomain::add(name, checked, self.ports.clock.now())?;

        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        if self.ports.store.count(uow.as_mut()).await? >= MAX_TRUST_DOMAINS {
            return Err(DomainError::conflict(
                "keys.too_many_trust_domains",
                "a tenant has at most 50 trust domains",
            ));
        }
        if self
            .ports
            .store
            .find_by_name(uow.as_mut(), name)
            .await?
            .is_some()
        {
            return Err(name_taken());
        }
        self.ports.store.insert(uow.as_mut(), &domain).await?;
        let event = TrustDomainEvent::Added {
            trust_domain_id: domain.id(),
            name: domain.name().to_string(),
            source: domain.source().as_str(),
            bundle: domain.bundle().map(|bundle| self.summary(bundle)),
        };
        self.record(uow.as_mut(), caller, &event)?;
        uow.commit().await?;
        Ok(domain)
    }

    /// Reads a trust domain of the tenant.
    ///
    /// # Errors
    ///
    /// Returns `keys.trust_domain_not_found`.
    pub async fn get(
        &self,
        tenant: &TenantContext,
        id: TrustDomainId,
    ) -> Result<TrustDomain, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        self.ports
            .store
            .get(uow.as_mut(), id)
            .await?
            .ok_or_else(not_found)
    }

    /// The tenant's trust domain of a name, if it has one: what checking a
    /// workload's credential starts from. Another tenant's trust domain of
    /// the same name is never found.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn find_by_name(
        &self,
        tenant: &TenantContext,
        name: &str,
    ) -> Result<Option<TrustDomain>, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        self.ports.store.find_by_name(uow.as_mut(), name).await
    }

    /// The tenant's trust domains, a page at a time, in the order of their
    /// identifiers.
    ///
    /// # Errors
    ///
    /// Returns `request.cursor_invalid` for a cursor this did not give.
    pub async fn list(
        &self,
        tenant: &TenantContext,
        page: &PageRequest,
    ) -> Result<Page<TrustDomain>, DomainError> {
        let after = page_after(page)?;
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let mut found = self
            .ports
            .store
            .list(uow.as_mut(), after, page.limit() + 1)
            .await?;
        let more = found.len() > page.limit() as usize;
        found.truncate(page.limit() as usize);
        let next_cursor = more
            .then(|| found.last().map(|last| Cursor::new(last.id().to_string())))
            .flatten();
        Ok(Page {
            items: found,
            next_cursor,
        })
    }

    /// Gives a trust domain another source, checked as when it is added. A
    /// refusal leaves it as it was.
    ///
    /// # Errors
    ///
    /// Returns `keys.trust_domain_not_found`, `keys.trust_domain_changed`,
    /// or a refusal of the source as [`TrustDomainService::add`] does.
    pub async fn replace(
        &self,
        tenant: &TenantContext,
        id: TrustDomainId,
        source: TrustSourceRequest,
        caller: Caller,
    ) -> Result<TrustDomain, DomainError> {
        // Said at once, before anything is fetched.
        if self.get(tenant, id).await?.source() == TrustSource::Authority {
            return Err(of_authority());
        }
        let checked = self.check(source).await?;

        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        // A worker recording a fetch of the same trust domain waits, and
        // then finds it changed.
        let mut domain = self
            .ports
            .store
            .lock(uow.as_mut(), id)
            .await?
            .ok_or_else(not_found)?;
        domain.replace(checked, self.ports.clock.now());
        self.ports.store.update(uow.as_mut(), &domain).await?;
        let event = TrustDomainEvent::Replaced {
            trust_domain_id: domain.id(),
            name: domain.name().to_string(),
            source: domain.source().as_str(),
            bundle: domain.bundle().map(|bundle| self.summary(bundle)),
        };
        self.record(uow.as_mut(), caller, &event)?;
        uow.commit().await?;
        Ok(domain)
    }

    /// Removes a trust domain with its bundle.
    ///
    /// # Errors
    ///
    /// Returns `keys.trust_domain_not_found`.
    pub async fn remove(
        &self,
        tenant: &TenantContext,
        id: TrustDomainId,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let domain = self
            .ports
            .store
            .lock(uow.as_mut(), id)
            .await?
            .ok_or_else(not_found)?;
        if !self.ports.store.remove(uow.as_mut(), id).await? {
            return Err(not_found());
        }
        self.record(
            uow.as_mut(),
            caller,
            &TrustDomainEvent::Removed {
                trust_domain_id: id,
                name: domain.name().to_string(),
            },
        )?;
        uow.commit().await
    }
}

fn of_authority() -> DomainError {
    DomainError::conflict(
        "keys.trust_domain_of_authority",
        "the tenant's certificate authority added this trust domain: it can be removed, not \
         replaced",
    )
}

/// What an event says of a bundle: its SHA-256 and how many authorities it
/// holds, never its keys.
pub(crate) fn bundle_summary(digest: &dyn Digest, bundle: &TrustBundle) -> BundleSummary {
    let digest = digest.sha256(bundle.document().as_bytes());
    let mut written = String::with_capacity(64);
    for byte in digest {
        let _ = write!(written, "{byte:02x}");
    }
    BundleSummary {
        bundle_sha256: written,
        sequence: bundle.sequence(),
        x509_authorities: bundle.authorities(SvidKind::X509),
        jwt_authorities: bundle.authorities(SvidKind::Jwt),
    }
}

pub(crate) fn name_taken() -> DomainError {
    DomainError::conflict(
        "keys.trust_domain_name_taken",
        "the tenant already has a trust domain of that name",
    )
}

/// A trust domain leased to this worker, to fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshLease {
    /// Its tenant.
    pub tenant: TenantId,
    /// The trust domain.
    pub id: TrustDomainId,
    /// The address to fetch.
    pub url: String,
    /// The version it was leased at; what is fetched is recorded only if it
    /// still has it.
    pub version: u32,
}

/// What one fetch of the worker did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// A new bundle was put in force.
    Changed,
    /// The bundle fetched is the one in force.
    Unchanged,
    /// The fetch failed or its bundle was refused; the bundle in force is
    /// kept.
    Failed,
    /// The trust domain changed or was removed while it was fetched; the
    /// result was dropped.
    Skipped,
}

impl RefreshOutcome {
    /// The name it is counted under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Changed => "changed",
            Self::Unchanged => "unchanged",
            Self::Failed => "failed",
            Self::Skipped => "skipped",
        }
    }
}

/// The worker's refreshing of bundles from their endpoints, on leases.
#[derive(Clone)]
pub struct BundleRefresher {
    service: TrustDomainService,
    due: Arc<dyn DueRefreshes>,
}

impl std::fmt::Debug for BundleRefresher {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BundleRefresher").finish_non_exhaustive()
    }
}

impl BundleRefresher {
    /// How many bundles one worker fetches at once.
    pub const CONCURRENCY: u32 = 8;

    /// Refreshes through the ports of `service`, finding what is due with
    /// `due`.
    #[must_use]
    pub fn new(service: TrustDomainService, due: Arc<dyn DueRefreshes>) -> Self {
        Self { service, due }
    }

    /// Leases up to `limit` trust domains whose bundle is due.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn lease_due(&self, limit: u32) -> Result<Vec<RefreshLease>, DomainError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let ports = &self.service.ports;
        let now = ports.clock.now();
        let lease_length = time::Duration::try_from(FETCH_TIME_LIMIT)
            .unwrap_or(time::Duration::ZERO)
            + LEASE_MARGIN;
        let candidates = self.due.due(now, limit.saturating_mul(4)).await?;
        let mut leases = Vec::new();
        for (tenant_id, id) in candidates {
            if leases.len() >= limit as usize {
                break;
            }
            // The worker's job loader is one of the places allowed to
            // establish a tenant context: the tenant comes from the stored
            // trust domain, not from any request.
            let tenant = TenantContext::assume(tenant_id);
            let mut uow = ports.units_of_work.begin(&tenant).await?;
            let Some(mut domain) = ports.store.take(uow.as_mut(), id).await? else {
                continue;
            };
            let Some(url) = domain.bundle_endpoint_url().map(str::to_owned) else {
                continue;
            };
            if domain.lease(now, now + lease_length).is_err() {
                continue;
            }
            ports.store.update(uow.as_mut(), &domain).await?;
            uow.commit().await?;
            leases.push(RefreshLease {
                tenant: tenant_id,
                id,
                url,
                version: domain.version() + 1,
            });
        }
        Ok(leases)
    }

    /// Fetches a leased trust domain's bundle, outside any transaction, and
    /// records what happened if it is still as it was leased.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn refresh(&self, lease: RefreshLease) -> Result<RefreshOutcome, DomainError> {
        let service = &self.service;
        let ports = &service.ports;
        let fetched = service.fetch(&lease.url).await;

        let tenant = TenantContext::assume(lease.tenant);
        let mut uow = ports.units_of_work.begin(&tenant).await?;
        let Some(mut domain) = ports.store.lock(uow.as_mut(), lease.id).await? else {
            return Ok(RefreshOutcome::Skipped);
        };
        if domain.version() != lease.version {
            return Ok(RefreshOutcome::Skipped);
        }
        let outcome = domain.record_fetch(fetched, ports.clock.now());
        ports.store.update(uow.as_mut(), &domain).await?;
        let name = domain.name().to_string();
        let answer = match outcome {
            FetchOutcome::Changed { previous_sequence } => {
                let bundle = domain
                    .bundle()
                    .map(|bundle| service.summary(bundle))
                    .ok_or_else(|| {
                        DomainError::internal(
                            "keys.trust_bundle_missing",
                            "a fetched bundle was not kept",
                        )
                    })?;
                service.record(
                    uow.as_mut(),
                    Caller::system(),
                    &TrustDomainEvent::BundleRefreshed {
                        trust_domain_id: lease.id,
                        name,
                        bundle,
                        previous_sequence,
                    },
                )?;
                RefreshOutcome::Changed
            }
            FetchOutcome::Unchanged => RefreshOutcome::Unchanged,
            FetchOutcome::Failed { reason, first } => {
                if first {
                    service.record(
                        uow.as_mut(),
                        Caller::system(),
                        &TrustDomainEvent::RefreshFailed {
                            trust_domain_id: lease.id,
                            name,
                            reason,
                        },
                    )?;
                }
                RefreshOutcome::Failed
            }
        };
        uow.commit().await?;
        Ok(answer)
    }
}
