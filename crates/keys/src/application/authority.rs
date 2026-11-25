//! The use cases of a tenant's certificate authority.
//!
//! See `docs/architecture/contexts/keys.md`, "The certificate authority of
//! a tenant".

use crate::application::ports::{AuthorityStore, CertificateWriter, KeyProvider, TrustDomainStore};
use crate::application::trust_domains::{bundle_summary, name_taken};
use crate::domain::authority::{
    AuthorityId, AuthorityKey, AuthorityKind, AuthorityRequest, AuthorityState, BACKDATING,
    CertificateAuthority, IssuedCertificate, hexadecimal,
};
use crate::domain::event::{AuthorityEvent, TrustDomainEvent};
use crate::domain::key::{KeyAlgorithm, KeyVersionId, SignatureEncoding};
use crate::domain::trust_domain::{
    CheckedSource, MAX_TRUST_DOMAINS, TrustBundle, TrustDomain, TrustSource,
};
use hodor_kernel::{
    Caller, Clock, Digest, DomainError, DomainEvent, EventEnvelope, EventMetadata, TenantContext,
    Timestamp, UnitOfWork, UnitOfWorkFactory,
};
use serde::Serialize;
use std::sync::Arc;

/// An authority as an administrator asks for it, before it is checked.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NewAuthority {
    /// `root` or `intermediate`.
    pub kind: String,
    /// The trust domains it signs for.
    pub trust_domains: Vec<String>,
    /// The common name of its certificate.
    pub common_name: Option<String>,
    /// A root's lifetime, in days.
    pub lifetime_days: Option<u32>,
    /// The bound on the intermediates it signs, in days.
    pub intermediate_lifetime_days: Option<u32>,
}

/// The ports the authority works through.
#[derive(Clone)]
pub struct AuthorityPorts {
    /// Starts units of work.
    pub units_of_work: Arc<dyn UnitOfWorkFactory>,
    /// Stores the authority.
    pub store: Arc<dyn AuthorityStore>,
    /// Stores the trust domains it adds.
    pub trust_domains: Arc<dyn TrustDomainStore>,
    /// Makes the authority's key: the provider that makes the keys of
    /// authorities.
    pub maker: Arc<dyn KeyProvider>,
    /// Signs with the authority's key: every provider, each using the keys
    /// it made.
    pub signer: Arc<dyn KeyProvider>,
    /// Writes and reads its certificates.
    pub certificates: Arc<dyn CertificateWriter>,
    /// SHA-256, for events.
    pub digest: Arc<dyn Digest>,
    /// The time.
    pub clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for AuthorityPorts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorityPorts").finish_non_exhaustive()
    }
}

/// The use cases of a tenant's certificate authority. Built only when the
/// installation turns the authority on.
#[derive(Clone)]
pub struct AuthorityService {
    ports: AuthorityPorts,
    for_development: bool,
}

impl std::fmt::Debug for AuthorityService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthorityService")
            .field("for_development", &self.for_development)
            .finish_non_exhaustive()
    }
}

fn not_found() -> DomainError {
    DomainError::not_found(
        "keys.authority_not_found",
        "the tenant has no certificate authority",
    )
}

fn exists() -> DomainError {
    DomainError::conflict(
        "keys.authority_exists",
        "the tenant has a certificate authority already",
    )
}

fn trust_domain_taken(name: &str) -> DomainError {
    DomainError::conflict(
        "keys.authority_trust_domain_taken",
        "the tenant already trusts a trust domain of the authority from another source: remove \
         it first",
    )
    .with_detail(format!("`{name}`"))
}

/// Seconds are what a certificate holds: the times kept are those it says.
fn whole_seconds(at: Timestamp) -> Timestamp {
    at.replace_nanosecond(0).unwrap_or(at)
}

impl AuthorityService {
    /// Wires the use cases to their ports. `for_development` accepts a
    /// provider that does not sign inside itself, and says so of every
    /// authority made.
    #[must_use]
    pub const fn new(ports: AuthorityPorts, for_development: bool) -> Self {
        Self {
            ports,
            for_development,
        }
    }

    /// Whether the installation runs the authority for development.
    #[must_use]
    pub const fn for_development(&self) -> bool {
        self.for_development
    }

    fn record<E: DomainEvent + Serialize>(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        event: &E,
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

    fn sha256(&self, bytes: &[u8]) -> String {
        hexadecimal(&self.ports.digest.sha256(bytes))
    }

    /// Refuses a trust domain the tenant already has from another source.
    async fn check_free(
        &self,
        uow: &mut dyn UnitOfWork,
        authority_names: &[crate::api::TrustDomainName],
    ) -> Result<(), DomainError> {
        for name in authority_names {
            if self
                .ports
                .trust_domains
                .find_by_name(uow, name.as_str())
                .await?
                .is_some()
            {
                return Err(trust_domain_taken(name.as_str()));
            }
        }
        Ok(())
    }

    /// Adds a trust domain of source `authority` for each of the
    /// authority's trust domains, holding its bundle.
    async fn add_trust_domains(
        &self,
        uow: &mut dyn UnitOfWork,
        authority: &CertificateAuthority,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let bundle = authority.bundle()?.ok_or_else(|| {
            DomainError::internal(
                "keys.authority_bundle_missing",
                "an active authority has no bundle",
            )
        })?;
        let store = &self.ports.trust_domains;
        let names = authority.trust_domains();
        let count = store.count(uow).await?;
        if count.saturating_add(u32::try_from(names.len()).unwrap_or(u32::MAX)) > MAX_TRUST_DOMAINS
        {
            return Err(DomainError::conflict(
                "keys.too_many_trust_domains",
                "a tenant has at most 50 trust domains",
            ));
        }
        self.check_free(uow, names).await?;
        let now = self.ports.clock.now();
        for name in names {
            let domain =
                TrustDomain::add(name.as_str(), CheckedSource::Authority(bundle.clone()), now)?;
            store.insert(uow, &domain).await.map_err(|error| {
                if error.code() == name_taken().code() {
                    trust_domain_taken(name.as_str())
                } else {
                    error
                }
            })?;
            self.record(
                uow,
                caller,
                &TrustDomainEvent::Added {
                    trust_domain_id: domain.id(),
                    name: name.to_string(),
                    source: TrustSource::Authority.as_str(),
                    bundle: Some(bundle_summary(self.ports.digest.as_ref(), &bundle)),
                },
            )?;
        }
        Ok(())
    }

    /// Creates the tenant's authority: has its key made, and for a root
    /// signs its certificate and adds its trust domains; for an
    /// intermediate signs its certificate signing request.
    ///
    /// # Errors
    ///
    /// Returns `keys.authority_request_invalid`,
    /// `keys.authority_trust_domain_invalid`, `keys.authority_exists`,
    /// `keys.authority_trust_domain_taken`,
    /// `keys.authority_provider_unsuitable`, and an error if the provider
    /// cannot make the key or sign.
    pub async fn create(
        &self,
        tenant: &TenantContext,
        asked: NewAuthority,
        caller: Caller,
    ) -> Result<CertificateAuthority, DomainError> {
        let request = AuthorityRequest::new(
            &asked.kind,
            &asked.trust_domains,
            asked.common_name.as_deref(),
            asked.lifetime_days,
            asked.intermediate_lifetime_days,
            self.for_development,
        )?;
        if !self.ports.maker.signs_inside() && !self.for_development {
            return Err(DomainError::conflict(
                "keys.authority_provider_unsuitable",
                "a certificate authority needs a key provider that signs inside itself, such as \
                 OpenBao; the local provider is accepted only on an installation set to \
                 `development`",
            ));
        }
        {
            // Said before a key is made.
            let mut uow = self.ports.units_of_work.begin(tenant).await?;
            if self.ports.store.get(uow.as_mut()).await?.is_some() {
                return Err(exists());
            }
            self.check_free(uow.as_mut(), request.trust_domains())
                .await?;
        }

        let id = AuthorityId::generate();
        let key_id = KeyVersionId::generate();
        let maker = &self.ports.maker;
        let generated = maker.generate(tenant, key_id, KeyAlgorithm::Es256).await?;
        let key = AuthorityKey::new(key_id, maker.name_for(KeyAlgorithm::Es256), generated)?;
        let now = whole_seconds(self.ports.clock.now());
        let profile = request.profile();
        let names: Vec<String> = request
            .trust_domains()
            .iter()
            .map(ToString::to_string)
            .collect();
        let certificates = &self.ports.certificates;

        let (authority, signed) = match request.kind() {
            AuthorityKind::Root => {
                let not_before = now - BACKDATING;
                let not_after = now + request.lifetime().unwrap_or_default();
                let tbs = certificates.root_to_be_signed(
                    &profile,
                    &key.public_key,
                    not_before,
                    not_after,
                )?;
                let signature = self
                    .ports
                    .signer
                    .sign(
                        tenant,
                        &key.version(now),
                        &tbs.bytes,
                        SignatureEncoding::Der,
                    )
                    .await?;
                let der = certificates.signed(&tbs.bytes, &signature);
                let certificate = IssuedCertificate {
                    sha256: self.sha256(&der),
                    der,
                    serial_number: tbs.serial_number.clone(),
                    not_before,
                    not_after,
                };
                let signed = AuthorityEvent::Signed {
                    authority_id: id,
                    signed: "certificate",
                    signed_sha256: self.sha256(&tbs.bytes),
                    serial_number: Some(tbs.serial_number),
                    trust_domains: names.clone(),
                };
                (
                    CertificateAuthority::root(id, &request, key, certificate, now),
                    signed,
                )
            }
            AuthorityKind::Intermediate => {
                let info = certificates.request_to_be_signed(&profile, &key.public_key)?;
                let signature = self
                    .ports
                    .signer
                    .sign(tenant, &key.version(now), &info, SignatureEncoding::Der)
                    .await?;
                let request_der = certificates.signed(&info, &signature);
                let signed = AuthorityEvent::Signed {
                    authority_id: id,
                    signed: "certificate_signing_request",
                    signed_sha256: self.sha256(&info),
                    serial_number: None,
                    trust_domains: names.clone(),
                };
                (
                    CertificateAuthority::intermediate(id, &request, key, request_der, now),
                    signed,
                )
            }
        };

        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        self.ports.store.insert(uow.as_mut(), &authority).await?;
        let key = authority.key();
        self.record(
            uow.as_mut(),
            caller,
            &AuthorityEvent::Created {
                authority_id: id,
                kind: request.kind().as_str(),
                trust_domains: names,
                key_id: key.id,
                provider: key.provider.clone(),
                for_development: self.for_development,
            },
        )?;
        self.record(uow.as_mut(), caller, &signed)?;
        if authority.state() == AuthorityState::Active {
            self.activated(uow.as_mut(), &authority, caller).await?;
        }
        uow.commit().await?;
        Ok(authority)
    }

    async fn activated(
        &self,
        uow: &mut dyn UnitOfWork,
        authority: &CertificateAuthority,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let certificate = authority.certificate().ok_or_else(not_found)?;
        self.record(
            uow,
            caller,
            &AuthorityEvent::Activated {
                authority_id: authority.id(),
                serial_number: certificate.serial_number.clone(),
                certificate_sha256: certificate.sha256.clone(),
                not_after: certificate.not_after,
            },
        )?;
        self.add_trust_domains(uow, authority, caller).await
    }

    /// The tenant's authority.
    ///
    /// # Errors
    ///
    /// Returns `keys.authority_not_found`.
    pub async fn get(&self, tenant: &TenantContext) -> Result<CertificateAuthority, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        self.ports
            .store
            .get(uow.as_mut())
            .await?
            .ok_or_else(not_found)
    }

    /// Installs an intermediate's certificate, in PEM, signed by the
    /// tenant's own root, with the certificates above it if given. The
    /// authority becomes active and its trust domains are added.
    ///
    /// # Errors
    ///
    /// Returns `keys.authority_not_found`,
    /// `keys.authority_not_awaiting_certificate`,
    /// `keys.authority_certificate_unsuitable`,
    /// `keys.authority_trust_domain_taken` and `keys.authority_changed`.
    pub async fn install(
        &self,
        tenant: &TenantContext,
        certificate: &str,
        chain: &[String],
        caller: Caller,
    ) -> Result<CertificateAuthority, DomainError> {
        let certificates = &self.ports.certificates;
        let facts = certificates.read(certificate)?;
        let chain = chain
            .iter()
            .map(|pem| certificates.read(pem).map(|read| read.der))
            .collect::<Result<Vec<_>, _>>()?;
        let sha256 = self.sha256(&facts.der);

        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let mut authority = self
            .ports
            .store
            .lock(uow.as_mut())
            .await?
            .ok_or_else(not_found)?;
        authority.install(facts, sha256, chain, self.ports.clock.now())?;
        self.ports.store.update(uow.as_mut(), &authority).await?;
        self.activated(uow.as_mut(), &authority, caller).await?;
        uow.commit().await?;
        Ok(authority)
    }

    /// Removes the tenant's authority, with the trust domains of source
    /// `authority` it added. Its key stays in its provider.
    ///
    /// # Errors
    ///
    /// Returns `keys.authority_not_found`.
    pub async fn remove(&self, tenant: &TenantContext, caller: Caller) -> Result<(), DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        let authority = self
            .ports
            .store
            .lock(uow.as_mut())
            .await?
            .ok_or_else(not_found)?;
        let store = &self.ports.trust_domains;
        for name in authority.trust_domains() {
            let Some(domain) = store.find_by_name(uow.as_mut(), name.as_str()).await? else {
                continue;
            };
            if domain.source() != TrustSource::Authority {
                continue;
            }
            if store.remove(uow.as_mut(), domain.id()).await? {
                self.record(
                    uow.as_mut(),
                    caller,
                    &TrustDomainEvent::Removed {
                        trust_domain_id: domain.id(),
                        name: name.to_string(),
                    },
                )?;
            }
        }
        if !self.ports.store.remove(uow.as_mut()).await? {
            return Err(not_found());
        }
        self.record(
            uow.as_mut(),
            caller,
            &AuthorityEvent::Removed {
                authority_id: authority.id(),
                key_id: authority.key().id,
            },
        )?;
        uow.commit().await
    }

    /// The bundle of the tenant's authority, if it is active.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn bundle(&self, tenant: &TenantContext) -> Result<Option<TrustBundle>, DomainError> {
        let mut uow = self.ports.units_of_work.begin(tenant).await?;
        match self.ports.store.get(uow.as_mut()).await? {
            Some(authority) => authority.bundle(),
            None => Ok(None),
        }
    }
}
