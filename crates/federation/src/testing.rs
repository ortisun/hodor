//! In-memory stores and the contract every implementation passes.

use crate::api::{
    Alias, ExternalIdentity, IdentityProvider, LinkStore, PendingAuthorization,
    PendingAuthorizationStore, ProviderId, ProviderKind, ProviderSettings, ProviderSnapshot,
    ProviderStatus, ProviderStore, SamlAnswer, Subject,
};
use hodor_authentication::api::TransactionId;
use hodor_kernel::{
    DomainError, SealedSecret, TenantContext, TenantId, Timestamp, UnitOfWork, UnitOfWorkFactory,
    UserId,
};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

type ProviderRows = BTreeMap<(TenantId, ProviderId), ProviderSnapshot>;
type LinkRows = BTreeMap<(TenantId, ProviderId, Subject), ExternalIdentity>;
type PendingRows = BTreeMap<(TenantId, TransactionId), PendingAuthorization>;

/// Providers and links kept in memory. One value serves as both stores,
/// since a link must name a provider that exists.
#[derive(Debug, Clone, Default)]
pub struct InMemoryFederation {
    providers: Arc<Mutex<ProviderRows>>,
    links: Arc<Mutex<LinkRows>>,
    pending: Arc<Mutex<PendingRows>>,
}

impl InMemoryFederation {
    fn pending(&self) -> std::sync::MutexGuard<'_, PendingRows> {
        self.pending.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn providers(&self) -> std::sync::MutexGuard<'_, ProviderRows> {
        self.providers.lock().unwrap_or_else(|e| e.into_inner())
    }

    fn links(&self) -> std::sync::MutexGuard<'_, LinkRows> {
        self.links.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Every pending authorization stored, of every tenant, for a test to
    /// look at what is kept.
    #[must_use]
    pub fn pending_authorizations(&self) -> Vec<PendingAuthorization> {
        self.pending().values().cloned().collect()
    }
}

fn modified_concurrently() -> DomainError {
    DomainError::conflict(
        "federation.provider_modified_concurrently",
        "the identity provider was changed by someone else; read it again",
    )
}

#[async_trait::async_trait]
impl ProviderStore for InMemoryFederation {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        provider: &IdentityProvider,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.providers();
        if rows
            .iter()
            .any(|((owner, _), row)| *owner == tenant && row.alias == *provider.alias())
        {
            return Err(DomainError::conflict(
                "federation.alias_taken",
                "this tenant already has an identity provider with this alias",
            ));
        }
        rows.insert((tenant, provider.id()), provider.snapshot().clone());
        Ok(())
    }

    async fn update(
        &self,
        uow: &mut dyn UnitOfWork,
        provider: &IdentityProvider,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut rows = self.providers();
        let stored = rows
            .get_mut(&(tenant, provider.id()))
            .filter(|stored| stored.version == provider.snapshot().version)
            .ok_or_else(modified_concurrently)?;
        *stored = ProviderSnapshot {
            version: stored.version + 1,
            ..provider.snapshot().clone()
        };
        Ok(())
    }

    async fn get(
        &self,
        uow: &mut dyn UnitOfWork,
        id: ProviderId,
    ) -> Result<Option<IdentityProvider>, DomainError> {
        Ok(self
            .providers()
            .get(&(uow.tenant().tenant_id(), id))
            .cloned()
            .map(IdentityProvider::from_snapshot))
    }

    async fn find_by_alias(
        &self,
        uow: &mut dyn UnitOfWork,
        alias: &Alias,
    ) -> Result<Option<IdentityProvider>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .providers()
            .iter()
            .find(|((owner, _), row)| *owner == tenant && row.alias == *alias)
            .map(|(_, row)| IdentityProvider::from_snapshot(row.clone())))
    }

    async fn list(&self, uow: &mut dyn UnitOfWork) -> Result<Vec<IdentityProvider>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut found: Vec<IdentityProvider> = self
            .providers()
            .iter()
            .filter(|((owner, _), _)| *owner == tenant)
            .map(|(_, row)| IdentityProvider::from_snapshot(row.clone()))
            .collect();
        found.sort_by(|a, b| a.alias().cmp(b.alias()));
        Ok(found)
    }
}

#[async_trait::async_trait]
impl LinkStore for InMemoryFederation {
    async fn insert(
        &self,
        uow: &mut dyn UnitOfWork,
        link: &ExternalIdentity,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        if !self.providers().contains_key(&(tenant, link.provider_id)) {
            return Err(DomainError::not_found(
                "federation.provider_not_found",
                "there is no such identity provider",
            ));
        }
        let key = (tenant, link.provider_id, link.subject.clone());
        let mut rows = self.links();
        if rows.contains_key(&key) {
            return Ok(false);
        }
        rows.insert(key, link.clone());
        Ok(true)
    }

    async fn find(
        &self,
        uow: &mut dyn UnitOfWork,
        provider_id: ProviderId,
        subject: &Subject,
    ) -> Result<Option<ExternalIdentity>, DomainError> {
        Ok(self
            .links()
            .get(&(uow.tenant().tenant_id(), provider_id, subject.clone()))
            .cloned())
    }

    async fn mark_used(
        &self,
        uow: &mut dyn UnitOfWork,
        provider_id: ProviderId,
        subject: &Subject,
        now: Timestamp,
    ) -> Result<bool, DomainError> {
        Ok(self
            .links()
            .get_mut(&(uow.tenant().tenant_id(), provider_id, subject.clone()))
            .map(|link| link.last_used_at = now)
            .is_some())
    }

    async fn list_for_user(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
    ) -> Result<Vec<ExternalIdentity>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut found: Vec<ExternalIdentity> = self
            .links()
            .iter()
            .filter(|((owner, _, _), link)| *owner == tenant && link.user_id == user_id)
            .map(|(_, link)| link.clone())
            .collect();
        found.sort_by(|a, b| {
            (a.linked_at, a.provider_id, &a.subject).cmp(&(b.linked_at, b.provider_id, &b.subject))
        });
        Ok(found)
    }

    async fn remove(
        &self,
        uow: &mut dyn UnitOfWork,
        provider_id: ProviderId,
        subject: &Subject,
    ) -> Result<Option<UserId>, DomainError> {
        Ok(self
            .links()
            .remove(&(uow.tenant().tenant_id(), provider_id, subject.clone()))
            .map(|link| link.user_id))
    }
}

#[async_trait::async_trait]
impl PendingAuthorizationStore for InMemoryFederation {
    async fn put(
        &self,
        uow: &mut dyn UnitOfWork,
        pending: &PendingAuthorization,
    ) -> Result<(), DomainError> {
        let tenant = uow.tenant().tenant_id();
        if !self
            .providers()
            .contains_key(&(tenant, pending.provider_id))
        {
            return Err(DomainError::not_found(
                "federation.provider_not_found",
                "there is no such identity provider",
            ));
        }
        self.pending()
            .insert((tenant, pending.transaction_id), pending.clone());
        Ok(())
    }

    async fn take(
        &self,
        uow: &mut dyn UnitOfWork,
        transaction_id: TransactionId,
    ) -> Result<Option<PendingAuthorization>, DomainError> {
        Ok(self
            .pending()
            .remove(&(uow.tenant().tenant_id(), transaction_id)))
    }

    async fn unanswered(
        &self,
        uow: &mut dyn UnitOfWork,
        provider_id: ProviderId,
        state_hash: [u8; 32],
        now: Timestamp,
    ) -> Result<Option<PendingAuthorization>, DomainError> {
        let tenant = uow.tenant().tenant_id();
        Ok(self
            .pending()
            .iter()
            .find(|((owner, _), pending)| {
                waiting(*owner, pending, tenant, provider_id, state_hash, now)
            })
            .map(|(_, pending)| pending.clone()))
    }

    async fn answer(
        &self,
        uow: &mut dyn UnitOfWork,
        provider_id: ProviderId,
        state_hash: [u8; 32],
        answer: &SamlAnswer,
        receipt_hash: [u8; 32],
        now: Timestamp,
    ) -> Result<bool, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut pending = self.pending();
        let found = pending.iter_mut().find(|((owner, _), pending)| {
            waiting(*owner, pending, tenant, provider_id, state_hash, now)
        });
        Ok(found.is_some_and(|(_, pending)| {
            pending.saml_answer = Some(answer.clone());
            pending.saml_receipt_hash = Some(receipt_hash);
            true
        }))
    }

    async fn remove_expired(
        &self,
        uow: &mut dyn UnitOfWork,
        now: Timestamp,
        limit: u32,
    ) -> Result<u64, DomainError> {
        let tenant = uow.tenant().tenant_id();
        let mut pending = self.pending();
        let expired: Vec<_> = pending
            .iter()
            .filter(|((owner, _), pending)| *owner == tenant && pending.expires_at <= now)
            .map(|(key, _)| *key)
            .take(usize::try_from(limit).unwrap_or(usize::MAX))
            .collect();
        for key in &expired {
            pending.remove(key);
        }
        Ok(expired.len() as u64)
    }
}

/// Whether a pending authorization is the one of this tenant, provider and
/// state, has not expired and has no answer yet.
fn waiting(
    owner: TenantId,
    pending: &PendingAuthorization,
    tenant: TenantId,
    provider_id: ProviderId,
    state_hash: [u8; 32],
    now: Timestamp,
) -> bool {
    owner == tenant
        && pending.provider_id == provider_id
        && pending.state_hash == state_hash
        && pending.expires_at > now
        && pending.saml_answer.is_none()
}

/// The ports under test.
#[derive(Clone)]
pub struct Ports<'a> {
    /// Starts units of work.
    pub units_of_work: &'a dyn UnitOfWorkFactory,
    /// The provider store under test.
    pub providers: &'a dyn ProviderStore,
    /// The link store under test.
    pub links: &'a dyn LinkStore,
    /// The pending authorization store under test.
    pub pending: &'a dyn PendingAuthorizationStore,
}

impl std::fmt::Debug for Ports<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Ports").finish_non_exhaustive()
    }
}

fn provider(alias: &str, issuer: &str) -> IdentityProvider {
    IdentityProvider::create(
        Alias::parse(alias).expect("alias"),
        ProviderKind::OpenIdConnect,
        ProviderSettings {
            display_name: format!("Provider {alias}"),
            issuer: issuer.to_owned(),
            client_id: "hodor".to_owned(),
            scopes: vec!["openid".to_owned(), "email".to_owned()],
            creates_users: true,
            trusts_email: false,
            directory: None,
            saml: None,
        },
        SealedSecret::from_stored(vec![0, 159, 146, 150, 255]),
        &[],
        Timestamp::UNIX_EPOCH,
    )
    .expect("provider")
}

fn link(
    provider: &IdentityProvider,
    subject: &str,
    user: UserId,
    at: Timestamp,
) -> ExternalIdentity {
    ExternalIdentity {
        provider_id: provider.id(),
        subject: Subject::parse(subject).expect("subject"),
        user_id: user,
        linked_at: at,
        last_used_at: at,
    }
}

macro_rules! within {
    ($ports:expr, $tenant:expr, |$uow:ident| $body:expr) => {{
        let mut unit = $ports.units_of_work.begin($tenant).await.expect("begin");
        let $uow: &mut dyn UnitOfWork = unit.as_mut();
        let result = $body;
        unit.commit().await.expect("commit");
        result
    }};
}

/// Runs every rule the two stores must obey. Each run uses tenants of
/// its own, so runs can share one database.
///
/// # Panics
///
/// Panics if an implementation breaks a rule.
#[allow(clippy::too_many_lines, reason = "one story, told in order")]
pub async fn run_contract(ports: Ports<'_>) {
    let tenant = TenantContext::assume(TenantId::generate());
    let elsewhere = TenantContext::assume(TenantId::generate());
    let later = Timestamp::UNIX_EPOCH + std::time::Duration::from_secs(60);

    // A tenant has no providers to begin with.
    assert!(
        within!(ports, &tenant, |uow| ports
            .providers
            .list(uow)
            .await
            .expect("list"))
        .is_empty()
    );

    // A provider comes back exactly as it was stored, by identifier and by alias.
    let google = provider("google", "https://accounts.google.example");
    let entra = provider("entra", "https://login.entra.example/tenant/v2.0");
    within!(ports, &tenant, |uow| {
        ports.providers.insert(uow, &google).await.expect("insert");
        ports.providers.insert(uow, &entra).await.expect("insert");
    });
    let read = within!(ports, &tenant, |uow| ports
        .providers
        .get(uow, google.id())
        .await
        .expect("get"))
    .expect("stored");
    assert_eq!(read, google);
    let by_alias = within!(ports, &tenant, |uow| ports
        .providers
        .find_by_alias(uow, google.alias())
        .await
        .expect("find"))
    .expect("stored");
    assert_eq!(by_alias, google);
    let listed = within!(ports, &tenant, |uow| ports
        .providers
        .list(uow)
        .await
        .expect("list"));
    assert_eq!(
        listed
            .iter()
            .map(|p| p.alias().as_str())
            .collect::<Vec<_>>(),
        ["entra", "google"],
        "ordered by alias"
    );

    // An alias is unique in a tenant.
    let impostor = provider("google", "https://evil.example");
    let mut unit = ports.units_of_work.begin(&tenant).await.expect("begin");
    let error = ports
        .providers
        .insert(unit.as_mut(), &impostor)
        .await
        .expect_err("alias taken");
    assert_eq!(error.code(), "federation.alias_taken");
    drop(unit);

    // Another tenant sees none of it, and may use the same alias.
    assert!(
        within!(ports, &elsewhere, |uow| ports
            .providers
            .list(uow)
            .await
            .expect("list"))
        .is_empty()
    );
    assert!(
        within!(ports, &elsewhere, |uow| ports
            .providers
            .get(uow, google.id())
            .await
            .expect("get"))
        .is_none()
    );
    assert!(
        within!(ports, &elsewhere, |uow| ports
            .providers
            .find_by_alias(uow, google.alias())
            .await
            .expect("find"))
        .is_none()
    );
    let their_google = provider("google", "https://accounts.google.example");
    within!(ports, &elsewhere, |uow| ports
        .providers
        .insert(uow, &their_google)
        .await
        .expect("the same alias in another tenant"));

    // A change is stored, and the stored version moves on.
    let mut changed = read.clone();
    assert!(changed.set_status(ProviderStatus::Disabled, later));
    changed.change_secret(SealedSecret::from_stored(vec![9, 9, 9]), later);
    within!(ports, &tenant, |uow| ports
        .providers
        .update(uow, &changed)
        .await
        .expect("update"));
    let after = within!(ports, &tenant, |uow| ports
        .providers
        .get(uow, google.id())
        .await
        .expect("get"))
    .expect("stored");
    assert_eq!(after.snapshot().status, ProviderStatus::Disabled);
    assert_eq!(after.snapshot().client_secret.as_bytes(), [9, 9, 9]);
    assert_eq!(after.snapshot().updated_at, later);
    assert_eq!(after.snapshot().version, 1);

    // A change based on what was read before that one is refused.
    let mut stale = read;
    assert!(stale.set_status(ProviderStatus::Disabled, later));
    let mut unit = ports.units_of_work.begin(&tenant).await.expect("begin");
    let error = ports
        .providers
        .update(unit.as_mut(), &stale)
        .await
        .expect_err("stale");
    assert_eq!(error.code(), "federation.provider_modified_concurrently");
    drop(unit);
    // And one tenant cannot change another's provider.
    let mut unit = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    let error = ports
        .providers
        .update(unit.as_mut(), &after)
        .await
        .expect_err("another tenant's provider");
    assert_eq!(error.code(), "federation.provider_modified_concurrently");
    drop(unit);

    // Links: an external identity belongs to at most one user.
    let (ana, bia) = (UserId::generate(), UserId::generate());
    let first = link(&google, "subject-1", ana, Timestamp::UNIX_EPOCH);
    assert!(within!(ports, &tenant, |uow| ports
        .links
        .insert(uow, &first)
        .await
        .expect("insert")));
    for user in [ana, bia] {
        let again = link(&google, "subject-1", user, later);
        assert!(
            !within!(ports, &tenant, |uow| ports
                .links
                .insert(uow, &again)
                .await
                .expect("insert")),
            "already linked"
        );
    }
    let found = within!(ports, &tenant, |uow| ports
        .links
        .find(uow, google.id(), &first.subject)
        .await
        .expect("find"))
    .expect("linked");
    assert_eq!(found, first);

    // A subject is compared exactly, and belongs to one provider.
    for (provider, subject) in [
        (&google, "SUBJECT-1"),
        (&google, "subject-1 "),
        (&entra, "subject-1"),
    ] {
        let subject = Subject::parse(subject).expect("subject");
        assert!(
            within!(ports, &tenant, |uow| ports
                .links
                .find(uow, provider.id(), &subject)
                .await
                .expect("find"))
            .is_none()
        );
    }

    // A user may have several external identities; they are listed oldest first.
    let second = link(&entra, "subject-1", ana, later);
    let third = link(&google, "subject-2", bia, later);
    within!(ports, &tenant, |uow| {
        assert!(ports.links.insert(uow, &second).await.expect("insert"));
        assert!(ports.links.insert(uow, &third).await.expect("insert"));
    });
    let of_ana = within!(ports, &tenant, |uow| ports
        .links
        .list_for_user(uow, ana)
        .await
        .expect("list"));
    assert_eq!(of_ana, [first.clone(), second.clone()]);

    // A link names a provider of the same tenant.
    let mut unit = ports.units_of_work.begin(&tenant).await.expect("begin");
    let foreign = link(&their_google, "subject-9", ana, later);
    let error = ports
        .links
        .insert(unit.as_mut(), &foreign)
        .await
        .expect_err("a provider of another tenant");
    assert_eq!(error.code(), "federation.provider_not_found");
    drop(unit);

    // Another tenant sees no link, cannot mark one used and cannot remove one.
    assert!(
        within!(ports, &elsewhere, |uow| ports
            .links
            .find(uow, google.id(), &first.subject)
            .await
            .expect("find"))
        .is_none()
    );
    assert!(
        within!(ports, &elsewhere, |uow| ports
            .links
            .list_for_user(uow, ana)
            .await
            .expect("list"))
        .is_empty()
    );
    assert!(!within!(ports, &elsewhere, |uow| ports
        .links
        .mark_used(uow, google.id(), &first.subject, later)
        .await
        .expect("mark")));
    assert!(
        within!(ports, &elsewhere, |uow| ports
            .links
            .remove(uow, google.id(), &first.subject)
            .await
            .expect("remove"))
        .is_none()
    );

    // Marking a link used moves only that link's time.
    assert!(within!(ports, &tenant, |uow| ports
        .links
        .mark_used(uow, google.id(), &first.subject, later)
        .await
        .expect("mark")));
    let found = within!(ports, &tenant, |uow| ports
        .links
        .find(uow, google.id(), &first.subject)
        .await
        .expect("find"))
    .expect("linked");
    assert_eq!(found.last_used_at, later);
    assert_eq!(found.linked_at, Timestamp::UNIX_EPOCH);
    let unknown = Subject::parse("nobody").expect("subject");
    assert!(!within!(ports, &tenant, |uow| ports
        .links
        .mark_used(uow, google.id(), &unknown, later)
        .await
        .expect("mark")));

    // Removing a link says whose it was, once.
    let removed = within!(ports, &tenant, |uow| ports
        .links
        .remove(uow, google.id(), &first.subject)
        .await
        .expect("remove"));
    assert_eq!(removed, Some(ana));
    let removed = within!(ports, &tenant, |uow| ports
        .links
        .remove(uow, google.id(), &first.subject)
        .await
        .expect("remove"));
    assert_eq!(removed, None);
    let of_ana = within!(ports, &tenant, |uow| ports
        .links
        .list_for_user(uow, ana)
        .await
        .expect("list"));
    assert_eq!(of_ana, [second]);
    // The identity is free again, for anyone.
    let relinked = link(&google, "subject-1", bia, later);
    assert!(within!(ports, &tenant, |uow| ports
        .links
        .insert(uow, &relinked)
        .await
        .expect("insert")));

    // Pending authorizations: one for a sign-in, taken once.
    let sign_in = TransactionId::generate();
    let pending = |provider: &IdentityProvider, nonce: &str| PendingAuthorization {
        transaction_id: sign_in,
        provider_id: provider.id(),
        state_hash: [7; 32],
        nonce: nonce.to_owned(),
        code_verifier: SealedSecret::from_stored(vec![0, 255, 128]),
        redirect_uri: "https://hodor.example.com/t/acme/account/providers/google/callback"
            .to_owned(),
        expires_at: later,
        saml_answer: None,
        saml_receipt_hash: None,
    };
    assert!(
        within!(ports, &tenant, |uow| ports
            .pending
            .take(uow, sign_in)
            .await
            .expect("take"))
        .is_none()
    );
    within!(ports, &tenant, |uow| ports
        .pending
        .put(uow, &pending(&google, "first"))
        .await
        .expect("put"));
    // Choosing a provider again replaces the pending authorization.
    within!(ports, &tenant, |uow| ports
        .pending
        .put(uow, &pending(&entra, "second"))
        .await
        .expect("put"));
    // Another tenant cannot take it, and cannot make one for a provider
    // it does not have.
    assert!(
        within!(ports, &elsewhere, |uow| ports
            .pending
            .take(uow, sign_in)
            .await
            .expect("take"))
        .is_none()
    );
    let mut unit = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    let error = ports
        .pending
        .put(unit.as_mut(), &pending(&google, "foreign"))
        .await
        .expect_err("a provider of another tenant");
    assert_eq!(error.code(), "federation.provider_not_found");
    drop(unit);
    let taken = within!(ports, &tenant, |uow| ports
        .pending
        .take(uow, sign_in)
        .await
        .expect("take"))
    .expect("the pending");
    assert_eq!(taken, pending(&entra, "second"));

    // The answer to a SAML response is kept once, with the pending
    // authorization of its provider and state, in its tenant, before it
    // expires; until then that pending authorization is found as waiting.
    within!(ports, &tenant, |uow| ports
        .pending
        .put(uow, &pending(&google, "request"))
        .await
        .expect("put"));
    let before = later - time::Duration::seconds(1);
    let owner = &tenant;
    let refused = |reason| SamlAnswer::Refused { reason };
    let keep = |provider: ProviderId, state: [u8; 32], answer: SamlAnswer, at: Timestamp| {
        let ports = ports.clone();
        async move {
            let mut unit = ports.units_of_work.begin(owner).await.expect("begin");
            let kept = ports
                .pending
                .answer(unit.as_mut(), provider, state, &answer, [9; 32], at)
                .await
                .expect("answer");
            unit.commit().await.expect("commit");
            kept
        }
    };
    let waiting = |provider: ProviderId, state: [u8; 32], at: Timestamp| {
        let ports = ports.clone();
        async move {
            let mut unit = ports.units_of_work.begin(owner).await.expect("begin");
            let found = ports
                .pending
                .unanswered(unit.as_mut(), provider, state, at)
                .await
                .expect("find");
            unit.commit().await.expect("commit");
            found.map(|pending| pending.nonce)
        }
    };
    assert_eq!(
        waiting(google.id(), [7; 32], before).await.as_deref(),
        Some("request")
    );
    assert_eq!(waiting(entra.id(), [7; 32], before).await, None);
    assert_eq!(waiting(google.id(), [8; 32], before).await, None);
    assert_eq!(waiting(google.id(), [7; 32], later).await, None);
    assert!(!keep(entra.id(), [7; 32], refused("signature"), before).await);
    assert!(!keep(google.id(), [8; 32], refused("signature"), before).await);
    assert!(!keep(google.id(), [7; 32], refused("signature"), later).await);
    let mut unit = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    assert!(
        ports
            .pending
            .unanswered(unit.as_mut(), google.id(), [7; 32], before)
            .await
            .expect("find")
            .is_none(),
        "another tenant finds nothing"
    );
    assert!(
        !ports
            .pending
            .answer(
                unit.as_mut(),
                google.id(),
                [7; 32],
                &refused("signature"),
                [9; 32],
                before,
            )
            .await
            .expect("answer")
    );
    drop(unit);
    let verified = SamlAnswer::Verified {
        subject: Subject::parse("saml-subject").expect("subject"),
        email: Some("ana@example.com".to_owned()),
        name: None,
    };
    assert!(keep(google.id(), [7; 32], verified.clone(), before).await);
    assert!(!keep(google.id(), [7; 32], refused("signature"), before).await);
    assert_eq!(
        waiting(google.id(), [7; 32], before).await,
        None,
        "an answered one is no longer waiting"
    );
    let taken = within!(ports, &tenant, |uow| ports
        .pending
        .take(uow, sign_in)
        .await
        .expect("take"))
    .expect("the pending");
    assert_eq!(taken.saml_answer, Some(verified));
    assert_eq!(taken.saml_receipt_hash, Some([9; 32]));

    // A refusal comes back with its reason.
    within!(ports, &tenant, |uow| ports
        .pending
        .put(uow, &pending(&google, "request"))
        .await
        .expect("put"));
    assert!(keep(google.id(), [7; 32], refused("signature"), before).await);
    let taken = within!(ports, &tenant, |uow| ports
        .pending
        .take(uow, sign_in)
        .await
        .expect("take"))
    .expect("the pending");
    assert_eq!(taken.saml_answer, Some(refused("signature")));

    // Expired pending authorizations are removed, a batch at a time, in
    // their tenant only; one that has not expired stays.
    let expired_at = later;
    let pending_of = |transaction_id, expires_at| PendingAuthorization {
        transaction_id,
        expires_at,
        ..pending(&google, "cleanup")
    };
    let first = TransactionId::generate();
    let second = TransactionId::generate();
    let current = TransactionId::generate();
    let mut unit = ports.units_of_work.begin(&tenant).await.expect("begin");
    for (transaction, expires_at) in [
        (first, expired_at),
        (second, expired_at),
        (current, expired_at + time::Duration::minutes(10)),
    ] {
        ports
            .pending
            .put(unit.as_mut(), &pending_of(transaction, expires_at))
            .await
            .expect("put");
    }
    unit.commit().await.expect("commit");
    let mut unit = ports.units_of_work.begin(&elsewhere).await.expect("begin");
    let removed_elsewhere = ports
        .pending
        .remove_expired(unit.as_mut(), expired_at, 10)
        .await
        .expect("remove");
    drop(unit);
    assert_eq!(removed_elsewhere, 0, "another tenant removes none of them");
    let mut unit = ports.units_of_work.begin(&tenant).await.expect("begin");
    let removed = ports
        .pending
        .remove_expired(unit.as_mut(), expired_at, 1)
        .await
        .expect("remove");
    let removed_next = ports
        .pending
        .remove_expired(unit.as_mut(), expired_at, 10)
        .await
        .expect("remove");
    unit.commit().await.expect("commit");
    assert_eq!((removed, removed_next), (1, 1), "a batch at a time");
    for (transaction, left) in [(first, false), (second, false), (current, true)] {
        let found = within!(ports, &tenant, |uow| ports
            .pending
            .take(uow, transaction)
            .await
            .expect("take"));
        assert_eq!(found.is_some(), left);
    }
    assert!(
        within!(ports, &tenant, |uow| ports
            .pending
            .take(uow, sign_in)
            .await
            .expect("take"))
        .is_none()
    );
}
