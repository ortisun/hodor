//! Secrets sealed under the tenant's data keys, against the in-memory
//! stores and the stand-in provider. What only real cryptography shows, a
//! changed bit refused, is tested with the local provider in
//! `hodor-adapters-crypto`.

use hodor_kernel::clock::testing::FixedClock;
use hodor_kernel::uow::testing::InMemoryUnitOfWorkFactory;
use hodor_kernel::{Caller, SealedSecret, Secret, SecretBox, TenantContext, TenantId, Timestamp};
use hodor_keys::api::{
    KeyAlgorithm, KeyService, KeyState, KeyUse, KeyVersionId, SEALED_FORMAT, TenantSecretBox,
};
use hodor_keys::testing::{FakeFirstFormat, FakeKeyProvider, InMemoryKeys, InMemorySealingStates};
use std::sync::Arc;
use time::Duration;

const PURPOSE: &str = "federation.client_secret";

struct World {
    secrets: TenantSecretBox,
    service: KeyService,
    units_of_work: InMemoryUnitOfWorkFactory,
    tenant: TenantContext,
}

fn world_with(first_format: bool) -> World {
    let units_of_work = InMemoryUnitOfWorkFactory::default();
    let keys = Arc::new(InMemoryKeys::default());
    let clock = Arc::new(FixedClock::at(Timestamp::UNIX_EPOCH));
    let secrets = TenantSecretBox::new(
        Arc::new(units_of_work.clone()),
        keys.clone(),
        Arc::new(FakeKeyProvider),
        Arc::new(InMemorySealingStates::default()),
        first_format.then(|| Arc::new(FakeFirstFormat) as _),
        clock.clone(),
    );
    let service = KeyService::new(
        Arc::new(units_of_work.clone()),
        keys,
        Arc::new(FakeKeyProvider),
        clock,
    );
    World {
        secrets,
        service,
        units_of_work,
        tenant: TenantContext::assume(TenantId::generate()),
    }
}

fn world() -> World {
    world_with(true)
}

fn secret() -> Secret<Vec<u8>> {
    Secret::new(b"the client secret of a provider".to_vec())
}

fn version_of(sealed: &SealedSecret) -> KeyVersionId {
    let bytes: [u8; 16] = sealed.as_bytes()[1..17].try_into().expect("16 bytes");
    KeyVersionId::from_uuid(uuid::Uuid::from_bytes(bytes))
}

impl World {
    async fn seal(&self) -> SealedSecret {
        self.secrets
            .seal(&self.tenant, PURPOSE, &secret())
            .await
            .expect("seal")
    }

    async fn opens(&self, sealed: &SealedSecret) -> bool {
        match self.secrets.open(&self.tenant, PURPOSE, sealed).await {
            Ok(opened) => {
                assert_eq!(opened.expose(), secret().expose());
                true
            }
            Err(error) => {
                assert_eq!(error.code(), "secret.unreadable");
                false
            }
        }
    }

    async fn data_versions(&self) -> Vec<(KeyVersionId, KeyState)> {
        let set = self
            .service
            .key_set(&self.tenant, KeyUse::Data)
            .await
            .expect("set");
        set.versions()
            .iter()
            .map(|version| (version.id(), version.state()))
            .collect()
    }

    /// Makes a new data key active; the one it replaces starts retiring.
    async fn change_data_key(&self) -> KeyVersionId {
        let made = self
            .service
            .create_version(&self.tenant, KeyAlgorithm::A256Gcm, Caller::system())
            .await
            .expect("create");
        self.service
            .activate(&self.tenant, made.id(), Duration::ZERO, Caller::system())
            .await
            .expect("activate");
        made.id()
    }
}

#[tokio::test]
async fn the_first_secret_makes_the_tenants_data_key_and_the_next_ones_use_it() {
    let world = world();
    assert!(world.data_versions().await.is_empty());

    let first = world.seal().await;
    let versions = world.data_versions().await;
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].1, KeyState::Active);
    assert_eq!(first.as_bytes()[0], SEALED_FORMAT);
    assert_eq!(version_of(&first), versions[0].0);

    let second = world.seal().await;
    assert_eq!(world.data_versions().await.len(), 1, "no second key");
    assert_eq!(version_of(&second), versions[0].0);
    assert!(world.opens(&first).await);
    assert!(world.opens(&second).await);

    // The key was made and activated like any other, so it is audited.
    let types = world.units_of_work.committed_event_types();
    assert_eq!(
        types,
        vec!["keys.version_created", "keys.version_activated"],
        "{types:?}"
    );
}

#[tokio::test]
async fn a_secret_opens_only_for_its_own_tenant_and_purpose() {
    let world = world();
    let sealed = world.seal().await;
    let other = TenantContext::assume(TenantId::generate());

    for (tenant, purpose) in [(&other, PURPOSE), (&world.tenant, "ldap.bind_password")] {
        let error = world
            .secrets
            .open(tenant, purpose, &sealed)
            .await
            .expect_err("must not open");
        assert_eq!(error.code(), "secret.unreadable");
    }
}

#[tokio::test]
async fn a_secret_naming_another_version_or_no_version_does_not_open() {
    let world = world();
    let sealed = world.seal().await;

    let mut renamed = sealed.as_bytes().to_vec();
    renamed[1..17].copy_from_slice(KeyVersionId::generate().as_uuid().as_bytes());
    assert!(!world.opens(&SealedSecret::from_stored(renamed)).await);

    for length in 0..18 {
        let cut = SealedSecret::from_stored(sealed.as_bytes()[..length].to_vec());
        assert!(!world.opens(&cut).await, "cut to {length}");
    }
}

#[tokio::test]
async fn a_retiring_data_key_still_opens_and_asks_for_resealing() {
    let world = world();
    let sealed = world.seal().await;
    assert!(
        !world
            .secrets
            .needs_resealing(&world.tenant, &sealed)
            .await
            .expect("decide")
    );

    let new = world.change_data_key().await;
    assert!(world.opens(&sealed).await, "a retiring key opens");
    assert!(
        world
            .secrets
            .needs_resealing(&world.tenant, &sealed)
            .await
            .expect("decide")
    );

    let resealed = world.seal().await;
    assert_eq!(version_of(&resealed), new);
    assert!(
        !world
            .secrets
            .needs_resealing(&world.tenant, &resealed)
            .await
            .expect("decide")
    );
}

#[tokio::test]
async fn a_retired_or_revoked_data_key_opens_nothing() {
    let world = world();
    let retired = world.seal().await;
    world.change_data_key().await;
    world
        .service
        .retire(&world.tenant, version_of(&retired), Caller::system())
        .await
        .expect("retire");
    assert!(!world.opens(&retired).await);

    let revoked = world.seal().await;
    world
        .service
        .revoke(
            &world.tenant,
            version_of(&revoked),
            "a test revokes it",
            Caller::system(),
        )
        .await
        .expect("revoke");
    assert!(!world.opens(&revoked).await);
}

#[tokio::test]
async fn a_revoked_active_data_key_is_never_sealed_with() {
    let world = world();
    let before = world.seal().await;
    world
        .service
        .revoke(
            &world.tenant,
            version_of(&before),
            "a test revokes it",
            Caller::system(),
        )
        .await
        .expect("revoke");

    let after = world.seal().await;
    assert_ne!(version_of(&after), version_of(&before));
    assert!(world.opens(&after).await);
}

#[tokio::test]
async fn the_first_format_opens_until_the_tenant_refuses_it() {
    let world = world();
    let old = FakeFirstFormat::seal(&world.tenant, PURPOSE, &secret());
    assert!(world.opens(&old).await);
    assert!(
        world
            .secrets
            .needs_resealing(&world.tenant, &old)
            .await
            .expect("decide")
    );
    assert!(
        !world
            .secrets
            .first_format_refused(&world.tenant)
            .await
            .expect("read")
    );

    world
        .secrets
        .refuse_first_format(&world.tenant)
        .await
        .expect("refuse");
    world
        .secrets
        .refuse_first_format(&world.tenant)
        .await
        .expect("refusing again changes nothing");
    assert!(
        world
            .secrets
            .first_format_refused(&world.tenant)
            .await
            .expect("read")
    );
    assert!(!world.opens(&old).await);

    // Another tenant has not refused it.
    let other = TenantContext::assume(TenantId::generate());
    let theirs = FakeFirstFormat::seal(&other, PURPOSE, &secret());
    let opened = world
        .secrets
        .open(&other, PURPOSE, &theirs)
        .await
        .expect("still opens there");
    assert_eq!(opened.expose(), secret().expose());
}

#[tokio::test]
async fn without_the_root_keys_the_first_format_does_not_open() {
    let world = world_with(false);
    let old = FakeFirstFormat::seal(&world.tenant, PURPOSE, &secret());
    assert!(!world.opens(&old).await);
}

#[tokio::test]
async fn a_purpose_that_is_not_a_plain_name_is_refused() {
    let world = world();
    for purpose in ["", "With Spaces", "a\0b", &"a".repeat(129)] {
        let error = world
            .secrets
            .seal(&world.tenant, purpose, &secret())
            .await
            .expect_err("purpose");
        assert_eq!(error.code(), "secret.purpose_invalid");
    }
}
