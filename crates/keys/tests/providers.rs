//! Several providers at once: which one makes a key, and that a version
//! goes back to the provider that made it and to no other.

use hodor_kernel::{DomainError, ErrorKind, Secret, TenantContext, TenantId};
use hodor_keys::api::{
    GeneratedKey, KeyAlgorithm, KeyProvider, KeyProviders, KeyVersion, KeyVersionId,
    SignatureEncoding,
};
use hodor_keys::testing::{FakeKeyProvider, der_to_jose, made_by};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

/// The stand-in provider under another name, which can be taken down.
struct Named {
    name: &'static str,
    down: AtomicBool,
}

impl Named {
    fn new(name: &'static str) -> Arc<Self> {
        Arc::new(Self {
            name,
            down: AtomicBool::new(false),
        })
    }

    fn check(&self) -> Result<(), DomainError> {
        if self.down.load(Ordering::SeqCst) {
            return Err(DomainError::new(
                ErrorKind::Unavailable,
                "keys.provider_unavailable",
                "down",
            ));
        }
        Ok(())
    }

    /// The fake provider checks its material by tenant, version and
    /// algorithm; the name is checked here.
    fn mine(&self, version: &KeyVersion) -> Result<(), DomainError> {
        self.check()?;
        if version.snapshot().provider != self.name {
            return Err(DomainError::internal("keys.unusable", "not mine"));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl KeyProvider for Named {
    fn name(&self) -> &'static str {
        self.name
    }

    async fn generate(
        &self,
        tenant: &TenantContext,
        version: KeyVersionId,
        algorithm: KeyAlgorithm,
    ) -> Result<GeneratedKey, DomainError> {
        self.check()?;
        FakeKeyProvider.generate(tenant, version, algorithm).await
    }

    async fn sign(
        &self,
        tenant: &TenantContext,
        version: &KeyVersion,
        message: &[u8],
        encoding: SignatureEncoding,
    ) -> Result<Vec<u8>, DomainError> {
        self.mine(version)?;
        FakeKeyProvider
            .sign(tenant, version, message, encoding)
            .await
    }

    async fn encrypt(
        &self,
        tenant: &TenantContext,
        version: &KeyVersion,
        associated: &[u8],
        plaintext: &Secret<Vec<u8>>,
    ) -> Result<Vec<u8>, DomainError> {
        self.mine(version)?;
        FakeKeyProvider
            .encrypt(tenant, version, associated, plaintext)
            .await
    }

    async fn decrypt(
        &self,
        tenant: &TenantContext,
        version: &KeyVersion,
        associated: &[u8],
        ciphertext: &[u8],
    ) -> Result<Secret<Vec<u8>>, DomainError> {
        self.mine(version)?;
        FakeKeyProvider
            .decrypt(tenant, version, associated, ciphertext)
            .await
    }
}

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

#[tokio::test]
async fn signing_keys_are_made_by_one_provider_and_data_keys_by_the_other() {
    let (vault, local) = (Named::new("vault_like"), Named::new("local_like"));
    let providers = KeyProviders::new(vault.clone(), local.clone());
    let tenant = tenant();
    for algorithm in [
        KeyAlgorithm::Es256,
        KeyAlgorithm::Rs256,
        KeyAlgorithm::Ps256,
    ] {
        assert_eq!(providers.name_for(algorithm), "vault_like");
        let version = made_by(&providers, &tenant, algorithm).await;
        assert_eq!(version.snapshot().provider, "vault_like");
        assert!(
            providers
                .sign(&tenant, &version, b"m", SignatureEncoding::Jose)
                .await
                .is_ok()
        );
    }
    assert_eq!(providers.name_for(KeyAlgorithm::A256Gcm), "local_like");
    let data = made_by(&providers, &tenant, KeyAlgorithm::A256Gcm).await;
    assert_eq!(data.snapshot().provider, "local_like");
    let secret = Secret::new(b"s".to_vec());
    let sealed = providers
        .encrypt(&tenant, &data, b"x", &secret)
        .await
        .expect("the data key encrypts where it was made");
    assert_eq!(
        providers
            .decrypt(&tenant, &data, b"x", &sealed)
            .await
            .expect("decrypt")
            .expose(),
        secret.expose()
    );
}

#[tokio::test]
async fn a_provider_that_is_down_is_not_replaced_by_another() {
    let (vault, local) = (Named::new("vault_like"), Named::new("local_like"));
    let providers = KeyProviders::new(vault.clone(), local.clone());
    let tenant = tenant();
    let version = made_by(&providers, &tenant, KeyAlgorithm::Es256).await;

    vault.down.store(true, Ordering::SeqCst);
    for encoding in [SignatureEncoding::Jose, SignatureEncoding::Der] {
        let error = providers
            .sign(&tenant, &version, b"m", encoding)
            .await
            .expect_err("nothing signs while the provider is down");
        assert_eq!(error.code(), "keys.provider_unavailable");
    }
    let error = providers
        .generate(&tenant, KeyVersionId::generate(), KeyAlgorithm::Es256)
        .await
        .expect_err("no signing key is made elsewhere either");
    assert_eq!(error.code(), "keys.provider_unavailable");

    vault.down.store(false, Ordering::SeqCst);
    assert!(
        providers
            .sign(&tenant, &version, b"m", SignatureEncoding::Jose)
            .await
            .is_ok()
    );
}

#[tokio::test]
async fn a_version_of_a_provider_not_configured_is_refused() {
    let (vault, local) = (Named::new("vault_like"), Named::new("local_like"));
    let tenant = tenant();
    let made_in_vault = made_by(vault.as_ref(), &tenant, KeyAlgorithm::Es256).await;
    let made_locally = made_by(local.as_ref(), &tenant, KeyAlgorithm::Es256).await;

    let local_only = KeyProviders::new(local.clone(), local.clone());
    let error = local_only
        .sign(&tenant, &made_in_vault, b"m", SignatureEncoding::Jose)
        .await
        .expect_err("refused");
    assert_eq!(error.code(), "keys.provider_not_configured");
    assert!(
        local_only
            .sign(&tenant, &made_locally, b"m", SignatureEncoding::Jose)
            .await
            .is_ok()
    );

    // Back to making keys locally, the versions made in the vault still
    // sign there.
    let back = KeyProviders::new(local.clone(), local).also(vault);
    assert_eq!(back.name_for(KeyAlgorithm::Es256), "local_like");
    assert!(
        back.sign(&tenant, &made_in_vault, b"m", SignatureEncoding::Jose)
            .await
            .is_ok()
    );
}

#[test]
fn a_der_signature_is_read_strictly() {
    let r = [0x80; 32];
    let s = [0x01; 32];
    let mut der = vec![0x30, 0x45, 0x02, 0x21, 0x00];
    der.extend_from_slice(&r);
    der.extend_from_slice(&[0x02, 0x20]);
    der.extend_from_slice(&s);
    let mut jose = r.to_vec();
    jose.extend_from_slice(&s);
    assert_eq!(der_to_jose(&der, 32), Some(jose));

    let short = [0x30, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07];
    let mut expected = vec![0; 31];
    expected.push(5);
    expected.extend_from_slice(&[0; 31]);
    expected.push(7);
    assert_eq!(der_to_jose(&short, 32), Some(expected));

    let mut trailing = der.clone();
    trailing.push(0);
    for bad in [
        &trailing[..],
        &der[..der.len() - 1],
        &[0x30, 0x06, 0x02, 0x01, 0x85, 0x02, 0x01, 0x07][..],
        &[0x30, 0x07, 0x02, 0x02, 0x00, 0x05, 0x02, 0x01, 0x07][..],
        &[0x31, 0x06, 0x02, 0x01, 0x05, 0x02, 0x01, 0x07][..],
        &[][..],
    ] {
        assert_eq!(der_to_jose(bad, 32), None, "{bad:?}");
    }
}
