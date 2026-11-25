//! The local key provider, with real keys: the contract of every key
//! provider, then what is the local provider's own.

use hodor_adapters_crypto::{AwsLcVerifier, LocalKeyProvider, OsRandom, SecretKeys};
use hodor_kernel::{
    PublicKey, SealedSecret, Secret, SignatureVerifier, TenantContext, TenantId, Timestamp,
};
use hodor_keys::api::{KeyAlgorithm, KeyProvider, KeyVersion, KeyVersionId, SignatureEncoding};
use hodor_keys::testing::{ProviderPorts, run_provider_contract};
use std::sync::Arc;

fn root(pairs: &[(&str, &Secret<String>)]) -> Arc<SecretKeys> {
    let setting: Vec<String> = pairs
        .iter()
        .map(|(identifier, key)| format!("{identifier}:{}", key.expose()))
        .collect();
    Arc::new(SecretKeys::parse(&Secret::new(setting.join(","))).expect("root keys"))
}

fn provider() -> (LocalKeyProvider, Arc<SecretKeys>) {
    let root = root(&[("root", &SecretKeys::generate(&OsRandom))]);
    (LocalKeyProvider::new(Arc::clone(&root)), root)
}

fn tenant() -> TenantContext {
    TenantContext::assume(TenantId::generate())
}

async fn make(
    provider: &LocalKeyProvider,
    tenant: &TenantContext,
    algorithm: KeyAlgorithm,
) -> KeyVersion {
    let id = KeyVersionId::generate();
    let generated = provider
        .generate(tenant, id, algorithm)
        .await
        .expect("generate");
    KeyVersion::create(
        id,
        algorithm,
        provider.name(),
        generated,
        Timestamp::UNIX_EPOCH,
    )
    .expect("a version")
    .0
}

fn purpose(version: &KeyVersion) -> String {
    let id: String = version
        .id()
        .to_string()
        .chars()
        .filter(|c| *c != '-')
        .collect();
    format!(
        "keys.{}.{id}",
        version.algorithm().as_str().to_ascii_lowercase()
    )
}

#[tokio::test]
async fn the_local_provider_passes_the_contract_of_a_key_provider() {
    let (provider, _) = provider();
    run_provider_contract(ProviderPorts {
        provider: &provider,
        verifier: &AwsLcVerifier,
        signing: &[
            KeyAlgorithm::Es256,
            KeyAlgorithm::Rs256,
            KeyAlgorithm::Ps256,
        ],
        data: true,
    })
    .await;
}

#[tokio::test]
async fn keys_have_the_sizes_decision_0008_names() {
    let (provider, _) = provider();
    let tenant = tenant();
    let p256 = make(&provider, &tenant, KeyAlgorithm::Es256).await;
    let Some(PublicKey::P256 { x, y }) = p256.public_key() else {
        panic!("a P-256 key");
    };
    assert_eq!((x.len(), y.len()), (32, 32));
    let rsa = make(&provider, &tenant, KeyAlgorithm::Rs256).await;
    let Some(PublicKey::Rsa { modulus, exponent }) = rsa.public_key() else {
        panic!("an RSA key");
    };
    assert_eq!(modulus.len(), 256, "2048 bits");
    assert_eq!(exponent.as_slice(), [1, 0, 1]);
    let data = make(&provider, &tenant, KeyAlgorithm::A256Gcm).await;
    assert!(data.public_key().is_none());
    // Two keys are never the same.
    let other = make(&provider, &tenant, KeyAlgorithm::Es256).await;
    assert_ne!(p256.public_key(), other.public_key());
}

#[tokio::test]
async fn the_material_holds_no_private_key_in_the_clear() {
    let (provider, root) = provider();
    let tenant = tenant();
    for algorithm in KeyAlgorithm::ALL {
        let version = make(&provider, &tenant, algorithm).await;
        // Opened here with the root keys only to compare: nothing in
        // Hodor opens material outside the provider.
        let key = root
            .open(
                &tenant,
                &purpose(&version),
                &SealedSecret::from_stored(version.material().as_bytes().to_vec()),
            )
            .expect("the root keys open it");
        let stored = version.material().as_bytes();
        let probe = &key.expose()[key.expose().len() - 16..];
        assert!(
            !stored.windows(probe.len()).any(|window| window == probe),
            "{} material shows its key",
            algorithm.as_str()
        );
        assert!(!format!("{version:?}").contains(&format!("{:?}", key.expose())));
    }
}

#[tokio::test]
async fn a_data_key_encrypts_and_decrypts_only_with_its_associated_data() {
    let (provider, _) = provider();
    let (tenant, elsewhere) = (tenant(), tenant());
    let data = make(&provider, &tenant, KeyAlgorithm::A256Gcm).await;
    let secret = Secret::new(b"the client secret of a provider".to_vec());

    let first = provider
        .encrypt(&tenant, &data, b"federation.client_secret", &secret)
        .await
        .expect("encrypt");
    let second = provider
        .encrypt(&tenant, &data, b"federation.client_secret", &secret)
        .await
        .expect("encrypt");
    assert_ne!(first, second, "a new nonce every time");
    assert_eq!(first.len(), 1 + 12 + secret.expose().len() + 16);
    assert!(
        !first
            .windows(secret.expose().len())
            .any(|window| window == secret.expose().as_slice())
    );
    let opened = provider
        .decrypt(&tenant, &data, b"federation.client_secret", &first)
        .await
        .expect("decrypt");
    assert_eq!(opened.expose(), secret.expose());

    assert!(
        provider
            .decrypt(&tenant, &data, b"ldap.bind_password", &first)
            .await
            .is_err()
    );
    assert!(
        provider
            .decrypt(&elsewhere, &data, b"federation.client_secret", &first)
            .await
            .is_err()
    );
    for position in 0..first.len() {
        let mut changed = first.clone();
        changed[position] ^= 0x80;
        let error = provider
            .decrypt(&tenant, &data, b"federation.client_secret", &changed)
            .await
            .expect_err("changed");
        assert_eq!(error.code(), "keys.unusable");
    }
    assert!(
        provider
            .decrypt(&tenant, &data, b"x", &[1, 2, 3])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn material_wrapped_under_an_old_root_key_is_used_after_a_new_one_is_put_first() {
    let old = SecretKeys::generate(&OsRandom);
    let new = SecretKeys::generate(&OsRandom);
    let before = LocalKeyProvider::new(root(&[("old", &old)]));
    let after = LocalKeyProvider::new(root(&[("new", &new), ("old", &old)]));
    let without_old = LocalKeyProvider::new(root(&[("new", &new)]));
    let tenant = tenant();

    let version = make(&before, &tenant, KeyAlgorithm::Es256).await;
    let signature = after
        .sign(&tenant, &version, b"m", SignatureEncoding::Jose)
        .await
        .expect("an old root key still unwraps");
    assert!(AwsLcVerifier.verify(
        hodor_kernel::SignatureAlgorithm::Es256,
        version.public_key().expect("public"),
        b"m",
        &signature
    ));
    assert!(
        without_old
            .sign(&tenant, &version, b"m", SignatureEncoding::Jose)
            .await
            .is_err()
    );
}

#[test]
fn the_provider_prints_no_key() {
    let (provider, _) = provider();
    assert_eq!(format!("{provider:?}"), "LocalKeyProvider { .. }");
}
