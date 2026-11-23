//! The local key provider, with real keys.

use hodor_adapters_crypto::{AwsLcVerifier, LocalKeyProvider, OsRandom, SecretKeys};
use hodor_kernel::{
    PublicKey, SealedSecret, Secret, SignatureVerifier, TenantContext, TenantId, Timestamp,
};
use hodor_keys::api::{KeyAlgorithm, KeyMaterial, KeyProvider, KeyVersion, KeyVersionId};
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

/// The same version with other material, as if a row had been copied.
fn with_material(version: &KeyVersion, material: &KeyMaterial) -> KeyVersion {
    let mut snapshot = version.snapshot().clone();
    snapshot.material = material.clone();
    KeyVersion::from_snapshot(snapshot)
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
async fn each_signing_algorithm_signs_what_its_public_key_checks() {
    let (provider, _) = provider();
    let tenant = tenant();
    for algorithm in [
        KeyAlgorithm::Es256,
        KeyAlgorithm::Rs256,
        KeyAlgorithm::Ps256,
    ] {
        let version = make(&provider, &tenant, algorithm).await;
        let public = version.public_key().expect("a public key");
        let signature = provider
            .sign(&tenant, &version, b"a message")
            .await
            .expect("sign");
        let checked = algorithm.signature().expect("a signing algorithm");
        assert!(
            AwsLcVerifier.verify(checked, public, b"a message", &signature),
            "{} signature checks",
            algorithm.as_str()
        );
        assert!(!AwsLcVerifier.verify(checked, public, b"another message", &signature));
    }
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
async fn material_is_refused_for_another_tenant_version_or_algorithm() {
    let (provider, _) = provider();
    let (tenant, elsewhere) = (tenant(), tenant());
    let es256 = make(&provider, &tenant, KeyAlgorithm::Es256).await;
    let other_es256 = make(&provider, &tenant, KeyAlgorithm::Es256).await;
    let rs256 = make(&provider, &tenant, KeyAlgorithm::Rs256).await;
    let ps256 = make(&provider, &tenant, KeyAlgorithm::Ps256).await;

    let cases = [
        ("another tenant", &elsewhere, es256.clone()),
        (
            "another version",
            &tenant,
            with_material(&other_es256, es256.material()),
        ),
        (
            "another algorithm",
            &tenant,
            with_material(&ps256, rs256.material()),
        ),
    ];
    for (case, tenant, version) in cases {
        let error = provider.sign(tenant, &version, b"m").await.expect_err(case);
        assert_eq!(error.code(), "keys.unusable", "{case}");
    }

    for position in [0, 5, es256.material().as_bytes().len() - 1] {
        let mut bytes = es256.material().as_bytes().to_vec();
        bytes[position] ^= 1;
        let changed = with_material(&es256, &KeyMaterial::from_stored(bytes));
        assert!(provider.sign(&tenant, &changed, b"m").await.is_err());
    }

    let mut foreign = es256.snapshot().clone();
    foreign.provider = "fake".to_owned();
    assert!(
        provider
            .sign(&tenant, &KeyVersion::from_snapshot(foreign), b"m")
            .await
            .is_err(),
        "material of another provider"
    );
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
async fn a_key_of_one_use_is_refused_for_the_other() {
    let (provider, _) = provider();
    let tenant = tenant();
    let signing = make(&provider, &tenant, KeyAlgorithm::Es256).await;
    let data = make(&provider, &tenant, KeyAlgorithm::A256Gcm).await;
    let secret = Secret::new(b"s".to_vec());
    assert!(provider.sign(&tenant, &data, b"m").await.is_err());
    assert!(
        provider
            .encrypt(&tenant, &signing, b"x", &secret)
            .await
            .is_err()
    );
    assert!(
        provider
            .decrypt(&tenant, &signing, b"x", &[1])
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
        .sign(&tenant, &version, b"m")
        .await
        .expect("an old root key still unwraps");
    assert!(AwsLcVerifier.verify(
        hodor_kernel::SignatureAlgorithm::Es256,
        version.public_key().expect("public"),
        b"m",
        &signature
    ));
    assert!(without_old.sign(&tenant, &version, b"m").await.is_err());
}

#[test]
fn the_provider_prints_no_key() {
    let (provider, _) = provider();
    assert_eq!(format!("{provider:?}"), "LocalKeyProvider { .. }");
}
