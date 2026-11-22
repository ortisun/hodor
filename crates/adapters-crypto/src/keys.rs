//! The local key provider: keys made and used inside the server with
//! `aws-lc-rs`, kept wrapped under the root keys of `HODOR_SECRET_KEYS`.
//!
//! See `docs/architecture/contexts/keys.md`, "The local provider".

use crate::sealing::SecretKeys;
use aws_lc_rs::aead::{AES_256_GCM, Aad, NONCE_LEN, Nonce, RandomizedNonceKey};
use aws_lc_rs::encoding::AsDer as _;
use aws_lc_rs::rand::SystemRandom;
use aws_lc_rs::rsa::KeySize;
use aws_lc_rs::signature::{
    ECDSA_P256_SHA256_FIXED_SIGNING, EcdsaKeyPair, KeyPair as _, RSA_PKCS1_SHA256, RSA_PSS_SHA256,
    RsaEncoding, RsaKeyPair,
};
use hodor_kernel::{DomainError, PublicKey, SealedSecret, Secret, TenantContext};
use hodor_keys::api::{
    GeneratedKey, KeyAlgorithm, KeyMaterial, KeyProvider, KeyUse, KeyVersion, KeyVersionId,
};
use std::sync::Arc;
use zeroize::Zeroize as _;

/// The name stored with every version this provider makes.
const NAME: &str = "local";
/// The first byte of what [`LocalKeyProvider::encrypt`] makes.
const CIPHERTEXT_FORMAT: u8 = 1;
const DATA_KEY_BYTES: usize = 32;

/// [`KeyProvider`] that makes keys with `aws-lc-rs` and keeps them sealed
/// with the root keys: the private key in the clear exists only in memory,
/// for one operation.
#[derive(Clone)]
pub struct LocalKeyProvider {
    root: Arc<SecretKeys>,
}

impl std::fmt::Debug for LocalKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LocalKeyProvider").finish_non_exhaustive()
    }
}

impl LocalKeyProvider {
    /// A provider whose keys are wrapped under `root`: the first root key
    /// wraps new keys, every root key unwraps.
    #[must_use]
    pub const fn new(root: Arc<SecretKeys>) -> Self {
        Self { root }
    }

    fn wrap(
        &self,
        tenant: &TenantContext,
        version: KeyVersionId,
        algorithm: KeyAlgorithm,
        key: Secret<Vec<u8>>,
    ) -> Result<KeyMaterial, DomainError> {
        let sealed = self.root.seal(tenant, &purpose(version, algorithm), &key)?;
        Ok(KeyMaterial::from_stored(sealed.as_bytes().to_vec()))
    }

    /// Opens a version's material, if it was made by this provider for this
    /// tenant, version and use.
    fn unwrap(
        &self,
        tenant: &TenantContext,
        version: &KeyVersion,
        key_use: KeyUse,
    ) -> Result<Secret<Vec<u8>>, DomainError> {
        if version.key_use() != key_use {
            return Err(unusable("the key version is not of the use asked for"));
        }
        if version.snapshot().provider != NAME {
            return Err(unusable("the key version was made by another provider"));
        }
        let sealed = SealedSecret::from_stored(version.material().as_bytes().to_vec());
        self.root
            .open(tenant, &purpose(version.id(), version.algorithm()), &sealed)
            .map_err(|_| unusable("the key material does not open"))
    }
}

/// The purpose a key is sealed for: its algorithm and its version, so that
/// material copied to another version or algorithm does not open.
fn purpose(version: KeyVersionId, algorithm: KeyAlgorithm) -> String {
    let version: String = version.to_string().chars().filter(|c| *c != '-').collect();
    format!("keys.{}.{version}", algorithm.as_str().to_ascii_lowercase())
}

/// One error for every reason a key cannot be used; the reason goes to the
/// log.
fn unusable(detail: &str) -> DomainError {
    DomainError::internal("keys.unusable", "the key could not be used").with_detail(detail)
}

fn failed(detail: &str) -> DomainError {
    DomainError::internal("keys.provider_failed", "a key could not be made").with_detail(detail)
}

fn generate_p256() -> Result<(PublicKey, Secret<Vec<u8>>), DomainError> {
    let pair = EcdsaKeyPair::generate(&ECDSA_P256_SHA256_FIXED_SIGNING)
        .map_err(|_| failed("a P-256 key could not be made"))?;
    let document = pair
        .to_pkcs8v1()
        .map_err(|_| failed("a P-256 key could not be written"))?;
    // An uncompressed point: 0x04, then x, then y.
    let point = pair.public_key().as_ref();
    if point.len() != 65 {
        return Err(failed("the P-256 public key has an unexpected size"));
    }
    let public = PublicKey::P256 {
        x: point[1..33].to_vec(),
        y: point[33..65].to_vec(),
    };
    Ok((public, Secret::new(document.as_ref().to_vec())))
}

fn generate_rsa() -> Result<(PublicKey, Secret<Vec<u8>>), DomainError> {
    let pair = RsaKeyPair::generate(KeySize::Rsa2048)
        .map_err(|_| failed("an RSA key could not be made"))?;
    let document = pair
        .as_der()
        .map_err(|_| failed("an RSA key could not be written"))?;
    let public = pair.public_key();
    let public = PublicKey::Rsa {
        modulus: public.modulus().big_endian_without_leading_zero().to_vec(),
        exponent: public.exponent().big_endian_without_leading_zero().to_vec(),
    };
    Ok((public, Secret::new(document.as_ref().to_vec())))
}

fn generate_data_key() -> Result<Secret<Vec<u8>>, DomainError> {
    let mut key = vec![0_u8; DATA_KEY_BYTES];
    aws_lc_rs::rand::fill(&mut key).map_err(|_| failed("no random bytes for a data key"))?;
    Ok(Secret::new(key))
}

fn data_key(key: &Secret<Vec<u8>>) -> Result<RandomizedNonceKey, DomainError> {
    RandomizedNonceKey::new(&AES_256_GCM, key.expose())
        .map_err(|_| unusable("the data key is not an AES-256 key"))
}

#[async_trait::async_trait]
impl KeyProvider for LocalKeyProvider {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn generate(
        &self,
        tenant: &TenantContext,
        version: KeyVersionId,
        algorithm: KeyAlgorithm,
    ) -> Result<GeneratedKey, DomainError> {
        let (public_key, key) = match algorithm {
            KeyAlgorithm::Es256 => {
                let (public, key) = generate_p256()?;
                (Some(public), key)
            }
            KeyAlgorithm::Rs256 | KeyAlgorithm::Ps256 => {
                let (public, key) = generate_rsa()?;
                (Some(public), key)
            }
            KeyAlgorithm::A256Gcm => (None, generate_data_key()?),
        };
        let material = self.wrap(tenant, version, algorithm, key)?;
        Ok(GeneratedKey {
            public_key,
            material,
        })
    }

    async fn sign(
        &self,
        tenant: &TenantContext,
        version: &KeyVersion,
        message: &[u8],
    ) -> Result<Vec<u8>, DomainError> {
        let key = self.unwrap(tenant, version, KeyUse::Signing)?;
        let random = SystemRandom::new();
        match version.algorithm() {
            KeyAlgorithm::Es256 => {
                let pair = EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, key.expose())
                    .map_err(|_| unusable("the key is not a P-256 key"))?;
                let signature = pair
                    .sign(&random, message)
                    .map_err(|_| unusable("the signature could not be made"))?;
                Ok(signature.as_ref().to_vec())
            }
            algorithm @ (KeyAlgorithm::Rs256 | KeyAlgorithm::Ps256) => {
                let pair = RsaKeyPair::from_pkcs8(key.expose())
                    .map_err(|_| unusable("the key is not an RSA key"))?;
                let padding: &'static dyn RsaEncoding = if algorithm == KeyAlgorithm::Rs256 {
                    &RSA_PKCS1_SHA256
                } else {
                    &RSA_PSS_SHA256
                };
                let mut signature = vec![0; pair.public_modulus_len()];
                pair.sign(padding, &random, message, &mut signature)
                    .map_err(|_| unusable("the signature could not be made"))?;
                Ok(signature)
            }
            KeyAlgorithm::A256Gcm => Err(unusable("a data key does not sign")),
        }
    }

    async fn encrypt(
        &self,
        tenant: &TenantContext,
        version: &KeyVersion,
        associated: &[u8],
        plaintext: &Secret<Vec<u8>>,
    ) -> Result<Vec<u8>, DomainError> {
        let key = data_key(&self.unwrap(tenant, version, KeyUse::Data)?)?;
        let mut buffer = plaintext.expose().clone();
        let nonce = key
            .seal_in_place_append_tag(Aad::from(associated), &mut buffer)
            .map_err(|_| {
                buffer.zeroize();
                unusable("the data could not be encrypted")
            })?;
        let mut ciphertext = Vec::with_capacity(1 + NONCE_LEN + buffer.len());
        ciphertext.push(CIPHERTEXT_FORMAT);
        ciphertext.extend_from_slice(nonce.as_ref());
        ciphertext.extend_from_slice(&buffer);
        Ok(ciphertext)
    }

    async fn decrypt(
        &self,
        tenant: &TenantContext,
        version: &KeyVersion,
        associated: &[u8],
        ciphertext: &[u8],
    ) -> Result<Secret<Vec<u8>>, DomainError> {
        let key = data_key(&self.unwrap(tenant, version, KeyUse::Data)?)?;
        let rest = match ciphertext.split_first() {
            Some((&CIPHERTEXT_FORMAT, rest)) if rest.len() >= NONCE_LEN => rest,
            _ => return Err(unusable("not a ciphertext of this provider")),
        };
        let (nonce, sealed) = rest.split_at(NONCE_LEN);
        let nonce = Nonce::try_assume_unique_for_key(nonce)
            .map_err(|_| unusable("not a ciphertext of this provider"))?;
        let mut buffer = sealed.to_vec();
        let length = key
            .open_in_place(nonce, Aad::from(associated), &mut buffer)
            .map(|plaintext| plaintext.len())
            .map_err(|_| unusable("changed, or made with other associated data or key"))?;
        buffer.truncate(length);
        Ok(Secret::new(buffer))
    }
}
