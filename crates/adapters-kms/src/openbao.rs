//! The OpenBao key provider: keys made and used in OpenBao's Transit
//! secrets engine, never exported.
//!
//! See `docs/architecture/contexts/keys.md`, "The OpenBao provider".

use crate::public_key;
use crate::settings::{OpenBaoLogin, OpenBaoSettings};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use hodor_kernel::{
    DomainError, ErrorKind, HttpClient, HttpRequest, HttpResponse, Secret, TenantContext,
};
use hodor_keys::api::{
    GeneratedKey, KeyAlgorithm, KeyMaterial, KeyProvider, KeyUse, KeyVersion, KeyVersionId,
    SignatureEncoding,
};
use serde_json::{Value, json};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

/// The name stored with every version this provider makes.
pub const NAME: &str = "openbao";
/// The first part of the material: the format, then the key's name and
/// its algorithm.
const MATERIAL_FORMAT: &str = "openbao:1";
/// The one version of a Transit key Hodor makes and signs with. A key is
/// never rotated in OpenBao: rotating is a new key version of Hodor's,
/// with a key of its own.
const TRANSIT_VERSION: u64 = 1;

/// A token OpenBao gave, and when to sign in again for a new one.
struct Token {
    value: Secret<String>,
    /// `None` for a token that does not expire.
    renew_at: Option<Instant>,
}

/// [`KeyProvider`] on OpenBao's Transit secrets engine.
///
/// Each key is made in OpenBao, named for its tenant and its version, not
/// exportable and with no plaintext backup, and every signature is made
/// there. What Hodor stores as the key's material is only the key's name
/// and algorithm, and a version is used only when that is exactly the
/// name the tenant and the version give: material of one tenant or version
/// is refused for another before anything is sent. A failure of OpenBao
/// is a failure to sign; nothing signs instead.
pub struct OpenBaoKeyProvider {
    http: Arc<dyn HttpClient>,
    address: String,
    mount: String,
    login: OpenBaoLogin,
    time_limit: Duration,
    token: Mutex<Option<Token>>,
}

impl std::fmt::Debug for OpenBaoKeyProvider {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("OpenBaoKeyProvider")
            .field("address", &self.address)
            .field("mount", &self.mount)
            .finish_non_exhaustive()
    }
}

fn unusable(detail: impl Into<String>) -> DomainError {
    DomainError::internal("keys.unusable", "the key could not be used").with_detail(detail)
}

fn unavailable(detail: impl Into<String>) -> DomainError {
    DomainError::new(
        ErrorKind::Unavailable,
        "keys.provider_unavailable",
        "the key provider did not answer",
    )
    .with_detail(detail)
}

fn failed(detail: impl Into<String>) -> DomainError {
    DomainError::internal("keys.provider_failed", "the key provider failed").with_detail(detail)
}

/// The errors OpenBao gave, which name paths and reasons, never a secret.
fn errors_of(response: &HttpResponse) -> String {
    serde_json::from_slice::<Value>(&response.body)
        .ok()
        .and_then(|body| body.get("errors").cloned())
        .map_or_else(String::new, |errors| errors.to_string())
}

/// What OpenBao answered other than a success, as an error.
fn refused(response: &HttpResponse, what: &str) -> DomainError {
    let detail = format!("{what}: status {} {}", response.status, errors_of(response));
    match response.status {
        500..=599 => unavailable(detail),
        403 => DomainError::internal(
            "keys.provider_refused",
            "the key provider refused what Hodor asked",
        )
        .with_detail(detail),
        _ => failed(detail),
    }
}

/// The type of a Transit key for an algorithm, and whether it is RSA.
fn transit_type(algorithm: KeyAlgorithm) -> Option<(&'static str, bool)> {
    match algorithm {
        KeyAlgorithm::Es256 => Some(("ecdsa-p256", false)),
        KeyAlgorithm::Rs256 | KeyAlgorithm::Ps256 => Some(("rsa-2048", true)),
        KeyAlgorithm::A256Gcm => None,
    }
}

impl OpenBaoKeyProvider {
    /// A provider that reaches OpenBao through `http`, which must call the
    /// address in `settings` and nothing else.
    #[must_use]
    pub fn new(http: Arc<dyn HttpClient>, settings: &OpenBaoSettings) -> Self {
        Self {
            http,
            address: settings.address.trim_end_matches('/').to_owned(),
            mount: settings.transit_mount.clone(),
            login: settings.login.clone(),
            time_limit: settings.time_limit,
            token: Mutex::new(None),
        }
    }

    /// The name of the Transit key of `version` in `tenant`:
    /// `tenant-<tenant>-version-<version>`.
    #[must_use]
    pub fn key_name(tenant: &TenantContext, version: KeyVersionId) -> String {
        format!("tenant-{}-version-{version}", tenant.tenant_id())
    }

    /// The material of a key: the format, the key's name and the
    /// algorithm. Nothing in it is secret; it binds the version's row to
    /// the one key it may use.
    fn material(tenant: &TenantContext, version: KeyVersionId, algorithm: KeyAlgorithm) -> String {
        format!(
            "{MATERIAL_FORMAT}:{}:{}",
            Self::key_name(tenant, version),
            algorithm.as_str()
        )
    }

    fn url(&self, path: &str) -> String {
        format!("{}/v1/{path}", self.address)
    }

    fn transit(&self, path: &str) -> String {
        self.url(&format!("{}/{path}", self.mount))
    }

    async fn send(&self, request: HttpRequest) -> Result<HttpResponse, DomainError> {
        self.http
            .send(request.within(self.time_limit))
            .await
            .map_err(|error| unavailable(error.code().to_owned()))
    }

    /// Signs in, with the method the operator chose.
    async fn sign_in(&self) -> Result<Token, DomainError> {
        let (mount, body) = match &self.login {
            OpenBaoLogin::AppRole {
                mount,
                role_id,
                secret_id,
            } => (
                mount,
                Secret::new(
                    json!({ "role_id": role_id, "secret_id": secret_id.expose() }).to_string(),
                ),
            ),
            OpenBaoLogin::Kubernetes {
                mount,
                role,
                token_file,
            } => {
                let jwt = read_token(token_file.clone()).await?;
                (
                    mount,
                    Secret::new(json!({ "role": role, "jwt": jwt.expose() }).to_string()),
                )
            }
        };
        let request = HttpRequest::post(
            self.url(&format!("auth/{mount}/login")),
            "application/json",
            body.expose().as_bytes().to_vec(),
        );
        let response = self.send(request).await?;
        if !response.is_success() {
            let detail = format!(
                "signing in to OpenBao: status {} {}",
                response.status,
                errors_of(&response)
            );
            return Err(if response.status >= 500 {
                unavailable(detail)
            } else {
                DomainError::internal(
                    "keys.provider_sign_in_refused",
                    "the key provider refused to let Hodor sign in",
                )
                .with_detail(detail)
            });
        }
        let body: Value = serde_json::from_slice(&response.body)
            .map_err(|_| failed("signing in to OpenBao: the answer is not JSON"))?;
        let auth = body.get("auth");
        let value = auth
            .and_then(|auth| auth.get("client_token"))
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .ok_or_else(|| failed("signing in to OpenBao: no token in the answer"))?;
        let lease = auth
            .and_then(|auth| auth.get("lease_duration"))
            .and_then(Value::as_u64)
            .unwrap_or(0);
        // Signed in again once two thirds of the token's life have passed,
        // long before OpenBao would refuse it.
        let renew_at = (lease > 0).then(|| Instant::now() + Duration::from_secs(lease) * 2 / 3);
        tracing::debug!(lease_seconds = lease, "signed in to OpenBao");
        Ok(Token {
            value: Secret::new(value.to_owned()),
            renew_at,
        })
    }

    /// The token to use, signing in when there is none or it is old.
    async fn token(&self, fresh: bool) -> Result<Secret<String>, DomainError> {
        let mut held = self.token.lock().await;
        let usable = held.as_ref().filter(|token| {
            !fresh
                && token
                    .renew_at
                    .is_none_or(|renew_at| Instant::now() < renew_at)
        });
        if let Some(token) = usable {
            return Ok(token.value.clone());
        }
        *held = None;
        let token = self.sign_in().await?;
        let value = token.value.clone();
        *held = Some(token);
        Ok(value)
    }

    /// Sends a request of Transit with the token. A token OpenBao no
    /// longer accepts, revoked or expired early, is answered `403`: Hodor
    /// signs in again once and tries again.
    async fn call(&self, request: HttpRequest) -> Result<HttpResponse, DomainError> {
        let token = self.token(false).await?;
        let response = self
            .send(
                request
                    .clone()
                    .header("x-vault-token", token.expose().clone()),
            )
            .await?;
        if response.status != 403 {
            return Ok(response);
        }
        tracing::info!("OpenBao refused the token: signing in again");
        let token = self.token(true).await?;
        self.send(request.header("x-vault-token", token.expose().clone()))
            .await
    }

    /// Reads a key and checks it is one Hodor would have made: of the
    /// type asked, never exportable, with no plaintext backup, not
    /// imported, and at its first version. Answers its public key.
    async fn read_key(
        &self,
        name: &str,
        algorithm: KeyAlgorithm,
    ) -> Result<hodor_kernel::PublicKey, DomainError> {
        let (kind, rsa) = transit_type(algorithm).ok_or_else(|| unusable("not a signing key"))?;
        let response = self
            .call(HttpRequest::get(self.transit(&format!("keys/{name}"))))
            .await?;
        if !response.is_success() {
            return Err(refused(&response, "reading a key"));
        }
        let body: Value = serde_json::from_slice(&response.body)
            .map_err(|_| failed("reading a key: the answer is not JSON"))?;
        let data = body
            .get("data")
            .ok_or_else(|| failed("reading a key: no data"))?;
        let is = |field: &str, expected: &Value| data.get(field) == Some(expected);
        let as_made = is("type", &json!(kind))
            && is("exportable", &json!(false))
            && is("allow_plaintext_backup", &json!(false))
            && is("imported_key", &json!(false))
            && is("latest_version", &json!(TRANSIT_VERSION));
        if !as_made {
            return Err(failed(format!(
                "the key {name} in OpenBao is not one Hodor makes: another type, exportable, \
                 backed up in plaintext, imported or rotated"
            )));
        }
        let pem = data
            .get("keys")
            .and_then(|keys| keys.get(TRANSIT_VERSION.to_string()))
            .and_then(|key| key.get("public_key"))
            .and_then(Value::as_str)
            .ok_or_else(|| failed("reading a key: no public key"))?;
        public_key::read(pem, rsa)
            .ok_or_else(|| failed("reading a key: the public key is not of the type asked"))
    }

    /// The name of the key `version` may use in `tenant`, once its
    /// material is found to be exactly what this provider made for it.
    fn key_of(&self, tenant: &TenantContext, version: &KeyVersion) -> Result<String, DomainError> {
        if version.key_use() != KeyUse::Signing {
            return Err(unusable("OpenBao keeps signing keys only"));
        }
        if version.snapshot().provider != NAME {
            return Err(unusable("the key version was made by another provider"));
        }
        let expected = Self::material(tenant, version.id(), version.algorithm());
        if version.material().as_bytes() != expected.as_bytes() {
            return Err(unusable(
                "the key material is not this tenant's, version's and algorithm's",
            ));
        }
        Ok(Self::key_name(tenant, version.id()))
    }
}

/// Reads the token of the pod's service account, which the cluster
/// replaces before it expires.
async fn read_token(path: PathBuf) -> Result<Secret<String>, DomainError> {
    tokio::task::spawn_blocking(move || std::fs::read_to_string(&path))
        .await
        .map_err(|_| failed("reading the service account's token"))?
        .map(|token| Secret::new(token.trim().to_owned()))
        .map_err(|error| {
            failed(format!(
                "the service account's token cannot be read: {}",
                error.kind()
            ))
        })
}

#[async_trait::async_trait]
impl KeyProvider for OpenBaoKeyProvider {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn generate(
        &self,
        tenant: &TenantContext,
        version: KeyVersionId,
        algorithm: KeyAlgorithm,
    ) -> Result<GeneratedKey, DomainError> {
        let (kind, _) = transit_type(algorithm).ok_or_else(|| {
            DomainError::invalid(
                "keys.algorithm_unsupported",
                "the key provider makes no key of this algorithm",
            )
            .with_detail("OpenBao keeps signing keys only")
        })?;
        let name = Self::key_name(tenant, version);
        // Only the type is sent: a key is made not exportable and with no
        // plaintext backup by default, and Hodor's policy refuses any
        // other parameter.
        let response = self
            .call(HttpRequest::post(
                self.transit(&format!("keys/{name}")),
                "application/json",
                json!({ "type": kind }).to_string().into_bytes(),
            ))
            .await?;
        if !response.is_success() {
            return Err(refused(&response, "making a key"));
        }
        // Making a key whose name exists answers the key that exists:
        // reading it back checks it is the one asked for.
        let public_key = self.read_key(&name, algorithm).await?;
        Ok(GeneratedKey {
            public_key: Some(public_key),
            material: KeyMaterial::from_stored(
                Self::material(tenant, version, algorithm).into_bytes(),
            ),
        })
    }

    async fn sign(
        &self,
        tenant: &TenantContext,
        version: &KeyVersion,
        message: &[u8],
        encoding: SignatureEncoding,
    ) -> Result<Vec<u8>, DomainError> {
        let name = self.key_of(tenant, version)?;
        let mut body = json!({
            "input": STANDARD.encode(message),
            "hash_algorithm": "sha2-256",
            "key_version": TRANSIT_VERSION,
        });
        let (jws, length) = match version.algorithm() {
            KeyAlgorithm::Es256 => {
                let jws = encoding == SignatureEncoding::Jose;
                body["marshaling_algorithm"] = json!(if jws { "jws" } else { "asn1" });
                (jws, jws.then_some(64))
            }
            KeyAlgorithm::Rs256 => {
                body["signature_algorithm"] = json!("pkcs1v15");
                (false, Some(256))
            }
            KeyAlgorithm::Ps256 => {
                // JSON Web Algorithms ask for a salt as long as the hash.
                body["signature_algorithm"] = json!("pss");
                body["salt_length"] = json!("hash");
                (false, Some(256))
            }
            KeyAlgorithm::A256Gcm => return Err(unusable("a data key does not sign")),
        };
        let response = self
            .call(HttpRequest::post(
                self.transit(&format!("sign/{name}")),
                "application/json",
                body.to_string().into_bytes(),
            ))
            .await?;
        if !response.is_success() {
            return Err(refused(&response, "signing"));
        }
        let answer: Value = serde_json::from_slice(&response.body)
            .map_err(|_| failed("signing: the answer is not JSON"))?;
        let written = answer
            .get("data")
            .and_then(|data| data.get("signature"))
            .and_then(Value::as_str)
            .ok_or_else(|| failed("signing: no signature in the answer"))?;
        // `vault:v1:` and the signature, in base64url for the JWS
        // marshaling and in base64 otherwise.
        let encoded = written
            .split_once(':')
            .and_then(|(_, rest)| rest.strip_prefix(&format!("v{TRANSIT_VERSION}:")))
            .ok_or_else(|| failed("signing: not a signature of the key's first version"))?;
        let signature = if jws {
            URL_SAFE_NO_PAD.decode(encoded)
        } else {
            STANDARD.decode(encoded)
        }
        .map_err(|_| failed("signing: the signature is not in the encoding asked for"))?;
        if length.is_some_and(|length| signature.len() != length) {
            return Err(failed("signing: the signature has an unexpected size"));
        }
        Ok(signature)
    }

    async fn encrypt(
        &self,
        _tenant: &TenantContext,
        _version: &KeyVersion,
        _associated: &[u8],
        _plaintext: &Secret<Vec<u8>>,
    ) -> Result<Vec<u8>, DomainError> {
        Err(unusable("OpenBao keeps signing keys only"))
    }

    async fn decrypt(
        &self,
        _tenant: &TenantContext,
        _version: &KeyVersion,
        _associated: &[u8],
        _ciphertext: &[u8],
    ) -> Result<Secret<Vec<u8>>, DomainError> {
        Err(unusable("OpenBao keeps signing keys only"))
    }
}
