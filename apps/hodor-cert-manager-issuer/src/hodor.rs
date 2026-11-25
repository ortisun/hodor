//! Asking Hodor: an access token for the audience of the certificate
//! authority, and the signing of an intermediate with it.
//!
//! Specified in `docs/operations/hodor-cert-manager-issuer.md`, "How it
//! proves who it is to Hodor" and "What it writes back".

use crate::assertion::ClientKey;
use crate::config::{Authentication, Settings};
use async_trait::async_trait;
use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::json;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// The audience of the tenant's certificate authority.
pub const AUDIENCE: &str = "urn:hodor:certificate-authority";
/// The one scope the issuer's client asks for.
pub const SCOPE: &str = "certificate-authority:sign";
/// How long before it expires a token is no longer used.
const EXPIRY_MARGIN: Duration = Duration::from_secs(30);
/// The assertion type of `private_key_jwt`.
const JWT_BEARER: &str = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

/// An intermediate Hodor signed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Signed {
    /// Its identifier in Hodor.
    pub id: String,
    /// Its serial number, in hexadecimal.
    pub serial_number: String,
    /// The intermediate, in PEM.
    pub certificate: String,
    /// The certificates above it, in PEM, nearest first: the last is the
    /// tenant's root.
    pub chain: Vec<String>,
}

/// Why Hodor signed nothing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Failure {
    /// Hodor read the request and refused it: the request is wrong, and
    /// sending it again changes nothing.
    Refused {
        /// The status Hodor answered.
        status: u16,
        /// Hodor's code, such as `keys.intermediate_lifetime_invalid`.
        code: String,
        /// The reason, as Hodor wrote it.
        detail: String,
    },
    /// Hodor could not be asked, or refused the issuer's own access: the
    /// request may go through later.
    Unavailable(String),
}

impl std::fmt::Display for Failure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused { code, detail, .. } => {
                write!(f, "Hodor refused the request: {code}: {detail}")
            }
            Self::Unavailable(reason) => write!(f, "Hodor could not sign: {reason}"),
        }
    }
}

/// Who signs the requests: Hodor, or a stand-in in tests.
#[async_trait]
pub trait Signer: Send + Sync {
    /// Signs a certificate signing request in PEM, for `lifetime_days`, or
    /// for the authority's bound when it is `None`.
    async fn sign(&self, request: &str, lifetime_days: Option<u32>) -> Result<Signed, Failure>;

    /// Whether the issuer's client gets an access token now.
    async fn check_access(&self) -> Result<(), Failure>;
}

#[derive(Debug, Clone)]
struct Held {
    token: String,
    until: Instant,
}

#[derive(Deserialize)]
struct TokenAnswer {
    access_token: String,
    expires_in: u64,
}

#[derive(Deserialize)]
struct SignedAnswer {
    id: String,
    serial_number: String,
    certificate: String,
    #[serde(default)]
    chain: Vec<String>,
}

#[derive(Deserialize)]
struct ProblemAnswer {
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    detail: Option<String>,
}

/// Hodor, as the issuer's client reaches it.
#[derive(Debug, Clone)]
pub struct Hodor {
    http: reqwest::Client,
    token_endpoint: String,
    signing_endpoint: String,
    issuer: String,
    client_id: String,
    key: Option<Arc<ClientKey>>,
    timeout: Duration,
    token: Arc<Mutex<Option<Held>>>,
}

impl Hodor {
    /// Hodor as `settings` name it, reached through `http`. `key` is the
    /// client's key when it uses `private_key_jwt`.
    #[must_use]
    pub fn new(settings: &Settings, key: Option<ClientKey>, http: reqwest::Client) -> Self {
        let key = match settings.authentication {
            Authentication::Forwarded => None,
            Authentication::PrivateKeyJwt { .. } => key.map(Arc::new),
        };
        Self {
            http,
            token_endpoint: settings.token_endpoint(),
            signing_endpoint: settings.signing_endpoint(),
            issuer: settings.issuer.clone(),
            client_id: settings.client_id.clone(),
            key,
            timeout: settings.timeout,
            token: Arc::new(Mutex::new(None)),
        }
    }

    /// The form of a token request: client credentials for the
    /// authority's audience and scope, with an assertion when the client
    /// signs one.
    fn token_form(&self) -> Result<String, Failure> {
        let mut form = form_urlencoded::Serializer::new(String::new());
        form.append_pair("grant_type", "client_credentials")
            .append_pair("client_id", &self.client_id)
            .append_pair("resource", AUDIENCE)
            .append_pair("scope", SCOPE);
        if let Some(key) = &self.key {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |since| {
                    i64::try_from(since.as_secs()).unwrap_or(i64::MAX)
                });
            let assertion = key
                .assertion(&self.client_id, &self.issuer, now)
                .map_err(|error| Failure::Unavailable(error.to_string()))?;
            form.append_pair("client_assertion_type", JWT_BEARER)
                .append_pair("client_assertion", &assertion);
        }
        Ok(form.finish())
    }

    fn forget(&self) {
        *self.token.lock().unwrap_or_else(PoisonError::into_inner) = None;
    }

    /// The access token: the one kept, while it has more than the margin
    /// left, or a new one.
    async fn token(&self) -> Result<String, Failure> {
        if let Some(held) = self
            .token
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|held| held.until > Instant::now())
        {
            return Ok(held.token.clone());
        }
        let asked = Instant::now();
        let form = self.token_form()?;
        let answer = self
            .http
            .post(&self.token_endpoint)
            .timeout(self.timeout)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await
            .map_err(|error| {
                Failure::Unavailable(format!("the token endpoint could not be reached: {error}"))
            })?;
        let status = answer.status();
        let bytes = answer.bytes().await.map_err(|error| {
            Failure::Unavailable(format!(
                "the token endpoint's answer could not be read: {error}"
            ))
        })?;
        if status != StatusCode::OK {
            // The OAuth error, such as `invalid_client`, says why; never
            // anything secret.
            let error = serde_json::from_slice::<serde_json::Value>(&bytes)
                .ok()
                .and_then(|body| {
                    body.get("error")
                        .and_then(|e| e.as_str())
                        .map(str::to_owned)
                })
                .unwrap_or_default();
            return Err(Failure::Unavailable(format!(
                "the token endpoint answered {status} {error}"
            )));
        }
        let answer: TokenAnswer = serde_json::from_slice(&bytes).map_err(|_| {
            Failure::Unavailable("the token endpoint's answer holds no token".to_owned())
        })?;
        let lifetime = Duration::from_secs(answer.expires_in).saturating_sub(EXPIRY_MARGIN);
        *self.token.lock().unwrap_or_else(PoisonError::into_inner) = Some(Held {
            token: answer.access_token.clone(),
            until: asked + lifetime,
        });
        Ok(answer.access_token)
    }
}

/// What Hodor's answer to a signing means.
fn read_answer(status: StatusCode, bytes: &[u8]) -> Result<Signed, Failure> {
    if status == StatusCode::CREATED {
        let answer: SignedAnswer = serde_json::from_slice(bytes).map_err(|_| {
            Failure::Unavailable("the signing operation's answer holds no certificate".to_owned())
        })?;
        return Ok(Signed {
            id: answer.id,
            serial_number: answer.serial_number,
            certificate: answer.certificate,
            chain: answer.chain,
        });
    }
    let problem = serde_json::from_slice::<ProblemAnswer>(bytes).ok();
    let code = problem
        .as_ref()
        .and_then(|problem| problem.code.clone())
        .unwrap_or_default();
    let detail = problem
        .and_then(|problem| problem.detail)
        .unwrap_or_default();
    let unavailable = status.is_server_error()
        || matches!(
            status,
            StatusCode::UNAUTHORIZED
                | StatusCode::FORBIDDEN
                | StatusCode::REQUEST_TIMEOUT
                | StatusCode::TOO_MANY_REQUESTS
        );
    if unavailable || !status.is_client_error() {
        let named = if code.is_empty() {
            String::new()
        } else {
            format!(" {code}")
        };
        return Err(Failure::Unavailable(format!(
            "the signing operation answered {status}{named}"
        )));
    }
    Err(Failure::Refused {
        status: status.as_u16(),
        code,
        detail,
    })
}

#[async_trait]
impl Signer for Hodor {
    async fn sign(&self, request: &str, lifetime_days: Option<u32>) -> Result<Signed, Failure> {
        let mut body = json!({ "certificate_signing_request": request });
        if let (Some(days), Some(object)) = (lifetime_days, body.as_object_mut()) {
            object.insert("lifetime_days".to_owned(), json!(days));
        }
        let body = body.to_string();
        for attempt in 0..2 {
            let token = self.token().await?;
            let answer = self
                .http
                .post(&self.signing_endpoint)
                .timeout(self.timeout)
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(body.clone())
                .send()
                .await
                .map_err(|error| {
                    Failure::Unavailable(format!(
                        "the signing operation could not be reached: {error}"
                    ))
                })?;
            let status = answer.status();
            if status == StatusCode::UNAUTHORIZED && attempt == 0 {
                // The token may have been revoked, or its key rotated.
                self.forget();
                continue;
            }
            let bytes = answer.bytes().await.map_err(|error| {
                Failure::Unavailable(format!(
                    "the signing operation's answer could not be read: {error}"
                ))
            })?;
            return read_answer(status, &bytes);
        }
        Err(Failure::Unavailable(
            "the signing operation refused a token just issued".to_owned(),
        ))
    }

    async fn check_access(&self) -> Result<(), Failure> {
        self.token().await.map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::{Failure, read_answer};
    use reqwest::StatusCode;

    #[test]
    fn a_signed_answer_gives_the_intermediate_and_its_chain() {
        let signed = read_answer(
            StatusCode::CREATED,
            br#"{ "id": "i-1", "serial_number": "41c2", "certificate": "LEAF", "chain": ["ROOT"], "state": "active" }"#,
        )
        .expect("signed");
        assert_eq!(signed.id, "i-1");
        assert_eq!(signed.serial_number, "41c2");
        assert_eq!(signed.certificate, "LEAF");
        assert_eq!(signed.chain, vec!["ROOT".to_owned()]);
        assert!(matches!(
            read_answer(StatusCode::CREATED, b"{}"),
            Err(Failure::Unavailable(_))
        ));
    }

    #[test]
    fn a_refusal_of_the_request_names_hodors_code_and_detail() {
        for status in [
            StatusCode::BAD_REQUEST,
            StatusCode::NOT_FOUND,
            StatusCode::CONFLICT,
            StatusCode::PAYLOAD_TOO_LARGE,
            StatusCode::UNPROCESSABLE_ENTITY,
        ] {
            assert_eq!(
                read_answer(
                    status,
                    br#"{ "code": "keys.intermediate_lifetime_invalid", "detail": "too long", "status": 422 }"#
                ),
                Err(Failure::Refused {
                    status: status.as_u16(),
                    code: "keys.intermediate_lifetime_invalid".to_owned(),
                    detail: "too long".to_owned(),
                }),
                "{status}"
            );
        }
    }

    #[test]
    fn what_is_not_about_the_request_leaves_it_for_later() {
        for status in [
            StatusCode::UNAUTHORIZED,
            StatusCode::FORBIDDEN,
            StatusCode::REQUEST_TIMEOUT,
            StatusCode::TOO_MANY_REQUESTS,
            StatusCode::INTERNAL_SERVER_ERROR,
            StatusCode::BAD_GATEWAY,
            StatusCode::SERVICE_UNAVAILABLE,
            StatusCode::OK,
            StatusCode::MOVED_PERMANENTLY,
        ] {
            assert!(
                matches!(
                    read_answer(status, br#"{ "code": "admin.forbidden" }"#),
                    Err(Failure::Unavailable(_))
                ),
                "{status}"
            );
        }
    }
}
