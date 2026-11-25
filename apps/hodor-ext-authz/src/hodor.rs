//! Asking Hodor: an access token per application's client, by the
//! adapter's mesh identity alone, and `evaluate` with it.
//!
//! Specified in `docs/operations/hodor-ext-authz.md`, "How it proves who it
//! is to Hodor" and "When it denies".

use crate::config::Settings;
use reqwest::StatusCode;
use reqwest::header::{AUTHORIZATION, CONTENT_TYPE};
use serde::Deserialize;
use serde_json::Value;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::{Duration, Instant};

/// The Authorization API's audience.
const AUDIENCE: &str = "urn:hodor:authorization";
/// The one scope the adapter's clients ask for.
const SCOPE: &str = "authz:evaluate";
/// How long before it expires a token is no longer used.
const EXPIRY_MARGIN: Duration = Duration::from_secs(30);

/// Why Hodor gave no decision. Logged, never sent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Failure(pub String);

/// What Hodor decided.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Decided {
    /// Whether the decision is `ALLOW`.
    pub allowed: bool,
    /// The decision as Hodor wrote it.
    pub decision: String,
    /// The decision's identifier in Hodor's record, if given.
    pub decision_id: Option<String>,
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
struct EvaluateAnswer {
    decision: String,
    #[serde(default)]
    decision_id: Option<String>,
}

/// Hodor, as the adapter's clients reach it.
#[derive(Debug, Clone)]
pub struct Hodor {
    http: reqwest::Client,
    token_endpoint: String,
    evaluate_endpoint: String,
    timeout: Duration,
    client_ids: Vec<String>,
    /// One access token per application, kept until shortly before it
    /// expires.
    tokens: Arc<Vec<Mutex<Option<Held>>>>,
}

impl Hodor {
    /// Hodor as `settings` name it, reached through `http`.
    #[must_use]
    pub fn new(settings: &Settings, http: reqwest::Client) -> Self {
        Self {
            http,
            token_endpoint: settings.token_endpoint(),
            evaluate_endpoint: settings.evaluate_endpoint(),
            timeout: settings.timeout,
            client_ids: settings
                .applications
                .iter()
                .map(|application| application.client_id.clone())
                .collect(),
            tokens: Arc::new(
                settings
                    .applications
                    .iter()
                    .map(|_| Mutex::new(None))
                    .collect(),
            ),
        }
    }

    /// What Hodor decides about `body`, asked as the client of the
    /// application at `application`. A token refused with `401` is
    /// replaced once.
    ///
    /// # Errors
    ///
    /// Returns a [`Failure`] for anything but a decision read from a `200`.
    pub async fn evaluate(&self, application: usize, body: &Value) -> Result<Decided, Failure> {
        let body = serde_json::to_vec(body).map_err(|error| Failure(error.to_string()))?;
        for attempt in 0..2 {
            let token = self.token(application).await?;
            let answer = self
                .http
                .post(&self.evaluate_endpoint)
                .timeout(self.timeout)
                .header(AUTHORIZATION, format!("Bearer {token}"))
                .header(CONTENT_TYPE, "application/json")
                .body(body.clone())
                .send()
                .await
                .map_err(|error| Failure(format!("evaluate could not be reached: {error}")))?;
            let status = answer.status();
            if status == StatusCode::UNAUTHORIZED && attempt == 0 {
                self.forget(application);
                continue;
            }
            if status != StatusCode::OK {
                return Err(Failure(format!("evaluate answered {status}")));
            }
            let bytes = answer.bytes().await.map_err(|error| {
                Failure(format!("evaluate's answer could not be read: {error}"))
            })?;
            let answer: EvaluateAnswer = serde_json::from_slice(&bytes)
                .map_err(|_| Failure("evaluate's answer holds no decision".to_owned()))?;
            return Ok(Decided {
                allowed: answer.decision == "ALLOW",
                decision: answer.decision,
                decision_id: answer.decision_id,
            });
        }
        Err(Failure("evaluate refused a token just issued".to_owned()))
    }

    fn slot(&self, application: usize) -> Result<&Mutex<Option<Held>>, Failure> {
        self.tokens
            .get(application)
            .ok_or_else(|| Failure("no such application".to_owned()))
    }

    fn forget(&self, application: usize) {
        if let Ok(slot) = self.slot(application) {
            *slot.lock().unwrap_or_else(PoisonError::into_inner) = None;
        }
    }

    /// The application's access token: the one kept, while it has more
    /// than the margin left, or a new one.
    async fn token(&self, application: usize) -> Result<String, Failure> {
        let slot = self.slot(application)?;
        if let Some(held) = slot
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .as_ref()
            .filter(|held| held.until > Instant::now())
        {
            return Ok(held.token.clone());
        }
        let asked = Instant::now();
        let form = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("client_id", &self.client_ids[application])
            .append_pair("resource", AUDIENCE)
            .append_pair("scope", SCOPE)
            .finish();
        let answer = self
            .http
            .post(&self.token_endpoint)
            .timeout(self.timeout)
            .header(CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await
            .map_err(|error| {
                Failure(format!("the token endpoint could not be reached: {error}"))
            })?;
        let status = answer.status();
        if status != StatusCode::OK {
            return Err(Failure(format!("the token endpoint answered {status}")));
        }
        let bytes = answer.bytes().await.map_err(|error| {
            Failure(format!(
                "the token endpoint's answer could not be read: {error}"
            ))
        })?;
        let answer: TokenAnswer = serde_json::from_slice(&bytes)
            .map_err(|_| Failure("the token endpoint's answer holds no token".to_owned()))?;
        let lifetime = Duration::from_secs(answer.expires_in).saturating_sub(EXPIRY_MARGIN);
        *slot.lock().unwrap_or_else(PoisonError::into_inner) = Some(Held {
            token: answer.access_token.clone(),
            until: asked + lifetime,
        });
        Ok(answer.access_token)
    }
}
