//! Signing in through GitHub, which is not an OpenID Connect provider.
//!
//! See `docs/architecture/contexts/federation.md`, "Signing in through
//! GitHub". There is no ID token: GitHub's own interface is asked who the
//! person is, with an access token that is used for that and dropped.

use crate::application::openid::{AuthorizationRequest, VerifiedIdentity};
use crate::domain::link::Subject;
use crate::domain::provider::{IdentityProvider, LONGEST_CLAIM_VALUE};
use hodor_identity::api::{ClaimField, StandardClaims};
use hodor_kernel::{
    DomainError, ErrorKind, HttpClient, HttpRequest, HttpResponse, RandomSource, Secret,
};
use serde_json::Value;
use std::sync::Arc;

const GITHUB: &str = "https://github.com";

fn unavailable(detail: impl Into<String>) -> DomainError {
    DomainError::new(
        ErrorKind::Unavailable,
        "federation.provider_unavailable",
        "the identity provider cannot be used right now",
    )
    .with_detail(detail)
}

fn not_verified(detail: impl Into<String>) -> DomainError {
    DomainError::new(
        ErrorKind::Unauthenticated,
        "federation.identity_not_verified",
        "the identity provider did not establish who you are",
    )
    .with_detail(detail)
}

/// Where GitHub's interface is for an issuer: its own address for
/// github.com, and under the installation for GitHub Enterprise Server.
fn interface_of(issuer: &str) -> String {
    let issuer = issuer.trim_end_matches('/');
    if issuer.eq_ignore_ascii_case(GITHUB) {
        "https://api.github.com".to_owned()
    } else {
        format!("{issuer}/api/v3")
    }
}

/// A plain word from an answer, safe to write to a log.
fn word(value: Option<&str>) -> String {
    value
        .unwrap_or("no reason given")
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
        .take(64)
        .collect()
}

/// Talks to GitHub.
#[derive(Clone)]
pub struct GitHubClient {
    http: Arc<dyn HttpClient>,
    random: Arc<dyn RandomSource>,
}

impl std::fmt::Debug for GitHubClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GitHubClient").finish_non_exhaustive()
    }
}

impl GitHubClient {
    /// Wires the client to its ports.
    #[must_use]
    pub fn new(http: Arc<dyn HttpClient>, random: Arc<dyn RandomSource>) -> Self {
        Self { http, random }
    }

    /// Prepares one authorization request: the address to send the
    /// person to and the `state` made for it. GitHub has no nonce, and
    /// no code verifier is sent.
    #[must_use]
    pub fn begin(&self, provider: &IdentityProvider, redirect_uri: &str) -> AuthorizationRequest {
        let settings = &provider.snapshot().settings;
        let mut bytes = [0_u8; 32];
        self.random.fill(&mut bytes);
        let state: String = bytes.iter().map(|byte| format!("{byte:02x}")).collect();
        let query = form_urlencoded::Serializer::new(String::new())
            .append_pair("client_id", &settings.client_id)
            .append_pair("redirect_uri", redirect_uri)
            .append_pair("scope", &settings.scopes.join(" "))
            .append_pair("state", &state)
            // Ask every time which account is meant, instead of silently
            // using whichever is signed in to GitHub in this browser.
            .append_pair("allow_signup", "false")
            .finish();
        AuthorizationRequest {
            url: format!(
                "{}/login/oauth/authorize?{query}",
                settings.issuer.trim_end_matches('/')
            ),
            state,
            nonce: String::new(),
            code_verifier: Secret::new(String::new()),
        }
    }

    async fn ask(
        &self,
        url: String,
        token: &Secret<String>,
        what: &str,
    ) -> Result<Value, DomainError> {
        let response = self
            .http
            .send(
                HttpRequest::get(url)
                    .header("accept", "application/vnd.github+json")
                    .header("authorization", format!("Bearer {}", token.expose()))
                    .header("x-github-api-version", "2022-11-28"),
            )
            .await
            .map_err(|error| unavailable(format!("{what} could not be asked: {}", error.code())))?;
        json_of(&response, what)
    }

    /// Exchanges the code a person came back with and asks GitHub who
    /// they are.
    ///
    /// # Errors
    ///
    /// Returns `federation.identity_not_verified` if GitHub refuses the
    /// code or does not say who the person is, and
    /// `federation.provider_unavailable` if GitHub cannot be reached.
    pub async fn finish(
        &self,
        provider: &IdentityProvider,
        client_secret: &Secret<String>,
        redirect_uri: &str,
        code: &str,
    ) -> Result<VerifiedIdentity, DomainError> {
        let settings = &provider.snapshot().settings;
        let issuer = settings.issuer.trim_end_matches('/');
        let request = {
            let body = form_urlencoded::Serializer::new(String::new())
                .append_pair("client_id", &settings.client_id)
                .append_pair("client_secret", client_secret.expose())
                .append_pair("code", code)
                .append_pair("redirect_uri", redirect_uri)
                .finish();
            HttpRequest::post(
                format!("{issuer}/login/oauth/access_token"),
                "application/x-www-form-urlencoded",
                body.into_bytes(),
            )
            .header("accept", "application/json")
        };
        let response = self.http.send(request).await.map_err(|error| {
            unavailable(format!("the code could not be exchanged: {}", error.code()))
        })?;
        let answer: Value = serde_json::from_slice(&response.body).unwrap_or(Value::Null);
        // GitHub answers 200 even when it refuses; `error` is what says so.
        let refused = answer.get("error").and_then(Value::as_str);
        if response.status != 200 || refused.is_some() {
            return Err(not_verified(format!(
                "GitHub refused the code with status {}: {}",
                response.status,
                word(refused)
            )));
        }
        let token = answer
            .get("access_token")
            .and_then(Value::as_str)
            .filter(|token| !token.is_empty())
            .map(|token| Secret::new(token.to_owned()))
            .ok_or_else(|| not_verified("GitHub's answer carries no access token"))?;

        let interface = interface_of(issuer);
        let user = self
            .ask(format!("{interface}/user"), &token, "who the person is")
            .await?;
        // The numeric identifier, never the login name: a name can be
        // changed, and taken by somebody else afterwards.
        let subject = user
            .get("id")
            .and_then(Value::as_u64)
            .and_then(|id| Subject::parse(&id.to_string()).ok())
            .ok_or_else(|| not_verified("GitHub did not say who the person is"))?;
        let name = user
            .get("name")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|name| !name.is_empty() && name.chars().count() <= 200)
            .map(str::to_owned);

        // The address marked both primary and verified, or none. The
        // address in the profile is not used: it is what the person
        // chose to show, which GitHub does not vouch for there.
        let emails = self
            .ask(
                format!("{interface}/user/emails"),
                &token,
                "the person's addresses",
            )
            .await;
        let email = match emails {
            Ok(Value::Array(listed)) => listed.iter().find_map(|entry| {
                let flag = |name: &str| entry.get(name) == Some(&Value::Bool(true));
                (flag("primary") && flag("verified"))
                    .then(|| entry.get("email").and_then(Value::as_str))
                    .flatten()
                    .filter(|address| !address.is_empty() && address.len() <= 254)
                    .map(str::to_owned)
            }),
            // Without the scope for addresses GitHub refuses the question;
            // the person is still who they are, with no address.
            Ok(_) | Err(_) => None,
        };

        // The picture and the site of the profile. GitHub says nothing of a
        // telephone number.
        let mut claims = StandardClaims::default();
        for (field, member) in [
            (ClaimField::Picture, "avatar_url"),
            (ClaimField::Website, "blog"),
        ] {
            claims.set(
                field,
                user.get(member)
                    .and_then(Value::as_str)
                    .filter(|value| value.chars().count() <= LONGEST_CLAIM_VALUE)
                    .map(str::to_owned),
            );
        }

        Ok(VerifiedIdentity {
            subject,
            email_verified: email.is_some(),
            email,
            name,
            locale: None,
            claims,
        })
    }
}

fn json_of(response: &HttpResponse, what: &str) -> Result<Value, DomainError> {
    if response.status != 200 {
        return Err(not_verified(format!(
            "GitHub answered {what} with status {}",
            response.status
        )));
    }
    serde_json::from_slice(&response.body)
        .map_err(|_| not_verified(format!("GitHub's answer to {what} is not JSON")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_interface_is_found_from_the_issuer() {
        assert_eq!(interface_of("https://github.com"), "https://api.github.com");
        assert_eq!(
            interface_of("https://github.com/"),
            "https://api.github.com"
        );
        assert_eq!(interface_of("https://GitHub.com"), "https://api.github.com");
        assert_eq!(
            interface_of("https://github.example.org"),
            "https://github.example.org/api/v3"
        );
        // A look-alike is another installation, never github.com.
        assert_eq!(
            interface_of("https://github.com.evil.example"),
            "https://github.com.evil.example/api/v3"
        );
    }
}
