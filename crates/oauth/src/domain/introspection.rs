//! Revocation and introspection: what a client presents there, the record
//! every access token has in the register, and what introspection answers.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Revocation,
//! introspection and metadata".

use crate::domain::authorization::GrantId;
use crate::domain::client::ClientId;
use crate::domain::openid::ReadAccessToken;
use crate::domain::refresh::RefreshFamilyId;
use crate::domain::token::{BasicCredentials, PresentedClient, TokenError, presented_client};
use hodor_kernel::{Secret, Timestamp, UserId};
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;
use std::fmt;

/// The reason a token revoked at the revocation endpoint carries.
pub const REVOKED_BY_CLIENT: &str = "revoked_by_client";

/// The kind of token a request says it is about. Only a hint: the other
/// kind is tried too.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TokenTypeHint {
    /// `access_token`.
    AccessToken,
    /// `refresh_token`.
    RefreshToken,
}

impl TokenTypeHint {
    /// The hint `value` names, or `None` for any other value, which is
    /// ignored (RFC 7009, section 2.1).
    #[must_use]
    pub fn from_parameter(value: &str) -> Option<Self> {
        match value {
            "access_token" => Some(Self::AccessToken),
            "refresh_token" => Some(Self::RefreshToken),
            _ => None,
        }
    }
}

/// A request to the revocation or the introspection endpoint, read but not
/// yet checked against any client.
pub struct TokenQuery {
    /// How the client says who it is.
    pub client: PresentedClient,
    /// The token the request is about.
    pub token: Secret<String>,
    /// What kind of token the request says it is.
    pub hint: Option<TokenTypeHint>,
}

impl fmt::Debug for TokenQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenQuery")
            .field("client", &self.client)
            .field("hint", &self.hint)
            .finish_non_exhaustive()
    }
}

impl TokenQuery {
    /// Reads a request from its form and the credentials of its
    /// `Authorization: Basic` header.
    ///
    /// # Errors
    ///
    /// Returns the error to answer with: `invalid_request` for a malformed
    /// request, `invalid_client` for one that does not say who the client
    /// is.
    pub fn parse(
        basic: Option<BasicCredentials>,
        pairs: impl IntoIterator<Item = (String, String)>,
    ) -> Result<Self, TokenError> {
        let mut form: Map<String, Value> = Map::new();
        let mut seen = BTreeSet::new();
        for (name, value) in pairs {
            if !seen.insert(name.clone()) {
                return Err(TokenError::invalid_request("a parameter is given twice"));
            }
            form.insert(name, Value::String(value));
        }
        let text = |name: &str| form.get(name).and_then(Value::as_str).map(str::to_owned);
        let client = presented_client(basic, &text)?;
        let token = text("token")
            .filter(|token| !token.is_empty())
            .ok_or(TokenError::invalid_request("token is missing"))?;
        Ok(Self {
            client,
            token: Secret::from(token),
            hint: text("token_type_hint")
                .as_deref()
                .and_then(TokenTypeHint::from_parameter),
        })
    }
}

/// The record of an access token in the register: what is kept of it, never
/// the token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccessTokenRecord {
    /// Its `jti`.
    pub token_id: String,
    /// The client it was issued to.
    pub client_id: ClientId,
    /// The grant it was issued under; none for client credentials.
    pub grant_id: Option<GrantId>,
    /// The refresh token family it came from; none for a code or client
    /// credentials.
    pub family_id: Option<RefreshFamilyId>,
    /// The service account or agent it was issued for, for a client that
    /// acts as one; none otherwise.
    pub principal_id: Option<UserId>,
    /// When it expires.
    pub expires_at: Timestamp,
    /// When it was revoked.
    pub revoked_at: Option<Timestamp>,
    /// Why, such as `revoked_by_client`.
    pub revocation_reason: Option<String>,
}

impl AccessTokenRecord {
    /// The record of a token just issued.
    #[must_use]
    pub const fn issued(
        token_id: String,
        client_id: ClientId,
        grant_id: Option<GrantId>,
        family_id: Option<RefreshFamilyId>,
        expires_at: Timestamp,
    ) -> Self {
        Self {
            token_id,
            client_id,
            grant_id,
            family_id,
            principal_id: None,
            expires_at,
            revoked_at: None,
            revocation_reason: None,
        }
    }

    /// The same record, for a token issued for `principal`.
    #[must_use]
    pub const fn for_principal(mut self, principal: Option<UserId>) -> Self {
        self.principal_id = principal;
        self
    }
}

/// The answer to a token that is not active, or that the caller may not
/// learn about: never more than this.
#[must_use]
pub fn inactive() -> Value {
    json!({"active": false})
}

/// The answer about an active access token.
#[must_use]
pub fn active_access_token(issuer: &str, token: &ReadAccessToken) -> Value {
    let mut answer = json!({
        "active": true,
        "scope": token.scopes.join(" "),
        "client_id": token.client_id,
        "sub": token.subject,
        "aud": token.audience,
        "iss": issuer,
        "exp": token.expires_at.unix_timestamp(),
        "iat": token.issued_at,
        "token_type": "Bearer",
    });
    if let Some(kind) = &token.principal_kind {
        answer["principal_kind"] = json!(kind);
    }
    answer
}

/// What an active refresh token is answered with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ActiveRefreshToken<'a> {
    /// The scopes of its family.
    pub scopes: &'a [String],
    /// The client it was issued to.
    pub client_id: ClientId,
    /// The person.
    pub subject: String,
    /// When it stops being usable: the earlier of the end of its family's
    /// lifetime and of its idle time.
    pub expires_at: Timestamp,
    /// When it was issued.
    pub issued_at: Timestamp,
}

/// The answer about an active refresh token.
#[must_use]
pub fn active_refresh_token(issuer: &str, token: &ActiveRefreshToken<'_>) -> Value {
    json!({
        "active": true,
        "scope": token.scopes.join(" "),
        "client_id": token.client_id.to_string(),
        "sub": token.subject,
        "aud": issuer,
        "iss": issuer,
        "exp": token.expires_at.unix_timestamp(),
        "iat": token.issued_at.unix_timestamp(),
        "token_type": "refresh_token",
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(items: &[(&str, &str)]) -> Vec<(String, String)> {
        items
            .iter()
            .map(|(name, value)| ((*name).to_owned(), (*value).to_owned()))
            .collect()
    }

    #[test]
    fn a_query_reads_the_token_the_hint_and_the_client() {
        let query = TokenQuery::parse(
            None,
            pairs(&[
                ("client_id", "c"),
                ("client_secret", "s"),
                ("token", "t"),
                ("token_type_hint", "refresh_token"),
            ]),
        )
        .expect("read");
        assert_eq!(query.token.expose(), "t");
        assert_eq!(query.hint, Some(TokenTypeHint::RefreshToken));
        assert!(matches!(query.client, PresentedClient::Secret { .. }));
    }

    #[test]
    fn an_unknown_hint_is_ignored() {
        let query = TokenQuery::parse(
            None,
            pairs(&[
                ("client_id", "c"),
                ("token", "t"),
                ("token_type_hint", "id_token"),
            ]),
        )
        .expect("read");
        assert_eq!(query.hint, None);
        assert!(matches!(query.client, PresentedClient::Public { .. }));
    }

    #[test]
    fn a_query_without_a_token_or_with_a_parameter_twice_is_malformed() {
        for form in [
            pairs(&[("client_id", "c")]),
            pairs(&[("client_id", "c"), ("token", "")]),
            pairs(&[("client_id", "c"), ("token", "a"), ("token", "b")]),
            pairs(&[
                ("client_id", "c"),
                ("client_secret", "s"),
                ("client_assertion", "x"),
            ]),
        ] {
            let error = TokenQuery::parse(None, form).expect_err("refused");
            assert_eq!(error.error, "invalid_request");
        }
        let error = TokenQuery::parse(None, pairs(&[("token", "t")])).expect_err("no client");
        assert_eq!(error.error, "invalid_client");
    }

    #[test]
    fn an_inactive_answer_says_nothing_else() {
        assert_eq!(inactive(), json!({"active": false}));
    }
}
