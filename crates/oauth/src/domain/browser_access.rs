//! The mark an administrator sets on a client for access tokens through
//! the browser, and what it allows: the scopes a request for a type that
//! returns one may ask for, and the lifetime and scopes of the token.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "The mark for access
//! tokens through the browser" and "The access token through the browser",
//! and Decisions 0046 and 0083.

use crate::domain::text::is_scope;
use hodor_kernel::{Actor, DomainError, Timestamp};
use serde_json::{Value, json};
use time::Duration;
use time::format_description::well_known::Rfc3339;

/// The scopes of OpenID Connect that an access token through the browser
/// may always carry.
pub const OPENID_CONNECT_SCOPES: [&str; 5] = ["openid", "profile", "email", "address", "phone"];

/// The scope that asks for a refresh token: allowed in a request for a
/// type that returns an access token, whose code may bring one from the
/// token endpoint, and never carried by the token through the browser.
pub(crate) const OFFLINE_ACCESS_SCOPE: &str = "offline_access";

/// The longest an access token through the browser lives, whatever the
/// client's token policy says.
pub const LONGEST_BROWSER_ACCESS_TOKEN_LIFETIME: Duration = Duration::minutes(5);

/// The most scopes a mark names.
pub(crate) const MAX_MARK_SCOPES: usize = 50;

/// The mark of a client for access tokens through the browser: the scopes
/// the token may carry beyond those of OpenID Connect, and who set it and
/// when.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BrowserAccessTokens {
    /// The scopes beyond `openid`, `profile`, `email`, `address` and
    /// `phone`, in the order given, each once.
    pub scopes: Vec<String>,
    /// Who set it: an administrator, or Hodor itself for the command-line
    /// tool.
    pub marked_by: Actor,
    /// When it was set, or its scopes last changed.
    pub marked_at: Timestamp,
}

pub(crate) fn mark_invalid(reason: &'static str) -> DomainError {
    DomainError::invalid(
        "oauth.client_browser_access_tokens_invalid",
        "only a client with `authorization_code` whose access tokens are not bound to its \
         certificate is marked for access tokens through the browser, with at most 50 \
         scopes, each written as a scope is, never `offline_access`",
    )
    .with_detail(reason)
}

impl BrowserAccessTokens {
    /// A mark of `scopes` as an administrator asks for it. Who set it and
    /// when are written by [`Self::stamped`] when it is saved.
    #[must_use]
    pub fn asked(scopes: Vec<String>) -> Self {
        Self {
            scopes,
            marked_by: Actor::System,
            marked_at: Timestamp::UNIX_EPOCH,
        }
    }

    /// The mark as it is saved: the record of `before` when its scopes are
    /// the same, so that a change that keeps the mark keeps who set it;
    /// otherwise set by `actor` at `now`.
    #[must_use]
    pub fn stamped(self, before: Option<&Self>, actor: Actor, now: Timestamp) -> Self {
        match before {
            Some(before) if before.scopes == self.scopes => before.clone(),
            _ => Self {
                scopes: self.scopes,
                marked_by: actor,
                marked_at: now,
            },
        }
    }

    /// The mark, its scopes each once, if they follow their rule.
    ///
    /// # Errors
    ///
    /// `oauth.client_browser_access_tokens_invalid`.
    pub fn checked(self) -> Result<Self, DomainError> {
        let mut scopes: Vec<String> = Vec::with_capacity(self.scopes.len());
        for scope in self.scopes {
            if !scopes.contains(&scope) {
                scopes.push(scope);
            }
        }
        if scopes.len() > MAX_MARK_SCOPES {
            return Err(mark_invalid("a mark names at most 50 scopes"));
        }
        if !scopes.iter().all(|scope| is_scope(scope)) {
            return Err(mark_invalid("a scope of the mark is not written as one"));
        }
        if scopes.iter().any(|scope| scope == OFFLINE_ACCESS_SCOPE) {
            return Err(mark_invalid(
                "`offline_access` asks for a refresh token, never issued through the browser",
            ));
        }
        Ok(Self { scopes, ..self })
    }

    /// Whether a request for a type that returns an access token may ask
    /// for `scope`: one of OpenID Connect, `offline_access`, or one of the
    /// mark.
    #[must_use]
    pub fn allows(&self, scope: &str) -> bool {
        OPENID_CONNECT_SCOPES.contains(&scope)
            || scope == OFFLINE_ACCESS_SCOPE
            || self.scopes.iter().any(|marked| marked == scope)
    }

    /// The mark as the administration interface and the storage write it.
    #[must_use]
    pub fn to_json(&self) -> Value {
        json!({
            "scopes": self.scopes,
            "marked_by": self.marked_by,
            "marked_at": self.marked_at.format(&Rfc3339).unwrap_or_default(),
        })
    }

    /// Reads a mark as [`Self::to_json`] writes it.
    ///
    /// # Errors
    ///
    /// `oauth.client_browser_access_tokens_invalid` for a document of
    /// another shape.
    pub fn from_json(value: &Value) -> Result<Self, DomainError> {
        let shape = || mark_invalid("a stored mark has scopes, who set it and when");
        let scopes = value["scopes"]
            .as_array()
            .ok_or_else(shape)?
            .iter()
            .map(|scope| scope.as_str().map(str::to_owned).ok_or_else(shape))
            .collect::<Result<Vec<_>, _>>()?;
        let marked_by: Actor =
            serde_json::from_value(value["marked_by"].clone()).map_err(|_| shape())?;
        let marked_at = value["marked_at"]
            .as_str()
            .and_then(|written| Timestamp::parse(written, &Rfc3339).ok())
            .ok_or_else(shape)?;
        Ok(Self {
            scopes,
            marked_by,
            marked_at,
        })
    }
}

/// The scopes the access token through the browser carries: those of the
/// request but `offline_access`.
#[must_use]
pub fn browser_access_token_scopes(scopes: &[String]) -> Vec<String> {
    scopes
        .iter()
        .filter(|scope| *scope != OFFLINE_ACCESS_SCOPE)
        .cloned()
        .collect()
}

/// How long the access token through the browser of a client whose policy
/// gives its access tokens `lifetime` lives: that, or five minutes,
/// whichever is shorter.
#[must_use]
pub fn browser_access_token_lifetime(lifetime: Duration) -> Duration {
    lifetime.min(LONGEST_BROWSER_ACCESS_TOKEN_LIFETIME)
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::UserId;

    fn scopes(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn a_mark_keeps_its_scopes_once_each_in_the_order_given() {
        let mark =
            BrowserAccessTokens::asked(scopes(&["invoices:read", "groups", "invoices:read"]))
                .checked()
                .expect("valid");
        assert_eq!(mark.scopes, ["invoices:read", "groups"]);
        let empty = BrowserAccessTokens::asked(Vec::new())
            .checked()
            .expect("valid");
        assert!(empty.scopes.is_empty());
    }

    #[test]
    fn a_mark_that_breaks_its_rule_is_refused() {
        let many: Vec<String> = (0..51).map(|n| format!("scope{n}")).collect();
        for refused in [
            many,
            scopes(&["offline_access"]),
            scopes(&["two words"]),
            scopes(&[""]),
        ] {
            let error = BrowserAccessTokens::asked(refused)
                .checked()
                .expect_err("refused");
            assert_eq!(error.code(), "oauth.client_browser_access_tokens_invalid");
        }
    }

    #[test]
    fn a_mark_allows_the_scopes_of_openid_connect_offline_access_and_its_own() {
        let mark = BrowserAccessTokens::asked(scopes(&["invoices:read"]));
        for allowed in [
            "openid",
            "profile",
            "email",
            "address",
            "phone",
            "offline_access",
            "invoices:read",
        ] {
            assert!(mark.allows(allowed), "{allowed}");
        }
        for refused in ["groups", "invoices:write", "OPENID"] {
            assert!(!mark.allows(refused), "{refused}");
        }
    }

    #[test]
    fn the_token_carries_the_scopes_but_offline_access_and_lives_five_minutes_at_most() {
        assert_eq!(
            browser_access_token_scopes(&scopes(&["openid", "offline_access", "invoices:read"])),
            ["openid", "invoices:read"]
        );
        assert_eq!(
            browser_access_token_lifetime(Duration::hours(1)),
            Duration::minutes(5)
        );
        assert_eq!(
            browser_access_token_lifetime(Duration::seconds(90)),
            Duration::seconds(90)
        );
    }

    #[test]
    fn a_mark_keeps_who_set_it_while_its_scopes_stay_the_same() {
        let first = Timestamp::UNIX_EPOCH + Duration::days(20_000);
        let later = first + Duration::hours(3);
        let ana = Actor::User(UserId::generate());
        let bruno = Actor::User(UserId::generate());
        let set = BrowserAccessTokens::asked(scopes(&["invoices:read"])).stamped(None, ana, first);
        assert_eq!((set.marked_by, set.marked_at), (ana, first));
        let kept = BrowserAccessTokens::asked(scopes(&["invoices:read"])).stamped(
            Some(&set),
            bruno,
            later,
        );
        assert_eq!(kept, set);
        let changed = BrowserAccessTokens::asked(Vec::new()).stamped(Some(&set), bruno, later);
        assert_eq!((changed.marked_by, changed.marked_at), (bruno, later));
    }

    #[test]
    fn a_mark_reads_back_as_it_was_written() {
        let mark = BrowserAccessTokens::asked(scopes(&["invoices:read"])).stamped(
            None,
            Actor::User(UserId::generate()),
            Timestamp::UNIX_EPOCH + Duration::days(20_000),
        );
        let written = mark.to_json();
        assert_eq!(written["marked_by"]["kind"], "user");
        assert_eq!(BrowserAccessTokens::from_json(&written), Ok(mark));
        let by_hodor = BrowserAccessTokens::asked(Vec::new());
        assert_eq!(by_hodor.to_json()["marked_by"], json!({ "kind": "system" }));
        assert_eq!(
            BrowserAccessTokens::from_json(&by_hodor.to_json()),
            Ok(by_hodor)
        );
        let error = BrowserAccessTokens::from_json(&json!({ "scopes": [] })).expect_err("shape");
        assert_eq!(error.code(), "oauth.client_browser_access_tokens_invalid");
    }
}
