//! Endpoints: where a tenant's events are sent, and which.

use crate::domain::catalog::EventType;
use hodor_kernel::{DomainError, Timestamp};
use std::collections::BTreeSet;

hodor_kernel::define_id!(
    /// Identifies a webhook endpoint.
    EndpointId
);

/// The most endpoints a tenant may have.
pub const MAX_ENDPOINTS: u32 = 20;

/// The longest address, in characters.
pub const MAX_URL_LENGTH: usize = 1000;

/// The longest description, in characters.
pub const MAX_DESCRIPTION_LENGTH: usize = 200;

/// Everything about an endpoint, for storage and for reading. Its secrets
/// are kept apart, sealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointSnapshot {
    /// The endpoint's identifier.
    pub id: EndpointId,
    /// Where deliveries are sent.
    pub url: String,
    /// What the administrator wrote about it.
    pub description: Option<String>,
    /// The event types it receives.
    pub event_types: BTreeSet<EventType>,
    /// When it was registered.
    pub created_at: Timestamp,
    /// When it was last changed.
    pub updated_at: Timestamp,
    /// Incremented on every stored change, for optimistic locking.
    pub version: u32,
}

/// A webhook endpoint of a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Endpoint {
    state: EndpointSnapshot,
}

fn address_invalid() -> DomainError {
    DomainError::invalid(
        "webhooks.endpoint_address_invalid",
        "an endpoint's address is an HTTPS address of at most 1000 characters, without a name \
         and password or a fragment",
    )
}

/// The rules an address must follow before anyone resolves it: an HTTP or
/// HTTPS address with a host, printable, without spaces, a name and
/// password or a fragment. Whether plain HTTP may be used, and whether the
/// host may be called, is for the destination check to say.
fn check_url(url: &str) -> Result<(), DomainError> {
    let rest = url
        .strip_prefix("https://")
        .or_else(|| url.strip_prefix("http://"))
        .ok_or_else(address_invalid)?;
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    let plain = url.chars().count() <= MAX_URL_LENGTH
        && !authority.is_empty()
        && !authority.contains('@')
        && url.bytes().all(|byte| {
            byte.is_ascii_graphic() && !matches!(byte, b'#' | b'\\' | b'"' | b'<' | b'>')
        });
    if plain {
        Ok(())
    } else {
        Err(address_invalid())
    }
}

fn check_description(description: Option<String>) -> Result<Option<String>, DomainError> {
    let Some(description) = description else {
        return Ok(None);
    };
    let trimmed = description.trim();
    if trimmed.is_empty() {
        return Ok(None);
    }
    if trimmed.chars().count() > MAX_DESCRIPTION_LENGTH || trimmed.chars().any(char::is_control) {
        return Err(DomainError::invalid(
            "webhooks.description_invalid",
            "a description is at most 200 characters, without control characters",
        ));
    }
    Ok(Some(trimmed.to_owned()))
}

/// Reads a list of event types; each must be in the catalog, and one named
/// twice is kept once.
///
/// # Errors
///
/// Returns `webhooks.event_type_unknown` for a type that is not in the
/// catalog.
pub fn event_types<S: AsRef<str>>(names: &[S]) -> Result<BTreeSet<EventType>, DomainError> {
    names
        .iter()
        .map(|name| EventType::parse(name.as_ref()))
        .collect()
}

impl Endpoint {
    /// A new endpoint, as an administrator registers it.
    ///
    /// # Errors
    ///
    /// Returns `webhooks.endpoint_address_invalid`,
    /// `webhooks.description_invalid` or `webhooks.event_type_unknown`.
    pub fn register<S: AsRef<str>>(
        url: &str,
        description: Option<String>,
        subscriptions: &[S],
        now: Timestamp,
    ) -> Result<Self, DomainError> {
        check_url(url)?;
        Ok(Self {
            state: EndpointSnapshot {
                id: EndpointId::generate(),
                url: url.to_owned(),
                description: check_description(description)?,
                event_types: event_types(subscriptions)?,
                created_at: now,
                updated_at: now,
                version: 0,
            },
        })
    }

    /// Rebuilds an endpoint read from storage.
    #[must_use]
    pub const fn from_snapshot(state: EndpointSnapshot) -> Self {
        Self { state }
    }

    /// Everything about it.
    #[must_use]
    pub const fn snapshot(&self) -> &EndpointSnapshot {
        &self.state
    }

    /// Its identifier.
    #[must_use]
    pub const fn id(&self) -> EndpointId {
        self.state.id
    }

    /// Where deliveries are sent.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.state.url
    }

    /// Whether it receives events of this type.
    #[must_use]
    pub fn is_subscribed_to(&self, event_type: &str) -> bool {
        self.state
            .event_types
            .iter()
            .any(|known| known.as_str() == event_type)
    }

    /// Replaces the event types it receives.
    ///
    /// # Errors
    ///
    /// Returns `webhooks.event_type_unknown`; nothing changes then.
    pub fn replace_subscriptions<S: AsRef<str>>(
        &mut self,
        subscriptions: &[S],
        now: Timestamp,
    ) -> Result<(), DomainError> {
        self.state.event_types = event_types(subscriptions)?;
        self.state.updated_at = now;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn register(url: &str) -> Result<Endpoint, DomainError> {
        Endpoint::register(url, None, &["session.started"], NOW)
    }

    #[test]
    fn an_address_must_be_plain_http_or_https_with_a_host() {
        for good in [
            "https://hooks.example.com/hodor",
            "https://93.184.216.34:8443/in?token=a1b2",
            "http://receiver:9000/",
        ] {
            assert!(register(good).is_ok(), "{good}");
        }
        let long = format!("https://example.com/{}", "a".repeat(MAX_URL_LENGTH));
        for bad in [
            "",
            "hooks.example.com",
            "ftp://example.com/",
            "https://",
            "https:///path",
            "https://user:password@example.com/",
            "https://example.com/#part",
            "https://example.com/a b",
            "https://example.com/\u{e9}",
            long.as_str(),
        ] {
            let error = register(bad).expect_err(bad);
            assert_eq!(error.code(), "webhooks.endpoint_address_invalid", "{bad}");
        }
    }

    #[test]
    fn a_description_is_trimmed_bounded_and_printable() {
        let endpoint = Endpoint::register(
            "https://example.com/",
            Some("  Our directory  ".to_owned()),
            &[] as &[&str],
            NOW,
        )
        .expect("registered");
        assert_eq!(
            endpoint.snapshot().description.as_deref(),
            Some("Our directory")
        );
        let blank = Endpoint::register(
            "https://example.com/",
            Some("   ".to_owned()),
            &[] as &[&str],
            NOW,
        )
        .expect("registered");
        assert_eq!(blank.snapshot().description, None);
        for bad in ["a".repeat(201), "line\nbreak".to_owned()] {
            let error = Endpoint::register("https://example.com/", Some(bad), &[] as &[&str], NOW)
                .expect_err("refused");
            assert_eq!(error.code(), "webhooks.description_invalid");
        }
    }

    #[test]
    fn subscriptions_come_from_the_catalog_each_once() {
        let mut endpoint = Endpoint::register(
            "https://example.com/",
            None,
            &[
                "session.started",
                "session.started",
                "identity.user_created",
            ],
            NOW,
        )
        .expect("registered");
        assert_eq!(endpoint.snapshot().event_types.len(), 2);
        assert!(endpoint.is_subscribed_to("session.started"));
        assert!(!endpoint.is_subscribed_to("session.revoked"));

        let error = endpoint
            .replace_subscriptions(&["session.revoked", "webhooks.endpoint_removed"], NOW)
            .expect_err("refused");
        assert_eq!(error.code(), "webhooks.event_type_unknown");
        assert!(
            endpoint.is_subscribed_to("session.started"),
            "nothing changed"
        );

        endpoint
            .replace_subscriptions(&["session.revoked"], NOW)
            .expect("replaced");
        assert!(endpoint.is_subscribed_to("session.revoked"));
        assert!(!endpoint.is_subscribed_to("session.started"));
    }
}
