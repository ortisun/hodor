//! Resource servers: the interfaces that accept Hodor's access tokens, and
//! the scopes they define.

use crate::domain::application::ApplicationId;
use crate::domain::event::OauthEvent;
use crate::domain::text;
use hodor_kernel::{DomainError, Timestamp};

hodor_kernel::define_id!(
    /// Identifies a resource server.
    ResourceServerId
);

/// The longest audience.
const MAX_AUDIENCE_LENGTH: usize = 255;
/// The most scopes a resource server may define.
pub(crate) const MAX_RESOURCE_SCOPES: usize = 100;
/// The longest description of a scope.
const MAX_DESCRIPTION_LENGTH: usize = 200;
/// The scopes OpenID Connect defines, which no resource server may.
pub const OPENID_SCOPES: [&str; 6] = [
    "openid",
    "profile",
    "email",
    "address",
    "phone",
    "offline_access",
];

/// The audience of a resource server: an absolute address, `https://…` or
/// `urn:…`, kept exactly as given.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Audience(String);

impl Audience {
    /// Reads an audience.
    ///
    /// # Errors
    ///
    /// Returns `oauth.audience_invalid` unless the value is an `https://`
    /// address with a host or a `urn:` name, without a fragment, at most
    /// 255 printable ASCII characters.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let shaped = value.len() <= MAX_AUDIENCE_LENGTH
            && value.bytes().all(|b| b.is_ascii_graphic())
            && !value.contains('#')
            && !value.contains('\\')
            && (value.strip_prefix("https://").is_some_and(|rest| {
                let host = rest.split(['/', '?']).next().unwrap_or_default();
                !host.is_empty() && !host.contains('@')
            }) || value
                .strip_prefix("urn:")
                .is_some_and(|rest| rest.contains(':') && !rest.starts_with(':')));
        if shaped {
            Ok(Self(value.to_owned()))
        } else {
            Err(DomainError::invalid(
                "oauth.audience_invalid",
                "an audience is an `https://` address or a `urn:` name without a fragment, at \
                 most 255 characters",
            ))
        }
    }

    /// The audience as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A scope a resource server defines.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScopeDefinition {
    /// The scope, as clients ask for it.
    pub name: String,
    /// What it lets a client do, for the consent page.
    pub description: String,
}

/// What an administrator decides about a resource server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceServerSettings {
    /// For administrators and the consent page.
    pub name: String,
    /// The scopes it defines, in order.
    pub scopes: Vec<ScopeDefinition>,
}

fn scopes_invalid(reason: &'static str) -> DomainError {
    DomainError::invalid(
        "oauth.resource_scope_invalid",
        "a resource server defines at most 100 scopes, each named once, written as OAuth \
         writes a scope, none of the scopes of OpenID Connect, with a description of at most \
         200 characters",
    )
    .with_detail(reason)
}

impl ResourceServerSettings {
    fn checked(self) -> Result<Self, DomainError> {
        let name = text::name(&self.name, "oauth.resource_server_name_invalid")?;
        if self.scopes.len() > MAX_RESOURCE_SCOPES {
            return Err(scopes_invalid("too many scopes"));
        }
        let mut scopes: Vec<ScopeDefinition> = Vec::with_capacity(self.scopes.len());
        for scope in self.scopes {
            if !text::is_scope(&scope.name) {
                return Err(scopes_invalid("a scope is not written as OAuth writes one"));
            }
            if OPENID_SCOPES.contains(&scope.name.as_str()) {
                return Err(scopes_invalid("a scope of OpenID Connect"));
            }
            if scopes.iter().any(|kept| kept.name == scope.name) {
                return Err(scopes_invalid("a scope is named twice"));
            }
            let description = scope.description.trim();
            if description.chars().count() > MAX_DESCRIPTION_LENGTH
                || description.chars().any(char::is_control)
            {
                return Err(scopes_invalid(
                    "a description is too long or has a control character",
                ));
            }
            scopes.push(ScopeDefinition {
                name: scope.name,
                description: description.to_owned(),
            });
        }
        Ok(Self { name, scopes })
    }
}

/// Everything stored about a resource server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceServerSnapshot {
    /// Its identifier.
    pub id: ResourceServerId,
    /// The application that exposes it. Never changes.
    pub application_id: ApplicationId,
    /// The audience of its tokens. Never changes.
    pub audience: Audience,
    /// What an administrator decided about it.
    pub settings: ResourceServerSettings,
    /// When it was registered.
    pub created_at: Timestamp,
    /// When it was last changed.
    pub updated_at: Timestamp,
    /// Incremented on every stored change, for optimistic locking.
    pub version: u32,
}

/// A resource server of a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceServer {
    state: ResourceServerSnapshot,
}

impl ResourceServer {
    /// A new resource server.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error if a setting breaks its rule.
    pub fn create(
        application_id: ApplicationId,
        audience: Audience,
        settings: ResourceServerSettings,
        now: Timestamp,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            state: ResourceServerSnapshot {
                id: ResourceServerId::generate(),
                application_id,
                audience,
                settings: settings.checked()?,
                created_at: now,
                updated_at: now,
                version: 0,
            },
        })
    }

    /// Rebuilds a resource server from storage.
    #[must_use]
    pub const fn from_snapshot(state: ResourceServerSnapshot) -> Self {
        Self { state }
    }

    /// Everything stored about it.
    #[must_use]
    pub const fn snapshot(&self) -> &ResourceServerSnapshot {
        &self.state
    }

    /// Its identifier.
    #[must_use]
    pub const fn id(&self) -> ResourceServerId {
        self.state.id
    }

    /// The audience of its tokens.
    #[must_use]
    pub const fn audience(&self) -> &Audience {
        &self.state.audience
    }

    /// Whether it defines `scope`.
    #[must_use]
    pub fn defines(&self, scope: &str) -> bool {
        self.state.settings.scopes.iter().any(|s| s.name == scope)
    }

    /// The event that says it was registered.
    #[must_use]
    pub fn created_event(&self) -> OauthEvent {
        OauthEvent::ResourceServerCreated {
            resource_server_id: self.state.id,
            audience: self.state.audience.as_str().to_owned(),
        }
    }

    /// Replaces the name and the scopes. Returns the event if anything
    /// changed.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error if a setting breaks its rule; nothing
    /// changes then.
    pub fn change(
        &mut self,
        settings: ResourceServerSettings,
        now: Timestamp,
    ) -> Result<Option<OauthEvent>, DomainError> {
        let settings = settings.checked()?;
        if settings == self.state.settings {
            return Ok(None);
        }
        self.state.settings = settings;
        self.state.updated_at = now;
        Ok(Some(OauthEvent::ResourceServerChanged {
            resource_server_id: self.state.id,
            audience: self.state.audience.as_str().to_owned(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn scope(name: &str) -> ScopeDefinition {
        ScopeDefinition {
            name: name.to_owned(),
            description: format!("  lets a client {name}  "),
        }
    }

    fn settings(scopes: Vec<ScopeDefinition>) -> ResourceServerSettings {
        ResourceServerSettings {
            name: "Payroll interface".to_owned(),
            scopes,
        }
    }

    #[test]
    fn an_audience_is_an_https_address_or_a_urn() {
        for good in [
            "https://api.payroll.example.com",
            "https://api.example.com/payroll/v1",
            "urn:example:payroll",
        ] {
            assert_eq!(Audience::parse(good).expect(good).as_str(), good);
        }
        for bad in [
            "",
            "http://api.example.com",
            "https://",
            "https://user@api.example.com",
            "https://api.example.com/#part",
            "urn:",
            "urn::x",
            "urn:example",
            "payroll",
            "https://api.example.com/a b",
            &format!("https://api.example.com/{}", "a".repeat(255)),
        ] {
            assert_eq!(
                Audience::parse(bad).expect_err(bad).code(),
                "oauth.audience_invalid",
                "{bad}"
            );
        }
    }

    #[test]
    fn scopes_are_held_to_their_rules() {
        let audience = Audience::parse("https://api.example.com").expect("valid");
        let server = ResourceServer::create(
            ApplicationId::generate(),
            audience.clone(),
            settings(vec![scope("read"), scope("write")]),
            NOW,
        )
        .expect("valid");
        assert!(server.defines("read"));
        assert!(!server.defines("delete"));
        assert_eq!(
            server.snapshot().settings.scopes[0].description,
            "lets a client read"
        );

        let mut long = scope("read");
        long.description = "x".repeat(201);
        for bad in [
            vec![scope("read"), scope("read")],
            vec![scope("openid")],
            vec![scope("offline_access")],
            vec![scope("two words")],
            vec![scope("")],
            vec![long],
            (0..101).map(|n| scope(&format!("s{n}"))).collect(),
        ] {
            let error = ResourceServer::create(
                ApplicationId::generate(),
                audience.clone(),
                settings(bad),
                NOW,
            )
            .expect_err("refused");
            assert_eq!(error.code(), "oauth.resource_scope_invalid");
        }
    }

    #[test]
    fn a_change_says_whether_it_changed_anything() {
        let mut server = ResourceServer::create(
            ApplicationId::generate(),
            Audience::parse("urn:example:payroll").expect("valid"),
            settings(vec![scope("read")]),
            NOW,
        )
        .expect("valid");
        assert!(
            server
                .change(settings(vec![scope("read")]), NOW)
                .expect("same")
                .is_none()
        );
        assert!(
            server
                .change(settings(vec![scope("read"), scope("write")]), NOW)
                .expect("changed")
                .is_some()
        );
        let mut nameless = settings(vec![]);
        nameless.name = String::new();
        assert_eq!(
            server.change(nameless, NOW).expect_err("name").code(),
            "oauth.resource_server_name_invalid"
        );
        assert!(server.defines("write"));
    }
}
