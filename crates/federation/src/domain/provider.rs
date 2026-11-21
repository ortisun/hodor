//! Identity providers: who a tenant trusts to vouch for people.

use hodor_kernel::{DomainError, SealedSecret, Timestamp};

hodor_kernel::define_id!(
    /// Identifies an identity provider of a tenant.
    ProviderId
);

/// The most identity providers a tenant may have.
pub(crate) const MAX_PROVIDERS: usize = 20;
const MAX_SCOPES: usize = 16;

/// The name of a provider in addresses. It never changes: it is part of
/// the address registered at the provider.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Alias(String);

impl Alias {
    /// Checks and wraps an alias: 2 to 32 lowercase letters, digits and
    /// hyphens, starting with a letter or digit.
    ///
    /// # Errors
    ///
    /// Returns `federation.alias_invalid`.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let bytes = value.as_bytes();
        let valid = (2..=32).contains(&bytes.len())
            && bytes[0].is_ascii_alphanumeric()
            && bytes
                .iter()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || *b == b'-');
        if valid {
            Ok(Self(value.to_owned()))
        } else {
            Err(DomainError::invalid(
                "federation.alias_invalid",
                "an alias is 2 to 32 lowercase letters, digits and hyphens, starting with a letter or digit",
            ))
        }
    }

    /// The alias as text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// How Hodor talks to a provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderKind {
    /// An OpenID Connect provider.
    OpenIdConnect,
}

impl ProviderKind {
    /// The name used in storage, in events and in interfaces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenIdConnect => "openid_connect",
        }
    }

    /// Reads a stored kind.
    ///
    /// # Errors
    ///
    /// Returns an internal error for a name this version does not know.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "openid_connect" => Ok(Self::OpenIdConnect),
            _ => Err(stored_data_invalid()),
        }
    }
}

/// Whether a provider signs people in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderStatus {
    /// Offered, and signs people in.
    Enabled,
    /// Not offered, and signs nobody in. Its links are kept.
    Disabled,
}

impl ProviderStatus {
    /// The name used in storage and in interfaces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }

    /// Reads a stored status.
    ///
    /// # Errors
    ///
    /// Returns an internal error for a name this version does not know.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "enabled" => Ok(Self::Enabled),
            "disabled" => Ok(Self::Disabled),
            _ => Err(stored_data_invalid()),
        }
    }
}

fn stored_data_invalid() -> DomainError {
    DomainError::internal(
        "federation.stored_data_invalid",
        "a stored identity provider could not be read",
    )
}

/// What an administrator decides about a provider, apart from its alias,
/// its kind and its secret. Checked as a whole: a provider never holds a
/// setting that breaks a rule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSettings {
    /// What a person reads on the sign-in page.
    pub display_name: String,
    /// The address that identifies the provider.
    pub issuer: String,
    /// Who Hodor is to the provider.
    pub client_id: String,
    /// What Hodor asks the provider for.
    pub scopes: Vec<String>,
    /// Whether a person nobody knows yet is created on first sign-in.
    pub creates_users: bool,
}

impl ProviderSettings {
    /// The scopes asked for unless said otherwise.
    #[must_use]
    pub fn default_scopes() -> Vec<String> {
        ["openid", "email", "profile"].map(str::to_owned).to_vec()
    }

    /// Checks every setting against its rule and tidies what may be
    /// tidied: the display name is trimmed, repeated scopes are dropped.
    ///
    /// # Errors
    ///
    /// Returns the `Invalid` error of the first rule that is broken.
    pub fn checked(self) -> Result<Self, DomainError> {
        self.checked_allowing(&[])
    }

    /// As [`ProviderSettings::checked`], except that the issuer may be
    /// plain HTTP when its host and port are one of `development_hosts`,
    /// such as `provider:9000`. For a development stack on one machine;
    /// the list is empty anywhere real.
    ///
    /// # Errors
    ///
    /// Returns the `Invalid` error of the first rule that is broken.
    pub fn checked_allowing(mut self, development_hosts: &[String]) -> Result<Self, DomainError> {
        self.display_name = self.display_name.trim().to_owned();
        let name_length = self.display_name.chars().count();
        if !(1..=64).contains(&name_length) || self.display_name.chars().any(char::is_control) {
            return Err(DomainError::invalid(
                "federation.display_name_invalid",
                "a display name is 1 to 64 characters",
            ));
        }
        check_issuer(&self.issuer, development_hosts)?;
        let id_length = self.client_id.chars().count();
        if !(1..=255).contains(&id_length)
            || self
                .client_id
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(DomainError::invalid(
                "federation.client_id_invalid",
                "a client identifier is 1 to 255 characters without spaces",
            ));
        }
        let mut scopes: Vec<String> = Vec::new();
        for scope in self.scopes {
            // The characters a scope may have, from RFC 6749, section 3.3.
            let well_formed = !scope.is_empty()
                && scope.len() <= 128
                && scope
                    .bytes()
                    .all(|b| b == 0x21 || (0x23..=0x5b).contains(&b) || (0x5d..=0x7e).contains(&b));
            if !well_formed {
                return Err(scopes_invalid());
            }
            if !scopes.contains(&scope) {
                scopes.push(scope);
            }
        }
        if scopes.len() > MAX_SCOPES || !scopes.iter().any(|scope| scope == "openid") {
            return Err(scopes_invalid());
        }
        self.scopes = scopes;
        Ok(self)
    }
}

fn scopes_invalid() -> DomainError {
    DomainError::invalid(
        "federation.scopes_invalid",
        "scopes include `openid`, number at most 16 and contain no spaces",
    )
}

/// Whether `address` is plain HTTP to exactly one of the development
/// hosts, each written as `host:port`.
#[must_use]
pub(crate) fn is_development_address(address: &str, development_hosts: &[String]) -> bool {
    let Some(rest) = address.strip_prefix("http://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    // A port that is left out is the one plain HTTP uses.
    let named = if authority.contains(':') {
        authority.to_owned()
    } else {
        format!("{authority}:80")
    };
    development_hosts
        .iter()
        .any(|host| host.eq_ignore_ascii_case(&named))
}

/// An issuer is an HTTPS address with a host, without a name and
/// password, a query or a fragment. It is kept exactly as given, since it
/// is compared character by character with what the provider says. Plain
/// HTTP is accepted for a development host only.
fn check_issuer(issuer: &str, development_hosts: &[String]) -> Result<(), DomainError> {
    let invalid = || {
        DomainError::invalid(
            "federation.issuer_invalid",
            "an issuer is an HTTPS address without a query or a fragment, at most 512 characters",
        )
    };
    let rest = match issuer.strip_prefix("https://") {
        Some(rest) => rest,
        None if is_development_address(issuer, development_hosts) => {
            issuer.strip_prefix("http://").ok_or_else(invalid)?
        }
        None => return Err(invalid()),
    };
    let host = rest.split('/').next().unwrap_or_default();
    let plain = issuer.len() <= 512
        && !host.is_empty()
        && !host.contains('@')
        && issuer.bytes().all(|b| {
            b.is_ascii_graphic() && !matches!(b, b'?' | b'#' | b'\\' | b'"' | b'<' | b'>')
        });
    if plain { Ok(()) } else { Err(invalid()) }
}

/// Everything about a provider, for storage and for reading.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderSnapshot {
    /// The provider's identifier.
    pub id: ProviderId,
    /// Its name in addresses.
    pub alias: Alias,
    /// How Hodor talks to it.
    pub kind: ProviderKind,
    /// What an administrator decided about it.
    pub settings: ProviderSettings,
    /// The client secret, sealed.
    pub client_secret: SealedSecret,
    /// Whether it signs people in.
    pub status: ProviderStatus,
    /// When it was added.
    pub created_at: Timestamp,
    /// When it was last changed.
    pub updated_at: Timestamp,
    /// Incremented on every stored change, for optimistic locking.
    pub version: u32,
}

/// An identity provider of a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdentityProvider {
    state: ProviderSnapshot,
}

impl IdentityProvider {
    /// A new provider, enabled. With `development_hosts`, the issuer may
    /// be plain HTTP at one of them; see
    /// [`ProviderSettings::checked_allowing`].
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error if a setting breaks its rule.
    pub fn create(
        alias: Alias,
        kind: ProviderKind,
        settings: ProviderSettings,
        client_secret: SealedSecret,
        development_hosts: &[String],
        now: Timestamp,
    ) -> Result<Self, DomainError> {
        Ok(Self {
            state: ProviderSnapshot {
                id: ProviderId::generate(),
                alias,
                kind,
                settings: settings.checked_allowing(development_hosts)?,
                client_secret,
                status: ProviderStatus::Enabled,
                created_at: now,
                updated_at: now,
                version: 0,
            },
        })
    }

    /// Rebuilds a provider from stored state.
    #[must_use]
    pub const fn from_snapshot(state: ProviderSnapshot) -> Self {
        Self { state }
    }

    /// The provider's state, for storage and for reading.
    #[must_use]
    pub const fn snapshot(&self) -> &ProviderSnapshot {
        &self.state
    }

    /// The provider's identifier.
    #[must_use]
    pub const fn id(&self) -> ProviderId {
        self.state.id
    }

    /// The provider's name in addresses.
    #[must_use]
    pub const fn alias(&self) -> &Alias {
        &self.state.alias
    }

    /// Whether the provider signs people in.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.state.status == ProviderStatus::Enabled
    }

    /// Replaces the settings. Returns whether anything changed.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error if a setting breaks its rule; the
    /// provider is then unchanged.
    pub fn change(
        &mut self,
        settings: ProviderSettings,
        development_hosts: &[String],
        now: Timestamp,
    ) -> Result<bool, DomainError> {
        let settings = settings.checked_allowing(development_hosts)?;
        if settings == self.state.settings {
            return Ok(false);
        }
        self.state.settings = settings;
        self.state.updated_at = now;
        Ok(true)
    }

    /// Replaces the sealed client secret.
    pub fn change_secret(&mut self, client_secret: SealedSecret, now: Timestamp) {
        self.state.client_secret = client_secret;
        self.state.updated_at = now;
    }

    /// Sets the status. Returns whether anything changed.
    pub fn set_status(&mut self, status: ProviderStatus, now: Timestamp) -> bool {
        if self.state.status == status {
            return false;
        }
        self.state.status = status;
        self.state.updated_at = now;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> ProviderSettings {
        ProviderSettings {
            display_name: "Example".to_owned(),
            issuer: "https://accounts.example.com".to_owned(),
            client_id: "hodor".to_owned(),
            scopes: ProviderSettings::default_scopes(),
            creates_users: true,
        }
    }

    #[test]
    fn aliases_are_checked_strictly() {
        for valid in ["go", "google", "entra-id", "9lives", &"a".repeat(32)] {
            assert!(Alias::parse(valid).is_ok(), "{valid}");
        }
        for invalid in [
            "",
            "g",
            "-google",
            "Google",
            "goo gle",
            "goo_gle",
            "goo/gle",
            "é1",
            &"a".repeat(33),
        ] {
            let error = Alias::parse(invalid).expect_err(invalid);
            assert_eq!(error.code(), "federation.alias_invalid");
        }
    }

    #[test]
    fn settings_that_follow_the_rules_are_kept_and_tidied() {
        let mut given = settings();
        given.display_name = "  Example  ".to_owned();
        given.scopes = vec!["openid".into(), "email".into(), "openid".into()];
        let checked = given.checked().expect("valid");
        assert_eq!(checked.display_name, "Example");
        assert_eq!(checked.scopes, ["openid", "email"]);
    }

    #[test]
    fn every_setting_is_held_to_its_rule() {
        let broken = |change: fn(&mut ProviderSettings), code: &str| {
            let mut given = settings();
            change(&mut given);
            assert_eq!(given.checked().expect_err(code).code(), code);
        };
        broken(
            |s| s.display_name = "   ".into(),
            "federation.display_name_invalid",
        );
        broken(
            |s| s.display_name = "a".repeat(65),
            "federation.display_name_invalid",
        );
        broken(
            |s| s.display_name = "line\nbreak".into(),
            "federation.display_name_invalid",
        );
        broken(
            |s| s.client_id = String::new(),
            "federation.client_id_invalid",
        );
        broken(
            |s| s.client_id = "has space".into(),
            "federation.client_id_invalid",
        );
        broken(
            |s| s.client_id = "a".repeat(256),
            "federation.client_id_invalid",
        );
        broken(
            |s| s.scopes = vec!["email".into()],
            "federation.scopes_invalid",
        );
        broken(
            |s| s.scopes = vec!["openid".into(), "two words".into()],
            "federation.scopes_invalid",
        );
        broken(
            |s| s.scopes = vec!["openid".into(), String::new()],
            "federation.scopes_invalid",
        );
        broken(
            |s| {
                s.scopes = (0..17)
                    .map(|n| format!("openid{n}"))
                    .chain(["openid".to_owned()])
                    .collect()
            },
            "federation.scopes_invalid",
        );
        for issuer in [
            "",
            "http://accounts.example.com",
            "accounts.example.com",
            "https://",
            "https:///path",
            "https://user:password@example.com",
            "https://example.com?x=1",
            "https://example.com/#fragment",
            "https://example.com/with space",
            "https://example.com/\u{e9}",
            "javascript:alert(1)",
        ] {
            let mut given = settings();
            given.issuer = issuer.to_owned();
            assert_eq!(
                given.checked().expect_err(issuer).code(),
                "federation.issuer_invalid",
                "{issuer}"
            );
        }
        let mut long = settings();
        long.issuer = format!("https://example.com/{}", "a".repeat(500));
        assert!(long.checked().is_err());
    }

    #[test]
    fn a_plain_http_issuer_is_accepted_only_at_a_development_host() {
        let hosts = ["provider:9000".to_owned(), "localhost:80".to_owned()];
        let with = |issuer: &str, hosts: &[String]| {
            let mut given = settings();
            given.issuer = issuer.to_owned();
            given.checked_allowing(hosts)
        };
        for issuer in [
            "http://provider:9000",
            "http://provider:9000/realms/acme",
            "http://PROVIDER:9000",
            // A port that is left out is the one plain HTTP uses.
            "http://localhost",
            "http://localhost/path",
        ] {
            assert!(with(issuer, &hosts).is_ok(), "{issuer}");
        }
        for issuer in [
            // Another port, another host, a host that only starts the same.
            "http://provider:9001",
            "http://provider",
            "http://other:9000",
            "http://provider:9000.evil.example",
            "http://provider:9000@evil.example",
            "http://evil.example/provider:9000",
            "http://evil.example?provider:9000",
            "http://localhost:8080",
        ] {
            let error = with(issuer, &hosts).expect_err(issuer);
            assert_eq!(error.code(), "federation.issuer_invalid", "{issuer}");
        }
        // And nowhere at all when the list is empty, as it is anywhere real.
        assert!(with("http://provider:9000", &[]).is_err());
        assert!(with("https://accounts.example.com", &hosts).is_ok());
    }

    #[test]
    fn an_issuer_is_kept_exactly_as_given() {
        for issuer in [
            "https://accounts.example.com",
            "https://accounts.example.com/",
            "https://login.example.com/tenant-1/v2.0",
            "https://EXAMPLE.com:8443/realms/acme",
        ] {
            let mut given = settings();
            given.issuer = issuer.to_owned();
            assert_eq!(given.checked().expect("valid").issuer, issuer);
        }
    }

    #[test]
    fn a_provider_says_whether_a_change_changed_anything() {
        let now = Timestamp::UNIX_EPOCH;
        let later = now + time::Duration::minutes(1);
        let sealed = SealedSecret::from_stored(vec![1, 2, 3]);
        let mut provider = IdentityProvider::create(
            Alias::parse("example").expect("alias"),
            ProviderKind::OpenIdConnect,
            settings(),
            sealed,
            &[],
            now,
        )
        .expect("provider");
        assert!(provider.is_enabled());

        assert!(
            !provider
                .change(settings(), &[], later)
                .expect("same settings")
        );
        assert_eq!(provider.snapshot().updated_at, now);

        let mut renamed = settings();
        renamed.display_name = "Another name".to_owned();
        assert!(provider.change(renamed, &[], later).expect("change"));
        assert_eq!(provider.snapshot().updated_at, later);

        let mut broken = settings();
        broken.issuer = "http://insecure.example.com".to_owned();
        assert!(provider.change(broken, &[], later).is_err());
        assert_eq!(provider.snapshot().settings.display_name, "Another name");

        assert!(provider.set_status(ProviderStatus::Disabled, later));
        assert!(!provider.set_status(ProviderStatus::Disabled, later));
        assert!(!provider.is_enabled());
    }
}
