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
    /// GitHub, which issues no ID token and is asked through its own
    /// interface who a person is.
    GitHub,
    /// A directory reached over LDAP. Nobody leaves for it: Hodor asks
    /// it with what the person typed.
    Ldap,
    /// A SAML identity provider: Hodor is its service provider.
    Saml,
}

impl ProviderKind {
    /// The name used in storage, in events and in interfaces.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OpenIdConnect => "openid_connect",
            Self::GitHub => "github",
            Self::Ldap => "ldap",
            Self::Saml => "saml",
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
            "github" => Ok(Self::GitHub),
            "ldap" => Ok(Self::Ldap),
            "saml" => Ok(Self::Saml),
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

/// What only a directory has: where its people are and how one is found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectorySettings {
    /// Where people are searched for, such as `ou=people,dc=example,dc=com`.
    pub base: String,
    /// How a person is found, with `{identifier}` where what they typed
    /// goes, such as `(uid={identifier})`.
    pub filter: String,
    /// The attribute that never changes for a person.
    pub subject_attribute: String,
    /// The attribute holding the person's email address.
    pub email_attribute: String,
    /// The attribute holding the person's name.
    pub name_attribute: String,
}

/// Where what a person typed goes in a directory's filter.
pub(crate) const IDENTIFIER_PLACE: &str = "{identifier}";

impl DirectorySettings {
    /// The settings of a directory with the usual attribute names:
    /// `entryUUID`, `mail` and `cn`.
    #[must_use]
    pub fn new(base: &str, filter: &str) -> Self {
        Self {
            base: base.to_owned(),
            filter: filter.to_owned(),
            subject_attribute: "entryUUID".to_owned(),
            email_attribute: "mail".to_owned(),
            name_attribute: "cn".to_owned(),
        }
    }

    fn checked(mut self) -> Result<Self, DomainError> {
        let invalid =
            |what: &'static str| DomainError::invalid("federation.directory_invalid", what);
        self.base = self.base.trim().to_owned();
        self.filter = self.filter.trim().to_owned();
        let plain = |text: &str, longest: usize| {
            !text.is_empty()
                && text.chars().count() <= longest
                && !text.chars().any(char::is_control)
        };
        if !plain(&self.base, 255) {
            return Err(invalid("a directory's base is 1 to 255 characters"));
        }
        let wrapped = self.filter.starts_with('(') && self.filter.ends_with(')');
        if !plain(&self.filter, 512)
            || !wrapped
            || self.filter.matches(IDENTIFIER_PLACE).count() != 1
        {
            return Err(invalid(
                "a directory's filter is in parentheses and contains `{identifier}` exactly once",
            ));
        }
        for attribute in [
            &self.subject_attribute,
            &self.email_attribute,
            &self.name_attribute,
        ] {
            let bytes = attribute.as_bytes();
            let named = (1..=64).contains(&bytes.len())
                && bytes[0].is_ascii_alphabetic()
                && bytes
                    .iter()
                    .all(|b| b.is_ascii_alphanumeric() || *b == b'-');
            if !named {
                return Err(invalid(
                    "an attribute name is a letter followed by letters, digits and hyphens",
                ));
            }
        }
        Ok(self)
    }
}

/// What only a SAML identity provider has.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SamlSettings {
    /// Where the person is sent with the request: the identity provider's
    /// single sign-on address for the HTTP-Redirect binding.
    pub single_sign_on_address: String,
    /// The identity provider's signing certificate, in PEM or as the
    /// base64 its metadata carries.
    pub certificate: String,
    /// The attribute that carries the person's address.
    pub email_attribute: String,
    /// The attribute that carries the person's name.
    pub name_attribute: String,
}

impl SamlSettings {
    /// The settings of a SAML identity provider whose attributes are named
    /// `email` and `name`.
    #[must_use]
    pub fn new(single_sign_on_address: &str, certificate: &str) -> Self {
        Self {
            single_sign_on_address: single_sign_on_address.to_owned(),
            certificate: certificate.to_owned(),
            email_attribute: "email".to_owned(),
            name_attribute: "name".to_owned(),
        }
    }

    /// The key every response of this identity provider is checked with.
    ///
    /// # Errors
    ///
    /// Returns `federation.saml_invalid` if the certificate cannot be used.
    pub fn key(&self) -> Result<hodor_saml::IdentityProviderKey, DomainError> {
        hodor_saml::IdentityProviderKey::from_certificate(&self.certificate).map_err(|error| {
            DomainError::invalid("federation.saml_invalid", "the certificate cannot be used")
                .with_detail(error.reason())
        })
    }

    fn checked(mut self, development_hosts: &[String]) -> Result<Self, DomainError> {
        let invalid = |what: &'static str| DomainError::invalid("federation.saml_invalid", what);
        self.single_sign_on_address = self.single_sign_on_address.trim().to_owned();
        self.certificate = self.certificate.trim().to_owned();
        self.email_attribute = self.email_attribute.trim().to_owned();
        self.name_attribute = self.name_attribute.trim().to_owned();
        check_address(&self.single_sign_on_address, development_hosts).map_err(|_| {
            invalid("a single sign-on address is an HTTPS address without a fragment, at most 512 characters")
        })?;
        if self.certificate.len() > 16 * 1024 {
            return Err(invalid("a certificate is at most 16 kibibytes"));
        }
        self.key()?;
        for attribute in [&self.email_attribute, &self.name_attribute] {
            let named = (1..=255).contains(&attribute.chars().count())
                && !attribute
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace());
            if !named {
                return Err(invalid(
                    "an attribute name is 1 to 255 characters without spaces",
                ));
            }
        }
        Ok(self)
    }
}

/// A SAML entity identifier: an absolute address or a `urn:` name, at most
/// 512 characters, without spaces. It names the identity provider and is
/// never fetched, so plain HTTP is allowed. Kept exactly as given.
fn check_entity_id(issuer: &str) -> Result<(), DomainError> {
    let absolute = issuer
        .strip_prefix("https://")
        .or_else(|| issuer.strip_prefix("http://"))
        .is_some_and(|rest| !rest.is_empty() && !rest.starts_with('/'))
        || issuer
            .strip_prefix("urn:")
            .is_some_and(|rest| !rest.is_empty());
    let plain = issuer.len() <= 512
        && issuer
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'\\' | b'"' | b'<' | b'>'));
    if absolute && plain {
        Ok(())
    } else {
        Err(DomainError::invalid(
            "federation.issuer_invalid",
            "a SAML entity identifier is an absolute address or a `urn:` name, at most 512 characters",
        ))
    }
}

/// The host and port of a directory's address, as `host:port`, for
/// comparing with the installation's list. `None` if it is not an
/// address of a directory.
#[must_use]
pub fn directory_host(address: &str) -> Option<String> {
    let (rest, usual_port) = if let Some(rest) = address.strip_prefix("ldaps://") {
        (rest, 636)
    } else {
        (address.strip_prefix("ldap://")?, 389)
    };
    // Nothing after the host: no path, no query, no name and password.
    let plain = !rest.is_empty()
        && rest.len() <= 255
        && rest
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b':'));
    if !plain {
        return None;
    }
    let (host, port) = match rest.split_once(':') {
        Some((host, port)) => (host, port.parse::<u16>().ok().filter(|port| *port != 0)?),
        None => (rest, usual_port),
    };
    (!host.is_empty() && !host.contains(':'))
        .then(|| format!("{}:{port}", host.to_ascii_lowercase()))
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
    /// Whether every address the provider gives is taken as vouched for,
    /// even when the provider does not say so.
    pub trusts_email: bool,
    /// What only a directory has. There for the kind `ldap` and for no
    /// other.
    pub directory: Option<DirectorySettings>,
    /// What only a SAML identity provider has. There for the kind `saml`
    /// and for no other.
    pub saml: Option<SamlSettings>,
}

impl ProviderSettings {
    /// The scopes asked of an OpenID Connect provider unless said
    /// otherwise.
    #[must_use]
    pub fn default_scopes() -> Vec<String> {
        Self::default_scopes_for(ProviderKind::OpenIdConnect)
    }

    /// The scopes asked of a provider of this kind unless said otherwise.
    #[must_use]
    pub fn default_scopes_for(kind: ProviderKind) -> Vec<String> {
        match kind {
            ProviderKind::OpenIdConnect => {
                ["openid", "email", "profile"].map(str::to_owned).to_vec()
            }
            ProviderKind::GitHub => ["read:user", "user:email"].map(str::to_owned).to_vec(),
            ProviderKind::Ldap | ProviderKind::Saml => Vec::new(),
        }
    }

    /// The issuer of a provider of this kind when none is given, if the
    /// kind has one.
    #[must_use]
    pub const fn default_issuer_for(kind: ProviderKind) -> Option<&'static str> {
        match kind {
            ProviderKind::OpenIdConnect | ProviderKind::Ldap | ProviderKind::Saml => None,
            ProviderKind::GitHub => Some("https://github.com"),
        }
    }

    /// Checks every setting against its rule and tidies what may be
    /// tidied: the display name is trimmed, repeated scopes are dropped.
    ///
    /// # Errors
    ///
    /// Returns the `Invalid` error of the first rule that is broken.
    pub fn checked(self) -> Result<Self, DomainError> {
        self.checked_for(ProviderKind::OpenIdConnect, &[])
    }

    /// As [`ProviderSettings::checked_for`], for an OpenID Connect
    /// provider.
    ///
    /// # Errors
    ///
    /// Returns the `Invalid` error of the first rule that is broken.
    pub fn checked_allowing(self, development_hosts: &[String]) -> Result<Self, DomainError> {
        self.checked_for(ProviderKind::OpenIdConnect, development_hosts)
    }

    /// Checks the settings of a provider of `kind`, which decides what the
    /// scopes must include. The issuer may be
    /// plain HTTP when its host and port are one of `development_hosts`,
    /// such as `provider:9000`. For a development stack on one machine;
    /// the list is empty anywhere real.
    ///
    /// # Errors
    ///
    /// Returns the `Invalid` error of the first rule that is broken.
    pub fn checked_for(
        mut self,
        kind: ProviderKind,
        development_hosts: &[String],
    ) -> Result<Self, DomainError> {
        self.display_name = self.display_name.trim().to_owned();
        let name_length = self.display_name.chars().count();
        if !(1..=64).contains(&name_length) || self.display_name.chars().any(char::is_control) {
            return Err(DomainError::invalid(
                "federation.display_name_invalid",
                "a display name is 1 to 64 characters",
            ));
        }
        let is_directory = kind == ProviderKind::Ldap;
        let is_saml = kind == ProviderKind::Saml;
        if is_saml {
            check_entity_id(&self.issuer)?;
        } else if is_directory {
            // A directory's address: over TLS, or in the clear at a
            // development host only.
            let reachable = directory_host(&self.issuer).is_some_and(|host| {
                self.issuer.starts_with("ldaps://")
                    || development_hosts
                        .iter()
                        .any(|allowed| allowed.eq_ignore_ascii_case(&host))
            });
            if !reachable {
                return Err(DomainError::invalid(
                    "federation.issuer_invalid",
                    "a directory's address is `ldaps://host` or `ldaps://host:port`",
                ));
            }
        } else {
            check_issuer(&self.issuer, development_hosts)?;
        }
        let id_length = self.client_id.chars().count();
        // A SAML identity provider knows Hodor by an entity identifier
        // made from the alias, not by a client identifier.
        let lengths = if is_saml { 0..=0 } else { 1..=255 };
        if !lengths.contains(&id_length)
            || self
                .client_id
                .chars()
                // The name Hodor binds to a directory with may have spaces.
                .any(|c| c.is_control() || (c.is_whitespace() && !is_directory))
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
        // An OpenID Connect provider issues no ID token unless asked for
        // `openid`; other kinds have no scope that must be there.
        let needs_openid = kind == ProviderKind::OpenIdConnect;
        // A directory and a SAML identity provider are asked for nothing
        // by scope; every other kind is asked for something.
        if scopes.is_empty() != (is_directory || is_saml)
            || scopes.len() > MAX_SCOPES
            || (needs_openid && !scopes.iter().any(|scope| scope == "openid"))
        {
            return Err(scopes_invalid());
        }
        self.scopes = scopes;
        // What only a directory has is there for a directory and for
        // nothing else.
        self.directory = match (is_directory, self.directory) {
            (true, Some(directory)) => Some(directory.checked()?),
            (false, None) => None,
            _ => {
                return Err(DomainError::invalid(
                    "federation.directory_invalid",
                    "a directory has a base and a filter, and no other kind of provider has",
                ));
            }
        };
        self.saml = match (is_saml, self.saml) {
            (true, Some(saml)) => Some(saml.checked(development_hosts)?),
            (false, None) => None,
            _ => {
                return Err(DomainError::invalid(
                    "federation.saml_invalid",
                    "a SAML provider has a single sign-on address and a certificate, and no other kind of provider has",
                ));
            }
        };
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
    check_address(issuer, development_hosts)?;
    if issuer.contains('?') {
        return Err(issuer_invalid());
    }
    Ok(())
}

fn issuer_invalid() -> DomainError {
    DomainError::invalid(
        "federation.issuer_invalid",
        "an issuer is an HTTPS address without a query or a fragment, at most 512 characters",
    )
}

/// An HTTPS address with a host, without a name and password or a
/// fragment, at most 512 characters. Plain HTTP for a development host only.
fn check_address(issuer: &str, development_hosts: &[String]) -> Result<(), DomainError> {
    let invalid = issuer_invalid;
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
        && issuer
            .bytes()
            .all(|b| b.is_ascii_graphic() && !matches!(b, b'#' | b'\\' | b'"' | b'<' | b'>'));
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
                settings: settings.checked_for(kind, development_hosts)?,
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
        let settings = settings.checked_for(self.state.kind, development_hosts)?;
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
            trusts_email: false,
            directory: None,
            saml: None,
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
    fn what_scopes_must_include_depends_on_the_kind() {
        let with = |scopes: &[&str], kind| {
            let mut given = settings();
            given.scopes = scopes.iter().map(|scope| (*scope).to_owned()).collect();
            given.checked_for(kind, &[])
        };
        assert!(with(&["read:user", "user:email"], ProviderKind::GitHub).is_ok());
        assert!(with(&["read:user", "user:email"], ProviderKind::OpenIdConnect).is_err());
        assert!(with(&[], ProviderKind::GitHub).is_err(), "no scopes at all");
        assert_eq!(
            ProviderSettings::default_scopes_for(ProviderKind::GitHub),
            ["read:user", "user:email"]
        );
        assert_eq!(
            ProviderSettings::default_issuer_for(ProviderKind::GitHub),
            Some("https://github.com")
        );
        assert_eq!(
            ProviderSettings::default_issuer_for(ProviderKind::OpenIdConnect),
            None
        );
        for kind in [ProviderKind::OpenIdConnect, ProviderKind::GitHub] {
            assert_eq!(
                ProviderKind::from_stored(kind.as_str()).expect("known"),
                kind
            );
        }
    }

    fn directory(
        issuer: &str,
        directory: DirectorySettings,
    ) -> Result<ProviderSettings, DomainError> {
        ProviderSettings {
            display_name: "Company".to_owned(),
            issuer: issuer.to_owned(),
            client_id: "cn=hodor,ou=services,dc=example,dc=com".to_owned(),
            scopes: Vec::new(),
            creates_users: true,
            trusts_email: false,
            directory: Some(directory),
            saml: None,
        }
        .checked_for(ProviderKind::Ldap, &["ldap.dev:389".to_owned()])
    }

    #[test]
    fn a_directory_is_held_to_its_rules() {
        let good = DirectorySettings::new("ou=people,dc=example,dc=com", "(uid={identifier})");
        let checked = directory("ldaps://ldap.example.com", good.clone()).expect("valid");
        // A name to bind with may have spaces.
        assert!(checked.client_id.contains(','));
        assert!(directory("ldaps://ldap.example.com:3269", good.clone()).is_ok());
        // In the clear only at a development host.
        assert!(directory("ldap://ldap.dev:389", good.clone()).is_ok());
        assert!(directory("ldap://ldap.dev", good.clone()).is_ok());
        for issuer in [
            "ldap://ldap.example.com",
            "https://ldap.example.com",
            "ldaps://",
            "ldaps://ldap.example.com/dc=example",
            "ldaps://user:password@ldap.example.com",
            "ldaps://ldap.example.com:0",
            "ldaps://ldap.example.com:99999",
        ] {
            let error = directory(issuer, good.clone()).expect_err(issuer);
            assert_eq!(error.code(), "federation.issuer_invalid", "{issuer}");
        }
        let broken = |change: fn(&mut DirectorySettings)| -> String {
            let mut given = good.clone();
            change(&mut given);
            directory("ldaps://ldap.example.com", given)
                .expect_err("broken")
                .code()
                .to_owned()
        };
        for change in [
            (|d: &mut DirectorySettings| d.base = String::new()) as fn(&mut DirectorySettings),
            |d| d.filter = "uid={identifier}".to_owned(),
            |d| d.filter = "(uid=ana)".to_owned(),
            |d| d.filter = "(|(uid={identifier})(mail={identifier}))".to_owned(),
            |d| d.subject_attribute = "entry UUID".to_owned(),
            |d| d.email_attribute = "1mail".to_owned(),
            |d| d.name_attribute = String::new(),
        ] {
            assert_eq!(broken(change), "federation.directory_invalid");
        }
        // Scopes are for other kinds; a directory's settings are for a directory.
        let mut with_scopes = directory("ldaps://ldap.example.com", good.clone()).expect("valid");
        with_scopes.scopes = vec!["openid".to_owned()];
        assert!(with_scopes.checked_for(ProviderKind::Ldap, &[]).is_err());
        let mut not_a_directory = settings();
        not_a_directory.directory = Some(good);
        assert_eq!(
            not_a_directory
                .checked()
                .expect_err("not a directory")
                .code(),
            "federation.directory_invalid"
        );
    }

    fn saml_settings(issuer: &str, certificate: &str) -> Result<ProviderSettings, DomainError> {
        ProviderSettings {
            display_name: "Corp".to_owned(),
            issuer: issuer.to_owned(),
            client_id: String::new(),
            scopes: Vec::new(),
            creates_users: true,
            trusts_email: false,
            directory: None,
            saml: Some(SamlSettings::new(
                "https://idp.example.com/sso",
                certificate,
            )),
        }
        .checked_for(ProviderKind::Saml, &[])
    }

    #[test]
    fn a_saml_provider_is_held_to_its_rules() {
        let identity_provider = hodor_saml::testing::TestIdentityProvider::rsa("urn:corp");
        let certificate = identity_provider.certificate_pem();
        // An entity identifier names the provider and is never fetched.
        for issuer in [
            "https://sts.windows.net/8d6a2b6e/",
            "http://www.okta.com/exk1a2b3c4",
            "http://adfs.example.com/adfs/services/trust",
            "urn:example:idp",
        ] {
            assert_eq!(
                saml_settings(issuer, certificate).expect(issuer).issuer,
                issuer
            );
        }
        for issuer in [
            "",
            "urn:",
            "idp.example.com",
            "https://",
            "https://a b",
            "ftp://idp",
        ] {
            let error = saml_settings(issuer, certificate).expect_err(issuer);
            assert_eq!(error.code(), "federation.issuer_invalid", "{issuer}");
        }
        let error = saml_settings("urn:corp", "not a certificate").expect_err("certificate");
        assert_eq!(error.code(), "federation.saml_invalid");
        assert_eq!(error.detail(), Some("certificate_unreadable"));

        let broken = |change: fn(&mut ProviderSettings)| {
            let mut given = saml_settings("urn:corp", certificate).expect("valid");
            change(&mut given);
            given
                .checked_for(ProviderKind::Saml, &[])
                .expect_err("broken")
                .code()
                .to_owned()
        };
        assert_eq!(
            broken(|s| s.client_id = "hodor".to_owned()),
            "federation.client_id_invalid"
        );
        assert_eq!(
            broken(|s| s.scopes = vec!["openid".to_owned()]),
            "federation.scopes_invalid"
        );
        assert_eq!(broken(|s| s.saml = None), "federation.saml_invalid");
        for address in [
            "http://idp.example.com/sso",
            "https://idp.example.com/sso#x",
            "idp",
        ] {
            let mut given = saml_settings("urn:corp", certificate).expect("valid");
            if let Some(saml) = given.saml.as_mut() {
                address.clone_into(&mut saml.single_sign_on_address);
            }
            let error = given
                .checked_for(ProviderKind::Saml, &[])
                .expect_err(address);
            assert_eq!(error.code(), "federation.saml_invalid", "{address}");
        }
        // A query is kept: some identity providers name the application there.
        let mut with_query = saml_settings("urn:corp", certificate).expect("valid");
        if let Some(saml) = with_query.saml.as_mut() {
            saml.single_sign_on_address = "https://idp.example.com/sso?app=hodor".to_owned();
        }
        assert!(with_query.checked_for(ProviderKind::Saml, &[]).is_ok());
        // SAML settings belong to a SAML provider only.
        let mut not_saml = settings();
        not_saml.saml = saml_settings("urn:corp", certificate).expect("valid").saml;
        assert_eq!(
            not_saml.checked().expect_err("not SAML").code(),
            "federation.saml_invalid"
        );
    }

    #[test]
    fn a_directory_address_names_its_host_and_port() {
        assert_eq!(
            directory_host("ldaps://LDAP.Example.com").as_deref(),
            Some("ldap.example.com:636")
        );
        assert_eq!(
            directory_host("ldap://ldap.example.com").as_deref(),
            Some("ldap.example.com:389")
        );
        assert_eq!(
            directory_host("ldaps://10.0.0.5:3269").as_deref(),
            Some("10.0.0.5:3269")
        );
        for address in [
            "https://ldap.example.com",
            "ldaps://",
            "ldaps://host/path",
            "ldaps://a:b:c",
        ] {
            assert_eq!(directory_host(address), None, "{address}");
        }
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
