//! Pairwise subject identifiers: a client's subject type, its sector, the
//! sector identifier address that may name it, and the identifiers a
//! pairwise client knows a person and a session by.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Pairwise subject
//! identifiers", and Decision 0040.

use crate::domain::backchannel::check_backchannel_logout_uri;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::{DomainError, RandomSource, Secret, TenantId};
use serde_json::Value;

/// The purpose a tenant's pairwise secret is sealed for.
pub const PAIRWISE_SECRET_PURPOSE: &str = "oauth.pairwise_secret";

/// How many bytes a pairwise secret has.
pub const PAIRWISE_SECRET_BYTES: usize = 32;

/// The longest sector identifier address.
pub const MAX_SECTOR_IDENTIFIER_URI_LENGTH: usize = crate::domain::client::MAX_REDIRECT_URI_LENGTH;

/// The largest sector identifier document Hodor reads, in bytes.
pub const MAX_SECTOR_DOCUMENT_BYTES: usize = 64 * 1024;

/// How long fetching a sector identifier document may take.
pub const SECTOR_DOCUMENT_TIME_LIMIT: std::time::Duration = std::time::Duration::from_secs(10);

/// What the message of a `sub` starts with.
const SUBJECT_USE: &[u8] = b"hodor.pairwise.sub";

/// What the message of a `sid` starts with.
const SESSION_USE: &[u8] = b"hodor.pairwise.sid";

/// HMAC-SHA-256.
///
/// A port, because Hodor implements no cryptography of its own; the
/// crypto adapter implements it.
pub trait HmacSha256: Send + Sync {
    /// The HMAC-SHA-256 of `message` under `key`.
    fn mac(&self, key: &[u8], message: &[u8]) -> [u8; 32];
}

/// How a client knows a person: its `subject_type` of OpenID Connect
/// Registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub enum SubjectType {
    /// By the person's user identifier, the same at every public client.
    #[default]
    Public,
    /// By an identifier of the client's sector alone.
    Pairwise,
}

impl SubjectType {
    /// The name, as OpenID Connect writes it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Pairwise => "pairwise",
        }
    }

    /// Reads a name.
    ///
    /// # Errors
    ///
    /// Returns `oauth.client_subject_type_invalid` for anything but
    /// `public` and `pairwise`.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "public" => Ok(Self::Public),
            "pairwise" => Ok(Self::Pairwise),
            _ => Err(subject_type_invalid(
                "the subject type is not one Hodor knows",
            )),
        }
    }
}

pub(crate) fn subject_type_invalid(reason: &'static str) -> DomainError {
    DomainError::invalid(
        "oauth.client_subject_type_invalid",
        "a client's subject type is `public` or `pairwise`, and only a client with \
         `authorization_code` may be pairwise",
    )
    .with_detail(reason)
}

pub(crate) fn sector_uri_invalid(reason: impl Into<String>) -> DomainError {
    DomainError::invalid(
        "oauth.client_sector_identifier_uri_invalid",
        "a sector identifier address is an HTTPS address of at most 2000 characters, with a host \
         and without a name and password or a fragment, for a pairwise client only",
    )
    .with_detail(reason)
}

pub(crate) fn sector_required() -> DomainError {
    DomainError::invalid(
        "oauth.client_sector_identifier_uri_required",
        "a pairwise client whose redirect addresses name more than one host, or one without a \
         host, needs a sector identifier address",
    )
}

/// The host of an `https://` or `http://` address, in lowercase and
/// without its port; none for any other address, such as one of a
/// private-use scheme.
#[must_use]
pub fn host_of(address: &str) -> Option<String> {
    let rest = address
        .strip_prefix("https://")
        .or_else(|| address.strip_prefix("http://"))?;
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    let authority = authority.rsplit('@').next().unwrap_or_default();
    let host = if authority.starts_with('[') {
        let end = authority.find(']')?;
        &authority[..=end]
    } else {
        authority.split(':').next().unwrap_or_default()
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

/// A client's sector: the host of its sector identifier address when it
/// has one, otherwise the one host all its redirect addresses name. None
/// when the redirect addresses name more than one host, or one has none.
#[must_use]
pub fn sector_of(sector_identifier_uri: Option<&str>, redirect_uris: &[String]) -> Option<String> {
    if let Some(uri) = sector_identifier_uri {
        return host_of(uri);
    }
    let mut hosts = redirect_uris.iter().map(|uri| host_of(uri));
    let first = hosts.next()??;
    hosts
        .all(|host| host.as_deref() == Some(first.as_str()))
        .then_some(first)
}

/// Checks the form of a sector identifier address, as a back-channel
/// logout address is checked: `https://` or `http://`, a host and maybe a
/// port, no name and password, no fragment, printable ASCII. Whether it
/// may be called, plain HTTP included, is for the guarded client to say.
///
/// # Errors
///
/// Returns `oauth.client_sector_identifier_uri_invalid`.
pub fn check_sector_identifier_uri(value: &str) -> Result<(), DomainError> {
    check_backchannel_logout_uri(value)
        .map_err(|error| sector_uri_invalid(error.detail().unwrap_or_default().to_owned()))
}

/// Checks the document a sector identifier address answered: a JSON array
/// of strings that holds every one of `redirect_uris`, compared character
/// for character (OpenID Connect Registration, section 5).
///
/// # Errors
///
/// Returns `oauth.client_sector_identifier_uri_document_invalid` for a
/// document that is not such an array, and
/// `oauth.client_sector_identifier_uri_mismatch` when a redirect address
/// is missing from it.
pub fn check_sector_document(body: &[u8], redirect_uris: &[String]) -> Result<(), DomainError> {
    let document = serde_json::from_slice::<Value>(body).ok();
    let listed: Option<Vec<&str>> = match &document {
        Some(Value::Array(values)) => values.iter().map(Value::as_str).collect(),
        _ => None,
    };
    let Some(listed) = listed else {
        return Err(DomainError::invalid(
            "oauth.client_sector_identifier_uri_document_invalid",
            "the sector identifier address must answer a JSON array of addresses",
        ));
    };
    if redirect_uris
        .iter()
        .all(|uri| listed.contains(&uri.as_str()))
    {
        Ok(())
    } else {
        Err(DomainError::invalid(
            "oauth.client_sector_identifier_uri_mismatch",
            "every redirect address of the client must be listed at its sector identifier address",
        ))
    }
}

/// A tenant's pairwise secret, opened.
pub struct PairwiseSecret(Secret<Vec<u8>>);

impl std::fmt::Debug for PairwiseSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("PairwiseSecret(…)")
    }
}

impl PairwiseSecret {
    /// A new secret of 32 random bytes.
    #[must_use]
    pub fn generate(random: &dyn RandomSource) -> Self {
        let mut bytes = vec![0_u8; PAIRWISE_SECRET_BYTES];
        random.fill(&mut bytes);
        Self(Secret::new(bytes))
    }

    /// A secret as it was opened from storage.
    ///
    /// # Errors
    ///
    /// Returns `secret.unreadable` unless it has 32 bytes.
    pub fn from_opened(secret: Secret<Vec<u8>>) -> Result<Self, DomainError> {
        if secret.expose().len() == PAIRWISE_SECRET_BYTES {
            Ok(Self(secret))
        } else {
            Err(hodor_kernel::sealing::unreadable(
                "a pairwise secret does not have 32 bytes",
            ))
        }
    }

    /// The secret, to seal.
    #[must_use]
    pub const fn as_secret(&self) -> &Secret<Vec<u8>> {
        &self.0
    }

    fn identifier(
        &self,
        mac: &dyn HmacSha256,
        purpose: &[u8],
        tenant: TenantId,
        sector: &str,
        id: &[u8; 16],
    ) -> String {
        let mut message = Vec::with_capacity(purpose.len() + sector.len() + 35);
        message.extend_from_slice(purpose);
        message.push(0);
        message.extend_from_slice(tenant.as_uuid().as_bytes());
        message.push(0);
        message.extend_from_slice(sector.to_ascii_lowercase().as_bytes());
        message.push(0);
        message.extend_from_slice(id);
        URL_SAFE_NO_PAD.encode(mac.mac(self.0.expose(), &message))
    }

    /// The `sub` by which a pairwise client of `sector` knows the person
    /// `user` of `tenant`: 43 characters of base64url.
    #[must_use]
    pub fn subject(
        &self,
        mac: &dyn HmacSha256,
        tenant: TenantId,
        sector: &str,
        user: &[u8; 16],
    ) -> String {
        self.identifier(mac, SUBJECT_USE, tenant, sector, user)
    }

    /// The `sid` by which a pairwise client of `sector` knows the session
    /// `session` of `tenant`.
    #[must_use]
    pub fn session(
        &self,
        mac: &dyn HmacSha256,
        tenant: TenantId,
        sector: &str,
        session: &[u8; 16],
    ) -> String {
        self.identifier(mac, SESSION_USE, tenant, sector, session)
    }
}

#[cfg(test)]
mod tests;
