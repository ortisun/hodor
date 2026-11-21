//! Checking a response from an identity provider.
//!
//! Not written yet: every response is refused, so that the attack corpus
//! shows what it is waiting for.

use time::{Duration, OffsetDateTime};

use crate::key::IdentityProviderKey;
use crate::refusal::{Reason, Refusal};

/// The largest response accepted, once decoded.
pub const MAX_RESPONSE_BYTES: usize = 256 * 1024;

/// The largest posted value accepted: the base64 of the largest response,
/// with room for the line breaks some identity providers write.
pub const MAX_POSTED_BYTES: usize = 384 * 1024;

/// How far apart two clocks may be.
const CLOCK_TOLERANCE: Duration = Duration::minutes(1);

/// Hodor, as the service provider of one identity provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceProvider {
    entity_id: String,
    assertion_consumer_address: String,
}

impl ServiceProvider {
    /// Hodor's entity identifier for this identity provider, and the address
    /// where its responses are posted.
    #[must_use]
    pub fn new(
        entity_id: impl Into<String>,
        assertion_consumer_address: impl Into<String>,
    ) -> Self {
        Self {
            entity_id: entity_id.into(),
            assertion_consumer_address: assertion_consumer_address.into(),
        }
    }

    /// The entity identifier, which audiences must name.
    #[must_use]
    pub fn entity_id(&self) -> &str {
        &self.entity_id
    }

    /// The assertion consumer address, which destinations and recipients must
    /// name.
    #[must_use]
    pub fn assertion_consumer_address(&self) -> &str {
        &self.assertion_consumer_address
    }
}

/// What a response must agree with.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    /// Hodor, for this identity provider.
    pub service_provider: &'a ServiceProvider,
    /// The identity provider's entity identifier, compared exactly.
    pub issuer: &'a str,
    /// The identity provider's key.
    pub key: &'a IdentityProviderKey,
    /// The identifier of the request this sign-in sent.
    pub request_id: &'a str,
    /// Now.
    pub now: OffsetDateTime,
}

/// What a checked response says, read from the signed assertion only.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Assertion {
    name_id: String,
    name_id_format: Option<String>,
    session_index: Option<String>,
    attributes: Vec<Attribute>,
}

impl Assertion {
    /// The `NameID`: who the person is to the identity provider.
    #[must_use]
    pub fn name_id(&self) -> &str {
        &self.name_id
    }

    /// The format of the `NameID`, when the identity provider gave one.
    #[must_use]
    pub fn name_id_format(&self) -> Option<&str> {
        self.name_id_format.as_deref()
    }

    /// The session index of the authentication statement.
    #[must_use]
    pub fn session_index(&self) -> Option<&str> {
        self.session_index.as_deref()
    }

    /// Every attribute, in the order of the assertion.
    #[must_use]
    pub fn attributes(&self) -> &[Attribute] {
        &self.attributes
    }

    /// The first value of the first attribute with this name.
    #[must_use]
    pub fn first_value(&self, name: &str) -> Option<&str> {
        self.attributes
            .iter()
            .find(|attribute| attribute.name == name)
            .and_then(|attribute| attribute.values.first())
            .map(String::as_str)
    }
}

/// One attribute of the assertion.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribute {
    name: String,
    values: Vec<String>,
}

impl Attribute {
    /// The attribute's `Name`.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Its values that are text.
    #[must_use]
    pub fn values(&self) -> &[String] {
        &self.values
    }
}

/// Checks a response as it was posted, the base64 value of `SAMLResponse`,
/// and returns what its signed assertion says.
///
/// # Errors
///
/// A [`Refusal`] with the reason of the first check that failed.
pub fn check_response(posted: &str, expected: &Expected<'_>) -> Result<Assertion, Refusal> {
    let _ = (posted, expected, CLOCK_TOLERANCE);
    Err(Reason::Structure.into())
}

