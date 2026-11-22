//! Why a response was refused.

use std::fmt;

/// The reason a response was refused, as a fixed name.
///
/// The person is never told the reason; it is recorded as
/// `federation.sign_in_refused` so that an administrator can see why somebody
/// could not get in. Each case of the attack corpus names the reason it must
/// be refused with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Reason {
    /// Larger than [`crate::MAX_RESPONSE_BYTES`].
    Size,
    /// Not base64, not UTF-8, not XML, or XML the two parsers read differently.
    Malformed,
    /// A document type declaration.
    DocumentType,
    /// Nested too deep.
    Depth,
    /// A processing instruction.
    ProcessingInstruction,
    /// A comment.
    Comment,
    /// Not the shape of a SAML response that Hodor accepts.
    Structure,
    /// An encrypted assertion, attribute or identifier.
    Encrypted,
    /// The status is not success.
    Status,
    /// More than one assertion, more than one signature, or a signature
    /// somewhere else than on the assertion or the response.
    Wrapping,
    /// No signature.
    Unsigned,
    /// The reference does not name the signed element by its identifier.
    Reference,
    /// Two elements carry the same identifier.
    DuplicateIdentifier,
    /// A transform or a canonicalization outside the profile.
    Transform,
    /// A digest or signature algorithm outside the profile, or one that does
    /// not match the key.
    Algorithm,
    /// The signature does not hold with the identity provider's key.
    Signature,
    /// What was signed has changed.
    Digest,
    /// The response was sent to another address.
    Destination,
    /// The response answers another request.
    Request,
    /// The response answers no request.
    Unsolicited,
    /// Another identity provider issued it.
    Issuer,
    /// No usable bearer confirmation.
    Confirmation,
    /// The confirmation names another address.
    Recipient,
    /// Not valid at this time.
    Time,
    /// Not meant for this service provider.
    Audience,
    /// The subject cannot be used to recognize the person.
    Subject,
}

impl Reason {
    /// Every reason, in the order of the checks.
    pub const ALL: [Self; 26] = [
        Self::Size,
        Self::Malformed,
        Self::DocumentType,
        Self::Depth,
        Self::ProcessingInstruction,
        Self::Comment,
        Self::Structure,
        Self::Encrypted,
        Self::Status,
        Self::Wrapping,
        Self::Unsigned,
        Self::Reference,
        Self::DuplicateIdentifier,
        Self::Transform,
        Self::Algorithm,
        Self::Signature,
        Self::Digest,
        Self::Destination,
        Self::Request,
        Self::Unsolicited,
        Self::Issuer,
        Self::Confirmation,
        Self::Recipient,
        Self::Time,
        Self::Audience,
        Self::Subject,
    ];

    /// The reason with this fixed name, as [`Reason::as_str`] writes it.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|reason| reason.as_str() == name)
    }

    /// The fixed name of the reason.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Size => "size",
            Self::Malformed => "malformed",
            Self::DocumentType => "document_type",
            Self::Depth => "depth",
            Self::ProcessingInstruction => "processing_instruction",
            Self::Comment => "comment",
            Self::Structure => "structure",
            Self::Encrypted => "encrypted",
            Self::Status => "status",
            Self::Wrapping => "wrapping",
            Self::Unsigned => "unsigned",
            Self::Reference => "reference",
            Self::DuplicateIdentifier => "duplicate_identifier",
            Self::Transform => "transform",
            Self::Algorithm => "algorithm",
            Self::Signature => "signature",
            Self::Digest => "digest",
            Self::Destination => "destination",
            Self::Request => "request",
            Self::Unsolicited => "unsolicited",
            Self::Issuer => "issuer",
            Self::Confirmation => "confirmation",
            Self::Recipient => "recipient",
            Self::Time => "time",
            Self::Audience => "audience",
            Self::Subject => "subject",
        }
    }
}

/// A response that was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub struct Refusal {
    reason: Reason,
}

impl Refusal {
    pub(crate) const fn new(reason: Reason) -> Self {
        Self { reason }
    }

    /// Why.
    #[must_use]
    pub const fn reason(&self) -> Reason {
        self.reason
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "the SAML response was refused: {}",
            self.reason.as_str()
        )
    }
}

impl From<Reason> for Refusal {
    fn from(reason: Reason) -> Self {
        Self::new(reason)
    }
}

#[cfg(test)]
mod tests {
    use super::Reason;

    #[test]
    fn every_reason_is_read_back_from_its_name() {
        for reason in Reason::ALL {
            assert_eq!(Reason::from_name(reason.as_str()), Some(reason));
        }
        assert_eq!(Reason::from_name("not a reason"), None);
    }
}
