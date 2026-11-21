//! SAML as computation on text.
//!
//! Hodor is a SAML **service provider**: it sends a person to an identity
//! provider with a request, and receives a signed response through the
//! person's browser. This crate holds what that needs and nothing that does
//! input or output: it checks a response ([`check_response`]), writes a
//! request ([`AuthenticationRequest`]) and writes Hodor's metadata
//! ([`metadata`]).
//!
//! It is the only crate of the workspace allowed to depend on an XML library
//! (Decision 0019). Responses are read once, by `xml-sec` with both of its
//! parsers, behind a narrow profile of Hodor's own: everything that real
//! identity providers do not send is refused before the signature is looked
//! at. The checks, in order, are in `docs/architecture/contexts/federation.md`;
//! what each must refuse is the attack corpus in
//! `docs/security/saml-attack-corpus.md`, whose cases are the tests of this
//! crate.

mod key;
mod metadata;
mod names;
mod refusal;
mod request;
mod response;
mod text;

#[cfg(feature = "testing")]
pub mod testing;

pub use key::{CertificateError, IdentityProviderKey};
pub use metadata::metadata;
pub use refusal::{Reason, Refusal};
pub use request::{AuthenticationRequest, request_id};
pub use response::{
    Assertion, Attribute, Expected, MAX_POSTED_BYTES, MAX_RESPONSE_BYTES, ServiceProvider,
    check_response,
};
