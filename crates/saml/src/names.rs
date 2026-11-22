//! The names SAML and XML signatures are written with.

pub(crate) const PROTOCOL: &str = "urn:oasis:names:tc:SAML:2.0:protocol";
pub(crate) const ASSERTION: &str = "urn:oasis:names:tc:SAML:2.0:assertion";
pub(crate) const METADATA: &str = "urn:oasis:names:tc:SAML:2.0:metadata";
pub(crate) const SIGNATURE: &str = "http://www.w3.org/2000/09/xmldsig#";
pub(crate) const XML: &str = "http://www.w3.org/XML/1998/namespace";

pub(crate) const EXCLUSIVE_CANONICALIZATION: &str = "http://www.w3.org/2001/10/xml-exc-c14n#";
pub(crate) const ENVELOPED_SIGNATURE: &str =
    "http://www.w3.org/2000/09/xmldsig#enveloped-signature";
pub(crate) const SHA256: &str = "http://www.w3.org/2001/04/xmlenc#sha256";
pub(crate) const RSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256";
pub(crate) const RSA_PSS_SHA256: &str = "http://www.w3.org/2007/05/xmldsig-more#sha256-rsa-MGF1";
pub(crate) const ECDSA_SHA256: &str = "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256";

pub(crate) const SUCCESS: &str = "urn:oasis:names:tc:SAML:2.0:status:Success";
pub(crate) const BEARER: &str = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
pub(crate) const TRANSIENT: &str = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
pub(crate) const HTTP_POST: &str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST";
