//! Checking a response from an identity provider.
//!
//! The steps follow the table in `docs/architecture/contexts/federation.md`,
//! in its order. Everything before the signature is checked refuses only: no
//! value read before that point is ever used.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use time::format_description::well_known::Rfc3339;
use time::{Duration, OffsetDateTime};
use xml_sec::api::Operation;
use xml_sec::policy::{PolicyCompileContext, PolicyCompiler, PolicyProfile};
use xml_sec::provider::RustCryptoProvider;
use xml_sec::xmldsig::{
    DsigStatus, FailureReason, SignatureAlgorithm, VerificationKey, VerificationRequest,
    VerifyEvidence,
};
use xml_sec::{
    DocumentView, Node, NodeId, NodeIdentity, ParseError, XmlDocumentError, XmlSecError,
    XmlSecurity,
};

use crate::key::{IdentityProviderKey, KeyKind};
use crate::names::{
    ASSERTION, BEARER, ECDSA_SHA256, ENVELOPED_SIGNATURE, EXCLUSIVE_CANONICALIZATION, PROTOCOL,
    RSA_PSS_SHA256, RSA_SHA256, SHA256, SIGNATURE, SUCCESS, TRANSIENT, XML,
};
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
    // Step 1: base64 of UTF-8 text, within the size.
    let xml = decode(posted)?;

    let provider = RustCryptoProvider;
    #[expect(
        clippy::expect_used,
        reason = "the profile and its context are fixed, and a test compiles them"
    )]
    let policies = PolicyCompiler::new(PolicyProfile::SecureSaml, &provider, None)
        .and_then(|compiler| {
            compiler.compile(&PolicyCompileContext {
                external_resources: false,
                target_evidence: true,
            })
        })
        .expect("the SAML profile of xml-sec compiles");
    let security = XmlSecurity::new(&policies, &provider).map_err(|_| Reason::Malformed)?;

    // Step 2: one parse, by both parsers, that everything after reads.
    let document = security
        .parse_document(xml, Operation::Verify)
        .map_err(parse_refusal)?;

    // Steps 3 to 10: the shape, before any cryptography.
    let plan = document.with_view(|view| inspect(view, expected))?;

    // Step 11: the signature, with the configured key only.
    let key = VerificationKey {
        algorithm: plan.algorithm,
        public_key_bytes: expected.key.subject_public_key_info().to_vec(),
        certificate_der: None,
        name: None,
    };
    let verifier = security.verifier().map_err(|_| Reason::Signature)?;
    let evidence = verifier
        .key(&key)
        .verify(
            &document,
            &VerificationRequest {
                expected_targets: &[plan.signed],
                ..Default::default()
            },
        )
        .map_err(|_| Reason::Signature)?;
    if !evidence.accepted(&document).unwrap_or(false) {
        return Err(failure(&evidence).into());
    }
    if plan.response_is_signed
        && !evidence
            .covers_element(&document, plan.assertion)
            .unwrap_or(false)
    {
        return Err(Reason::Wrapping.into());
    }

    // Steps 12 to 17: what the signed assertion says.
    document.with_view(|view| read(view, &plan, expected))
}

/// What the inspection established, for the verification and the reading.
struct Plan {
    signed: NodeIdentity,
    assertion: NodeIdentity,
    response_is_signed: bool,
    algorithm: SignatureAlgorithm,
}

fn decode(posted: &str) -> Result<String, Refusal> {
    if posted.len() > MAX_POSTED_BYTES {
        return Err(Reason::Size.into());
    }
    let compact: String = posted
        .chars()
        .filter(|character| !character.is_ascii_whitespace())
        .collect();
    let bytes = STANDARD.decode(compact).map_err(|_| Reason::Malformed)?;
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(Reason::Size.into());
    }
    String::from_utf8(bytes).map_err(|_| Reason::Malformed.into())
}

fn parse_refusal(error: XmlSecError) -> Refusal {
    match error {
        XmlSecError::Document(XmlDocumentError::Parse(ParseError::DtdDetected)) => {
            Reason::DocumentType
        }
        XmlSecError::Document(XmlDocumentError::DocumentTooDeep { .. }) => Reason::Depth,
        XmlSecError::Document(XmlDocumentError::DocumentTooLarge { .. }) => Reason::Size,
        _ => Reason::Malformed,
    }
    .into()
}

fn failure(evidence: &VerifyEvidence) -> Reason {
    match evidence
        .signatures()
        .first()
        .map(|signature| signature.result())
    {
        Some(Ok(result))
            if matches!(
                result.status,
                DsigStatus::Invalid(FailureReason::ReferenceDigestMismatch { .. })
            ) =>
        {
            Reason::Digest
        }
        _ => Reason::Signature,
    }
}

fn inspect(view: DocumentView<'_>, expected: &Expected<'_>) -> Result<Plan, Refusal> {
    let tree = view.document();

    // Step 3: no processing instruction, no comment.
    for node in tree.descendants() {
        if node.is_pi() {
            return Err(Reason::ProcessingInstruction.into());
        }
        if node.is_comment() {
            return Err(Reason::Comment.into());
        }
    }

    // Step 4: a SAML 2.0 response, nothing encrypted, and a success. The
    // status is read before the signature is checked, only to refuse.
    let response = tree.root_element();
    if !is(response, PROTOCOL, "Response") || response.attribute("Version") != Some("2.0") {
        return Err(Reason::Structure.into());
    }
    if tree.descendants().any(|node| {
        is(node, ASSERTION, "EncryptedAssertion")
            || is(node, ASSERTION, "EncryptedAttribute")
            || is(node, ASSERTION, "EncryptedID")
    }) {
        return Err(Reason::Encrypted.into());
    }
    let status = child(response, PROTOCOL, "Status")
        .and_then(|status| child(status, PROTOCOL, "StatusCode"))
        .and_then(|code| code.attribute("Value"));
    if status != Some(SUCCESS) {
        return Err(Reason::Status.into());
    }

    // Step 5: exactly one assertion in the whole document, a child of the
    // response.
    let assertions: Vec<Node<'_, '_>> = tree
        .descendants()
        .filter(|node| is(*node, ASSERTION, "Assertion"))
        .collect();
    let assertion = match assertions.as_slice() {
        [] => return Err(Reason::Structure.into()),
        [one] => *one,
        _ => return Err(Reason::Wrapping.into()),
    };
    if assertion.parent_element().map(|parent| parent.id()) != Some(response.id()) {
        return Err(Reason::Wrapping.into());
    }

    // Step 6: exactly one signature in the whole document, on the assertion
    // or on the response, holding only what a signature holds.
    let signatures: Vec<Node<'_, '_>> = tree
        .descendants()
        .filter(|node| is(*node, SIGNATURE, "Signature"))
        .collect();
    let signature = match signatures.as_slice() {
        [] => return Err(Reason::Unsigned.into()),
        [one] => *one,
        _ => return Err(Reason::Wrapping.into()),
    };
    let Some(signed) = signature.parent_element() else {
        return Err(Reason::Wrapping.into());
    };
    let response_is_signed = signed.id() == response.id();
    if !response_is_signed && signed.id() != assertion.id() {
        return Err(Reason::Wrapping.into());
    }
    let parts = elements(signature);
    let signed_info = match parts.as_slice() {
        [info, value] | [info, value, _]
            if is(*info, SIGNATURE, "SignedInfo")
                && is(*value, SIGNATURE, "SignatureValue")
                && parts
                    .get(2)
                    .is_none_or(|key| is(*key, SIGNATURE, "KeyInfo")) =>
        {
            *info
        }
        _ => return Err(Reason::Wrapping.into()),
    };

    // Step 7: the signed element has an identifier that nothing else has.
    let Some(signed_id) = signed.attribute("ID") else {
        return Err(Reason::Reference.into());
    };
    let Some(assertion_id) = assertion.attribute("ID") else {
        return Err(Reason::Structure.into());
    };
    if carriers(view, signed_id) > 1 || carriers(view, assertion_id) > 1 {
        return Err(Reason::DuplicateIdentifier.into());
    }

    // Step 8: exactly one reference, to that identifier.
    let info = elements(signed_info);
    let (canonicalization, method, references) = match info.as_slice() {
        [canonicalization, method, references @ ..]
            if is(*canonicalization, SIGNATURE, "CanonicalizationMethod")
                && is(*method, SIGNATURE, "SignatureMethod") =>
        {
            (*canonicalization, *method, references)
        }
        _ => return Err(Reason::Structure.into()),
    };
    let reference = match references {
        [one] if is(*one, SIGNATURE, "Reference") => *one,
        _ => return Err(Reason::Reference.into()),
    };
    if reference.attribute("URI") != Some(format!("#{signed_id}").as_str()) {
        return Err(Reason::Reference.into());
    }

    // Step 9: the enveloped signature and exclusive canonicalization only.
    if !is_exclusive_canonicalization(canonicalization) {
        return Err(Reason::Transform.into());
    }
    let (transforms, digest) = match elements(reference).as_slice() {
        [transforms, digest, value]
            if is(*transforms, SIGNATURE, "Transforms")
                && is(*digest, SIGNATURE, "DigestMethod")
                && is(*value, SIGNATURE, "DigestValue") =>
        {
            (*transforms, *digest)
        }
        _ => return Err(Reason::Transform.into()),
    };
    let transforms = elements(transforms);
    let accepted_transforms = match transforms.as_slice() {
        [enveloped] => is_enveloped(*enveloped),
        [enveloped, exclusive] => {
            is_enveloped(*enveloped)
                && is(*exclusive, SIGNATURE, "Transform")
                && is_exclusive_canonicalization(*exclusive)
        }
        _ => false,
    };
    if !accepted_transforms {
        return Err(Reason::Transform.into());
    }

    // Step 10: SHA-256, and an algorithm that matches the key.
    if digest.attribute("Algorithm") != Some(SHA256) || !elements(digest).is_empty() {
        return Err(Reason::Algorithm.into());
    }
    if !elements(method).is_empty() {
        return Err(Reason::Algorithm.into());
    }
    let algorithm = match (method.attribute("Algorithm"), expected.key.kind()) {
        (Some(RSA_SHA256), KeyKind::Rsa) => SignatureAlgorithm::RsaSha256,
        (Some(RSA_PSS_SHA256), KeyKind::Rsa) => SignatureAlgorithm::RsaPssSha256,
        (Some(ECDSA_SHA256), KeyKind::EllipticCurveP256) => SignatureAlgorithm::EcdsaSha256,
        _ => return Err(Reason::Algorithm.into()),
    };

    // The identities xml-sec resolves must be the very elements found above.
    let signed_identity = view
        .node_for_id(signed_id, &[])
        .filter(|identity| same(view, *identity, signed))
        .ok_or(Reason::Reference)?;
    let assertion_identity = view
        .node_for_id(assertion_id, &[])
        .filter(|identity| same(view, *identity, assertion))
        .ok_or(Reason::Structure)?;

    Ok(Plan {
        signed: signed_identity,
        assertion: assertion_identity,
        response_is_signed,
        algorithm,
    })
}

fn read(
    view: DocumentView<'_>,
    plan: &Plan,
    expected: &Expected<'_>,
) -> Result<Assertion, Refusal> {
    let tree = view.document();
    let response = tree.root_element();
    let assertion = node(view, plan.assertion).ok_or(Reason::Structure)?;
    let service_provider = expected.service_provider;

    // Step 12: the assertion holds what an assertion of a sign-in holds.
    let mut issuer = None;
    let mut subject = None;
    let mut conditions = None;
    let mut authentication = None;
    let mut attribute_statements = Vec::new();
    for part in elements(assertion) {
        let slot = if is(part, ASSERTION, "Issuer") {
            &mut issuer
        } else if is(part, ASSERTION, "Subject") {
            &mut subject
        } else if is(part, ASSERTION, "Conditions") {
            &mut conditions
        } else if is(part, ASSERTION, "AuthnStatement") {
            &mut authentication
        } else if is(part, ASSERTION, "AttributeStatement") {
            attribute_statements.push(part);
            continue;
        } else if is(part, SIGNATURE, "Signature") {
            continue;
        } else {
            return Err(Reason::Structure.into());
        };
        if slot.replace(part).is_some() {
            return Err(Reason::Structure.into());
        }
    }
    let (Some(issuer), Some(subject), Some(conditions), Some(authentication)) =
        (issuer, subject, conditions, authentication)
    else {
        return Err(Reason::Structure.into());
    };
    let mut name_id = None;
    let mut confirmations = Vec::new();
    for part in elements(subject) {
        if is(part, ASSERTION, "NameID") {
            if name_id.replace(part).is_some() {
                return Err(Reason::Structure.into());
            }
        } else if is(part, ASSERTION, "SubjectConfirmation") {
            confirmations.push(part);
        } else {
            return Err(Reason::Structure.into());
        }
    }
    let name_id = name_id.ok_or(Reason::Structure)?;

    // Step 13: sent to Hodor's assertion consumer, for this request.
    if response.attribute("Destination") != Some(service_provider.assertion_consumer_address()) {
        return Err(Reason::Destination.into());
    }
    match response.attribute("InResponseTo") {
        None => return Err(Reason::Unsolicited.into()),
        Some(request) if request != expected.request_id => return Err(Reason::Request.into()),
        Some(_) => {}
    }

    // Step 14: issued by the identity provider.
    if text(issuer).as_deref().map(str::trim) != Some(expected.issuer) {
        return Err(Reason::Issuer.into());
    }
    if let Some(response_issuer) = child(response, ASSERTION, "Issuer")
        && text(response_issuer).as_deref().map(str::trim) != Some(expected.issuer)
    {
        return Err(Reason::Issuer.into());
    }

    // Step 15: a bearer confirmation for this address, this request, now.
    let bearers: Vec<Node<'_, '_>> = confirmations
        .into_iter()
        .filter(|confirmation| confirmation.attribute("Method") == Some(BEARER))
        .collect();
    if bearers.is_empty() {
        return Err(Reason::Confirmation.into());
    }
    let mut first_failure = None;
    for bearer in &bearers {
        match confirm(*bearer, expected) {
            Ok(()) => {
                first_failure = None;
                break;
            }
            Err(reason) => {
                first_failure.get_or_insert(reason);
            }
        }
    }
    if let Some(reason) = first_failure {
        return Err(reason.into());
    }

    // Step 16: the conditions hold now, and name Hodor as the audience.
    let now = expected.now;
    if let Some(not_before) = conditions.attribute("NotBefore")
        && now + CLOCK_TOLERANCE < instant(not_before)?
    {
        return Err(Reason::Time.into());
    }
    if let Some(not_on_or_after) = conditions.attribute("NotOnOrAfter")
        && now - CLOCK_TOLERANCE >= instant(not_on_or_after)?
    {
        return Err(Reason::Time.into());
    }
    let mut restrictions = 0;
    for condition in elements(conditions) {
        if is(condition, ASSERTION, "AudienceRestriction") {
            restrictions += 1;
            let names_hodor = elements(condition).into_iter().any(|audience| {
                is(audience, ASSERTION, "Audience")
                    && text(audience).as_deref().map(str::trim)
                        == Some(service_provider.entity_id())
            });
            if !names_hodor {
                return Err(Reason::Audience.into());
            }
        } else if !is(condition, ASSERTION, "OneTimeUse")
            && !is(condition, ASSERTION, "ProxyRestriction")
        {
            return Err(Reason::Structure.into());
        }
    }
    if restrictions == 0 {
        return Err(Reason::Audience.into());
    }

    // Step 17: a subject that stays the same from one sign-in to the next.
    let name_id_format = name_id.attribute("Format");
    if name_id_format == Some(TRANSIENT) {
        return Err(Reason::Subject.into());
    }
    let value = text(name_id)
        .map(|value| value.trim().to_owned())
        .filter(|value| !value.is_empty())
        .ok_or(Reason::Subject)?;

    let mut attributes = Vec::new();
    for statement in attribute_statements {
        for attribute in elements(statement) {
            if !is(attribute, ASSERTION, "Attribute") {
                return Err(Reason::Structure.into());
            }
            let Some(name) = attribute.attribute("Name") else {
                return Err(Reason::Structure.into());
            };
            let values = elements(attribute)
                .into_iter()
                .filter(|value| is(*value, ASSERTION, "AttributeValue"))
                .filter_map(text)
                .collect();
            attributes.push(Attribute {
                name: name.to_owned(),
                values,
            });
        }
    }

    Ok(Assertion {
        name_id: value,
        name_id_format: name_id_format.map(str::to_owned),
        session_index: authentication.attribute("SessionIndex").map(str::to_owned),
        attributes,
    })
}

/// Checks one bearer confirmation.
fn confirm(bearer: Node<'_, '_>, expected: &Expected<'_>) -> Result<(), Reason> {
    let data = elements(bearer)
        .into_iter()
        .find(|part| is(*part, ASSERTION, "SubjectConfirmationData"))
        .ok_or(Reason::Confirmation)?;
    if data.attribute("Recipient") != Some(expected.service_provider.assertion_consumer_address()) {
        return Err(Reason::Recipient);
    }
    if data.attribute("InResponseTo") != Some(expected.request_id) {
        return Err(Reason::Request);
    }
    let not_on_or_after = data.attribute("NotOnOrAfter").ok_or(Reason::Confirmation)?;
    if expected.now - CLOCK_TOLERANCE
        >= instant(not_on_or_after).map_err(|refusal| refusal.reason())?
    {
        return Err(Reason::Time);
    }
    Ok(())
}

fn instant(value: &str) -> Result<OffsetDateTime, Refusal> {
    OffsetDateTime::parse(value.trim(), &Rfc3339).map_err(|_| Reason::Time.into())
}

/// Whether a node is the element with this namespace and local name.
fn is(node: Node<'_, '_>, namespace: &str, name: &str) -> bool {
    node.is_element()
        && node.tag_name().namespace() == Some(namespace)
        && node.tag_name().name() == name
}

/// The first child element with this namespace and local name.
fn child<'a, 'input>(
    node: Node<'a, 'input>,
    namespace: &str,
    name: &str,
) -> Option<Node<'a, 'input>> {
    node.children().find(|child| is(*child, namespace, name))
}

/// The child elements, without the text between them.
fn elements<'a, 'input>(node: Node<'a, 'input>) -> Vec<Node<'a, 'input>> {
    node.children().filter(Node::is_element).collect()
}

/// The text of an element that holds text only.
fn text(node: Node<'_, '_>) -> Option<String> {
    let mut value = String::new();
    for part in node.children() {
        if part.is_element() {
            return None;
        }
        if let Some(text) = part.text() {
            value.push_str(text);
        }
    }
    Some(value)
}

fn is_enveloped(transform: Node<'_, '_>) -> bool {
    is(transform, SIGNATURE, "Transform")
        && transform.attribute("Algorithm") == Some(ENVELOPED_SIGNATURE)
        && elements(transform).is_empty()
}

/// Exclusive canonicalization without comments, with at most its list of
/// namespaces to keep.
fn is_exclusive_canonicalization(method: Node<'_, '_>) -> bool {
    method.attribute("Algorithm") == Some(EXCLUSIVE_CANONICALIZATION)
        && match elements(method).as_slice() {
            [] => true,
            [namespaces] => {
                is(
                    *namespaces,
                    EXCLUSIVE_CANONICALIZATION,
                    "InclusiveNamespaces",
                ) && elements(*namespaces).is_empty()
            }
            _ => false,
        }
}

/// How many elements carry this value as an identifier, whatever the spelling
/// of the attribute.
fn carriers(view: DocumentView<'_>, value: &str) -> usize {
    view.document()
        .descendants()
        .filter(Node::is_element)
        .map(|element| {
            element
                .attributes()
                .filter(|attribute| {
                    let identifier = match attribute.namespace() {
                        None => matches!(attribute.name(), "ID" | "Id" | "id"),
                        Some(namespace) => namespace == XML && attribute.name() == "id",
                    };
                    identifier && attribute.value() == value
                })
                .count()
        })
        .sum()
}

/// The element of the tree an identity names.
fn node<'a>(view: DocumentView<'a>, identity: NodeIdentity) -> Option<Node<'a, 'a>> {
    let order = view.document_order(identity).ok()?;
    let id = NodeId::from(u32::try_from(order).ok()?);
    view.document().get_node(id)
}

/// Whether an identity names this very element.
fn same(view: DocumentView<'_>, identity: NodeIdentity, element: Node<'_, '_>) -> bool {
    node(view, identity).is_some_and(|found| found.id() == element.id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_profile_compiles() {
        let provider = RustCryptoProvider;
        let compiled =
            PolicyCompiler::new(PolicyProfile::SecureSaml, &provider, None).and_then(|compiler| {
                compiler.compile(&PolicyCompileContext {
                    external_resources: false,
                    target_evidence: true,
                })
            });
        assert!(compiled.is_ok(), "{compiled:?}");
    }

    #[test]
    fn a_posted_value_beyond_the_limit_is_refused_before_decoding() {
        let posted = "A".repeat(MAX_POSTED_BYTES + 1);
        assert_eq!(decode(&posted), Err(Reason::Size.into()));
    }

    #[test]
    fn line_breaks_in_base64_are_accepted() {
        assert_eq!(
            decode("PFJl\r\nc3Bv\nbnNlLz4="),
            Ok("<Response/>".to_owned())
        );
    }
}
