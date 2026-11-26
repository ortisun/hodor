//! Logout initiated by the relying party: the request an application
//! sends to the end-session endpoint, the ID token it may name as a hint,
//! and what is done with the browser's session.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Logout initiated
//! by the relying party".

use crate::domain::application::Application;
use crate::domain::client::{Client, ClientId, IdTokenAlgorithm};
use crate::domain::openid::PublishedKey;
use crate::domain::token::decode_json;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::{SignatureVerifier, UserId};
use hodor_session::api::SessionId;
use serde_json::Value;

/// The longest `state` a logout request may carry.
pub const MAX_LOGOUT_STATE_LENGTH: usize = 1024;
/// The longest `ui_locales` a logout request may carry.
pub const MAX_LOGOUT_LOCALES_LENGTH: usize = 255;
/// The largest `id_token_hint` that is read at all.
const MAX_HINT_BYTES: usize = 16 * 1024;

/// The codes of the page a refused logout request is answered with.
pub mod refusal {
    /// A parameter given twice, or a `state` or `ui_locales` that breaks
    /// its rule.
    pub const REQUEST_INVALID: &str = "oauth.logout_request_invalid";
    /// The hint is not an ID token of this tenant.
    pub const ID_TOKEN_HINT_INVALID: &str = "oauth.logout_id_token_hint_invalid";
    /// The client is not one of this tenant that may get tokens, or a
    /// return address was given without naming a client.
    pub const CLIENT_UNKNOWN: &str = "oauth.logout_client_unknown";
    /// `client_id` and the hint name different clients.
    pub const CLIENT_MISMATCH: &str = "oauth.logout_client_mismatch";
    /// The return address is not one of the client's.
    pub const REDIRECT_URI_UNREGISTERED: &str = "oauth.logout_redirect_uri_unregistered";
}

/// The parameters of a logout request, as they arrived.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LogoutParameters {
    pairs: Vec<(String, String)>,
}

enum Given<'a> {
    Absent,
    Once(&'a str),
    Repeated,
}

const NAMES: [&str; 5] = [
    "id_token_hint",
    "client_id",
    "post_logout_redirect_uri",
    "state",
    "ui_locales",
];

impl LogoutParameters {
    /// The parameters of a query or a form. An empty value counts as not
    /// given, as at the authorization endpoint.
    pub fn from_pairs(pairs: impl IntoIterator<Item = (String, String)>) -> Self {
        Self {
            pairs: pairs
                .into_iter()
                .filter(|(_, value)| !value.is_empty())
                .collect(),
        }
    }

    fn given(&self, name: &str) -> Given<'_> {
        let mut found = self.pairs.iter().filter(|(key, _)| key == name);
        match (found.next(), found.next()) {
            (None, _) => Given::Absent,
            (Some((_, value)), None) => Given::Once(value),
            (Some(_), Some(_)) => Given::Repeated,
        }
    }

    fn once(&self, name: &str) -> Option<&str> {
        match self.given(name) {
            Given::Once(value) => Some(value),
            Given::Absent | Given::Repeated => None,
        }
    }

    /// The hint, read only to know whose keys to check it with; see
    /// [`check_id_token_hint`].
    #[must_use]
    pub fn id_token_hint(&self) -> Option<&str> {
        self.once("id_token_hint")
    }

    /// The client the request names by `client_id`, if it parses.
    #[must_use]
    pub fn client_id(&self) -> Option<&str> {
        self.once("client_id")
    }
}

fn printable(value: &str) -> bool {
    value.bytes().all(|b| (0x20..0x7f).contains(&b))
}

/// What an `id_token_hint` that passed every check says.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IdTokenHint {
    /// The client it was issued to, its `aud`.
    pub client_id: ClientId,
    /// The person as that client knows them, its `sub`: a user identifier,
    /// or for a pairwise client a pairwise one.
    pub subject: String,
    /// The session as that client knows it, its `sid`. An ID token issued
    /// before `sid` existed has none.
    pub session: Option<String>,
}

/// Checks an `id_token_hint`: an ID token this tenant issued. Its
/// signature is checked before anything it says is used; its expiry is
/// not, since the specification allows an expired hint.
///
/// # Errors
///
/// Returns the reason, for the logs.
pub fn check_id_token_hint(
    token: &str,
    issuer: &str,
    keys: &[PublishedKey],
    verifier: &dyn SignatureVerifier,
) -> Result<IdTokenHint, &'static str> {
    if token.len() > MAX_HINT_BYTES {
        return Err("the hint is too large");
    }
    let parts: Vec<&str> = token.split('.').collect();
    let [header_part, claims_part, signature_part] = parts.as_slice() else {
        return Err("the hint is not three parts");
    };
    let header = decode_json(header_part).ok_or("the header is malformed")?;
    if header.get("typ").and_then(Value::as_str) != Some("JWT") {
        return Err("the hint is not an ID token");
    }
    // An ID token of Hodor's is signed with one of the algorithms a client
    // may choose for them, and nothing else.
    let algorithm = header
        .get("alg")
        .and_then(Value::as_str)
        .and_then(IdTokenAlgorithm::from_name)
        .map(IdTokenAlgorithm::signature)
        .ok_or("the hint names another algorithm")?;
    let kid = header
        .get("kid")
        .and_then(Value::as_str)
        .ok_or("the hint names no key")?;
    let key = keys
        .iter()
        .find(|key| key.key_id == kid && key.algorithm == algorithm)
        .ok_or("the hint's key is not published by this tenant")?;
    let signature = URL_SAFE_NO_PAD
        .decode(signature_part)
        .map_err(|_| "the signature is malformed")?;
    let signed = format!("{header_part}.{claims_part}");
    if !verifier.verify(key.algorithm, &key.key, signed.as_bytes(), &signature) {
        return Err("the signature does not verify");
    }

    // Only now is anything the hint says used.
    let claims = decode_json(claims_part).ok_or("the claims are malformed")?;
    if claims.get("iss").and_then(Value::as_str) != Some(issuer) {
        return Err("the hint is from another issuer");
    }
    // Hodor's ID tokens name one audience, the client.
    let audience = match claims.get("aud") {
        Some(Value::String(one)) => Some(one.as_str()),
        Some(Value::Array(many)) if many.len() == 1 => many[0].as_str(),
        _ => None,
    };
    let client_id = audience
        .and_then(|text| text.parse::<ClientId>().ok())
        .ok_or("the hint names no client")?;
    // Read as text: a pairwise client's `sub` and `sid` are no
    // identifiers of Hodor's, and are compared with what the client was
    // told, never parsed.
    let subject = claims
        .get("sub")
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or("the hint names no person")?
        .to_owned();
    let session = match claims.get("sid") {
        None => None,
        Some(value) => Some(
            value
                .as_str()
                .filter(|text| !text.is_empty())
                .ok_or("the hint's session is malformed")?
                .to_owned(),
        ),
    };
    Ok(IdTokenHint {
        client_id,
        subject,
        session,
    })
}

/// Where the person goes back to after signing out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReturnAddress {
    /// The client whose post-logout redirect address it is.
    pub client_id: ClientId,
    /// The address, exactly as registered.
    pub uri: String,
    /// The request's `state`, given back as it came.
    pub state: Option<String>,
}

/// A logout request that passed every check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutRequest {
    /// The hint, when the request had one.
    pub hint: Option<IdTokenHint>,
    /// Where the person goes back to, when the request named an address.
    pub return_to: Option<ReturnAddress>,
    /// The languages to ask the person in.
    pub ui_locales: Option<String>,
}

/// What is done with the browser's session.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogoutDecision {
    /// There is no session to end: go on to the finish.
    Finish,
    /// The request comes from the browser's own session: end it, then
    /// finish.
    EndSession,
    /// Ask the person first.
    Ask,
}

/// The browser's session, as the HTTP layer found it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CurrentSession {
    /// The person.
    pub user_id: UserId,
    /// The session.
    pub session_id: SessionId,
}

/// The browser's session as the hint's client knows it: the `sub` and the
/// `sid` that client's ID tokens give the person and the session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KnownSession {
    /// The person, as the client knows them.
    pub subject: String,
    /// The session, as the client knows it.
    pub session: String,
}

impl LogoutRequest {
    /// What to do, given the browser's session as the hint's client knows
    /// it and whether the request came as a form. A form another site
    /// posts does not carry the session cookie, so it always asks.
    #[must_use]
    pub fn decide(&self, current: Option<&KnownSession>, by_form: bool) -> LogoutDecision {
        if by_form {
            return LogoutDecision::Ask;
        }
        let Some(current) = current else {
            return LogoutDecision::Finish;
        };
        match &self.hint {
            Some(hint)
                if hint.subject == current.subject
                    && hint.session.as_deref() == Some(current.session.as_str()) =>
            {
                LogoutDecision::EndSession
            }
            _ => LogoutDecision::Ask,
        }
    }
}

/// The checks that need nothing stored: repeats, `state` and
/// `ui_locales`. Returns the `client_id` the request names, if it parses.
///
/// # Errors
///
/// Returns the code of the refusal.
pub(crate) fn check_shape(parameters: &LogoutParameters) -> Result<Option<ClientId>, &'static str> {
    for name in NAMES {
        if matches!(parameters.given(name), Given::Repeated) {
            return Err(refusal::REQUEST_INVALID);
        }
    }
    if let Some(state) = parameters.once("state")
        && (state.len() > MAX_LOGOUT_STATE_LENGTH || !printable(state))
    {
        return Err(refusal::REQUEST_INVALID);
    }
    if parameters
        .once("ui_locales")
        .is_some_and(|locales| locales.len() > MAX_LOGOUT_LOCALES_LENGTH || !printable(locales))
    {
        return Err(refusal::REQUEST_INVALID);
    }
    match parameters.client_id() {
        None => Ok(None),
        Some(text) => text
            .parse::<ClientId>()
            .map(Some)
            .map_err(|_| refusal::CLIENT_UNKNOWN),
    }
}

/// Checks a request whose hint, when it has one, has been checked, against
/// the client it names and that client's application. `client` is the
/// client named by `client_id` or else by the hint, as loaded from the
/// tenant; `None` when the tenant has no such client.
///
/// # Errors
///
/// Returns the code of the refusal.
pub(crate) fn check_request(
    parameters: &LogoutParameters,
    named_client: Option<ClientId>,
    hint: Option<IdTokenHint>,
    client: Option<(&Client, Option<&Application>)>,
) -> Result<LogoutRequest, &'static str> {
    if let (Some(named), Some(hint)) = (named_client, &hint)
        && named != hint.client_id
    {
        return Err(refusal::CLIENT_MISMATCH);
    }
    let wanted = named_client.or_else(|| hint.as_ref().map(|hint| hint.client_id));
    // A named client must be one that may get tokens.
    let usable = match (wanted, client) {
        (None, _) => None,
        (Some(id), Some((client, application)))
            if client.id() == id
                && client.is_enabled()
                && application.is_some_and(Application::is_enabled) =>
        {
            Some(client)
        }
        (Some(_), _) => return Err(refusal::CLIENT_UNKNOWN),
    };
    let return_to = match parameters.once("post_logout_redirect_uri") {
        None => None,
        Some(uri) => {
            let client = usable.ok_or(refusal::CLIENT_UNKNOWN)?;
            if !client.accepts_post_logout_redirect_uri(uri) {
                return Err(refusal::REDIRECT_URI_UNREGISTERED);
            }
            Some(ReturnAddress {
                client_id: client.id(),
                uri: uri.to_owned(),
                state: parameters.once("state").map(str::to_owned),
            })
        }
    };
    Ok(LogoutRequest {
        hint,
        return_to,
        ui_locales: parameters.once("ui_locales").map(str::to_owned),
    })
}

/// Checks a return address kept while the person was asked, again, at the
/// finish: the client must still get tokens and the address still be
/// registered. Anything else drops the address.
#[must_use]
pub(crate) fn still_returns(
    kept: &ReturnAddress,
    client: Option<(&Client, Option<&Application>)>,
) -> bool {
    client.is_some_and(|(client, application)| {
        client.id() == kept.client_id
            && client.is_enabled()
            && application.is_some_and(Application::is_enabled)
            && client.accepts_post_logout_redirect_uri(&kept.uri)
    })
}

#[cfg(test)]
mod tests;
