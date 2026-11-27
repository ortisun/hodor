//! Front-channel logout: the address a client is told at through the
//! person's browser, the address of the frame that tells it, the site the
//! signed-out page's policy names for it, and the frames kept on the server
//! for one sign-out.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Front-channel
//! logout", and Decision 0081.

use crate::domain::authorization::{TOKEN_LENGTH, is_base64url, random_token};
use crate::domain::client::{ClientType, MAX_REDIRECT_URI_LENGTH, check_redirect_uri, is_port};
use hodor_kernel::{Digest, DomainError, RandomSource, Secret, Timestamp};
use hodor_session::api::SessionId;
use std::fmt;
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies the frames kept for one sign-out.
    FrontChannelLogoutId
);

/// The longest front-channel logout address.
pub const MAX_FRONTCHANNEL_LOGOUT_URI_LENGTH: usize = MAX_REDIRECT_URI_LENGTH;

/// How long the frames of a sign-out can be read, and how long the cookie
/// that names them lives.
pub const FRAMES_LIFETIME: Duration = Duration::seconds(120);

/// How long the signed-out page waits for its frames before it goes on.
pub const FRAMES_WAIT: Duration = Duration::seconds(5);

pub(crate) fn uri_invalid(reason: impl Into<String>) -> DomainError {
    DomainError::invalid(
        "oauth.client_frontchannel_logout_uri_invalid",
        "a front-channel logout address follows the rules of a redirect address, without a \
         private-use scheme, on the scheme, host and port of one of the client's redirect \
         addresses, for a client with `authorization_code` only",
    )
    .with_detail(reason)
}

/// The scheme, host and port of a web address: where a browser loads it
/// from. The host is lowercase, and a port left out is the scheme's own.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Site {
    scheme: &'static str,
    /// The host as written, lowercase, brackets of an address included.
    host: String,
    /// The port as written, if one was.
    written_port: Option<u16>,
}

impl Site {
    /// The site of an `https://` or `http://` address whose host is a name
    /// or an address and nothing else, or `None`.
    pub(crate) fn of(address: &str) -> Option<Self> {
        let (scheme, rest) = match address.strip_prefix("https://") {
            Some(rest) => ("https", rest),
            None => ("http", address.strip_prefix("http://")?),
        };
        let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
        let (host, port) = if authority.starts_with('[') {
            let (inside, after) = authority.split_once(']')?;
            let inside = &inside[1..];
            let shaped = !inside.is_empty()
                && inside
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.');
            if !shaped {
                return None;
            }
            (format!("[{inside}]"), after)
        } else {
            let (host, after) = match authority.find(':') {
                Some(colon) => (&authority[..colon], &authority[colon..]),
                None => (authority, ""),
            };
            let shaped = !host.is_empty()
                && host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
            if !shaped {
                return None;
            }
            (host.to_owned(), after)
        };
        let written_port = match port {
            "" => None,
            port => {
                let port = port.strip_prefix(':')?;
                if !is_port(port) {
                    return None;
                }
                Some(port.parse().ok()?)
            }
        };
        Some(Self {
            scheme,
            host: host.to_ascii_lowercase(),
            written_port,
        })
    }

    const fn port(&self) -> u16 {
        match (self.written_port, self.scheme.as_bytes()) {
            (Some(port), _) => port,
            (None, b"https") => 443,
            (None, _) => 80,
        }
    }

    /// Whether both are the same site: the same scheme, host and port.
    pub(crate) fn same_as(&self, other: &Self) -> bool {
        self.scheme == other.scheme && self.host == other.host && self.port() == other.port()
    }

    /// The site as a source of a content security policy, such as
    /// `https://payroll.example.com:8443`.
    pub(crate) fn source(&self) -> String {
        match self.written_port {
            Some(port) => format!("{}://{}:{port}", self.scheme, self.host),
            None => format!("{}://{}", self.scheme, self.host),
        }
    }
}

/// Checks a front-channel logout address against the rules of a redirect
/// address, without a private-use scheme, and against the sites of the
/// client's `redirect_uris`: the address must share the scheme, host and
/// port of one of them (OpenID Connect Front-Channel Logout, section 2).
///
/// # Errors
///
/// Returns `oauth.client_frontchannel_logout_uri_invalid`, whose detail
/// says which rule the address broke.
pub fn check_frontchannel_logout_uri(
    value: &str,
    redirect_uris: &[String],
) -> Result<(), DomainError> {
    if !value.starts_with("https://") && !value.starts_with("http://") {
        return Err(uri_invalid(
            "the address is neither HTTPS nor plain HTTP to a loopback address",
        ));
    }
    check_redirect_uri(value, ClientType::Confidential)
        .map_err(|error| uri_invalid(error.detail().unwrap_or_default().to_owned()))?;
    let Some(site) = Site::of(value) else {
        return Err(uri_invalid("the host is neither a name nor an address"));
    };
    let shared = redirect_uris
        .iter()
        .filter_map(|uri| Site::of(uri))
        .any(|redirect| redirect.same_as(&site));
    if shared {
        Ok(())
    } else {
        Err(uri_invalid(
            "the scheme, host and port are those of none of the client's redirect addresses",
        ))
    }
}

/// The address of the frame that tells a client, at its front-channel
/// logout address `uri`, that the session it knows as `sid` ended at the
/// issuer `issuer`: `iss` and `sid` added to the address's query, form
/// encoded (OpenID Connect Front-Channel Logout, section 3).
#[must_use]
pub fn frame_address(uri: &str, issuer: &str, sid: &str) -> String {
    let separator = if uri.contains('?') { '&' } else { '?' };
    let query = form_urlencoded::Serializer::new(String::new())
        .append_pair("iss", issuer)
        .append_pair("sid", sid)
        .finish();
    format!("{uri}{separator}{query}")
}

/// The sources of the signed-out page's `frame-src` for `frames`: the site
/// of each, once, in the order they first appear. A frame whose site
/// cannot be written as a source is left out of the policy, and so is not
/// loaded.
#[must_use]
pub fn frame_sources(frames: &[String]) -> Vec<String> {
    let mut sources: Vec<String> = Vec::new();
    for frame in frames {
        if let Some(site) = Site::of(frame) {
            let source = site.source();
            if !sources.contains(&source) {
                sources.push(source);
            }
        }
    }
    sources
}

/// The SHA-256 of a handle; what is stored.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct HandleHash([u8; 32]);

impl HandleHash {
    /// The hash of a handle as the browser presented it, or `None` when it
    /// does not have the shape of one Hodor makes: it cannot be one, and
    /// nothing is computed.
    #[must_use]
    pub fn of_presented(value: &str, digest: &dyn Digest) -> Option<Self> {
        (value.len() == TOKEN_LENGTH && is_base64url(value))
            .then(|| Self(digest.sha256(value.as_bytes())))
    }

    /// Rebuilds a hash read from storage.
    #[must_use]
    pub const fn from_stored(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// The bytes, for storage.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Debug for HandleHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HandleHash(..)")
    }
}

/// The handle itself: given to the browser once, in a cookie, and stored
/// nowhere.
pub struct SignedOutHandle(Secret<String>);

impl SignedOutHandle {
    /// The handle, for the cookie.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }
}

impl fmt::Debug for SignedOutHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SignedOutHandle([REDACTED])")
    }
}

/// The frames kept for the signed-out page of one sign-out, found by the
/// hash of their handle while they live.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FrontChannelLogout {
    /// Its identifier.
    pub id: FrontChannelLogoutId,
    /// The hash of its handle.
    pub handle_hash: HandleHash,
    /// The session that ended.
    pub session_id: SessionId,
    /// The addresses of the frames, in the order they are loaded; never
    /// empty.
    pub frames: Vec<String>,
    /// When the session ended and the frames were made.
    pub created_at: Timestamp,
    /// When they can no longer be read.
    pub expires_at: Timestamp,
}

impl FrontChannelLogout {
    /// Keeps `frames` for the sign-out of `session` at `now`, or `None`
    /// when there is no frame to keep. The browser gets the handle.
    #[must_use]
    pub fn keep(
        session: SessionId,
        frames: Vec<String>,
        now: Timestamp,
        random: &dyn RandomSource,
        digest: &dyn Digest,
    ) -> Option<(Self, SignedOutHandle)> {
        if frames.is_empty() {
            return None;
        }
        let handle = random_token(random);
        let kept = Self {
            id: FrontChannelLogoutId::generate(),
            handle_hash: HandleHash(digest.sha256(handle.as_bytes())),
            session_id: session,
            frames,
            created_at: now,
            expires_at: now + FRAMES_LIFETIME,
        };
        Some((kept, SignedOutHandle(Secret::from(handle))))
    }

    /// Whether the frames can still be read at `now`.
    #[must_use]
    pub fn is_live_at(&self, now: Timestamp) -> bool {
        now < self.expires_at
    }
}

#[cfg(test)]
mod tests;
