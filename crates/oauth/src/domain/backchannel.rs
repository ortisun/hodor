//! Back-channel logout: the address a client is told at, the logout token
//! it is told with, and the deliveries that carry one token to one client,
//! with what each attempt did to them.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Back-channel
//! logout".

use crate::domain::client::{ClientId, MAX_REDIRECT_URI_LENGTH, is_port};
use crate::domain::event::OauthEvent;
use hodor_kernel::{DomainError, Timestamp, UserId};
use hodor_session::api::SessionId;
use serde_json::{Value, json};
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies a logout delivery.
    LogoutDeliveryId
);

/// The event a logout token announces, its one member of `events`.
pub const BACKCHANNEL_LOGOUT_EVENT: &str = "http://schemas.openid.net/event/backchannel-logout";

/// The `typ` of a logout token's header.
pub const LOGOUT_TOKEN_TYPE: &str = "logout+jwt";

/// How long a logout token lives.
pub const LOGOUT_TOKEN_LIFETIME: Duration = Duration::minutes(2);

/// The longest back-channel logout address.
pub const MAX_BACKCHANNEL_LOGOUT_URI_LENGTH: usize = MAX_REDIRECT_URI_LENGTH;

/// The longest reason kept for a failed attempt, in characters.
pub const MAX_LOGOUT_ERROR_LENGTH: usize = 500;

/// The event type a logout is made from.
pub const SESSION_REVOKED: &str = "session.revoked";

pub(crate) fn uri_invalid(reason: &'static str) -> DomainError {
    DomainError::invalid(
        "oauth.client_backchannel_logout_uri_invalid",
        "a back-channel logout address is an HTTPS address of at most 2000 characters, with a \
         host and without a name and password or a fragment, for a client with \
         `authorization_code` only",
    )
    .with_detail(reason)
}

/// Checks the form of a back-channel logout address: `https://` or
/// `http://`, a host and maybe a port, no name and password, no fragment,
/// printable ASCII. Whether it may be called, plain HTTP included, is for
/// the guarded client to say.
///
/// # Errors
///
/// Returns `oauth.client_backchannel_logout_uri_invalid`.
pub fn check_backchannel_logout_uri(value: &str) -> Result<(), DomainError> {
    if value.is_empty() || value.len() > MAX_BACKCHANNEL_LOGOUT_URI_LENGTH {
        return Err(uri_invalid("the address is empty or too long"));
    }
    if !value.bytes().all(|b| b.is_ascii_graphic()) {
        return Err(uri_invalid(
            "the address has a space or a character outside ASCII",
        ));
    }
    if value.contains('#') || value.contains('\\') {
        return Err(uri_invalid("the address has a fragment or a backslash"));
    }
    let Some(rest) = value
        .strip_prefix("https://")
        .or_else(|| value.strip_prefix("http://"))
    else {
        return Err(uri_invalid("the address is not HTTPS"));
    };
    let authority = rest.split(['/', '?']).next().unwrap_or_default();
    if authority.contains('@') {
        return Err(uri_invalid("the address has a name and password"));
    }
    let (host, port) = if authority.starts_with('[') {
        match authority.split_once(']') {
            Some((inside, "")) => (inside.trim_start_matches('['), None),
            Some((inside, after)) => (
                inside.trim_start_matches('['),
                Some(after.strip_prefix(':').unwrap_or("not a port")),
            ),
            None => ("", None),
        }
    } else {
        match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        }
    };
    if host.is_empty() || port.is_some_and(|p| !is_port(p)) {
        return Err(uri_invalid("the address has no usable host"));
    }
    Ok(())
}

/// The header of a logout token signed by the key version `key_id`.
#[must_use]
pub fn logout_token_header(algorithm: &str, key_id: &str) -> Value {
    json!({"alg": algorithm, "typ": LOGOUT_TOKEN_TYPE, "kid": key_id})
}

/// What a logout token says.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogoutTokenSubject<'a> {
    /// The tenant's issuer.
    pub issuer: &'a str,
    /// The client it is for.
    pub client_id: ClientId,
    /// The person whose session ended.
    pub user_id: UserId,
    /// The session that ended.
    pub session_id: SessionId,
}

/// The claims of a logout token signed at `now`, with `token_id` as its
/// `jti` (OpenID Connect Back-Channel Logout, section 2.4). Never a
/// `nonce`.
#[must_use]
pub fn logout_token_claims(
    subject: LogoutTokenSubject<'_>,
    now: Timestamp,
    token_id: &str,
) -> Value {
    json!({
        "iss": subject.issuer,
        "sub": subject.user_id.to_string(),
        "aud": subject.client_id.to_string(),
        "iat": now.unix_timestamp(),
        "exp": (now + LOGOUT_TOKEN_LIFETIME).unix_timestamp(),
        "jti": token_id,
        "events": { BACKCHANNEL_LOGOUT_EVENT: {} },
        "sid": subject.session_id.to_string(),
    })
}

/// Where a logout delivery is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum LogoutDeliveryStatus {
    /// Waiting for its next attempt, or being sent.
    Pending,
    /// The client took it.
    Delivered,
    /// Every attempt failed, or the client could no longer be sent to.
    SetAside,
}

impl LogoutDeliveryStatus {
    /// Every status.
    pub const ALL: [Self; 3] = [Self::Pending, Self::Delivered, Self::SetAside];

    /// The name it is stored under.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Delivered => "delivered",
            Self::SetAside => "set_aside",
        }
    }

    /// Reads a status by its name.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|status| status.as_str() == name)
    }
}

/// How many attempts a logout delivery gets, and how long it waits between
/// them: the rules of webhooks, which this context does not depend on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LogoutRetryPolicy {
    max_attempts: u32,
    first_wait: Duration,
}

impl LogoutRetryPolicy {
    /// The longest wait between two attempts.
    pub const LONGEST_WAIT: Duration = Duration::hours(1);

    /// Eight attempts, the first wait 30 seconds.
    pub const DEFAULT: Self = Self {
        max_attempts: 8,
        first_wait: Duration::seconds(30),
    };

    /// A policy of `max_attempts` attempts, from 1 to 20, the first wait
    /// `first_wait`, more than nothing and at most an hour.
    ///
    /// # Errors
    ///
    /// Returns `oauth.logout_retry_policy_invalid` outside those bounds.
    pub fn new(max_attempts: u32, first_wait: Duration) -> Result<Self, DomainError> {
        if !(1..=20).contains(&max_attempts)
            || first_wait <= Duration::ZERO
            || first_wait > Self::LONGEST_WAIT
        {
            return Err(DomainError::invalid(
                "oauth.logout_retry_policy_invalid",
                "a logout delivery has 1 to 20 attempts, and the first wait is more than nothing \
                 and at most an hour",
            ));
        }
        Ok(Self {
            max_attempts,
            first_wait,
        })
    }

    /// How many attempts a delivery gets.
    #[must_use]
    pub const fn max_attempts(&self) -> u32 {
        self.max_attempts
    }

    /// The wait after the attempt numbered `attempts`, counted from 1: the
    /// first wait, doubled after each attempt, up to an hour.
    #[must_use]
    pub fn wait_after(&self, attempts: u32) -> Duration {
        let doublings = attempts.saturating_sub(1).min(31);
        let factor = i32::try_from(1_u64 << doublings).unwrap_or(i32::MAX);
        self.first_wait
            .checked_mul(factor)
            .unwrap_or(Self::LONGEST_WAIT)
            .min(Self::LONGEST_WAIT)
    }
}

impl Default for LogoutRetryPolicy {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// Everything about a logout delivery, for storage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutDeliverySnapshot {
    /// Its identifier.
    pub id: LogoutDeliveryId,
    /// The client it goes to.
    pub client_id: ClientId,
    /// The session that ended: the token's `sid`.
    pub session_id: SessionId,
    /// Whose session it was: the token's `sub`.
    pub user_id: UserId,
    /// Where it is.
    pub status: LogoutDeliveryStatus,
    /// How many attempts were made.
    pub attempts: u32,
    /// When the next attempt is due.
    pub next_attempt_at: Timestamp,
    /// While a worker sends it, when its lease ends.
    pub leased_until: Option<Timestamp>,
    /// The status of the last answer, if the client answered.
    pub last_response_status: Option<u16>,
    /// Why the last attempt failed.
    pub last_error: Option<String>,
    /// When it was made.
    pub created_at: Timestamp,
    /// When it was delivered or set aside.
    pub finished_at: Option<Timestamp>,
}

/// One logout token on its way to one client, for one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogoutDelivery {
    state: LogoutDeliverySnapshot,
}

fn shortened(reason: &str) -> String {
    reason.chars().take(MAX_LOGOUT_ERROR_LENGTH).collect()
}

impl LogoutDelivery {
    /// A delivery to `client_id` for the end of `session_id`, due at once.
    #[must_use]
    pub fn make(
        client_id: ClientId,
        session_id: SessionId,
        user_id: UserId,
        now: Timestamp,
    ) -> Self {
        Self {
            state: LogoutDeliverySnapshot {
                id: LogoutDeliveryId::generate(),
                client_id,
                session_id,
                user_id,
                status: LogoutDeliveryStatus::Pending,
                attempts: 0,
                next_attempt_at: now,
                leased_until: None,
                last_response_status: None,
                last_error: None,
                created_at: now,
                finished_at: None,
            },
        }
    }

    /// Rebuilds a delivery read from storage.
    #[must_use]
    pub const fn from_snapshot(state: LogoutDeliverySnapshot) -> Self {
        Self { state }
    }

    /// Everything about it.
    #[must_use]
    pub const fn snapshot(&self) -> &LogoutDeliverySnapshot {
        &self.state
    }

    /// Its identifier.
    #[must_use]
    pub const fn id(&self) -> LogoutDeliveryId {
        self.state.id
    }

    /// Where it is.
    #[must_use]
    pub const fn status(&self) -> LogoutDeliveryStatus {
        self.state.status
    }

    /// Whether it may be leased at `now`: pending, due, and not leased by
    /// anyone whose lease still runs.
    #[must_use]
    pub fn is_due(&self, now: Timestamp) -> bool {
        self.state.status == LogoutDeliveryStatus::Pending
            && self.state.next_attempt_at <= now
            && self.state.leased_until.is_none_or(|until| until <= now)
    }

    /// Whether a worker's lease runs at `now`.
    #[must_use]
    pub fn is_leased(&self, now: Timestamp) -> bool {
        self.state.status == LogoutDeliveryStatus::Pending
            && self.state.leased_until.is_some_and(|until| until > now)
    }

    /// Leases it to the worker about to send it, until `until`.
    ///
    /// # Errors
    ///
    /// Returns `oauth.logout_delivery_not_due` unless it is due at `now`.
    pub fn lease(&mut self, now: Timestamp, until: Timestamp) -> Result<(), DomainError> {
        if !self.is_due(now) {
            return Err(DomainError::conflict(
                "oauth.logout_delivery_not_due",
                "the logout delivery is not due",
            ));
        }
        self.state.leased_until = Some(until);
        Ok(())
    }

    /// Whether it is still the delivery a worker leased after `attempts`
    /// attempts: pending, leased, and with no attempt recorded since.
    #[must_use]
    pub fn is_as_leased(&self, attempts: u32) -> bool {
        self.state.status == LogoutDeliveryStatus::Pending
            && self.state.leased_until.is_some()
            && self.state.attempts == attempts
    }

    /// The client took it.
    pub fn record_success(&mut self, now: Timestamp, status: u16) {
        self.state.attempts += 1;
        self.state.status = LogoutDeliveryStatus::Delivered;
        self.state.leased_until = None;
        self.state.last_response_status = Some(status);
        self.state.last_error = None;
        self.state.finished_at = Some(now);
    }

    /// An attempt failed: the next one waits longer, or, after the last,
    /// the delivery is set aside and the event that says so returned.
    pub fn record_failure(
        &mut self,
        now: Timestamp,
        status: Option<u16>,
        reason: &str,
        policy: &LogoutRetryPolicy,
    ) -> Option<OauthEvent> {
        self.state.attempts += 1;
        self.state.leased_until = None;
        self.state.last_response_status = status;
        if self.state.attempts >= policy.max_attempts() {
            return Some(self.set_aside(now, reason));
        }
        self.state.last_error = Some(shortened(reason));
        self.state.next_attempt_at = now + policy.wait_after(self.state.attempts);
        None
    }

    /// Sets it aside without an attempt, because its client can no longer
    /// be sent to. Returns the event that says so.
    pub fn set_aside(&mut self, now: Timestamp, reason: &str) -> OauthEvent {
        self.state.status = LogoutDeliveryStatus::SetAside;
        self.state.leased_until = None;
        self.state.last_error = Some(shortened(reason));
        self.state.finished_at = Some(now);
        OauthEvent::BackchannelLogoutSetAside {
            delivery_id: self.state.id,
            client_id: self.state.client_id,
            session_id: self.state.session_id,
            attempts: self.state.attempts,
        }
    }
}

#[cfg(test)]
mod tests;
