//! Consent: what a person agreed to for a client, whether a request must
//! ask them, and the answer a waiting request was given.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Consent".

use crate::domain::authorization::AuthorizationRequest;
use crate::domain::client::ClientId;
use crate::domain::event::OauthEvent;
use crate::domain::refresh::OFFLINE_ACCESS;
use hodor_kernel::{DomainError, Timestamp, UserId};
use hodor_session::api::SessionId;
use time::Duration;

/// The consent lifetime of a client that was not given one.
pub const DEFAULT_CONSENT_LIFETIME: Duration = Duration::days(365);
/// The shortest consent lifetime a client may have.
pub const SHORTEST_CONSENT_LIFETIME: Duration = Duration::days(1);
/// The longest consent lifetime a client may have.
pub const LONGEST_CONSENT_LIFETIME: Duration = Duration::days(730);

/// Who withdrew a consent, or whose answer an entry of the history is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentActor {
    /// The person the consent is theirs.
    Person,
    /// An administrator of the tenant.
    Administrator,
}

impl ConsentActor {
    /// As stored and as events carry it.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Person => "person",
            Self::Administrator => "administrator",
        }
    }

    /// From what was stored.
    ///
    /// # Errors
    ///
    /// Returns `oauth.stored_data_invalid` for an unknown value.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "person" => Ok(Self::Person),
            "administrator" => Ok(Self::Administrator),
            _ => Err(stored_invalid()),
        }
    }
}

fn stored_invalid() -> DomainError {
    DomainError::internal(
        "oauth.stored_data_invalid",
        "stored OAuth data could not be read",
    )
}

/// What a person agreed to for one client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Consent {
    /// Whose.
    pub user_id: UserId,
    /// For which client.
    pub client_id: ClientId,
    /// The scopes agreed to, never `offline_access`.
    pub scopes: Vec<String>,
    /// The audiences of the resource servers they were agreed for.
    pub audiences: Vec<String>,
    /// When the person last agreed.
    pub given_at: Timestamp,
    /// When it runs out.
    pub expires_at: Timestamp,
    /// When it was withdrawn, if it was.
    pub withdrawn_at: Option<Timestamp>,
    /// Who withdrew it.
    pub withdrawn_by: Option<ConsentActor>,
}

fn add_missing(into: &mut Vec<String>, from: &[String]) {
    for value in from {
        if value != OFFLINE_ACCESS && !into.contains(value) {
            into.push(value.clone());
        }
    }
}

impl Consent {
    /// Whether it stands at `now`: not withdrawn and not expired.
    #[must_use]
    pub fn stands_at(&self, now: Timestamp) -> bool {
        self.withdrawn_at.is_none() && now < self.expires_at
    }

    /// Whether it stands at `now` and holds every scope and audience of
    /// `request`. `offline_access` is never covered.
    #[must_use]
    pub fn covers(&self, request: &AuthorizationRequest, now: Timestamp) -> bool {
        self.stands_at(now)
            && request
                .scopes
                .iter()
                .all(|scope| scope != OFFLINE_ACCESS && self.scopes.contains(scope))
            && request
                .audiences
                .iter()
                .all(|audience| self.audiences.contains(audience))
    }

    /// The consent after the person agrees to `request` at `now`. A
    /// consent that stands keeps what it held and gains what was asked;
    /// one that expired or was withdrawn starts over. Either way it lasts
    /// `lifetime` from `now`.
    #[must_use]
    pub fn give(
        existing: Option<&Self>,
        user_id: UserId,
        request: &AuthorizationRequest,
        lifetime: Duration,
        now: Timestamp,
    ) -> Self {
        let (mut scopes, mut audiences) = match existing {
            Some(consent) if consent.stands_at(now) => {
                (consent.scopes.clone(), consent.audiences.clone())
            }
            _ => (Vec::new(), Vec::new()),
        };
        add_missing(&mut scopes, &request.scopes);
        add_missing(&mut audiences, &request.audiences);
        Self {
            user_id,
            client_id: request.client_id,
            scopes,
            audiences,
            given_at: now,
            expires_at: now + lifetime,
            withdrawn_at: None,
            withdrawn_by: None,
        }
    }

    /// The event that says the person agreed.
    #[must_use]
    pub fn given_event(&self) -> OauthEvent {
        OauthEvent::ConsentGiven {
            client_id: self.client_id,
            user_id: self.user_id,
            scopes: self.scopes.clone(),
        }
    }

    /// Withdraws it. Returns the event, or `None` when it no longer stood.
    pub fn withdraw(&mut self, by: ConsentActor, now: Timestamp) -> Option<OauthEvent> {
        if !self.stands_at(now) {
            return None;
        }
        self.withdrawn_at = Some(now);
        self.withdrawn_by = Some(by);
        Some(OauthEvent::ConsentWithdrawn {
            client_id: self.client_id,
            user_id: self.user_id,
            by: by.as_str(),
        })
    }
}

/// Whether a request for a signed-in person must ask them. `first_party`
/// is whether the client's application is first party; `standing` is the
/// person's consent for the client, if they have one.
#[must_use]
pub fn must_ask(
    request: &AuthorizationRequest,
    standing: Option<&Consent>,
    now: Timestamp,
) -> bool {
    let asked_again = request.prompt.iter().any(|value| value == "consent");
    if request.first_party && !asked_again {
        return false;
    }
    if asked_again || request.scopes.iter().any(|scope| scope == OFFLINE_ACCESS) {
        return true;
    }
    !standing.is_some_and(|consent| consent.covers(request, now))
}

/// The scopes consented to for the client of `request`, once a code may
/// be issued for it: for a first-party application, `allowed`, the scopes
/// the client may ask for, which its administrator decided for the person;
/// for a third-party one, the scopes of the request, which the person
/// agreed to, and those of `standing`, their consent for the client, when
/// it stands at `now`. What the `claims` parameter may give claims of
/// (Decision 0068).
#[must_use]
pub fn consented_scopes(
    request: &AuthorizationRequest,
    standing: Option<&Consent>,
    allowed: &[String],
    now: Timestamp,
) -> Vec<String> {
    let mut scopes = request.scopes.clone();
    let more: &[String] = if request.first_party {
        allowed
    } else {
        match standing {
            Some(consent) if consent.stands_at(now) => &consent.scopes,
            _ => &[],
        }
    };
    for scope in more {
        if !scopes.contains(scope) {
            scopes.push(scope.clone());
        }
    }
    scopes
}

/// The person's answer to a request that waits for consent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentAnswer {
    /// They agreed: the code is issued.
    Agreed,
    /// They refused: `access_denied`.
    Refused,
}

impl ConsentAnswer {
    /// As stored.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Agreed => "agreed",
            Self::Refused => "refused",
        }
    }

    /// From what was stored.
    ///
    /// # Errors
    ///
    /// Returns `oauth.stored_data_invalid` for an unknown value.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "agreed" => Ok(Self::Agreed),
            "refused" => Ok(Self::Refused),
            _ => Err(stored_invalid()),
        }
    }
}

/// That a pending request waits for one person's consent, in one session,
/// and the answer once it was given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConsentWait {
    /// The person asked.
    pub user_id: UserId,
    /// The session they were asked in.
    pub session_id: SessionId,
    /// Their answer, once given.
    pub answer: Option<ConsentAnswer>,
}

/// What happened, for the history of a person's consents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConsentAction {
    /// The person agreed.
    Given,
    /// The person refused.
    Refused,
    /// The consent was withdrawn.
    Withdrawn,
}

impl ConsentAction {
    /// As stored.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Given => "given",
            Self::Refused => "refused",
            Self::Withdrawn => "withdrawn",
        }
    }
}

/// One entry of the history of a person's consents. Never changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ConsentHistoryEntry {
    /// Whose.
    pub user_id: UserId,
    /// For which client.
    pub client_id: ClientId,
    /// What happened.
    pub action: ConsentAction,
    /// The scopes concerned.
    pub scopes: Vec<String>,
    /// The audiences concerned.
    pub audiences: Vec<String>,
    /// Who did it.
    pub by: ConsentActor,
    /// When.
    pub at: Timestamp,
}

#[cfg(test)]
mod tests;
