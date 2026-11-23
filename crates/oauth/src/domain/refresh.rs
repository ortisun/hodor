//! Refresh tokens: the family each belongs to, how a token leads to the
//! next, and what a refresh may do.
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "Refresh tokens".

use crate::domain::authorization::{
    AuthorizationCode, GrantId, TOKEN_LENGTH, is_base64url, random_token, same_bytes,
};
use crate::domain::client::{ClientId, TokenPolicy};
use crate::domain::event::OauthEvent;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::{Digest, DomainError, RandomSource, SealedSecret, Secret, Timestamp, UserId};
use hodor_session::api::SessionId;
use std::fmt;
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies a family of refresh tokens: every token issued, one after
    /// the other, for one exchange of a code.
    RefreshFamilyId
);

/// The purpose a family's secret is sealed for.
pub const FAMILY_SECRET_PURPOSE: &str = "oauth.refresh_token_family_secret";
/// The scope that lets a family outlive the session it was made in.
pub const OFFLINE_ACCESS: &str = "offline_access";
/// How long a token one generation old is answered again, by default.
pub const DEFAULT_RETRY_WINDOW: Duration = Duration::seconds(10);
/// The longest retry window that may be configured.
pub const LONGEST_RETRY_WINDOW: Duration = Duration::seconds(60);

/// The SHA-256 of a refresh token; what is stored.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct RefreshTokenHash([u8; 32]);

impl RefreshTokenHash {
    /// The hash of a token as presented, or `None` when the value does not
    /// have the shape of a refresh token: it cannot be one, and nothing is
    /// computed.
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

impl fmt::Debug for RefreshTokenHash {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RefreshTokenHash(..)")
    }
}

/// A refresh token itself. Given to the client, and stored nowhere.
pub struct RefreshTokenValue(Secret<String>);

impl RefreshTokenValue {
    /// The token, for the answer.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose()
    }

    /// The token, to be handed on.
    #[must_use]
    pub fn into_secret(self) -> Secret<String> {
        self.0
    }

    /// Its hash.
    #[must_use]
    pub fn hash(&self, digest: &dyn Digest) -> RefreshTokenHash {
        RefreshTokenHash(digest.sha256(self.0.expose().as_bytes()))
    }
}

impl fmt::Debug for RefreshTokenValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RefreshTokenValue([REDACTED])")
    }
}

/// A family's secret, from which each token after the first is derived.
/// Kept sealed; opened only to derive.
pub struct FamilySecret(Secret<Vec<u8>>);

impl FamilySecret {
    /// 32 random bytes.
    #[must_use]
    pub fn generate(random: &dyn RandomSource) -> Self {
        let mut bytes = vec![0_u8; 32];
        random.fill(&mut bytes);
        Self(Secret::from(bytes))
    }

    /// A secret as it was opened.
    #[must_use]
    pub const fn from_opened(secret: Secret<Vec<u8>>) -> Self {
        Self(secret)
    }

    /// The secret, to be sealed.
    #[must_use]
    pub const fn as_secret(&self) -> &Secret<Vec<u8>> {
        &self.0
    }

    /// The token that comes after `presented`: the SHA-256 of the secret
    /// followed by `presented`. The same token always leads to the same
    /// next one, which is what lets a retry be answered without anything of
    /// the answer being stored.
    #[must_use]
    pub fn next_after(&self, presented: &str, digest: &dyn Digest) -> RefreshTokenValue {
        let mut input = Vec::with_capacity(self.0.expose().len() + presented.len());
        input.extend_from_slice(self.0.expose());
        input.extend_from_slice(presented.as_bytes());
        RefreshTokenValue(Secret::from(URL_SAFE_NO_PAD.encode(digest.sha256(&input))))
    }
}

impl fmt::Debug for FamilySecret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("FamilySecret([REDACTED])")
    }
}

/// Whether a family still stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FamilyStatus {
    /// It stands.
    Active,
    /// It was revoked.
    Revoked,
}

impl FamilyStatus {
    /// As stored.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }

    /// From what was stored.
    ///
    /// # Errors
    ///
    /// Returns `oauth.stored_data_invalid` for an unknown value.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            _ => Err(DomainError::internal(
                "oauth.stored_data_invalid",
                "stored OAuth data could not be read",
            )),
        }
    }
}

/// What a move asked for: the scopes and the resource of the refresh that
/// moved the family. A retry must ask for the same.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RefreshAsk {
    /// The scopes asked for, in the order of the family; empty when the
    /// refresh named none.
    pub scopes: Vec<String>,
    /// The resource asked for.
    pub resource: Option<String>,
}

/// A family of refresh tokens.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefreshFamily {
    /// Its identifier.
    pub id: RefreshFamilyId,
    /// The grant it was issued under.
    pub grant_id: GrantId,
    /// The client it was issued to.
    pub client_id: ClientId,
    /// The person.
    pub user_id: UserId,
    /// The session the code was issued in.
    pub session_id: SessionId,
    /// The scopes of the code.
    pub scopes: Vec<String>,
    /// The audiences of the code.
    pub audiences: Vec<String>,
    /// Whether it outlives its session: the code held `offline_access`.
    pub offline: bool,
    /// When the person signed in.
    pub signed_in_at: Timestamp,
    /// The methods they signed in with.
    pub methods: Vec<String>,
    /// The secret each next token is derived with, sealed.
    pub sealed_secret: SealedSecret,
    /// The generation of its newest token, from 1.
    pub generation: i32,
    /// The hash of its newest token.
    pub current_hash: RefreshTokenHash,
    /// When it last moved, if it has.
    pub moved_at: Option<Timestamp>,
    /// What the refresh that last moved it asked for.
    pub moved_for: RefreshAsk,
    /// Whether it stands.
    pub status: FamilyStatus,
    /// When it started.
    pub created_at: Timestamp,
    /// When it ends whatever happens: its absolute lifetime.
    pub expires_at: Timestamp,
    /// How long its newest token lasts unused.
    pub idle: Duration,
    /// When it was last used.
    pub last_used_at: Timestamp,
    /// When it was revoked.
    pub revoked_at: Option<Timestamp>,
    /// Why, such as `refresh_token_reused`.
    pub revocation_reason: Option<String>,
}

/// A token of a family, as stored.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RefreshTokenRecord {
    /// Its hash.
    pub hash: RefreshTokenHash,
    /// Its family.
    pub family_id: RefreshFamilyId,
    /// Its generation.
    pub generation: i32,
    /// When it was issued.
    pub issued_at: Timestamp,
}

/// Why a refresh is refused. The client is told `invalid_grant` for each,
/// except `ScopeNotGranted` (`invalid_scope`) and `ResourceNotGranted`
/// (`invalid_target`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RefreshRefusal {
    /// The family was revoked.
    Revoked,
    /// Its absolute lifetime is over.
    Expired,
    /// It was not used for its idle time.
    Idle,
    /// Another client presented it: it has leaked, and the family is
    /// revoked.
    OtherClient,
    /// A token used before was presented again, outside a retry: the family
    /// and its grant are revoked.
    Reused,
    /// A scope asked for is not one of the family's.
    ScopeNotGranted,
    /// The resource asked for is not one of the family's audiences.
    ResourceNotGranted,
}

impl RefreshRefusal {
    /// The reason, for logs and events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
            Self::Expired => "expired",
            Self::Idle => "idle",
            Self::OtherClient => "other_client",
            Self::Reused => "refresh_token_reused",
            Self::ScopeNotGranted => "scope_not_granted",
            Self::ResourceNotGranted => "resource_not_granted",
        }
    }

    /// Whether the family is revoked for it.
    #[must_use]
    pub const fn revokes_the_family(self) -> bool {
        matches!(self, Self::OtherClient | Self::Reused)
    }

    /// Whether the grant is revoked for it as well.
    #[must_use]
    pub const fn revokes_the_grant(self) -> bool {
        matches!(self, Self::Reused)
    }
}

/// What a refresh does, once its token is found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshDecision {
    /// The newest token: move the family one generation.
    Move(RefreshAsk),
    /// A token one generation old presented again within the window for the
    /// same request: answer again with the same next token.
    Retry(RefreshAsk),
}

impl RefreshFamily {
    /// The family for a redeemed `code`, with the client's `policy`, and
    /// its first token.
    #[must_use]
    pub fn start(
        code: &AuthorizationCode,
        policy: &TokenPolicy,
        sealed_secret: SealedSecret,
        now: Timestamp,
        random: &dyn RandomSource,
        digest: &dyn Digest,
    ) -> (Self, RefreshTokenValue) {
        let first = RefreshTokenValue(Secret::from(random_token(random)));
        let family = Self {
            id: RefreshFamilyId::generate(),
            grant_id: code.grant_id,
            client_id: code.client_id,
            user_id: code.user_id,
            session_id: code.session_id,
            scopes: code.scopes.clone(),
            audiences: code.audiences.clone(),
            offline: code.scopes.iter().any(|scope| scope == OFFLINE_ACCESS),
            signed_in_at: code.signed_in_at,
            methods: code.methods.clone(),
            sealed_secret,
            generation: 1,
            current_hash: first.hash(digest),
            moved_at: None,
            moved_for: RefreshAsk::default(),
            status: FamilyStatus::Active,
            created_at: now,
            expires_at: now + policy.refresh_token,
            idle: policy.refresh_idle,
            last_used_at: now,
            revoked_at: None,
            revocation_reason: None,
        };
        (family, first)
    }

    /// The record of its first token.
    #[must_use]
    pub const fn first_record(&self) -> RefreshTokenRecord {
        RefreshTokenRecord {
            hash: self.current_hash,
            family_id: self.id,
            generation: 1,
            issued_at: self.created_at,
        }
    }

    /// What `asked` comes to against the family: the scopes and resource
    /// it narrows to, or why it cannot.
    fn ask(
        &self,
        scope: Option<&str>,
        resource: Option<&str>,
    ) -> Result<RefreshAsk, RefreshRefusal> {
        let mut scopes = Vec::new();
        if let Some(scope) = scope {
            for asked in scope.split(' ').filter(|asked| !asked.is_empty()) {
                if !self.scopes.iter().any(|granted| granted == asked) {
                    return Err(RefreshRefusal::ScopeNotGranted);
                }
                if !scopes.iter().any(|known: &String| known == asked) {
                    scopes.push(asked.to_owned());
                }
            }
            // Kept in the order of the family, so that the same scopes
            // asked in another order are the same request.
            scopes.sort_by_key(|asked| self.scopes.iter().position(|granted| granted == asked));
        }
        if let Some(resource) = resource
            && !self.audiences.iter().any(|audience| audience == resource)
        {
            return Err(RefreshRefusal::ResourceNotGranted);
        }
        Ok(RefreshAsk {
            scopes,
            resource: resource.map(str::to_owned),
        })
    }

    /// Decides a refresh with the token of `generation`, presented by
    /// `client`, asking for `scope` and `resource`, at `now`, with the
    /// retry window `window`. The checks of the grant, the person and the
    /// session are the service's.
    ///
    /// # Errors
    ///
    /// Returns why the refresh is refused.
    pub fn decide(
        &self,
        generation: i32,
        client: ClientId,
        scope: Option<&str>,
        resource: Option<&str>,
        now: Timestamp,
        window: Duration,
    ) -> Result<RefreshDecision, RefreshRefusal> {
        if self.status == FamilyStatus::Revoked {
            return Err(RefreshRefusal::Revoked);
        }
        if now >= self.expires_at {
            return Err(RefreshRefusal::Expired);
        }
        if client != self.client_id {
            return Err(RefreshRefusal::OtherClient);
        }
        if generation < self.generation {
            let asked = self.ask(scope, resource);
            let retry = generation == self.generation - 1
                && self.moved_at.is_some_and(|moved| now < moved + window)
                && asked.as_ref().is_ok_and(|asked| *asked == self.moved_for);
            return match asked {
                Ok(asked) if retry => Ok(RefreshDecision::Retry(asked)),
                _ => Err(RefreshRefusal::Reused),
            };
        }
        if now >= self.last_used_at + self.idle {
            return Err(RefreshRefusal::Idle);
        }
        self.ask(scope, resource).map(RefreshDecision::Move)
    }

    /// Whether `token`, derived again for a retry, is the newest of the
    /// family: that the family has not moved again since.
    #[must_use]
    pub fn is_newest(&self, token: &RefreshTokenValue, digest: &dyn Digest) -> bool {
        same_bytes(token.hash(digest).as_bytes(), self.current_hash.as_bytes())
    }

    /// Revokes it. Returns the event, or `None` if it was revoked already.
    pub fn revoke(&mut self, reason: &'static str, now: Timestamp) -> Option<OauthEvent> {
        if self.status == FamilyStatus::Revoked {
            return None;
        }
        self.status = FamilyStatus::Revoked;
        self.revoked_at = Some(now);
        self.revocation_reason = Some(reason.to_owned());
        Some(OauthEvent::RefreshTokenFamilyRevoked {
            family_id: self.id,
            grant_id: self.grant_id,
            client_id: self.client_id,
            reason,
        })
    }

    /// The event that says it started.
    #[must_use]
    pub const fn started_event(&self) -> OauthEvent {
        OauthEvent::RefreshTokenFamilyStarted {
            family_id: self.id,
            grant_id: self.grant_id,
            client_id: self.client_id,
            user_id: self.user_id,
            offline: self.offline,
        }
    }
}

#[cfg(test)]
mod tests;
