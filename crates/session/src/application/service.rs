//! The use cases of the session context.

use crate::application::ports::SessionStore;
use crate::domain::event::SessionEvent;
use crate::domain::session::{
    Assurance, ClientInfo, Session, SessionId, SessionState, SessionTimeouts, SessionToken,
    TokenHash,
};
use hodor_kernel::{
    Caller, Clock, Digest, DomainError, EventEnvelope, EventMetadata, RandomSource, TenantContext,
    UnitOfWork, UnitOfWorkFactory, UserId,
};
use std::sync::Arc;

/// What is needed to start a session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartSession {
    /// Whose session it is.
    pub user_id: UserId,
    /// How strongly the user proved who they are.
    pub assurance: Assurance,
    /// By which methods.
    pub methods: Vec<String>,
    /// The tenant's timeouts.
    pub timeouts: SessionTimeouts,
    /// Where the request came from.
    pub client: ClientInfo,
}

/// The use cases of the session context.
#[derive(Clone)]
pub struct SessionService {
    units_of_work: Arc<dyn UnitOfWorkFactory>,
    sessions: Arc<dyn SessionStore>,
    digest: Arc<dyn Digest>,
    random: Arc<dyn RandomSource>,
    clock: Arc<dyn Clock>,
}

impl std::fmt::Debug for SessionService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SessionService").finish_non_exhaustive()
    }
}

impl SessionService {
    /// Wires the use cases to their ports.
    #[must_use]
    pub fn new(
        units_of_work: Arc<dyn UnitOfWorkFactory>,
        sessions: Arc<dyn SessionStore>,
        digest: Arc<dyn Digest>,
        random: Arc<dyn RandomSource>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            units_of_work,
            sessions,
            digest,
            random,
            clock,
        }
    }

    /// Starts a session and returns it with its token. The token is not
    /// available again.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if the timeouts or methods are not acceptable.
    pub async fn start(
        &self,
        tenant: &TenantContext,
        command: StartSession,
        caller: Caller,
    ) -> Result<(Session, SessionToken), DomainError> {
        let (session, token, event) = Session::start(
            command.user_id,
            command.assurance,
            command.methods,
            command.timeouts,
            command.client,
            self.clock.now(),
            self.random.as_ref(),
            self.digest.as_ref(),
        )?;
        let mut uow = self.units_of_work.begin(tenant).await?;
        self.sessions.insert(uow.as_mut(), &session).await?;
        self.record(uow.as_mut(), caller, &event)?;
        uow.commit().await?;
        Ok((session, token))
    }

    /// Returns the active session a presented token belongs to, and
    /// records the activity.
    ///
    /// A token that is malformed, unknown, expired or revoked finds
    /// nothing; the four are not told apart.
    ///
    /// # Errors
    ///
    /// Returns an error only if storage fails.
    pub async fn find_by_token(
        &self,
        tenant: &TenantContext,
        presented: &str,
    ) -> Result<Option<Session>, DomainError> {
        let Some(hash) = TokenHash::of_presented(presented, self.digest.as_ref()) else {
            return Ok(None);
        };
        let now = self.clock.now();
        let mut uow = self.units_of_work.begin(tenant).await?;
        let Some(mut session) = self
            .sessions
            .find_by_token_hash(uow.as_mut(), &hash)
            .await?
        else {
            return Ok(None);
        };
        if session.state_at(now) != SessionState::Active {
            return Ok(None);
        }
        if session.record_activity(now) {
            self.sessions.update(uow.as_mut(), &session).await?;
            uow.commit().await?;
        }
        Ok(Some(session))
    }

    /// Returns a user's active sessions, newest first.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn list_for_user(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
    ) -> Result<Vec<Session>, DomainError> {
        let now = self.clock.now();
        let mut uow = self.units_of_work.begin(tenant).await?;
        let sessions = self
            .sessions
            .list_for_user(uow.as_mut(), user_id, now)
            .await?;
        Ok(sessions
            .into_iter()
            .filter(|session| session.state_at(now) == SessionState::Active)
            .collect())
    }

    /// Ends one session. Ending a session that is already revoked changes
    /// nothing.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has no such session.
    pub async fn revoke(
        &self,
        tenant: &TenantContext,
        id: SessionId,
        reason: &str,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut session = self.sessions.get(uow.as_mut(), id).await?.ok_or_else(|| {
            DomainError::not_found("session.not_found", "the session does not exist")
        })?;
        if let Some(event) = session.revoke(reason, self.clock.now()) {
            self.sessions.update(uow.as_mut(), &session).await?;
            self.record(uow.as_mut(), caller, &event)?;
            uow.commit().await?;
        }
        Ok(())
    }

    /// Ends a session only if it belongs to the given user and is active.
    /// This is what a person uses on their own sessions.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has no such session, if it is
    /// another user's, or if it has already ended. The three are not told
    /// apart, so that one person cannot learn about another's sessions.
    pub async fn revoke_for_user(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        id: SessionId,
        reason: &str,
        caller: Caller,
    ) -> Result<(), DomainError> {
        let not_found =
            || DomainError::not_found("session.not_found", "the session does not exist");
        let now = self.clock.now();
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut session = self
            .sessions
            .get(uow.as_mut(), id)
            .await?
            .filter(|session| {
                session.user_id() == user_id && session.state_at(now) == SessionState::Active
            })
            .ok_or_else(not_found)?;
        let event = session.revoke(reason, now).ok_or_else(not_found)?;
        self.sessions.update(uow.as_mut(), &session).await?;
        self.record(uow.as_mut(), caller, &event)?;
        uow.commit().await
    }

    /// Ends all of a user's active sessions, optionally keeping one.
    /// Returns how many were ended.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails.
    pub async fn revoke_all_for_user(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        keep: Option<SessionId>,
        reason: &str,
        caller: Caller,
    ) -> Result<usize, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let ended = self
            .revoke_all_for_user_in(uow.as_mut(), user_id, keep, reason, caller)
            .await?;
        if ended > 0 {
            uow.commit().await?;
        }
        Ok(ended)
    }

    /// As [`SessionService::revoke_all_for_user`], in the caller's unit of
    /// work, so that the sessions end together with whatever else the
    /// caller is doing, or not at all.
    ///
    /// # Errors
    ///
    /// Returns an error if storage fails. After an error the unit of work
    /// must be abandoned.
    pub async fn revoke_all_for_user_in(
        &self,
        uow: &mut dyn UnitOfWork,
        user_id: UserId,
        keep: Option<SessionId>,
        reason: &str,
        caller: Caller,
    ) -> Result<usize, DomainError> {
        let now = self.clock.now();
        let sessions = self.sessions.list_for_user(uow, user_id, now).await?;
        let mut ended = 0;
        for mut session in sessions {
            if Some(session.id()) == keep {
                continue;
            }
            if let Some(event) = session.revoke(reason, now) {
                self.sessions.update(uow, &session).await?;
                self.record(uow, caller, &event)?;
                ended += 1;
            }
        }
        Ok(ended)
    }

    /// Gives a session a new token; the old one stops working at once.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has no such session, and `Conflict`
    /// if it is no longer active.
    pub async fn replace_token(
        &self,
        tenant: &TenantContext,
        id: SessionId,
    ) -> Result<SessionToken, DomainError> {
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut session = self.sessions.get(uow.as_mut(), id).await?.ok_or_else(|| {
            DomainError::not_found("session.not_found", "the session does not exist")
        })?;
        let token =
            session.replace_token(self.clock.now(), self.random.as_ref(), self.digest.as_ref())?;
        self.sessions.update(uow.as_mut(), &session).await?;
        uow.commit().await?;
        Ok(token)
    }

    /// Raises a session after a step-up, as the specification says: only
    /// an active session of `user_id` is raised. Returns the session and its
    /// new token; the old token stops working at once.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the tenant has no such session, if it is
    /// another user's or no longer active, and `Invalid` if no method was
    /// proven.
    pub async fn raise(
        &self,
        tenant: &TenantContext,
        user_id: UserId,
        id: SessionId,
        proven: &[String],
        assurance: Assurance,
        caller: Caller,
    ) -> Result<(Session, SessionToken), DomainError> {
        let now = self.clock.now();
        let mut uow = self.units_of_work.begin(tenant).await?;
        let mut session = self
            .sessions
            .get(uow.as_mut(), id)
            .await?
            .filter(|session| {
                session.user_id() == user_id && session.state_at(now) == SessionState::Active
            })
            .ok_or_else(|| {
                DomainError::not_found("session.not_found", "the session does not exist")
            })?;
        let (token, event) = session.raise(
            proven,
            assurance,
            now,
            self.random.as_ref(),
            self.digest.as_ref(),
        )?;
        self.sessions.update(uow.as_mut(), &session).await?;
        self.record(uow.as_mut(), caller, &event)?;
        uow.commit().await?;
        Ok((session, token))
    }

    fn record(
        &self,
        uow: &mut dyn UnitOfWork,
        caller: Caller,
        event: &SessionEvent,
    ) -> Result<(), DomainError> {
        let metadata = EventMetadata::new(
            uow.tenant().tenant_id(),
            caller.actor,
            caller.correlation_id,
            self.clock.as_ref(),
        );
        uow.record_event(EventEnvelope::new(metadata, event)?);
        Ok(())
    }
}
