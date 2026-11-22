//! The user aggregate: lifecycle and login identifiers.

use crate::domain::event::UserEvent;
use crate::domain::identifier::{
    IdentifierId, IdentifierKind, LoginIdentifier, NormalizedIdentifier,
};
use hodor_kernel::{DomainError, Timestamp, UserId};

/// What sort of principal a user is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserKind {
    /// A person.
    Human,
    /// A workload acting for an application.
    ServiceAccount,
    /// An artificial intelligence agent.
    Agent,
}

impl UserKind {
    /// The name used in storage and in events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Human => "human",
            Self::ServiceAccount => "service_account",
            Self::Agent => "agent",
        }
    }

    /// Reads a kind from its stored name.
    ///
    /// # Errors
    ///
    /// Returns an internal error for an unknown name.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "human" => Ok(Self::Human),
            "service_account" => Ok(Self::ServiceAccount),
            "agent" => Ok(Self::Agent),
            other => Err(unknown_stored("user kind", other)),
        }
    }
}

/// Where a user is in their life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum UserStatus {
    /// Created, but not confirmed yet.
    Pending,
    /// Normal.
    Active,
    /// Blocked by an administrator or a security rule.
    Suspended,
    /// Closed; can be restored.
    Deactivated,
    /// Personal data erased; only the identifier remains.
    Deleted,
}

impl UserStatus {
    /// The name used in storage and in events.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::Deactivated => "deactivated",
            Self::Deleted => "deleted",
        }
    }

    /// Reads a status from its stored name.
    ///
    /// # Errors
    ///
    /// Returns an internal error for an unknown name.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "deactivated" => Ok(Self::Deactivated),
            "deleted" => Ok(Self::Deleted),
            other => Err(unknown_stored("user status", other)),
        }
    }
}

fn unknown_stored(what: &str, value: &str) -> DomainError {
    DomainError::internal(
        "identity.stored_data_invalid",
        "the user could not be loaded",
    )
    .with_detail(format!("unknown stored {what} `{value}`"))
}

/// The optional, human-facing details of a user.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Profile {
    /// The name shown for the user.
    pub display_name: Option<String>,
    /// Language tag such as `en` or `pt-BR`.
    pub locale: Option<String>,
}

impl Profile {
    /// Longest display name, in characters.
    pub const MAX_DISPLAY_NAME_LENGTH: usize = 200;

    fn validated(self) -> Result<Self, DomainError> {
        let display_name = self
            .display_name
            .map(|name| name.trim().to_owned())
            .filter(|name| !name.is_empty());
        if display_name
            .as_ref()
            .is_some_and(|name| name.chars().count() > Self::MAX_DISPLAY_NAME_LENGTH)
        {
            return Err(DomainError::invalid(
                "identity.display_name_invalid",
                "a display name has at most 200 characters",
            ));
        }
        let locale = self
            .locale
            .map(|locale| locale.trim().to_owned())
            .filter(|locale| !locale.is_empty());
        if locale
            .as_deref()
            .is_some_and(|locale| !is_language_tag(locale))
        {
            return Err(DomainError::invalid(
                "identity.locale_invalid",
                "a locale is a language tag such as en or pt-BR",
            ));
        }
        Ok(Self {
            display_name,
            locale,
        })
    }
}

/// A light check of the shape of a language tag: a 2 or 3 letter language,
/// then optional subtags of 2 to 8 letters or digits.
fn is_language_tag(value: &str) -> bool {
    let mut parts = value.split('-');
    let language_ok = parts
        .next()
        .is_some_and(|p| (2..=3).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphabetic()));
    language_ok
        && parts.all(|p| (2..=8).contains(&p.len()) && p.bytes().all(|b| b.is_ascii_alphanumeric()))
}

/// The state of a user as it is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UserSnapshot {
    /// The user's identifier.
    pub id: UserId,
    /// What sort of principal the user is.
    pub kind: UserKind,
    /// The user's status.
    pub status: UserStatus,
    /// Why the user was last suspended.
    pub status_reason: Option<String>,
    /// Display name and locale.
    pub profile: Profile,
    /// The names the user can be found by, oldest first.
    pub identifiers: Vec<LoginIdentifier>,
    /// When the user was created.
    pub created_at: Timestamp,
    /// When the user was last changed.
    pub updated_at: Timestamp,
    /// Incremented on every stored change, for optimistic locking.
    pub version: u32,
}

/// A user of a tenant.
///
/// Every method that changes the user checks the rules of
/// `docs/architecture/contexts/identity.md` and returns the events that
/// describe the change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct User {
    state: UserSnapshot,
}

impl User {
    /// Most login identifiers a user may have.
    pub const MAX_IDENTIFIERS: usize = 10;

    /// Creates a user.
    ///
    /// The user starts `Pending`, or `Active` when `confirmed` is set, as
    /// when an administrator creates an account by hand. The first
    /// identifier of each kind becomes primary.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error if a person is created without any login
    /// identifier, if there are too many, or if the same one is given twice.
    pub fn create(
        kind: UserKind,
        identifiers: Vec<NormalizedIdentifier>,
        profile: Profile,
        confirmed: bool,
        now: Timestamp,
    ) -> Result<(Self, Vec<UserEvent>), DomainError> {
        if kind == UserKind::Human && identifiers.is_empty() {
            return Err(DomainError::invalid(
                "identity.identifier_required",
                "a person needs at least one login identifier",
            ));
        }
        let status = if confirmed {
            UserStatus::Active
        } else {
            UserStatus::Pending
        };
        let mut user = Self {
            state: UserSnapshot {
                id: UserId::generate(),
                kind,
                status,
                status_reason: None,
                profile: profile.validated()?,
                identifiers: Vec::new(),
                created_at: now,
                updated_at: now,
                version: 0,
            },
        };
        let mut events = vec![UserEvent::Created {
            user_id: user.state.id,
            kind: kind.as_str(),
            status: status.as_str(),
        }];
        for identifier in identifiers {
            events.push(user.add_identifier(identifier, now)?);
        }
        Ok((user, events))
    }

    /// Rebuilds a user from stored state.
    #[must_use]
    pub const fn from_snapshot(state: UserSnapshot) -> Self {
        Self { state }
    }

    /// The user's current state, for storage and for reading.
    #[must_use]
    pub const fn snapshot(&self) -> &UserSnapshot {
        &self.state
    }

    /// The user's identifier.
    #[must_use]
    pub const fn id(&self) -> UserId {
        self.state.id
    }

    /// The user's status.
    #[must_use]
    pub const fn status(&self) -> UserStatus {
        self.state.status
    }

    /// Whether the user may sign in.
    #[must_use]
    pub const fn may_sign_in(&self) -> bool {
        matches!(self.state.status, UserStatus::Active)
    }

    /// The user's login identifiers, oldest first.
    #[must_use]
    pub fn identifiers(&self) -> &[LoginIdentifier] {
        &self.state.identifiers
    }

    /// Confirms a pending user.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error unless the user is `Pending`.
    pub fn activate(&mut self, now: Timestamp) -> Result<UserEvent, DomainError> {
        self.require(&[UserStatus::Pending], "activated")?;
        self.transition(UserStatus::Active, now);
        Ok(UserEvent::Activated {
            user_id: self.state.id,
        })
    }

    /// Blocks the user, recording why.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error unless the user is `Active`, and an
    /// `Invalid` error if the reason is empty.
    pub fn suspend(&mut self, reason: &str, now: Timestamp) -> Result<UserEvent, DomainError> {
        self.require(&[UserStatus::Active], "suspended")?;
        let reason = reason.trim();
        if reason.is_empty() {
            return Err(DomainError::invalid(
                "identity.suspension_reason_missing",
                "a reason is required to suspend a user",
            ));
        }
        self.transition(UserStatus::Suspended, now);
        self.state.status_reason = Some(reason.to_owned());
        Ok(UserEvent::Suspended {
            user_id: self.state.id,
            reason: reason.to_owned(),
        })
    }

    /// Unblocks a suspended user.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error unless the user is `Suspended`.
    pub fn reactivate(&mut self, now: Timestamp) -> Result<UserEvent, DomainError> {
        self.require(&[UserStatus::Suspended], "reactivated")?;
        self.transition(UserStatus::Active, now);
        Ok(UserEvent::Reactivated {
            user_id: self.state.id,
        })
    }

    /// Closes the user's account. It can be restored.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error if the user is already `Deactivated` or
    /// `Deleted`.
    pub fn deactivate(&mut self, now: Timestamp) -> Result<UserEvent, DomainError> {
        self.require(
            &[
                UserStatus::Pending,
                UserStatus::Active,
                UserStatus::Suspended,
            ],
            "deactivated",
        )?;
        self.transition(UserStatus::Deactivated, now);
        Ok(UserEvent::Deactivated {
            user_id: self.state.id,
        })
    }

    /// Reopens a closed account.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error unless the user is `Deactivated`, and an
    /// `Invalid` error if a person would be restored with no login
    /// identifier left.
    pub fn restore(&mut self, now: Timestamp) -> Result<UserEvent, DomainError> {
        self.require(&[UserStatus::Deactivated], "restored")?;
        if self.state.kind == UserKind::Human && self.state.identifiers.is_empty() {
            return Err(DomainError::invalid(
                "identity.identifier_required",
                "a person needs at least one login identifier",
            ));
        }
        self.transition(UserStatus::Active, now);
        Ok(UserEvent::Restored {
            user_id: self.state.id,
        })
    }

    /// Erases the user: login identifiers and profile are removed, and
    /// only the identifier remains so that references stay valid.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error unless the user is `Deactivated`.
    pub fn mark_deleted(&mut self, now: Timestamp) -> Result<UserEvent, DomainError> {
        self.require(&[UserStatus::Deactivated], "deleted")?;
        self.transition(UserStatus::Deleted, now);
        self.state.identifiers.clear();
        self.state.profile = Profile::default();
        Ok(UserEvent::Deleted {
            user_id: self.state.id,
        })
    }

    /// Adds a login identifier. The first of its kind becomes primary.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error if the user is deleted or already has
    /// this identifier, and an `Invalid` error if the user has the maximum
    /// number of identifiers.
    pub fn add_identifier(
        &mut self,
        value: NormalizedIdentifier,
        now: Timestamp,
    ) -> Result<UserEvent, DomainError> {
        self.require_not_deleted()?;
        if self.state.identifiers.len() >= Self::MAX_IDENTIFIERS {
            return Err(DomainError::invalid(
                "identity.too_many_identifiers",
                "a user has at most 10 login identifiers",
            ));
        }
        if self
            .state
            .identifiers
            .iter()
            .any(|i| i.value.same_as(&value))
        {
            return Err(DomainError::conflict(
                "identity.identifier_duplicate",
                "the user already has this login identifier",
            ));
        }
        let kind = value.kind();
        let primary = !self
            .state
            .identifiers
            .iter()
            .any(|i| i.value.kind() == kind);
        let id = IdentifierId::generate();
        self.state.identifiers.push(LoginIdentifier {
            id,
            value,
            verified_at: None,
            primary,
            created_at: now,
        });
        self.state.updated_at = now;
        Ok(UserEvent::IdentifierAdded {
            user_id: self.state.id,
            identifier_id: id,
            identifier_kind: kind.as_str(),
        })
    }

    /// Records that the user proved control of a login identifier.
    ///
    /// Returns `None` when it was already verified: nothing changes and
    /// there is nothing to announce.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the user has no such identifier, `Invalid` if
    /// identifiers of that kind are not verified, and `Conflict` if the
    /// user is deleted.
    pub fn verify_identifier(
        &mut self,
        id: IdentifierId,
        now: Timestamp,
    ) -> Result<Option<UserEvent>, DomainError> {
        self.require_not_deleted()?;
        let user_id = self.state.id;
        let identifier = self.identifier_mut(id)?;
        let kind = identifier.value.kind();
        if !kind.needs_verification() {
            return Err(DomainError::invalid(
                "identity.identifier_not_verifiable",
                "this kind of login identifier is not verified",
            ));
        }
        if identifier.is_verified() {
            return Ok(None);
        }
        identifier.verified_at = Some(now);
        self.state.updated_at = now;
        Ok(Some(UserEvent::IdentifierVerified {
            user_id,
            identifier_id: id,
            identifier_kind: kind.as_str(),
        }))
    }

    /// Makes a login identifier the primary one of its kind.
    ///
    /// Returns `None` when it already is.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the user has no such identifier, and
    /// `Conflict` if it needs verification and has none, or the user is
    /// deleted.
    pub fn choose_primary(
        &mut self,
        id: IdentifierId,
        now: Timestamp,
    ) -> Result<Option<UserEvent>, DomainError> {
        self.require_not_deleted()?;
        let identifier = self.identifier_mut(id)?;
        let kind = identifier.value.kind();
        if identifier.primary {
            return Ok(None);
        }
        if kind.needs_verification() && !identifier.is_verified() {
            return Err(DomainError::conflict(
                "identity.identifier_not_verified",
                "a login identifier must be verified before it becomes primary",
            ));
        }
        for other in &mut self.state.identifiers {
            if other.value.kind() == kind {
                other.primary = other.id == id;
            }
        }
        self.state.updated_at = now;
        Ok(Some(UserEvent::PrimaryIdentifierChanged {
            user_id: self.state.id,
            identifier_id: id,
            identifier_kind: kind.as_str(),
        }))
    }

    /// Removes a login identifier. If it was primary, the oldest remaining
    /// identifier of its kind becomes primary.
    ///
    /// # Errors
    ///
    /// Returns `NotFound` if the user has no such identifier, and
    /// `Conflict` if it is the last one of a user who can still be used, or
    /// the user is deleted.
    pub fn remove_identifier(
        &mut self,
        id: IdentifierId,
        now: Timestamp,
    ) -> Result<Vec<UserEvent>, DomainError> {
        self.require_not_deleted()?;
        let position = self
            .state
            .identifiers
            .iter()
            .position(|i| i.id == id)
            .ok_or_else(identifier_not_found)?;
        if self.state.identifiers.len() == 1 && self.state.status != UserStatus::Deactivated {
            return Err(DomainError::conflict(
                "identity.last_identifier",
                "the last login identifier of a user cannot be removed",
            ));
        }
        let removed = self.state.identifiers.remove(position);
        let kind = removed.value.kind();
        let user_id = self.state.id;
        let mut events = vec![UserEvent::IdentifierRemoved {
            user_id,
            identifier_id: id,
            identifier_kind: kind.as_str(),
        }];
        if removed.primary
            && let Some(next) = self
                .state
                .identifiers
                .iter_mut()
                .find(|i| i.value.kind() == kind)
        {
            next.primary = true;
            events.push(UserEvent::PrimaryIdentifierChanged {
                user_id,
                identifier_id: next.id,
                identifier_kind: kind.as_str(),
            });
        }
        self.state.updated_at = now;
        Ok(events)
    }

    /// Replaces the display name and locale.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if the profile breaks a rule, and `Conflict` if
    /// the user is deleted.
    pub fn change_profile(
        &mut self,
        profile: Profile,
        now: Timestamp,
    ) -> Result<UserEvent, DomainError> {
        self.require_not_deleted()?;
        self.state.profile = profile.validated()?;
        self.state.updated_at = now;
        Ok(UserEvent::ProfileChanged {
            user_id: self.state.id,
        })
    }

    /// The login identifier that matches `value`, if the user has it.
    #[must_use]
    pub fn identifier_matching(&self, value: &NormalizedIdentifier) -> Option<&LoginIdentifier> {
        self.state
            .identifiers
            .iter()
            .find(|i| i.value.same_as(value))
    }

    /// The primary login identifier of a kind, if the user has one.
    #[must_use]
    pub fn primary_identifier(&self, kind: IdentifierKind) -> Option<&LoginIdentifier> {
        self.state
            .identifiers
            .iter()
            .find(|i| i.primary && i.value.kind() == kind)
    }

    fn identifier_mut(&mut self, id: IdentifierId) -> Result<&mut LoginIdentifier, DomainError> {
        self.state
            .identifiers
            .iter_mut()
            .find(|i| i.id == id)
            .ok_or_else(identifier_not_found)
    }

    fn require(&self, allowed: &[UserStatus], action: &'static str) -> Result<(), DomainError> {
        if allowed.contains(&self.state.status) {
            Ok(())
        } else {
            Err(self.wrong_status(action))
        }
    }

    fn require_not_deleted(&self) -> Result<(), DomainError> {
        if self.state.status == UserStatus::Deleted {
            Err(self.wrong_status("changed"))
        } else {
            Ok(())
        }
    }

    fn wrong_status(&self, action: &'static str) -> DomainError {
        DomainError::conflict(
            "identity.invalid_transition",
            format!(
                "a user that is {} cannot be {action}",
                self.state.status.as_str()
            ),
        )
    }

    fn transition(&mut self, status: UserStatus, now: Timestamp) {
        self.state.status = status;
        self.state.updated_at = now;
        if status != UserStatus::Suspended {
            self.state.status_reason = None;
        }
    }
}

fn identifier_not_found() -> DomainError {
    DomainError::not_found(
        "identity.identifier_not_found",
        "the user has no such login identifier",
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::DomainEvent;
    use proptest::prelude::*;

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn email(value: &str) -> NormalizedIdentifier {
        NormalizedIdentifier::parse(IdentifierKind::Email, value).expect("valid email")
    }

    fn username(value: &str) -> NormalizedIdentifier {
        NormalizedIdentifier::parse(IdentifierKind::Username, value).expect("valid username")
    }

    fn person(confirmed: bool) -> User {
        User::create(
            UserKind::Human,
            vec![email("ana@example.com")],
            Profile::default(),
            confirmed,
            NOW,
        )
        .expect("create")
        .0
    }

    fn types(events: &[UserEvent]) -> Vec<&'static str> {
        events.iter().map(DomainEvent::event_type).collect()
    }

    #[test]
    fn a_new_user_is_pending_unless_already_confirmed() {
        assert_eq!(person(false).status(), UserStatus::Pending);
        assert!(!person(false).may_sign_in());
        assert_eq!(person(true).status(), UserStatus::Active);
        assert!(person(true).may_sign_in());
    }

    #[test]
    fn creation_announces_the_user_and_each_identifier() {
        let (user, events) = User::create(
            UserKind::Human,
            vec![email("ana@example.com"), username("ana")],
            Profile::default(),
            false,
            NOW,
        )
        .expect("create");
        assert_eq!(
            types(&events),
            [
                "identity.user_created",
                "identity.identifier_added",
                "identity.identifier_added"
            ]
        );
        assert!(
            user.identifiers().iter().all(|i| i.primary),
            "first of each kind is primary"
        );
        assert!(user.identifiers().iter().all(|i| !i.is_verified()));
    }

    #[test]
    fn a_person_needs_a_login_identifier_but_a_workload_does_not() {
        let person = User::create(UserKind::Human, vec![], Profile::default(), true, NOW);
        assert_eq!(
            person.expect_err("must fail").code(),
            "identity.identifier_required"
        );
        let workload = User::create(
            UserKind::ServiceAccount,
            vec![],
            Profile::default(),
            true,
            NOW,
        );
        assert!(workload.is_ok());
    }

    #[test]
    fn events_never_carry_an_identifier_value() {
        let (_, events) = User::create(
            UserKind::Human,
            vec![email("secret.address@example.com")],
            Profile {
                display_name: Some("Ana Silva".to_owned()),
                locale: None,
            },
            false,
            NOW,
        )
        .expect("create");
        let printed = format!("{events:?}");
        assert!(!printed.contains("secret.address"), "{printed}");
        assert!(!printed.contains("Ana Silva"), "{printed}");
    }

    #[test]
    fn the_whole_lifecycle_follows_the_specification() {
        let mut user = person(false);
        user.activate(NOW).expect("activate");
        user.suspend("fraud review", NOW).expect("suspend");
        assert_eq!(
            user.snapshot().status_reason.as_deref(),
            Some("fraud review")
        );
        assert!(!user.may_sign_in());
        user.reactivate(NOW).expect("reactivate");
        assert_eq!(user.snapshot().status_reason, None);
        user.deactivate(NOW).expect("deactivate");
        user.restore(NOW).expect("restore");
        assert!(user.may_sign_in());
        user.deactivate(NOW).expect("deactivate");
        user.mark_deleted(NOW).expect("delete");
        assert_eq!(user.status(), UserStatus::Deleted);
    }

    #[test]
    fn deleting_erases_personal_data_and_freezes_the_user() {
        let mut user = User::create(
            UserKind::Human,
            vec![email("ana@example.com"), username("ana")],
            Profile {
                display_name: Some("Ana".to_owned()),
                locale: Some("pt-BR".to_owned()),
            },
            true,
            NOW,
        )
        .expect("create")
        .0;
        user.deactivate(NOW).expect("deactivate");
        user.mark_deleted(NOW).expect("delete");

        assert!(user.identifiers().is_empty());
        assert_eq!(user.snapshot().profile, Profile::default());
        for error in [
            user.add_identifier(username("again"), NOW)
                .expect_err("frozen"),
            user.change_profile(Profile::default(), NOW)
                .expect_err("frozen"),
            user.restore(NOW).expect_err("frozen"),
        ] {
            assert_eq!(error.code(), "identity.invalid_transition");
        }
    }

    #[test]
    fn an_identifier_cannot_be_added_twice_however_it_is_typed() {
        let mut user = person(true);
        let error = user
            .add_identifier(email("  ANA@Example.COM "), NOW)
            .expect_err("duplicate");
        assert_eq!(error.code(), "identity.identifier_duplicate");
    }

    #[test]
    fn a_user_has_at_most_ten_identifiers() {
        let mut user = person(true);
        for n in 0..9 {
            user.add_identifier(username(&format!("name{n}")), NOW)
                .expect("add");
        }
        let error = user
            .add_identifier(username("one-too-many"), NOW)
            .expect_err("limit");
        assert_eq!(error.code(), "identity.too_many_identifiers");
    }

    #[test]
    fn verifying_happens_once_and_only_for_kinds_that_need_it() {
        let mut user = User::create(
            UserKind::Human,
            vec![email("ana@example.com"), username("ana")],
            Profile::default(),
            false,
            NOW,
        )
        .expect("create")
        .0;
        let email_id = user.identifiers()[0].id;
        let username_id = user.identifiers()[1].id;

        let first = user.verify_identifier(email_id, NOW).expect("verify");
        assert_eq!(
            first.map(|e| e.event_type()),
            Some("identity.identifier_verified")
        );
        assert_eq!(user.verify_identifier(email_id, NOW).expect("again"), None);

        let error = user
            .verify_identifier(username_id, NOW)
            .expect_err("username");
        assert_eq!(error.code(), "identity.identifier_not_verifiable");
        let missing = user
            .verify_identifier(IdentifierId::generate(), NOW)
            .expect_err("missing");
        assert_eq!(missing.code(), "identity.identifier_not_found");
    }

    #[test]
    fn an_email_must_be_verified_before_it_becomes_primary() {
        let mut user = person(true);
        user.add_identifier(email("work@example.com"), NOW)
            .expect("add");
        let second = user.identifiers()[1].id;

        let error = user.choose_primary(second, NOW).expect_err("unverified");
        assert_eq!(error.code(), "identity.identifier_not_verified");

        user.verify_identifier(second, NOW).expect("verify");
        assert!(user.choose_primary(second, NOW).expect("choose").is_some());
        assert_eq!(user.choose_primary(second, NOW).expect("again"), None);
        assert_eq!(
            user.primary_identifier(IdentifierKind::Email).map(|i| i.id),
            Some(second)
        );
    }

    #[test]
    fn removing_the_primary_promotes_the_oldest_of_its_kind() {
        let mut user = person(true);
        user.add_identifier(email("second@example.com"), NOW)
            .expect("add");
        user.add_identifier(email("third@example.com"), NOW)
            .expect("add");
        let (first, second) = (user.identifiers()[0].id, user.identifiers()[1].id);

        let events = user.remove_identifier(first, NOW).expect("remove");

        assert_eq!(
            types(&events),
            [
                "identity.identifier_removed",
                "identity.primary_identifier_changed"
            ]
        );
        assert_eq!(
            user.primary_identifier(IdentifierKind::Email).map(|i| i.id),
            Some(second)
        );
    }

    #[test]
    fn the_last_identifier_stays_unless_the_account_is_closed() {
        let mut user = person(true);
        let only = user.identifiers()[0].id;
        let error = user.remove_identifier(only, NOW).expect_err("last");
        assert_eq!(error.code(), "identity.last_identifier");

        user.deactivate(NOW).expect("deactivate");
        user.remove_identifier(only, NOW)
            .expect("allowed once closed");
        // A person cannot be restored with nothing to sign in with.
        let error = user.restore(NOW).expect_err("no identifier");
        assert_eq!(error.code(), "identity.identifier_required");
    }

    #[test]
    fn profiles_are_trimmed_and_validated() {
        let mut user = person(true);
        user.change_profile(
            Profile {
                display_name: Some("  Ana Silva  ".to_owned()),
                locale: Some("pt-BR".to_owned()),
            },
            NOW,
        )
        .expect("change");
        assert_eq!(
            user.snapshot().profile.display_name.as_deref(),
            Some("Ana Silva")
        );

        for (profile, code) in [
            (
                Profile {
                    display_name: Some("x".repeat(201)),
                    locale: None,
                },
                "identity.display_name_invalid",
            ),
            (
                Profile {
                    display_name: None,
                    locale: Some("portuguese".to_owned()),
                },
                "identity.locale_invalid",
            ),
        ] {
            assert_eq!(
                user.change_profile(profile, NOW)
                    .expect_err("invalid")
                    .code(),
                code
            );
        }
        // Blank values mean "not set".
        user.change_profile(
            Profile {
                display_name: Some("   ".to_owned()),
                locale: Some(String::new()),
            },
            NOW,
        )
        .expect("blank");
        assert_eq!(user.snapshot().profile, Profile::default());
    }

    #[test]
    fn stored_names_round_trip() {
        for kind in [UserKind::Human, UserKind::ServiceAccount, UserKind::Agent] {
            assert_eq!(UserKind::from_stored(kind.as_str()).expect("known"), kind);
        }
        for status in [
            UserStatus::Pending,
            UserStatus::Active,
            UserStatus::Suspended,
            UserStatus::Deactivated,
            UserStatus::Deleted,
        ] {
            assert_eq!(
                UserStatus::from_stored(status.as_str()).expect("known"),
                status
            );
        }
        assert!(UserKind::from_stored("robot").is_err());
        assert!(UserStatus::from_stored("frozen").is_err());
    }

    #[derive(Debug, Clone)]
    enum Action {
        Activate,
        Suspend,
        Reactivate,
        Deactivate,
        Restore,
        MarkDeleted,
        Add(u8, bool),
        Remove(usize),
        Verify(usize),
        ChoosePrimary(usize),
    }

    fn action() -> impl Strategy<Value = Action> {
        prop_oneof![
            Just(Action::Activate),
            Just(Action::Suspend),
            Just(Action::Reactivate),
            Just(Action::Deactivate),
            Just(Action::Restore),
            Just(Action::MarkDeleted),
            (0_u8..14, any::<bool>()).prop_map(|(n, is_email)| Action::Add(n, is_email)),
            (0_usize..12).prop_map(Action::Remove),
            (0_usize..12).prop_map(Action::Verify),
            (0_usize..12).prop_map(Action::ChoosePrimary),
        ]
    }

    /// The transitions drawn in the specification, and nothing else.
    fn specified(from: UserStatus, action: &Action) -> Option<UserStatus> {
        use UserStatus::{Active, Deactivated, Deleted, Pending, Suspended};
        match (from, action) {
            (Pending, Action::Activate) => Some(Active),
            (Active, Action::Suspend) => Some(Suspended),
            (Suspended, Action::Reactivate) => Some(Active),
            (Pending | Active | Suspended, Action::Deactivate) => Some(Deactivated),
            (Deactivated, Action::Restore) => Some(Active),
            (Deactivated, Action::MarkDeleted) => Some(Deleted),
            _ => None,
        }
    }

    proptest! {
        /// Whatever is attempted, in whatever order, the user stays within
        /// the rules: only specified transitions happen, a rejected
        /// operation changes nothing, and the identifier rules always hold.
        #[test]
        fn the_rules_hold_under_any_sequence_of_operations(
            actions in proptest::collection::vec(action(), 0..60)
        ) {
            let mut user = person(false);
            for action in actions {
                let before = user.clone();
                let pick = |index: usize| {
                    before
                        .identifiers()
                        .get(index)
                        .map_or_else(IdentifierId::generate, |i| i.id)
                };
                let failed = match &action {
                    Action::Activate => user.activate(NOW).is_err(),
                    Action::Suspend => user.suspend("reason", NOW).is_err(),
                    Action::Reactivate => user.reactivate(NOW).is_err(),
                    Action::Deactivate => user.deactivate(NOW).is_err(),
                    Action::Restore => user.restore(NOW).is_err(),
                    Action::MarkDeleted => user.mark_deleted(NOW).is_err(),
                    Action::Add(n, true) => user.add_identifier(email(&format!("user{n}@example.com")), NOW).is_err(),
                    Action::Add(n, false) => user.add_identifier(username(&format!("user{n}")), NOW).is_err(),
                    Action::Remove(index) => user.remove_identifier(pick(*index), NOW).is_err(),
                    Action::Verify(index) => user.verify_identifier(pick(*index), NOW).is_err(),
                    Action::ChoosePrimary(index) => user.choose_primary(pick(*index), NOW).is_err(),
                };
                if failed {
                    prop_assert_eq!(&user, &before, "a rejected operation changes nothing");
                }

                // Lifecycle: the status only moves along a drawn transition.
                if user.status() != before.status() {
                    prop_assert_eq!(specified(before.status(), &action), Some(user.status()));
                }

                // Identifier rules.
                let identifiers = user.identifiers();
                prop_assert!(identifiers.len() <= User::MAX_IDENTIFIERS);
                for kind in [IdentifierKind::Email, IdentifierKind::Username] {
                    let of_kind: Vec<_> = identifiers.iter().filter(|i| i.value.kind() == kind).collect();
                    let primaries = of_kind.iter().filter(|i| i.primary).count();
                    prop_assert_eq!(primaries, usize::from(!of_kind.is_empty()), "exactly one primary per kind in use");
                }
                for (index, identifier) in identifiers.iter().enumerate() {
                    prop_assert!(
                        identifiers[index + 1..].iter().all(|other| !other.value.same_as(&identifier.value)),
                        "no identifier twice"
                    );
                    if !identifier.value.kind().needs_verification() {
                        prop_assert!(!identifier.is_verified());
                    }
                }
                match user.status() {
                    UserStatus::Deleted => prop_assert!(identifiers.is_empty()),
                    UserStatus::Deactivated => {}
                    _ => prop_assert!(!identifiers.is_empty(), "a usable person can sign in with something"),
                }
            }
        }
    }
}
