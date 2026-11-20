//! The tenant aggregate and its lifecycle.

use crate::domain::event::TenantEvent;
use crate::domain::settings::TenantSettings;
use crate::domain::slug::Slug;
use hodor_kernel::{DomainError, TenantId, Timestamp};
use time::Duration;

/// Where a tenant is in its life.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum TenantStatus {
    /// Created, but its initial data is not complete yet.
    Provisioning,
    /// Normal operation.
    Active,
    /// Data is kept; every request is refused.
    Suspended,
    /// Will be purged after the deletion date unless deletion is cancelled.
    PendingDeletion,
    /// Data has been purged; only the record that it existed remains.
    Deleted,
}

impl TenantStatus {
    /// Whether a tenant in this status serves requests.
    #[must_use]
    pub const fn serves_requests(self) -> bool {
        matches!(self, Self::Active)
    }

    /// The name used in storage and in the directory.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Provisioning => "provisioning",
            Self::Active => "active",
            Self::Suspended => "suspended",
            Self::PendingDeletion => "pending_deletion",
            Self::Deleted => "deleted",
        }
    }

    /// Reads a status from its stored name.
    ///
    /// # Errors
    ///
    /// Returns an internal error for an unknown name, which indicates
    /// corrupted data or a missing migration.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "provisioning" => Ok(Self::Provisioning),
            "active" => Ok(Self::Active),
            "suspended" => Ok(Self::Suspended),
            "pending_deletion" => Ok(Self::PendingDeletion),
            "deleted" => Ok(Self::Deleted),
            other => Err(DomainError::internal(
                "tenant.status_unknown",
                "the tenant could not be loaded",
            )
            .with_detail(format!("unknown stored tenant status `{other}`"))),
        }
    }
}

/// The state of a tenant as it is stored. Used to rebuild the aggregate
/// from storage and to write it back.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantSnapshot {
    /// The tenant's identifier.
    pub id: TenantId,
    /// Its slug.
    pub slug: Slug,
    /// Its display name.
    pub display_name: String,
    /// Its status.
    pub status: TenantStatus,
    /// Why it was last suspended.
    pub status_reason: Option<String>,
    /// Its policies.
    pub settings: TenantSettings,
    /// Set only while deletion is pending.
    pub deletion_scheduled_for: Option<Timestamp>,
    /// When it was created.
    pub created_at: Timestamp,
    /// When it was last changed.
    pub updated_at: Timestamp,
    /// Incremented on every stored change, for optimistic locking.
    pub version: u32,
}

/// A tenant: the hard isolation boundary.
///
/// Every method that changes the tenant checks the lifecycle rules of
/// `docs/architecture/contexts/tenant.md` and returns the event that
/// describes the change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Tenant {
    state: TenantSnapshot,
}

impl Tenant {
    /// Longest display name, in characters.
    pub const MAX_DISPLAY_NAME_LENGTH: usize = 100;
    /// Grace period used when the caller gives none.
    pub const DEFAULT_DELETION_GRACE: Duration = Duration::days(30);
    /// Shortest grace period a caller may ask for.
    pub const MIN_DELETION_GRACE: Duration = Duration::days(1);

    /// Creates a tenant in `Provisioning` with default settings.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error if the display name is empty or too long.
    pub fn create(
        slug: Slug,
        display_name: &str,
        now: Timestamp,
    ) -> Result<(Self, TenantEvent), DomainError> {
        let display_name = display_name.trim();
        let length = display_name.chars().count();
        if length == 0 || length > Self::MAX_DISPLAY_NAME_LENGTH {
            return Err(DomainError::invalid(
                "tenant.display_name_invalid",
                "a tenant name has 1 to 100 characters",
            ));
        }
        let id = TenantId::generate();
        let event = TenantEvent::Created {
            tenant_id: id,
            slug: slug.as_str().to_owned(),
            display_name: display_name.to_owned(),
        };
        let tenant = Self {
            state: TenantSnapshot {
                id,
                slug,
                display_name: display_name.to_owned(),
                status: TenantStatus::Provisioning,
                status_reason: None,
                settings: TenantSettings::default(),
                deletion_scheduled_for: None,
                created_at: now,
                updated_at: now,
                version: 0,
            },
        };
        Ok((tenant, event))
    }

    /// Rebuilds a tenant from its stored state.
    #[must_use]
    pub const fn from_snapshot(state: TenantSnapshot) -> Self {
        Self { state }
    }

    /// The tenant's current state, for storage and for reading.
    #[must_use]
    pub const fn snapshot(&self) -> &TenantSnapshot {
        &self.state
    }

    /// The tenant's identifier.
    #[must_use]
    pub const fn id(&self) -> TenantId {
        self.state.id
    }

    /// The tenant's status.
    #[must_use]
    pub const fn status(&self) -> TenantStatus {
        self.state.status
    }

    /// Finishes provisioning.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error unless the tenant is `Provisioning`.
    pub fn activate(&mut self, now: Timestamp) -> Result<TenantEvent, DomainError> {
        self.require(&[TenantStatus::Provisioning], "activated")?;
        self.transition(TenantStatus::Active, now);
        Ok(TenantEvent::Activated {
            tenant_id: self.state.id,
        })
    }

    /// Suspends the tenant, recording why.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error unless the tenant is `Active`, and an
    /// `Invalid` error if the reason is empty.
    pub fn suspend(&mut self, reason: &str, now: Timestamp) -> Result<TenantEvent, DomainError> {
        self.require(&[TenantStatus::Active], "suspended")?;
        let reason = reason.trim();
        if reason.is_empty() {
            return Err(DomainError::invalid(
                "tenant.suspension_reason_missing",
                "a reason is required to suspend a tenant",
            ));
        }
        self.transition(TenantStatus::Suspended, now);
        self.state.status_reason = Some(reason.to_owned());
        Ok(TenantEvent::Suspended {
            tenant_id: self.state.id,
            reason: reason.to_owned(),
        })
    }

    /// Returns a suspended tenant to active.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error unless the tenant is `Suspended`.
    pub fn reactivate(&mut self, now: Timestamp) -> Result<TenantEvent, DomainError> {
        self.require(&[TenantStatus::Suspended], "reactivated")?;
        self.transition(TenantStatus::Active, now);
        self.state.status_reason = None;
        Ok(TenantEvent::Reactivated {
            tenant_id: self.state.id,
        })
    }

    /// Schedules deletion after a grace period.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error unless the tenant is `Active` or
    /// `Suspended`, and an `Invalid` error if the grace period is shorter
    /// than one day.
    pub fn schedule_deletion(
        &mut self,
        grace: Option<Duration>,
        now: Timestamp,
    ) -> Result<TenantEvent, DomainError> {
        self.require(
            &[TenantStatus::Active, TenantStatus::Suspended],
            "scheduled for deletion",
        )?;
        let grace = grace.unwrap_or(Self::DEFAULT_DELETION_GRACE);
        if grace < Self::MIN_DELETION_GRACE {
            return Err(DomainError::invalid(
                "tenant.deletion_grace_too_short",
                "the grace period before deletion must be at least one day",
            ));
        }
        let deletion_date = now + grace;
        self.transition(TenantStatus::PendingDeletion, now);
        self.state.deletion_scheduled_for = Some(deletion_date);
        Ok(TenantEvent::DeletionScheduled {
            tenant_id: self.state.id,
            deletion_date,
        })
    }

    /// Cancels a scheduled deletion. The tenant becomes `Suspended`, never
    /// `Active`: someone has to decide to reactivate it.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error unless deletion is pending.
    pub fn cancel_deletion(&mut self, now: Timestamp) -> Result<TenantEvent, DomainError> {
        self.require(&[TenantStatus::PendingDeletion], "restored")?;
        self.transition(TenantStatus::Suspended, now);
        self.state.deletion_scheduled_for = None;
        self.state.status_reason = Some("deletion cancelled".to_owned());
        Ok(TenantEvent::DeletionCancelled {
            tenant_id: self.state.id,
        })
    }

    /// Marks the tenant deleted, once its deletion date has passed.
    ///
    /// # Errors
    ///
    /// Returns a `Conflict` error unless deletion is pending and the
    /// deletion date has passed.
    pub fn mark_deleted(&mut self, now: Timestamp) -> Result<TenantEvent, DomainError> {
        self.require(&[TenantStatus::PendingDeletion], "deleted")?;
        if self
            .state
            .deletion_scheduled_for
            .is_none_or(|date| now < date)
        {
            return Err(DomainError::conflict(
                "tenant.deletion_date_not_reached",
                "the tenant cannot be deleted before its deletion date",
            ));
        }
        self.transition(TenantStatus::Deleted, now);
        self.state.deletion_scheduled_for = None;
        Ok(TenantEvent::Deleted {
            tenant_id: self.state.id,
        })
    }

    /// Replaces the tenant's settings.
    ///
    /// # Errors
    ///
    /// Returns an `Invalid` error if the settings break a rule, and a
    /// `Conflict` error if the tenant is deleted.
    pub fn change_settings(
        &mut self,
        settings: TenantSettings,
        now: Timestamp,
    ) -> Result<TenantEvent, DomainError> {
        if self.state.status == TenantStatus::Deleted {
            return Err(self.wrong_status("changed"));
        }
        settings.validate()?;
        self.state.settings = settings.clone();
        self.state.updated_at = now;
        Ok(TenantEvent::SettingsChanged {
            tenant_id: self.state.id,
            settings,
        })
    }

    fn require(&self, allowed: &[TenantStatus], action: &'static str) -> Result<(), DomainError> {
        if allowed.contains(&self.state.status) {
            Ok(())
        } else {
            Err(self.wrong_status(action))
        }
    }

    fn wrong_status(&self, action: &'static str) -> DomainError {
        DomainError::conflict(
            "tenant.invalid_transition",
            format!(
                "a tenant that is {} cannot be {action}",
                self.state.status.as_str().replace('_', " ")
            ),
        )
    }

    fn transition(&mut self, status: TenantStatus, now: Timestamp) {
        self.state.status = status;
        self.state.updated_at = now;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::DomainEvent as _;
    use proptest::prelude::*;

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn provisioning() -> Tenant {
        Tenant::create(Slug::parse("acme").expect("slug"), "Acme", NOW)
            .expect("create")
            .0
    }

    fn active() -> Tenant {
        let mut tenant = provisioning();
        tenant.activate(NOW).expect("activate");
        tenant
    }

    #[test]
    fn a_new_tenant_is_provisioning_with_default_settings() {
        let (tenant, event) =
            Tenant::create(Slug::parse("acme").expect("slug"), "  Acme Corp  ", NOW)
                .expect("create");
        let state = tenant.snapshot();
        assert_eq!(state.status, TenantStatus::Provisioning);
        assert_eq!(state.display_name, "Acme Corp");
        assert_eq!(state.settings, TenantSettings::default());
        assert_eq!(state.version, 0);
        assert!(!state.status.serves_requests());
        assert_eq!(event.event_type(), "tenant.created");
    }

    #[test]
    fn display_names_must_have_between_1_and_100_characters() {
        let slug = || Slug::parse("acme").expect("slug");
        for name in ["", "   ", &"x".repeat(101)] {
            let error = Tenant::create(slug(), name, NOW).expect_err("must fail");
            assert_eq!(error.code(), "tenant.display_name_invalid");
        }
        assert!(Tenant::create(slug(), &"é".repeat(100), NOW).is_ok());
    }

    #[test]
    fn the_whole_lifecycle_follows_the_specification() {
        let mut tenant = provisioning();

        assert_eq!(
            tenant.activate(NOW).expect("activate").event_type(),
            "tenant.activated"
        );
        assert!(tenant.status().serves_requests());

        let suspended = tenant.suspend("unpaid invoice", NOW).expect("suspend");
        assert_eq!(suspended.event_type(), "tenant.suspended");
        assert_eq!(
            tenant.snapshot().status_reason.as_deref(),
            Some("unpaid invoice")
        );
        assert!(!tenant.status().serves_requests());

        tenant.reactivate(NOW).expect("reactivate");
        assert_eq!(tenant.status(), TenantStatus::Active);
        assert_eq!(tenant.snapshot().status_reason, None);

        let scheduled = tenant.schedule_deletion(None, NOW).expect("schedule");
        assert_eq!(scheduled.event_type(), "tenant.deletion_scheduled");
        assert_eq!(
            tenant.snapshot().deletion_scheduled_for,
            Some(NOW + Duration::days(30))
        );

        // Cancelling never returns straight to active.
        tenant.cancel_deletion(NOW).expect("cancel");
        assert_eq!(tenant.status(), TenantStatus::Suspended);
        assert_eq!(tenant.snapshot().deletion_scheduled_for, None);

        tenant
            .schedule_deletion(Some(Duration::days(2)), NOW)
            .expect("schedule again");
        let early = tenant
            .mark_deleted(NOW + Duration::days(1))
            .expect_err("too early");
        assert_eq!(early.code(), "tenant.deletion_date_not_reached");
        tenant
            .mark_deleted(NOW + Duration::days(2))
            .expect("delete");
        assert_eq!(tenant.status(), TenantStatus::Deleted);
    }

    #[test]
    fn suspending_requires_a_reason() {
        let error = active().suspend("   ", NOW).expect_err("must fail");
        assert_eq!(error.code(), "tenant.suspension_reason_missing");
    }

    #[test]
    fn the_grace_period_cannot_be_shorter_than_a_day() {
        let error = active()
            .schedule_deletion(Some(Duration::hours(23)), NOW)
            .expect_err("must fail");
        assert_eq!(error.code(), "tenant.deletion_grace_too_short");
    }

    #[test]
    fn invalid_settings_leave_the_tenant_unchanged() {
        let mut tenant = active();
        let mut settings = TenantSettings::default();
        settings.password.min_length = 1;
        assert!(tenant.change_settings(settings, NOW).is_err());
        assert_eq!(tenant.snapshot().settings, TenantSettings::default());
    }

    #[test]
    fn stored_statuses_round_trip() {
        for status in [
            TenantStatus::Provisioning,
            TenantStatus::Active,
            TenantStatus::Suspended,
            TenantStatus::PendingDeletion,
            TenantStatus::Deleted,
        ] {
            assert_eq!(
                TenantStatus::from_stored(status.as_str()).expect("known"),
                status
            );
        }
        assert!(TenantStatus::from_stored("frozen").is_err());
    }

    #[derive(Debug, Clone, Copy)]
    enum Action {
        Activate,
        Suspend,
        Reactivate,
        ScheduleDeletion,
        CancelDeletion,
        MarkDeleted,
    }

    /// The transitions drawn in the specification, and nothing else.
    fn specified(from: TenantStatus, action: Action) -> Option<TenantStatus> {
        use TenantStatus::{Active, Deleted, PendingDeletion, Provisioning, Suspended};
        match (from, action) {
            (Provisioning, Action::Activate) => Some(Active),
            (Active, Action::Suspend) => Some(Suspended),
            (Suspended, Action::Reactivate) => Some(Active),
            (Active | Suspended, Action::ScheduleDeletion) => Some(PendingDeletion),
            (PendingDeletion, Action::CancelDeletion) => Some(Suspended),
            (PendingDeletion, Action::MarkDeleted) => Some(Deleted),
            _ => None,
        }
    }

    fn action() -> impl Strategy<Value = Action> {
        prop_oneof![
            Just(Action::Activate),
            Just(Action::Suspend),
            Just(Action::Reactivate),
            Just(Action::ScheduleDeletion),
            Just(Action::CancelDeletion),
            Just(Action::MarkDeleted),
        ]
    }

    proptest! {
        /// Whatever sequence of operations is attempted, the tenant only
        /// ever moves along a transition the specification draws, and a
        /// rejected operation changes nothing.
        #[test]
        fn only_specified_transitions_ever_happen(actions in proptest::collection::vec(action(), 0..40)) {
            let mut tenant = provisioning();
            // Far enough in the future for any scheduled deletion to be due.
            let later = NOW + Duration::days(365);
            for action in actions {
                let before = tenant.clone();
                let result = match action {
                    Action::Activate => tenant.activate(later),
                    Action::Suspend => tenant.suspend("reason", later),
                    Action::Reactivate => tenant.reactivate(later),
                    Action::ScheduleDeletion => tenant.schedule_deletion(None, NOW),
                    Action::CancelDeletion => tenant.cancel_deletion(later),
                    Action::MarkDeleted => tenant.mark_deleted(later),
                };
                match specified(before.status(), action) {
                    Some(expected) => {
                        prop_assert!(result.is_ok(), "{:?} from {:?}", action, before.status());
                        prop_assert_eq!(tenant.status(), expected);
                    }
                    None => {
                        let error = result.expect_err("unspecified transition must fail");
                        prop_assert_eq!(error.code(), "tenant.invalid_transition");
                        prop_assert_eq!(&tenant, &before);
                    }
                }
                prop_assert_eq!(
                    tenant.snapshot().deletion_scheduled_for.is_some(),
                    tenant.status() == TenantStatus::PendingDeletion
                );
            }
        }
    }
}
