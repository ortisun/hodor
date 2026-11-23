//! Applications: what a tenant's administrator registers, and what people
//! recognize on the consent page.

use crate::domain::text;
use hodor_kernel::{DomainError, Timestamp};

hodor_kernel::define_id!(
    /// Identifies an application.
    ApplicationId
);

/// The most applications a tenant may have.
pub const MAX_APPLICATIONS: usize = 100;

/// Whether an application, a client or a resource server is in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Status {
    /// In use.
    Enabled,
    /// Kept, but gets no tokens.
    Disabled,
}

impl Status {
    /// The stored name.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }

    /// Reads a stored name.
    ///
    /// # Errors
    ///
    /// Returns `Internal` for a name that is not one of the two.
    pub fn from_stored(value: &str) -> Result<Self, DomainError> {
        match value {
            "enabled" => Ok(Self::Enabled),
            "disabled" => Ok(Self::Disabled),
            _ => Err(stored_data_invalid()),
        }
    }
}

/// The error for stored data that breaks a rule the code keeps.
pub(crate) fn stored_data_invalid() -> DomainError {
    DomainError::internal(
        "oauth.stored_data_invalid",
        "stored OAuth data could not be read",
    )
}

/// What an administrator decides about an application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationSettings {
    /// Shown to people.
    pub name: String,
    /// Whether it belongs to whoever runs the tenant; such an application
    /// is not asked for consent.
    pub first_party: bool,
}

impl ApplicationSettings {
    fn checked(self) -> Result<Self, DomainError> {
        Ok(Self {
            name: text::name(&self.name, "oauth.application_name_invalid")?,
            first_party: self.first_party,
        })
    }
}

/// Everything stored about an application.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApplicationSnapshot {
    /// Its identifier.
    pub id: ApplicationId,
    /// What an administrator decided about it.
    pub settings: ApplicationSettings,
    /// Whether its clients get tokens.
    pub status: Status,
    /// When it was registered.
    pub created_at: Timestamp,
    /// When it was last changed.
    pub updated_at: Timestamp,
    /// Incremented on every stored change, for optimistic locking.
    pub version: u32,
}

/// An application of a tenant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Application {
    state: ApplicationSnapshot,
}

impl Application {
    /// A new application, enabled.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if the name breaks its rule.
    pub fn create(settings: ApplicationSettings, now: Timestamp) -> Result<Self, DomainError> {
        Ok(Self {
            state: ApplicationSnapshot {
                id: ApplicationId::generate(),
                settings: settings.checked()?,
                status: Status::Enabled,
                created_at: now,
                updated_at: now,
                version: 0,
            },
        })
    }

    /// Rebuilds an application from storage.
    #[must_use]
    pub const fn from_snapshot(state: ApplicationSnapshot) -> Self {
        Self { state }
    }

    /// Everything stored about it.
    #[must_use]
    pub const fn snapshot(&self) -> &ApplicationSnapshot {
        &self.state
    }

    /// Its identifier.
    #[must_use]
    pub const fn id(&self) -> ApplicationId {
        self.state.id
    }

    /// Its name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.state.settings.name
    }

    /// Whether its clients get tokens.
    #[must_use]
    pub fn is_enabled(&self) -> bool {
        self.state.status == Status::Enabled
    }

    /// Replaces the settings. Returns whether anything changed.
    ///
    /// # Errors
    ///
    /// Returns `Invalid` if the name breaks its rule; nothing changes then.
    pub fn change(
        &mut self,
        settings: ApplicationSettings,
        now: Timestamp,
    ) -> Result<bool, DomainError> {
        let settings = settings.checked()?;
        if settings == self.state.settings {
            return Ok(false);
        }
        self.state.settings = settings;
        self.state.updated_at = now;
        Ok(true)
    }

    /// Sets the status. Returns whether anything changed.
    pub fn set_status(&mut self, status: Status, now: Timestamp) -> bool {
        if self.state.status == status {
            return false;
        }
        self.state.status = status;
        self.state.updated_at = now;
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn settings(name: &str) -> ApplicationSettings {
        ApplicationSettings {
            name: name.to_owned(),
            first_party: false,
        }
    }

    #[test]
    fn a_new_application_is_enabled_with_its_name_tidied() {
        let application = Application::create(settings("  Payroll "), NOW).expect("valid");
        assert_eq!(application.name(), "Payroll");
        assert!(application.is_enabled());
        assert_eq!(application.snapshot().version, 0);
        let error = Application::create(settings(""), NOW).expect_err("no name");
        assert_eq!(error.code(), "oauth.application_name_invalid");
    }

    #[test]
    fn a_change_says_whether_it_changed_anything() {
        let mut application = Application::create(settings("Payroll"), NOW).expect("valid");
        let later = NOW + Duration::minutes(1);
        assert!(
            !application
                .change(settings(" Payroll "), later)
                .expect("same")
        );
        assert_eq!(application.snapshot().updated_at, NOW);
        let mut first_party = settings("Payroll");
        first_party.first_party = true;
        assert!(application.change(first_party, later).expect("changed"));
        assert_eq!(application.snapshot().updated_at, later);
        assert!(application.change(settings("\n"), later).is_err());
        assert!(application.snapshot().settings.first_party);
    }

    #[test]
    fn a_status_is_set_once() {
        let mut application = Application::create(settings("Payroll"), NOW).expect("valid");
        assert!(!application.set_status(Status::Enabled, NOW));
        assert!(application.set_status(Status::Disabled, NOW));
        assert!(!application.is_enabled());
        assert!(!application.set_status(Status::Disabled, NOW));
        assert_eq!(
            Status::from_stored("disabled").expect("known"),
            Status::Disabled
        );
        assert!(Status::from_stored("paused").is_err());
    }
}
