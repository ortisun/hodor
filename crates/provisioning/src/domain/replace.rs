//! Replacing what SCIM says of a user: the changes a `PUT` makes to the
//! identity context's user.
//!
//! Specified in `docs/architecture/contexts/provisioning.md`, "`userName`",
//! "`emails`" and "`active`".

use crate::domain::resource::UserRequest;
use hodor_identity::api::{IdentifierId, IdentifierKind, Profile, User, UserEvent, UserStatus};
use hodor_kernel::{DomainError, Timestamp};

/// What replacing a user did, and what is left to the use case.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Replaced {
    /// The events of every change made; none when nothing changed.
    pub events: Vec<UserEvent>,
    /// Whether the request deprovisions the user: `active: false` for a
    /// user who is not Deactivated yet. What that does is the tenant's
    /// policy, which the use case reads.
    pub deprovision: bool,
}

/// Changes `user` to what `request` says: its login identifiers, the
/// primary one of each kind, its display name, and its status when
/// `active` is `true`.
///
/// The `userName` is added first, so that the user never loses its last
/// identifier, and what the request does not name is removed before the
/// rest is added, so that a user at the bound of identifiers can still
/// trade some for others.
///
/// # Errors
///
/// What the identity context refuses: an identifier past the bound of 10,
/// a display name too long, a transition its lifecycle does not allow.
pub fn replace_user(
    user: &mut User,
    request: &UserRequest,
    now: Timestamp,
) -> Result<Replaced, DomainError> {
    let mut events = Vec::new();
    let desired = request.identifiers();
    let mut desired_iter = desired.iter();
    if let Some(first) = desired_iter.next()
        && user.identifier_matching(first).is_none()
    {
        events.push(user.add_identifier(first.clone(), now)?);
    }
    let undesired: Vec<IdentifierId> = user
        .identifiers()
        .iter()
        .filter(|held| !desired.iter().any(|wanted| wanted.same_as(&held.value)))
        .map(|held| held.id)
        .collect();
    for id in undesired {
        events.extend(user.remove_identifier(id, now)?);
    }
    for wanted in desired_iter {
        if user.identifier_matching(wanted).is_none() {
            events.push(user.add_identifier(wanted.clone(), now)?);
        }
    }
    let addresses: Vec<IdentifierId> = user
        .identifiers()
        .iter()
        .filter(|held| held.value.kind() == IdentifierKind::Email)
        .map(|held| held.id)
        .collect();
    for id in addresses {
        events.extend(user.verify_identifier(id, now)?);
    }
    for primary in request.username.iter().chain(request.emails.first()) {
        if let Some(id) = user.identifier_matching(primary).map(|held| held.id) {
            events.extend(user.choose_primary(id, now)?);
        }
    }
    let profile = user.snapshot().profile.clone();
    if profile.display_name != request.display_name {
        events.push(user.change_profile(
            Profile {
                display_name: request.display_name.clone(),
                locale: profile.locale,
            },
            now,
        )?);
    }
    let mut deprovision = false;
    match (user.status(), request.active) {
        (UserStatus::Pending, true) => events.push(user.activate(now)?),
        (UserStatus::Suspended, true) => events.push(user.reactivate(now)?),
        (UserStatus::Deactivated, true) => events.push(user.restore(now)?),
        (UserStatus::Active | UserStatus::Pending | UserStatus::Suspended, false) => {
            deprovision = true;
        }
        _ => {}
    }
    Ok(Replaced {
        events,
        deprovision,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::attribute::USER_SCHEMA;
    use crate::domain::resource::read_user;
    use hodor_identity::api::{NormalizedIdentifier, UserKind};
    use serde_json::json;

    fn person(identifiers: &[(IdentifierKind, &str)]) -> User {
        User::create(
            UserKind::Human,
            identifiers
                .iter()
                .map(|(kind, value)| NormalizedIdentifier::parse(*kind, value).expect("valid"))
                .collect(),
            Profile::default(),
            true,
            Timestamp::UNIX_EPOCH,
        )
        .expect("a user")
        .0
    }

    fn values(user: &User) -> Vec<(String, bool, bool)> {
        user.identifiers()
            .iter()
            .map(|held| {
                (
                    held.value.normalized().to_owned(),
                    held.primary,
                    held.is_verified(),
                )
            })
            .collect()
    }

    #[test]
    fn identifiers_become_what_the_request_names_with_every_address_verified() {
        let mut user = person(&[
            (IdentifierKind::Username, "ana"),
            (IdentifierKind::Email, "old@example.com"),
        ]);
        let request = read_user(&json!({
            "schemas": [USER_SCHEMA],
            "userName": "ana.silva",
            "displayName": "Ana Silva",
            "emails": [{ "value": "ana@example.com" }, { "value": "ana@home.org", "primary": true }],
        }))
        .expect("read");
        let replaced = replace_user(&mut user, &request, Timestamp::UNIX_EPOCH).expect("replaced");
        assert!(!replaced.events.is_empty());
        assert!(!replaced.deprovision);
        assert_eq!(
            values(&user),
            [
                ("ana.silva".to_owned(), true, false),
                ("ana@home.org".to_owned(), true, true),
                ("ana@example.com".to_owned(), false, true),
            ]
        );
        assert_eq!(
            user.snapshot().profile.display_name.as_deref(),
            Some("Ana Silva")
        );
        let again = replace_user(&mut user, &request, Timestamp::UNIX_EPOCH).expect("again");
        assert!(
            again.events.is_empty(),
            "the same request changes nothing: {again:?}"
        );
    }

    #[test]
    fn active_maps_to_the_status_and_false_asks_for_deprovisioning() {
        let mut user = person(&[(IdentifierKind::Username, "ana")]);
        let mut request =
            read_user(&json!({ "schemas": [USER_SCHEMA], "userName": "ana", "active": "False" }))
                .expect("read");
        let replaced = replace_user(&mut user, &request, Timestamp::UNIX_EPOCH).expect("read");
        assert!(replaced.deprovision);
        assert_eq!(
            user.status(),
            UserStatus::Active,
            "the policy is the use case's"
        );
        user.deactivate(Timestamp::UNIX_EPOCH).expect("deactivated");
        let replaced = replace_user(&mut user, &request, Timestamp::UNIX_EPOCH).expect("again");
        assert!(
            !replaced.deprovision,
            "a Deactivated user is not deprovisioned again"
        );
        request.active = true;
        replace_user(&mut user, &request, Timestamp::UNIX_EPOCH).expect("restored");
        assert_eq!(user.status(), UserStatus::Active);
    }
}
