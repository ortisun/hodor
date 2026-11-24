//! Replacing what SCIM says of a user: the changes a `PUT` makes to the
//! identity context's user.
//!
//! Specified in `docs/architecture/contexts/provisioning.md`, "`userName`",
//! "`emails`" and "`active`".

use crate::domain::resource::{SUSPENDED_THROUGH_SCIM, UserRequest};
use hodor_identity::api::{IdentifierId, IdentifierKind, Profile, User, UserEvent, UserStatus};
use hodor_kernel::{DomainError, Timestamp};

/// Changes `user` to what `request` says: its login identifiers, the
/// primary one of each kind, its display name and its status. Answers the
/// events of every change; none when nothing changed.
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
) -> Result<Vec<UserEvent>, DomainError> {
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
    match (user.status(), request.active) {
        (UserStatus::Active, false) => events.push(user.suspend(SUSPENDED_THROUGH_SCIM, now)?),
        (UserStatus::Pending, true) => events.push(user.activate(now)?),
        (UserStatus::Suspended, true) => events.push(user.reactivate(now)?),
        (UserStatus::Deactivated, true) => events.push(user.restore(now)?),
        _ => {}
    }
    Ok(events)
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
        let events = replace_user(&mut user, &request, Timestamp::UNIX_EPOCH).expect("replaced");
        assert!(!events.is_empty());
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
            again.is_empty(),
            "the same request changes nothing: {again:?}"
        );
    }

    #[test]
    fn active_maps_to_the_status() {
        let mut user = person(&[(IdentifierKind::Username, "ana")]);
        let mut request =
            read_user(&json!({ "schemas": [USER_SCHEMA], "userName": "ana", "active": false }))
                .expect("read");
        replace_user(&mut user, &request, Timestamp::UNIX_EPOCH).expect("suspended");
        assert_eq!(user.status(), UserStatus::Suspended);
        replace_user(&mut user, &request, Timestamp::UNIX_EPOCH).expect("still suspended");
        request.active = true;
        replace_user(&mut user, &request, Timestamp::UNIX_EPOCH).expect("reactivated");
        assert_eq!(user.status(), UserStatus::Active);
    }
}
