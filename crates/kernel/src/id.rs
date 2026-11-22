//! Typed identifiers.
//!
//! Every identifier is a UUIDv7 wrapped in its own type, so a `UserId` cannot
//! be passed where a `TenantId` is expected. UUIDv7 values sort by creation
//! time, which keeps primary-key indexes compact.

/// Error returned when a string is not a valid identifier.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("invalid {kind}: expected a UUID")]
pub struct ParseIdError {
    kind: &'static str,
}

impl ParseIdError {
    #[doc(hidden)]
    #[must_use]
    pub const fn new(kind: &'static str) -> Self {
        Self { kind }
    }
}

/// Defines a typed UUIDv7 identifier.
///
/// Contexts use this for identifiers they own; identifiers referenced by
/// several contexts are defined in this crate.
///
/// ```
/// hodor_kernel::define_id!(
///     /// Identifies a group.
///     GroupId
/// );
///
/// let identifier = GroupId::generate();
/// assert_eq!(identifier.to_string().parse::<GroupId>(), Ok(identifier));
/// ```
#[macro_export]
macro_rules! define_id {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name($crate::__private::uuid::Uuid);

        impl $name {
            /// Generates a new identifier from the current time.
            #[must_use]
            pub fn generate() -> Self {
                Self($crate::__private::uuid::Uuid::now_v7())
            }

            /// Wraps an existing UUID, for example one read from storage.
            #[must_use]
            pub const fn from_uuid(value: $crate::__private::uuid::Uuid) -> Self {
                Self(value)
            }

            /// Returns the underlying UUID.
            #[must_use]
            pub const fn as_uuid(&self) -> $crate::__private::uuid::Uuid {
                self.0
            }
        }

        impl $crate::__private::serde::Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> ::std::result::Result<S::Ok, S::Error>
            where
                S: $crate::__private::serde::Serializer,
            {
                $crate::__private::serde::Serialize::serialize(&self.0, serializer)
            }
        }

        impl<'de> $crate::__private::serde::Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> ::std::result::Result<Self, D::Error>
            where
                D: $crate::__private::serde::Deserializer<'de>,
            {
                <$crate::__private::uuid::Uuid as $crate::__private::serde::Deserialize>::deserialize(
                    deserializer,
                )
                .map(Self)
            }
        }

        impl ::std::fmt::Display for $name {
            fn fmt(&self, f: &mut ::std::fmt::Formatter<'_>) -> ::std::fmt::Result {
                ::std::fmt::Display::fmt(&self.0, f)
            }
        }

        impl ::std::str::FromStr for $name {
            type Err = $crate::id::ParseIdError;

            fn from_str(value: &str) -> ::std::result::Result<Self, Self::Err> {
                $crate::__private::uuid::Uuid::parse_str(value)
                    .map(Self)
                    .map_err(|_| $crate::id::ParseIdError::new(stringify!($name)))
            }
        }
    };
}

define_id!(
    /// Identifies a tenant, the hard isolation boundary.
    TenantId
);
define_id!(
    /// Identifies a principal: a human user, service account or agent.
    UserId
);
define_id!(
    /// Identifies one domain event; handlers deduplicate on it.
    EventId
);
define_id!(
    /// Ties together everything caused by one request or job.
    CorrelationId
);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_ids_are_uuid_v7() {
        assert_eq!(TenantId::generate().as_uuid().get_version_num(), 7);
    }

    #[test]
    fn ids_round_trip_through_strings() {
        let id = UserId::generate();
        let parsed: UserId = id.to_string().parse().expect("valid id");
        assert_eq!(parsed, id);
    }

    #[test]
    fn invalid_strings_are_rejected_with_the_type_name() {
        let error = "not-a-uuid".parse::<TenantId>().expect_err("must fail");
        assert_eq!(error.to_string(), "invalid TenantId: expected a UUID");
    }

    #[test]
    fn ids_serialize_as_plain_strings() {
        let id = EventId::generate();
        let json = serde_json::to_string(&id).expect("serializable");
        assert_eq!(json, format!("\"{id}\""));
        let back: EventId = serde_json::from_str(&json).expect("deserializable");
        assert_eq!(back, id);
    }

    #[test]
    fn later_ids_do_not_sort_before_earlier_ones() {
        let first = CorrelationId::generate();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let second = CorrelationId::generate();
        assert!(first < second);
    }
}
