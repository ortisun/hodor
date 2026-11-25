//! The secrets deliveries are signed with, and their rotation.

use crate::domain::endpoint::EndpointId;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use hodor_kernel::{DomainError, SealedSecret, Secret, Timestamp};
use time::Duration;

hodor_kernel::define_id!(
    /// Identifies one signing secret of an endpoint.
    SigningSecretId
);

/// The purpose signing secrets are sealed for.
pub const SIGNING_SECRET_PURPOSE: &str = "webhooks.signing_secret";

/// How many random bytes a secret has.
pub const SECRET_BYTES: usize = 32;

/// What a secret is written after, in the form Standard Webhooks libraries
/// read.
pub const SECRET_PREFIX: &str = "whsec_";

/// How long the previous secret keeps signing after a rotation, unless
/// asked otherwise.
pub const DEFAULT_OVERLAP_HOURS: u32 = 24;

/// The longest overlap that may be asked for.
pub const MAX_OVERLAP_HOURS: u32 = 168;

/// One secret of an endpoint, sealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigningSecret {
    /// Its identifier.
    pub id: SigningSecretId,
    /// The endpoint it signs for.
    pub endpoint_id: EndpointId,
    /// The secret's bytes, sealed for [`SIGNING_SECRET_PURPOSE`].
    pub sealed: SealedSecret,
    /// When it was made.
    pub created_at: Timestamp,
    /// `None` while it is the current secret; the end of its overlap once
    /// another replaced it.
    pub expires_at: Option<Timestamp>,
}

impl SigningSecret {
    /// Whether it signs at `now`.
    #[must_use]
    pub fn is_in_force(&self, now: Timestamp) -> bool {
        self.expires_at.is_none_or(|end| end > now)
    }
}

/// The secret as a person is given it: `whsec_` and the Base64 of its
/// bytes.
#[must_use]
pub(crate) fn written(bytes: &[u8]) -> Secret<String> {
    Secret::new(format!("{SECRET_PREFIX}{}", STANDARD.encode(bytes)))
}

/// Reads the overlap asked for a rotation, in hours.
///
/// # Errors
///
/// Returns `webhooks.overlap_invalid` past [`MAX_OVERLAP_HOURS`].
pub(crate) fn overlap(hours: Option<u32>) -> Result<Duration, DomainError> {
    let hours = hours.unwrap_or(DEFAULT_OVERLAP_HOURS);
    if hours > MAX_OVERLAP_HOURS {
        return Err(DomainError::invalid(
            "webhooks.overlap_invalid",
            "the overlap is a whole number of hours from 0 to 168",
        ));
    }
    Ok(Duration::hours(i64::from(hours)))
}

/// What a rotation at `now` does to the secrets an endpoint has: the end
/// each one in force is given. The newest keeps signing until `now` and
/// the overlap; any older one still in force ends at once, so that no more
/// than two secrets ever sign.
#[must_use]
pub(crate) fn rotation(
    secrets: &[SigningSecret],
    now: Timestamp,
    overlap: Duration,
) -> Vec<(SigningSecretId, Timestamp)> {
    let mut in_force: Vec<&SigningSecret> = secrets
        .iter()
        .filter(|secret| secret.is_in_force(now))
        .collect();
    in_force.sort_by_key(|secret| std::cmp::Reverse((secret.created_at, secret.id)));
    in_force
        .iter()
        .enumerate()
        .map(|(position, secret)| {
            let end = if position == 0 { now + overlap } else { now };
            // A secret already ending sooner keeps its end.
            let end = secret.expires_at.map_or(end, |current| current.min(end));
            (secret.id, end)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: Timestamp = Timestamp::UNIX_EPOCH;

    fn secret(created: i64, expires: Option<i64>) -> SigningSecret {
        SigningSecret {
            id: SigningSecretId::generate(),
            endpoint_id: EndpointId::generate(),
            sealed: SealedSecret::from_stored(vec![1]),
            created_at: NOW + Duration::seconds(created),
            expires_at: expires.map(|seconds| NOW + Duration::seconds(seconds)),
        }
    }

    #[test]
    fn a_secret_is_written_as_standard_webhooks_libraries_read_it() {
        let written = written(&[0_u8; 32]);
        assert_eq!(
            written.expose(),
            "whsec_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
        );
    }

    #[test]
    fn the_overlap_is_24_hours_unless_asked_and_at_most_a_week() {
        assert_eq!(overlap(None), Ok(Duration::hours(24)));
        assert_eq!(overlap(Some(0)), Ok(Duration::ZERO));
        assert_eq!(overlap(Some(168)), Ok(Duration::hours(168)));
        assert_eq!(
            overlap(Some(169)).expect_err("refused").code(),
            "webhooks.overlap_invalid"
        );
    }

    #[test]
    fn a_rotation_leaves_the_replaced_secret_its_overlap_and_ends_any_older_one() {
        let older = secret(0, Some(3_600));
        let current = secret(10, None);
        let gone = secret(-10, Some(-1));
        let now = NOW + Duration::seconds(20);
        let ends = rotation(
            &[older.clone(), current.clone(), gone],
            now,
            Duration::hours(24),
        );
        assert_eq!(
            ends,
            [(current.id, now + Duration::hours(24)), (older.id, now)]
        );
        assert!(rotation(&[], now, Duration::hours(1)).is_empty());
    }

    #[test]
    fn a_secret_signs_until_its_end() {
        let ending = secret(0, Some(10));
        assert!(ending.is_in_force(NOW + Duration::seconds(9)));
        assert!(!ending.is_in_force(NOW + Duration::seconds(10)));
        assert!(secret(0, None).is_in_force(NOW + Duration::days(9_999)));
    }
}
