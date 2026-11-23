//! An Open Policy Agent instance registered with Hodor, and its credential.

use crate::bundle::Author;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::{Digest, DomainError, RandomSource, Secret, TenantId, Timestamp};

hodor_kernel::define_id!(
    /// Identifies a registered Open Policy Agent instance.
    InstanceId
);

/// What every credential starts with, so that one found in a log or a
/// repository is recognized.
pub const CREDENTIAL_PREFIX: &str = "hodor_pa_";
/// Random bytes in a credential.
const CREDENTIAL_BYTES: usize = 32;

/// The name an operator gives an instance: 1 to 63 lower-case letters,
/// digits and `-`, starting with a letter or digit.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct InstanceName(String);

impl InstanceName {
    /// Reads a name.
    ///
    /// # Errors
    ///
    /// Returns `authorization.policy_agent_instance_name_invalid` for a
    /// name that is not one.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        let well_formed = (1..=63).contains(&value.len())
            && value
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
            && !value.starts_with('-');
        if well_formed {
            Ok(Self(value.to_owned()))
        } else {
            Err(DomainError::invalid(
                "authorization.policy_agent_instance_name_invalid",
                "an instance's name has 1 to 63 lower-case letters, digits and `-`, and does not start with `-`",
            ))
        }
    }

    /// The name as written.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A registered instance.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Instance {
    id: InstanceId,
    name: InstanceName,
    tenant: Option<TenantId>,
    registered_at: Timestamp,
    disabled_at: Option<Timestamp>,
}

impl Instance {
    /// A new instance: shared without a tenant, or of `tenant`'s own.
    #[must_use]
    pub fn new(name: InstanceName, tenant: Option<TenantId>, now: Timestamp) -> Self {
        Self {
            id: InstanceId::generate(),
            name,
            tenant,
            registered_at: now,
            disabled_at: None,
        }
    }

    /// An instance as storage holds it.
    #[must_use]
    pub const fn from_stored(
        id: InstanceId,
        name: InstanceName,
        tenant: Option<TenantId>,
        registered_at: Timestamp,
        disabled_at: Option<Timestamp>,
    ) -> Self {
        Self {
            id,
            name,
            tenant,
            registered_at,
            disabled_at,
        }
    }

    /// Its identifier.
    #[must_use]
    pub const fn id(&self) -> InstanceId {
        self.id
    }

    /// Its name.
    #[must_use]
    pub const fn name(&self) -> &InstanceName {
        &self.name
    }

    /// The tenant it belongs to, or `None` for a shared instance.
    #[must_use]
    pub const fn tenant(&self) -> Option<TenantId> {
        self.tenant
    }

    /// When it was registered.
    #[must_use]
    pub const fn registered_at(&self) -> Timestamp {
        self.registered_at
    }

    /// When it was disabled, if it was.
    #[must_use]
    pub const fn disabled_at(&self) -> Option<Timestamp> {
        self.disabled_at
    }

    /// Whether it may be served anything of `tenant`: its own tenant for
    /// an instance of a tenant's own, any tenant for a shared one.
    #[must_use]
    pub fn serves(&self, tenant: TenantId) -> bool {
        self.tenant.is_none_or(|own| own == tenant)
    }

    /// Whether it may pull a bundle of `tenant` written by `author`. A
    /// shared instance never runs what a tenant wrote (Decision 0010).
    #[must_use]
    pub fn may_pull(&self, tenant: TenantId, author: Author) -> bool {
        match self.tenant {
            Some(own) => own == tenant,
            None => author == Author::Operator,
        }
    }
}

/// A new credential: the prefix and 32 random bytes in base64url.
#[must_use]
pub(crate) fn new_credential(random: &dyn RandomSource) -> Secret<String> {
    let mut bytes = [0_u8; CREDENTIAL_BYTES];
    random.fill(&mut bytes);
    Secret::from(format!(
        "{CREDENTIAL_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(bytes)
    ))
}

/// What is kept of a credential, or `None` for something that cannot be
/// one, which needs no lookup.
#[must_use]
pub(crate) fn credential_digest(credential: &str, digest: &dyn Digest) -> Option<[u8; 32]> {
    let encoded = credential.strip_prefix(CREDENTIAL_PREFIX)?;
    let decoded = URL_SAFE_NO_PAD.decode(encoded).ok()?;
    (decoded.len() == CREDENTIAL_BYTES).then(|| digest.sha256(credential.as_bytes()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::random::testing::{CountingRandom, FakeDigest};

    #[test]
    fn names_are_lower_case_letters_digits_and_hyphens() {
        for good in ["a", "policy-1", "0shared"] {
            assert!(InstanceName::parse(good).is_ok(), "{good}");
        }
        for bad in ["", "-a", "Policy", "a_b", "a b", &"a".repeat(64)] {
            assert!(InstanceName::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn a_shared_instance_pulls_only_what_the_operator_wrote() {
        let tenant = TenantId::generate();
        let shared = Instance::new(
            InstanceName::parse("shared").expect("name"),
            None,
            time::OffsetDateTime::UNIX_EPOCH,
        );
        assert!(shared.may_pull(tenant, Author::Operator));
        assert!(!shared.may_pull(tenant, Author::Tenant));
        assert!(shared.serves(tenant));
    }

    #[test]
    fn an_instance_of_a_tenant_pulls_only_that_tenant() {
        let tenant = TenantId::generate();
        let other = TenantId::generate();
        let own = Instance::new(
            InstanceName::parse("own").expect("name"),
            Some(tenant),
            time::OffsetDateTime::UNIX_EPOCH,
        );
        assert!(own.may_pull(tenant, Author::Tenant));
        assert!(own.may_pull(tenant, Author::Operator));
        assert!(!own.may_pull(other, Author::Operator));
        assert!(!own.serves(other));
    }

    #[test]
    fn a_credential_is_recognized_and_anything_else_is_not() {
        let credential = new_credential(&CountingRandom::default());
        assert!(credential.expose().starts_with(CREDENTIAL_PREFIX));
        assert_eq!(credential.expose().len(), CREDENTIAL_PREFIX.len() + 43);
        assert!(credential_digest(credential.expose(), &FakeDigest).is_some());
        for bad in [
            "",
            "hodor_pa_",
            "hodor_at_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
            "hodor_pa_AAAA",
            "hodor_pa_!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!",
        ] {
            assert!(credential_digest(bad, &FakeDigest).is_none(), "{bad}");
        }
    }
}
