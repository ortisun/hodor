//! Which instance answers a tenant.
//!
//! Named by whoever operates the installation, in the server's
//! configuration; never by a tenant, a binding or a request.

use hodor_kernel::{DomainError, TenantContext, TenantId};
use std::collections::BTreeMap;

/// The instances of an installation: a shared one for policy written by
/// the operator, and instances of their own for tenants that write their
/// own policy.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Instances {
    shared: Option<String>,
    dedicated: BTreeMap<TenantId, String>,
}

fn invalid() -> DomainError {
    DomainError::invalid(
        "authorization.open_policy_agent_instances_invalid",
        "instances of their own are `tenant-identifier=address` pairs separated by commas",
    )
}

/// An origin without the `/` an address may end with.
fn origin(address: &str) -> String {
    address.trim().trim_end_matches('/').to_owned()
}

impl Instances {
    /// No instance: every request is indeterminate.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }

    /// The shared instance, if any, and the tenants' own instances as
    /// `tenant-identifier=address` pairs separated by commas. Whether an
    /// address is an origin is the client's to check, when it is built
    /// with the same addresses.
    ///
    /// # Errors
    ///
    /// Returns `authorization.open_policy_agent_instances_invalid` for a
    /// pair that is not one, an identifier that is not a tenant's, or a
    /// tenant named twice.
    pub fn parse(shared: Option<&str>, dedicated: &str) -> Result<Self, DomainError> {
        let shared = shared
            .map(str::trim)
            .filter(|address| !address.is_empty())
            .map(origin);
        let mut own = BTreeMap::new();
        for pair in dedicated
            .split(',')
            .map(str::trim)
            .filter(|p| !p.is_empty())
        {
            let (tenant, address) = pair.split_once('=').ok_or_else(invalid)?;
            let tenant: TenantId = tenant.trim().parse().map_err(|_| invalid())?;
            let address = origin(address);
            if address.is_empty() || own.insert(tenant, address).is_some() {
                return Err(invalid());
            }
        }
        Ok(Self {
            shared,
            dedicated: own,
        })
    }

    /// The instance that answers `tenant`: its own, or the shared one.
    #[must_use]
    pub fn for_tenant(&self, tenant: &TenantContext) -> Option<&str> {
        self.dedicated
            .get(&tenant.tenant_id())
            .or(self.shared.as_ref())
            .map(String::as_str)
    }

    /// Every address, for the client that may call them and nothing else.
    #[must_use]
    pub fn addresses(&self) -> Vec<String> {
        let mut all: Vec<String> = self.shared.iter().cloned().collect();
        for address in self.dedicated.values() {
            if !all.contains(address) {
                all.push(address.clone());
            }
        }
        all
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tenant_with_its_own_instance_is_answered_by_it() {
        let own = TenantId::generate();
        let other = TenantId::generate();
        let instances = Instances::parse(
            Some("http://localhost:8181/"),
            &format!(" {own}=http://policy-a:8181 "),
        )
        .expect("instances");
        assert_eq!(
            instances.for_tenant(&TenantContext::assume(own)),
            Some("http://policy-a:8181")
        );
        assert_eq!(
            instances.for_tenant(&TenantContext::assume(other)),
            Some("http://localhost:8181")
        );
        assert_eq!(
            instances.addresses(),
            vec![
                "http://localhost:8181".to_owned(),
                "http://policy-a:8181".to_owned()
            ]
        );
    }

    #[test]
    fn without_instances_nobody_is_answered() {
        let instances = Instances::parse(None, "").expect("none");
        assert_eq!(instances, Instances::none());
        assert_eq!(
            instances.for_tenant(&TenantContext::assume(TenantId::generate())),
            None
        );
        assert!(
            Instances::parse(Some("  "), "")
                .expect("blank")
                .addresses()
                .is_empty()
        );
    }

    #[test]
    fn a_pair_that_is_not_one_is_refused() {
        let tenant = TenantId::generate();
        for bad in [
            "http://policy:8181".to_owned(),
            "acme=http://policy:8181".to_owned(),
            format!("{tenant}="),
            format!("{tenant}=http://a:1,{tenant}=http://b:1"),
        ] {
            assert_eq!(
                Instances::parse(None, &bad).map_err(|e| e.code().to_owned()),
                Err("authorization.open_policy_agent_instances_invalid".to_owned()),
                "{bad}"
            );
        }
    }
}
