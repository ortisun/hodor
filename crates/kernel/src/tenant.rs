//! The tenant a piece of work runs under.

use crate::id::TenantId;

/// Proof that the current work is scoped to one tenant.
///
/// Every port method that touches tenant data takes a `&TenantContext`, so
/// tenant-scoped data cannot be reached without one.
///
/// A context is created by [`TenantContext::assume`]. Only three places may
/// call it: the HTTP tenant resolver, the worker's job loader and tests. The
/// tenant is never taken from a request body, header or query parameter. See
/// `docs/architecture/multi-tenancy.md`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TenantContext {
    tenant_id: TenantId,
}

impl TenantContext {
    /// Asserts that the caller has established which tenant this work
    /// belongs to. The name is deliberately conspicuous: every call site is
    /// a place where tenant isolation is decided.
    #[must_use]
    pub const fn assume(tenant_id: TenantId) -> Self {
        Self { tenant_id }
    }

    /// The tenant this work is scoped to.
    #[must_use]
    pub const fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn context_carries_its_tenant() {
        let tenant_id = TenantId::generate();
        assert_eq!(TenantContext::assume(tenant_id).tenant_id(), tenant_id);
    }

    #[test]
    fn contexts_of_different_tenants_differ() {
        let a = TenantContext::assume(TenantId::generate());
        let b = TenantContext::assume(TenantId::generate());
        assert_ne!(a, b);
    }
}
