//! The decision path: from the tenant and the binding, never the request.

use hodor_authorization::api::Namespace;
use hodor_kernel::{Digest, TenantContext};
use std::fmt::Write as _;

/// How many hexadecimal digits of the namespace's digest name it.
const NAMESPACE_DIGITS: usize = 32;

/// The path of the Data API that decides for `namespace` in `tenant`,
/// such as `/v1/data/hodor/tenants/t…/resource_servers/r…/decision`.
///
/// The tenant is its identifier as 32 hexadecimal digits; the namespace,
/// an address or a name that cannot be a segment of a Rego package, is
/// the first 32 hexadecimal digits of its SHA-256. Both segments are a
/// letter followed by hexadecimal digits, so nothing in them can add a
/// segment or escape one.
#[must_use]
pub fn decision_path(tenant: &TenantContext, namespace: &Namespace, digest: &dyn Digest) -> String {
    let tenant = tenant.tenant_id().as_uuid().simple().to_string();
    let mut resource_server = String::with_capacity(NAMESPACE_DIGITS);
    for byte in digest
        .sha256(namespace.as_str().as_bytes())
        .iter()
        .take(NAMESPACE_DIGITS / 2)
    {
        // Writing to a `String` cannot fail.
        let _ = write!(resource_server, "{byte:02x}");
    }
    format!("/v1/data/hodor/tenants/t{tenant}/resource_servers/r{resource_server}/decision")
}

/// The Rego package whose rule `decision` answers for `namespace` in
/// `tenant`: the decision path as a package, `hodor.tenants.t….resource_servers.r…`.
#[must_use]
pub fn decision_package(
    tenant: &TenantContext,
    namespace: &Namespace,
    digest: &dyn Digest,
) -> String {
    decision_path(tenant, namespace, digest)
        .trim_start_matches("/v1/data/")
        .trim_end_matches("/decision")
        .replace('/', ".")
}

#[cfg(test)]
mod tests {
    use super::*;
    use hodor_kernel::TenantId;

    /// A digest that is not SHA-256, only stable, for the shape of the path.
    struct Counting;

    impl Digest for Counting {
        fn sha256(&self, data: &[u8]) -> [u8; 32] {
            let mut out = [0_u8; 32];
            for (index, byte) in data.iter().enumerate() {
                out[index % 32] ^= byte.wrapping_add(u8::try_from(index % 251).unwrap_or(0));
            }
            out
        }

        fn sha512(&self, _data: &[u8]) -> [u8; 64] {
            unreachable!("a path is named by SHA-256")
        }
    }

    fn namespace(value: &str) -> Namespace {
        Namespace::parse(value).expect("namespace")
    }

    #[test]
    fn the_path_is_made_of_the_tenant_and_the_namespace_only() {
        let tenant = TenantContext::assume(TenantId::generate());
        let path = decision_path(&tenant, &namespace("https://api.example.com"), &Counting);
        let simple = tenant.tenant_id().as_uuid().simple().to_string();
        assert!(path.starts_with(&format!(
            "/v1/data/hodor/tenants/t{simple}/resource_servers/r"
        )));
        assert!(path.ends_with("/decision"));
        let segments: Vec<&str> = path.split('/').collect();
        assert_eq!(segments.len(), 9, "{path}");
        for segment in &segments[1..] {
            assert!(
                segment
                    .chars()
                    .all(|character| character.is_ascii_lowercase()
                        || character.is_ascii_digit()
                        || character == '_'),
                "{segment}"
            );
        }
        assert_eq!(segments[5].len(), 1 + 32, "the tenant");
        assert_eq!(segments[7].len(), 1 + NAMESPACE_DIGITS, "the namespace");
    }

    #[test]
    fn tenants_and_namespaces_get_paths_of_their_own() {
        let first = TenantContext::assume(TenantId::generate());
        let second = TenantContext::assume(TenantId::generate());
        let api = namespace("https://api.example.com");
        let other = namespace("urn:example:documents");
        assert_ne!(
            decision_path(&first, &api, &Counting),
            decision_path(&second, &api, &Counting)
        );
        assert_ne!(
            decision_path(&first, &api, &Counting),
            decision_path(&first, &other, &Counting)
        );
        assert_eq!(
            decision_path(&first, &api, &Counting),
            decision_path(&first, &api, &Counting)
        );
    }

    #[test]
    fn a_namespace_that_looks_like_a_path_stays_one_segment() {
        let tenant = TenantContext::assume(TenantId::generate());
        let path = decision_path(
            &tenant,
            &namespace("https://api.example.com/../../tenants/other"),
            &Counting,
        );
        assert_eq!(path.split('/').count(), 9, "{path}");
        assert!(!path.contains(".."));
    }
}
