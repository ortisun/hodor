//! What a bundle holds, how its files are checked, and how it is signed.
//!
//! Specified in `docs/architecture/contexts/authorization.md`, "Bundles".

use crate::archive::{gzip, tar};
use crate::canonical::to_canonical;
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use hodor_kernel::{Digest, DomainError, TenantId, Timestamp};
use serde_json::{Value, json};
use std::collections::BTreeSet;
use std::fmt::Write as _;

/// At most this many files in a bundle.
const MAX_FILES: usize = 1000;
/// At most this many bytes in one file.
const MAX_FILE_BYTES: usize = 1024 * 1024;
/// At most this many bytes in all files together.
const MAX_TOTAL_BYTES: usize = 8 * 1024 * 1024;
/// At most this many characters in a path under the tenant's tree.
const MAX_PATH: usize = 200;

/// Who wrote what a bundle holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Author {
    /// Whoever operates the installation. Only such a bundle is served to
    /// a shared instance.
    Operator,
    /// The tenant. Served only to an instance of the tenant's own.
    Tenant,
}

impl Author {
    /// The name storage and the command line use.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Operator => "operator",
            Self::Tenant => "tenant",
        }
    }

    /// Reads a name.
    ///
    /// # Errors
    ///
    /// Returns `authorization.bundle_author_invalid` for anything but
    /// `operator` or `tenant`.
    pub fn parse(value: &str) -> Result<Self, DomainError> {
        match value {
            "operator" => Ok(Self::Operator),
            "tenant" => Ok(Self::Tenant),
            _ => Err(DomainError::invalid(
                "authorization.bundle_author_invalid",
                "a bundle is written by `operator` or `tenant`",
            )),
        }
    }
}

/// The name of `tenant`'s bundle, `t` and the tenant's identifier as 32
/// hexadecimal digits, as the decision path names the tenant.
#[must_use]
pub fn bundle_name(tenant: TenantId) -> String {
    format!("t{}", tenant.as_uuid().simple())
}

/// The tenant a bundle name names, or `None` for a name that is not one.
#[must_use]
pub fn tenant_of(name: &str) -> Option<TenantId> {
    let digits = name.strip_prefix('t')?;
    let lower = digits.len() == 32
        && digits
            .chars()
            .all(|c| c.is_ascii_digit() || ('a'..='f').contains(&c));
    lower
        .then(|| digits.parse().ok())
        .flatten()
        .map(TenantId::from_uuid)
}

/// The tree of `tenant` in an instance's documents, which its bundle's
/// one root names.
#[must_use]
pub fn tenant_root(tenant: TenantId) -> String {
    format!("hodor/tenants/{}", bundle_name(tenant))
}

/// The Rego package of `tenant`'s tree.
fn tenant_package(tenant: TenantId) -> String {
    tenant_root(tenant).replace('/', ".")
}

/// One file given to a bundle, at a path under the tenant's tree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BundleFile {
    /// Relative to the tenant's tree: `resource_servers/r…/policy.rego`.
    pub path: String,
    /// What it holds.
    pub contents: Vec<u8>,
}

/// Signs what Hodor publishes, with ES256: an ECDSA P-256 signature of
/// the SHA-256 of a message, as the 64 bytes of its two numbers.
pub trait BundleSigner: Send + Sync {
    /// The name instances know the key by, the `kid` of the signature.
    fn key_id(&self) -> &str;

    /// The signature of `message`.
    ///
    /// # Errors
    ///
    /// Returns an error if the key cannot sign.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DomainError>;
}

fn file_error(message: String) -> DomainError {
    DomainError::invalid(
        "authorization.bundle_file_invalid",
        "a file of the bundle is refused",
    )
    .with_detail(message)
}

fn well_formed_path(path: &str) -> bool {
    path.len() <= MAX_PATH
        && path.split('/').all(|segment| {
            !segment.is_empty()
                && segment != "."
                && segment != ".."
                && segment
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        })
}

/// The package a module declares, or `None` if its first statement is
/// not a plain `package a.b.c`.
fn declared_package(module: &str) -> Option<&str> {
    for line in module.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let rest = line.strip_prefix("package")?;
        if !rest.starts_with([' ', '\t']) {
            return None;
        }
        let name = rest.split('#').next()?.trim();
        let plain = !name.is_empty()
            && name.split('.').all(|part| {
                let mut characters = part.chars();
                characters
                    .next()
                    .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                    && characters.all(|c| c.is_ascii_alphanumeric() || c == '_')
            });
        return plain.then_some(name);
    }
    None
}

/// Whether a file is a test of the policy: a module whose name ends in
/// `_test.rego`. Tests are checked and run, and never published.
#[must_use]
pub fn is_test(path: &str) -> bool {
    path.rsplit('/')
        .next()
        .is_some_and(|name| name.ends_with("_test.rego"))
}

/// Checks `files` as a bundle of `tenant` holds them, and returns them in
/// the form they are kept and archived in: sorted by path, with data
/// documents in canonical form.
///
/// # Errors
///
/// Returns `authorization.bundle_file_invalid` for a file that is
/// refused, `authorization.bundle_too_large` for too many files or bytes,
/// and `authorization.bundle_empty` for no file.
pub fn normalize(tenant: TenantId, files: &[BundleFile]) -> Result<Vec<BundleFile>, DomainError> {
    if files.is_empty() {
        return Err(DomainError::invalid(
            "authorization.bundle_empty",
            "a bundle holds at least one file",
        ));
    }
    let total: usize = files.iter().map(|file| file.contents.len()).sum();
    if files.len() > MAX_FILES || total > MAX_TOTAL_BYTES {
        return Err(DomainError::invalid(
            "authorization.bundle_too_large",
            "a bundle holds at most 1000 files and 8 mebibytes",
        ));
    }
    let mut seen = BTreeSet::new();
    let mut normalized = Vec::with_capacity(files.len());
    for file in files {
        if !seen.insert(file.path.clone()) {
            return Err(file_error(format!("`{}` is given twice", file.path)));
        }
        let (_, contents) = checked(tenant, file)?;
        normalized.push(BundleFile {
            path: file.path.clone(),
            contents,
        });
    }
    normalized.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(normalized)
}

/// Checks one file and returns what goes into the archive.
fn checked(tenant: TenantId, file: &BundleFile) -> Result<(String, Vec<u8>), DomainError> {
    if !well_formed_path(&file.path) {
        return Err(file_error(format!(
            "`{}` is not a relative path of letters, digits, `_`, `-` and `.`",
            file.path
        )));
    }
    if file.contents.len() > MAX_FILE_BYTES {
        return Err(file_error(format!(
            "`{}` is larger than 1 mebibyte",
            file.path
        )));
    }
    let archived = format!("{}/{}", tenant_root(tenant), file.path);
    if std::path::Path::new(&file.path)
        .extension()
        .is_some_and(|extension| extension == "rego")
    {
        let module = std::str::from_utf8(&file.contents)
            .map_err(|_| file_error(format!("`{}` is not UTF-8 text", file.path)))?;
        let root = tenant_package(tenant);
        let inside = declared_package(module)
            .is_some_and(|name| name == root || name.starts_with(&format!("{root}.")));
        if !inside {
            return Err(file_error(format!(
                "`{}` does not declare a package in `{root}`",
                file.path
            )));
        }
        Ok((archived, file.contents.clone()))
    } else if file.path == "data.json" || file.path.ends_with("/data.json") {
        let value: Value = serde_json::from_slice(&file.contents)
            .map_err(|_| file_error(format!("`{}` is not JSON", file.path)))?;
        if !value.is_object() {
            return Err(file_error(format!("`{}` is not a JSON object", file.path)));
        }
        Ok((archived, to_canonical(&value).into_bytes()))
    } else {
        Err(file_error(format!(
            "`{}` is neither a policy module (`.rego`) nor a data document (`data.json`)",
            file.path
        )))
    }
}

fn hexadecimal(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        // Writing to a `String` cannot fail.
        let _ = write!(out, "{byte:02x}");
    }
    out
}

/// A bundle built and signed, ready to be stored and served.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishedBundle {
    /// Its revision: 1 for a tenant's first bundle, then 2 and so on.
    pub revision: u64,
    /// Who wrote it.
    pub author: Author,
    /// The gzip-compressed tar file.
    pub archive: Vec<u8>,
    /// The SHA-256 of the archive, its entity tag.
    pub digest: [u8; 32],
    /// When it was published.
    pub published_at: Timestamp,
}

impl PublishedBundle {
    /// The entity tag the bundle is served with, quoted.
    #[must_use]
    pub fn entity_tag(&self) -> String {
        format!("\"{}\"", hexadecimal(&self.digest))
    }
}

/// Checks `files` and builds `tenant`'s bundle of `revision`, signed by
/// `signer`.
///
/// # Errors
///
/// Returns `authorization.bundle_file_invalid` for a file that is
/// refused, `authorization.bundle_too_large` for too many files or bytes,
/// `authorization.bundle_empty` for no file, and the signer's error if it
/// cannot sign.
pub(crate) fn build(
    tenant: TenantId,
    revision: u64,
    files: &[BundleFile],
    signer: &dyn BundleSigner,
    digest: &dyn Digest,
) -> Result<Vec<u8>, DomainError> {
    let root = tenant_root(tenant);
    let contents: Vec<(String, Vec<u8>)> = normalize(tenant, files)?
        .into_iter()
        .map(|file| (format!("{root}/{}", file.path), file.contents))
        .collect();

    let manifest = to_canonical(&json!({
        "revision": revision.to_string(),
        "roots": [tenant_root(tenant)],
    }))
    .into_bytes();
    let mut signed = vec![(".manifest".to_owned(), manifest)];
    signed.extend(contents);

    let listed: Vec<Value> = signed
        .iter()
        .map(|(path, bytes)| {
            json!({
                "name": path,
                "hash": hexadecimal(&digest.sha256(bytes)),
                "algorithm": "SHA-256",
            })
        })
        .collect();
    let header = json!({"alg": "ES256", "kid": signer.key_id(), "typ": "JWT"});
    let payload = json!({"files": listed});
    let signing_input = format!(
        "{}.{}",
        URL_SAFE_NO_PAD.encode(to_canonical(&header)),
        URL_SAFE_NO_PAD.encode(to_canonical(&payload))
    );
    let signature = signer.sign(signing_input.as_bytes())?;
    let token = format!("{signing_input}.{}", URL_SAFE_NO_PAD.encode(signature));
    let signatures = to_canonical(&json!({"signatures": [token]})).into_bytes();

    let mut archived = vec![(".signatures.json".to_owned(), signatures)];
    archived.extend(signed);
    Ok(gzip(&tar(&archived)?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{gunzip, untar};
    use hodor_kernel::random::testing::FakeDigest;

    struct Fixed;

    impl BundleSigner for Fixed {
        fn key_id(&self) -> &str {
            "test"
        }

        fn sign(&self, message: &[u8]) -> Result<Vec<u8>, DomainError> {
            Ok(FakeDigest.sha256(message).repeat(2))
        }
    }

    fn file(path: &str, contents: &str) -> BundleFile {
        BundleFile {
            path: path.to_owned(),
            contents: contents.as_bytes().to_vec(),
        }
    }

    fn policy(tenant: TenantId, rest: &str) -> String {
        format!(
            "# A policy.\npackage {}{rest}\n\ndefault allow := false\n",
            tenant_package(tenant)
        )
    }

    #[test]
    fn names_and_tenants_go_both_ways() {
        let tenant = TenantId::generate();
        let name = bundle_name(tenant);
        assert_eq!(name.len(), 33);
        assert_eq!(tenant_of(&name), Some(tenant));
        for bad in [
            "",
            "t",
            &name[1..],
            &name.to_uppercase(),
            &format!("{name}0"),
            "x0193a1",
        ] {
            assert_eq!(tenant_of(bad), None, "{bad}");
        }
    }

    #[test]
    fn a_bundle_holds_its_files_under_the_tenant_root_with_a_signature() {
        let tenant = TenantId::generate();
        let archive = build(
            tenant,
            3,
            &[
                file(
                    "resource_servers/rab/policy.rego",
                    &policy(tenant, ".resource_servers.rab"),
                ),
                file("data.json", r#"{"b": 1, "a": [true]}"#),
            ],
            &Fixed,
            &FakeDigest,
        )
        .expect("bundle");
        let files = untar(&gunzip(&archive, 1 << 20).expect("gzip"));
        let root = tenant_root(tenant);
        let paths: Vec<&str> = files.iter().map(|(path, _)| path.as_str()).collect();
        assert_eq!(
            paths,
            vec![
                ".signatures.json",
                ".manifest",
                &format!("{root}/data.json"),
                &format!("{root}/resource_servers/rab/policy.rego"),
            ]
        );
        assert_eq!(
            String::from_utf8(files[1].1.clone()).expect("text"),
            format!(r#"{{"revision":"3","roots":["{root}"]}}"#)
        );
        assert_eq!(files[2].1, br#"{"a":[true],"b":1}"#.to_vec());

        let signatures: Value = serde_json::from_slice(&files[0].1).expect("json");
        let token = signatures["signatures"][0].as_str().expect("token");
        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);
        let header: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[0]).expect("b64")).expect("json");
        assert_eq!(header["alg"], "ES256");
        assert_eq!(header["kid"], "test");
        let payload: Value =
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(parts[1]).expect("b64")).expect("json");
        let listed = payload["files"].as_array().expect("files");
        assert_eq!(listed.len(), 3, "every file but the signatures");
        for (entry, (path, bytes)) in listed.iter().zip(&files[1..]) {
            assert_eq!(entry["name"], path.as_str());
            assert_eq!(entry["hash"], hexadecimal(&FakeDigest.sha256(bytes)));
            assert_eq!(entry["algorithm"], "SHA-256");
        }
        let signed = format!("{}.{}", parts[0], parts[1]);
        assert_eq!(
            URL_SAFE_NO_PAD.decode(parts[2]).expect("b64"),
            Fixed.sign(signed.as_bytes()).expect("signature")
        );
    }

    #[test]
    fn the_same_files_make_the_same_archive() {
        let tenant = TenantId::generate();
        let files = [file("data.json", "{}")];
        assert_eq!(
            build(tenant, 1, &files, &Fixed, &FakeDigest).expect("first"),
            build(tenant, 1, &files, &Fixed, &FakeDigest).expect("second")
        );
    }

    #[test]
    fn a_module_outside_the_tenant_package_is_refused() {
        let tenant = TenantId::generate();
        let other = TenantId::generate();
        let refused = [
            policy(other, ""),
            policy(tenant, "x"),
            "package hodor.tenants\n".to_owned(),
            "package system.authz\n".to_owned(),
            format!("package {}[\"x\"]\n", tenant_package(tenant)),
            "default allow := true\n".to_owned(),
            String::new(),
        ];
        for module in refused {
            let error = build(tenant, 1, &[file("p.rego", &module)], &Fixed, &FakeDigest)
                .expect_err("refused");
            assert_eq!(
                error.code(),
                "authorization.bundle_file_invalid",
                "{module}"
            );
        }
        assert!(
            build(
                tenant,
                1,
                &[file("p.rego", &policy(tenant, ".a.b_c"))],
                &Fixed,
                &FakeDigest
            )
            .is_ok()
        );
    }

    #[test]
    fn paths_and_kinds_of_file_that_are_not_allowed_are_refused() {
        let tenant = TenantId::generate();
        for (path, contents) in [
            ("../data.json", "{}"),
            ("/data.json", "{}"),
            ("a//data.json", "{}"),
            ("a/./data.json", "{}"),
            ("a b/data.json", "{}"),
            (".manifest", "{}"),
            ("x.json", "{}"),
            ("data.yaml", "a: 1"),
            ("data.json", "[1]"),
            ("data.json", "not json"),
        ] {
            let error = build(tenant, 1, &[file(path, contents)], &Fixed, &FakeDigest)
                .expect_err("refused");
            assert_eq!(error.code(), "authorization.bundle_file_invalid", "{path}");
        }
        let twice = [file("data.json", "{}"), file("data.json", "{}")];
        assert!(build(tenant, 1, &twice, &Fixed, &FakeDigest).is_err());
        assert_eq!(
            build(tenant, 1, &[], &Fixed, &FakeDigest).map_err(|e| e.code().to_owned()),
            Err("authorization.bundle_empty".to_owned())
        );
        let large = BundleFile {
            path: "data.json".to_owned(),
            contents: vec![b' '; MAX_FILE_BYTES + 1],
        };
        assert!(build(tenant, 1, &[large], &Fixed, &FakeDigest).is_err());
    }

    #[test]
    fn authors_are_read_by_name() {
        assert_eq!(
            Author::parse("operator").expect("operator"),
            Author::Operator
        );
        assert_eq!(Author::parse("tenant").expect("tenant").as_str(), "tenant");
        assert!(Author::parse("Operator").is_err());
    }
}
