//! The versions of resources: weak entity tags of RFC 7232, and the
//! preconditions of `If-Match` and `If-None-Match`.
//!
//! Specified in `docs/architecture/contexts/provisioning.md`, "Versions".
//! A version is a hash of the resource as SCIM writes it, so it changes
//! whenever what a SCIM client reads of the resource changes.

use serde_json::Value;
use std::fmt::Write as _;

/// The version of a resource whose JSON is `document`, without its
/// `meta.version`: `W/"<16 hexadecimal digits>"`. The hash is FNV-1a of
/// 64 bits over the document written with the keys of every object in
/// order, so that two equal documents have one version. It is no secret
/// and needs no cryptography: it only tells versions apart.
#[must_use]
pub fn version_of(document: &Value) -> String {
    let mut written = String::new();
    canonical(document, &mut written);
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in written.bytes() {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    format!("W/\"{hash:016x}\"")
}

fn canonical(value: &Value, out: &mut String) {
    match value {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                let _ = write!(out, "{}", Value::String(key.clone()));
                out.push(':');
                if let Some(inner) = map.get(key) {
                    canonical(inner, out);
                }
            }
            out.push('}');
        }
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                canonical(item, out);
            }
            out.push(']');
        }
        other => {
            let _ = write!(out, "{other}");
        }
    }
}

/// The opaque part of an entity tag, without `W/`.
fn opaque(tag: &str) -> &str {
    let tag = tag.trim();
    tag.strip_prefix("W/").unwrap_or(tag)
}

/// What a request's `If-Match` or `If-None-Match` names: any version, or
/// some versions.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Precondition {
    /// `*`: any version the resource has.
    Any,
    /// These versions, compared without regard to `W/`.
    Versions(Vec<String>),
}

impl Precondition {
    /// Reads the value of an `If-Match` or `If-None-Match` header, or the
    /// `version` of a bulk operation.
    #[must_use]
    pub fn read(header: &str) -> Self {
        if header.trim() == "*" {
            return Self::Any;
        }
        Self::Versions(
            header
                .split(',')
                .map(|tag| opaque(tag).to_owned())
                .filter(|tag| !tag.is_empty())
                .collect(),
        )
    }

    /// Whether a resource at `version` is one of those named.
    #[must_use]
    pub fn admits(&self, version: &str) -> bool {
        match self {
            Self::Any => true,
            Self::Versions(tags) => tags.iter().any(|tag| tag == opaque(version)),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn equal_documents_have_one_version_and_any_change_another() {
        let one = version_of(&json!({ "b": 1, "a": [true, "x"] }));
        assert_eq!(one, version_of(&json!({ "a": [true, "x"], "b": 1 })));
        assert_ne!(one, version_of(&json!({ "a": [true, "y"], "b": 1 })));
        assert!(one.starts_with("W/\"") && one.len() == 20, "{one}");
    }

    #[test]
    fn a_precondition_names_versions_without_regard_to_weakness() {
        let version = version_of(&json!({}));
        let strong = version.trim_start_matches("W/").to_owned();
        assert!(Precondition::read(&version).admits(&version));
        assert!(Precondition::read(&strong).admits(&version));
        assert!(Precondition::read(&format!("W/\"other\", {version}")).admits(&version));
        assert!(Precondition::read("*").admits(&version));
        assert!(!Precondition::read("W/\"other\"").admits(&version));
    }
}
