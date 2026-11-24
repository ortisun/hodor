//! Bulk requests (RFC 7644, section 3.7): reading them within their
//! bounds, and the references between their operations.
//!
//! Specified in `docs/architecture/contexts/provisioning.md`, "Bulk
//! requests". Doing each operation is the HTTP layer's, with the same use
//! cases as the request alone.

use crate::domain::error::{invalid_syntax, invalid_value, too_many};
use hodor_kernel::DomainError;
use serde_json::{Map, Value};
use std::collections::BTreeMap;

/// The URI of a bulk request.
pub const BULK_REQUEST_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:BulkRequest";
/// The URI of a bulk answer.
pub const BULK_RESPONSE_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:BulkResponse";
/// The most operations of one bulk request.
pub const MAX_BULK_OPERATIONS: usize = 100;
/// The largest body of a bulk request, in bytes.
pub const MAX_BULK_BYTES: usize = 1_048_576;
/// The most characters of a `bulkId`.
pub const MAX_BULK_ID_CHARACTERS: usize = 64;

const REFERENCE: &str = "bulkId:";

/// What one operation does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BulkMethod {
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `PATCH`.
    Patch,
    /// `DELETE`.
    Delete,
}

impl BulkMethod {
    /// How it is written.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Post => "POST",
            Self::Put => "PUT",
            Self::Patch => "PATCH",
            Self::Delete => "DELETE",
        }
    }
}

/// One operation, read; what it names is checked when it is done.
#[derive(Debug, Clone, PartialEq)]
pub struct BulkOperation {
    /// `method`, as written.
    pub method: String,
    /// `bulkId`, as written.
    pub bulk_id: Option<String>,
    /// `path`, as written.
    pub path: Option<String>,
    /// `version`: the operation's `If-Match`.
    pub version: Option<String>,
    /// `data`: the body of the operation.
    pub data: Option<Value>,
}

/// A bulk request within its bounds.
#[derive(Debug, Clone, PartialEq)]
pub struct BulkRequest {
    /// How many operations may fail before the rest are not done.
    pub fail_on_errors: Option<u64>,
    /// The operations, in order.
    pub operations: Vec<BulkOperation>,
}

fn field<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    object
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
        .filter(|value| !value.is_null())
}

fn text(object: &Map<String, Value>, name: &str) -> Option<String> {
    field(object, name)
        .and_then(Value::as_str)
        .map(str::to_owned)
}

/// Reads a bulk request of `size` bytes.
///
/// # Errors
///
/// `provisioning.too_many` for a body past [`MAX_BULK_BYTES`] or more than
/// [`MAX_BULK_OPERATIONS`] operations: the whole request is refused.
/// `provisioning.invalid_syntax` for a body that is not a `BulkRequest`.
pub fn read_bulk(body: &Value, size: usize) -> Result<BulkRequest, DomainError> {
    if size > MAX_BULK_BYTES {
        return Err(too_many(format!(
            "a bulk request holds at most {MAX_BULK_BYTES} bytes"
        )));
    }
    let object = body
        .as_object()
        .ok_or_else(|| invalid_syntax("the body is not a JSON object"))?;
    let named = field(object, "schemas")
        .and_then(Value::as_array)
        .is_some_and(|schemas| {
            schemas.iter().any(|schema| {
                schema
                    .as_str()
                    .is_some_and(|schema| schema.eq_ignore_ascii_case(BULK_REQUEST_SCHEMA))
            })
        });
    if !named {
        return Err(invalid_syntax(format!(
            "schemas names {BULK_REQUEST_SCHEMA}"
        )));
    }
    let listed = field(object, "Operations")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_syntax("Operations is a list of operations"))?;
    if listed.len() > MAX_BULK_OPERATIONS {
        return Err(too_many(format!(
            "a bulk request holds at most {MAX_BULK_OPERATIONS} operations"
        )));
    }
    let fail_on_errors = match field(object, "failOnErrors") {
        None => None,
        Some(value) => Some(
            value
                .as_u64()
                .filter(|count| *count > 0)
                .ok_or_else(|| invalid_syntax("failOnErrors is a whole number above 0"))?,
        ),
    };
    let operations = listed
        .iter()
        .map(|operation| {
            let operation = operation.as_object().cloned().unwrap_or_default();
            BulkOperation {
                method: text(&operation, "method").unwrap_or_default(),
                bulk_id: text(&operation, "bulkId"),
                path: text(&operation, "path"),
                version: text(&operation, "version"),
                data: field(&operation, "data").cloned(),
            }
        })
        .collect();
    Ok(BulkRequest {
        fail_on_errors,
        operations,
    })
}

/// The method of an operation.
///
/// # Errors
///
/// `provisioning.invalid_value` for one that is not `POST`, `PUT`,
/// `PATCH` or `DELETE`.
pub fn method_of(operation: &BulkOperation) -> Result<BulkMethod, DomainError> {
    match operation.method.to_ascii_uppercase().as_str() {
        "POST" => Ok(BulkMethod::Post),
        "PUT" => Ok(BulkMethod::Put),
        "PATCH" => Ok(BulkMethod::Patch),
        "DELETE" => Ok(BulkMethod::Delete),
        _ => Err(invalid_value(
            "a bulk operation's method is POST, PUT, PATCH or DELETE",
        )),
    }
}

/// Checks a `bulkId`: 1 to 64 letters, digits, `-` and `_`.
///
/// # Errors
///
/// `provisioning.invalid_value` for one that breaks the rule.
pub fn check_bulk_id(bulk_id: &str) -> Result<(), DomainError> {
    let valid = !bulk_id.is_empty()
        && bulk_id.chars().count() <= MAX_BULK_ID_CHARACTERS
        && bulk_id
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'));
    if valid {
        Ok(())
    } else {
        Err(invalid_value(format!(
            "a bulkId is 1 to {MAX_BULK_ID_CHARACTERS} letters, digits, - and _"
        )))
    }
}

fn resolved(text: &str, created: &BTreeMap<String, String>) -> Result<String, DomainError> {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(at) = rest.find(REFERENCE) {
        out.push_str(&rest[..at]);
        let after = &rest[at + REFERENCE.len()..];
        let end = after
            .find(|character: char| {
                !(character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
            })
            .unwrap_or(after.len());
        let name = &after[..end];
        let id = created.get(name).ok_or_else(|| {
            invalid_value(format!(
                "the operation names bulkId:{name}, which no earlier operation of the request created"
            ))
        })?;
        out.push_str(id);
        rest = &after[end..];
    }
    out.push_str(rest);
    Ok(out)
}

/// The path with each `bulkId:<name>` replaced by the identifier an
/// earlier operation's `POST` gave out.
///
/// # Errors
///
/// `provisioning.invalid_value` for a reference to a `bulkId` no earlier
/// operation created.
pub fn resolve_path(path: &str, created: &BTreeMap<String, String>) -> Result<String, DomainError> {
    resolved(path, created)
}

/// The data with every string value that is `bulkId:<name>` replaced as
/// [`resolve_path`] does.
///
/// # Errors
///
/// As [`resolve_path`].
pub fn resolve_data(
    data: &Value,
    created: &BTreeMap<String, String>,
) -> Result<Value, DomainError> {
    Ok(match data {
        Value::String(text) if text.starts_with(REFERENCE) => {
            Value::String(resolved(text, created)?)
        }
        Value::Array(items) => Value::Array(
            items
                .iter()
                .map(|item| resolve_data(item, created))
                .collect::<Result<_, _>>()?,
        ),
        Value::Object(object) => Value::Object(
            object
                .iter()
                .map(|(key, value)| Ok((key.clone(), resolve_data(value, created)?)))
                .collect::<Result<_, DomainError>>()?,
        ),
        other => other.clone(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn body(count: usize) -> Value {
        json!({
            "schemas": [BULK_REQUEST_SCHEMA],
            "Operations": vec![json!({ "method": "DELETE", "path": "/Groups/x" }); count],
        })
    }

    #[test]
    fn a_request_past_a_bound_is_refused_whole() {
        assert_eq!(
            read_bulk(&body(MAX_BULK_OPERATIONS), 10)
                .expect("read")
                .operations
                .len(),
            100
        );
        for refused in [
            read_bulk(&body(MAX_BULK_OPERATIONS + 1), 10),
            read_bulk(&body(1), MAX_BULK_BYTES + 1),
        ] {
            assert_eq!(
                refused.expect_err("refused").code(),
                "provisioning.too_many"
            );
        }
        assert_eq!(
            read_bulk(&json!({ "Operations": [] }), 10)
                .expect_err("refused")
                .code(),
            "provisioning.invalid_syntax"
        );
    }

    #[test]
    fn references_are_replaced_by_what_earlier_operations_created() {
        let created = BTreeMap::from([("ana".to_owned(), "0193-a".to_owned())]);
        assert_eq!(
            resolve_path("/Users/bulkId:ana", &created).expect("resolved"),
            "/Users/0193-a"
        );
        let data = resolve_data(
            &json!({ "members": [{ "value": "bulkId:ana" }], "displayName": "bulkId is a word" }),
            &created,
        )
        .expect("resolved");
        assert_eq!(data["members"][0]["value"], "0193-a");
        assert_eq!(data["displayName"], "bulkId is a word");
        assert!(resolve_path("/Users/bulkId:later", &created).is_err());
        assert!(check_bulk_id("ana-1").is_ok());
        assert!(check_bulk_id("has space").is_err());
        assert!(check_bulk_id("").is_err());
    }
}
