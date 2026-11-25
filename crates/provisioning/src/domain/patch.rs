//! `PATCH` of a resource (RFC 7644, section 3.5.2): reading the operations
//! and applying them, in order, to the resource as SCIM writes it.
//!
//! Specified in `docs/architecture/contexts/provisioning.md`, "Changing
//! with `PATCH`". The result is read again as the body of a `PUT` would be,
//! so every rule of a replacement holds for it; this module only moves
//! JSON values.

use crate::domain::error::invalid_filter;
use crate::domain::error::{
    MUTABILITY, invalid_path, invalid_syntax, invalid_value, no_target, too_many,
};
use crate::domain::filter::{ElementFilter, FilterRefusal, parse_element_filter};
use hodor_kernel::DomainError;
use serde_json::{Map, Value};

/// The URI of a `PATCH` body.
pub const PATCH_SCHEMA: &str = "urn:ietf:params:scim:api:messages:2.0:PatchOp";
/// The most operations of one `PATCH`.
pub const MAX_PATCH_OPERATIONS: usize = 100;
/// The most characters of a path.
pub const MAX_PATH_CHARACTERS: usize = 1000;

/// What an operation does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PatchOp {
    /// `add`.
    Add,
    /// `remove`.
    Remove,
    /// `replace`.
    Replace,
}

/// Where an operation applies: an attribute, in the resource or in an
/// extension, the values of it a filter selects, and a sub-attribute.
#[derive(Debug, Clone, PartialEq)]
pub struct PatchPath {
    /// The extension the attribute is in, by its URI; `None` for the core
    /// schema.
    pub extension: Option<&'static str>,
    /// The attribute, as written.
    pub attribute: String,
    /// The value filter, when the path has one.
    pub filter: Option<ElementFilter>,
    /// The sub-attribute, when the path names one.
    pub sub: Option<String>,
}

/// One operation of a `PATCH`.
#[derive(Debug, Clone, PartialEq)]
pub struct PatchOperation {
    /// What it does.
    pub op: PatchOp,
    /// Where; `None` for an operation on the whole resource.
    pub path: Option<PatchPath>,
    /// The value it sets or, for `remove`, the values it takes out.
    pub value: Option<Value>,
}

/// A `PATCH` request, read and checked.
#[derive(Debug, Clone, PartialEq)]
pub struct PatchRequest {
    /// The operations, in order.
    pub operations: Vec<PatchOperation>,
}

/// The attributes of a resource a `PATCH` needs to know of: what it may
/// not change, and what holds several values.
#[derive(Debug, Clone, Copy)]
pub struct Shape {
    /// The URI of the resource's core schema, which may be written before
    /// an attribute.
    pub core: &'static str,
    /// The URIs of the extensions whose attributes a path may name.
    pub extensions: &'static [&'static str],
    /// The read-only attributes.
    pub read_only: &'static [&'static str],
    /// The multi-valued attributes.
    pub multi_valued: &'static [&'static str],
}

fn field<'a>(object: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    object
        .iter()
        .find(|(key, _)| key.eq_ignore_ascii_case(name))
        .map(|(_, value)| value)
}

fn key_of(object: &Map<String, Value>, name: &str) -> String {
    object
        .keys()
        .find(|key| key.eq_ignore_ascii_case(name))
        .cloned()
        .unwrap_or_else(|| name.to_owned())
}

fn is_name(text: &str) -> bool {
    let mut characters = text.chars();
    characters
        .next()
        .is_some_and(|first| first.is_ascii_alphabetic() || first == '$')
        && characters.all(|next| next.is_ascii_alphanumeric() || matches!(next, '_' | '-' | '$'))
}

fn filter_refused(refusal: &FilterRefusal) -> DomainError {
    invalid_filter(refusal)
}

/// Reads a path of a `PATCH`.
///
/// # Errors
///
/// `provisioning.invalid_path` for a path that cannot be read, and
/// `provisioning.invalid_filter` for a value filter that cannot be read.
pub fn read_path(text: &str, shape: &Shape) -> Result<PatchPath, DomainError> {
    if text.chars().count() > MAX_PATH_CHARACTERS {
        return Err(invalid_path(format!(
            "a path holds at most {MAX_PATH_CHARACTERS} characters"
        )));
    }
    let lowered = text.to_ascii_lowercase();
    let mut extension = None;
    let mut rest = text;
    if lowered.starts_with("urn:") {
        let core = format!("{}:", shape.core.to_ascii_lowercase());
        if let Some(found) = shape
            .extensions
            .iter()
            .copied()
            .find(|known| lowered == known.to_ascii_lowercase())
        {
            return Ok(PatchPath {
                extension: None,
                attribute: found.to_owned(),
                filter: None,
                sub: None,
            });
        }
        if lowered.starts_with(&core) {
            rest = &text[core.len()..];
        } else if let Some(found) = shape
            .extensions
            .iter()
            .copied()
            .find(|known| lowered.starts_with(&format!("{}:", known.to_ascii_lowercase())))
        {
            extension = Some(found);
            rest = &text[found.len() + 1..];
        } else {
            return Err(invalid_path(format!(
                "the path {text} names no schema of this resource"
            )));
        }
    }
    let end = rest.find(['[', '.']).unwrap_or(rest.len());
    let attribute = &rest[..end];
    if !is_name(attribute) {
        return Err(invalid_path(format!("the path {text} cannot be read")));
    }
    let mut after = &rest[end..];
    let mut filter = None;
    if let Some(inside) = after.strip_prefix('[') {
        let mut quoted = false;
        let mut escaped = false;
        let mut close = None;
        for (at, character) in inside.char_indices() {
            match character {
                _ if escaped => escaped = false,
                '\\' if quoted => escaped = true,
                '"' => quoted = !quoted,
                ']' if !quoted => {
                    close = Some(at);
                    break;
                }
                _ => {}
            }
        }
        let close = close.ok_or_else(|| invalid_path(format!("the path {text} cannot be read")))?;
        filter = Some(
            parse_element_filter(&inside[..close]).map_err(|refusal| filter_refused(&refusal))?,
        );
        after = &inside[close + 1..];
    }
    let sub = match after.strip_prefix('.') {
        Some(sub) if is_name(sub) => Some(sub.to_owned()),
        Some(_) => return Err(invalid_path(format!("the path {text} cannot be read"))),
        None if after.is_empty() => None,
        None => return Err(invalid_path(format!("the path {text} cannot be read"))),
    };
    Ok(PatchPath {
        extension,
        attribute: attribute.to_owned(),
        filter,
        sub,
    })
}

/// Reads the body of a `PATCH`.
///
/// # Errors
///
/// `provisioning.invalid_syntax` for a body that is not a `PatchOp`,
/// `provisioning.too_many` past [`MAX_PATCH_OPERATIONS`],
/// `provisioning.invalid_value` for an operation that cannot be one, and
/// the refusals of [`read_path`].
pub fn read_patch(body: &Value, shape: &Shape) -> Result<PatchRequest, DomainError> {
    let object = body
        .as_object()
        .ok_or_else(|| invalid_syntax("the body is not a JSON object"))?;
    let named = field(object, "schemas")
        .and_then(Value::as_array)
        .is_some_and(|schemas| {
            schemas.iter().any(|schema| {
                schema
                    .as_str()
                    .is_some_and(|schema| schema.eq_ignore_ascii_case(PATCH_SCHEMA))
            })
        });
    if !named {
        return Err(invalid_syntax(format!("schemas names {PATCH_SCHEMA}")));
    }
    let listed = field(object, "Operations")
        .and_then(Value::as_array)
        .ok_or_else(|| invalid_syntax("Operations is a list of operations"))?;
    if listed.is_empty() {
        return Err(invalid_value("a PATCH holds at least one operation"));
    }
    if listed.len() > MAX_PATCH_OPERATIONS {
        return Err(too_many(format!(
            "a PATCH holds at most {MAX_PATCH_OPERATIONS} operations"
        )));
    }
    let mut operations = Vec::with_capacity(listed.len());
    for operation in listed {
        let operation = operation
            .as_object()
            .ok_or_else(|| invalid_value("an operation is an object"))?;
        let op = match field(operation, "op").and_then(Value::as_str) {
            Some(op) if op.eq_ignore_ascii_case("add") => PatchOp::Add,
            Some(op) if op.eq_ignore_ascii_case("remove") => PatchOp::Remove,
            Some(op) if op.eq_ignore_ascii_case("replace") => PatchOp::Replace,
            _ => return Err(invalid_value("an operation's op is add, remove or replace")),
        };
        let path = match field(operation, "path") {
            None | Some(Value::Null) => None,
            Some(Value::String(path)) => Some(read_path(path, shape)?),
            Some(_) => return Err(invalid_path("a path is a string")),
        };
        let value = field(operation, "value")
            .filter(|value| !value.is_null())
            .cloned();
        if op == PatchOp::Remove && path.is_none() {
            return Err(no_target("remove names a path"));
        }
        if op != PatchOp::Remove && value.is_none() {
            return Err(invalid_value("add and replace give a value"));
        }
        operations.push(PatchOperation { op, path, value });
    }
    Ok(PatchRequest { operations })
}

impl PatchRequest {
    /// How many values the operations give for `attribute`, at the top of
    /// the resource or in a value without a path: what the bound on a
    /// group's members counts.
    #[must_use]
    pub fn values_named(&self, attribute: &str) -> usize {
        let count = |value: &Value| match value {
            Value::Array(items) => items.len(),
            _ => 1,
        };
        self.operations
            .iter()
            .map(|operation| match (&operation.path, &operation.value) {
                (Some(path), Some(value))
                    if path.extension.is_none()
                        && path.attribute.eq_ignore_ascii_case(attribute) =>
                {
                    count(value)
                }
                (None, Some(Value::Object(object))) => field(object, attribute).map_or(0, count),
                _ => 0,
            })
            .sum()
    }
}

fn values_of(value: &Value) -> Vec<Value> {
    match value {
        Value::Array(items) => items.clone(),
        other => vec![other.clone()],
    }
}

/// Merges the sub-attributes of `value` into `into`.
fn merge(into: &mut Map<String, Value>, value: &Map<String, Value>) {
    for (key, given) in value {
        let key = key_of(into, key);
        if given.is_null() {
            into.remove(&key);
        } else {
            into.insert(key, given.clone());
        }
    }
}

/// After values of a multi-valued attribute were set, at most one stays
/// primary: the last one set primary (RFC 7644, section 3.5.2).
fn one_primary(items: &mut [Value], touched: &[usize]) {
    let chosen = touched.iter().rev().copied().find(|index| {
        items[*index]
            .as_object()
            .and_then(|item| field(item, "primary"))
            .is_some_and(|primary| primary == &Value::Bool(true))
    });
    if let Some(chosen) = chosen {
        for (index, item) in items.iter_mut().enumerate() {
            if index != chosen
                && let Some(item) = item.as_object_mut()
            {
                let key = key_of(item, "primary");
                if item.contains_key(&key) {
                    item.insert(key, Value::Bool(false));
                }
            }
        }
    }
}

/// The value of `remove`'s `value` that names `item`: equal, or with the
/// same `value` sub-attribute, compared without regard to case.
fn names(given: &Value, item: &Value) -> bool {
    let value_of = |value: &Value| {
        value
            .as_object()
            .and_then(|object| field(object, "value"))
            .and_then(Value::as_str)
            .map(str::to_ascii_lowercase)
    };
    given == item || (value_of(given).is_some() && value_of(given) == value_of(item))
}

struct Applying<'a> {
    shape: &'a Shape,
}

impl Applying<'_> {
    fn multi_valued(
        &self,
        attribute: &str,
        current: Option<&Value>,
        value: Option<&Value>,
    ) -> bool {
        self.shape
            .multi_valued
            .iter()
            .any(|known| known.eq_ignore_ascii_case(attribute))
            || matches!(current, Some(Value::Array(_)))
            || matches!(value, Some(Value::Array(_)))
    }

    fn container<'d>(
        document: &'d mut Map<String, Value>,
        path: &PatchPath,
    ) -> Result<&'d mut Map<String, Value>, DomainError> {
        let Some(extension) = path.extension else {
            return Ok(document);
        };
        let key = key_of(document, extension);
        let entry = document
            .entry(key)
            .or_insert_with(|| Value::Object(Map::new()));
        if entry.is_null() {
            *entry = Value::Object(Map::new());
        }
        entry
            .as_object_mut()
            .ok_or_else(|| invalid_value(format!("{extension} is an object")))
    }

    fn apply(
        &self,
        document: &mut Map<String, Value>,
        op: PatchOp,
        path: &PatchPath,
        value: Option<&Value>,
    ) -> Result<(), DomainError> {
        if path.extension.is_none()
            && (self
                .shape
                .read_only
                .iter()
                .any(|known| known.eq_ignore_ascii_case(&path.attribute))
                || path.attribute.eq_ignore_ascii_case("schemas"))
        {
            return Err(DomainError::invalid(
                MUTABILITY,
                format!("{} is read only", path.attribute),
            ));
        }
        let container = Self::container(document, path)?;
        let key = key_of(container, &path.attribute);
        let multi = self.multi_valued(&path.attribute, container.get(&key), value);
        match (&path.filter, &path.sub) {
            (None, None) => self.on_attribute(container, &key, multi, op, value),
            (None, Some(sub)) => {
                if multi {
                    return Err(invalid_path(format!(
                        "a sub-attribute of {} is named with a value filter",
                        path.attribute
                    )));
                }
                let entry = container
                    .entry(key.clone())
                    .or_insert_with(|| Value::Object(Map::new()));
                if entry.is_null() {
                    *entry = Value::Object(Map::new());
                }
                let object = entry
                    .as_object_mut()
                    .ok_or_else(|| invalid_value(format!("{key} is an object")))?;
                let sub_key = key_of(object, sub);
                match (op, value) {
                    (PatchOp::Remove, _) | (_, None | Some(Value::Null)) => {
                        object.remove(&sub_key);
                    }
                    (_, Some(value)) => {
                        object.insert(sub_key, value.clone());
                    }
                }
                Ok(())
            }
            (Some(filter), sub) => {
                self.on_selected(container, &key, filter, sub.as_deref(), op, value)
            }
        }
    }

    fn on_attribute(
        &self,
        container: &mut Map<String, Value>,
        key: &str,
        multi: bool,
        op: PatchOp,
        value: Option<&Value>,
    ) -> Result<(), DomainError> {
        match op {
            PatchOp::Remove => {
                match (value, multi, container.get_mut(key)) {
                    (Some(given), true, Some(Value::Array(items))) => {
                        let given = values_of(given);
                        items.retain(|item| !given.iter().any(|named| names(named, item)));
                    }
                    _ => {
                        container.remove(key);
                    }
                }
                Ok(())
            }
            PatchOp::Add | PatchOp::Replace => {
                let Some(value) = value else {
                    return Ok(());
                };
                if multi {
                    let mut items = match (op, container.remove(key)) {
                        (PatchOp::Add, Some(Value::Array(items))) => items,
                        _ => Vec::new(),
                    };
                    let start = items.len();
                    items.extend(values_of(value));
                    let touched: Vec<usize> = (start..items.len()).collect();
                    one_primary(&mut items, &touched);
                    container.insert(key.to_owned(), Value::Array(items));
                    return Ok(());
                }
                match (container.get_mut(key), value) {
                    (Some(Value::Object(current)), Value::Object(given)) => merge(current, given),
                    _ => {
                        container.insert(key.to_owned(), value.clone());
                    }
                }
                Ok(())
            }
        }
    }

    fn on_selected(
        &self,
        container: &mut Map<String, Value>,
        key: &str,
        filter: &ElementFilter,
        sub: Option<&str>,
        op: PatchOp,
        value: Option<&Value>,
    ) -> Result<(), DomainError> {
        let entry = container
            .entry(key.to_owned())
            .or_insert_with(|| Value::Array(Vec::new()));
        if entry.is_null() {
            *entry = Value::Array(Vec::new());
        }
        let items = entry.as_array_mut().ok_or_else(|| {
            invalid_path(format!("{key} holds one value and takes no value filter"))
        })?;
        let selected = |item: &Value| item.as_object().is_some_and(|item| filter.matches(item));
        if op == PatchOp::Remove {
            match sub {
                None => items.retain(|item| !selected(item)),
                Some(sub) => {
                    for item in items.iter_mut().filter(|item| selected(item)) {
                        if let Some(item) = item.as_object_mut() {
                            let sub_key = key_of(item, sub);
                            item.remove(&sub_key);
                        }
                    }
                }
            }
            return Ok(());
        }
        let Some(value) = value else {
            return Ok(());
        };
        let mut touched: Vec<usize> = items
            .iter()
            .enumerate()
            .filter(|(_, item)| selected(item))
            .map(|(index, _)| index)
            .collect();
        if touched.is_empty() {
            let made = filter
                .equalities()
                .ok_or_else(|| no_target(format!("the value filter of {key} selects nothing")))?;
            items.push(Value::Object(made.into_iter().collect()));
            touched.push(items.len() - 1);
        }
        for index in &touched {
            let Some(item) = items[*index].as_object_mut() else {
                continue;
            };
            match (sub, value) {
                (Some(sub), value) => {
                    let sub_key = key_of(item, sub);
                    item.insert(sub_key, value.clone());
                }
                (None, Value::Object(given)) => merge(item, given),
                (None, _) => {
                    return Err(invalid_value(format!(
                        "the values {key} selects are set from an object"
                    )));
                }
            }
        }
        one_primary(items, &touched);
        Ok(())
    }
}

/// Applies the operations of `request`, in order, to `document`, the
/// resource as SCIM writes it.
///
/// # Errors
///
/// `provisioning.mutability` for an operation on a read-only attribute,
/// `provisioning.no_target` for a value filter that selects nothing and
/// makes nothing, `provisioning.invalid_path` and
/// `provisioning.invalid_value` for an operation that cannot apply.
pub fn apply_patch(
    document: &mut Map<String, Value>,
    request: &PatchRequest,
    shape: &Shape,
) -> Result<(), DomainError> {
    let applying = Applying { shape };
    for operation in &request.operations {
        match &operation.path {
            Some(path) => applying.apply(document, operation.op, path, operation.value.as_ref())?,
            None => {
                let Some(Value::Object(given)) = &operation.value else {
                    return Err(invalid_value(
                        "an operation without a path gives an object as its value",
                    ));
                };
                for (attribute, value) in given {
                    let path = read_path(attribute, shape)?;
                    applying.apply(document, operation.op, &path, Some(value))?;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    const SHAPE: Shape = Shape {
        core: "urn:ietf:params:scim:schemas:core:2.0:User",
        extensions: &["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"],
        read_only: &["id", "meta", "groups"],
        multi_valued: &["emails"],
    };

    fn patched(document: Value, operations: Value) -> Result<Value, DomainError> {
        let request = read_patch(
            &json!({ "schemas": [PATCH_SCHEMA], "Operations": operations }),
            &SHAPE,
        )?;
        let mut document = document.as_object().cloned().expect("an object");
        apply_patch(&mut document, &request, &SHAPE)?;
        Ok(Value::Object(document))
    }

    fn ana() -> Value {
        json!({
            "userName": "ana",
            "name": { "givenName": "Ana", "familyName": "Silva" },
            "emails": [
                { "value": "ana@example.com", "type": "work", "primary": true },
                { "value": "ana@home.org", "type": "home" }
            ],
            "active": true
        })
    }

    #[test]
    fn a_value_filter_selects_the_values_an_operation_changes() {
        let result = patched(
            ana(),
            json!([{ "op": "Replace", "path": "emails[type eq \"work\"].value", "value": "ana.silva@example.com" }]),
        )
        .expect("patched");
        assert_eq!(result["emails"][0]["value"], "ana.silva@example.com");
        assert_eq!(result["emails"][0]["type"], "work");
        assert_eq!(result["emails"][1]["value"], "ana@home.org");

        let result = patched(
            ana(),
            json!([{ "op": "remove", "path": "emails[type eq \"home\"]" }]),
        )
        .expect("patched");
        assert_eq!(result["emails"].as_array().map(Vec::len), Some(1));
        let again = patched(
            ana(),
            json!([{ "op": "remove", "path": "emails[type eq \"other\"]" }]),
        )
        .expect("nothing selected, nothing removed");
        assert_eq!(again, ana());
    }

    #[test]
    fn a_filter_of_equalities_that_selects_nothing_makes_a_value() {
        let result = patched(
            ana(),
            json!([{ "op": "add", "path": "emails[type eq \"other\"].value", "value": "ana@other.net" }]),
        )
        .expect("patched");
        assert_eq!(
            result["emails"][2],
            json!({ "type": "other", "value": "ana@other.net" })
        );
        let refused = patched(
            ana(),
            json!([{ "op": "replace", "path": "emails[value co \"nowhere\"].type", "value": "work" }]),
        )
        .expect_err("nothing to make");
        assert_eq!(refused.code(), "provisioning.no_target");
    }

    #[test]
    fn operations_without_a_path_apply_each_attribute_and_one_value_stays_primary() {
        let result = patched(
            ana(),
            json!([
                { "op": "replace", "value": { "active": false, "name": { "givenName": "Ana Maria" } } },
                { "op": "add", "value": { "emails": [{ "value": "a@b.org", "primary": true }] } },
                { "op": "add", "path": "urn:ietf:params:scim:schemas:extension:enterprise:2.0:User:department", "value": "Sales" },
                { "op": "remove", "path": "name.familyName" }
            ]),
        )
        .expect("patched");
        assert_eq!(result["active"], false);
        assert_eq!(result["name"], json!({ "givenName": "Ana Maria" }));
        assert_eq!(result["emails"][0]["primary"], false);
        assert_eq!(result["emails"][2]["primary"], true);
        assert_eq!(
            result["urn:ietf:params:scim:schemas:extension:enterprise:2.0:User"]["department"],
            "Sales"
        );
    }

    #[test]
    fn remove_with_values_takes_out_only_those() {
        let result = patched(
            ana(),
            json!([{ "op": "remove", "path": "emails", "value": [{ "value": "ANA@home.org" }] }]),
        )
        .expect("patched");
        assert_eq!(result["emails"].as_array().map(Vec::len), Some(1));
    }

    #[test]
    fn what_cannot_be_read_or_changed_is_refused_with_its_code() {
        let code = |operations: Value| {
            patched(ana(), operations)
                .expect_err("refused")
                .code()
                .to_owned()
        };
        assert_eq!(
            code(json!([{ "op": "replace", "path": "id", "value": "x" }])),
            MUTABILITY
        );
        assert_eq!(
            code(json!([{ "op": "add", "path": "groups", "value": [] }])),
            MUTABILITY
        );
        assert_eq!(code(json!([{ "op": "remove" }])), "provisioning.no_target");
        assert_eq!(
            code(json!([{ "op": "move", "path": "active", "value": 1 }])),
            "provisioning.invalid_value"
        );
        assert_eq!(
            code(json!([{ "op": "add", "path": "emails[", "value": 1 }])),
            "provisioning.invalid_path"
        );
        assert_eq!(
            code(json!([{ "op": "add", "path": "emails[type xx \"a\"]", "value": 1 }])),
            "provisioning.invalid_filter"
        );
        assert_eq!(
            code(json!([{ "op": "add", "path": "urn:example:other:x", "value": 1 }])),
            "provisioning.invalid_path"
        );
        assert_eq!(code(json!([])), "provisioning.invalid_value");
        let many: Vec<Value> = (0..=MAX_PATCH_OPERATIONS)
            .map(|_| json!({ "op": "replace", "path": "active", "value": true }))
            .collect();
        assert_eq!(code(Value::Array(many)), "provisioning.too_many");
    }
}
