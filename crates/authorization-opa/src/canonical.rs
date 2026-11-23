//! JSON in the canonical form Open Policy Agent hashes it in.
//!
//! Open Policy Agent checks the signature of a bundle's JSON files over
//! their contents written again in one form: object keys sorted by their
//! bytes, no space, numbers as written, strings escaped as Go escapes them
//! without escaping HTML. Hodor writes the files in that form, so their
//! bytes and the form hashed are the same.

use serde_json::Value;
use std::fmt::Write as _;

/// `value` in the canonical form.
#[must_use]
pub fn to_canonical(value: &Value) -> String {
    let mut out = String::new();
    write_value(value, &mut out);
    out
}

fn write_value(value: &Value, out: &mut String) {
    match value {
        Value::Null => out.push_str("null"),
        Value::Bool(true) => out.push_str("true"),
        Value::Bool(false) => out.push_str("false"),
        Value::Number(number) => out.push_str(&number.to_string()),
        Value::String(text) => write_string(text, out),
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_value(item, out);
            }
            out.push(']');
        }
        Value::Object(members) => {
            let mut keys: Vec<&String> = members.keys().collect();
            keys.sort_by(|a, b| a.as_bytes().cmp(b.as_bytes()));
            out.push('{');
            for (index, key) in keys.into_iter().enumerate() {
                if index > 0 {
                    out.push(',');
                }
                write_string(key, out);
                out.push(':');
                write_value(&members[key], out);
            }
            out.push('}');
        }
    }
}

/// A string as Go's encoder writes it with HTML escaping turned off.
fn write_string(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{8}' => out.push_str("\\b"),
            '\u{c}' => out.push_str("\\f"),
            '\u{2028}' => out.push_str("\\u2028"),
            '\u{2029}' => out.push_str("\\u2029"),
            control if u32::from(control) < 0x20 => {
                // Writing to a `String` cannot fail.
                let _ = write!(out, "\\u{:04x}", u32::from(control));
            }
            other => out.push(other),
        }
    }
    out.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_are_sorted_and_nothing_is_spaced() {
        let value = json!({"b": [1, 2.5, "x"], "a": {"z": null, "y": true}, "B": false});
        assert_eq!(
            to_canonical(&value),
            r#"{"B":false,"a":{"y":true,"z":null},"b":[1,2.5,"x"]}"#
        );
    }

    #[test]
    fn strings_are_escaped_as_go_escapes_them_without_html() {
        let value = json!("<a href=\"x\">&\u{1}\u{8}\u{c}\n\r\t\\\u{2028}\u{e9}</a>");
        let expected = concat!(
            "\"<a href=\\\"x\\\">&",
            "\\u0001\\b\\f\\n\\r\\t\\\\\\u2028\u{e9}</a>\""
        );
        assert_eq!(to_canonical(&value), expected);
    }

    #[test]
    fn the_canonical_form_reads_back_as_the_same_value() {
        let value = json!({"numbers": [0, -3, 1.0e-7, 18446744073709551615_u64], "text": "ünï"});
        let written = to_canonical(&value);
        let read: Value = serde_json::from_str(&written).expect("json");
        assert_eq!(read, value);
        assert_eq!(to_canonical(&read), written);
    }
}
