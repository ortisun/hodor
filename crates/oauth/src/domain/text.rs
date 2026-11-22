//! Rules for the short texts of the context: names and scopes.

use hodor_kernel::DomainError;

/// The longest name of an application, a client or a resource server.
pub(crate) const MAX_NAME_LENGTH: usize = 100;
/// The longest scope, in characters.
pub const MAX_SCOPE_LENGTH: usize = 128;

/// A name shown to people: 1 to 100 characters without control
/// characters, with the spaces at either end removed.
///
/// # Errors
///
/// Returns `Invalid` with `code` otherwise.
pub(crate) fn name(value: &str, code: &'static str) -> Result<String, DomainError> {
    let value = value.trim();
    if value.is_empty()
        || value.chars().count() > MAX_NAME_LENGTH
        || value.chars().any(char::is_control)
    {
        return Err(DomainError::invalid(
            code,
            "a name is 1 to 100 characters without control characters",
        ));
    }
    Ok(value.to_owned())
}

/// Whether `value` is a scope as OAuth writes it (RFC 6749, section 3.3):
/// 1 to 128 printable ASCII characters other than a space, a double quote
/// and a backslash.
#[must_use]
pub fn is_scope(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_SCOPE_LENGTH
        && value
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_name_is_trimmed_and_held_to_its_length() {
        assert_eq!(name("  Payroll  ", "code").expect("valid"), "Payroll");
        assert!(name(&"é".repeat(100), "code").is_ok());
        for bad in ["", "   ", "two\nlines", "tab\there", &"x".repeat(101)] {
            assert_eq!(name(bad, "code").expect_err(bad).code(), "code");
        }
    }

    #[test]
    fn a_scope_is_written_as_oauth_writes_it() {
        for good in [
            "openid",
            "read:invoices",
            "https://api.example.com/read",
            "a",
        ] {
            assert!(is_scope(good), "{good}");
        }
        for bad in [
            "",
            "two words",
            "quote\"",
            "back\\slash",
            "tab\t",
            "não",
            &"x".repeat(129),
        ] {
            assert!(!is_scope(bad), "{bad}");
        }
        assert!(is_scope(&"x".repeat(128)));
    }
}
