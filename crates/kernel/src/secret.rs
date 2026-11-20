//! Wrapper for values that must never be logged or serialized.

use std::fmt;
use zeroize::Zeroize;

/// A secret value: a password, token, key or similar.
///
/// `Secret` has a redacted `Debug`, no `Display` and no `Serialize`, and its
/// contents are zeroized when dropped. Reading the value requires an explicit
/// call to [`Secret::expose`], which makes every use easy to find in review.
pub struct Secret<T: Zeroize>(T);

impl<T: Zeroize> Secret<T> {
    /// Wraps a secret value.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }

    /// Returns the secret. Do not log, format or store the result in a type
    /// that can be logged.
    #[must_use]
    pub const fn expose(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize + Clone> Clone for Secret<T> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

impl<T: Zeroize> fmt::Debug for Secret<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([REDACTED])")
    }
}

impl<T: Zeroize> Drop for Secret<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl From<String> for Secret<String> {
    fn from(value: String) -> Self {
        Self::new(value)
    }
}

impl From<Vec<u8>> for Secret<Vec<u8>> {
    fn from(value: Vec<u8>) -> Self {
        Self::new(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug)]
    #[allow(dead_code)]
    struct Login {
        username: String,
        password: Secret<String>,
    }

    #[test]
    fn debug_output_never_contains_the_value() {
        let login = Login {
            username: "ana".to_owned(),
            password: Secret::from("correct horse battery staple".to_owned()),
        };
        let printed = format!("{login:?} {login:#?}");
        assert!(printed.contains("ana"));
        assert!(printed.contains("[REDACTED]"));
        assert!(!printed.contains("correct horse"));
    }

    #[test]
    fn expose_returns_the_value() {
        let secret = Secret::from(vec![1_u8, 2, 3]);
        assert_eq!(secret.expose(), &[1, 2, 3]);
    }
}
