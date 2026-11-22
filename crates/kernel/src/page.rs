//! Cursor pagination, the only pagination style the APIs offer.

/// Opaque position in a result set. Its contents are an implementation
/// detail of the repository that produced it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cursor(String);

impl Cursor {
    /// Wraps an encoded cursor.
    #[must_use]
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    /// The encoded cursor.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A request for one page of results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PageRequest {
    limit: u32,
    cursor: Option<Cursor>,
}

impl PageRequest {
    /// Page size used when the caller does not ask for one.
    pub const DEFAULT_LIMIT: u32 = 50;
    /// Largest page size a caller can ask for.
    pub const MAX_LIMIT: u32 = 200;

    /// Creates a request. A missing limit becomes the default; a limit
    /// outside `1..=MAX_LIMIT` is clamped rather than rejected.
    #[must_use]
    pub fn new(limit: Option<u32>, cursor: Option<Cursor>) -> Self {
        Self {
            limit: limit
                .unwrap_or(Self::DEFAULT_LIMIT)
                .clamp(1, Self::MAX_LIMIT),
            cursor,
        }
    }

    /// Number of items to return.
    #[must_use]
    pub const fn limit(&self) -> u32 {
        self.limit
    }

    /// Where to resume, if this is not the first page.
    #[must_use]
    pub const fn cursor(&self) -> Option<&Cursor> {
        self.cursor.as_ref()
    }
}

impl Default for PageRequest {
    fn default() -> Self {
        Self::new(None, None)
    }
}

/// One page of results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Page<T> {
    /// The items, in the order of the query.
    pub items: Vec<T>,
    /// Present when more results exist.
    pub next_cursor: Option<Cursor>,
}

impl<T> Page<T> {
    /// Converts the items, keeping the cursor.
    #[must_use]
    pub fn map<U>(self, f: impl FnMut(T) -> U) -> Page<U> {
        Page {
            items: self.items.into_iter().map(f).collect(),
            next_cursor: self.next_cursor,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_limit_uses_the_default() {
        assert_eq!(PageRequest::default().limit(), PageRequest::DEFAULT_LIMIT);
    }

    #[test]
    fn limits_are_clamped() {
        assert_eq!(PageRequest::new(Some(0), None).limit(), 1);
        assert_eq!(
            PageRequest::new(Some(10_000), None).limit(),
            PageRequest::MAX_LIMIT
        );
        assert_eq!(PageRequest::new(Some(25), None).limit(), 25);
    }

    #[test]
    fn map_keeps_the_cursor() {
        let page = Page {
            items: vec![1, 2],
            next_cursor: Some(Cursor::new("abc")),
        };
        let mapped = page.map(|n| n.to_string());
        assert_eq!(mapped.items, ["1", "2"]);
        assert_eq!(mapped.next_cursor.as_ref().map(Cursor::as_str), Some("abc"));
    }
}
