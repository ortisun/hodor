//! Path patterns of route rules, and the paths they are matched against.
//!
//! Specified in `docs/operations/hodor-ext-authz.md`, "Route rules".

/// One segment of a pattern.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Segment {
    /// Matches exactly this text.
    Literal(String),
    /// `{id}`: any one segment, which becomes the resource's identifier.
    Id,
    /// `*`: any one segment.
    Any,
    /// `**`, last only: any number of segments, none included.
    Rest,
}

/// A path pattern: `/`, then segments separated by `/`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPattern {
    segments: Vec<Segment>,
}

impl PathPattern {
    /// Reads a pattern.
    ///
    /// # Errors
    ///
    /// Says why the pattern cannot be read.
    pub fn parse(text: &str) -> Result<Self, String> {
        let Some(rest) = text.strip_prefix('/') else {
            return Err("a path starts with /".to_owned());
        };
        let parts: Vec<&str> = rest.split('/').collect();
        let mut segments = Vec::with_capacity(parts.len());
        let mut identifiers = 0;
        for (index, part) in parts.iter().enumerate() {
            let segment = match *part {
                "{id}" => {
                    identifiers += 1;
                    Segment::Id
                }
                "*" => Segment::Any,
                "**" if index + 1 == parts.len() => Segment::Rest,
                "**" => return Err("a path holds ** as its last segment only".to_owned()),
                literal if literal.contains(['{', '}', '*', '?', '#']) => {
                    return Err(format!(
                        "a path segment is a literal, {{id}}, * or **, not `{literal}`"
                    ));
                }
                literal => Segment::Literal(literal.to_owned()),
            };
            segments.push(segment);
        }
        if identifiers > 1 {
            return Err("a path holds {id} at most once".to_owned());
        }
        Ok(Self { segments })
    }

    /// Whether `path`'s segments match, and the identifier `{id}` took if
    /// any: `None` when they do not match, `Some(None)` when they match
    /// without an identifier.
    #[must_use]
    pub fn matches(&self, path: &[&str]) -> Option<Option<String>> {
        let mut identifier = None;
        for (index, segment) in self.segments.iter().enumerate() {
            match segment {
                Segment::Rest => return Some(identifier),
                Segment::Literal(literal) => {
                    if path.get(index) != Some(&literal.as_str()) {
                        return None;
                    }
                }
                Segment::Any => {
                    path.get(index)?;
                }
                Segment::Id => {
                    let value = path.get(index)?;
                    if value.is_empty() {
                        return None;
                    }
                    identifier = Some((*value).to_owned());
                }
            }
        }
        (path.len() == self.segments.len()).then_some(identifier)
    }
}

/// The segments of a request's path, without its query or fragment, or
/// `None` when the path is refused before any rule is tried: it does not
/// start with `/`, or a segment is `.` or `..`, written plainly or
/// percent-encoded, or holds an encoded `/` or `\`, or a `\`.
#[must_use]
pub fn segments(path: &str) -> Option<Vec<&str>> {
    let path = path.split(['?', '#']).next().unwrap_or_default();
    let rest = path.strip_prefix('/')?;
    let segments: Vec<&str> = rest.split('/').collect();
    for segment in &segments {
        let lowered = segment.to_ascii_lowercase();
        let dots = lowered.replace("%2e", ".");
        if dots == "."
            || dots == ".."
            || lowered.contains("%2f")
            || lowered.contains("%5c")
            || segment.contains('\\')
        {
            return None;
        }
    }
    Some(segments)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn matched(pattern: &str, path: &str) -> Option<Option<String>> {
        PathPattern::parse(pattern)
            .expect("pattern")
            .matches(&segments(path).expect("path"))
    }

    #[test]
    fn literals_compare_segment_by_segment_exactly() {
        assert_eq!(matched("/orders", "/orders"), Some(None));
        assert_eq!(matched("/orders", "/orders?page=2"), Some(None));
        assert_eq!(matched("/orders", "/orders/"), None);
        assert_eq!(matched("/orders/", "/orders/"), Some(None));
        assert_eq!(matched("/orders", "/Orders"), None);
        assert_eq!(matched("/orders", "/orders/1"), None);
        assert_eq!(matched("/", "/"), Some(None));
        assert_eq!(matched("/", "/orders"), None);
    }

    #[test]
    fn the_identifier_is_taken_from_its_segment() {
        assert_eq!(
            matched("/orders/{id}/approve", "/orders/42/approve"),
            Some(Some("42".to_owned()))
        );
        assert_eq!(matched("/orders/{id}", "/orders/"), None);
        assert_eq!(matched("/orders/{id}", "/orders"), None);
        assert_eq!(matched("/orders/{id}", "/orders/42/approve"), None);
    }

    #[test]
    fn wildcards_match_one_segment_or_the_rest() {
        assert_eq!(matched("/*/orders", "/v1/orders"), Some(None));
        assert_eq!(matched("/*/orders", "/orders"), None);
        assert_eq!(matched("/static/**", "/static"), Some(None));
        assert_eq!(matched("/static/**", "/static/css/site.css"), Some(None));
        assert_eq!(
            matched("/orders/{id}/**", "/orders/7/lines/2"),
            Some(Some("7".to_owned()))
        );
        assert_eq!(matched("/static/**", "/other/css"), None);
    }

    #[test]
    fn a_pattern_that_cannot_be_read_is_refused() {
        for wrong in [
            "",
            "orders",
            "/**/orders",
            "/{id}/{id}",
            "/{identifier}",
            "/order*",
            "/a?b",
        ] {
            assert!(PathPattern::parse(wrong).is_err(), "{wrong}");
        }
    }

    #[test]
    fn a_path_with_dot_segments_or_encoded_separators_is_refused() {
        for refused in [
            "orders",
            "/orders/../admin",
            "/orders/./1",
            "/orders/%2e%2e/admin",
            "/orders/.%2E/admin",
            "/orders/a%2Fb",
            "/orders/a%5cb",
            "/orders/a\\b",
        ] {
            assert_eq!(segments(refused), None, "{refused}");
        }
        assert_eq!(segments("/orders/a.b"), Some(vec!["orders", "a.b"]));
    }
}
