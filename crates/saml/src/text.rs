//! Writing text into XML.

/// Escapes text for an attribute value or element content.
pub(crate) fn escape(text: &str) -> String {
    let mut escaped = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&apos;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// An instant as SAML writes it: UTC, to the second.
pub(crate) fn instant(at: time::OffsetDateTime) -> String {
    let at = at.to_offset(time::UtcOffset::UTC);
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        at.year(),
        u8::from(at.month()),
        at.day(),
        at.hour(),
        at.minute(),
        at.second()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn markup_is_escaped() {
        assert_eq!(
            escape(r#"a&b<c>"d"'e'"#),
            "a&amp;b&lt;c&gt;&quot;d&quot;&apos;e&apos;"
        );
    }

    #[test]
    fn instants_are_written_in_utc_to_the_second() {
        let at = time::OffsetDateTime::from_unix_timestamp(1_795_000_000)
            .expect("a valid timestamp")
            .to_offset(time::UtcOffset::from_hms(-3, 0, 0).expect("a valid offset"));
        assert_eq!(instant(at), "2026-11-18T11:06:40Z");
    }
}
