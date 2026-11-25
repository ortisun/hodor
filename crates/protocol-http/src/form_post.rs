//! The page of the `form_post` response mode: a page of Hodor's own that
//! posts the answer of the authorization endpoint to the client's redirect
//! address as a form, and does nothing else (OAuth 2.0 Form Post Response
//! Mode).
//!
//! Specified in `docs/architecture/contexts/oauth.md`, "The page of
//! `form_post`".

use axum::http::StatusCode;
use axum::http::header::{self, HeaderValue};
use axum::response::{IntoResponse, Response};
use std::fmt::Write as _;

/// The one script of the page: it sends the form as the page loads.
pub(crate) const SUBMIT_SCRIPT: &str = "document.forms[0].submit();";

/// The content security policy of the page. Only the script whose SHA-256
/// is named runs; nothing loads; the page cannot be framed. `form-action`
/// is left out on purpose: browsers check it again at every redirect that
/// follows the post, which would refuse a client whose redirect address
/// sends the browser on to another of its origins.
pub(crate) const FORM_POST_CONTENT_SECURITY_POLICY: &str = "default-src 'none'; \
     script-src 'sha256-8lDeP0UDwCO6/RhblgeH/ctdBzjVpJxrXizsnIk3cEQ='; \
     base-uri 'none'; \
     frame-ancestors 'none'; \
     require-trusted-types-for 'script'; \
     trusted-types 'none'";

/// Writes `text` for an HTML attribute or text: `&`, `<`, `>`, `"` and `'`
/// as character references, every other character as it is.
fn escaped(text: &str) -> String {
    let mut written = String::with_capacity(text.len());
    for character in text.chars() {
        match character {
            '&' => written.push_str("&amp;"),
            '<' => written.push_str("&lt;"),
            '>' => written.push_str("&gt;"),
            '"' => written.push_str("&quot;"),
            '\'' => written.push_str("&#x27;"),
            other => written.push(other),
        }
    }
    written
}

/// The page that posts `parameters` to `uri`, with its headers: status
/// `200`, `Cache-Control: no-store`, `Pragma: no-cache`,
/// `Referrer-Policy: no-referrer` and its content security policy.
pub(crate) fn form_post_page(uri: &str, parameters: &[(&str, &str)]) -> Response {
    let mut fields = String::new();
    for (name, value) in parameters {
        // Writing to a `String` cannot fail.
        let _ = writeln!(
            fields,
            "<input type=\"hidden\" name=\"{}\" value=\"{}\">",
            escaped(name),
            escaped(value)
        );
    }
    let body = format!(
        "<!doctype html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n\
         <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
         <title>Going back to the application</title>\n</head>\n<body>\n\
         <form method=\"post\" action=\"{action}\">\n{fields}\
         <p>If you are not taken back to the application, continue.</p>\n\
         <button type=\"submit\">Continue</button>\n\
         </form>\n<script>{SUBMIT_SCRIPT}</script>\n</body>\n</html>\n",
        action = escaped(uri),
    );
    let mut response = (StatusCode::OK, body).into_response();
    let headers = response.headers_mut();
    headers.insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/html; charset=utf-8"),
    );
    headers.insert(
        header::CONTENT_SECURITY_POLICY,
        HeaderValue::from_static(FORM_POST_CONTENT_SECURITY_POLICY),
    );
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(header::PRAGMA, HeaderValue::from_static("no-cache"));
    headers.insert(
        header::REFERRER_POLICY,
        HeaderValue::from_static("no-referrer"),
    );
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine as _;
    use base64::engine::general_purpose::STANDARD;
    use hodor_kernel::Digest as _;
    use http_body_util::BodyExt as _;

    async fn page(uri: &str, parameters: &[(&str, &str)]) -> (Response, String) {
        let response = form_post_page(uri, parameters);
        let (parts, body) = response.into_parts();
        let bytes = body.collect().await.expect("body").to_bytes();
        (
            Response::from_parts(parts, axum::body::Body::empty()),
            String::from_utf8(bytes.to_vec()).expect("text"),
        )
    }

    #[test]
    fn the_policy_names_the_hash_of_the_script_and_nothing_else_runs() {
        let digest = hodor_adapters_crypto::Sha256Digest.sha256(SUBMIT_SCRIPT.as_bytes());
        let named = format!("script-src 'sha256-{}';", STANDARD.encode(digest));
        assert!(
            FORM_POST_CONTENT_SECURITY_POLICY.contains(&named),
            "{named}"
        );
        assert!(FORM_POST_CONTENT_SECURITY_POLICY.starts_with("default-src 'none';"));
        for loose in ["'self'", "'unsafe-inline'", "'unsafe-eval'", "http", "*"] {
            assert!(
                !FORM_POST_CONTENT_SECURITY_POLICY.contains(loose),
                "{loose}"
            );
        }
    }

    #[test]
    fn every_name_and_value_is_escaped() {
        assert_eq!(
            escaped(r#"a"b'c<d>e&f é"#),
            "a&quot;b&#x27;c&lt;d&gt;e&amp;f é"
        );
        assert_eq!(escaped("&amp;"), "&amp;amp;");
    }

    #[tokio::test]
    async fn the_page_posts_the_answer_and_nothing_else() {
        let (response, body) = page(
            "https://app.example.com/callback?tenant=a&x=\"1\"",
            &[
                ("code", "the-code"),
                ("state", "\"><script>alert(1)</script>"),
                ("iss", "https://hodor.example.com/t/acme"),
            ],
        )
        .await;
        assert_eq!(response.status(), StatusCode::OK);
        let headers = response.headers();
        assert_eq!(headers[header::CONTENT_TYPE], "text/html; charset=utf-8");
        assert_eq!(headers[header::CACHE_CONTROL], "no-store");
        assert_eq!(headers[header::PRAGMA], "no-cache");
        assert_eq!(headers[header::REFERRER_POLICY], "no-referrer");
        assert_eq!(
            headers[header::CONTENT_SECURITY_POLICY],
            FORM_POST_CONTENT_SECURITY_POLICY
        );

        assert!(body.contains(
            "<form method=\"post\" action=\"https://app.example.com/callback?tenant=a&amp;x=&quot;1&quot;\">"
        ));
        let fields: Vec<&str> = body
            .lines()
            .filter(|line| line.starts_with("<input"))
            .collect();
        assert_eq!(
            fields,
            [
                "<input type=\"hidden\" name=\"code\" value=\"the-code\">",
                "<input type=\"hidden\" name=\"state\" value=\"&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;\">",
                "<input type=\"hidden\" name=\"iss\" value=\"https://hodor.example.com/t/acme\">",
            ]
        );
        // One form, three fields, one script of Hodor's, a button without a
        // name, and nothing that loads anything.
        assert_eq!(body.matches("<form").count(), 1);
        assert_eq!(body.matches("<input").count(), 3);
        assert_eq!(body.matches("<button").count(), 1);
        assert_eq!(body.matches("<script").count(), 1);
        assert!(body.contains(&format!("<script>{SUBMIT_SCRIPT}</script>")));
        assert!(body.contains("<button type=\"submit\">Continue</button>"));
        for loading in [
            "src=", "href=", "<link", "<img", "<iframe", "<style", "style=",
        ] {
            assert!(!body.contains(loading), "{loading}");
        }
    }
}
