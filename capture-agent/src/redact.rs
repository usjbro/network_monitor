const SENSITIVE_HEADER_NAMES: &[&str] =
    &["authorization", "cookie", "set-cookie", "proxy-authorization", "x-api-key"];

pub fn is_sensitive_header_name(name: &str) -> bool {
    SENSITIVE_HEADER_NAMES.contains(&name.to_ascii_lowercase().as_str())
}

fn looks_like_bearer_token(value: &str) -> bool {
    value.trim_start().to_ascii_lowercase().starts_with("bearer ")
}

/// Mutates header values in place — never removes the header, never touches
/// the name — for any header matched by name or whose value looks like a
/// bearer token, even under an unlisted header name. Applied before the
/// record ever enters the ring buffer or is emitted (spec Components §3);
/// body content is never in scope for this function (named limitation, see
/// Scope).
pub fn redact_headers(headers: &mut [(String, String)]) {
    for (name, value) in headers.iter_mut() {
        if is_sensitive_header_name(name) || looks_like_bearer_token(value) {
            *value = "[REDACTED]".to_string();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacts_known_sensitive_header_names_case_insensitively() {
        let mut headers = vec![
            ("Authorization".to_string(), "Bearer abc123".to_string()),
            ("cookie".to_string(), "session=xyz".to_string()),
            ("Set-Cookie".to_string(), "session=xyz; HttpOnly".to_string()),
            ("PROXY-AUTHORIZATION".to_string(), "Basic dXNlcjpwYXNz".to_string()),
            ("X-Api-Key".to_string(), "sk-live-12345".to_string()),
        ];
        redact_headers(&mut headers);
        for (name, value) in &headers {
            assert_eq!(value, "[REDACTED]", "header {name} should have been redacted");
        }
    }

    #[test]
    fn preserves_header_names_and_leaves_non_sensitive_values_untouched() {
        let mut headers = vec![
            ("Content-Type".to_string(), "application/json".to_string()),
            ("Authorization".to_string(), "Bearer abc123".to_string()),
        ];
        redact_headers(&mut headers);
        assert_eq!(headers[0], ("Content-Type".to_string(), "application/json".to_string()));
        assert_eq!(headers[1].0, "Authorization"); // name preserved
        assert_eq!(headers[1].1, "[REDACTED]");
    }

    #[test]
    fn redacts_bearer_token_shaped_values_in_non_listed_headers() {
        let mut headers = vec![("X-Custom-Auth".to_string(), "Bearer eyJhbGciOiJIUzI1NiJ9.abc.def".to_string())];
        redact_headers(&mut headers);
        assert_eq!(headers[0].1, "[REDACTED]");
    }

    #[test]
    fn does_not_touch_body_content_by_design() {
        // Named limitation, not a bug — documents the boundary explicitly
        // rather than leaving it implicit (spec Scope: "body content is NOT
        // redacted"). redact_headers only ever operates on the headers Vec —
        // there is no function in this module that takes body bytes at all,
        // which this test's absence-of-a-call documents structurally.
        let body = b"{\"password\": \"hunter2\"}";
        let _ = body;
    }
}
