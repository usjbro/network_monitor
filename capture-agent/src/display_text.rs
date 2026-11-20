//! Display-safe rendering of untrusted text: a DNS name, an HTTP method and
//! path, an SNI. Printable ASCII and the space pass through; everything else
//! is escaped as `\u{..}`, so control characters, ANSI escape sequences and
//! bidirectional overrides arrive as visible text, never as instructions to a
//! terminal or a renderer.
//!
//! Moved from `transaction.rs` (KAN-130 plan P4) so Expert Info summaries and
//! TCP sample labels share one rule.

/// Escapes `text` and cuts it after `max_chars` input characters, marking the
/// cut with `…`. This is the behaviour `unanswered-request` summaries have
/// always had.
pub fn display_safe_chars(text: &str, max_chars: usize) -> String {
    let mut out = String::new();
    for (count, c) in text.chars().enumerate() {
        if count == max_chars {
            out.push('…');
            break;
        }
        push_safe(&mut out, c);
    }
    out
}

/// Escapes `text` into at most `max_bytes` bytes of printable ASCII. A cut
/// falls on a whole character or escape and is marked with `...`, which
/// counts toward `max_bytes`.
pub fn display_safe_bytes(text: &str, max_bytes: usize) -> String {
    const MARK: &str = "...";
    let mut out = String::new();
    // The longest prefix, on a whole character or escape, that still leaves
    // room for the marker.
    let mut marked_cut = 0;
    for c in text.chars() {
        let before = out.len();
        if before + MARK.len() <= max_bytes {
            marked_cut = before;
        }
        push_safe(&mut out, c);
        if out.len() > max_bytes {
            if max_bytes < MARK.len() {
                // No room for the marker: keep what fits.
                out.truncate(before);
            } else {
                out.truncate(marked_cut);
                out.push_str(MARK);
            }
            return out;
        }
    }
    out
}

fn push_safe(out: &mut String, c: char) {
    if c.is_ascii_graphic() || c == ' ' {
        out.push(c);
    } else {
        out.extend(c.escape_unicode());
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chars_variant_keeps_its_existing_behaviour() {
        assert_eq!(
            display_safe_chars("GET /a\u{1b}[31m", 120),
            "GET /a\\u{1b}[31m"
        );
        assert_eq!(display_safe_chars("abcdef", 3), "abc…");
        assert_eq!(display_safe_chars("abc", 3), "abc");
    }

    #[test]
    fn bytes_variant_passes_short_printable_text_unchanged() {
        assert_eq!(
            display_safe_bytes("ClientHello (SNI: example.com)", 64),
            "ClientHello (SNI: example.com)"
        );
        assert_eq!(display_safe_bytes("", 64), "");
    }

    #[test]
    fn bytes_variant_escapes_control_bidi_and_non_ascii() {
        assert_eq!(
            display_safe_bytes("a\u{1b}b\u{202e}c\u{e9}", 64),
            "a\\u{1b}b\\u{202e}c\\u{e9}"
        );
    }

    #[test]
    fn bytes_variant_never_exceeds_the_limit_and_marks_the_cut() {
        let long = "x".repeat(200);
        let out = display_safe_bytes(&long, 64);
        assert_eq!(out.len(), 64);
        assert!(out.ends_with("..."));
        assert_eq!(&out[..61], &long[..61]);
        // Exactly at the limit: no cut.
        assert_eq!(display_safe_bytes(&"y".repeat(64), 64), "y".repeat(64));
        // One over: cut.
        assert_eq!(
            display_safe_bytes(&"y".repeat(65), 64),
            format!("{}...", "y".repeat(61))
        );
    }

    #[test]
    fn bytes_variant_cuts_on_a_whole_escape() {
        // 58 printable bytes, then an 8-byte escape that would end at 66.
        let text = format!("{}\u{202e}tail", "a".repeat(58));
        let out = display_safe_bytes(&text, 64);
        assert_eq!(out, format!("{}...", "a".repeat(58)));
        assert!(out.len() <= 64);
    }

    #[test]
    fn bytes_variant_output_is_always_printable_ascii() {
        for text in ["\u{0}\u{7f}\u{85}", "\u{feff}é漢字🙂", "tab\there\nnewline"] {
            for max in [0, 1, 3, 4, 10, 64] {
                let out = display_safe_bytes(text, max);
                assert!(out.len() <= max, "{text:?} {max}: {out:?}");
                assert!(
                    out.bytes().all(|b| b.is_ascii_graphic() || b == b' '),
                    "{out:?}"
                );
            }
        }
    }
}
