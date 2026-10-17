//! JSONC comment stripping.
//!
//! The `OpenCode` config is JSONC: `//` and `/* */` comments plus trailing
//! commas. `serde_json` handles neither, so we strip comments ourselves rather
//! than take a dependency — the function is small, pure, and fully unit-tested
//! below. Comment markers inside string literals are left alone, which is the
//! part every naive implementation gets wrong (our own config contains
//! `"https://api.githubcopilot.com/mcp/"`).
//!
//! Stripping replaces comment bytes with spaces rather than deleting them, so
//! byte offsets in parse errors still point at the right place in the original
//! file.

/// Remove `//` and `/* */` comments from JSONC text, preserving string
/// literals, line structure, and byte offsets.
#[must_use]
pub fn strip_comments(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut in_string = false;
    let mut escaped = false;
    let mut i = 0usize;

    while i < bytes.len() {
        let b = bytes[i];

        if in_string {
            out.push(b);
            if escaped {
                escaped = false;
            } else if b == b'\\' {
                escaped = true;
            } else if b == b'"' {
                in_string = false;
            }
            i += 1;
            continue;
        }

        match b {
            b'"' => {
                in_string = true;
                out.push(b);
                i += 1;
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    out.push(b' ');
                    i += 1;
                }
            }
            b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                let mut closed = false;
                while i < bytes.len() {
                    if bytes[i] == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                        out.push(b' ');
                        out.push(b' ');
                        i += 2;
                        closed = true;
                        break;
                    }
                    // keep newlines so line numbers in errors stay honest
                    out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                    i += 1;
                }
                if !closed {
                    // Unterminated block comment: everything left is comment.
                    while i < bytes.len() {
                        out.push(if bytes[i] == b'\n' { b'\n' } else { b' ' });
                        i += 1;
                    }
                }
            }
            _ => {
                out.push(b);
                i += 1;
            }
        }
    }

    // Non-ASCII bytes survive because we copy them verbatim.
    String::from_utf8(out).unwrap_or_else(|_| input.to_string())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::assertions_on_constants
)]
mod tests {
    use super::strip_comments;

    #[test]
    fn strips_line_comments() {
        let out = strip_comments("{\n  // a comment\n  \"a\": 1\n}");
        assert!(!out.contains("a comment"));
        assert!(out.contains("\"a\": 1"));
    }

    #[test]
    fn strips_block_comments_but_keeps_newlines() {
        let src = "{\n/* one\ntwo */\n\"a\": 1\n}";
        let out = strip_comments(src);
        assert!(!out.contains("one"));
        assert_eq!(
            out.lines().count(),
            src.lines().count(),
            "line count must be preserved so error line numbers stay honest"
        );
        assert!(out.contains("\"a\": 1"));
    }

    #[test]
    fn leaves_comment_markers_inside_strings() {
        let src = "{\"url\": \"https://api.githubcopilot.com/mcp/\", \"a\": \"// not a comment\"}";
        assert_eq!(strip_comments(src), src);
    }

    #[test]
    fn handles_escaped_quotes_inside_strings() {
        let src = r#"{"a": "he said \"hi\" // not a comment", "b": 2}"#;
        assert_eq!(strip_comments(src), src);
    }

    #[test]
    fn preserves_byte_offsets() {
        let src = "{\n  // 0123456789\n  \"a\": 1\n}";
        let out = strip_comments(src);
        assert_eq!(src.len(), out.len());
        assert_eq!(out.find("\"a\""), src.find("\"a\""));
    }

    #[test]
    fn unterminated_block_comment_swallows_the_rest() {
        let out = strip_comments("{\"a\": 1} /* oops");
        assert!(!out.contains("oops"));
        assert!(out.contains("\"a\": 1"));
    }

    #[test]
    fn is_idempotent() {
        let src = "// x\n{\"a\": \"// y\" /* z */}";
        let once = strip_comments(src);
        assert_eq!(once, strip_comments(&once));
    }

    #[test]
    fn keeps_non_ascii_intact() {
        let src = "{\"a\": \"caf\u{e9} \u{2014} \u{4f60}\"}";
        assert_eq!(strip_comments(src), src);
    }
}
