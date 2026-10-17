//! Small shared helpers.
//!
//! Exists so "truncate evidence to a readable length" has one implementation
//! rather than one per probe — reports are read by humans and diffed by CI,
//! and an unbounded `detail` line is neither.

/// Truncate to `max` characters (not bytes), appending an ellipsis.
///
/// Character-aware on purpose: slicing a UTF-8 string by byte index panics.
#[must_use]
pub fn truncate(s: &str, max: usize) -> String {
    let flat = s.replace(['\n', '\r'], " ");
    if flat.chars().count() <= max {
        return flat.trim().to_string();
    }
    let head: String = flat.chars().take(max).collect();
    format!("{}...", head.trim_end())
}

#[cfg(test)]
#[allow(
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::assertions_on_constants
)]
mod tests {
    use super::truncate;

    #[test]
    fn short_strings_pass_through_trimmed() {
        assert_eq!(truncate("  hello  ", 40), "hello");
    }

    #[test]
    fn long_strings_are_truncated_with_an_ellipsis() {
        let out = truncate("abcdefghij", 4);
        assert!(out.starts_with("abcd"));
        assert!(out.ends_with("..."));
    }

    #[test]
    fn multibyte_characters_never_panic() {
        assert_eq!(
            truncate("\u{4f60}\u{597d}\u{4e16}\u{754c}", 2),
            "\u{4f60}\u{597d}..."
        );
    }

    #[test]
    fn newlines_collapse_so_one_finding_stays_one_line() {
        assert_eq!(truncate("a\nb\nc", 40), "a b c");
    }
}
