//! Safe rendering of untrusted (server-authored) text for terminals, PR
//! comments and logs. Tool descriptions are attacker-controlled: they can carry
//! ANSI escapes that rewrite the terminal, bidi overrides that reorder text
//! (Trojan Source, CVE-2021-42574), and invisible characters (zero-width,
//! Unicode tag block, variation selectors) used to smuggle hidden instructions.

/// Characters that are invisible, reorder text, or control the terminal.
/// Covers every Unicode Default_Ignorable_Code_Point, including the reserved
/// ones, so characters assigned there later are shown too.
pub fn is_suspicious(c: char) -> bool {
    let u = c as u32;
    matches!(u,
        0x00..=0x1F | 0x7F..=0x9F          // C0, DEL, C1 controls (ANSI escapes, CSI 0x9B)
        | 0x00AD                            // soft hyphen
        | 0x034F                            // combining grapheme joiner
        | 0x061C                            // arabic letter mark
        | 0x115F | 0x1160 | 0x3164 | 0xFFA0 // hangul fillers (render blank)
        | 0x17B4 | 0x17B5                   // khmer invisible vowels
        | 0x180B..=0x180F                   // mongolian variation selectors / vowel separator
        | 0x200B..=0x200F                   // zero-width space/joiners, LRM, RLM
        | 0x2028 | 0x2029                   // line / paragraph separator
        | 0x202A..=0x202E                   // bidi embeddings and overrides
        | 0x2060..=0x206F                   // word joiner, invisible operators, bidi isolates
        | 0xFE00..=0xFE0F                   // variation selectors
        | 0xFEFF                            // zero-width no-break space / BOM
        | 0xFFF0..=0xFFF8                   // reserved default-ignorable
        | 0xFFF9..=0xFFFB                   // interlinear annotation
        | 0x1BCA0..=0x1BCA3                 // shorthand format controls
        | 0x1D173..=0x1D17A                 // musical formatting controls
        | 0xE0000..=0xE007F                 // Unicode tag block (ASCII smuggling)
        | 0xE0080..=0xE00FF                 // reserved default-ignorable
        | 0xE0100..=0xE01EF                 // variation selectors supplement
        | 0xE01F0..=0xE0FFF                 // reserved default-ignorable
    )
}

/// Render untrusted text on a single line with every suspicious character made
/// visible as `<U+XXXX>`; `\n`, `\r`, `\t` become their escape sequences so a
/// description cannot fake extra diff lines.
pub fn escape_untrusted(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if is_suspicious(c) => out.push_str(&format!("<U+{:04X}>", c as u32)),
            c => out.push(c),
        }
    }
    out
}

/// Suspicious characters found in `s` (deduplicated, in order of first appearance).
pub fn suspicious_chars(s: &str) -> Vec<char> {
    let mut out: Vec<char> = Vec::new();
    for c in s.chars().filter(|c| is_suspicious(*c) && !matches!(c, '\n' | '\t')) {
        if !out.contains(&c) {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ansi_escape_is_neutralized() {
        let s = "ok\x1b[2J\x1b[1A";
        let r = escape_untrusted(s);
        assert!(!r.contains('\x1b'));
        assert_eq!(r, "ok<U+001B>[2J<U+001B>[1A");
    }

    #[test]
    fn newlines_cannot_fake_diff_lines() {
        assert_eq!(escape_untrusted("a\n+ approved\tb\r"), "a\\n+ approved\\tb\\r");
    }

    #[test]
    fn bidi_zero_width_tags_and_variation_selectors_are_visible() {
        let s = "a\u{202E}b\u{200B}c\u{E0041}d\u{FE0F}e\u{2066}f\u{00AD}g";
        assert_eq!(
            escape_untrusted(s),
            "a<U+202E>b<U+200B>c<U+E0041>d<U+FE0F>e<U+2066>f<U+00AD>g"
        );
    }

    #[test]
    fn ordinary_unicode_is_untouched() {
        assert_eq!(escape_untrusted("Café 日本語 — ok"), "Café 日本語 — ok");
    }

    #[test]
    fn c1_controls_and_del_are_visible() {
        assert_eq!(escape_untrusted("x\u{7f}\u{9b}y"), "x<U+007F><U+009B>y");
    }

    #[test]
    fn suspicious_chars_reports_hidden_payload() {
        let hidden: String = "ignore"
            .chars()
            .map(|c| char::from_u32(0xE0000 + c as u32).unwrap())
            .collect();
        let s = format!("Adds numbers{hidden}");
        let found = suspicious_chars(&s);
        assert!(!found.is_empty());
        assert!(suspicious_chars("plain\ntext").is_empty());
    }

    /// Every Default_Ignorable_Code_Point range, copied from
    /// https://www.unicode.org/Public/UCD/latest/ucd/DerivedCoreProperties.txt
    /// (DerivedCoreProperties-18.0.0.txt, Unicode 18.0.0). These render as
    /// nothing, so each one must be shown.
    const DEFAULT_IGNORABLE: &[(u32, u32)] = &[
        (0x00AD, 0x00AD),
        (0x034F, 0x034F),
        (0x061C, 0x061C),
        (0x115F, 0x1160),
        (0x17B4, 0x17B5),
        (0x180B, 0x180D),
        (0x180E, 0x180E),
        (0x180F, 0x180F),
        (0x200B, 0x200F),
        (0x202A, 0x202E),
        (0x2060, 0x2064),
        (0x2065, 0x2065),
        (0x2066, 0x206F),
        (0x3164, 0x3164),
        (0xFE00, 0xFE0F),
        (0xFEFF, 0xFEFF),
        (0xFFA0, 0xFFA0),
        (0xFFF0, 0xFFF8),
        (0x1BCA0, 0x1BCA3),
        (0x1D173, 0x1D17A),
        (0xE0000, 0xE0000),
        (0xE0001, 0xE0001),
        (0xE0002, 0xE001F),
        (0xE0020, 0xE007F),
        (0xE0080, 0xE00FF),
        (0xE0100, 0xE01EF),
        (0xE01F0, 0xE0FFF),
    ];

    #[test]
    fn every_default_ignorable_code_point_is_suspicious() {
        let mut missing = Vec::new();
        for &(lo, hi) in DEFAULT_IGNORABLE {
            for u in lo..=hi {
                let c = char::from_u32(u).unwrap();
                if !is_suspicious(c) {
                    missing.push(format!("U+{u:04X}"));
                }
            }
        }
        assert!(
            missing.is_empty(),
            "not flagged: {} code points, first {:?}",
            missing.len(),
            &missing[..missing.len().min(8)]
        );
    }

    #[test]
    fn shorthand_format_controls_are_visible() {
        for c in ['\u{1BCA0}', '\u{1BCA1}', '\u{1BCA2}', '\u{1BCA3}'] {
            let s = format!("a{c}b");
            assert_eq!(escape_untrusted(&s), format!("a<U+{:04X}>b", c as u32));
            assert_eq!(suspicious_chars(&s), vec![c]);
        }
    }
}
