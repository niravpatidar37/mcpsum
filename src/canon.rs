//! Canonical JSON (RFC 8785, JCS) and SHA-256 digests.
//!
//! We hash the canonical form of what the server actually sent (whole objects,
//! no field allow-list) so that new spec fields are covered automatically and
//! key order / whitespace cannot cause false drift.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// RFC 8785 canonical serialization.
pub fn canonical_json(v: &Value) -> String {
    // serde_jcs only fails on non-serializable inputs; a parsed `Value` is always serializable.
    serde_jcs::to_string(v).expect("serde_json::Value is always JCS-serializable")
}

/// `sha256:<hex>` of raw bytes.
pub fn sha256_tagged(bytes: &[u8]) -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(bytes)))
}

/// Digest of the canonical form of a JSON value.
pub fn digest(v: &Value) -> String {
    sha256_tagged(canonical_json(v).as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // RFC 8785 section 3.2.2 example (numbers, strings, literals).
    #[test]
    fn rfc8785_sample_vector() {
        let input = r#"{"numbers":[333333333.33333329,1E30,4.50,2e-3,0.000000000000000000000000001],"string":"\u20ac$\u000F\u000aA'\u0042\u0022\u005c\\\"\/","literals":[null,true,false]}"#;
        let v: Value = serde_json::from_str(input).unwrap();
        let expected = "{\"literals\":[null,true,false],\"numbers\":[333333333.3333333,1e+30,4.5,0.002,1e-27],\"string\":\"\u{20ac}$\\u000f\\nA'B\\\"\\\\\\\\\\\"/\"}";
        assert_eq!(canonical_json(&v), expected);
    }

    // RFC 8785 section 3.2.3: keys sort by UTF-16 code units, not code points.
    #[test]
    fn rfc8785_key_sorting_utf16() {
        let input = r#"{"\u20ac":"Euro","\r":"CR","\ufb33":"Dalet","1":"One","\ud83d\ude00":"Emoji","\u0080":"Control","\u00f6":"o"}"#;
        let v: Value = serde_json::from_str(input).unwrap();
        let out = canonical_json(&v);
        let order: Vec<usize> = ["CR", "One", "Control", "\"o\"", "Euro", "Emoji", "Dalet"]
            .iter()
            .map(|k| out.find(k).unwrap())
            .collect();
        let mut sorted = order.clone();
        sorted.sort();
        assert_eq!(order, sorted, "canonical output: {out}");
    }

    #[test]
    fn digest_ignores_key_order_and_whitespace() {
        let a: Value = serde_json::from_str(r#"{"b":1, "a":{"y":2,"x":[1,2]}}"#).unwrap();
        let b = json!({"a":{"x":[1,2],"y":2},"b":1});
        assert_eq!(digest(&a), digest(&b));
    }

    #[test]
    fn digest_detects_single_invisible_char() {
        let a = json!({"description":"Adds two numbers"});
        let b = json!({"description":"Adds two\u{200b} numbers"});
        assert_ne!(digest(&a), digest(&b));
    }

    #[test]
    fn sha256_known_answer() {
        assert_eq!(
            sha256_tagged(b"abc"),
            "sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}
