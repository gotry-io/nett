//! Canonical JSON: a subset of RFC 8785, where numbers may only be integers from 0 to 2⁵³−1
//! (design/auth.md section 10.5).
//!
//! A signature covers bytes. The verifier accepts only bytes exactly equal to their own canonical
//! form, so the same content has only one spelling: duplicate keys (different parsers handle them
//! differently), extra whitespace and non-canonical escapes all fail.

use std::io::Write as _;

use serde_json::Value;

/// The maximum number of bytes of a signed payload or admission proof, which bounds memory use
/// while parsing.
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// The largest integer JavaScript can represent exactly; the console generates payloads in the
/// browser, and larger integers would lose precision.
const MAX_SAFE_INTEGER: u64 = (1 << 53) - 1;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CanonicalError {
    #[error("document is {len} bytes, larger than the {MAX_DOCUMENT_BYTES}-byte limit")]
    TooLarge { len: usize },
    #[error("document is not valid JSON: {0}")]
    Syntax(String),
    #[error("document must be a JSON object")]
    NotObject,
    #[error("numbers must be integers between 0 and 2^53-1")]
    Number,
    #[error("document bytes are not in canonical form (RFC 8785)")]
    NotCanonical,
}

/// Generates the canonical form of a JSON value.
pub fn to_canonical(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// Parses a document and confirms that the received bytes are its canonical form.
pub fn parse_canonical(bytes: &[u8]) -> Result<Value, CanonicalError> {
    if bytes.len() > MAX_DOCUMENT_BYTES {
        return Err(CanonicalError::TooLarge { len: bytes.len() });
    }
    let value: Value =
        serde_json::from_slice(bytes).map_err(|e| CanonicalError::Syntax(e.to_string()))?;
    if !value.is_object() {
        return Err(CanonicalError::NotObject);
    }
    if to_canonical(&value)? != bytes {
        return Err(CanonicalError::NotCanonical);
    }
    Ok(value)
}

fn write_value(value: &Value, out: &mut Vec<u8>) -> Result<(), CanonicalError> {
    match value {
        Value::Null => out.extend_from_slice(b"null"),
        Value::Bool(true) => out.extend_from_slice(b"true"),
        Value::Bool(false) => out.extend_from_slice(b"false"),
        Value::Number(n) => {
            let n = n
                .as_u64()
                .filter(|n| *n <= MAX_SAFE_INTEGER)
                .ok_or(CanonicalError::Number)?;
            out.extend_from_slice(n.to_string().as_bytes());
        }
        Value::String(s) => write_string(s, out),
        Value::Array(items) => {
            out.push(b'[');
            for (i, item) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_value(item, out)?;
            }
            out.push(b']');
        }
        Value::Object(map) => {
            // RFC 8785 sorts keys by UTF-16 code unit; this differs from UTF-8 byte order only for
            // characters outside the BMP
            let mut entries: Vec<_> = map.iter().collect();
            entries.sort_by(|a, b| a.0.encode_utf16().cmp(b.0.encode_utf16()));
            out.push(b'{');
            for (i, (key, item)) in entries.into_iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                write_string(key, out);
                out.push(b':');
                write_value(item, out)?;
            }
            out.push(b'}');
        }
    }
    Ok(())
}

/// Same as ECMAScript's `JSON.stringify`: only quotes, backslashes and control characters are
/// escaped, and other characters are output as is.
fn write_string(s: &str, out: &mut Vec<u8>) {
    out.push(b'"');
    for c in s.chars() {
        match c {
            '"' => out.extend_from_slice(b"\\\""),
            '\\' => out.extend_from_slice(b"\\\\"),
            '\u{08}' => out.extend_from_slice(b"\\b"),
            '\t' => out.extend_from_slice(b"\\t"),
            '\n' => out.extend_from_slice(b"\\n"),
            '\u{0c}' => out.extend_from_slice(b"\\f"),
            '\r' => out.extend_from_slice(b"\\r"),
            c if u32::from(c) < 0x20 => {
                // Writing to a Vec cannot fail
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => {
                let mut buf = [0u8; 4];
                out.extend_from_slice(c.encode_utf8(&mut buf).as_bytes());
            }
        }
    }
    out.push(b'"');
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn canon(v: &Value) -> String {
        String::from_utf8(to_canonical(v).expect("canonical")).expect("utf-8")
    }

    #[test]
    fn sorts_keys_and_drops_whitespace() {
        let v = json!({"b": 1, "a": [true, null, "x"], "c": {"z": 0, "y": "é"}});
        assert_eq!(
            canon(&v),
            r#"{"a":[true,null,"x"],"b":1,"c":{"y":"é","z":0}}"#
        );
    }

    #[test]
    fn sorts_keys_by_utf16_code_units() {
        // U+FF61 comes before U+1F600 in UTF-8 byte order, but after it in UTF-16 code units
        let v = json!({"\u{1F600}": 1, "\u{FF61}": 2});
        assert_eq!(canon(&v), "{\"\u{1F600}\":1,\"\u{FF61}\":2}");
    }

    #[test]
    fn escapes_like_json_stringify() {
        let v = json!({"s": "\"\\/\u{08}\t\n\u{0c}\r\u{01}\u{1f}\u{7f}\u{2028}"});
        assert_eq!(
            canon(&v),
            "{\"s\":\"\\\"\\\\/\\b\\t\\n\\f\\r\\u0001\\u001f\u{7f}\u{2028}\"}"
        );
    }

    #[test]
    fn rejects_numbers_outside_the_integer_subset() {
        for n in [json!(-1), json!(1.5), json!(9_007_199_254_740_992_u64)] {
            assert_eq!(
                to_canonical(&json!({ "n": n })),
                Err(CanonicalError::Number)
            );
        }
        assert!(to_canonical(&json!({"n": 9_007_199_254_740_991_u64})).is_ok());
    }

    #[test]
    fn parse_accepts_only_canonical_bytes() {
        assert!(parse_canonical(br#"{"a":1,"b":"x"}"#).is_ok());
        for bad in [
            &br#"{"b":"x","a":1}"#[..], // key order
            br#"{"a": 1,"b":"x"}"#,     // whitespace
            br#"{"a":1,"a":2}"#,        // duplicate key
            b"{\"a\":\"\\u0041\"}",     // non-canonical escape
            br#"{"a":1.0}"#,            // floating point
            br#"{"a":1e2}"#,
            br#"{"a":-0}"#,
            b"{\"a\":1}\n",
        ] {
            assert!(
                parse_canonical(bad).is_err(),
                "{}",
                String::from_utf8_lossy(bad)
            );
        }
    }

    #[test]
    fn parse_rejects_non_objects_and_oversized_documents() {
        assert_eq!(parse_canonical(b"[1]"), Err(CanonicalError::NotObject));
        let big = format!("{{\"a\":\"{}\"}}", "x".repeat(MAX_DOCUMENT_BYTES));
        assert!(matches!(
            parse_canonical(big.as_bytes()),
            Err(CanonicalError::TooLarge { .. })
        ));
    }
}
