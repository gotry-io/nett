//! 规范化 JSON：RFC 8785 的子集，数值只允许 0 到 2⁵³−1 的整数（design/auth.md 第 10.5 节）。
//!
//! 签名针对的是字节。验证方只接受恰好等于自身规范形式的字节，因此同一份内容只有一种写法：
//! 重复的键（不同解析器取舍不同）、多余的空白、非规范的转义都不能通过。

use std::io::Write as _;

use serde_json::Value;

/// 一份签名载荷或准入证明的最大字节数，限制解析时的内存占用。
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024;

/// JavaScript 能精确表示的最大整数；控制台在浏览器中生成载荷，更大的整数会失真。
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

/// 生成一个 JSON 值的规范形式。
pub fn to_canonical(value: &Value) -> Result<Vec<u8>, CanonicalError> {
    let mut out = Vec::new();
    write_value(value, &mut out)?;
    Ok(out)
}

/// 解析一份文档，并确认收到的字节就是它的规范形式。
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
            // RFC 8785 按 UTF-16 码元排序键；与 UTF-8 字节序只在 BMP 之外的字符上不同
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

/// 与 ECMAScript 的 `JSON.stringify` 相同：只转义引号、反斜杠和控制字符，其余字符原样输出。
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
                // 写入 Vec 不会失败
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
        // U+FF61 在 UTF-8 字节序中排在 U+1F600 之前，按 UTF-16 码元则排在其后
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
            &br#"{"b":"x","a":1}"#[..], // 键的顺序
            br#"{"a": 1,"b":"x"}"#,     // 空白
            br#"{"a":1,"a":2}"#,        // 重复的键
            b"{\"a\":\"\\u0041\"}",     // 非规范的转义
            br#"{"a":1.0}"#,            // 浮点
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
