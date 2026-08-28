//! Hand-rolled RFC 8785 JSON Canonicalization Scheme (JCS) reference implementation.
//! Pure Rust, zero external JCS dependencies. Sorts keys by UTF-16 code units.

use serde_json::Value;

pub struct JcsRef;

impl JcsRef {
    /// Canonicalize a `serde_json::Value` according to RFC 8785 rules.
    pub fn canonicalize(val: &Value) -> Result<String, String> {
        let mut out = String::new();
        Self::format_value(val, &mut out)?;
        Ok(out)
    }

    fn format_value(val: &Value, out: &mut String) -> Result<(), String> {
        match val {
            Value::Null => out.push_str("null"),
            Value::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Value::Number(n) => {
                if let Some(i) = n.as_i64() {
                    out.push_str(&i.to_string());
                } else if let Some(u) = n.as_u64() {
                    out.push_str(&u.to_string());
                } else if let Some(f) = n.as_f64() {
                    // Integer or float representation
                    if f.fract() == 0.0 && f.abs() < 1e16 {
                        out.push_str(&(f as i64).to_string());
                    } else {
                        out.push_str(&f.to_string());
                    }
                }
            }
            Value::String(s) => Self::format_string(s, out),
            Value::Array(arr) => {
                out.push('[');
                for (i, elem) in arr.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    Self::format_value(elem, out)?;
                }
                out.push(']');
            }
            Value::Object(map) => {
                out.push('{');
                // RFC 8785 §3.2.3: Object keys sorted by UTF-16 code units (lexicographical)
                let mut sorted_keys: Vec<&String> = map.keys().collect();
                sorted_keys.sort_by(|a, b| {
                    let a_utf16: Vec<u16> = a.encode_utf16().collect();
                    let b_utf16: Vec<u16> = b.encode_utf16().collect();
                    a_utf16.cmp(&b_utf16)
                });

                for (i, k) in sorted_keys.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    Self::format_string(k, out);
                    out.push(':');
                    let v = &map[*k];
                    Self::format_value(v, out)?;
                }
                out.push('}');
            }
        }
        Ok(())
    }

    fn format_string(s: &str, out: &mut String) {
        out.push('"');
        for c in s.chars() {
            match c {
                '"' => out.push_str("\\\""),
                '\\' => out.push_str("\\\\"),
                '\u{0008}' => out.push_str("\\b"),
                '\u{000C}' => out.push_str("\\f"),
                '\n' => out.push_str("\\n"),
                '\r' => out.push_str("\\r"),
                '\t' => out.push_str("\\t"),
                c if (c as u32) < 0x20 => {
                    out.push_str(&format!("\\u{:04x}", c as u32));
                }
                c => out.push(c),
            }
        }
        out.push('"');
    }
}
