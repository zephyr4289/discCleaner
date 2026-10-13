//! TOML-lite: a strict, dependency-free subset of TOML for vendor profiles.
//!
//! Supports: `[section]` headers (nested `a.b` dotted ok), `key = value`
//! with integers (decimal or 0x hex), quoted strings, booleans, `#` comments
//! and blank lines. Anything else is a parse error — profiles are operator
//! input on an air-gapped bench, so we fail loudly rather than guess.

use std::collections::HashMap;
use std::fmt;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Int(i64),
    Str(String),
    Bool(bool),
}

impl Value {
    pub fn as_int(&self) -> Option<i64> {
        match self {
            Value::Int(v) => Some(*v),
            _ => None,
        }
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::Str(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_u32(&self) -> Option<u32> {
        self.as_int().and_then(|v| u32::try_from(v).ok())
    }
}

#[derive(Debug, Clone)]
pub struct ParseError {
    pub line: usize,
    pub msg: String,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "profile line {}: {}", self.line, self.msg)
    }
}

impl std::error::Error for ParseError {}

/// Parsed document: `section.key` -> value (root section is "").
pub struct Doc {
    map: HashMap<String, Value>,
}

impl Doc {
    pub fn parse(text: &str) -> Result<Doc, ParseError> {
        let mut map: HashMap<String, Value> = HashMap::new();
        let mut section = String::new();
        for (idx, raw) in text.lines().enumerate() {
            let line = raw.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') {
                if !line.ends_with(']') {
                    return Err(ParseError {
                        line: idx + 1,
                        msg: "unterminated section header".into(),
                    });
                }
                section = line[1..line.len() - 1].trim().to_ascii_lowercase();
                if section.is_empty() {
                    return Err(ParseError {
                        line: idx + 1,
                        msg: "empty section name".into(),
                    });
                }
                continue;
            }
            let eq = line.find('=').ok_or_else(|| ParseError {
                line: idx + 1,
                msg: "expected key = value".into(),
            })?;
            let key = line[..eq].trim().to_ascii_lowercase();
            if key.is_empty() {
                return Err(ParseError {
                    line: idx + 1,
                    msg: "empty key".into(),
                });
            }
            let raw_val = line[eq + 1..].trim();
            let value = if let Some(rest) = raw_val.strip_prefix('"') {
                let end = rest.find('"').ok_or_else(|| ParseError {
                    line: idx + 1,
                    msg: "unterminated string".into(),
                })?;
                Value::Str(rest[..end].to_string())
            } else if raw_val == "true" {
                Value::Bool(true)
            } else if raw_val == "false" {
                Value::Bool(false)
            } else {
                let v = if let Some(hex) = raw_val
                    .strip_prefix("0x")
                    .or_else(|| raw_val.strip_prefix("0X"))
                {
                    i64::from_str_radix(hex, 16)
                } else {
                    raw_val.parse::<i64>()
                };
                Value::Int(v.map_err(|_| ParseError {
                    line: idx + 1,
                    msg: format!("bad value: {raw_val}"),
                })?)
            };
            let full = if section.is_empty() {
                key.clone()
            } else {
                format!("{section}.{key}")
            };
            map.insert(full, value);
        }
        Ok(Doc { map })
    }

    pub fn get(&self, full_key: &str) -> Option<&Value> {
        self.map.get(full_key)
    }

    pub fn get_str(&self, key: &str) -> Option<&str> {
        self.get(key).and_then(|v| v.as_str())
    }

    pub fn get_u32(&self, key: &str) -> Option<u32> {
        self.get(key).and_then(|v| v.as_u32())
    }

    pub fn get_bool(&self, key: &str) -> Option<bool> {
        self.get(key).and_then(|v| v.as_bool())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_profile_shapes() {
        let text = r#"
# a vendor profile
name = "SM2262EN"
family = "siliconmotion"
sram_base = 0x10000000
sram_size = 0x00040000
jtag_irlen = 4
auth_required = true

[brom]
baud = 115200
magic = "SM2262-BROM"
"#;
        let doc = Doc::parse(text).unwrap();
        assert_eq!(doc.get_str("name"), Some("SM2262EN"));
        assert_eq!(doc.get_u32("sram_base"), Some(0x1000_0000));
        assert_eq!(doc.get_bool("auth_required"), Some(true));
        assert_eq!(doc.get_str("brom.magic"), Some("SM2262-BROM"));
        assert_eq!(doc.get_u32("brom.baud"), Some(115_200));
        assert!(doc.get_u32("missing").is_none());
    }

    #[test]
    fn rejects_garbage() {
        assert!(Doc::parse("this is not toml").is_err());
        assert!(Doc::parse("key = \"unterminated").is_err());
        assert!(Doc::parse("key = 0xZZ").is_err());
        assert!(Doc::parse("[unclosed").is_err());
    }
}
