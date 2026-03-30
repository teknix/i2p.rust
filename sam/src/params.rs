//! SAM protocol parameter parser.
//!
//! Parses a single SAM protocol line into a [`Params`] map.  This is the
//! Rust equivalent of `SAMUtils.parseParams()` in the Java implementation.
//!
//! # Grammar
//!
//! ```text
//! line   ::= COMMAND [OPCODE] [key=value]*
//! line   ::= PING  [anything]
//! line   ::= PONG  [anything]
//! value  ::= bare_word | "quoted string"
//! ```
//!
//! Rules:
//! - `COMMAND` and `OPCODE` are folded to upper-case.
//! - Keys are **not** quoted and are **not** folded.
//! - Duplicate keys are rejected.
//! - Backslash escapes any following character.
//! - A key without a `=` is stored with the value `"true"`.
//! - The special keys [`COMMAND_KEY`] and [`OPCODE_KEY`] hold the command and
//!   opcode tokens respectively.

use std::collections::HashMap;

use crate::error::{Result, SamError};

/// Map key used to store the parsed command token (e.g. `"SESSION"`).
pub const COMMAND_KEY: &str = "\"\"COMMAND\"\"";
/// Map key used to store the parsed opcode token (e.g. `"CREATE"`).
pub const OPCODE_KEY: &str = "\"\"OPCODE\"\"";

/// A parsed SAM parameter map.
///
/// The `COMMAND` and `OPCODE` tokens are stored under the special keys
/// [`COMMAND_KEY`] and [`OPCODE_KEY`].  All other `key=value` pairs are
/// stored verbatim.
pub type Params = HashMap<String, String>;

/// Parse a single SAM protocol line into a [`Params`] map.
///
/// # Errors
///
/// Returns [`SamError::Protocol`] when:
/// - An unterminated quote is encountered.
/// - An unterminated backslash escape is encountered.
/// - An empty parameter name (`=value`) is encountered.
/// - A duplicate key is present.
pub fn parse_params(args: &str) -> Result<Params> {
    let mut rv: Params = HashMap::new();
    let mut buf = String::with_capacity(32);
    let mut is_quoted = false;
    let mut key: Option<String> = None;

    // Append a synthetic trailing space so the main loop never needs
    // post-loop clean-up, matching the Java implementation's technique.
    let chars: Vec<char> = args.chars().chain(std::iter::once(' ')).collect();
    let length = chars.len();
    let mut i = 0usize;

    while i < length {
        let c = chars[i];
        match c {
            '"' => {
                if is_quoted {
                    // End of quoted section: store the current key/value.
                    if let Some(k) = key.take() {
                        let v = if buf.is_empty() {
                            "true".to_owned()
                        } else {
                            buf.clone()
                        };
                        if rv.insert(k.clone(), v).is_some() {
                            return Err(SamError::Protocol(format!(
                                "Duplicate parameter '{k}'"
                            )));
                        }
                    }
                    buf.clear();
                }
                is_quoted = !is_quoted;
            }

            '\r' | '\n' => {
                // Strip line endings.
            }

            ' ' | '\x08' | '\x0c' | '\t' => {
                if is_quoted {
                    buf.push(c);
                } else {
                    // Token delimiter.
                    if let Some(k) = key.take() {
                        let v = if buf.is_empty() {
                            "true".to_owned()
                        } else {
                            buf.clone()
                        };
                        if rv.insert(k.clone(), v).is_some() {
                            return Err(SamError::Protocol(format!(
                                "Duplicate parameter '{k}'"
                            )));
                        }
                        buf.clear();
                    } else if !buf.is_empty() {
                        // Bare token with no '='.
                        if rv.is_empty() {
                            // First token → COMMAND.
                            let cmd = buf.to_uppercase();
                            rv.insert(COMMAND_KEY.to_owned(), cmd.clone());
                            if cmd == "PING" || cmd == "PONG" {
                                // Everything after this token is the ping data.
                                let rest: String = chars[i + 1..length - 1].iter().collect();
                                if !rest.is_empty() {
                                    rv.insert(OPCODE_KEY.to_owned(), rest);
                                }
                                // Skip to end of input.
                                i = length;
                                buf.clear();
                                continue;
                            }
                        } else if rv.len() == 1 {
                            // Second token → OPCODE.
                            rv.insert(OPCODE_KEY.to_owned(), buf.to_uppercase());
                        } else {
                            // Bare key without value → store as "true".
                            let k = buf.clone();
                            if rv.insert(k.clone(), "true".to_owned()).is_some() {
                                return Err(SamError::Protocol(format!(
                                    "Duplicate parameter '{k}'"
                                )));
                            }
                        }
                        buf.clear();
                    }
                }
            }

            '=' => {
                if is_quoted {
                    buf.push(c);
                } else if key.is_some() {
                    // '=' inside a value (e.g. base-64 padding).
                    buf.push(c);
                } else {
                    if buf.is_empty() {
                        return Err(SamError::Protocol("Empty parameter name".to_owned()));
                    }
                    key = Some(buf.clone());
                    buf.clear();
                }
            }

            '\\' => {
                i += 1;
                if i >= length {
                    return Err(SamError::Protocol("Unterminated escape".to_owned()));
                }
                buf.push(chars[i]);
            }

            _ => {
                buf.push(c);
            }
        }
        i += 1;
    }

    if is_quoted {
        return Err(SamError::Protocol("Unterminated quote".to_owned()));
    }

    Ok(rv)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cmd(p: &Params) -> Option<&str> {
        p.get(COMMAND_KEY).map(String::as_str)
    }

    fn opcode(p: &Params) -> Option<&str> {
        p.get(OPCODE_KEY).map(String::as_str)
    }

    #[test]
    fn simple_key_value() {
        let p = parse_params("a=b c=d").unwrap();
        assert_eq!(p.get("a").map(String::as_str), Some("b"));
        assert_eq!(p.get("c").map(String::as_str), Some("d"));
    }

    #[test]
    fn quoted_values() {
        let p = parse_params(r#"a="b c d" e="f g h" i="j""#).unwrap();
        assert_eq!(p.get("a").map(String::as_str), Some("b c d"));
        assert_eq!(p.get("e").map(String::as_str), Some("f g h"));
        assert_eq!(p.get("i").map(String::as_str), Some("j"));
    }

    #[test]
    fn command_and_opcode() {
        let p = parse_params("SESSION CREATE STYLE=STREAM").unwrap();
        assert_eq!(cmd(&p), Some("SESSION"));
        assert_eq!(opcode(&p), Some("CREATE"));
        assert_eq!(p.get("STYLE").map(String::as_str), Some("STREAM"));
    }

    #[test]
    fn naming_lookup() {
        let p = parse_params("NAMING LOOKUP NAME=zzz.i2p").unwrap();
        assert_eq!(cmd(&p), Some("NAMING"));
        assert_eq!(opcode(&p), Some("LOOKUP"));
        assert_eq!(p.get("NAME").map(String::as_str), Some("zzz.i2p"));
    }

    #[test]
    fn ping_pong() {
        let p = parse_params("PING hello world").unwrap();
        assert_eq!(cmd(&p), Some("PING"));
        assert_eq!(opcode(&p), Some("hello world"));
    }

    #[test]
    fn backslash_escape() {
        let p = parse_params(r#"key=val\"ue"#).unwrap();
        assert_eq!(p.get("key").map(String::as_str), Some(r#"val"ue"#));
    }

    #[test]
    fn duplicate_key_is_error() {
        let result = parse_params("a=b a=c");
        assert!(matches!(result, Err(SamError::Protocol(_))));
    }

    #[test]
    fn empty_key_is_error() {
        let result = parse_params("=value");
        assert!(matches!(result, Err(SamError::Protocol(_))));
    }

    #[test]
    fn unterminated_quote_is_error() {
        let result = parse_params(r#"key="unterminated"#);
        assert!(matches!(result, Err(SamError::Protocol(_))));
    }

    #[test]
    fn base64_equals_in_value() {
        // base-64 padding '=' must not be treated as a key=value separator
        let p = parse_params("VALUE=abc==").unwrap();
        assert_eq!(p.get("VALUE").map(String::as_str), Some("abc=="));
    }
}
