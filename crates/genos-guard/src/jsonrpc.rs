//! JSON and JSON-RPC 2.0 line parser and canonical serializer for `genos-guard`.
//!
//! Uses `BTreeMap` for object fields so serialized JSON has deterministic,
//! canonical key ordering suitable for SHA-256 hash chaining in the causal ledger.

use std::collections::BTreeMap;
use std::fmt;

/// Error code returned when a tool call is held/rejected by GenOS Guard policy or Escrow.
pub const JSONRPC_ERR_HELD_BY_GENOS: i64 = -32001;

/// Canonical JSON value representation.
#[derive(Debug, Clone, PartialEq)]
pub enum JsonValue {
    Null,
    Bool(bool),
    Number(f64),
    Int(i64),
    Str(String),
    Array(Vec<JsonValue>),
    Object(BTreeMap<String, JsonValue>),
}

impl JsonValue {
    pub fn as_str(&self) -> Option<&str> {
        match self {
            JsonValue::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_i64(&self) -> Option<i64> {
        match self {
            JsonValue::Int(n) => Some(*n),
            JsonValue::Number(n) => Some(*n as i64),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            JsonValue::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_object(&self) -> Option<&BTreeMap<String, JsonValue>> {
        match self {
            JsonValue::Object(map) => Some(map),
            _ => None,
        }
    }

    pub fn get(&self, key: &str) -> Option<&JsonValue> {
        self.as_object()?.get(key)
    }

    /// Serializes into a compact, single-line canonical JSON string.
    pub fn to_json_line(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out);
        out
    }

    fn write_json(&self, out: &mut String) {
        match self {
            JsonValue::Null => out.push_str("null"),
            JsonValue::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            JsonValue::Int(n) => out.push_str(&n.to_string()),
            JsonValue::Number(n) => {
                if n.fract() == 0.0 && n.abs() < (i64::MAX as f64) {
                    out.push_str(&(*n as i64).to_string());
                } else {
                    out.push_str(&n.to_string());
                }
            }
            JsonValue::Str(s) => {
                out.push('"');
                escape_json_str(s, out);
                out.push('"');
            }
            JsonValue::Array(items) => {
                out.push('[');
                for (i, item) in items.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    item.write_json(out);
                }
                out.push(']');
            }
            JsonValue::Object(map) => {
                out.push('{');
                for (i, (k, v)) in map.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push('"');
                    escape_json_str(k, out);
                    out.push_str("\":");
                    v.write_json(out);
                }
                out.push('}');
            }
        }
    }
}

impl fmt::Display for JsonValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_json_line())
    }
}

pub fn escape_json_str(s: &str, out: &mut String) {
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0C}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
}

/// Parses a single JSON string into a `JsonValue`.
pub fn parse_json(input: &str) -> Result<JsonValue, String> {
    let chars: Vec<char> = input.chars().collect();
    let mut pos = 0;
    skip_ws(&chars, &mut pos);
    let val = parse_value(&chars, &mut pos)?;
    skip_ws(&chars, &mut pos);
    if pos < chars.len() {
        return Err(format!("Trailing characters at position {}", pos));
    }
    Ok(val)
}

fn skip_ws(chars: &[char], pos: &mut usize) {
    while *pos < chars.len() && chars[*pos].is_ascii_whitespace() {
        *pos += 1;
    }
}

fn parse_value(chars: &[char], pos: &mut usize) -> Result<JsonValue, String> {
    skip_ws(chars, pos);
    if *pos >= chars.len() {
        return Err("Unexpected end of JSON input".to_string());
    }
    match chars[*pos] {
        '"' => Ok(JsonValue::Str(parse_string(chars, pos)?)),
        '{' => parse_object(chars, pos),
        '[' => parse_array(chars, pos),
        't' | 'f' => parse_bool(chars, pos),
        'n' => parse_null(chars, pos),
        '-' | '0'..='9' => parse_number(chars, pos),
        c => Err(format!("Unexpected character '{}' at pos {}", c, *pos)),
    }
}

fn parse_string(chars: &[char], pos: &mut usize) -> Result<String, String> {
    if chars.get(*pos) != Some(&'"') {
        return Err(format!("Expected '\"' at pos {}", *pos));
    }
    *pos += 1;
    let mut out = String::new();
    while *pos < chars.len() {
        let c = chars[*pos];
        *pos += 1;
        if c == '"' {
            return Ok(out);
        }
        if c == '\\' {
            if *pos >= chars.len() {
                return Err("Unterminated escape sequence".to_string());
            }
            let esc = chars[*pos];
            *pos += 1;
            match esc {
                '"' => out.push('"'),
                '\\' => out.push('\\'),
                '/' => out.push('/'),
                'b' => out.push('\u{08}'),
                'f' => out.push('\u{0C}'),
                'n' => out.push('\n'),
                'r' => out.push('\r'),
                't' => out.push('\t'),
                'u' => {
                    if *pos + 4 > chars.len() {
                        return Err("Invalid \\uXXXX escape".to_string());
                    }
                    let hex: String = chars[*pos..*pos + 4].iter().collect();
                    *pos += 4;
                    let code = u32::from_str_radix(&hex, 16)
                        .map_err(|_| format!("Invalid hex in \\u{}", hex))?;
                    if let Some(ch) = char::from_u32(code) {
                        out.push(ch);
                    }
                }
                other => out.push(other),
            }
        } else {
            out.push(c);
        }
    }
    Err("Unterminated JSON string".to_string())
}

fn parse_object(chars: &[char], pos: &mut usize) -> Result<JsonValue, String> {
    *pos += 1; // consume '{'
    skip_ws(chars, pos);
    let mut map = BTreeMap::new();
    if chars.get(*pos) == Some(&'}') {
        *pos += 1;
        return Ok(JsonValue::Object(map));
    }
    loop {
        skip_ws(chars, pos);
        let key = parse_string(chars, pos)?;
        skip_ws(chars, pos);
        if chars.get(*pos) != Some(&':') {
            return Err(format!("Expected ':' after object key at pos {}", *pos));
        }
        *pos += 1;
        let val = parse_value(chars, pos)?;
        map.insert(key, val);
        skip_ws(chars, pos);
        match chars.get(*pos) {
            Some(',') => {
                *pos += 1;
            }
            Some('}') => {
                *pos += 1;
                return Ok(JsonValue::Object(map));
            }
            _ => return Err(format!("Expected ',' or '}}' at pos {}", *pos)),
        }
    }
}

fn parse_array(chars: &[char], pos: &mut usize) -> Result<JsonValue, String> {
    *pos += 1; // consume '['
    skip_ws(chars, pos);
    let mut items = Vec::new();
    if chars.get(*pos) == Some(&']') {
        *pos += 1;
        return Ok(JsonValue::Array(items));
    }
    loop {
        let val = parse_value(chars, pos)?;
        items.push(val);
        skip_ws(chars, pos);
        match chars.get(*pos) {
            Some(',') => {
                *pos += 1;
            }
            Some(']') => {
                *pos += 1;
                return Ok(JsonValue::Array(items));
            }
            _ => return Err(format!("Expected ',' or ']' at pos {}", *pos)),
        }
    }
}

fn parse_bool(chars: &[char], pos: &mut usize) -> Result<JsonValue, String> {
    if chars[*pos..].starts_with(&['t', 'r', 'u', 'e']) {
        *pos += 4;
        Ok(JsonValue::Bool(true))
    } else if chars[*pos..].starts_with(&['f', 'a', 'l', 's', 'e']) {
        *pos += 5;
        Ok(JsonValue::Bool(false))
    } else {
        Err(format!("Invalid boolean token at pos {}", *pos))
    }
}

fn parse_null(chars: &[char], pos: &mut usize) -> Result<JsonValue, String> {
    if chars[*pos..].starts_with(&['n', 'u', 'l', 'l']) {
        *pos += 4;
        Ok(JsonValue::Null)
    } else {
        Err(format!("Invalid null token at pos {}", *pos))
    }
}

fn parse_number(chars: &[char], pos: &mut usize) -> Result<JsonValue, String> {
    let start = *pos;
    if chars.get(*pos) == Some(&'-') {
        *pos += 1;
    }
    let mut is_float = false;
    while *pos < chars.len() {
        match chars[*pos] {
            '0'..='9' => *pos += 1,
            '.' | 'e' | 'E' | '+' | '-' => {
                is_float = true;
                *pos += 1;
            }
            _ => break,
        }
    }
    let slice: String = chars[start..*pos].iter().collect();
    if !is_float {
        if let Ok(n) = slice.parse::<i64>() {
            return Ok(JsonValue::Int(n));
        }
    }
    let f = slice
        .parse::<f64>()
        .map_err(|_| format!("Invalid number '{}'", slice))?;
    Ok(JsonValue::Number(f))
}

/// Extracted metadata from a JSON-RPC 2.0 message line.
#[derive(Debug, Clone, PartialEq)]
pub struct RpcSummary {
    /// Request/Response identifier encoded as canonical JSON string (e.g. `1` or `"req-1"`).
    pub id_key: Option<String>,
    /// Raw `JsonValue` of the `id` field.
    pub id_value: Option<JsonValue>,
    /// Method name if this is a Request or Notification.
    pub method: Option<String>,
    /// If `method == "tools/call"`, holds `params.name` and serialized `params.arguments`.
    pub tool_call: Option<ToolCallParams>,
    /// True if the message is a response (`result` or `error` field present, no `method`).
    pub is_response: bool,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ToolCallParams {
    pub tool_name: String,
    pub arguments_json: String,
}

/// Inspects a parsed JSON-RPC message and extracts its routing and tool-call metadata.
pub fn inspect_rpc(val: &JsonValue) -> RpcSummary {
    let id_value = val.get("id").cloned();
    let id_key = id_value.as_ref().map(|v| v.to_json_line());
    let method = val.get("method").and_then(|m| m.as_str()).map(String::from);
    let is_response = method.is_none() && (val.get("result").is_some() || val.get("error").is_some());

    let tool_call = if method.as_deref() == Some("tools/call") {
        val.get("params").and_then(|params| {
            let name = params.get("name")?.as_str()?.to_string();
            let args = params
                .get("arguments")
                .map(|a| a.to_json_line())
                .unwrap_or_else(|| "{}".to_string());
            Some(ToolCallParams {
                tool_name: name,
                arguments_json: args,
            })
        })
    } else {
        None
    };

    RpcSummary {
        id_key,
        id_value,
        method,
        tool_call,
        is_response,
    }
}

/// Builds a standard JSON-RPC 2.0 error response line.
pub fn build_error_response(id: Option<&JsonValue>, code: i64, message: &str) -> String {
    let mut err_obj = BTreeMap::new();
    err_obj.insert("code".to_string(), JsonValue::Int(code));
    err_obj.insert("message".to_string(), JsonValue::Str(message.to_string()));

    let mut root = BTreeMap::new();
    root.insert("jsonrpc".to_string(), JsonValue::Str("2.0".to_string()));
    root.insert("id".to_string(), id.cloned().unwrap_or(JsonValue::Null));
    root.insert("error".to_string(), JsonValue::Object(err_obj));

    JsonValue::Object(root).to_json_line()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_and_extract_tools_call() {
        let raw = r#"{"jsonrpc":"2.0","id":42,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"/tmp/a.txt","content":"hello"}}}"#;
        let parsed = parse_json(raw).expect("valid JSON");
        let summary = inspect_rpc(&parsed);
        assert_eq!(summary.id_key.as_deref(), Some("42"));
        assert_eq!(summary.method.as_deref(), Some("tools/call"));
        assert!(!summary.is_response);
        let tc = summary.tool_call.expect("tool_call extracted");
        assert_eq!(tc.tool_name, "write_file");
        assert!(tc.arguments_json.contains("\"/tmp/a.txt\""));
    }

    #[test]
    fn test_build_error_response_format() {
        let id = JsonValue::Int(7);
        let line = build_error_response(Some(&id), JSONRPC_ERR_HELD_BY_GENOS, "Blocked by GenOS Guard");
        let parsed = parse_json(&line).unwrap();
        assert_eq!(parsed.get("id").unwrap().as_i64(), Some(7));
        let err = parsed.get("error").unwrap();
        assert_eq!(err.get("code").unwrap().as_i64(), Some(-32001));
        assert_eq!(
            err.get("message").unwrap().as_str(),
            Some("Blocked by GenOS Guard")
        );
    }
}
