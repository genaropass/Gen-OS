//! Policy parser and fail-closed rule evaluator for `genos-guard`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use causal_core::TaintMask;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuardSection {
    pub approval_timeout_secs: u64,
    pub approval_port: u16,
    pub ledger_path: PathBuf,
}

impl Default for GuardSection {
    fn default() -> Self {
        Self {
            approval_timeout_secs: 120,
            approval_port: 7878,
            ledger_path: PathBuf::from("genos-ledger.jsonl"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DefaultsSection {
    pub unknown_tool_mutating: bool,
    pub unknown_tool_taint_mask: u32,
}

impl Default for DefaultsSection {
    fn default() -> Self {
        Self {
            unknown_tool_mutating: true,
            unknown_tool_taint_mask: TaintMask::TOOL_OUTPUT,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolRule {
    pub name: String,
    pub taint_mask: u32,
    pub taint_names: Vec<String>,
    pub mutating: bool,
    pub is_default_fallback: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Policy {
    pub guard: GuardSection,
    pub defaults: DefaultsSection,
    pub tools: BTreeMap<String, ToolRule>,
}

impl Policy {
    /// Loads and validates a TOML policy file from disk.
    /// Fails closed on any I/O or syntax error.
    pub fn from_file(path: &Path) -> Result<Self, String> {
        let content = fs::read_to_string(path)
            .map_err(|e| format!("Failed to read policy file '{}': {}", path.display(), e))?;
        Self::parse_toml(&content)
    }

    /// Parses a TOML string into a `Policy`.
    pub fn parse_toml(input: &str) -> Result<Self, String> {
        let mut policy = Policy::default();

        #[derive(PartialEq)]
        enum Section {
            None,
            Guard,
            Defaults,
            Tool,
        }

        let mut current_section = Section::None;
        let mut current_tool: Option<(Option<String>, Option<u32>, Vec<String>, Option<bool>)> =
            None;

        let flush_tool =
            |tool_state: &mut Option<(Option<String>, Option<u32>, Vec<String>, Option<bool>)>,
             tools_map: &mut BTreeMap<String, ToolRule>|
             -> Result<(), String> {
                if let Some((name_opt, mask_opt, names, mut_opt)) = tool_state.take() {
                    let name = name_opt
                        .ok_or_else(|| "[[tool]] block is missing required 'name' field".to_string())?;
                    if name.trim().is_empty() {
                        return Err("[[tool]] 'name' cannot be empty".to_string());
                    }
                    let rule = ToolRule {
                        name: name.clone(),
                        taint_mask: mask_opt.unwrap_or(TaintMask::CLEAN),
                        taint_names: names,
                        mutating: mut_opt.unwrap_or(true), // Fail-closed if omitted
                        is_default_fallback: false,
                    };
                    tools_map.insert(name, rule);
                }
                Ok(())
            };

        for (idx, raw_line) in input.lines().enumerate() {
            let line_no = idx + 1;
            let line = strip_toml_comment(raw_line).trim();
            if line.is_empty() {
                continue;
            }

            if line == "[guard]" {
                flush_tool(&mut current_tool, &mut policy.tools)?;
                current_section = Section::Guard;
                continue;
            } else if line == "[defaults]" {
                flush_tool(&mut current_tool, &mut policy.tools)?;
                current_section = Section::Defaults;
                continue;
            } else if line == "[[tool]]" {
                flush_tool(&mut current_tool, &mut policy.tools)?;
                current_section = Section::Tool;
                current_tool = Some((None, None, Vec::new(), None));
                continue;
            } else if line.starts_with('[') {
                return Err(format!("Line {}: Unknown section '{}'", line_no, line));
            }

            let (k_raw, v_raw) = line
                .split_once('=')
                .ok_or_else(|| format!("Line {}: Expected 'key = value'", line_no))?;
            let key = k_raw.trim();
            let val = v_raw.trim();

            match current_section {
                Section::None => {
                    return Err(format!(
                        "Line {}: Key '{}' outside of any section",
                        line_no, key
                    ))
                }
                Section::Guard => match key {
                    "approval_timeout_secs" => {
                        let secs = val.parse::<u64>().map_err(|_| {
                            format!("Line {}: Invalid integer for approval_timeout_secs", line_no)
                        })?;
                        policy.guard.approval_timeout_secs = secs;
                    }
                    "approval_port" => {
                        let port = val.parse::<u16>().map_err(|_| {
                            format!("Line {}: Invalid port for approval_port", line_no)
                        })?;
                        policy.guard.approval_port = port;
                    }
                    "ledger_path" => {
                        let s = parse_toml_string(val, line_no)?;
                        policy.guard.ledger_path = PathBuf::from(s);
                    }
                    other => {
                        return Err(format!(
                            "Line {}: Unknown key '{}' in [guard]",
                            line_no, other
                        ))
                    }
                },
                Section::Defaults => match key {
                    "unknown_tool_mutating" => {
                        policy.defaults.unknown_tool_mutating = parse_toml_bool(val, line_no)?;
                    }
                    "unknown_tool_taint" | "unknown_tool_taints" => {
                        let (mask, _) = parse_taint_array(val, line_no)?;
                        policy.defaults.unknown_tool_taint_mask = mask;
                    }
                    other => {
                        return Err(format!(
                            "Line {}: Unknown key '{}' in [defaults]",
                            line_no, other
                        ))
                    }
                },
                Section::Tool => {
                    let state = current_tool.as_mut().unwrap();
                    match key {
                        "name" => {
                            state.0 = Some(parse_toml_string(val, line_no)?);
                        }
                        "taint" | "taints" => {
                            let (mask, names) = parse_taint_array(val, line_no)?;
                            state.1 = Some(mask);
                            state.2 = names;
                        }
                        "mutating" => {
                            state.3 = Some(parse_toml_bool(val, line_no)?);
                        }
                        other => {
                            return Err(format!(
                                "Line {}: Unknown key '{}' in [[tool]]",
                                line_no, other
                            ))
                        }
                    }
                }
            }
        }

        flush_tool(&mut current_tool, &mut policy.tools)?;
        Ok(policy)
    }

    /// Returns the effective rule for `tool_name`.
    /// Unknown tools fall back to the `[defaults]` fail-closed policy.
    pub fn rule_for(&self, tool_name: &str) -> ToolRule {
        if let Some(rule) = self.tools.get(tool_name) {
            rule.clone()
        } else {
            ToolRule {
                name: tool_name.to_string(),
                taint_mask: self.defaults.unknown_tool_taint_mask,
                taint_names: mask_to_names(self.defaults.unknown_tool_taint_mask),
                mutating: self.defaults.unknown_tool_mutating,
                is_default_fallback: true,
            }
        }
    }
}

pub fn mask_to_names(mask: u32) -> Vec<String> {
    let mut out = Vec::new();
    if mask & TaintMask::WEB_UNTRUSTED != 0 {
        out.push("WEB_UNTRUSTED".to_string());
    }
    if mask & TaintMask::TOOL_OUTPUT != 0 {
        out.push("TOOL_OUTPUT".to_string());
    }
    if mask & TaintMask::SPECULATIVE_BRANCH != 0 {
        out.push("SPECULATIVE_BRANCH".to_string());
    }
    if mask & TaintMask::ADVERSARIAL_INJECTION != 0 {
        out.push("ADVERSARIAL_INJECTION".to_string());
    }
    out
}

fn strip_toml_comment(line: &str) -> &str {
    let mut in_quotes = false;
    for (idx, ch) in line.char_indices() {
        if ch == '"' {
            in_quotes = !in_quotes;
        } else if ch == '#' && !in_quotes {
            return &line[..idx];
        }
    }
    line
}

fn parse_toml_string(val: &str, line_no: usize) -> Result<String, String> {
    let v = val.trim();
    if v.len() >= 2 && v.starts_with('"') && v.ends_with('"') {
        Ok(v[1..v.len() - 1].to_string())
    } else {
        Err(format!("Line {}: Expected quoted string, got '{}'", line_no, v))
    }
}

fn parse_toml_bool(val: &str, line_no: usize) -> Result<bool, String> {
    match val.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(format!("Line {}: Expected boolean, got '{}'", line_no, other)),
    }
}

fn parse_taint_array(val: &str, line_no: usize) -> Result<(u32, Vec<String>), String> {
    let v = val.trim();
    if !v.starts_with('[') || !v.ends_with(']') {
        return Err(format!(
            "Line {}: Expected array of taint strings, got '{}'",
            line_no, v
        ));
    }
    let inner = v[1..v.len() - 1].trim();
    if inner.is_empty() {
        return Ok((TaintMask::CLEAN, Vec::new()));
    }
    let mut mask = TaintMask::CLEAN;
    let mut names = Vec::new();
    for item in inner.split(',') {
        let trimmed = item.trim();
        if trimmed.is_empty() {
            continue;
        }
        let s = parse_toml_string(trimmed, line_no)?;
        let bit = match s.as_str() {
            "CLEAN" => TaintMask::CLEAN,
            "WEB_UNTRUSTED" => TaintMask::WEB_UNTRUSTED,
            "TOOL_OUTPUT" => TaintMask::TOOL_OUTPUT,
            "SPECULATIVE_BRANCH" => TaintMask::SPECULATIVE_BRANCH,
            "ADVERSARIAL_INJECTION" => TaintMask::ADVERSARIAL_INJECTION,
            other => {
                return Err(format!(
                    "Line {}: Unknown taint label '{}'",
                    line_no, other
                ))
            }
        };
        mask |= bit;
        names.push(s);
    }
    Ok((mask, names))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_valid_policy_and_fail_closed_defaults() {
        let toml = r#"
            [guard]
            approval_timeout_secs = 90
            approval_port = 7999
            ledger_path = "custom.jsonl"

            [defaults]
            unknown_tool_mutating = true
            unknown_tool_taints = ["TOOL_OUTPUT"]

            [[tool]]
            name = "fetch_url"
            taints = ["WEB_UNTRUSTED"]
            mutating = false

            [[tool]]
            name = "write_file"
            taints = []
            mutating = true
        "#;

        let policy = Policy::parse_toml(toml).expect("valid policy");
        assert_eq!(policy.guard.approval_timeout_secs, 90);
        assert_eq!(policy.guard.approval_port, 7999);

        let fetch = policy.rule_for("fetch_url");
        assert_eq!(fetch.taint_mask, TaintMask::WEB_UNTRUSTED);
        assert!(!fetch.mutating);
        assert!(!fetch.is_default_fallback);

        let write = policy.rule_for("write_file");
        assert_eq!(write.taint_mask, TaintMask::CLEAN);
        assert!(write.mutating);

        let unknown = policy.rule_for("mysterious_shell_exec");
        assert!(unknown.is_default_fallback);
        assert!(unknown.mutating);
        assert_eq!(unknown.taint_mask, TaintMask::TOOL_OUTPUT);
    }

    #[test]
    fn test_invalid_policy_rejected() {
        let bad = r#"
            [[tool]]
            name = "fetch_url"
            taints = ["NOT_A_REAL_TAINT"]
        "#;
        assert!(Policy::parse_toml(bad).is_err());
    }
}
