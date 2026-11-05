//! Session state, DIFC taint tracking, capability enforcement, and pure `decide()` logic.

use capability_engine::{CSpace, CapError, CapId, ObjectId, Permissions};
use causal_core::{SecurityLabel, TaintMask};

use crate::policy::{mask_to_names, Policy};

/// Provenance record of a tool result that tainted the current session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaintSource {
    pub seq: u64,
    pub tool_name: String,
    pub taint_mask: u32,
}

/// Decision returned by `decide()` for an incoming `tools/call`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    Allow {
        reason: String,
    },
    Hold {
        reason: String,
        taint_mask: u32,
        integrity: u16,
        causes: Vec<u64>,
    },
}

/// Session state tracked by `genos-guard` across an MCP connection.
pub struct Session {
    pub label: SecurityLabel,
    pub taint_sources: Vec<TaintSource>,
    pub cspace: CSpace,
    pub declassify_cap: CapId,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Session {
    pub fn new() -> Self {
        let mut cspace = CSpace::new();
        let declassify_cap = cspace.mint_root(
            ObjectId(1),
            Permissions::READ | Permissions::WRITE | Permissions::DECLASSIFY,
            1,
        );
        Self {
            label: SecurityLabel::TRUSTED_KERNEL,
            taint_sources: Vec::new(),
            cspace,
            declassify_cap,
        }
    }

    pub fn is_tainted(&self) -> bool {
        self.label.taint_mask != TaintMask::CLEAN
            || self.label.integrity < SecurityLabel::TRUSTED_KERNEL.integrity
    }

    pub fn cause_seqs(&self) -> Vec<u64> {
        self.taint_sources.iter().map(|s| s.seq).collect()
    }

    /// Updates session security label when a `tools/call` response arrives.
    /// Returns `true` if the tool response introduced taint into the session.
    pub fn on_tool_result(&mut self, policy: &Policy, tool_name: &str, ledger_seq: u64) -> bool {
        let rule = policy.rule_for(tool_name);
        if rule.taint_mask != TaintMask::CLEAN {
            let incoming = SecurityLabel::new(
                SecurityLabel::UNTRUSTED_EXTERNAL.confidentiality,
                SecurityLabel::UNTRUSTED_EXTERNAL.integrity,
                rule.taint_mask,
            );
            self.label = self.label.combine(&incoming);
            self.taint_sources.push(TaintSource {
                seq: ledger_seq,
                tool_name: tool_name.to_string(),
                taint_mask: rule.taint_mask,
            });
            true
        } else {
            false
        }
    }

    /// Explicitly resets (declassifies) the session taint back to `TRUSTED_KERNEL`.
    /// Requires the session's `DECLASSIFY` capability in `CSpace`.
    pub fn reset(&mut self) -> Result<(), CapError> {
        self.cspace
            .verify(self.declassify_cap, Permissions::DECLASSIFY)?;
        let _ = self.label.declassify(u32::MAX);
        self.label = SecurityLabel::TRUSTED_KERNEL;
        self.taint_sources.clear();
        Ok(())
    }
}

/// Pure decision function: evaluates whether `tool_name` is allowed immediately
/// or must be held in Escrow given the current `Policy` and `Session`.
pub fn decide(policy: &Policy, session: &Session, tool_name: &str) -> Decision {
    let rule = policy.rule_for(tool_name);

    if !rule.mutating {
        return Decision::Allow {
            reason: format!("Tool '{}' is non-mutating", tool_name),
        };
    }

    if !session.is_tainted() {
        return Decision::Allow {
            reason: format!(
                "Tool '{}' is mutating ({}), allowed because session is CLEAN (integrity={})",
                tool_name,
                if rule.is_default_fallback {
                    "fail-closed unknown tool"
                } else {
                    "policy rule"
                },
                session.label.integrity
            ),
        };
    }

    let source_summary: Vec<String> = session
        .taint_sources
        .iter()
        .map(|s| {
            format!(
                "#{} {} ({})",
                s.seq,
                s.tool_name,
                mask_to_names(s.taint_mask).join("|")
            )
        })
        .collect();

    let reason = format!(
        "Held by GenOS: session is tainted [{}] by [{}] (integrity={}); mutating tool '{}'{} requires human approval in Escrow",
        mask_to_names(session.label.taint_mask).join("|"),
        source_summary.join(", "),
        session.label.integrity,
        tool_name,
        if rule.is_default_fallback {
            " (unknown tool -> fail-closed)"
        } else {
            ""
        }
    );

    Decision::Hold {
        reason,
        taint_mask: session.label.taint_mask,
        integrity: session.label.integrity,
        causes: session.cause_seqs(),
    }
}

/// Scans an argument JSON payload for high-confidence secret exfiltration patterns
/// (OpenAI/Anthropic `sk-` keys, AWS `AKIA` keys, PEM private keys).
pub fn inspect_dlp_secrets(arguments_json: &str) -> Option<&'static str> {
    if arguments_json.contains("-----BEGIN ") && arguments_json.contains("PRIVATE KEY-----") {
        return Some("PEM Private Key block");
    }
    if arguments_json.contains("sk-proj-") || arguments_json.contains("sk-ant-") {
        return Some("API Secret Key (sk-proj / sk-ant)");
    }
    if arguments_json.contains("AKIA") {
        return Some("AWS Access Key ID (AKIA*)");
    }
    None
}

/// Argument-aware decision evaluator supporting `deny_paths`, `safe_write_paths`, and DLP inspection.
pub fn decide_with_args(
    policy: &Policy,
    session: &Session,
    tool_name: &str,
    arguments_json: &str,
) -> Decision {
    // 1. Check explicit deny_paths (enforced even in CLEAN sessions)
    for forbidden in &policy.defaults.deny_paths {
        if !forbidden.is_empty() && arguments_json.contains(forbidden) {
            return Decision::Hold {
                reason: format!(
                    "Blocked by GenOS path policy: tool '{}' targets denied path pattern '{}'",
                    tool_name, forbidden
                ),
                taint_mask: session.label.taint_mask,
                integrity: session.label.integrity,
                causes: session.cause_seqs(),
            };
        }
    }

    // 2. Check DLP secret patterns on mutating / outbound calls
    let rule = policy.rule_for(tool_name);
    if rule.mutating {
        if let Some(secret_kind) = inspect_dlp_secrets(arguments_json) {
            return Decision::Hold {
                reason: format!(
                    "Blocked by GenOS DLP: outbound arguments for '{}' contain {}",
                    tool_name, secret_kind
                ),
                taint_mask: session.label.taint_mask,
                integrity: session.label.integrity,
                causes: session.cause_seqs(),
            };
        }
    }

    // 3. Check safe_write_paths (reduces alert fatigue in tainted sessions when writing to scratch/tmp)
    if session.is_tainted() && rule.mutating && !policy.defaults.safe_write_paths.is_empty() {
        let is_safe_scratch = policy
            .defaults
            .safe_write_paths
            .iter()
            .any(|safe_prefix| !safe_prefix.is_empty() && arguments_json.contains(safe_prefix));
        if is_safe_scratch {
            return Decision::Allow {
                reason: format!(
                    "Tool '{}' allowed in tainted session via safe_write_paths scope",
                    tool_name
                ),
            };
        }
    }

    decide(policy, session, tool_name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_policy() -> Policy {
        Policy::parse_toml(
            r#"
            [defaults]
            unknown_tool_mutating = true
            unknown_tool_taints = ["TOOL_OUTPUT"]

            [[tool]]
            name = "read_file"
            taints = []
            mutating = false

            [[tool]]
            name = "fetch_url"
            taints = ["WEB_UNTRUSTED"]
            mutating = false

            [[tool]]
            name = "write_file"
            taints = []
            mutating = true
        "#,
        )
        .unwrap()
    }

    #[test]
    fn test_case_1_clean_session_non_mutating_allowed() {
        let policy = sample_policy();
        let session = Session::new();
        assert!(matches!(
            decide(&policy, &session, "read_file"),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn test_case_2_clean_session_mutating_allowed() {
        let policy = sample_policy();
        let session = Session::new();
        assert!(matches!(
            decide(&policy, &session, "write_file"),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn test_case_3_tainted_session_non_mutating_allowed() {
        let policy = sample_policy();
        let mut session = Session::new();
        assert!(session.on_tool_result(&policy, "fetch_url", 5));
        assert!(session.is_tainted());
        assert!(matches!(
            decide(&policy, &session, "read_file"),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn test_case_4_tainted_session_mutating_held_in_escrow() {
        let policy = sample_policy();
        let mut session = Session::new();
        session.on_tool_result(&policy, "fetch_url", 9);

        match decide(&policy, &session, "write_file") {
            Decision::Hold {
                taint_mask,
                causes,
                reason,
                ..
            } => {
                assert_eq!(taint_mask, TaintMask::WEB_UNTRUSTED);
                assert_eq!(causes, vec![9]);
                assert!(reason.contains("fetch_url"));
            }
            other => panic!("Expected Hold, got {:?}", other),
        }
    }

    #[test]
    fn test_case_5_unknown_tool_fails_closed() {
        let policy = sample_policy();
        let mut session = Session::new();
        // Calling an unknown tool taints the session upon completion:
        assert!(session.on_tool_result(&policy, "unlisted_tool", 3));
        assert!(session.is_tainted());

        // Subsequent invocation of an unknown tool is treated as mutating -> HELD!
        match decide(&policy, &session, "another_unlisted_tool") {
            Decision::Hold { causes, reason, .. } => {
                assert_eq!(causes, vec![3]);
                assert!(reason.contains("fail-closed"));
            }
            other => panic!("Expected Hold for unknown tool, got {:?}", other),
        }
    }

    #[test]
    fn test_case_6_explicit_session_reset_declassifies() {
        let policy = sample_policy();
        let mut session = Session::new();
        session.on_tool_result(&policy, "fetch_url", 11);
        assert!(session.is_tainted());

        session.reset().expect("DECLASSIFY capability valid");
        assert!(!session.is_tainted());
        assert!(session.taint_sources.is_empty());
        assert!(matches!(
            decide(&policy, &session, "write_file"),
            Decision::Allow { .. }
        ));
    }

    #[test]
    fn test_case_7_scoped_paths_and_dlp_secret_protection() {
        let policy = Policy::parse_toml(
            r#"
            [defaults]
            unknown_tool_mutating = true
            unknown_tool_taints = ["TOOL_OUTPUT"]
            deny_paths = [".env", ".ssh/id_rsa"]
            safe_write_paths = ["scratch/", "tmp/"]

            [[tool]]
            name = "fetch_url"
            taints = ["WEB_UNTRUSTED"]
            mutating = false

            [[tool]]
            name = "write_file"
            taints = []
            mutating = true
        "#,
        )
        .unwrap();

        let mut session = Session::new();
        // Even in a CLEAN session, touching `.env` or leaking a PEM key is held/blocked:
        assert!(matches!(
            decide_with_args(
                &policy,
                &session,
                "write_file",
                r#"{"path":".env","content":"A=B"}"#
            ),
            Decision::Hold { .. }
        ));
        assert!(matches!(
            decide_with_args(
                &policy,
                &session,
                "write_file",
                r#"{"path":"out.txt","content":"-----BEGIN RSA PRIVATE KEY-----"}"#
            ),
            Decision::Hold { .. }
        ));

        // Now taint the session via `fetch_url`:
        session.on_tool_result(&policy, "fetch_url", 2);
        assert!(session.is_tainted());

        // Writing to `scratch/notes.md` is allowed without alert fatigue!
        assert!(matches!(
            decide_with_args(
                &policy,
                &session,
                "write_file",
                r#"{"path":"scratch/notes.md","content":"draft summary"}"#
            ),
            Decision::Allow { .. }
        ));

        // Writing outside `scratch/` in a tainted session is still held in Escrow:
        assert!(matches!(
            decide_with_args(
                &policy,
                &session,
                "write_file",
                r#"{"path":"src/main.rs","content":"modified code"}"#
            ),
            Decision::Hold { .. }
        ));
    }
}
