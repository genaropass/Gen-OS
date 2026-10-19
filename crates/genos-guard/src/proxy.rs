//! Bidirectional MCP stdio proxy with DIFC taint enforcement and Escrow holding.
//!
//! Invariants:
//! - `stdout` is strictly reserved for newline-delimited JSON-RPC 2.0 messages to the MCP host.
//! - All diagnostic and audit logs go to `stderr`.
//! - Held tool calls in `HoldMode::Escrow` wait on a background worker thread so non-mutating
//!   requests on the same session are never blocked.

use std::io::{self, BufRead, BufReader, Write};
use std::process::{ChildStdin, Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use crate::escrow_http::{generate_session_token, spawn_approval_http_server, GuardRuntimeState};
use crate::jsonrpc::{
    build_error_response, inspect_rpc, parse_json, JsonValue, JSONRPC_ERR_HELD_BY_GENOS,
};
use crate::policy::{mask_to_names, Policy};
use crate::session::{decide, Decision};

/// Controls how `genos-guard` handles a `Decision::Hold` event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HoldMode {
    /// Holds the tool call in `EscrowManager` and waits up to `approval_timeout_secs`
    /// for human approval via the localhost UI or CLI (`approve` / `deny`).
    Escrow,
    /// Immediately rejects the held tool call with JSON-RPC error `-32001` (no wait).
    Reject,
}

/// Configuration for running the `genos-guard` stdio proxy.
pub struct ProxyConfig {
    pub policy: Policy,
    pub hold_mode: HoldMode,
    pub token_override: Option<String>,
    pub child_program: String,
    pub child_args: Vec<String>,
}

/// Runs the MCP stdio proxy until `stdin` closes and the child MCP server exits.
/// Returns the child process exit code.
pub fn run_stdio_proxy(config: ProxyConfig) -> Result<i32, String> {
    let mut child = Command::new(&config.child_program)
        .args(&config.child_args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| {
            format!(
                "Failed to spawn MCP server '{}': {}",
                config.child_program, e
            )
        })?;

    let child_stdin = child
        .stdin
        .take()
        .ok_or_else(|| "Failed to capture child stdin".to_string())?;
    let child_stdout = child
        .stdout
        .take()
        .ok_or_else(|| "Failed to capture child stdout".to_string())?;

    let approval_port = config.policy.guard.approval_port;
    let approval_timeout_secs = config.policy.guard.approval_timeout_secs;
    let runtime_state = Arc::new(Mutex::new(GuardRuntimeState::new(config.policy)?));

    let token = config
        .token_override
        .unwrap_or_else(generate_session_token);

    let bound_port = if config.hold_mode == HoldMode::Escrow {
        spawn_approval_http_server(Arc::clone(&runtime_state), approval_port, token.clone())?
    } else {
        0
    };

    let child_stdin_arc = Arc::new(Mutex::new(child_stdin));
    let host_stdout_arc: Arc<Mutex<Box<dyn Write + Send>>> =
        Arc::new(Mutex::new(Box::new(io::stdout())));

    // Thread 1: Child stdout -> Host stdout (inspects responses for taint propagation)
    let state_for_stdout = Arc::clone(&runtime_state);
    let host_out_for_stdout = Arc::clone(&host_stdout_arc);
    let stdout_handle = thread::spawn(move || {
        let reader = BufReader::new(child_stdout);
        for line_res in reader.lines() {
            match line_res {
                Ok(line) => {
                    handle_server_to_client_line(&line, &state_for_stdout, &host_out_for_stdout);
                }
                Err(e) => {
                    eprintln!("[genos-guard] Error reading child stdout: {}", e);
                    break;
                }
            }
        }
    });

    // Main loop: Host stdin -> Child stdin (inspects `tools/call` for DIFC & Escrow)
    let stdin = io::stdin();
    let reader = BufReader::new(stdin.lock());
    let mut escrow_wait_handles = Vec::new();

    for line_res in reader.lines() {
        match line_res {
            Ok(line) => {
                if line.trim().is_empty() {
                    continue;
                }
                if let Some(handle) = handle_client_to_server_line(
                    &line,
                    config.hold_mode,
                    bound_port,
                    &token,
                    approval_timeout_secs,
                    &runtime_state,
                    &child_stdin_arc,
                    &host_stdout_arc,
                ) {
                    escrow_wait_handles.push(handle);
                }
            }
            Err(e) => {
                eprintln!("[genos-guard] Error reading host stdin: {}", e);
                break;
            }
        }
    }

    // Wait for any in-flight Escrow decisions to complete before closing child stdin
    for h in escrow_wait_handles {
        let _ = h.join();
    }

    // Drop our reference to child_stdin so the child sees EOF and terminates cleanly
    drop(child_stdin_arc);

    let _ = stdout_handle.join();

    let status = child
        .wait()
        .map_err(|e| format!("Failed waiting for child process: {}", e))?;
    Ok(status.code().unwrap_or(1))
}

#[allow(clippy::too_many_arguments)]
fn handle_client_to_server_line(
    raw_line: &str,
    hold_mode: HoldMode,
    bound_port: u16,
    token: &str,
    approval_timeout_secs: u64,
    runtime_state: &Arc<Mutex<GuardRuntimeState>>,
    child_stdin: &Arc<Mutex<ChildStdin>>,
    host_stdout: &Arc<Mutex<Box<dyn Write + Send>>>,
) -> Option<thread::JoinHandle<()>> {
    let parsed = match parse_json(raw_line) {
        Ok(val) => val,
        Err(_) => {
            // Forward non-JSON or malformed lines transparently so the MCP server can reply with its own parse error
            forward_to_child(child_stdin, raw_line);
            return None;
        }
    };

    let summary = inspect_rpc(&parsed);
    let tc = match summary.tool_call {
        Some(tc) => tc,
        None => {
            // Non-tool call (`initialize`, `tools/list`, notifications, etc.) -> transparent passthrough
            forward_to_child(child_stdin, raw_line);
            return None;
        }
    };

    // Ensure any already-forwarded tool call has returned its response from the MCP server
    // before evaluating the next tool call (guarantees deterministic causal ordering in piped batch mode
    // while never blocking when another call is held in Escrow, since held calls are in `pending`, not `inflight_calls`).
    for _ in 0..500 {
        let has_inflight = runtime_state
            .lock()
            .map(|g| !g.inflight_calls.is_empty())
            .unwrap_or(false);
        if !has_inflight {
            break;
        }
        thread::sleep(Duration::from_millis(2));
    }

    // Evaluate policy + session taint inside state lock
    let mut guard = match runtime_state.lock() {
        Ok(g) => g,
        Err(_) => return None,
    };

    let decision = decide(&guard.policy, &guard.session, &tc.tool_name);
    match decision {
        Decision::Allow { reason } => {
            let causes = guard.session.cause_seqs();
            let session_label = guard.session.label;
            let seq = guard
                .ledger
                .append(
                    "call",
                    &tc.tool_name,
                    "ALLOW",
                    session_label,
                    causes,
                    &tc.arguments_json,
                )
                .map(|e| e.seq)
                .unwrap_or(0);

            if let Some(id_key) = summary.id_key {
                guard
                    .inflight_calls
                    .insert(id_key, (tc.tool_name.clone(), seq));
            }
            eprintln!(
                "[genos-guard] ALLOW seq=#{} tool='{}' ({})",
                seq, tc.tool_name, reason
            );
            drop(guard);
            forward_to_child(child_stdin, raw_line);
            None
        }
        Decision::Hold {
            reason,
            taint_mask,
            integrity,
            causes,
        } => {
            let session_label = guard.session.label;
            let seq = guard
                .ledger
                .append(
                    "call",
                    &tc.tool_name,
                    "HOLD",
                    session_label,
                    causes.clone(),
                    &tc.arguments_json,
                )
                .map(|e| e.seq)
                .unwrap_or(0);

            let taint_names = mask_to_names(taint_mask).join("|");
            eprintln!(
                "[genos-guard] HOLD  seq=#{} tool='{}' taint={} integrity={} causes={:?} reason=\"{}\"",
                seq, tc.tool_name, taint_names, integrity, causes, reason
            );

            if hold_mode == HoldMode::Reject {
                drop(guard);
                let msg = format!(
                    "Held by GenOS Guard (seq #{}, taint={}, integrity={}): {}",
                    seq, taint_names, integrity, reason
                );
                let err_line = build_error_response(
                    summary.id_value.as_ref(),
                    JSONRPC_ERR_HELD_BY_GENOS,
                    &msg,
                );
                write_to_host(host_stdout, &err_line);
                return None;
            }

            // HoldMode::Escrow: stage in EscrowManager and wait on a worker thread
            let (branch_id, rx) = guard.stage_held_call(
                seq,
                tc.tool_name.clone(),
                tc.arguments_json.clone(),
                raw_line,
                reason.clone(),
            );
            drop(guard);

            eprintln!(
                "[genos-guard] ESCROW branch=#{} staged for tool '{}'. Approve via UI http://127.0.0.1:{}/?token={} or CLI `genos-guard approve {} --port {} --token {}`",
                branch_id, tc.tool_name, bound_port, token, branch_id, bound_port, token
            );

            let state_clone = Arc::clone(runtime_state);
            let child_in_clone = Arc::clone(child_stdin);
            let host_out_clone = Arc::clone(host_stdout);
            let raw_line_owned = raw_line.to_string();
            let id_val_owned: Option<JsonValue> = summary.id_value;
            let id_key_owned = summary.id_key;
            let tool_name_owned = tc.tool_name;

            let handle = thread::spawn(move || {
                match rx.recv_timeout(Duration::from_secs(approval_timeout_secs)) {
                    Ok(true) => {
                        // Human approved -> record inflight call and forward raw request line to child MCP server
                        if let Some(id_key) = id_key_owned {
                            if let Ok(mut g) = state_clone.lock() {
                                g.inflight_calls
                                    .insert(id_key, (tool_name_owned.clone(), seq));
                            }
                        }
                        eprintln!(
                            "[genos-guard] ESCROW branch=#{} APPROVED -> forwarding '{}' to MCP server",
                            branch_id, tool_name_owned
                        );
                        forward_to_child(&child_in_clone, &raw_line_owned);
                    }
                    Ok(false) => {
                        // Human denied -> return JSON-RPC error -32001 to MCP host
                        eprintln!(
                            "[genos-guard] ESCROW branch=#{} DENIED -> aborting '{}' in O(1)",
                            branch_id, tool_name_owned
                        );
                        let msg = format!(
                            "Held by GenOS Guard and denied by operator (escrow #{}, seq #{}): {}",
                            branch_id, seq, reason
                        );
                        let err_line = build_error_response(
                            id_val_owned.as_ref(),
                            JSONRPC_ERR_HELD_BY_GENOS,
                            &msg,
                        );
                        write_to_host(&host_out_clone, &err_line);
                    }
                    Err(_) => {
                        // Timeout -> fail-closed O(1) abort
                        if let Ok(mut g) = state_clone.lock() {
                            g.timeout_pending(branch_id);
                        }
                        eprintln!(
                            "[genos-guard] ESCROW branch=#{} TIMED OUT after {}s -> fail-closed abort",
                            branch_id, approval_timeout_secs
                        );
                        let msg = format!(
                            "Held by GenOS Guard: approval timed out after {}s (escrow #{}, seq #{})",
                            approval_timeout_secs, branch_id, seq
                        );
                        let err_line = build_error_response(
                            id_val_owned.as_ref(),
                            JSONRPC_ERR_HELD_BY_GENOS,
                            &msg,
                        );
                        write_to_host(&host_out_clone, &err_line);
                    }
                }
            });

            Some(handle)
        }
    }
}

fn handle_server_to_client_line(
    raw_line: &str,
    runtime_state: &Arc<Mutex<GuardRuntimeState>>,
    host_stdout: &Arc<Mutex<Box<dyn Write + Send>>>,
) {
    if let Ok(parsed) = parse_json(raw_line) {
        let summary = inspect_rpc(&parsed);
        if summary.is_response {
            if let Some(id_key) = summary.id_key {
                if let Ok(mut guard) = runtime_state.lock() {
                    if let Some((tool_name, call_seq)) = guard.inflight_calls.remove(&id_key) {
                        let policy_clone = guard.policy.clone();
                        let rule = policy_clone.rule_for(&tool_name);
                        // Compute the ledger seq that will be assigned to this result entry
                        let result_seq = guard.ledger.next_seq();
                        let tainted =
                            guard
                                .session
                                .on_tool_result(&policy_clone, &tool_name, result_seq);
                        let decision_tag = if tainted {
                            format!("TAINT:{}", mask_to_names(rule.taint_mask).join("|"))
                        } else {
                            "CLEAN".to_string()
                        };
                        let session_label = guard.session.label;
                        let _ = guard.ledger.append(
                            "result",
                            &tool_name,
                            &decision_tag,
                            session_label,
                            vec![call_seq],
                            raw_line,
                        );
                        if tainted {
                            eprintln!(
                                "[genos-guard] TAINT seq=#{} tool='{}' tainted session with {} (integrity now {})",
                                result_seq,
                                tool_name,
                                decision_tag,
                                guard.session.label.integrity
                            );
                        }
                    }
                }
            }
        }
    }

    write_to_host(host_stdout, raw_line);
}

fn forward_to_child(child_stdin: &Arc<Mutex<ChildStdin>>, line: &str) {
    if let Ok(mut stdin) = child_stdin.lock() {
        let _ = stdin.write_all(line.as_bytes());
        let _ = stdin.write_all(b"\n");
        let _ = stdin.flush();
    }
}

fn write_to_host(host_stdout: &Arc<Mutex<Box<dyn Write + Send>>>, line: &str) {
    if let Ok(mut out) = host_stdout.lock() {
        let _ = out.write_all(line.as_bytes());
        let _ = out.write_all(b"\n");
        let _ = out.flush();
    }
}
