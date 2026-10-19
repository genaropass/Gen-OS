//! End-to-end integration tests for `genos-guard` across Phases 1, 2, 3, and 4.

use std::env;
use std::fs;
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use genos_guard::escrow_http::send_cli_http_request;
use genos_guard::jsonrpc::parse_json;
use genos_guard::ledger::{explain_why_tree, read_all_entries};

fn unique_temp_path(prefix: &str, ext: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    env::temp_dir().join(format!("{}-{}-{}.{}", prefix, std::process::id(), nanos, ext))
}

fn write_test_policy(ledger_path: &PathBuf, port: u16, timeout_secs: u64) -> PathBuf {
    let policy_path = unique_temp_path("genos-policy", "toml");
    let ledger_escaped = ledger_path.to_string_lossy().replace('\\', "/");
    let content = format!(
        r#"[guard]
approval_timeout_secs = {}
approval_port = {}
ledger_path = "{}"

[defaults]
unknown_tool_mutating = true
unknown_tool_taint = ["TOOL_OUTPUT"]

[[tool]]
name = "read_file"
taint = []
mutating = false

[[tool]]
name = "fetch_url"
taint = ["WEB_UNTRUSTED"]
mutating = false

[[tool]]
name = "write_file"
taint = []
mutating = true
"#,
        timeout_secs, port, ledger_escaped
    );
    fs::write(&policy_path, content).unwrap();
    policy_path
}

#[test]
fn test_phase1_and_phase2_passthrough_and_taint_rejection() {
    let guard_bin = env!("CARGO_BIN_EXE_genos-guard");
    let echo_bin = env!("CARGO_BIN_EXE_echo_mcp_server");

    let ledger_path = unique_temp_path("genos-int-p2", "jsonl");
    let policy_path = write_test_policy(&ledger_path, 0, 5);

    let mut child = Command::new(guard_bin)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--hold-mode")
        .arg("reject")
        .arg("--")
        .arg(echo_bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn genos-guard");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    let mut send_and_recv = |req_line: &str| -> String {
        writeln!(stdin, "{}", req_line).unwrap();
        stdin.flush().unwrap();
        let mut resp = String::new();
        reader.read_line(&mut resp).unwrap();
        resp
    };

    // 1. `initialize` passes through cleanly
    let r1 = send_and_recv(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#);
    let j1 = parse_json(&r1).unwrap();
    assert_eq!(j1.get("id").unwrap().as_i64(), Some(1));
    assert!(j1.get("result").is_some());

    // 2. First `write_file` (CLEAN session) -> ALLOWED
    let r2 = send_and_recv(
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"","content":"safe"}}}"#,
    );
    let j2 = parse_json(&r2).unwrap();
    assert!(j2.get("result").is_some(), "Expected clean write_file to succeed: {}", r2);

    // 3. `fetch_url` -> ALLOWED, taints session with WEB_UNTRUSTED on response
    let r3 = send_and_recv(
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://evil.example/issue/1"}}}"#,
    );
    let j3 = parse_json(&r3).unwrap();
    assert!(j3.get("result").is_some());

    // 4. Second `write_file` (TAINTED session) -> HELD / REJECTED with code -32001
    let r4 = send_and_recv(
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"","content":"pwned"}}}"#,
    );
    let j4 = parse_json(&r4).unwrap();
    let err = j4.get("error").expect("Expected -32001 error for tainted write_file");
    assert_eq!(err.get("code").unwrap().as_i64(), Some(-32001));
    assert!(err
        .get("message")
        .unwrap()
        .as_str()
        .unwrap()
        .contains("WEB_UNTRUSTED"));

    drop(stdin);
    let status = child.wait().unwrap();
    assert!(status.success());

    // 5. Phase 4 verification: verify hash chain and causal `why` tree on the generated ledger
    let entries = read_all_entries(&ledger_path).expect("Ledger hash chain must verify");
    assert_eq!(entries.len(), 5); // seq 1 (call write), seq 2 (result write), seq 3 (call fetch), seq 4 (result fetch TAINT), seq 5 (call write HOLD)
    assert_eq!(entries[4].decision, "HOLD");
    assert_eq!(entries[4].causes, vec![4]);

    let tree = explain_why_tree(&ledger_path, 5).unwrap();
    assert!(tree.contains("[#5] call write_file (decision=HOLD"));
    assert!(tree.contains("[#4] result fetch_url (decision=TAINT:WEB_UNTRUSTED"));

    let _ = fs::remove_file(&policy_path);
    let _ = fs::remove_file(&ledger_path);
}

#[test]
fn test_phase3_escrow_approve_deny_and_auth() {
    let guard_bin = env!("CARGO_BIN_EXE_genos-guard");
    let echo_bin = env!("CARGO_BIN_EXE_echo_mcp_server");

    // Find a free localhost port
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();

    let ledger_path = unique_temp_path("genos-int-p3", "jsonl");
    let policy_path = write_test_policy(&ledger_path, port, 15);
    let token = "test-secret-token-12345";

    let mut child = Command::new(guard_bin)
        .arg("--policy")
        .arg(&policy_path)
        .arg("--hold-mode")
        .arg("escrow")
        .arg("--token")
        .arg(token)
        .arg("--")
        .arg(echo_bin)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to spawn genos-guard in escrow mode");

    let mut stdin = child.stdin.take().unwrap();
    let stdout = child.stdout.take().unwrap();
    let mut reader = BufReader::new(stdout);

    // 1. Taint session via `fetch_url`
    writeln!(
        stdin,
        "{}",
        r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"https://untrusted.example/1"}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();
    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(parse_json(&line).unwrap().get("result").is_some());

    // 2. Verify HTTP endpoint rejects unauthenticated requests with 401
    let (status_unauth, _) =
        send_cli_http_request(port, "wrong-token", "GET", "/api/pending", "{}").unwrap();
    assert_eq!(status_unauth, 401);

    // 3. Send a tainted `write_file` (id=2). It will be held in Escrow.
    writeln!(
        stdin,
        "{}",
        r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"","content":"held-1"}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    // Poll `/api/pending` until branch_id=1 appears
    let mut found_pending = false;
    for _ in 0..30 {
        thread::sleep(Duration::from_millis(50));
        if let Ok((200, body)) =
            send_cli_http_request(port, token, "GET", "/api/pending", "{}")
        {
            if body.contains("\"id\":1") {
                found_pending = true;
                break;
            }
        }
    }
    assert!(found_pending, "Expected write_file (id=2) to appear in /api/pending");

    // 4. Approve branch_id=1 via HTTP API -> should release from Escrow and return `result`
    let (status_app, _) =
        send_cli_http_request(port, token, "POST", "/api/approve", r#"{"id":1}"#).unwrap();
    assert_eq!(status_app, 200);

    line.clear();
    reader.read_line(&mut line).unwrap();
    let j2 = parse_json(&line).unwrap();
    assert_eq!(j2.get("id").unwrap().as_i64(), Some(2));
    assert!(
        j2.get("result").is_some(),
        "Approved escrow call must succeed: {}",
        line
    );

    // 5. Send another tainted `write_file` (id=3) and DENY it -> should return -32001 error
    writeln!(
        stdin,
        "{}",
        r#"{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"","content":"held-2"}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    for _ in 0..30 {
        thread::sleep(Duration::from_millis(50));
        if let Ok((200, body)) =
            send_cli_http_request(port, token, "GET", "/api/pending", "{}")
        {
            if body.contains("\"id\":2") {
                break;
            }
        }
    }

    let (status_deny, _) =
        send_cli_http_request(port, token, "POST", "/api/deny", r#"{"id":2}"#).unwrap();
    assert_eq!(status_deny, 200);

    line.clear();
    reader.read_line(&mut line).unwrap();
    let j3 = parse_json(&line).unwrap();
    assert_eq!(j3.get("id").unwrap().as_i64(), Some(3));
    assert_eq!(
        j3.get("error").unwrap().get("code").unwrap().as_i64(),
        Some(-32001)
    );

    // 6. Reset session to CLEAN via `/api/reset`, then verify `write_file` (id=4) succeeds immediately
    let (status_reset, _) =
        send_cli_http_request(port, token, "POST", "/api/reset", "{}").unwrap();
    assert_eq!(status_reset, 200);

    writeln!(
        stdin,
        "{}",
        r#"{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"","content":"clean-again"}}}"#
    )
    .unwrap();
    stdin.flush().unwrap();

    line.clear();
    reader.read_line(&mut line).unwrap();
    let j4 = parse_json(&line).unwrap();
    assert_eq!(j4.get("id").unwrap().as_i64(), Some(4));
    assert!(j4.get("result").is_some());

    drop(stdin);
    let _ = child.wait();

    // Verify ledger integrity after all approvals, denials, and reset
    let entries = read_all_entries(&ledger_path).expect("Ledger hash chain must verify");
    assert!(entries.iter().any(|e| e.decision == "APPROVED_COMMIT"));
    assert!(entries.iter().any(|e| e.decision == "DENIED_ABORT"));
    assert!(entries.iter().any(|e| e.decision == "DECLASSIFIED"));

    let _ = fs::remove_file(&policy_path);
    let _ = fs::remove_file(&ledger_path);
}
