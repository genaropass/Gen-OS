//! Localhost-only (`127.0.0.1`) Escrow Human Approval Server and CLI client.

use std::collections::hash_map::RandomState;
use std::collections::BTreeMap;
use std::hash::{BuildHasher, Hasher};
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use causal_core::hash::sha256;
use causal_core::{BranchId, EffectId, EscrowManager};

use crate::jsonrpc::{parse_json, JsonValue};
use crate::ledger::{bytes_to_hex, explain_why_tree, LedgerWriter};
use crate::policy::{mask_to_names, Policy};
use crate::session::Session;

/// Information about a single held `tools/call` awaiting human decision in Escrow.
pub struct PendingEscrowItem {
    pub branch_id: u32,
    pub ledger_seq: u64,
    pub tool_name: String,
    pub arguments_json: String,
    pub reason: String,
    pub why_tree: String,
    pub responder: Sender<bool>,
}

/// Shared state protected by a Mutex across the MCP relay threads and the HTTP server.
pub struct GuardRuntimeState {
    pub policy: Policy,
    pub session: Session,
    pub escrow: EscrowManager,
    pub ledger: LedgerWriter,
    pub next_branch_id: u32,
    pub pending: BTreeMap<u32, PendingEscrowItem>,
    pub inflight_calls: BTreeMap<String, (String, u64)>,
}

impl GuardRuntimeState {
    pub fn new(policy: Policy) -> Result<Self, String> {
        let ledger = LedgerWriter::open(&policy.guard.ledger_path)?;
        Ok(Self {
            policy,
            session: Session::new(),
            escrow: EscrowManager::new(),
            ledger,
            next_branch_id: 1,
            pending: BTreeMap::new(),
            inflight_calls: BTreeMap::new(),
        })
    }

    /// Stages a held tool call in `EscrowManager` and returns `(branch_id, Receiver<bool>)`.
    pub fn stage_held_call(
        &mut self,
        ledger_seq: u64,
        tool_name: String,
        arguments_json: String,
        raw_request_line: &str,
        reason: String,
    ) -> (u32, Receiver<bool>) {
        let branch_id = self.next_branch_id;
        self.next_branch_id = self.next_branch_id.wrapping_add(1).max(1);

        self.escrow.stage_action(
            BranchId(branch_id),
            EffectId(ledger_seq),
            raw_request_line.as_bytes().to_vec(),
        );

        let why_tree = explain_why_tree(&self.policy.guard.ledger_path, ledger_seq)
            .unwrap_or_else(|_| format!("[#{}] HOLD {}", ledger_seq, tool_name));

        let (tx, rx) = mpsc::channel();
        self.pending.insert(
            branch_id,
            PendingEscrowItem {
                branch_id,
                ledger_seq,
                tool_name,
                arguments_json,
                reason,
                why_tree,
                responder: tx,
            },
        );

        (branch_id, rx)
    }

    /// Resolves a pending Escrow item (`approve = true` commits branch; `false` aborts in O(1)).
    pub fn resolve_pending(&mut self, branch_id: u32, approve: bool, actor: &str) -> Result<(), String> {
        let item = self
            .pending
            .remove(&branch_id)
            .ok_or_else(|| format!("Escrow item #{} not found or already resolved", branch_id))?;

        let decision_str = if approve {
            let released = self.escrow.commit_branch(BranchId(branch_id));
            if released.is_empty() {
                return Err(format!("Escrow branch #{} had no staged actions", branch_id));
            }
            "APPROVED_COMMIT"
        } else {
            self.escrow.abort_branch(BranchId(branch_id));
            "DENIED_ABORT"
        };

        let _ = self.ledger.append(
            "approval",
            &item.tool_name,
            decision_str,
            self.session.label,
            vec![item.ledger_seq],
            &format!("escrow_id={} actor={} approve={}", branch_id, actor, approve),
        );

        let _ = item.responder.send(approve);
        Ok(())
    }

    /// Called when an Escrow wait times out: aborts the branch in O(1) and removes the pending entry.
    pub fn timeout_pending(&mut self, branch_id: u32) {
        if let Some(item) = self.pending.remove(&branch_id) {
            self.escrow.abort_branch(BranchId(branch_id));
            let _ = self.ledger.append(
                "approval",
                &item.tool_name,
                "TIMEOUT_ABORT",
                self.session.label,
                vec![item.ledger_seq],
                &format!("escrow_id={} timed out -> fail-closed abort", branch_id),
            );
        }
    }

    /// Resets (declassifies) the session back to `TRUSTED_KERNEL`.
    pub fn reset_session(&mut self, actor: &str) -> Result<(), String> {
        let causes = self.session.cause_seqs();
        self.session
            .reset()
            .map_err(|e| format!("Failed capability verification for DECLASSIFY: {:?}", e))?;
        let _ = self.ledger.append(
            "reset",
            "session",
            "DECLASSIFIED",
            self.session.label,
            causes,
            &format!("Session reset to CLEAN by {}", actor),
        );
        Ok(())
    }
}

/// Generates a 128-bit random hex token for authenticating the localhost approval UI.
pub fn generate_session_token() -> String {
    let s1 = RandomState::new();
    let s2 = RandomState::new();
    let mut h1 = s1.build_hasher();
    let mut h2 = s2.build_hasher();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    h1.write_u128(nanos);
    h1.write_u32(std::process::id());
    h2.write_usize(&nanos as *const _ as usize);

    let mut seed = [0u8; 24];
    seed[0..8].copy_from_slice(&h1.finish().to_le_bytes());
    seed[8..16].copy_from_slice(&h2.finish().to_le_bytes());
    seed[16..24].copy_from_slice(&(nanos as u64).to_be_bytes());
    let digest = sha256(&seed);
    bytes_to_hex(&digest[0..16])
}

/// Starts the background HTTP server on `127.0.0.1:<port>`.
/// Returns the actual bound port (useful when `port == 0` in tests).
pub fn spawn_approval_http_server(
    state: Arc<Mutex<GuardRuntimeState>>,
    port: u16,
    token: String,
) -> Result<u16, String> {
    let listener = TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| format!("Failed to bind approval server on 127.0.0.1:{}: {}", port, e))?;
    let local_port = listener
        .local_addr()
        .map_err(|e| format!("Failed to query local_addr: {}", e))?
        .port();

    eprintln!(
        "[genos-guard] Approval UI: http://127.0.0.1:{}/?token={}",
        local_port, token
    );

    thread::spawn(move || {
        for stream_res in listener.incoming() {
            if let Ok(stream) = stream_res {
                let st = Arc::clone(&state);
                let tk = token.clone();
                thread::spawn(move || {
                    let _ = handle_http_connection(stream, st, &tk);
                });
            }
        }
    });

    Ok(local_port)
}

fn handle_http_connection(
    mut stream: TcpStream,
    state: Arc<Mutex<GuardRuntimeState>>,
    expected_token: &str,
) -> Result<(), String> {
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let mut buf = [0u8; 8192];
    let n = stream.read(&mut buf).map_err(|e| e.to_string())?;
    if n == 0 {
        return Ok(());
    }
    let raw = String::from_utf8_lossy(&buf[..n]);
    let (header_part, body_part) = raw.split_once("\r\n\r\n").unwrap_or((&raw, ""));
    let mut lines = header_part.lines();
    let req_line = lines.next().unwrap_or("");
    let parts: Vec<&str> = req_line.split_whitespace().collect();
    if parts.len() < 2 {
        return send_http_response(&mut stream, 400, "text/plain", "Bad Request");
    }
    let method = parts[0];
    let full_target = parts[1];
    let (path, query) = full_target.split_once('?').unwrap_or((full_target, ""));

    // Extract token from header `X-Genos-Token` or query parameter `token=...`
    let mut header_token = None;
    for hline in lines {
        if let Some((k, v)) = hline.split_once(':') {
            if k.trim().eq_ignore_ascii_case("x-genos-token") {
                header_token = Some(v.trim().to_string());
            }
        }
    }
    let query_params = parse_query_params(query);
    let provided_token = header_token
        .or_else(|| query_params.get("token").cloned())
        .unwrap_or_default();

    if provided_token != expected_token {
        return send_http_response(
            &mut stream,
            401,
            "application/json",
            r#"{"error":"Unauthorized: invalid or missing token"}"#,
        );
    }

    match (method, path) {
        ("GET", "/") => {
            let html = render_dashboard_html(expected_token);
            send_http_response(&mut stream, 200, "text/html; charset=utf-8", &html)
        }
        ("GET", "/api/pending") => {
            let json = {
                let guard = state.lock().unwrap();
                let mut pending_arr = Vec::new();
                for item in guard.pending.values() {
                    let mut obj = BTreeMap::new();
                    obj.insert("id".to_string(), JsonValue::Int(item.branch_id as i64));
                    obj.insert("seq".to_string(), JsonValue::Int(item.ledger_seq as i64));
                    obj.insert("tool".to_string(), JsonValue::Str(item.tool_name.clone()));
                    obj.insert(
                        "arguments".to_string(),
                        JsonValue::Str(item.arguments_json.clone()),
                    );
                    obj.insert("reason".to_string(), JsonValue::Str(item.reason.clone()));
                    obj.insert("why".to_string(), JsonValue::Str(item.why_tree.clone()));
                    pending_arr.push(JsonValue::Object(obj));
                }
                let mut root = BTreeMap::new();
                root.insert(
                    "tainted".to_string(),
                    JsonValue::Bool(guard.session.is_tainted()),
                );
                root.insert(
                    "integrity".to_string(),
                    JsonValue::Int(guard.session.label.integrity as i64),
                );
                root.insert(
                    "taints".to_string(),
                    JsonValue::Array(
                        mask_to_names(guard.session.label.taint_mask)
                            .into_iter()
                            .map(JsonValue::Str)
                            .collect(),
                    ),
                );
                root.insert("pending".to_string(), JsonValue::Array(pending_arr));
                JsonValue::Object(root).to_json_line()
            };
            send_http_response(&mut stream, 200, "application/json", &json)
        }
        ("POST", "/api/decide") | ("POST", "/api/approve") | ("POST", "/api/deny") => {
            let forced_approve = match path {
                "/api/approve" => Some(true),
                "/api/deny" => Some(false),
                _ => None,
            };
            let (id, approve) = if !body_part.trim().is_empty() {
                let val = parse_json(body_part.trim())
                    .map_err(|e| format!("Invalid JSON body: {}", e))?;
                let id = val
                    .get("id")
                    .and_then(|v| v.as_i64())
                    .ok_or_else(|| "Missing 'id'".to_string())? as u32;
                let approve = match forced_approve {
                    Some(a) => a,
                    None => val
                        .get("approve")
                        .and_then(|v| v.as_bool())
                        .ok_or_else(|| "Missing 'approve'".to_string())?,
                };
                (id, approve)
            } else {
                let id = query_params
                    .get("id")
                    .and_then(|s| s.parse::<u32>().ok())
                    .unwrap_or(0);
                let approve = forced_approve.unwrap_or_else(|| {
                    query_params
                        .get("approve")
                        .map(|s| s == "true" || s == "1")
                        .unwrap_or(false)
                });
                (id, approve)
            };

            let res = {
                let mut guard = state.lock().unwrap();
                guard.resolve_pending(id, approve, "human_operator")
            };
            match res {
                Ok(()) => send_http_response(
                    &mut stream,
                    200,
                    "application/json",
                    r#"{"ok":true}"#,
                ),
                Err(msg) => {
                    let mut map = BTreeMap::new();
                    map.insert("ok".to_string(), JsonValue::Bool(false));
                    map.insert("error".to_string(), JsonValue::Str(msg));
                    send_http_response(
                        &mut stream,
                        404,
                        "application/json",
                        &JsonValue::Object(map).to_json_line(),
                    )
                }
            }
        }
        ("POST", "/api/reset") => {
            let res = {
                let mut guard = state.lock().unwrap();
                guard.reset_session("human_operator")
            };
            match res {
                Ok(()) => send_http_response(
                    &mut stream,
                    200,
                    "application/json",
                    r#"{"ok":true,"status":"CLEAN"}"#,
                ),
                Err(msg) => {
                    let mut map = BTreeMap::new();
                    map.insert("ok".to_string(), JsonValue::Bool(false));
                    map.insert("error".to_string(), JsonValue::Str(msg));
                    send_http_response(
                        &mut stream,
                        500,
                        "application/json",
                        &JsonValue::Object(map).to_json_line(),
                    )
                }
            }
        }
        _ => send_http_response(&mut stream, 404, "application/json", r#"{"error":"Not Found"}"#),
    }
}

fn parse_query_params(query: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for pair in query.split('&') {
        if let Some((k, v)) = pair.split_once('=') {
            map.insert(k.to_string(), v.to_string());
        }
    }
    map
}

fn send_http_response(
    stream: &mut TcpStream,
    status: u16,
    content_type: &str,
    body: &str,
) -> Result<(), String> {
    let status_text = match status {
        200 => "OK",
        400 => "Bad Request",
        401 => "Unauthorized",
        404 => "Not Found",
        _ => "Internal Server Error",
    };
    let resp = format!(
        "HTTP/1.1 {} {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        status,
        status_text,
        content_type,
        body.len(),
        body
    );
    stream
        .write_all(resp.as_bytes())
        .and_then(|_| stream.flush())
        .map_err(|e| e.to_string())
}

fn render_dashboard_html(token: &str) -> String {
    format!(
        r#"<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>GenOS Guard — Escrow Approval Console</title>
<style>
  body {{ font-family: system-ui, -apple-system, sans-serif; background: #0d1117; color: #c9d1d9; margin: 2rem; }}
  h1 {{ color: #58a6ff; margin-bottom: 0.25rem; }}
  .badge {{ display: inline-block; padding: 0.25rem 0.6rem; border-radius: 6px; font-weight: 700; font-size: 0.85rem; }}
  .clean {{ background: #238636; color: #fff; }}
  .tainted {{ background: #da3633; color: #fff; }}
  .card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 1rem; margin-top: 1rem; }}
  pre {{ background: #010409; padding: 0.75rem; border-radius: 6px; overflow-x: auto; font-size: 0.82rem; color: #79c0ff; }}
  button {{ border: none; padding: 0.5rem 1rem; border-radius: 6px; font-weight: 600; cursor: pointer; margin-right: 0.5rem; }}
  .btn-approve {{ background: #238636; color: white; }}
  .btn-deny {{ background: #da3633; color: white; }}
  .btn-reset {{ background: #1f6feb; color: white; }}
</style>
</head>
<body>
  <h1>GenOS Guard — Multiverse Escrow Console</h1>
  <div id="status">Loading session status...</div>
  <div style="margin-top:0.75rem;">
    <button class="btn-reset" onclick="resetSession()">Reset Session (Declassify Taint)</button>
  </div>
  <div id="list"></div>
<script>
const TOKEN = "{token}";
async function refresh() {{
  const res = await fetch(`/api/pending?token=${{TOKEN}}`);
  const data = await res.json();
  const st = document.getElementById('status');
  if (data.tainted) {{
    st.innerHTML = `Session Status: <span class="badge tainted">TAINTED (${{data.taints.join(', ')}}) — Integrity ${{data.integrity}}</span>`;
  }} else {{
    st.innerHTML = `Session Status: <span class="badge clean">CLEAN — Integrity ${{data.integrity}}</span>`;
  }}
  const list = document.getElementById('list');
  if (!data.pending.length) {{
    list.innerHTML = '<div class="card">No pending tool calls held in Escrow.</div>';
    return;
  }}
  list.innerHTML = data.pending.map(item => `
    <div class="card">
      <h3>Escrow #${{item.id}} — Tool: <code>${{item.tool}}</code> (Ledger #${{item.seq}})</h3>
      <p>${{item.reason}}</p>
      <strong>Arguments:</strong>
      <pre>${{item.arguments}}</pre>
      <strong>Causal Lineage (why):</strong>
      <pre>${{item.why}}</pre>
      <button class="btn-approve" onclick="decide(${{item.id}}, true)">Approve & Commit</button>
      <button class="btn-deny" onclick="decide(${{item.id}}, false)">Deny & Abort O(1)</button>
    </div>
  `).join('');
}}
async function decide(id, approve) {{
  await fetch(`/api/decide?token=${{TOKEN}}`, {{
    method: 'POST',
    headers: {{'Content-Type': 'application/json'}},
    body: JSON.stringify({{id, approve}})
  }});
  refresh();
}}
async function resetSession() {{
  await fetch(`/api/reset?token=${{TOKEN}}`, {{ method: 'POST' }});
  refresh();
}}
setInterval(refresh, 1000);
refresh();
</script>
</body>
</html>"#
    )
}

/// Sends an HTTP request to the local `genos-guard` approval server for CLI subcommands.
pub fn send_cli_http_request(
    port: u16,
    token: &str,
    method: &str,
    path: &str,
    body: &str,
) -> Result<(u16, String), String> {
    let mut stream = TcpStream::connect(("127.0.0.1", port))
        .map_err(|e| format!("Failed to connect to 127.0.0.1:{}: {}", port, e))?;
    let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
    let req = format!(
        "{} {} HTTP/1.1\r\nHost: 127.0.0.1:{}\r\nX-Genos-Token: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        method,
        path,
        port,
        token,
        body.len(),
        body
    );
    stream
        .write_all(req.as_bytes())
        .and_then(|_| stream.flush())
        .map_err(|e| e.to_string())?;

    let mut resp = String::new();
    stream
        .read_to_string(&mut resp)
        .map_err(|e| e.to_string())?;
    let (headers, resp_body) = resp.split_once("\r\n\r\n").unwrap_or((&resp, ""));
    let status = headers
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(500);
    Ok((status, resp_body.to_string()))
}
