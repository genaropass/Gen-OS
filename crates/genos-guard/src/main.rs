//! CLI entry point for `genos-guard`.
//!
//! Supported modes:
//! 1. MCP Proxy Mode:
//!    `genos-guard [--policy <path>] [--hold-mode escrow|reject] [--token <tok>] -- <command> [args...]`
//! 2. Causal Audit & Ledger Verification:
//!    `genos-guard why <seq> [--ledger <path>]`
//!    `genos-guard verify [--ledger <path>]`
//! 3. Live Escrow Operator Commands:
//!    `genos-guard pending [--port <port>] --token <tok>`
//!    `genos-guard approve <escrow_id> [--port <port>] --token <tok>`
//!    `genos-guard deny <escrow_id> [--port <port>] --token <tok>`
//!    `genos-guard reset [--port <port>] --token <tok>`

use std::env;
use std::path::PathBuf;
use std::process;

use genos_guard::escrow_http::send_cli_http_request;
use genos_guard::ledger::{explain_why_tree, read_all_entries};
use genos_guard::policy::Policy;
use genos_guard::proxy::{run_stdio_proxy, HoldMode, ProxyConfig};

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" {
        print_usage();
        return;
    }

    match args[0].as_str() {
        "why" => cmd_why(&args[1..]),
        "verify" => cmd_verify(&args[1..]),
        "pending" => cmd_http_action("GET", "/api/pending", "{}", &args[1..]),
        "approve" => {
            if args.len() < 2 {
                eprintln!("Usage: genos-guard approve <escrow_id> [--port <port>] --token <token>");
                process::exit(2);
            }
            let id: u32 = args[1].parse().unwrap_or_else(|_| {
                eprintln!("Invalid escrow_id '{}'", args[1]);
                process::exit(2);
            });
            let body = format!("{{\"id\":{}}}", id);
            cmd_http_action("POST", "/api/approve", &body, &args[2..]);
        }
        "deny" => {
            if args.len() < 2 {
                eprintln!("Usage: genos-guard deny <escrow_id> [--port <port>] --token <token>");
                process::exit(2);
            }
            let id: u32 = args[1].parse().unwrap_or_else(|_| {
                eprintln!("Invalid escrow_id '{}'", args[1]);
                process::exit(2);
            });
            let body = format!("{{\"id\":{}}}", id);
            cmd_http_action("POST", "/api/deny", &body, &args[2..]);
        }
        "reset" => cmd_http_action("POST", "/api/reset", "{}", &args[1..]),
        _ => cmd_proxy(&args),
    }
}

fn cmd_proxy(args: &[String]) {
    let mut policy_path: Option<PathBuf> = None;
    let mut hold_mode = HoldMode::Escrow;
    let mut token_override: Option<String> = None;
    let mut sep_idx: Option<usize> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--" => {
                sep_idx = Some(i);
                break;
            }
            "--policy" => {
                if i + 1 >= args.len() {
                    eprintln!("[genos-guard] Missing argument after --policy");
                    process::exit(2);
                }
                policy_path = Some(PathBuf::from(&args[i + 1]));
                i += 2;
            }
            "--hold-mode" => {
                if i + 1 >= args.len() {
                    eprintln!("[genos-guard] Missing argument after --hold-mode");
                    process::exit(2);
                }
                hold_mode = match args[i + 1].as_str() {
                    "escrow" => HoldMode::Escrow,
                    "reject" => HoldMode::Reject,
                    other => {
                        eprintln!(
                            "[genos-guard] Unknown --hold-mode '{}', expected 'escrow' or 'reject'",
                            other
                        );
                        process::exit(2);
                    }
                };
                i += 2;
            }
            "--token" => {
                if i + 1 >= args.len() {
                    eprintln!("[genos-guard] Missing argument after --token");
                    process::exit(2);
                }
                token_override = Some(args[i + 1].clone());
                i += 2;
            }
            other => {
                eprintln!(
                    "[genos-guard] Unrecognized option '{}'. Use `--` before the MCP server command.",
                    other
                );
                process::exit(2);
            }
        }
    }

    let sep = match sep_idx {
        Some(idx) if idx + 1 < args.len() => idx,
        _ => {
            eprintln!("[genos-guard] Error: missing `-- <mcp-server-command> [args...]`");
            print_usage();
            process::exit(2);
        }
    };

    let policy = match policy_path {
        Some(path) => match Policy::from_file(&path) {
            Ok(p) => p,
            Err(e) => {
                // Fail-closed: exit immediately if the specified policy file is invalid or missing
                eprintln!("[genos-guard] FAIL-CLOSED: {}", e);
                process::exit(1);
            }
        },
        None => {
            let default_path = PathBuf::from("genos.toml");
            if default_path.exists() {
                match Policy::from_file(&default_path) {
                    Ok(p) => p,
                    Err(e) => {
                        eprintln!("[genos-guard] FAIL-CLOSED: {}", e);
                        process::exit(1);
                    }
                }
            } else {
                Policy::default()
            }
        }
    };

    let child_program = args[sep + 1].clone();
    let child_args = args[sep + 2..].to_vec();

    let cfg = ProxyConfig {
        policy,
        hold_mode,
        token_override,
        child_program,
        child_args,
    };

    match run_stdio_proxy(cfg) {
        Ok(code) => process::exit(code),
        Err(e) => {
            eprintln!("[genos-guard] Proxy error: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_why(args: &[String]) {
    if args.is_empty() {
        eprintln!("Usage: genos-guard why <seq> [--ledger <path>]");
        process::exit(2);
    }
    let target_seq: u64 = match args[0].parse() {
        Ok(s) => s,
        Err(_) => {
            eprintln!("Invalid sequence number '{}'", args[0]);
            process::exit(2);
        }
    };
    let mut ledger_path = PathBuf::from("genos-ledger.jsonl");
    let mut i = 1;
    while i < args.len() {
        if args[i] == "--ledger" && i + 1 < args.len() {
            ledger_path = PathBuf::from(&args[i + 1]);
            i += 2;
        } else {
            eprintln!("Unknown argument '{}'", args[i]);
            process::exit(2);
        }
    }

    match explain_why_tree(&ledger_path, target_seq) {
        Ok(tree) => {
            println!("{}", tree);
        }
        Err(e) => {
            eprintln!("Error: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_verify(args: &[String]) {
    let mut ledger_path = PathBuf::from("genos-ledger.jsonl");
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--ledger" && i + 1 < args.len() {
            ledger_path = PathBuf::from(&args[i + 1]);
            i += 2;
        } else {
            eprintln!("Unknown argument '{}'", args[i]);
            process::exit(2);
        }
    }

    match read_all_entries(&ledger_path) {
        Ok(entries) => {
            let last_hash = entries
                .last()
                .map(|e| e.hash.as_str())
                .unwrap_or("0000000000000000000000000000000000000000000000000000000000000000");
            println!(
                "VERIFIED OK: {} causal entries in '{}' (head SHA-256: {})",
                entries.len(),
                ledger_path.display(),
                last_hash
            );
        }
        Err(e) => {
            eprintln!("VERIFICATION FAILED: {}", e);
            process::exit(1);
        }
    }
}

fn cmd_http_action(method: &str, path: &str, body: &str, args: &[String]) {
    let mut port: u16 = 7878;
    let mut token: Option<String> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--port" if i + 1 < args.len() => {
                port = args[i + 1].parse().unwrap_or_else(|_| {
                    eprintln!("Invalid port '{}'", args[i + 1]);
                    process::exit(2);
                });
                i += 2;
            }
            "--token" if i + 1 < args.len() => {
                token = Some(args[i + 1].clone());
                i += 2;
            }
            other => {
                eprintln!("Unknown argument '{}'", other);
                process::exit(2);
            }
        }
    }

    let tok = token
        .or_else(|| env::var("GENOS_GUARD_TOKEN").ok())
        .unwrap_or_else(|| {
            eprintln!(
                "Error: missing `--token <token>` (or `GENOS_GUARD_TOKEN` env var) for localhost authentication"
            );
            process::exit(2);
        });

    match send_cli_http_request(port, &tok, method, path, body) {
        Ok((status, resp_body)) => {
            if (200..300).contains(&status) {
                println!("{}", resp_body);
            } else {
                eprintln!("HTTP {}: {}", status, resp_body);
                process::exit(1);
            }
        }
        Err(e) => {
            eprintln!("Error communicating with genos-guard server: {}", e);
            process::exit(1);
        }
    }
}

fn print_usage() {
    eprintln!(
        "genos-guard v0.1.0 — Capability, DIFC & Transactional Escrow Proxy for MCP Agents

USAGE:
  1. Wrap an MCP stdio server:
     genos-guard [--policy <genos.toml>] [--hold-mode escrow|reject] -- <command> [args...]

  2. Inspect causal provenance (`why`) or verify SHA-256 ledger integrity:
     genos-guard why <seq> [--ledger <genos-ledger.jsonl>]
     genos-guard verify [--ledger <genos-ledger.jsonl>]

  3. Operator approval / session control:
     genos-guard pending [--port 7878] --token <token>
     genos-guard approve <escrow_id> [--port 7878] --token <token>
     genos-guard deny <escrow_id> [--port 7878] --token <token>
     genos-guard reset [--port 7878] --token <token>"
    );
}
