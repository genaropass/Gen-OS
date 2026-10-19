# Reproducible Demo: Stopping Indirect Prompt Injection with `genos-guard`

This directory contains a 100% offline, reproducible demonstration of how **`genos-guard`** uses GenOS's **Decentralized Information Flow Control (DIFC)**, **Transactional Escrow**, and **SHA-256 Causal Ledger** to stop an Indirect Prompt Injection attack on an MCP agent session.

---

## Scenario Overview

An AI coding agent has access to three MCP tools provided by `echo_mcp_server`:
1. `read_file` (`mutating = false`, `taint = []`)
2. `fetch_url` (`mutating = false`, `taint = ["WEB_UNTRUSTED"]`)
3. `write_file` (`mutating = true`, `taint = []`)

### Attack Sequence
1. **Clean Write (`id: 1`):** The agent writes to `notes.txt` while the session is `CLEAN` (`TRUSTED_KERNEL`, `integrity = 10000`). **`genos-guard` ALLOWS it immediately.**
2. **Untrusted Read (`id: 2`):** The agent calls `fetch_url` on `file://examples/prompt-injection-demo/payload/issue.md`, which contains a hidden prompt injection instructing the agent to overwrite `.env.exfil`. When the result returns, **`genos-guard` taints the session with `WEB_UNTRUSTED` and drops session integrity to `0` (`UNTRUSTED_EXTERNAL`).**
3. **Hijacked Write (`id: 3`):** The compromised agent attempts to call `write_file` to create `.env.exfil`. **`genos-guard` intercepts the call before it reaches the MCP server**, holds it in `EscrowManager` (or rejects it with JSON-RPC error `-32001`), and records the exact causal provenance edge pointing back to the `fetch_url` response (`causes = [4]`).

---

## Quick Run (Headless Reject Mode)

Run from the repository root (`e:\Genaro\Desktop\AgentOS`):

### PowerShell
```powershell
Remove-Item -ErrorAction SilentlyContinue genos-ledger.jsonl
@(
  '{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"","content":"clean note"}}}'
  '{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"fetch_url","arguments":{"url":"file://examples/prompt-injection-demo/payload/issue.md"}}}'
  '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"write_file","arguments":{"path":"","content":"EXFILTRATED_API_KEY=sk-live-secret"}}}'
) | cargo run --quiet -p genos-guard --bin genos-guard -- --policy examples/prompt-injection-demo/genos.toml --hold-mode reject -- target/debug/echo_mcp_server
```

### Inspect the Causal Provenance Tree (`why`)
```powershell
cargo run --quiet -p genos-guard --bin genos-guard -- why 5 --ledger genos-ledger.jsonl
```

Expected output:
```text
[#5] call write_file (decision=HOLD, integrity=0, taint=WEB_UNTRUSTED)
      payload_sha256=... preview="{\"content\":\"EXFILTRATED_API_KEY=sk-live-secret\",\"path\":\"\"}"
  └── [#4] result fetch_url (decision=TAINT:WEB_UNTRUSTED, integrity=0, taint=WEB_UNTRUSTED)
          payload_sha256=... preview="{\"id\":2,\"jsonrpc\":\"2.0\",\"result\":{\"content\":[{\"text\":\"# Issue #42: Crash when parsing empty config..."
      └── [#3] call fetch_url (decision=ALLOW, integrity=10000, taint=CLEAN)
              payload_sha256=... preview="{\"url\":\"file://examples/prompt-injection-demo/payload/issue.md\"}"
```

### Verify the Cryptographic SHA-256 Hash Chain (`verify`)
```powershell
cargo run --quiet -p genos-guard --bin genos-guard -- verify --ledger genos-ledger.jsonl
```

---

## Interactive Human-in-the-Loop Escrow Mode

To hold the hijacked `write_file` call in `EscrowManager` and approve or deny it from your browser (`http://127.0.0.1:7878/?token=...`) or via CLI:

1. Run `genos-guard` with `--hold-mode escrow` (the default):
   ```powershell
   cargo run -p genos-guard --bin genos-guard -- --policy examples/prompt-injection-demo/genos.toml -- target/debug/echo_mcp_server
   ```
2. Copy the `http://127.0.0.1:7878/?token=<TOKEN>` URL printed on `stderr` into your browser, or run from another terminal:
   ```powershell
   cargo run -p genos-guard --bin genos-guard -- pending --port 7878 --token <TOKEN>
   cargo run -p genos-guard --bin genos-guard -- deny 1 --port 7878 --token <TOKEN>
   ```
