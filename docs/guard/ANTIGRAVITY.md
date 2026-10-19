# Configuring `genos-guard` with Antigravity, Claude Desktop, and Cursor

`genos-guard` acts as a drop-in stdio proxy (`stdin`/`stdout` JSON-RPC 2.0) between any Model Context Protocol (MCP) host and any MCP server.

---

## 1. Build the Release Binary

From the repository root:

```bash
cargo build --release -p genos-guard
```

This produces:
- Windows: `target\release\genos-guard.exe`
- Linux / macOS: `target/release/genos-guard`

---

## 2. Create Your `genos.toml` Policy

Copy [`crates/genos-guard/genos.example.toml`](../../crates/genos-guard/genos.example.toml) to your workspace or home directory (e.g. `genos.toml`) and list your MCP tools:

```toml
[guard]
approval_timeout_secs = 120
approval_port = 7878
ledger_path = "genos-ledger.jsonl"

[defaults]
# Fail-closed: any tool not explicitly listed below is treated as mutating and taints the session
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
```

---

## 3. Wrap Your MCP Server in Antigravity / Claude Desktop / Cursor

In your MCP client configuration (`mcp_config.json` or `claude_desktop_config.json`), replace the original `"command"` with `genos-guard` and pass the original command after `--`:

### Before (Unprotected MCP Server)
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/path/to/workspace"]
    }
  }
}
```

### After (Protected by `genos-guard`)
```json
{
  "mcpServers": {
    "filesystem": {
      "command": "E:/Genaro/Desktop/AgentOS/target/release/genos-guard.exe",
      "args": [
        "--policy",
        "E:/Genaro/Desktop/AgentOS/examples/prompt-injection-demo/genos.toml",
        "--",
        "npx",
        "-y",
        "@modelcontextprotocol/server-filesystem",
        "/path/to/workspace"
      ]
    }
  }
}
```

---

## 4. Operating the Escrow Console & Causal Audit CLI

- **When a tainted session attempts a mutating tool call:**
  `genos-guard` holds the call in `EscrowManager` and prints the localhost approval URL to `stderr`:
  ```text
  [genos-guard] Approval UI: http://127.0.0.1:7878/?token=<SESSION_TOKEN>
  ```
- **Approve or Deny via Browser:** Open the localhost URL to see the pending tool call, arguments, DIFC taint mask, and causal tree, and click **Approve (Commit)** or **Deny ($O(1)$ Abort)**.
- **Approve, Deny, or Reset via CLI:**
  ```bash
  genos-guard pending --port 7878 --token <SESSION_TOKEN>
  genos-guard approve 1 --port 7878 --token <SESSION_TOKEN>
  genos-guard deny 1 --port 7878 --token <SESSION_TOKEN>
  genos-guard reset --port 7878 --token <SESSION_TOKEN>
  ```
- **Audit the Causal Ledger Offline:**
  ```bash
  genos-guard verify --ledger genos-ledger.jsonl
  genos-guard why 5 --ledger genos-ledger.jsonl
  ```
