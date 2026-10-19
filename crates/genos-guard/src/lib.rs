//! `genos-guard`: User-space MCP security proxy enforcing GenOS Capabilities, DIFC taint tracking,
//! transactional Escrow holds, and SHA-256 hash-chained causal provenance (`why()`).

pub mod escrow_http;
pub mod jsonrpc;
pub mod ledger;
pub mod policy;
pub mod proxy;
pub mod session;
