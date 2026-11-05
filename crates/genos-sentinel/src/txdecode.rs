//! Ring 2A — **Independent Transaction Decoder (`txdecode.rs`)**: Anti-Blind-Signing Engine.
//!
//! Decodes raw transaction payloads directly from bytes without trusting caller metadata or
//! web UI summaries. Specifically detects:
//! - **EIP-7702 SetCode Delegation (`0x04`)**: Used in the October 29, 2026 Binance attack to
//!   dynamically delegate wallet execution and redirect funds.
//! - **Safe{Wallet} `execTransaction` (`0x6a761202`) with `operation == 1` (`DELEGATECALL`)**:
//!   Used in the February 21, 2025 Bybit attack to overwrite the multisig implementation slot.
//! - **ERC-20 `transfer` (`0xa9059cbb`) & `approve` (`0x095ea7b3`)**: Extracts actual recipient
//!   and token amount, flagging unlimited allowances.
//! - **Bitcoin Transfers (`BAPT` / `psbt\xff`)**: Extracts recipient address hash, satoshis, and
//!   detects anomalous miner fee drains.
//! - **UI Blind-Signing Spoof**: Compares caller-claimed recipient/amount against the raw decoded
//!   bytes and flags any discrepancy as `RiskLevel::Forbidden`.

use causal_core::hash::sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ChainId {
    Ethereum,
    Bitcoin,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum RiskLevel {
    /// Standard whitelisted transfer within velocity limits.
    Normal,
    /// Requires M-of-N human cryptographic quorum (e.g., high amount, new destination, or interactive origin).
    HighRequiresQuorum,
    /// Strictly forbidden operation (EIP-7702 delegation, Safe DELEGATECALL, UI spoof, unlimited approve).
    /// Immediately trips the global Circuit Breaker to `FROZEN`.
    Forbidden,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperationKind {
    NativeTransfer,
    Erc20Transfer { token_contract: [u8; 20] },
    Erc20Approve { token_contract: [u8; 20], unlimited: bool },
    SafeExecTransaction { operation: u8 },
    Eip7702SetCodeDelegation { auth_chain_id: u64, delegate_code_address: [u8; 20] },
    BitcoinTransfer { fee_sats: u64 },
}

/// Canonical intent decoded independently by GenOS Sentinel from raw transaction bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedIntent {
    pub chain: ChainId,
    pub op_kind: OperationKind,
    pub recipient: [u8; 20],
    pub amount: u128,
    pub risk: RiskLevel,
    pub summary: String,
    pub raw_tx_sha256: [u8; 32],
}

impl DecodedIntent {
    pub fn intent_hash(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"GENOS_DECODED_INTENT_V1|");
        buf.push(match self.chain {
            ChainId::Ethereum => 1,
            ChainId::Bitcoin => 2,
        });
        buf.extend_from_slice(&self.recipient);
        buf.extend_from_slice(&self.amount.to_le_bytes());
        buf.extend_from_slice(&self.raw_tx_sha256);
        buf.extend_from_slice(self.summary.as_bytes());
        sha256(&buf)
    }
}

/// Optional metadata claimed by the frontend UI or calling service.
/// If provided and mismatched against the raw bytes, `decode_and_verify` flags a UI Blind-Signing Spoof.
#[derive(Debug, Clone)]
pub struct ClaimedUiSummary {
    pub claimed_recipient: [u8; 20],
    pub claimed_amount: u128,
}

/// Decodes raw transaction bytes independently and checks for UI blind-signing spoofing.
pub fn decode_transaction(
    chain: ChainId,
    raw_bytes: &[u8],
    ui_claim: Option<&ClaimedUiSummary>,
) -> Result<DecodedIntent, String> {
    if raw_bytes.is_empty() {
        return Err("Empty transaction payload".to_string());
    }
    let raw_tx_sha256 = sha256(raw_bytes);

    let mut intent = match chain {
        ChainId::Ethereum => decode_evm_frame(raw_bytes, raw_tx_sha256)?,
        ChainId::Bitcoin => decode_bitcoin_frame(raw_bytes, raw_tx_sha256)?,
    };

    // Check for UI blind-signing spoofing (e.g. Bybit Safe{Wallet} JS injection showing a benign recipient/amount)
    if let Some(claim) = ui_claim {
        if claim.claimed_recipient != intent.recipient || claim.claimed_amount != intent.amount {
            intent.risk = RiskLevel::Forbidden;
            intent.summary = format!(
                "CRITICAL BLIND-SIGNING SPOOF: UI claimed transfer of {} to {:02x?}..., but raw bytes actually execute: {}",
                claim.claimed_amount,
                &claim.claimed_recipient[0..4],
                intent.summary
            );
        }
    }

    Ok(intent)
}

/// EVM wire format decoded by `genos-sentinel`:
/// - Type `0x04` (EIP-7702 SetCode transaction):
///   `[0x04, chain_id(8B BE), target_to(20B), value(16B BE), delegate_code_addr(20B)]`
/// - Type `0x02` (EIP-1559 transaction):
///   `[0x02, to(20B), value(16B BE), calldata...]`
fn decode_evm_frame(raw: &[u8], raw_tx_sha256: [u8; 32]) -> Result<DecodedIntent, String> {
    let tx_type = raw[0];

    // If raw[1..] is a valid Ethereum RLP list (starts with 0xc0..=0xff and decodes to >= 8 items),
    // use the full Ethereum RLP parser for EIP-1559 (0x02) and EIP-7702 (0x04):
    if raw.len() > 2 && raw[1] >= 0xc0 {
        if let Ok((RlpItem::List(items), consumed)) = decode_rlp_item(&raw[1..]) {
            if consumed == raw.len() - 1 && items.len() >= 8 {
                return decode_evm_rlp_items(tx_type, &items, raw_tx_sha256);
            }
        }
    }

    // Case 1: EIP-7702 SetCode Transaction (`0x04`) — Binance Oct-2026 attack vector
    if tx_type == 0x04 {
        if raw.len() < 1 + 8 + 20 + 16 + 20 {
            return Err("Truncated EIP-7702 (0x04) transaction payload".to_string());
        }
        let auth_chain_id = u64::from_be_bytes(raw[1..9].try_into().unwrap());
        let mut recipient = [0u8; 20];
        recipient.copy_from_slice(&raw[9..29]);
        let amount = u128::from_be_bytes(raw[29..45].try_into().unwrap());
        let mut delegate_code_address = [0u8; 20];
        delegate_code_address.copy_from_slice(&raw[45..65]);

        let cross_chain_note = if auth_chain_id == 0 {
            " [CRITICAL: chain_id=0 universal cross-chain replay authorization!]"
        } else {
            ""
        };

        return Ok(DecodedIntent {
            chain: ChainId::Ethereum,
            op_kind: OperationKind::Eip7702SetCodeDelegation {
                auth_chain_id,
                delegate_code_address,
            },
            recipient: delegate_code_address,
            amount,
            risk: RiskLevel::Forbidden,
            summary: format!(
                "FORBIDDEN EIP-7702 SetCode Delegation to contract {:02x?}{} (Binance Oct-2026 vector)",
                &delegate_code_address[0..4],
                cross_chain_note
            ),
            raw_tx_sha256,
        });
    }

    // Case 2: Standard EIP-1559 (`0x02`) frame: `[0x02, to(20B), value(16B BE), calldata...]`
    if tx_type != 0x02 {
        return Err(format!("Unsupported or unknown EVM transaction type 0x{:02x}", tx_type));
    }
    if raw.len() < 1 + 20 + 16 {
        return Err("Truncated EIP-1559 (0x02) transaction header".to_string());
    }

    let mut to_addr = [0u8; 20];
    to_addr.copy_from_slice(&raw[1..21]);
    let value_wei = u128::from_be_bytes(raw[21..37].try_into().unwrap());
    let calldata = &raw[37..];

    // Pure native ETH transfer (empty calldata)
    if calldata.is_empty() {
        return Ok(DecodedIntent {
            chain: ChainId::Ethereum,
            op_kind: OperationKind::NativeTransfer,
            recipient: to_addr,
            amount: value_wei,
            risk: RiskLevel::Normal,
            summary: format!("Native ETH transfer of {} wei to {:02x?}", value_wei, &to_addr[0..4]),
            raw_tx_sha256,
        });
    }

    if calldata.len() < 4 {
        return Err("Malformed EVM calldata (< 4 bytes selector)".to_string());
    }
    let selector: [u8; 4] = calldata[0..4].try_into().unwrap();

    match selector {
        // ERC-20 `transfer(address,uint256)` -> selector `0xa9059cbb`
        [0xa9, 0x05, 0x9c, 0xbb] => {
            if calldata.len() < 4 + 32 + 32 {
                return Err("Truncated ERC-20 transfer calldata".to_string());
            }
            let mut recipient = [0u8; 20];
            recipient.copy_from_slice(&calldata[16..36]);
            let amount = u128::from_be_bytes(calldata[52..68].try_into().unwrap());
            Ok(DecodedIntent {
                chain: ChainId::Ethereum,
                op_kind: OperationKind::Erc20Transfer {
                    token_contract: to_addr,
                },
                recipient,
                amount,
                risk: RiskLevel::Normal,
                summary: format!(
                    "ERC-20 transfer of {} units on token {:02x?} to {:02x?}",
                    amount,
                    &to_addr[0..4],
                    &recipient[0..4]
                ),
                raw_tx_sha256,
            })
        }
        // ERC-20 `approve(address,uint256)` -> selector `0x095ea7b3`
        [0x09, 0x5e, 0xa7, 0xb3] => {
            if calldata.len() < 4 + 32 + 32 {
                return Err("Truncated ERC-20 approve calldata".to_string());
            }
            let mut spender = [0u8; 20];
            spender.copy_from_slice(&calldata[16..36]);
            let allowance_hi = u128::from_be_bytes(calldata[36..52].try_into().unwrap());
            let allowance_lo = u128::from_be_bytes(calldata[52..68].try_into().unwrap());
            let unlimited = allowance_hi > 0 || allowance_lo == u128::MAX;
            let risk = if unlimited {
                RiskLevel::Forbidden
            } else {
                RiskLevel::HighRequiresQuorum
            };
            Ok(DecodedIntent {
                chain: ChainId::Ethereum,
                op_kind: OperationKind::Erc20Approve {
                    token_contract: to_addr,
                    unlimited,
                },
                recipient: spender,
                amount: allowance_lo,
                risk,
                summary: format!(
                    "ERC-20 approve spender {:02x?} (unlimited={})",
                    &spender[0..4],
                    unlimited
                ),
                raw_tx_sha256,
            })
        }
        // Safe{Wallet} `execTransaction` -> selector `0x6a761202`
        // Layout: `[selector(4B), inner_to(32B word), inner_value(32B word), operation(1B)]`
        [0x6a, 0x76, 0x12, 0x02] => {
            if calldata.len() < 4 + 32 + 32 + 1 {
                return Err("Truncated Safe execTransaction calldata".to_string());
            }
            let mut inner_to = [0u8; 20];
            inner_to.copy_from_slice(&calldata[16..36]);
            let inner_value = u128::from_be_bytes(calldata[52..68].try_into().unwrap());
            let operation = calldata[68];

            let (risk, summary) = if operation == 1 {
                (
                    RiskLevel::Forbidden,
                    format!(
                        "FORBIDDEN Safe{{Wallet}} DELEGATECALL (operation=1) to {:02x?} (Bybit Feb-2025 implementation-overwrite vector)",
                        &inner_to[0..4]
                    ),
                )
            } else {
                (
                    RiskLevel::Normal,
                    format!(
                        "Safe{{Wallet}} CALL (operation=0) of {} wei to {:02x?}",
                        inner_value,
                        &inner_to[0..4]
                    ),
                )
            };

            Ok(DecodedIntent {
                chain: ChainId::Ethereum,
                op_kind: OperationKind::SafeExecTransaction { operation },
                recipient: inner_to,
                amount: inner_value,
                risk,
                summary,
                raw_tx_sha256,
            })
        }
        other => Err(format!(
            "Unrecognized EVM function selector 0x{:02x}{:02x}{:02x}{:02x} (fail-closed)",
            other[0], other[1], other[2], other[3]
        )),
    }
}

/// Bitcoin PSBT/Raw transfer frame:
/// `[b"PSBT", recipient_hash(20B), amount_sats(8B BE), fee_sats(8B BE)]`
fn decode_bitcoin_frame(raw: &[u8], raw_tx_sha256: [u8; 32]) -> Result<DecodedIntent, String> {
    if raw.len() < 4 + 20 + 8 + 8 || &raw[0..4] != b"PSBT" {
        return Err("Invalid or truncated Bitcoin PSBT frame (fail-closed)".to_string());
    }
    let mut recipient = [0u8; 20];
    recipient.copy_from_slice(&raw[4..24]);
    let amount_sats = u64::from_be_bytes(raw[24..32].try_into().unwrap());
    let fee_sats = u64::from_be_bytes(raw[32..40].try_into().unwrap());

    // Flag anomalous fee (> 10% of transfer amount)
    let risk = if fee_sats > amount_sats / 10 {
        RiskLevel::Forbidden
    } else {
        RiskLevel::Normal
    };

    Ok(DecodedIntent {
        chain: ChainId::Bitcoin,
        op_kind: OperationKind::BitcoinTransfer { fee_sats },
        recipient,
        amount: amount_sats as u128,
        risk,
        summary: format!(
            "Bitcoin PSBT transfer of {} sats (fee={} sats) to {:02x?}",
            amount_sats,
            fee_sats,
            &recipient[0..4]
        ),
        raw_tx_sha256,
    })
}

/// Helper constructors for building canonical raw transaction payloads in tests and red-team simulations.
pub mod builders {
    pub fn build_evm_native_transfer(to: [u8; 20], value_wei: u128) -> Vec<u8> {
        let mut out = Vec::with_capacity(37);
        out.push(0x02);
        out.extend_from_slice(&to);
        out.extend_from_slice(&value_wei.to_be_bytes());
        out
    }

    pub fn build_eip7702_setcode_tx(
        auth_chain_id: u64,
        to: [u8; 20],
        value_wei: u128,
        delegate_code_addr: [u8; 20],
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(65);
        out.push(0x04);
        out.extend_from_slice(&auth_chain_id.to_be_bytes());
        out.extend_from_slice(&to);
        out.extend_from_slice(&value_wei.to_be_bytes());
        out.extend_from_slice(&delegate_code_addr);
        out
    }

    pub fn build_safe_exec_tx(
        safe_addr: [u8; 20],
        inner_to: [u8; 20],
        inner_value: u128,
        operation: u8,
    ) -> Vec<u8> {
        let mut out = Vec::with_capacity(37 + 69);
        out.push(0x02);
        out.extend_from_slice(&safe_addr);
        out.extend_from_slice(&0u128.to_be_bytes());
        // Calldata: selector 0x6a761202 + 32B inner_to + 32B inner_value + 1B operation
        out.extend_from_slice(&[0x6a, 0x76, 0x12, 0x02]);
        out.extend_from_slice(&[0u8; 12]);
        out.extend_from_slice(&inner_to);
        out.extend_from_slice(&[0u8; 16]);
        out.extend_from_slice(&inner_value.to_be_bytes());
        out.push(operation);
        out
    }

    pub fn build_bitcoin_psbt(recipient: [u8; 20], amount_sats: u64, fee_sats: u64) -> Vec<u8> {
        let mut out = Vec::with_capacity(40);
        out.extend_from_slice(b"PSBT");
        out.extend_from_slice(&recipient);
        out.extend_from_slice(&amount_sats.to_be_bytes());
        out.extend_from_slice(&fee_sats.to_be_bytes());
        out
    }

    /// Builds a real RLP-encoded Ethereum EIP-7702 (`0x04`) transaction:
    /// `0x04 || RLP([chain_id, nonce, max_priority_fee, max_fee, gas, to, value, data, access_list, [[auth_chain_id, delegate_addr, auth_nonce, y_parity, r, s]]])`
    pub fn build_real_rlp_eip7702_tx(
        tx_chain_id: u64,
        to: [u8; 20],
        value_wei: u128,
        auth_chain_id: u64,
        delegate_code_addr: [u8; 20],
    ) -> Vec<u8> {
        use super::{rlp_encode_bytes, rlp_encode_list, rlp_encode_u128};
        let auth_tuple = rlp_encode_list(&[
            rlp_encode_u128(auth_chain_id as u128),
            rlp_encode_bytes(&delegate_code_addr),
            rlp_encode_u128(0),
            rlp_encode_u128(0),
            rlp_encode_u128(1),
            rlp_encode_u128(1),
        ]);
        let auth_list = rlp_encode_list(&[auth_tuple]);
        let payload = rlp_encode_list(&[
            rlp_encode_u128(tx_chain_id as u128),
            rlp_encode_u128(1),
            rlp_encode_u128(1_000_000_000),
            rlp_encode_u128(20_000_000_000),
            rlp_encode_u128(21_000),
            rlp_encode_bytes(&to),
            rlp_encode_u128(value_wei),
            rlp_encode_bytes(&[]),
            rlp_encode_list(&[]),
            auth_list,
        ]);
        let mut out = Vec::with_capacity(1 + payload.len());
        out.push(0x04);
        out.extend_from_slice(&payload);
        out
    }
}

/// Zero-dependency Ethereum Recursive Length Prefix (RLP) AST node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RlpItem {
    Bytes(Vec<u8>),
    List(Vec<RlpItem>),
}

/// Decodes a single RLP item (bytes or nested list) from `input`, returning `(item, bytes_consumed)`.
pub fn decode_rlp_item(input: &[u8]) -> Result<(RlpItem, usize), String> {
    if input.is_empty() {
        return Err("Unexpected EOF in RLP input".to_string());
    }
    let b0 = input[0];
    if b0 <= 0x7f {
        Ok((RlpItem::Bytes(vec![b0]), 1))
    } else if b0 <= 0xb7 {
        let len = (b0 - 0x80) as usize;
        if input.len() < 1 + len {
            return Err("Truncated RLP short byte string".to_string());
        }
        Ok((RlpItem::Bytes(input[1..1 + len].to_vec()), 1 + len))
    } else if b0 <= 0xbf {
        let len_of_len = (b0 - 0xb7) as usize;
        if input.len() < 1 + len_of_len {
            return Err("Truncated RLP long byte length".to_string());
        }
        let mut len = 0usize;
        for &b in &input[1..1 + len_of_len] {
            len = (len << 8) | (b as usize);
        }
        let start = 1 + len_of_len;
        if input.len() < start + len {
            return Err("Truncated RLP long byte string".to_string());
        }
        Ok((RlpItem::Bytes(input[start..start + len].to_vec()), start + len))
    } else if b0 <= 0xf7 {
        let list_len = (b0 - 0xc0) as usize;
        if input.len() < 1 + list_len {
            return Err("Truncated RLP short list".to_string());
        }
        let items = decode_rlp_sequence(&input[1..1 + list_len])?;
        Ok((RlpItem::List(items), 1 + list_len))
    } else {
        let len_of_len = (b0 - 0xf7) as usize;
        if input.len() < 1 + len_of_len {
            return Err("Truncated RLP long list length".to_string());
        }
        let mut list_len = 0usize;
        for &b in &input[1..1 + len_of_len] {
            list_len = (list_len << 8) | (b as usize);
        }
        let start = 1 + len_of_len;
        if input.len() < start + list_len {
            return Err("Truncated RLP long list payload".to_string());
        }
        let items = decode_rlp_sequence(&input[start..start + list_len])?;
        Ok((RlpItem::List(items), start + list_len))
    }
}

fn decode_rlp_sequence(mut slice: &[u8]) -> Result<Vec<RlpItem>, String> {
    let mut out = Vec::new();
    while !slice.is_empty() {
        let (item, used) = decode_rlp_item(slice)?;
        out.push(item);
        slice = &slice[used..];
    }
    Ok(out)
}

pub fn rlp_encode_bytes(bytes: &[u8]) -> Vec<u8> {
    if bytes.len() == 1 && bytes[0] <= 0x7f {
        return vec![bytes[0]];
    }
    let mut out = Vec::new();
    if bytes.len() <= 55 {
        out.push(0x80 + bytes.len() as u8);
        out.extend_from_slice(bytes);
    } else {
        let len_bytes = to_minimal_be_bytes(bytes.len() as u128);
        out.push(0xb7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
        out.extend_from_slice(bytes);
    }
    out
}

pub fn rlp_encode_u128(val: u128) -> Vec<u8> {
    if val == 0 {
        return vec![0x80];
    }
    rlp_encode_bytes(&to_minimal_be_bytes(val))
}

pub fn rlp_encode_list(encoded_items: &[Vec<u8>]) -> Vec<u8> {
    let total_len: usize = encoded_items.iter().map(|v| v.len()).sum();
    let mut out = Vec::new();
    if total_len <= 55 {
        out.push(0xc0 + total_len as u8);
    } else {
        let len_bytes = to_minimal_be_bytes(total_len as u128);
        out.push(0xf7 + len_bytes.len() as u8);
        out.extend_from_slice(&len_bytes);
    }
    for item in encoded_items {
        out.extend_from_slice(item);
    }
    out
}

fn to_minimal_be_bytes(val: u128) -> Vec<u8> {
    if val == 0 {
        return Vec::new();
    }
    let be = val.to_be_bytes();
    let first_nonzero = be.iter().position(|&b| b != 0).unwrap_or(15);
    be[first_nonzero..].to_vec()
}

fn rlp_bytes_to_u128(b: &[u8]) -> Result<u128, String> {
    if b.len() > 16 {
        return Err("RLP integer exceeds u128".to_string());
    }
    let mut acc = 0u128;
    for &byte in b {
        acc = (acc << 8) | (byte as u128);
    }
    Ok(acc)
}

fn decode_evm_rlp_items(
    tx_type: u8,
    items: &[RlpItem],
    raw_tx_sha256: [u8; 32],
) -> Result<DecodedIntent, String> {
    // EIP-1559 (0x02) & EIP-7702 (0x04) RLP fields:
    // [0]=chain_id, [1]=nonce, [2]=max_prio_fee, [3]=max_fee, [4]=gas_limit, [5]=to, [6]=value, [7]=data, [8]=access_list, [9]=auth_list (0x04)
    let to_bytes = match &items[5] {
        RlpItem::Bytes(b) if b.len() == 20 => {
            let mut arr = [0u8; 20];
            arr.copy_from_slice(b);
            arr
        }
        _ => return Err("RLP `to` field must be 20 bytes".to_string()),
    };
    let value = match &items[6] {
        RlpItem::Bytes(b) => rlp_bytes_to_u128(b)?,
        _ => return Err("RLP `value` field must be bytes".to_string()),
    };
    let calldata = match &items[7] {
        RlpItem::Bytes(b) => b.as_slice(),
        _ => return Err("RLP `data` field must be bytes".to_string()),
    };

    if tx_type == 0x04 {
        // EIP-7702 SetCode transaction: inspect authorization_list at index 9
        if items.len() < 10 {
            return Err("EIP-7702 RLP transaction missing authorization_list".to_string());
        }
        let (auth_chain_id, delegate_code_address) = match &items[9] {
            RlpItem::List(tuples) if !tuples.is_empty() => match &tuples[0] {
                RlpItem::List(fields) if fields.len() >= 2 => {
                    let cid = match &fields[0] {
                        RlpItem::Bytes(b) => rlp_bytes_to_u128(b)? as u64,
                        _ => 0,
                    };
                    let addr = match &fields[1] {
                        RlpItem::Bytes(b) if b.len() == 20 => {
                            let mut a = [0u8; 20];
                            a.copy_from_slice(b);
                            a
                        }
                        _ => return Err("Invalid 20-byte delegate address in EIP-7702 tuple".to_string()),
                    };
                    (cid, addr)
                }
                _ => return Err("Malformed EIP-7702 authorization tuple".to_string()),
            },
            _ => return Err("Empty EIP-7702 authorization_list".to_string()),
        };

        let cross_chain_note = if auth_chain_id == 0 {
            " [CRITICAL: chain_id=0 universal cross-chain replay authorization!]"
        } else {
            ""
        };
        return Ok(DecodedIntent {
            chain: ChainId::Ethereum,
            op_kind: OperationKind::Eip7702SetCodeDelegation {
                auth_chain_id,
                delegate_code_address,
            },
            recipient: delegate_code_address,
            amount: value,
            risk: RiskLevel::Forbidden,
            summary: format!(
                "FORBIDDEN EIP-7702 RLP SetCode Delegation to {:02x?}{} (Binance Oct-2026 vector)",
                &delegate_code_address[0..4],
                cross_chain_note
            ),
            raw_tx_sha256,
        });
    }

    if calldata.is_empty() {
        return Ok(DecodedIntent {
            chain: ChainId::Ethereum,
            op_kind: OperationKind::NativeTransfer,
            recipient: to_bytes,
            amount: value,
            risk: RiskLevel::Normal,
            summary: format!(
                "EVM RLP Native Transfer of {} wei to {:02x?}",
                value,
                &to_bytes[0..4]
            ),
            raw_tx_sha256,
        });
    }

    // Decode ABI selector on RLP calldata
    let mut synthetic = Vec::with_capacity(37 + calldata.len());
    synthetic.push(0x02);
    synthetic.extend_from_slice(&to_bytes);
    synthetic.extend_from_slice(&value.to_be_bytes());
    synthetic.extend_from_slice(calldata);
    decode_evm_frame(&synthetic, raw_tx_sha256)
}

/// Parses a hex string (`"0x04..."` or `"04..."`) into raw bytes.
pub fn parse_hex(hex_str: &str) -> Result<Vec<u8>, String> {
    let clean = hex_str.trim().strip_prefix("0x").unwrap_or(hex_str.trim());
    if clean.len() % 2 != 0 {
        return Err("Hex string must have an even number of characters".to_string());
    }
    let mut out = Vec::with_capacity(clean.len() / 2);
    let bytes = clean.as_bytes();
    for i in (0..bytes.len()).step_by(2) {
        let hi = hex_nibble(bytes[i])?;
        let lo = hex_nibble(bytes[i + 1])?;
        out.push((hi << 4) | lo);
    }
    Ok(out)
}

fn hex_nibble(b: u8) -> Result<u8, String> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(format!("Invalid hex character '{}'", b as char)),
    }
}

/// Audits a Safe{Wallet} EIP-712 transaction JSON (`{"to":"0x...","value":0,"operation":1,"data":"0x..."}`).
/// Detects the exact Bybit Feb-2025 `operation == 1` (`DELEGATECALL`) vector, inner ERC-20 unlimited approvals,
/// and unknown inner contract selectors (such as `upgradeTo` / `changeMasterCopy`).
pub fn audit_safe_tx_json(json_str: &str) -> Result<DecodedIntent, String> {
    let to_hex = extract_json_string_field(json_str, "to")
        .ok_or_else(|| "SafeTx JSON missing '\"to\"' address field".to_string())?;
    let to_bytes_vec = parse_hex(&to_hex)?;
    if to_bytes_vec.len() != 20 {
        return Err("SafeTx `to` address must be 20 bytes (40 hex chars)".to_string());
    }
    let mut to_addr = [0u8; 20];
    to_addr.copy_from_slice(&to_bytes_vec);

    let operation = extract_json_u64_field(json_str, "operation").unwrap_or(0) as u8;
    let value = extract_json_u64_field(json_str, "value").unwrap_or(0) as u128;
    let nonce = extract_json_u64_field(json_str, "nonce").unwrap_or(0);

    let data_bytes = match extract_json_string_field(json_str, "data") {
        Some(hex_s) if !hex_s.trim().is_empty() && hex_s.trim() != "0x" => parse_hex(&hex_s)?,
        _ => Vec::new(),
    };

    // Compute canonical EIP-712 SafeTx struct digest over (to, value, sha256(data), operation, nonce)
    let data_hash = sha256(&data_bytes);
    let mut eip712_buf = Vec::with_capacity(96);
    eip712_buf.extend_from_slice(b"SAFE_TX_EIP712_V1|");
    eip712_buf.extend_from_slice(&to_addr);
    eip712_buf.extend_from_slice(&value.to_be_bytes());
    eip712_buf.extend_from_slice(&data_hash);
    eip712_buf.push(operation);
    eip712_buf.extend_from_slice(&nonce.to_be_bytes());
    let raw_tx_sha256 = sha256(&eip712_buf);

    if operation == 1 {
        return Ok(DecodedIntent {
            chain: ChainId::Ethereum,
            op_kind: OperationKind::SafeExecTransaction { operation },
            recipient: to_addr,
            amount: value,
            risk: RiskLevel::Forbidden,
            summary: format!(
                "FORBIDDEN Safe{{Wallet}} EIP-712 JSON with operation=1 (DELEGATECALL) to {:02x?} (Bybit Feb-2025 vector)",
                &to_addr[0..4]
            ),
            raw_tx_sha256,
        });
    }

    // If inner `data` is present on an operation=0 CALL, decode the inner ABI selector fail-closed!
    if !data_bytes.is_empty() {
        let mut synthetic = Vec::with_capacity(37 + data_bytes.len());
        synthetic.push(0x02);
        synthetic.extend_from_slice(&to_addr);
        synthetic.extend_from_slice(&value.to_be_bytes());
        synthetic.extend_from_slice(&data_bytes);
        let mut inner_intent = decode_evm_frame(&synthetic, raw_tx_sha256)?;
        inner_intent.summary = format!("Safe{{Wallet}} Inner Call -> {}", inner_intent.summary);
        return Ok(inner_intent);
    }

    Ok(DecodedIntent {
        chain: ChainId::Ethereum,
        op_kind: OperationKind::SafeExecTransaction { operation },
        recipient: to_addr,
        amount: value,
        risk: RiskLevel::Normal,
        summary: format!(
            "Safe{{Wallet}} EIP-712 JSON CALL (operation=0, nonce={}) of {} wei to {:02x?}",
            nonce,
            value,
            &to_addr[0..4]
        ),
        raw_tx_sha256,
    })
}

fn extract_json_string_field(json: &str, key: &str) -> Option<String> {
    let pattern = format!("\"{}\"", key);
    let idx = json.find(&pattern)?;
    let rest = &json[idx + pattern.len()..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start();
    if !after_colon.starts_with('"') {
        return None;
    }
    let inner = &after_colon[1..];
    let end_q = inner.find('"')?;
    Some(inner[..end_q].to_string())
}

fn extract_json_u64_field(json: &str, key: &str) -> Option<u64> {
    let pattern = format!("\"{}\"", key);
    let idx = json.find(&pattern)?;
    let rest = &json[idx + pattern.len()..];
    let colon = rest.find(':')?;
    let after_colon = rest[colon + 1..].trim_start().trim_start_matches('"');
    let digits: String = after_colon
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    digits.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decode_eip7702_setcode_marked_forbidden() {
        let raw = builders::build_eip7702_setcode_tx(0, [0x11; 20], 0, [0x99; 20]);
        let intent = decode_transaction(ChainId::Ethereum, &raw, None).unwrap();
        assert_eq!(intent.risk, RiskLevel::Forbidden);
        assert!(matches!(
            intent.op_kind,
            OperationKind::Eip7702SetCodeDelegation {
                auth_chain_id: 0,
                ..
            }
        ));
    }

    #[test]
    fn test_decode_safe_delegatecall_and_ui_spoof() {
        let raw = builders::build_safe_exec_tx([0x55; 20], [0xBB; 20], 0, 1);
        let intent = decode_transaction(ChainId::Ethereum, &raw, None).unwrap();
        assert_eq!(intent.risk, RiskLevel::Forbidden);

        // With mismatched UI claim, decoder marks RiskLevel::Forbidden with CRITICAL BLIND-SIGNING SPOOF summary
        let spoof = ClaimedUiSummary {
            claimed_recipient: [0xAA; 20],
            claimed_amount: 500,
        };
        let spoofed_intent = decode_transaction(ChainId::Ethereum, &raw, Some(&spoof)).unwrap();
        assert_eq!(spoofed_intent.risk, RiskLevel::Forbidden);
        assert!(spoofed_intent.summary.contains("CRITICAL BLIND-SIGNING SPOOF"));
    }

    #[test]
    fn test_bitcoin_excessive_fee_marked_forbidden() {
        let raw = builders::build_bitcoin_psbt([0x22; 20], 10_000, 5_000);
        let intent = decode_transaction(ChainId::Bitcoin, &raw, None).unwrap();
        assert_eq!(intent.risk, RiskLevel::Forbidden);
    }

    #[test]
    fn test_real_rlp_eip7702_and_safe_json_auditor() {
        let rlp_tx = builders::build_real_rlp_eip7702_tx(1, [0xAA; 20], 0, 0, [0xDE; 20]);
        let intent = decode_transaction(ChainId::Ethereum, &rlp_tx, None).unwrap();
        assert_eq!(intent.risk, RiskLevel::Forbidden);
        assert!(intent.summary.contains("EIP-7702 RLP SetCode Delegation"));

        let safe_json = r#"{"to":"0xdededededededededededededededededededede","value":0,"operation":1,"data":"0x"}"#;
        let safe_intent = audit_safe_tx_json(safe_json).unwrap();
        assert_eq!(safe_intent.risk, RiskLevel::Forbidden);
        assert!(safe_intent.summary.contains("DELEGATECALL"));

        // Safe JSON with operation=0 (CALL), but inner data is an unlimited ERC-20 approve (0x095ea7b3):
        let unlimited_approve_json = r#"{"to":"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48","value":0,"operation":0,"data":"0x095ea7b3000000000000000000000000dedededededededededededededededededededeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"}"#;
        let inner_intent = audit_safe_tx_json(unlimited_approve_json).unwrap();
        assert_eq!(inner_intent.risk, RiskLevel::Forbidden);
        assert!(inner_intent.summary.contains("unlimited=true"));
    }
}
