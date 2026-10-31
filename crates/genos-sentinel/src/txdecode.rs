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
}
