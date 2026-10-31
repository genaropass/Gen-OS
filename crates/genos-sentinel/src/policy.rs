//! Ring 2B — **Custody Policy, Sliding-Window Velocity Limiter & Automatic Circuit Breaker**.
//!
//! Prevents rapid multi-chain wallet drains (such as the October 29, 2026 Binance 20-minute drain)
//! by enforcing per-tx ceilings, 1-hour sliding-window velocity caps, destination whitelists,
//! and an automatic `CircuitState::Frozen` breaker.

use std::collections::{BTreeMap, BTreeSet};

use crate::shield::PeerOriginKind;
use crate::txdecode::{ChainId, DecodedIntent, RiskLevel};

/// State of the global GenOS Sentinel Circuit Breaker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CircuitState {
    /// Normal operation: policy and velocity limits are enforced per transaction.
    Armed,
    /// Emergency freeze triggered automatically by an attack indicator or velocity breach.
    /// Zero transactions can be co-signed on ANY chain until an M-of-N operator quorum unfreezes it.
    Frozen { reason: String, tripped_at_secs: u64 },
}

#[derive(Debug, Clone)]
pub struct ChainLimits {
    /// Maximum amount allowed in a single transaction without M-of-N human quorum.
    pub auto_sign_max_amount: u128,
    /// Hard maximum amount allowed in a single transaction even before velocity check.
    pub hard_single_tx_cap: u128,
    /// Maximum cumulative outflow allowed within any 3,600-second (1-hour) sliding window.
    pub hourly_velocity_cap: u128,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyVerdict {
    /// Transaction is within automated limits, to a whitelisted destination, from a trusted service.
    AllowImmediateCoSign,
    /// Transaction is valid but requires M-of-N human cryptographic quorum in Escrow.
    HoldForQuorum { reason: String },
    /// Transaction violates a hard security invariant -> reject AND trip global Circuit Breaker!
    RejectAndFreeze { reason: String },
}

/// Configurable custody policy for GenOS Sentinel.
pub struct CustodyPolicy {
    pub whitelisted_destinations: BTreeSet<[u8; 20]>,
    pub chain_limits: BTreeMap<ChainId, ChainLimits>,
    pub circuit_state: CircuitState,
    outflow_history: Vec<(u64, ChainId, u128)>,
}

impl CustodyPolicy {
    pub fn new() -> Self {
        Self {
            whitelisted_destinations: BTreeSet::new(),
            chain_limits: BTreeMap::new(),
            circuit_state: CircuitState::Armed,
            outflow_history: Vec::new(),
        }
    }

    pub fn add_whitelisted_destination(&mut self, addr: [u8; 20]) {
        self.whitelisted_destinations.insert(addr);
    }

    pub fn set_chain_limits(&mut self, chain: ChainId, limits: ChainLimits) {
        self.chain_limits.insert(chain, limits);
    }

    pub fn is_frozen(&self) -> bool {
        matches!(self.circuit_state, CircuitState::Frozen { .. })
    }

    pub fn trip_circuit_breaker(&mut self, reason: String, now_secs: u64) {
        if !self.is_frozen() {
            self.circuit_state = CircuitState::Frozen {
                reason,
                tripped_at_secs: now_secs,
            };
        }
    }

    pub fn unfreeze_after_quorum(&mut self) {
        self.circuit_state = CircuitState::Armed;
    }

    /// Computes total outflow for `chain` in the last 3,600 seconds `[now_secs - 3600, now_secs]`.
    pub fn current_hourly_outflow(&self, chain: ChainId, now_secs: u64) -> u128 {
        let cutoff = now_secs.saturating_sub(3600);
        self.outflow_history
            .iter()
            .filter(|&&(ts, ch, _)| ch == chain && ts >= cutoff)
            .map(|&(_, _, amt)| amt)
            .fold(0u128, |acc, x| acc.saturating_add(x))
    }

    /// Records a committed outflow into the sliding window.
    pub fn record_committed_outflow(&mut self, chain: ChainId, amount: u128, now_secs: u64) {
        self.outflow_history.push((now_secs, chain, amount));
    }

    /// Evaluates a decoded transaction intent against the active policy, velocity window, and origin.
    pub fn evaluate(
        &mut self,
        intent: &DecodedIntent,
        origin: PeerOriginKind,
        session_tainted: bool,
        now_secs: u64,
    ) -> PolicyVerdict {
        // 1. If Circuit Breaker is already Frozen, reject everything immediately
        if let CircuitState::Frozen { ref reason, .. } = self.circuit_state {
            return PolicyVerdict::RejectAndFreeze {
                reason: format!("Circuit Breaker is FROZEN ({})", reason),
            };
        }

        // 2. Forbidden operation kinds (EIP-7702 SetCode, Safe DELEGATECALL, UI Spoof, Unlimited Approve)
        // immediately trip the global Circuit Breaker!
        if intent.risk == RiskLevel::Forbidden {
            let reason = format!("Forbidden operation blocked: {}", intent.summary);
            self.trip_circuit_breaker(reason.clone(), now_secs);
            return PolicyVerdict::RejectAndFreeze { reason };
        }

        // 3. Lookup chain limits (fail-closed if chain has no configured limits)
        let limits = match self.chain_limits.get(&intent.chain) {
            Some(l) => l.clone(),
            None => {
                let reason = format!("No chain limits configured for {:?}", intent.chain);
                self.trip_circuit_breaker(reason.clone(), now_secs);
                return PolicyVerdict::RejectAndFreeze { reason };
            }
        };

        // 4. Hard single-transaction ceiling
        if intent.amount > limits.hard_single_tx_cap {
            let reason = format!(
                "Amount {} exceeds hard single-tx cap {} on {:?}",
                intent.amount, limits.hard_single_tx_cap, intent.chain
            );
            self.trip_circuit_breaker(reason.clone(), now_secs);
            return PolicyVerdict::RejectAndFreeze { reason };
        }

        // 5. Sliding-window 1-hour velocity limit check
        let prior_outflow = self.current_hourly_outflow(intent.chain, now_secs);
        let projected = prior_outflow.saturating_add(intent.amount);
        if projected > limits.hourly_velocity_cap {
            let reason = format!(
                "1-hour velocity cap exceeded on {:?}: projected {} > cap {} (automatic drain protection)",
                intent.chain, projected, limits.hourly_velocity_cap
            );
            self.trip_circuit_breaker(reason.clone(), now_secs);
            return PolicyVerdict::RejectAndFreeze { reason };
        }

        // 6. Destination whitelist check -> non-whitelisted destinations ALWAYS require M-of-N human quorum
        if !self.whitelisted_destinations.contains(&intent.recipient) {
            return PolicyVerdict::HoldForQuorum {
                reason: format!(
                    "Destination {:02x?} is not in the verified whitelist; M-of-N hardware quorum required",
                    &intent.recipient[0..4]
                ),
            };
        }

        // 7. Interactive DevOps session or DIFC tainted session -> ALWAYS hold for M-of-N human quorum
        if origin == PeerOriginKind::InteractiveDevOpsSession || session_tainted {
            return PolicyVerdict::HoldForQuorum {
                reason: "Order originated from interactive DevOps/tainted context; M-of-N quorum required"
                    .to_string(),
            };
        }

        // 8. Amount exceeds auto-sign threshold -> hold for M-of-N human quorum
        if intent.amount > limits.auto_sign_max_amount || intent.risk == RiskLevel::HighRequiresQuorum
        {
            return PolicyVerdict::HoldForQuorum {
                reason: format!(
                    "Amount {} exceeds automated co-signing limit {}; M-of-N quorum required",
                    intent.amount, limits.auto_sign_max_amount
                ),
            };
        }

        PolicyVerdict::AllowImmediateCoSign
    }
}

impl Default for CustodyPolicy {
    fn default() -> Self {
        Self::new()
    }
}
