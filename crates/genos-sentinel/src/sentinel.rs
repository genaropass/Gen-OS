//! Core **GenOS Sentinel** Orchestrator, Cryptographically Signed Ledger, and Red-Team Suite.
//!
//! Combines:
//! - **Ring 1 (`GenosShield`)**: IP/CIDR allowlist, Signed Binary Manifest verification,
//!   Peer session signature & monotonic anti-replay nonce.
//! - **Capability & DIFC Engine (`CSpace`, `SecurityLabel`, `EscrowManager`)**: Generational
//!   capability verification and origin taint tracking.
//! - **Ring 2 (`txdecode`, `CustodyPolicy`, `QuorumVerifier`)**: Independent transaction decoding
//!   (EIP-7702, Safe DELEGATECALL, ERC-20, BTC PSBT), sliding-window velocity limiter, automatic
//!   Circuit Breaker, and M-of-N cryptographic operator quorum.
//! - **Signed Audit Ledger (`SignedAuditLedger`)**: Every decision is both SHA-256 hash-chained
//!   AND cryptographically signed by the Sentinel keypair, preventing full-file rewrite attacks.

use std::collections::BTreeMap;

use capability_engine::{CSpace, CapId, ObjectId, Permissions};
use causal_core::hash::sha256;
use causal_core::pqc::{PqcKeyPair, PqcPublicKey, PqcSignature};
use causal_core::{BranchId, EffectId, EscrowManager, SecurityLabel, TaintMask};

use crate::policy::{ChainLimits, CustodyPolicy, PolicyVerdict};
use crate::quorum::{ApprovalCommitment, QuorumError, QuorumStatus, QuorumVerifier, SignedOperatorApproval};
use crate::shield::{
    GenosShield, Ipv4Cidr, PeerOriginKind, RegisteredPeer, ShieldError, SignedBinaryManifest,
    SignedPeerEnvelope,
};
use crate::txdecode::{
    builders, decode_transaction, ChainId, ClaimedUiSummary, DecodedIntent,
};

/// Cryptographic co-signature emitted by GenOS Sentinel when (and only when) all Ring 1 + Ring 2
/// invariants pass. Without this co-signature, the downstream multisig/MPC cannot broadcast.
#[derive(Debug, Clone)]
pub struct SentinelCoSignature {
    pub ledger_seq: u64,
    pub raw_tx_sha256: [u8; 32],
    pub decoded_intent_hash: [u8; 32],
    pub sentinel_pubkey: PqcPublicKey,
    pub signature: PqcSignature,
}

impl SentinelCoSignature {
    pub fn verify(&self) -> bool {
        let mut msg = [0u8; 64];
        msg[0..32].copy_from_slice(&self.raw_tx_sha256);
        msg[32..64].copy_from_slice(&self.decoded_intent_hash);
        let digest = sha256(&msg);
        self.sentinel_pubkey.verify(&digest, &self.signature)
    }
}

/// A single cryptographically signed and hash-chained entry in the Sentinel Audit Ledger.
#[derive(Debug, Clone)]
pub struct SignedLedgerEntry {
    pub seq: u64,
    pub timestamp_secs: u64,
    pub peer_id: String,
    pub decision: String,
    pub detail: String,
    pub prev_hash: [u8; 32],
    pub entry_hash: [u8; 32],
    pub sentinel_pubkey: PqcPublicKey,
    pub sentinel_signature: PqcSignature,
}

impl SignedLedgerEntry {
    pub fn compute_entry_hash(
        seq: u64,
        timestamp_secs: u64,
        peer_id: &str,
        decision: &str,
        detail: &str,
        prev_hash: &[u8; 32],
    ) -> [u8; 32] {
        let mut buf = Vec::with_capacity(128 + detail.len());
        buf.extend_from_slice(prev_hash);
        buf.extend_from_slice(&seq.to_le_bytes());
        buf.extend_from_slice(&timestamp_secs.to_le_bytes());
        buf.extend_from_slice(peer_id.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(decision.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(detail.as_bytes());
        sha256(&buf)
    }
}

/// Append-only ledger where every entry is signed by the Sentinel authority key,
/// closing Gap B7 (prevents an attacker with disk access from rewriting the hash chain).
pub struct SignedAuditLedger {
    pub entries: Vec<SignedLedgerEntry>,
    pub trusted_sentinel_roots: Vec<[u8; 32]>,
    signing_seed_base: [u8; 32],
}

impl SignedAuditLedger {
    pub fn new(signing_seed_base: [u8; 32]) -> Self {
        Self {
            entries: Vec::new(),
            trusted_sentinel_roots: Vec::new(),
            signing_seed_base,
        }
    }

    pub fn append(
        &mut self,
        timestamp_secs: u64,
        peer_id: &str,
        decision: &str,
        detail: &str,
    ) -> u64 {
        let seq = (self.entries.len() as u64) + 1;
        let prev_hash = self
            .entries
            .last()
            .map(|e| e.entry_hash)
            .unwrap_or([0u8; 32]);
        let entry_hash = SignedLedgerEntry::compute_entry_hash(
            seq,
            timestamp_secs,
            peer_id,
            decision,
            detail,
            &prev_hash,
        );

        // Derive a unique one-time WOTS keypair per ledger sequence number
        let mut per_entry_seed = [0u8; 40];
        per_entry_seed[0..32].copy_from_slice(&self.signing_seed_base);
        per_entry_seed[32..40].copy_from_slice(&seq.to_le_bytes());
        let kp = PqcKeyPair::from_seed(sha256(&per_entry_seed));
        let pubkey = kp.public_key();
        let sig = kp.sign(&entry_hash);
        self.trusted_sentinel_roots.push(pubkey.root);

        self.entries.push(SignedLedgerEntry {
            seq,
            timestamp_secs,
            peer_id: peer_id.to_string(),
            decision: decision.to_string(),
            detail: detail.to_string(),
            prev_hash,
            entry_hash,
            sentinel_pubkey: pubkey,
            sentinel_signature: sig,
        });
        seq
    }

    /// Verifies both the SHA-256 hash chain AND the pinned Sentinel WOTS signature on every entry.
    pub fn verify_integrity(&self) -> Result<usize, String> {
        let mut expected_prev = [0u8; 32];
        for (idx, entry) in self.entries.iter().enumerate() {
            if entry.prev_hash != expected_prev {
                return Err(format!("Broken prev_hash link at seq #{}", entry.seq));
            }
            let recomputed = SignedLedgerEntry::compute_entry_hash(
                entry.seq,
                entry.timestamp_secs,
                &entry.peer_id,
                &entry.decision,
                &entry.detail,
                &entry.prev_hash,
            );
            if recomputed != entry.entry_hash {
                return Err(format!("Tampered entry_hash at seq #{}", entry.seq));
            }
            let pinned_root = self
                .trusted_sentinel_roots
                .get(idx)
                .ok_or_else(|| format!("Missing pinned Sentinel root for seq #{}", entry.seq))?;
            if &entry.sentinel_pubkey.root != pinned_root {
                return Err(format!(
                    "Forged Sentinel public key at seq #{} (rewrite attack detected)",
                    entry.seq
                ));
            }
            if !entry
                .sentinel_pubkey
                .verify(&entry.entry_hash, &entry.sentinel_signature)
            {
                return Err(format!("Invalid Sentinel signature at seq #{}", entry.seq));
            }
            expected_prev = entry.entry_hash;
        }
        Ok(self.entries.len())
    }
}

/// Held transaction staged in `EscrowManager` awaiting M-of-N cryptographic operator quorum.
pub struct HeldWithdrawal {
    pub branch_id: u32,
    pub commitment: ApprovalCommitment,
    pub intent: DecodedIntent,
    pub raw_bytes: Vec<u8>,
}

#[derive(Debug)]
pub enum SentinelDecision {
    /// Co-signed immediately (within automated limits, whitelisted destination, trusted service).
    CoSigned(SentinelCoSignature),
    /// Held in `EscrowManager` awaiting M-of-N human cryptographic quorum.
    HeldInEscrow {
        branch_id: u32,
        commitment: ApprovalCommitment,
        decoded_summary: String,
        reason: String,
    },
    /// Rejected at Ring 1 (Shield) or Ring 2 (Policy/Decoder); Circuit Breaker tripped if critical.
    Rejected {
        ledger_seq: u64,
        reason: String,
        circuit_frozen: bool,
    },
}

/// Full GenOS Shield + Sentinel engine.
pub struct GenosSentinel {
    pub shield: GenosShield,
    pub cspace: CSpace,
    pub policy: CustodyPolicy,
    pub quorum: QuorumVerifier,
    pub escrow: EscrowManager,
    pub ledger: SignedAuditLedger,
    pub held_withdrawals: BTreeMap<u32, HeldWithdrawal>,
    next_branch_id: u32,
    cosign_seed: [u8; 32],
}

impl GenosSentinel {
    pub fn new(required_quorum_m: usize, master_seed: [u8; 32]) -> Self {
        Self {
            shield: GenosShield::new(),
            cspace: CSpace::new(),
            policy: CustodyPolicy::new(),
            quorum: QuorumVerifier::new(required_quorum_m),
            escrow: EscrowManager::new(),
            ledger: SignedAuditLedger::new(master_seed),
            held_withdrawals: BTreeMap::new(),
            next_branch_id: 1,
            cosign_seed: sha256(&master_seed),
        }
    }

    /// Mints a withdrawal capability in `CSpace`.
    pub fn mint_withdrawal_capability(&mut self, object_id: u64) -> CapId {
        self.cspace.mint_root(
            ObjectId(object_id),
            Permissions::READ | Permissions::WRITE | Permissions::EXECUTE,
            1,
        )
    }

    /// Evaluates a withdrawal signing request through Ring 1 (GenOS Shield) and Ring 2 (GenOS Sentinel).
    #[allow(clippy::too_many_arguments)]
    pub fn submit_withdrawal(
        &mut self,
        envelope: &SignedPeerEnvelope,
        cap_id: CapId,
        chain: ChainId,
        raw_tx_bytes: &[u8],
        ui_claim: Option<&ClaimedUiSummary>,
        now_secs: u64,
    ) -> SentinelDecision {
        // -----------------------------------------------------------------
        // RING 1: GenOS Shield (IP Allowlist + Signed Binary + Peer Auth)
        // -----------------------------------------------------------------
        let origin_kind = match self
            .shield
            .verify_incoming_request(envelope, raw_tx_bytes, now_secs)
        {
            Ok(kind) => kind,
            Err(shield_err) => {
                let reason = format!("Ring 1 Shield blocked request: {:?}", shield_err);
                // Any binary integrity or unauthorized IP from a production peer trips the breaker
                if matches!(
                    shield_err,
                    ShieldError::UntrustedBinaryHash
                        | ShieldError::InvalidBinarySignature { .. }
                        | ShieldError::UnauthorizedIp { .. }
                ) {
                    self.policy.trip_circuit_breaker(reason.clone(), now_secs);
                }
                let seq = self
                    .ledger
                    .append(now_secs, &envelope.peer_id, "SHIELD_REJECT", &reason);
                return SentinelDecision::Rejected {
                    ledger_seq: seq,
                    reason,
                    circuit_frozen: self.policy.is_frozen(),
                };
            }
        };

        // -----------------------------------------------------------------
        // RING 1B: Generational Capability Check (`CSpace`)
        // -----------------------------------------------------------------
        if let Err(cap_err) = self.cspace.verify(cap_id, Permissions::EXECUTE) {
            let reason = format!("Capability verification failed: {:?}", cap_err);
            let seq = self
                .ledger
                .append(now_secs, &envelope.peer_id, "CAP_REJECT", &reason);
            return SentinelDecision::Rejected {
                ledger_seq: seq,
                reason,
                circuit_frozen: self.policy.is_frozen(),
            };
        }

        // Compute DIFC origin taint label
        let session_label = match origin_kind {
            PeerOriginKind::AutomatedProductionService => SecurityLabel::TRUSTED_KERNEL,
            PeerOriginKind::InteractiveDevOpsSession => SecurityLabel::UNTRUSTED_EXTERNAL,
        };
        let is_tainted = session_label.taint_mask != TaintMask::CLEAN;

        // -----------------------------------------------------------------
        // RING 2A: Independent Transaction Decoder (Anti-Blind-Signing)
        // -----------------------------------------------------------------
        let intent = match decode_transaction(chain, raw_tx_bytes, ui_claim) {
            Ok(decoded) => decoded,
            Err(dec_err) => {
                let reason = format!("Transaction decoder fail-closed rejection: {}", dec_err);
                self.policy.trip_circuit_breaker(reason.clone(), now_secs);
                let seq = self
                    .ledger
                    .append(now_secs, &envelope.peer_id, "DECODE_REJECT", &reason);
                return SentinelDecision::Rejected {
                    ledger_seq: seq,
                    reason,
                    circuit_frozen: self.policy.is_frozen(),
                };
            }
        };

        // -----------------------------------------------------------------
        // RING 2B: Custody Policy, Velocity Limiter & Circuit Breaker
        // -----------------------------------------------------------------
        match self
            .policy
            .evaluate(&intent, origin_kind, is_tainted, now_secs)
        {
            PolicyVerdict::AllowImmediateCoSign => {
                self.policy
                    .record_committed_outflow(intent.chain, intent.amount, now_secs);
                let seq = self.ledger.append(
                    now_secs,
                    &envelope.peer_id,
                    "COSIGN_ALLOW",
                    &intent.summary,
                );
                let cosig = self.mint_cosignature(seq, &intent);
                SentinelDecision::CoSigned(cosig)
            }
            PolicyVerdict::HoldForQuorum { reason } => {
                let branch_id = self.next_branch_id;
                self.next_branch_id += 1;

                let seq = self.ledger.append(
                    now_secs,
                    &envelope.peer_id,
                    "ESCROW_HOLD",
                    &format!("{} | {}", intent.summary, reason),
                );
                self.escrow.stage_action(
                    BranchId(branch_id),
                    EffectId(seq),
                    raw_tx_bytes.to_vec(),
                );

                let commitment = ApprovalCommitment {
                    branch_id,
                    requester_id: envelope.peer_id.clone(),
                    raw_tx_sha256: intent.raw_tx_sha256,
                    decoded_intent_hash: intent.intent_hash(),
                    expiry_secs: now_secs + 3600,
                };

                self.held_withdrawals.insert(
                    branch_id,
                    HeldWithdrawal {
                        branch_id,
                        commitment: commitment.clone(),
                        intent: intent.clone(),
                        raw_bytes: raw_tx_bytes.to_vec(),
                    },
                );

                SentinelDecision::HeldInEscrow {
                    branch_id,
                    commitment,
                    decoded_summary: intent.summary,
                    reason,
                }
            }
            PolicyVerdict::RejectAndFreeze { reason } => {
                let seq = self
                    .ledger
                    .append(now_secs, &envelope.peer_id, "CIRCUIT_FREEZE", &reason);
                SentinelDecision::Rejected {
                    ledger_seq: seq,
                    reason,
                    circuit_frozen: self.policy.is_frozen(),
                }
            }
        }
    }

    /// Submits an independent operator's signed approval for a held withdrawal in Escrow.
    /// Once M-of-N approvals are reached, commits the Escrow branch and issues the `SentinelCoSignature`.
    pub fn approve_held_withdrawal(
        &mut self,
        approval: &SignedOperatorApproval,
        now_secs: u64,
    ) -> Result<Option<SentinelCoSignature>, QuorumError> {
        let held = self
            .held_withdrawals
            .get(&approval.branch_id)
            .ok_or(QuorumError::CommitmentMismatch)?;

        let status = self
            .quorum
            .submit_approval(&held.commitment, approval, now_secs)?;

        match status {
            QuorumStatus::Pending { .. } => {
                self.ledger.append(
                    now_secs,
                    &approval.operator_id,
                    "QUORUM_PARTIAL",
                    &format!("Approved branch #{}", approval.branch_id),
                );
                Ok(None)
            }
            QuorumStatus::Reached { approvers } => {
                let held = self.held_withdrawals.remove(&approval.branch_id).unwrap();
                let released = self.escrow.commit_branch(BranchId(held.branch_id));
                debug_assert!(!released.is_empty());

                self.policy.record_committed_outflow(
                    held.intent.chain,
                    held.intent.amount,
                    now_secs,
                );
                let seq = self.ledger.append(
                    now_secs,
                    &approval.operator_id,
                    "QUORUM_COMMIT_COSIGN",
                    &format!(
                        "Branch #{} committed by M-of-N quorum {:?}: {}",
                        held.branch_id, approvers, held.intent.summary
                    ),
                );
                Ok(Some(self.mint_cosignature(seq, &held.intent)))
            }
        }
    }

    fn mint_cosignature(&self, ledger_seq: u64, intent: &DecodedIntent) -> SentinelCoSignature {
        let mut seed_buf = [0u8; 40];
        seed_buf[0..32].copy_from_slice(&self.cosign_seed);
        seed_buf[32..40].copy_from_slice(&ledger_seq.to_le_bytes());
        let kp = PqcKeyPair::from_seed(sha256(&seed_buf));

        let mut msg = [0u8; 64];
        msg[0..32].copy_from_slice(&intent.raw_tx_sha256);
        msg[32..64].copy_from_slice(&intent.intent_hash());
        let digest = sha256(&msg);
        let signature = kp.sign(&digest);

        SentinelCoSignature {
            ledger_seq,
            raw_tx_sha256: intent.raw_tx_sha256,
            decoded_intent_hash: intent.intent_hash(),
            sentinel_pubkey: kp.public_key(),
            signature,
        }
    }
}

/// Reproducible Red-Team Simulation Suite modeling:
/// 1. **Binance Oct-2026 Attack** (DevOps laptop compromise -> unauthorized container IP / unsigned binary -> EIP-7702 SetCode delegation -> multi-chain velocity drain).
/// 2. **Bybit Feb-2025 Attack** (Safe{Wallet} UI blind-signing spoof -> `execTransaction` with `operation = 1` `DELEGATECALL`).
/// 3. **Single Compromised Operator Key & Self-Approval Attack**.
/// 4. **Authorized 2-of-3 Hardware Quorum Treasury Transfer**.
pub struct RedTeamReport {
    pub scenario_name: String,
    pub attacker_goal: String,
    pub defense_layer_triggered: String,
    pub funds_lost_wei_or_sats: u128,
    pub circuit_breaker_frozen: bool,
    pub ledger_verified_entries: usize,
}

pub fn run_all_redteam_scenarios() -> Vec<RedTeamReport> {
    vec![
        simulate_scenario_1_binance_oct_2026_eip7702_and_devops_breach(),
        simulate_scenario_2_bybit_feb_2025_safe_delegatecall_blind_signing(),
        simulate_scenario_3_unauthorized_ip_and_trojanized_binary(),
        simulate_scenario_4_velocity_drain_and_quorum_protection(),
    ]
}

fn setup_test_sentinel() -> (GenosSentinel, PqcKeyPair, [u8; 32], CapId, [u8; 20]) {
    let mut sentinel = GenosSentinel::new(2, *b"GENOS_SENTINEL_MASTER_SEED_2026!");

    // 1. Register release authority and sign the official withdrawal container binary
    let release_auth_kp = PqcKeyPair::from_seed(*b"RELEASE_AUTHORITY_KEY_SEED_00001");
    sentinel
        .shield
        .binary_registry
        .add_trusted_authority(release_auth_kp.public_key().root);

    let official_binary_bytes = b"ELF64_OFFICIAL_WITHDRAWAL_SERVICE_BINARY_V1.0";
    let manifest = SignedBinaryManifest::sign_new(
        "withdrawal-service-v1",
        official_binary_bytes,
        0x07,
        &release_auth_kp,
    );
    let binary_hash = manifest.binary_sha256;
    sentinel
        .shield
        .binary_registry
        .register_manifest(manifest)
        .unwrap();

    // 2. Register production peer (`prod-withdraw-svc`) restricted to subnet `10.10.1.0/24`
    sentinel.shield.register_peer(RegisteredPeer {
        peer_id: "prod-withdraw-svc".to_string(),
        allowed_subnets: vec![Ipv4Cidr::new([10, 10, 1, 0], 24)],
        allowed_binary_hashes: vec![binary_hash],
        origin_kind: PeerOriginKind::AutomatedProductionService,
        last_nonce: 0,
        active: true,
    });

    // 3. Configure Ethereum & Bitcoin velocity limits and whitelisted warm wallet
    let whitelisted_warm_wallet = [0xAA; 20];
    sentinel
        .policy
        .add_whitelisted_destination(whitelisted_warm_wallet);
    sentinel.policy.set_chain_limits(
        ChainId::Ethereum,
        ChainLimits {
            auto_sign_max_amount: 10_000,
            hard_single_tx_cap: 100_000,
            hourly_velocity_cap: 25_000,
        },
    );
    sentinel.policy.set_chain_limits(
        ChainId::Bitcoin,
        ChainLimits {
            auto_sign_max_amount: 5_000,
            hard_single_tx_cap: 50_000,
            hourly_velocity_cap: 15_000,
        },
    );

    let cap = sentinel.mint_withdrawal_capability(100);
    let peer_kp = PqcKeyPair::from_seed(*b"PROD_WITHDRAW_SVC_SESSION_KEY_01");

    (sentinel, peer_kp, binary_hash, cap, whitelisted_warm_wallet)
}

/// Scenario 1: Replays the October 29, 2026 Binance attack vector (compromised DevOps pivot into
/// service container attempting EIP-7702 SetCode delegation + rapid multi-chain BTC/ETH drain).
pub fn simulate_scenario_1_binance_oct_2026_eip7702_and_devops_breach() -> RedTeamReport {
    let (mut sentinel, peer_kp, binary_hash, cap, warm_wallet) = setup_test_sentinel();

    // Step 1: Attacker inside the container submits an EIP-7702 (`0x04`) SetCode transaction
    // attempting to delegate the hot wallet's code to Lazarus drainer contract `[0xDE; 20]`
    // with `auth_chain_id = 0` (cross-chain replay).
    let lazarus_drainer = [0xDE; 20];
    let malicious_7702_tx =
        builders::build_eip7702_setcode_tx(0, warm_wallet, 0, lazarus_drainer);

    let env1 = SignedPeerEnvelope::sign_new(
        "prod-withdraw-svc",
        [10, 10, 1, 42],
        binary_hash,
        1,
        1_700_000_000,
        60,
        &malicious_7702_tx,
        &peer_kp,
    );

    let dec1 = sentinel.submit_withdrawal(
        &env1,
        cap,
        ChainId::Ethereum,
        &malicious_7702_tx,
        None,
        1_700_000_005,
    );
    assert!(matches!(
        dec1,
        SentinelDecision::Rejected {
            circuit_frozen: true,
            ..
        }
    ));

    // Step 2: Attacker immediately tries to drain Bitcoin hot wallet on a second chain,
    // but the global Circuit Breaker is already FROZEN!
    let btc_drain_tx = builders::build_bitcoin_psbt(warm_wallet, 4_000, 10);
    let peer_kp2 = PqcKeyPair::from_seed(*b"PROD_WITHDRAW_SVC_SESSION_KEY_02");
    let env2 = SignedPeerEnvelope::sign_new(
        "prod-withdraw-svc",
        [10, 10, 1, 42],
        binary_hash,
        2,
        1_700_000_006,
        60,
        &btc_drain_tx,
        &peer_kp2,
    );
    let dec2 = sentinel.submit_withdrawal(
        &env2,
        cap,
        ChainId::Bitcoin,
        &btc_drain_tx,
        None,
        1_700_000_007,
    );
    assert!(matches!(
        dec2,
        SentinelDecision::Rejected {
            circuit_frozen: true,
            ..
        }
    ));

    let verified = sentinel.ledger.verify_integrity().unwrap();
    RedTeamReport {
        scenario_name: "Binance Oct-2026 Replay (EIP-7702 SetCode + Multi-Chain Drain)".to_string(),
        attacker_goal: "Delegate hot-wallet execution via EIP-7702 (0x04) and drain ETH + BTC in 20 minutes".to_string(),
        defense_layer_triggered: "Ring 2A Independent Decoder caught EIP-7702 (0x04, chain_id=0) + Ring 2B Circuit Breaker FROZE all chains".to_string(),
        funds_lost_wei_or_sats: 0,
        circuit_breaker_frozen: sentinel.policy.is_frozen(),
        ledger_verified_entries: verified,
    }
}

/// Scenario 2: Replays the February 21, 2025 Bybit Safe{Wallet} blind-signing attack
/// (Frontend UI claims a normal transfer to `warm_wallet`, while raw bytes execute `DELEGATECALL`).
pub fn simulate_scenario_2_bybit_feb_2025_safe_delegatecall_blind_signing() -> RedTeamReport {
    let (mut sentinel, peer_kp, binary_hash, cap, warm_wallet) = setup_test_sentinel();

    let safe_contract = [0x5A; 20];
    let attacker_impl = [0xFA; 20];
    // operation = 1 (DELEGATECALL)
    let malicious_safe_tx = builders::build_safe_exec_tx(safe_contract, attacker_impl, 0, 1);

    // Compromised web UI claims this is a harmless transfer of 1,000 wei to `warm_wallet`
    let spoofed_ui_claim = ClaimedUiSummary {
        claimed_recipient: warm_wallet,
        claimed_amount: 1_000,
    };

    let env = SignedPeerEnvelope::sign_new(
        "prod-withdraw-svc",
        [10, 10, 1, 15],
        binary_hash,
        1,
        1_700_000_100,
        60,
        &malicious_safe_tx,
        &peer_kp,
    );

    let decision = sentinel.submit_withdrawal(
        &env,
        cap,
        ChainId::Ethereum,
        &malicious_safe_tx,
        Some(&spoofed_ui_claim),
        1_700_000_102,
    );
    assert!(matches!(
        decision,
        SentinelDecision::Rejected {
            circuit_frozen: true,
            ..
        }
    ));

    // Follow-up attempt after Safe DELEGATECALL is also blocked by the frozen Circuit Breaker
    let followup_tx = builders::build_evm_native_transfer(warm_wallet, 1_000);
    let peer_kp2 = PqcKeyPair::from_seed(*b"PROD_WITHDRAW_SVC_SESSION_KEY_22");
    let env2 = SignedPeerEnvelope::sign_new(
        "prod-withdraw-svc",
        [10, 10, 1, 15],
        binary_hash,
        2,
        1_700_000_105,
        60,
        &followup_tx,
        &peer_kp2,
    );
    let dec2 = sentinel.submit_withdrawal(
        &env2,
        cap,
        ChainId::Ethereum,
        &followup_tx,
        None,
        1_700_000_106,
    );
    assert!(matches!(
        dec2,
        SentinelDecision::Rejected {
            circuit_frozen: true,
            ..
        }
    ));

    let verified = sentinel.ledger.verify_integrity().unwrap();
    RedTeamReport {
        scenario_name: "Bybit Feb-2025 Replay (Safe{Wallet} UI Spoof + DELEGATECALL)".to_string(),
        attacker_goal: "Trick signers with benign UI while signing Safe execTransaction(operation=1 DELEGATECALL)".to_string(),
        defense_layer_triggered: "Ring 2A Independent Decoder detected both Safe DELEGATECALL (op=1) and UI Blind-Signing Spoof -> Circuit Breaker FROZEN".to_string(),
        funds_lost_wei_or_sats: 0,
        circuit_breaker_frozen: sentinel.policy.is_frozen(),
        ledger_verified_entries: verified,
    }
}

/// Scenario 3: Replays an attacker attempting to connect from an unauthorized IP or running an
/// unsigned/trojanized binary inside the container (Ring 1 GenOS Shield).
pub fn simulate_scenario_3_unauthorized_ip_and_trojanized_binary() -> RedTeamReport {
    let (mut sentinel, peer_kp, binary_hash, cap, warm_wallet) = setup_test_sentinel();

    let tx = builders::build_evm_native_transfer(warm_wallet, 500);

    // Attack A: Valid binary hash, but request comes from an unauthorized IP `[192, 168, 99, 5]`
    // outside `10.10.1.0/24`.
    let env_bad_ip = SignedPeerEnvelope::sign_new(
        "prod-withdraw-svc",
        [192, 168, 99, 5],
        binary_hash,
        1,
        1_700_000_200,
        60,
        &tx,
        &peer_kp,
    );
    let dec_ip = sentinel.submit_withdrawal(
        &env_bad_ip,
        cap,
        ChainId::Ethereum,
        &tx,
        None,
        1_700_000_201,
    );
    assert!(matches!(
        dec_ip,
        SentinelDecision::Rejected {
            circuit_frozen: true,
            ..
        }
    ));

    // Unfreeze to also test Attack B (trojanized binary with unverified SHA-256 hash)
    sentinel.policy.unfreeze_after_quorum();
    let trojan_binary_hash = sha256(b"TROJANIZED_PYTHON_DOCKER_SCRIPT_BY_LAZARUS");
    let peer_kp2 = PqcKeyPair::from_seed(*b"PROD_WITHDRAW_SVC_SESSION_KEY_03");
    let env_bad_bin = SignedPeerEnvelope::sign_new(
        "prod-withdraw-svc",
        [10, 10, 1, 10],
        trojan_binary_hash,
        2,
        1_700_000_210,
        60,
        &tx,
        &peer_kp2,
    );
    let dec_bin = sentinel.submit_withdrawal(
        &env_bad_bin,
        cap,
        ChainId::Ethereum,
        &tx,
        None,
        1_700_000_211,
    );
    assert!(matches!(
        dec_bin,
        SentinelDecision::Rejected {
            circuit_frozen: true,
            ..
        }
    ));

    let verified = sentinel.ledger.verify_integrity().unwrap();
    RedTeamReport {
        scenario_name: "GenOS Shield Perimeter (Unauthorized IP + Trojanized Binary)".to_string(),
        attacker_goal: "Issue withdrawal from external/lateral IP 192.168.99.5 or execute unsigned binary".to_string(),
        defense_layer_triggered: "Ring 1 GenOS Shield blocked UnauthorizedIp & UntrustedBinaryHash and froze Circuit Breaker".to_string(),
        funds_lost_wei_or_sats: 0,
        circuit_breaker_frozen: sentinel.policy.is_frozen(),
        ledger_verified_entries: verified,
    }
}

/// Scenario 4: Tests 2-of-3 hardware operator cryptographic quorum for a high-value withdrawal
/// (blocks self-approval, requires 2 distinct operators, and enforces 1-hour velocity cap).
pub fn simulate_scenario_4_velocity_drain_and_quorum_protection() -> RedTeamReport {
    let (mut sentinel, peer_kp, binary_hash, cap, warm_wallet) = setup_test_sentinel();

    // Register 3 independent hardware operators
    let op1_kp = PqcKeyPair::from_seed(*b"HARDWARE_FIDO_OPERATOR_ALICE_KEY");
    let op2_kp = PqcKeyPair::from_seed(*b"HARDWARE_FIDO_OPERATOR_BOB_KEY!!");
    sentinel
        .quorum
        .register_operator("alice-secops", op1_kp.public_key().root);
    sentinel
        .quorum
        .register_operator("bob-treasury", op2_kp.public_key().root);

    // High-value transfer (20,000 > auto_sign_max_amount 10,000) -> Held in Escrow for 2-of-3 quorum
    let high_val_tx = builders::build_evm_native_transfer(warm_wallet, 20_000);
    let env1 = SignedPeerEnvelope::sign_new(
        "prod-withdraw-svc",
        [10, 10, 1, 20],
        binary_hash,
        1,
        1_700_000_300,
        60,
        &high_val_tx,
        &peer_kp,
    );
    let dec1 = sentinel.submit_withdrawal(
        &env1,
        cap,
        ChainId::Ethereum,
        &high_val_tx,
        None,
        1_700_000_301,
    );
    let (_branch_id, commitment) = match dec1 {
        SentinelDecision::HeldInEscrow {
            branch_id,
            commitment,
            ..
        } => (branch_id, commitment),
        other => panic!("Expected HeldInEscrow, got {:?}", other),
    };

    // 1. Self-approval attempt by requester (`prod-withdraw-svc`) -> FORBIDDEN
    let self_app =
        SignedOperatorApproval::sign_commitment("prod-withdraw-svc", &commitment, &peer_kp);
    assert_eq!(
        sentinel.approve_held_withdrawal(&self_app, 1_700_000_305).unwrap_err(),
        QuorumError::SelfApprovalForbidden {
            operator_id: "prod-withdraw-svc".to_string()
        }
    );

    // 2. First valid operator (`alice-secops`) approves -> 1 of 2 (still pending!)
    let app1 = SignedOperatorApproval::sign_commitment("alice-secops", &commitment, &op1_kp);
    assert!(sentinel
        .approve_held_withdrawal(&app1, 1_700_000_306)
        .unwrap()
        .is_none());

    // 3. Second valid operator (`bob-treasury`) approves -> 2 of 2 reached -> Co-signed!
    let app2 = SignedOperatorApproval::sign_commitment("bob-treasury", &commitment, &op2_kp);
    let cosig = sentinel
        .approve_held_withdrawal(&app2, 1_700_000_307)
        .unwrap()
        .expect("Expected SentinelCoSignature after 2-of-2 quorum");
    assert!(cosig.verify());

    // 4. Now cumulative 1-hour outflow is 20,000 (hourly cap is 25,000).
    // An attacker tries a second transfer of 8,000 within the same hour (20,000 + 8,000 = 28,000 > 25,000)
    // -> Velocity limiter trips Circuit Breaker to FROZEN!
    let drain_tx = builders::build_evm_native_transfer(warm_wallet, 8_000);
    let peer_kp2 = PqcKeyPair::from_seed(*b"PROD_WITHDRAW_SVC_SESSION_KEY_09");
    let env2 = SignedPeerEnvelope::sign_new(
        "prod-withdraw-svc",
        [10, 10, 1, 20],
        binary_hash,
        2,
        1_700_000_320,
        60,
        &drain_tx,
        &peer_kp2,
    );
    let dec2 = sentinel.submit_withdrawal(
        &env2,
        cap,
        ChainId::Ethereum,
        &drain_tx,
        None,
        1_700_000_321,
    );
    assert!(matches!(
        dec2,
        SentinelDecision::Rejected {
            circuit_frozen: true,
            ..
        }
    ));

    let verified = sentinel.ledger.verify_integrity().unwrap();
    RedTeamReport {
        scenario_name: "M-of-N Hardware Quorum + Sliding-Window Velocity Circuit Breaker".to_string(),
        attacker_goal: "Self-approve held withdrawal or exceed 1-hour velocity cap across multiple transactions".to_string(),
        defense_layer_triggered: "Ring 2C blocked Self-Approval, verified 2-of-2 hardware quorum, then Ring 2B froze on velocity breach".to_string(),
        funds_lost_wei_or_sats: 0,
        circuit_breaker_frozen: sentinel.policy.is_frozen(),
        ledger_verified_entries: verified,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_all_four_lazarus_redteam_scenarios_pass_with_zero_theft() {
        let reports = run_all_redteam_scenarios();
        assert_eq!(reports.len(), 4);
        for r in &reports {
            assert_eq!(r.funds_lost_wei_or_sats, 0);
            assert!(r.circuit_breaker_frozen);
            assert!(r.ledger_verified_entries >= 2);
        }
    }

    #[test]
    fn test_signed_audit_ledger_detects_full_chain_rewrite_attack() {
        let mut ledger = SignedAuditLedger::new(*b"SENTINEL_LEDGER_KEY_SEED_0000001");
        ledger.append(100, "peer-1", "COSIGN_ALLOW", "Transfer 100");
        ledger.append(105, "peer-1", "CIRCUIT_FREEZE", "Blocked EIP-7702");
        assert_eq!(ledger.verify_integrity().unwrap(), 2);

        // Suppose an attacker with disk write access alters entry #2 and recomputes its SHA-256 hash
        // and signs it with their own forged WOTS keypair:
        let fake_kp = PqcKeyPair::from_seed(*b"ATTACKER_FORGED_KEY_SEED_0000000");
        let prev_hash = ledger.entries[0].entry_hash;
        let forged_hash = SignedLedgerEntry::compute_entry_hash(
            2,
            105,
            "peer-1",
            "COSIGN_ALLOW",
            "Attacker rewrote history",
            &prev_hash,
        );
        ledger.entries[1].decision = "COSIGN_ALLOW".to_string();
        ledger.entries[1].detail = "Attacker rewrote history".to_string();
        ledger.entries[1].entry_hash = forged_hash;
        ledger.entries[1].sentinel_pubkey = fake_kp.public_key();
        ledger.entries[1].sentinel_signature = fake_kp.sign(&forged_hash);

        let err = ledger.verify_integrity().unwrap_err();
        assert!(err.contains("Forged Sentinel public key at seq #2"));
    }
}
