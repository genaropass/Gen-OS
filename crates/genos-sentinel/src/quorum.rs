//! Ring 2C — **M-of-N Cryptographic Quorum & Role Separation (`quorum.rs`)**.
//!
//! Replaces single-user localhost approval with cryptographic M-of-N multi-operator quorum:
//! - Each operator holds an independent cryptographic keypair on a separate hardware device.
//! - Each operator signs the exact `ApprovalCommitment` binding `branch_id`, `raw_tx_sha256`,
//!   and `decoded_intent_hash`.
//! - **Anti-Self-Approval Invariant**: The peer identity that submitted the transaction request
//!   cannot participate as an approver.

use std::collections::{BTreeMap, BTreeSet};

use causal_core::hash::sha256;
use causal_core::pqc::{PqcKeyPair, PqcPublicKey, PqcSignature};

/// Cryptographic commitment over the exact transaction and decoded intent held in Escrow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalCommitment {
    pub branch_id: u32,
    pub requester_id: String,
    pub raw_tx_sha256: [u8; 32],
    pub decoded_intent_hash: [u8; 32],
    pub expiry_secs: u64,
}

impl ApprovalCommitment {
    pub fn digest(&self) -> [u8; 32] {
        let mut buf = Vec::with_capacity(112);
        buf.extend_from_slice(b"GENOS_QUORUM_COMMITMENT_V1|");
        buf.extend_from_slice(&self.branch_id.to_le_bytes());
        buf.extend_from_slice(self.requester_id.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(&self.raw_tx_sha256);
        buf.extend_from_slice(&self.decoded_intent_hash);
        buf.extend_from_slice(&self.expiry_secs.to_le_bytes());
        sha256(&buf)
    }
}

/// Cryptographically signed approval statement from an independent human security officer.
#[derive(Debug, Clone)]
pub struct SignedOperatorApproval {
    pub operator_id: String,
    pub branch_id: u32,
    pub commitment_digest: [u8; 32],
    pub signer_pubkey: PqcPublicKey,
    pub signature: PqcSignature,
}

impl SignedOperatorApproval {
    pub fn sign_commitment(
        operator_id: &str,
        commitment: &ApprovalCommitment,
        operator_keypair: &PqcKeyPair,
    ) -> Self {
        let commitment_digest = commitment.digest();
        let signature = operator_keypair.sign(&commitment_digest);
        Self {
            operator_id: operator_id.to_string(),
            branch_id: commitment.branch_id,
            commitment_digest,
            signer_pubkey: operator_keypair.public_key(),
            signature,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumError {
    UnknownOperator { operator_id: String },
    SelfApprovalForbidden { operator_id: String },
    CommitmentMismatch,
    ApprovalExpired { now_secs: u64, expiry_secs: u64 },
    InvalidOperatorSignature { operator_id: String },
    DuplicateOperatorApproval { operator_id: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QuorumStatus {
    Pending { collected: usize, required_m: usize },
    Reached { approvers: Vec<String> },
}

/// Verifies M-of-N cryptographic operator approvals with strict role separation.
pub struct QuorumVerifier {
    pub required_m: usize,
    pub registered_operators: BTreeMap<String, [u8; 32]>,
    approvals_by_branch: BTreeMap<u32, BTreeSet<String>>,
}

impl QuorumVerifier {
    pub fn new(required_m: usize) -> Self {
        Self {
            required_m: required_m.max(1),
            registered_operators: BTreeMap::new(),
            approvals_by_branch: BTreeMap::new(),
        }
    }

    pub fn register_operator(&mut self, operator_id: &str, pubkey_root: [u8; 32]) {
        self.registered_operators
            .insert(operator_id.to_string(), pubkey_root);
    }

    /// Validates and records a single operator's cryptographic approval for `commitment`.
    pub fn submit_approval(
        &mut self,
        commitment: &ApprovalCommitment,
        approval: &SignedOperatorApproval,
        now_secs: u64,
    ) -> Result<QuorumStatus, QuorumError> {
        // 1. Check expiration
        if now_secs > commitment.expiry_secs {
            return Err(QuorumError::ApprovalExpired {
                now_secs,
                expiry_secs: commitment.expiry_secs,
            });
        }

        // 2. Role Separation: requester cannot approve their own withdrawal
        if approval.operator_id == commitment.requester_id {
            return Err(QuorumError::SelfApprovalForbidden {
                operator_id: approval.operator_id.clone(),
            });
        }

        // 3. Check operator is registered and public key matches pinned root
        let expected_root = self
            .registered_operators
            .get(&approval.operator_id)
            .ok_or_else(|| QuorumError::UnknownOperator {
                operator_id: approval.operator_id.clone(),
            })?;
        if &approval.signer_pubkey.root != expected_root {
            return Err(QuorumError::InvalidOperatorSignature {
                operator_id: approval.operator_id.clone(),
            });
        }

        // 4. Verify commitment digest matches the exact raw bytes + decoded intent in Escrow
        let expected_digest = commitment.digest();
        if approval.branch_id != commitment.branch_id
            || approval.commitment_digest != expected_digest
        {
            return Err(QuorumError::CommitmentMismatch);
        }

        // 5. Verify cryptographic signature over the commitment digest
        if !approval
            .signer_pubkey
            .verify(&expected_digest, &approval.signature)
        {
            return Err(QuorumError::InvalidOperatorSignature {
                operator_id: approval.operator_id.clone(),
            });
        }

        // 6. Record unique operator approval
        let set = self
            .approvals_by_branch
            .entry(commitment.branch_id)
            .or_default();
        if !set.insert(approval.operator_id.clone()) {
            return Err(QuorumError::DuplicateOperatorApproval {
                operator_id: approval.operator_id.clone(),
            });
        }

        if set.len() >= self.required_m {
            Ok(QuorumStatus::Reached {
                approvers: set.iter().cloned().collect(),
            })
        } else {
            Ok(QuorumStatus::Pending {
                collected: set.len(),
                required_m: self.required_m,
            })
        }
    }
}
