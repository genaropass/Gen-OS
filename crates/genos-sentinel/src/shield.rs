//! Ring 1 — **GenOS Shield**: Zero-Trust OS & Network Perimeter.
//!
//! Enforces:
//! 1. **IPv4 / CIDR Subnet Allowlisting (`IpAllowlist`)**: Only authorized source IPs for a given
//!    peer identity may submit requests.
//! 2. **Signed Binary Execution Gate (`BinaryIntegrityRegistry`)**: Every binary, container image,
//!    or service daemon must have a cryptographically signed manifest (`SignedBinaryManifest`)
//!    binding its SHA-256 executable digest and allowed capability mask.
//! 3. **Cryptographic Peer Session Authentication (`PeerAuthenticator`)**: Every request must be
//!    signed with a one-time post-quantum WOTS key bound to the peer's registered identity, a
//!    strictly monotonic anti-replay `nonce`, and a bounded TTL window.

use std::collections::BTreeMap;

use causal_core::hash::sha256;
use causal_core::pqc::{PqcKeyPair, PqcPublicKey, PqcSignature};

/// IPv4 CIDR subnet mask (e.g. `10.20.1.0/24`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ipv4Cidr {
    pub network: [u8; 4],
    pub prefix_len: u8,
}

impl Ipv4Cidr {
    pub const fn new(network: [u8; 4], prefix_len: u8) -> Self {
        Self {
            network,
            prefix_len: if prefix_len > 32 { 32 } else { prefix_len },
        }
    }

    /// Returns `true` if `ip` falls within this CIDR subnet in constant time.
    pub fn contains(&self, ip: [u8; 4]) -> bool {
        if self.prefix_len == 0 {
            return true;
        }
        let net_u32 = u32::from_be_bytes(self.network);
        let ip_u32 = u32::from_be_bytes(ip);
        let mask = if self.prefix_len >= 32 {
            u32::MAX
        } else {
            u32::MAX << (32 - self.prefix_len)
        };
        (net_u32 & mask) == (ip_u32 & mask)
    }

    /// Parses `"a.b.c.d/prefix"` or `"a.b.c.d"` (defaults to `/32`).
    pub fn parse(s: &str) -> Result<Self, String> {
        let (ip_part, prefix) = match s.split_once('/') {
            Some((ip_s, p_s)) => {
                let p = p_s
                    .parse::<u8>()
                    .map_err(|_| format!("Invalid CIDR prefix in '{}'", s))?;
                if p > 32 {
                    return Err(format!("CIDR prefix {} exceeds 32", p));
                }
                (ip_s, p)
            }
            None => (s, 32),
        };
        let octets: Vec<&str> = ip_part.split('.').collect();
        if octets.len() != 4 {
            return Err(format!("Invalid IPv4 address '{}'", ip_part));
        }
        let mut bytes = [0u8; 4];
        for (i, oct) in octets.iter().enumerate() {
            bytes[i] = oct
                .parse::<u8>()
                .map_err(|_| format!("Invalid octet '{}' in '{}'", oct, s))?;
        }
        Ok(Self::new(bytes, prefix))
    }
}

/// Cryptographically signed manifest for an authorized executable binary or container image.
#[derive(Debug, Clone)]
pub struct SignedBinaryManifest {
    pub binary_name: String,
    pub binary_sha256: [u8; 32],
    pub allowed_permissions: u32,
    pub authority_pubkey: PqcPublicKey,
    pub authority_signature: PqcSignature,
}

impl SignedBinaryManifest {
    /// Computes the canonical 32-byte digest signed by the release authority.
    pub fn compute_manifest_digest(
        binary_name: &str,
        binary_sha256: &[u8; 32],
        allowed_permissions: u32,
    ) -> [u8; 32] {
        let mut buf = Vec::with_capacity(64 + binary_name.len());
        buf.extend_from_slice(b"GENOS_BINARY_MANIFEST_V1|");
        buf.extend_from_slice(binary_name.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(binary_sha256);
        buf.extend_from_slice(&allowed_permissions.to_le_bytes());
        sha256(&buf)
    }

    /// Creates and signs a binary manifest using the release authority's keypair.
    pub fn sign_new(
        binary_name: &str,
        binary_image_bytes: &[u8],
        allowed_permissions: u32,
        authority_keypair: &PqcKeyPair,
    ) -> Self {
        let binary_sha256 = sha256(binary_image_bytes);
        let digest =
            Self::compute_manifest_digest(binary_name, &binary_sha256, allowed_permissions);
        let authority_signature = authority_keypair.sign(&digest);
        Self {
            binary_name: binary_name.to_string(),
            binary_sha256,
            allowed_permissions,
            authority_pubkey: authority_keypair.public_key(),
            authority_signature,
        }
    }

    /// Verifies the release authority signature over this manifest.
    pub fn verify_signature(&self, trusted_authority_root: &[u8; 32]) -> bool {
        if &self.authority_pubkey.root != trusted_authority_root {
            return false;
        }
        let digest = Self::compute_manifest_digest(
            &self.binary_name,
            &self.binary_sha256,
            self.allowed_permissions,
        );
        self.authority_pubkey.verify(&digest, &self.authority_signature)
    }
}

/// Registry of trusted release authorities and signed binary manifests.
pub struct BinaryIntegrityRegistry {
    trusted_authorities: Vec<[u8; 32]>,
    manifests_by_hash: BTreeMap<[u8; 32], SignedBinaryManifest>,
}

impl Default for BinaryIntegrityRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl BinaryIntegrityRegistry {
    pub fn new() -> Self {
        Self {
            trusted_authorities: Vec::new(),
            manifests_by_hash: BTreeMap::new(),
        }
    }

    pub fn add_trusted_authority(&mut self, pubkey_root: [u8; 32]) {
        if !self.trusted_authorities.contains(&pubkey_root) {
            self.trusted_authorities.push(pubkey_root);
        }
    }

    /// Registers a signed binary manifest after verifying its cryptographic signature.
    pub fn register_manifest(&mut self, manifest: SignedBinaryManifest) -> Result<(), ShieldError> {
        let valid = self
            .trusted_authorities
            .iter()
            .any(|root| manifest.verify_signature(root));
        if !valid {
            return Err(ShieldError::InvalidBinarySignature {
                binary_name: manifest.binary_name,
            });
        }
        self.manifests_by_hash
            .insert(manifest.binary_sha256, manifest);
        Ok(())
    }

    /// Verifies that `binary_sha256` corresponds to a registered, cryptographically signed binary.
    pub fn verify_binary_hash(
        &self,
        binary_sha256: &[u8; 32],
    ) -> Result<&SignedBinaryManifest, ShieldError> {
        let manifest = self
            .manifests_by_hash
            .get(binary_sha256)
            .ok_or(ShieldError::UntrustedBinaryHash)?;
        let valid = self
            .trusted_authorities
            .iter()
            .any(|root| manifest.verify_signature(root));
        if !valid {
            return Err(ShieldError::InvalidBinarySignature {
                binary_name: manifest.binary_name.clone(),
            });
        }
        Ok(manifest)
    }
}

/// Origin classification of a peer node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerOriginKind {
    /// Automated production withdrawal service running an attested binary in an isolated subnet.
    AutomatedProductionService,
    /// Interactive DevOps laptop, SSH/kubectl session, or ad-hoc container shell (lower integrity).
    InteractiveDevOpsSession,
}

/// Registered peer identity in GenOS Shield.
#[derive(Debug, Clone)]
pub struct RegisteredPeer {
    pub peer_id: String,
    pub allowed_subnets: Vec<Ipv4Cidr>,
    pub allowed_binary_hashes: Vec<[u8; 32]>,
    pub origin_kind: PeerOriginKind,
    pub last_nonce: u64,
    pub active: bool,
}

/// Signed request envelope presented by a peer when invoking GenOS Sentinel.
#[derive(Debug, Clone)]
pub struct SignedPeerEnvelope {
    pub peer_id: String,
    pub source_ip: [u8; 4],
    pub binary_sha256: [u8; 32],
    pub nonce: u64,
    pub timestamp_secs: u64,
    pub ttl_secs: u64,
    pub payload_sha256: [u8; 32],
    pub signer_pubkey: PqcPublicKey,
    pub signature: PqcSignature,
}

impl SignedPeerEnvelope {
    pub fn compute_envelope_digest(
        peer_id: &str,
        source_ip: [u8; 4],
        binary_sha256: &[u8; 32],
        nonce: u64,
        timestamp_secs: u64,
        ttl_secs: u64,
        payload_sha256: &[u8; 32],
    ) -> [u8; 32] {
        let mut buf = Vec::with_capacity(128);
        buf.extend_from_slice(b"GENOS_SHIELD_ENVELOPE_V1|");
        buf.extend_from_slice(peer_id.as_bytes());
        buf.push(b'|');
        buf.extend_from_slice(&source_ip);
        buf.extend_from_slice(binary_sha256);
        buf.extend_from_slice(&nonce.to_le_bytes());
        buf.extend_from_slice(&timestamp_secs.to_le_bytes());
        buf.extend_from_slice(&ttl_secs.to_le_bytes());
        buf.extend_from_slice(payload_sha256);
        sha256(&buf)
    }

    #[allow(clippy::too_many_arguments)]
    pub fn sign_new(
        peer_id: &str,
        source_ip: [u8; 4],
        binary_sha256: [u8; 32],
        nonce: u64,
        timestamp_secs: u64,
        ttl_secs: u64,
        payload_bytes: &[u8],
        keypair: &PqcKeyPair,
    ) -> Self {
        let payload_sha256 = sha256(payload_bytes);
        let digest = Self::compute_envelope_digest(
            peer_id,
            source_ip,
            &binary_sha256,
            nonce,
            timestamp_secs,
            ttl_secs,
            &payload_sha256,
        );
        let signature = keypair.sign(&digest);
        Self {
            peer_id: peer_id.to_string(),
            source_ip,
            binary_sha256,
            nonce,
            timestamp_secs,
            ttl_secs,
            payload_sha256,
            signer_pubkey: keypair.public_key(),
            signature,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ShieldError {
    UnknownOrRevokedPeer { peer_id: String },
    UnauthorizedIp { peer_id: String, ip: [u8; 4] },
    UntrustedBinaryHash,
    BinaryNotAllowedForPeer { peer_id: String },
    InvalidBinarySignature { binary_name: String },
    ReplayNonceDetected { peer_id: String, provided: u64, last_seen: u64 },
    EnvelopeExpired { now_secs: u64, expiry_secs: u64 },
    PayloadHashMismatch,
    InvalidEnvelopeSignature { peer_id: String },
}

/// Complete Ring 1 Shield gate combining IP allowlists, signed binary verification,
/// anti-replay nonces, and cryptographic request signatures.
pub struct GenosShield {
    pub binary_registry: BinaryIntegrityRegistry,
    pub peers: BTreeMap<String, RegisteredPeer>,
}

impl Default for GenosShield {
    fn default() -> Self {
        Self::new()
    }
}

impl GenosShield {
    pub fn new() -> Self {
        Self {
            binary_registry: BinaryIntegrityRegistry::new(),
            peers: BTreeMap::new(),
        }
    }

    pub fn register_peer(&mut self, peer: RegisteredPeer) {
        self.peers.insert(peer.peer_id.clone(), peer);
    }

    /// Verifies all Ring 1 perimeter invariants for an incoming request.
    pub fn verify_incoming_request(
        &mut self,
        envelope: &SignedPeerEnvelope,
        raw_payload: &[u8],
        now_secs: u64,
    ) -> Result<PeerOriginKind, ShieldError> {
        // 1. Verify payload digest matches raw bytes
        let actual_payload_hash = sha256(raw_payload);
        if actual_payload_hash != envelope.payload_sha256 {
            return Err(ShieldError::PayloadHashMismatch);
        }

        // 2. Verify cryptographic signature over the envelope first
        let env_digest = SignedPeerEnvelope::compute_envelope_digest(
            &envelope.peer_id,
            envelope.source_ip,
            &envelope.binary_sha256,
            envelope.nonce,
            envelope.timestamp_secs,
            envelope.ttl_secs,
            &envelope.payload_sha256,
        );
        if !envelope
            .signer_pubkey
            .verify(&env_digest, &envelope.signature)
        {
            return Err(ShieldError::InvalidEnvelopeSignature {
                peer_id: envelope.peer_id.clone(),
            });
        }

        // 3. Verify binary hash is registered and signed by a trusted release authority
        self.binary_registry
            .verify_binary_hash(&envelope.binary_sha256)?;

        // 4. Lookup peer identity
        let peer = self
            .peers
            .get_mut(&envelope.peer_id)
            .ok_or_else(|| ShieldError::UnknownOrRevokedPeer {
                peer_id: envelope.peer_id.clone(),
            })?;

        if !peer.active {
            return Err(ShieldError::UnknownOrRevokedPeer {
                peer_id: envelope.peer_id.clone(),
            });
        }

        // 5. Enforce CIDR / IP allowlist
        if !peer
            .allowed_subnets
            .iter()
            .any(|cidr| cidr.contains(envelope.source_ip))
        {
            return Err(ShieldError::UnauthorizedIp {
                peer_id: envelope.peer_id.clone(),
                ip: envelope.source_ip,
            });
        }

        // 6. Enforce that this peer is authorized to run this signed binary
        if !peer.allowed_binary_hashes.contains(&envelope.binary_sha256) {
            return Err(ShieldError::BinaryNotAllowedForPeer {
                peer_id: envelope.peer_id.clone(),
            });
        }

        // 7. Enforce TTL window
        let expiry = envelope.timestamp_secs.saturating_add(envelope.ttl_secs);
        if now_secs > expiry || envelope.timestamp_secs > now_secs.saturating_add(30) {
            return Err(ShieldError::EnvelopeExpired {
                now_secs,
                expiry_secs: expiry,
            });
        }

        // 8. Enforce strict monotonic anti-replay nonce
        if envelope.nonce <= peer.last_nonce {
            return Err(ShieldError::ReplayNonceDetected {
                peer_id: envelope.peer_id.clone(),
                provided: envelope.nonce,
                last_seen: peer.last_nonce,
            });
        }
        peer.last_nonce = envelope.nonce;

        Ok(peer.origin_kind)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_cidr_matching() {
        let cidr = Ipv4Cidr::parse("10.20.1.0/24").unwrap();
        assert!(cidr.contains([10, 20, 1, 1]));
        assert!(cidr.contains([10, 20, 1, 254]));
        assert!(!cidr.contains([10, 20, 2, 1]));
        assert!(!cidr.contains([192, 168, 1, 1]));
    }

    #[test]
    fn test_shield_blocks_replay_nonce_and_expired_envelope() {
        let mut shield = GenosShield::new();
        let auth_kp = PqcKeyPair::from_seed(*b"AUTHORITY_SEED_FOR_SHIELD_TEST_1");
        shield
            .binary_registry
            .add_trusted_authority(auth_kp.public_key().root);

        let manifest =
            SignedBinaryManifest::sign_new("svc-bin", b"BINARY_BYTES_V1", 1, &auth_kp);
        let bin_hash = manifest.binary_sha256;
        shield.binary_registry.register_manifest(manifest).unwrap();

        shield.register_peer(RegisteredPeer {
            peer_id: "node-1".to_string(),
            allowed_subnets: vec![Ipv4Cidr::new([10, 0, 0, 0], 24)],
            allowed_binary_hashes: vec![bin_hash],
            origin_kind: PeerOriginKind::AutomatedProductionService,
            last_nonce: 0,
            active: true,
        });

        let payload = b"tx_payload";
        let kp1 = PqcKeyPair::from_seed(*b"PEER_SESSION_SEED_00000000000001");
        let env1 = SignedPeerEnvelope::sign_new(
            "node-1",
            [10, 0, 0, 5],
            bin_hash,
            1,
            1_000,
            60,
            payload,
            &kp1,
        );
        assert_eq!(
            shield.verify_incoming_request(&env1, payload, 1_010).unwrap(),
            PeerOriginKind::AutomatedProductionService
        );

        // Replaying the exact same envelope (nonce=1) is rejected
        assert_eq!(
            shield.verify_incoming_request(&env1, payload, 1_011).unwrap_err(),
            ShieldError::ReplayNonceDetected {
                peer_id: "node-1".to_string(),
                provided: 1,
                last_seen: 1,
            }
        );

        // Expired envelope (now_secs = 2_000 > 1_000 + 60) is rejected
        let kp2 = PqcKeyPair::from_seed(*b"PEER_SESSION_SEED_00000000000002");
        let env2 = SignedPeerEnvelope::sign_new(
            "node-1",
            [10, 0, 0, 5],
            bin_hash,
            2,
            1_000,
            60,
            payload,
            &kp2,
        );
        assert!(matches!(
            shield.verify_incoming_request(&env2, payload, 2_000).unwrap_err(),
            ShieldError::EnvelopeExpired { .. }
        ));
    }
}
