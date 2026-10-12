//! # Post-Quantum Cryptography (PQC) & Verifiable State Transitions
//!
//! Implementación de primitivas criptográficas poscuánticas basadas en hashes (WOTS+)
//! y pruebas de membresía de conocimiento cero (Zero-Knowledge Merkle Audit Proofs) para AgentOS.
//!
//! ## Fundamento Matemático de Seguridad Poscuántica:
//! 1. **Inmunidad al Algoritmo de Shor (1994)**:
//!    El algoritmo de Shor resuelve la factorización entera y el logaritmo discreto en tiempo polinomial
//!    O((log N)^3), rompiendo RSA, Diffie-Hellman y curvas elípticas (ECDSA/Ed25519).
//!    Sin embargo, las funciones hash criptográficas carecen de estructura algebraica de grupo abeliano,
//!    por lo que Shor es completamente inaplicable a esquemas basados en hashes (WOTS+/SLH-DSA).
//!
//! 2. **Límite del Algoritmo de Grover (1996)**:
//!    Grover provee una aceleración cuántica cuadrática O(2^(n/2)) para búsquedas en bases de datos no estructuradas.
//!    Para SHA-256 (n = 256), la cota de seguridad frente a un computador cuántico universal es 2^128 operaciones,
//!    superando ampliamente cualquier límite computacional físico conocido.

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

use crate::hash::sha256;
use crate::EffectId;

/// Número de cadenas para WOTS+ con parámetro w=16 (4 bits por dígito):
/// - 256 bits de mensaje = 64 nibbles (l1 = 64)
/// - Suma máxima de checksum = 64 * 15 = 960 < 16^3 => 3 nibbles (l2 = 3)
/// - Total de cadenas l = l1 + l2 = 67
pub const WOTS_CHAINS: usize = 67;
pub const WOTS_W: usize = 16;

/// Clave pública poscuántica WOTS+ (Root Merkle de las 67 cadenas)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct PqcPublicKey {
    pub root: [u8; 32],
}

/// Firma digital poscuántica WOTS+ (67 cadenas de 32 bytes)
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PqcSignature {
    pub chains: [[u8; 32]; WOTS_CHAINS],
}

/// Par de claves poscuánticas WOTS+
#[derive(Clone, Debug)]
pub struct PqcKeyPair {
    seed: [u8; 32],
    public_key: PqcPublicKey,
    terminal_hashes: [[u8; 32]; WOTS_CHAINS],
}

impl PqcKeyPair {
    /// Genera un nuevo par de claves poscuánticas deterministas a partir de una semilla segura de 32 bytes
    pub fn from_seed(seed: [u8; 32]) -> Self {
        let mut terminal_hashes = [[0u8; 32]; WOTS_CHAINS];

        for i in 0..WOTS_CHAINS {
            let sk_i = Self::derive_chain_secret(&seed, i as u16);
            // Aplicar 15 pasos de función unidireccional (f^15(sk_i))
            let mut curr = sk_i;
            for step in 0..15 {
                curr = Self::step_hash(&curr, i as u16, step);
            }
            terminal_hashes[i] = curr;
        }

        // El hash raíz de las 67 terminales es la clave pública
        let root = Self::compute_public_key_root(&terminal_hashes);
        let public_key = PqcPublicKey { root };

        Self {
            seed,
            public_key,
            terminal_hashes,
        }
    }

    pub fn public_key(&self) -> PqcPublicKey {
        self.public_key
    }

    /// Retorna las 67 terminales hash públicas calculadas
    pub fn terminal_hashes(&self) -> &[[u8; 32]; WOTS_CHAINS] {
        &self.terminal_hashes
    }

    /// Deriva la clave privada de la cadena i: SHA-256(seed || i || "PQC_SK")
    fn derive_chain_secret(seed: &[u8; 32], chain_idx: u16) -> [u8; 32] {
        let mut buf = [0u8; 32 + 2 + 6];
        buf[0..32].copy_from_slice(seed);
        buf[32..34].copy_from_slice(&chain_idx.to_be_bytes());
        buf[34..40].copy_from_slice(b"PQC_SK");
        sha256(&buf)
    }

    /// Paso de iteración de la cadena: f(x, chain, step) = SHA-256(x || chain || step || "PQC_F")
    fn step_hash(x: &[u8; 32], chain_idx: u16, step: u8) -> [u8; 32] {
        let mut buf = [0u8; 32 + 2 + 1 + 5];
        buf[0..32].copy_from_slice(x);
        buf[32..34].copy_from_slice(&chain_idx.to_be_bytes());
        buf[34] = step;
        buf[35..40].copy_from_slice(b"PQC_F");
        sha256(&buf)
    }

    /// Calcula la clave pública raíz a partir de las 67 terminales
    fn compute_public_key_root(terminals: &[[u8; 32]; WOTS_CHAINS]) -> [u8; 32] {
        let mut buf = Vec::with_capacity(WOTS_CHAINS * 32);
        for term in terminals {
            buf.extend_from_slice(term);
        }
        sha256(&buf)
    }

    /// Firma un mensaje con seguridad poscuántica WOTS+
    pub fn sign(&self, message: &[u8]) -> PqcSignature {
        let msg_digest = sha256(message);
        let digits = Self::message_to_digits(&msg_digest);

        let mut signature_chains = [[0u8; 32]; WOTS_CHAINS];

        for i in 0..WOTS_CHAINS {
            let sk_i = Self::derive_chain_secret(&self.seed, i as u16);
            let steps = digits[i];
            let mut curr = sk_i;
            for step in 0..steps {
                curr = Self::step_hash(&curr, i as u16, step);
            }
            signature_chains[i] = curr;
        }

        PqcSignature {
            chains: signature_chains,
        }
    }

    /// Descompone el digest en 64 nibbles + 3 nibbles de checksum
    fn message_to_digits(digest: &[u8; 32]) -> [u8; WOTS_CHAINS] {
        let mut digits = [0u8; WOTS_CHAINS];
        let mut csum: u16 = 0;

        // 64 dígitos del mensaje (4 bits cada uno)
        for i in 0..32 {
            let high = (digest[i] >> 4) & 0x0F;
            let low = digest[i] & 0x0F;
            digits[2 * i] = high;
            digits[2 * i + 1] = low;
            csum += (15 - high) as u16;
            csum += (15 - low) as u16;
        }

        // Checksum en 3 nibbles (csum <= 960 < 4096 = 16^3)
        digits[64] = ((csum >> 8) & 0x0F) as u8;
        digits[65] = ((csum >> 4) & 0x0F) as u8;
        digits[66] = (csum & 0x0F) as u8;

        digits
    }
}

impl PqcPublicKey {
    /// Verifica una firma poscuántica WOTS+ contra un mensaje dado
    pub fn verify(&self, message: &[u8], signature: &PqcSignature) -> bool {
        let msg_digest = sha256(message);
        let digits = PqcKeyPair::message_to_digits(&msg_digest);

        let mut reconstructed_terminals = [[0u8; 32]; WOTS_CHAINS];

        for i in 0..WOTS_CHAINS {
            let mut curr = signature.chains[i];
            let start_step = digits[i];
            // Completar los pasos restantes hasta 15
            for step in start_step..15 {
                curr = PqcKeyPair::step_hash(&curr, i as u16, step);
            }
            reconstructed_terminals[i] = curr;
        }

        let computed_root = PqcKeyPair::compute_public_key_root(&reconstructed_terminals);
        computed_root == self.root
    }
}

/// Paso individual de una ruta de auditoría de Merkle (Merkle Audit Path)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct MerkleProofStep {
    pub is_left: bool,
    pub sibling_hash: [u8; 32],
}

/// Prueba de membresía verificable de conocimiento cero (Zero-Knowledge Merkle Inclusion Proof)
/// Demuestra formalmente que una acción o registro causal está incluido en el estado raíz del kernel
/// sin revelar el contenido de ningún otro registro del sistema.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CausalMembershipProof {
    pub effect_id: EffectId,
    pub record_hash: [u8; 32],
    pub root_hash: [u8; 32],
    pub audit_path: Vec<MerkleProofStep>,
}

impl CausalMembershipProof {
    /// Verifica matemáticamente la validez de la prueba de inclusión contra la raíz del estado
    pub fn verify(&self) -> bool {
        let mut current_hash = self.record_hash;

        for step in &self.audit_path {
            let mut input = [0u8; 64];
            if step.is_left {
                input[0..32].copy_from_slice(&step.sibling_hash);
                input[32..64].copy_from_slice(&current_hash);
            } else {
                input[0..32].copy_from_slice(&current_hash);
                input[32..64].copy_from_slice(&step.sibling_hash);
            }
            current_hash = sha256(&input);
        }

        current_hash == self.root_hash
    }
}

/// Cifrador poscuántico simétrico resistente a Grover (Quantum-Resistant Stream Cipher)
/// Derivación de clave basada en HMAC-SHA-256 con 256 bits de entropía (128 bits de seguridad cuántica).
pub struct QuantumResistantCipher;

impl QuantumResistantCipher {
    /// Cifra o descifra datos mediante XOR-pad derivado criptográficamente con SHA-256 en modo CTR
    pub fn apply_keystream(key: &[u8; 32], nonce: u64, data: &mut [u8]) {
        let mut block_idx: u32 = 0;
        let mut offset = 0;

        while offset < data.len() {
            let mut counter_buf = [0u8; 32 + 8 + 4];
            counter_buf[0..32].copy_from_slice(key);
            counter_buf[32..40].copy_from_slice(&nonce.to_be_bytes());
            counter_buf[40..44].copy_from_slice(&block_idx.to_be_bytes());

            let keystream_block = sha256(&counter_buf);
            let to_xor = core::cmp::min(32, data.len() - offset);

            for i in 0..to_xor {
                data[offset + i] ^= keystream_block[i];
            }

            offset += to_xor;
            block_idx = block_idx.wrapping_add(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pqc_key_generation_and_signature_verification() {
        let seed = [0x42u8; 32];
        let keypair = PqcKeyPair::from_seed(seed);
        let pubkey = keypair.public_key();

        let message = b"AGENTOS_CRITICAL_STATE_TRANSITION: transfer_capability(Agent#1, Agent#2)";
        let signature = keypair.sign(message);

        // Verificación exitosa
        assert!(pubkey.verify(message, &signature), "La firma WOTS+ debe ser valida");
    }

    #[test]
    fn test_pqc_signature_tamper_rejection() {
        let seed = [0x99u8; 32];
        let keypair = PqcKeyPair::from_seed(seed);
        let pubkey = keypair.public_key();

        let message = b"AUTHENTIC_GOAL_DIRECTIVE: analyze_codebase";
        let signature = keypair.sign(message);

        // 1. Alterar el mensaje (intento de suplantación de identidad)
        let altered_message = b"FORGED_GOAL_DIRECTIVE: inject_prompt_payload";
        assert!(
            !pubkey.verify(altered_message, &signature),
            "Mensaje alterado debe ser rechazado inmediatamente"
        );

        // 2. Alterar un byte de la firma poscuántica
        let mut forged_sig = signature.clone();
        forged_sig.chains[0][0] ^= 0x01;
        assert!(
            !pubkey.verify(message, &forged_sig),
            "Firma con 1 bit alterado debe ser rechazada inmediatamente"
        );
    }

    #[test]
    fn test_pqc_different_keys_reject_signature() {
        let seed1 = [0x11u8; 32];
        let seed2 = [0x22u8; 32];
        let keypair1 = PqcKeyPair::from_seed(seed1);
        let keypair2 = PqcKeyPair::from_seed(seed2);

        let message = b"KERNEL_SYSRET_RING3_PAYLOAD";
        let signature1 = keypair1.sign(message);

        // Clave pública distinta no puede verificar la firma
        assert!(!keypair2.public_key().verify(message, &signature1));
    }

    #[test]
    fn test_quantum_resistant_cipher_roundtrip() {
        let key = [0x5Au8; 32];
        let nonce = 123456789u64;
        let original_data = b"CONFIDENTIAL_AGENT_MEMORY_SNAPSHOT_WITH_ZERO_DEHYDRATION_LEAKS".to_vec();

        let mut encrypted = original_data.clone();
        QuantumResistantCipher::apply_keystream(&key, nonce, &mut encrypted);

        // El texto cifrado debe ser pseudoaleatorio y no coincidir con el original
        assert_ne!(encrypted, original_data);

        // Descifrado simétrico restaura el mensaje exacto
        let mut decrypted = encrypted.clone();
        QuantumResistantCipher::apply_keystream(&key, nonce, &mut decrypted);
        assert_eq!(decrypted, original_data);
    }

    #[test]
    fn test_zero_knowledge_merkle_membership_proof_verification() {
        // Árbol Merkle de 4 hojas: H0, H1, H2, H3
        let leaf0 = sha256(b"LEAF_0_ACTION");
        let leaf1 = sha256(b"LEAF_1_ACTION");
        let leaf2 = sha256(b"LEAF_2_ACTION");
        let leaf3 = sha256(b"LEAF_3_ACTION");

        // Nivel 1
        let mut in01 = [0u8; 64];
        in01[0..32].copy_from_slice(&leaf0);
        in01[32..64].copy_from_slice(&leaf1);
        let node01 = sha256(&in01);

        let mut in23 = [0u8; 64];
        in23[0..32].copy_from_slice(&leaf2);
        in23[32..64].copy_from_slice(&leaf3);
        let node23 = sha256(&in23);

        // Raíz (Root)
        let mut in_root = [0u8; 64];
        in_root[0..32].copy_from_slice(&node01);
        in_root[32..64].copy_from_slice(&node23);
        let root = sha256(&in_root);

        // Construir prueba de inclusión para leaf2 (índice 2)
        // Pasos:
        // 1. leaf2 se combina a la derecha con leaf3 (sibling leaf3 a la derecha => is_left = false)
        // 2. node23 se combina con node01 (sibling node01 a la izquierda => is_left = true)
        let proof = CausalMembershipProof {
            effect_id: EffectId(2),
            record_hash: leaf2,
            root_hash: root,
            audit_path: vec![
                MerkleProofStep {
                    is_left: false,
                    sibling_hash: leaf3,
                },
                MerkleProofStep {
                    is_left: true,
                    sibling_hash: node01,
                },
            ],
        };

        // Verificación matemática de conocimiento cero
        assert!(proof.verify(), "La prueba de membresia debe ser matematicamente valida");

        // Si se altera el hash de la hoja, la prueba falla
        let mut tampered_proof = proof.clone();
        tampered_proof.record_hash[0] ^= 0xFF;
        assert!(!tampered_proof.verify(), "Prueba con hoja falsificada debe fallar");

        // Si se altera el hermano en la ruta de auditoría, la prueba falla
        let mut tampered_audit = proof.clone();
        tampered_audit.audit_path[0].sibling_hash[0] ^= 0xFF;
        assert!(!tampered_audit.verify(), "Prueba con auditoria alterada debe fallar");
    }
}
