//! # causal-core
//!
//! Núcleo del Grafo Causal y Multiverso con Escrow de AgentOS.
//! Implementa la primitiva fundamental: toda interacción entre dominios
//! es un efecto causal registrado en un Grafo Acíclico Dirigido (DAG).

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Identificador único e inmutable de un Efecto en el Grafo Causal
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct EffectId(pub u64);

/// Identificador de un Dominio de Protección (agente o servicio del sistema)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct DomainId(pub u32);

/// Identificador de una Rama en el Multiverso especulativo
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct BranchId(pub u32);

/// Clasificación de reversibilidad de un efecto
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Reversibility {
    /// Reversible localmente (memoria privada o almacenamiento versionado)
    PurelyReversible,
    /// Acción externa retenida en la cola de Escrow hasta que la rama confirme
    EscrowStaged,
    /// Efecto permanente e irreversible en el hardware/mundo real
    Irreversible,
}

/// Máscaras de contaminación (Taint Tracking) para Information Flow Control
pub struct TaintMask;
impl TaintMask {
    pub const CLEAN: u32 = 0;
    pub const WEB_UNTRUSTED: u32 = 1 << 0;
    pub const TOOL_OUTPUT: u32 = 1 << 1;
    pub const SPECULATIVE_BRANCH: u32 = 1 << 2;
    pub const ADVERSARIAL_INJECTION: u32 = 1 << 3;
}

/// Nivel de confianza y procedencia de datos (Information Flow Control / DIFC)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SecurityLabel {
    /// Nivel de confidencialidad (quién puede leerlo: mayor número = más secreto)
    pub confidentiality: u16,
    /// Nivel de integridad (0 = entrada web no confiable, 100 = código firmado del kernel)
    pub integrity: u16,
    /// Máscara de bits de contaminación (taint tracking)
    pub taint_mask: u32,
}

impl SecurityLabel {
    pub const TRUSTED_KERNEL: Self = Self {
        confidentiality: 0,
        integrity: 100,
        taint_mask: TaintMask::CLEAN,
    };
    pub const UNTRUSTED_EXTERNAL: Self = Self {
        confidentiality: 0,
        integrity: 10,
        taint_mask: TaintMask::WEB_UNTRUSTED,
    };

    pub const fn new(confidentiality: u16, integrity: u16, taint_mask: u32) -> Self {
        Self {
            confidentiality,
            integrity,
            taint_mask,
        }
    }

    /// Teorema de No-Interferencia de Bell-LaPadula y Biba (DIFC)
    /// Un flujo desde `self` hacia `target` es admisible si y solo si:
    /// 1. self.confidentiality <= target.confidentiality (No leer hacia arriba / No escribir hacia abajo)
    /// 2. self.integrity >= target.integrity (No escribir hacia arriba en integridad sin autorización)
    /// 3. Toda contaminación activa en self está expresamente permitida en target
    pub fn can_flow_to(&self, target: &Self) -> bool {
        self.confidentiality <= target.confidentiality
            && self.integrity >= target.integrity
            && ((self.taint_mask & !target.taint_mask) == 0)
    }

    /// Propagación conservadora de etiquetas (retículo DIFC)
    pub fn combine(&self, other: &Self) -> Self {
        Self {
            confidentiality: self.confidentiality.max(other.confidentiality),
            integrity: self.integrity.min(other.integrity),
            taint_mask: self.taint_mask | other.taint_mask,
        }
    }

    /// Desclasificación controlada mediante capacidad con derecho DECLASSIFY
    pub fn declassify(&self, mask_to_clear: u32) -> Self {
        Self {
            confidentiality: self.confidentiality,
            integrity: self.integrity,
            taint_mask: self.taint_mask & !mask_to_clear,
        }
    }
}

pub mod hash;
pub mod pqc;

pub use pqc::{
    CausalMembershipProof, MerkleProofStep, PqcKeyPair, PqcPublicKey, PqcSignature,
    QuantumResistantCipher,
};

/// Registro atómico de un Efecto en el Libro Mayor Causal (Nodo del Merkle-DAG v2)
#[derive(Clone, Debug, PartialEq)]
pub struct CausalRecord {
    pub id: EffectId,
    pub branch: BranchId,
    pub emitter: DomainId,
    pub target: DomainId,
    pub label: SecurityLabel,
    pub reversibility: Reversibility,
    /// Causas inmediatas (aristas entrantes en el DAG)
    pub causes: Vec<EffectId>,
    /// Identificadores de capacidades empleadas para la autorización
    pub used_capabilities: Vec<u64>,
    /// Resumen o firma del payload (SHA-256)
    pub payload_digest: [u8; 32],
    /// Hash del nodo anterior para encadenamiento lineal
    pub previous_record_hash: [u8; 32],
    /// Hash criptográfico Merkle (sella id, procedencia, causas, capacidades, label, prev_hash y payload)
    pub merkle_hash: [u8; 32],
    /// Firma digital poscuántica WOTS+ (opcional para acciones críticas)
    pub pqc_signature: Option<PqcSignature>,
    /// Clave pública poscuántica del agente o entidad firmante
    pub signer_pubkey: Option<PqcPublicKey>,
}

impl CausalRecord {
    /// Firma este registro causal con una clave poscuántica WOTS+
    pub fn sign_pqc(&mut self, keypair: &PqcKeyPair) {
        let sig = keypair.sign(&self.merkle_hash);
        self.pqc_signature = Some(sig);
        self.signer_pubkey = Some(keypair.public_key());
    }

    /// Verifica la firma poscuántica WOTS+ del registro causal
    pub fn verify_pqc(&self) -> bool {
        match (&self.pqc_signature, &self.signer_pubkey) {
            (Some(sig), Some(pk)) => pk.verify(&self.merkle_hash, sig),
            (None, None) => true, // Sin firma requerida
            _ => false,           // Estado inconsistente
        }
    }
}

/// El Libro Mayor Causal (Causal Ledger v2)
/// Almacén estructurado en Merkle-DAG que garantiza la inmutabilidad y verificabilidad criptográfica
#[derive(Default, Debug)]
pub struct CausalLedger {
    pub records: Vec<CausalRecord>,
    next_effect_id: u64,
}

impl CausalLedger {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            next_effect_id: 1,
        }
    }

    /// Calcula el hash Merkle determinista de un nodo
    pub fn compute_record_hash(
        id: EffectId,
        branch: BranchId,
        emitter: DomainId,
        target: DomainId,
        label: SecurityLabel,
        causes: &[EffectId],
        used_capabilities: &[u64],
        payload_digest: &[u8; 32],
        previous_record_hash: &[u8; 32],
        parent_hashes: &[[u8; 32]],
    ) -> [u8; 32] {
        let mut input = Vec::with_capacity(256);
        input.extend_from_slice(&id.0.to_be_bytes());
        input.extend_from_slice(&branch.0.to_be_bytes());
        input.extend_from_slice(&emitter.0.to_be_bytes());
        input.extend_from_slice(&target.0.to_be_bytes());
        input.extend_from_slice(&label.confidentiality.to_be_bytes());
        input.extend_from_slice(&label.integrity.to_be_bytes());
        input.extend_from_slice(&label.taint_mask.to_be_bytes());
        input.extend_from_slice(previous_record_hash);
        for &cap in used_capabilities {
            input.extend_from_slice(&cap.to_be_bytes());
        }
        for (i, &cause_id) in causes.iter().enumerate() {
            if i < parent_hashes.len() {
                input.extend_from_slice(&parent_hashes[i]);
            } else {
                input.extend_from_slice(&cause_id.0.to_be_bytes());
            }
        }
        input.extend_from_slice(payload_digest);
        hash::sha256(&input)
    }

    /// Registra un nuevo efecto en el Merkle-DAG causal calculando su hash criptográfico
    pub fn record_effect(
        &mut self,
        branch: BranchId,
        emitter: DomainId,
        target: DomainId,
        causes: Vec<EffectId>,
        label: SecurityLabel,
        reversibility: Reversibility,
        payload_digest: [u8; 32],
    ) -> EffectId {
        self.record_effect_with_caps(
            branch,
            emitter,
            target,
            causes,
            Vec::new(),
            label,
            reversibility,
            payload_digest,
        )
    }

    /// Registra un nuevo efecto asociando explícitamente las capacidades empleadas
    pub fn record_effect_with_caps(
        &mut self,
        branch: BranchId,
        emitter: DomainId,
        target: DomainId,
        causes: Vec<EffectId>,
        used_capabilities: Vec<u64>,
        label: SecurityLabel,
        reversibility: Reversibility,
        payload_digest: [u8; 32],
    ) -> EffectId {
        let id = EffectId(self.next_effect_id);
        self.next_effect_id += 1;

        let prev_hash = self.records.last().map(|r| r.merkle_hash).unwrap_or([0u8; 32]);
        let mut parent_hashes = Vec::with_capacity(causes.len());
        for &cause_id in &causes {
            if let Some(parent) = self.get_effect(cause_id) {
                parent_hashes.push(parent.merkle_hash);
            } else {
                parent_hashes.push([0u8; 32]);
            }
        }

        let merkle_hash = Self::compute_record_hash(
            id,
            branch,
            emitter,
            target,
            label,
            &causes,
            &used_capabilities,
            &payload_digest,
            &prev_hash,
            &parent_hashes,
        );

        let record = CausalRecord {
            id,
            branch,
            emitter,
            target,
            label,
            reversibility,
            causes,
            used_capabilities,
            payload_digest,
            previous_record_hash: prev_hash,
            merkle_hash,
            pqc_signature: None,
            signer_pubkey: None,
        };

        self.records.push(record);
        id
    }

    /// Verifica criptográficamente que ningún nodo del Merkle-DAG haya sido alterado en memoria
    pub fn verify_merkle_integrity(&self) -> bool {
        let mut expected_prev = [0u8; 32];
        for record in &self.records {
            if record.previous_record_hash != expected_prev {
                return false;
            }

            let mut parent_hashes = Vec::with_capacity(record.causes.len());
            for &cause_id in &record.causes {
                if let Some(parent) = self.get_effect(cause_id) {
                    parent_hashes.push(parent.merkle_hash);
                } else {
                    parent_hashes.push([0u8; 32]);
                }
            }

            let expected_hash = Self::compute_record_hash(
                record.id,
                record.branch,
                record.emitter,
                record.target,
                record.label,
                &record.causes,
                &record.used_capabilities,
                &record.payload_digest,
                &record.previous_record_hash,
                &parent_hashes,
            );

            if record.merkle_hash != expected_hash {
                return false;
            }

            expected_prev = record.merkle_hash;
        }
        true
    }

    /// Verifica la integridad del subgrafo de procedencia causal hacia atrás desde un efecto dado
    pub fn verify_subgraph_integrity(&self, root: EffectId) -> bool {
        let ancestors = self.why(root);
        for effect_id in ancestors {
            let record = match self.get_effect(effect_id) {
                Some(r) => r,
                None => return false,
            };

            let mut parent_hashes = Vec::with_capacity(record.causes.len());
            for &cause_id in &record.causes {
                if let Some(parent) = self.get_effect(cause_id) {
                    parent_hashes.push(parent.merkle_hash);
                } else {
                    parent_hashes.push([0u8; 32]);
                }
            }

            let expected_hash = Self::compute_record_hash(
                record.id,
                record.branch,
                record.emitter,
                record.target,
                record.label,
                &record.causes,
                &record.used_capabilities,
                &record.payload_digest,
                &record.previous_record_hash,
                &parent_hashes,
            );

            if record.merkle_hash != expected_hash {
                return false;
            }
        }
        true
    }

    /// Obtiene un efecto por su identificador
    pub fn get_effect(&self, id: EffectId) -> Option<&CausalRecord> {
        self.records.iter().find(|r| r.id == id)
    }

    /// Total de efectos registrados
    pub fn len(&self) -> usize {
        self.records.len()
    }

    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Retorna los registros causales en orden topológico para auditoría formal
    pub fn explain(&self, target_id: EffectId) -> Vec<&CausalRecord> {
        let why_ids = self.why(target_id);
        why_ids.into_iter().filter_map(|id| self.get_effect(id)).collect()
    }

    /// Syscall `why`: Reconstruye el linaje causal completo (recorrido inverso del DAG)
    pub fn why(&self, target_id: EffectId) -> Vec<EffectId> {
        let mut ancestry = Vec::new();
        let mut queue = Vec::new();

        if let Some(initial) = self.get_effect(target_id) {
            ancestry.push(target_id);
            for cause in &initial.causes {
                queue.push(*cause);
            }
        }

        while let Some(current_id) = queue.pop() {
            if !ancestry.contains(&current_id) {
                ancestry.push(current_id);
                if let Some(record) = self.get_effect(current_id) {
                    for cause in &record.causes {
                        queue.push(*cause);
                    }
                }
            }
        }

        ancestry
    }

    /// Registra un efecto y lo firma atómicamente con una clave poscuántica WOTS+
    pub fn record_effect_signed(
        &mut self,
        branch: BranchId,
        emitter: DomainId,
        target: DomainId,
        causes: Vec<EffectId>,
        used_capabilities: Vec<u64>,
        label: SecurityLabel,
        reversibility: Reversibility,
        payload_digest: [u8; 32],
        keypair: &PqcKeyPair,
    ) -> EffectId {
        let effect_id = self.record_effect_with_caps(
            branch,
            emitter,
            target,
            causes,
            used_capabilities,
            label,
            reversibility,
            payload_digest,
        );

        if let Some(record) = self.records.last_mut() {
            record.sign_pqc(keypair);
        }

        effect_id
    }

    /// Calcula la raíz del estado global de Merkle de todos los registros en el ledger
    pub fn compute_state_root(&self) -> [u8; 32] {
        if self.records.is_empty() {
            return [0u8; 32];
        }

        let mut current_level: Vec<[u8; 32]> = self.records.iter().map(|r| r.merkle_hash).collect();

        while current_level.len() > 1 {
            if !current_level.len().is_multiple_of(2) {
                let last = *current_level.last().unwrap();
                current_level.push(last);
            }

            let mut next_level = Vec::with_capacity(current_level.len() / 2);
            for chunk in current_level.chunks(2) {
                let mut input = [0u8; 64];
                input[0..32].copy_from_slice(&chunk[0]);
                input[32..64].copy_from_slice(&chunk[1]);
                next_level.push(hash::sha256(&input));
            }
            current_level = next_level;
        }

        current_level[0]
    }

    /// Genera una prueba de inclusión verificable de conocimiento cero (CausalMembershipProof)
    pub fn generate_membership_proof(&self, id: EffectId) -> Option<pqc::CausalMembershipProof> {
        let target_idx = self.records.iter().position(|r| r.id == id)?;
        let record_hash = self.records[target_idx].merkle_hash;
        let root_hash = self.compute_state_root();

        let mut current_level: Vec<[u8; 32]> = self.records.iter().map(|r| r.merkle_hash).collect();
        let mut idx = target_idx;
        let mut audit_path = Vec::new();

        while current_level.len() > 1 {
            if !current_level.len().is_multiple_of(2) {
                let last = *current_level.last().unwrap();
                current_level.push(last);
            }

            let is_right = (idx % 2) != 0;
            let sibling_idx = if is_right { idx - 1 } else { idx + 1 };
            let sibling_hash = current_level[sibling_idx];

            audit_path.push(pqc::MerkleProofStep {
                is_left: is_right,
                sibling_hash,
            });

            let mut next_level = Vec::with_capacity(current_level.len() / 2);
            for chunk in current_level.chunks(2) {
                let mut input = [0u8; 64];
                input[0..32].copy_from_slice(&chunk[0]);
                input[32..64].copy_from_slice(&chunk[1]);
                next_level.push(hash::sha256(&input));
            }

            idx /= 2;
            current_level = next_level;
        }

        Some(pqc::CausalMembershipProof {
            effect_id: id,
            record_hash,
            root_hash,
            audit_path,
        })
    }
}

/// Entrada retenida en la cola de Escrow
#[derive(Clone, Debug)]
pub struct EscrowEntry {
    pub effect_id: EffectId,
    pub branch: BranchId,
    pub payload: Vec<u8>,
}

/// Gestor del Multiverso y Escrow
/// Retiene efectos irreversibles en ramas especulativas hasta su commit
#[derive(Default, Debug)]
pub struct EscrowManager {
    staged: Vec<EscrowEntry>,
}

impl EscrowManager {
    pub fn new() -> Self {
        Self { staged: Vec::new() }
    }

    /// Retiene una acción en Escrow
    pub fn stage_action(&mut self, branch: BranchId, effect_id: EffectId, payload: Vec<u8>) {
        self.staged.push(EscrowEntry {
            effect_id,
            branch,
            payload,
        });
    }

    /// Descarta una rama especulativa: todos los efectos retenidos se evaporan sin tocar el mundo real
    pub fn abort_branch(&mut self, branch: BranchId) -> usize {
        let initial_len = self.staged.len();
        self.staged.retain(|entry| entry.branch != branch);
        initial_len - self.staged.len()
    }

    /// Confirma una rama: libera las acciones retenidas para su ejecución real en hardware
    pub fn commit_branch(&mut self, branch: BranchId) -> Vec<EscrowEntry> {
        let mut committed = Vec::new();
        let mut remaining = Vec::new();

        for entry in self.staged.drain(..) {
            if entry.branch == branch {
                committed.push(entry);
            } else {
                remaining.push(entry);
            }
        }

        self.staged = remaining;
        committed
    }

    /// Cantidad de efectos actualmente retenidos en Escrow
    pub fn pending_count(&self) -> usize {
        self.staged.len()
    }

    /// Cantidad de efectos retenidos para una rama específica
    pub fn staged_count(&self, branch: BranchId) -> usize {
        self.staged.iter().filter(|e| e.branch == branch).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_causal_dag_and_why_query() {
        let mut ledger = CausalLedger::new();
        let root_branch = BranchId(0);

        let email_agent = DomainId(1);
        let planner_agent = DomainId(2);
        let network_agent = DomainId(3);

        // 1. Entrada externa: llega un email hostil con baja integridad
        let e1 = ledger.record_effect(
            root_branch,
            email_agent,
            planner_agent,
            vec![],
            SecurityLabel::UNTRUSTED_EXTERNAL,
            Reversibility::PurelyReversible,
            [0xaa; 32],
        );

        // 2. El planificador procesa el email y decide llamar a una herramienta
        let e2 = ledger.record_effect(
            root_branch,
            planner_agent,
            network_agent,
            vec![e1],
            SecurityLabel::UNTRUSTED_EXTERNAL,
            Reversibility::PurelyReversible,
            [0xbb; 32],
        );

        // 3. El agente de red intenta exfiltrar datos
        let e3 = ledger.record_effect(
            root_branch,
            network_agent,
            DomainId(999), // Red exterior
            vec![e2],
            SecurityLabel::UNTRUSTED_EXTERNAL,
            Reversibility::EscrowStaged,
            [0xcc; 32],
        );

        // Consulta forense `why(e3)`
        let chain = ledger.why(e3);
        assert_eq!(chain, vec![e3, e2, e1]);
        
        // Verificamos que la causa raíz del intento de exfiltración e3 es el email e1
        let root_cause = ledger.get_effect(*chain.last().unwrap()).unwrap();
        assert_eq!(root_cause.id, e1);
        assert_eq!(root_cause.label.integrity, 10); // Integridad degradada detectada
    }

    #[test]
    fn test_escrow_abort_prevents_side_effects() {
        let mut escrow = EscrowManager::new();
        let spec_branch = BranchId(42);

        // Se retienen dos acciones externas en Escrow
        escrow.stage_action(spec_branch, EffectId(101), vec![1, 2, 3]);
        escrow.stage_action(spec_branch, EffectId(102), vec![4, 5, 6]);
        assert_eq!(escrow.pending_count(), 2);

        // Se aborta la rama especulativa por fallo o anomalía
        let aborted_count = escrow.abort_branch(spec_branch);
        assert_eq!(aborted_count, 2);
        assert_eq!(escrow.pending_count(), 0); // Ningún paquete llegó al mundo exterior
    }

    #[test]
    fn test_escrow_commit_releases_actions() {
        let mut escrow = EscrowManager::new();
        let spec_branch = BranchId(7);

        escrow.stage_action(spec_branch, EffectId(200), vec![0xFF]);
        assert_eq!(escrow.pending_count(), 1);

        // La rama fue exitosa y se confirma
        let released = escrow.commit_branch(spec_branch);
        assert_eq!(released.len(), 1);
        assert_eq!(released[0].effect_id, EffectId(200));
        assert_eq!(released[0].payload, vec![0xFF]);
        assert_eq!(escrow.pending_count(), 0);
    }

    #[test]
    fn test_merkle_dag_integrity_and_tamper_detection() {
        let mut ledger = CausalLedger::new();
        let branch = BranchId(0);
        let domain_a = DomainId(1);
        let domain_b = DomainId(2);

        let e1 = ledger.record_effect(
            branch, domain_a, domain_b, vec![],
            SecurityLabel::TRUSTED_KERNEL,
            Reversibility::PurelyReversible,
            [1u8; 32],
        );

        let e2 = ledger.record_effect(
            branch, domain_b, domain_a, vec![e1],
            SecurityLabel::TRUSTED_KERNEL,
            Reversibility::PurelyReversible,
            [2u8; 32],
        );

        // 1. Integridad inicial verificada
        assert!(ledger.verify_merkle_integrity(), "El Merkle-DAG debe ser valido");
        assert_ne!(ledger.get_effect(e1).unwrap().merkle_hash, [0u8; 32]);
        assert_ne!(ledger.get_effect(e2).unwrap().merkle_hash, [0u8; 32]);
        assert_ne!(
            ledger.get_effect(e1).unwrap().merkle_hash,
            ledger.get_effect(e2).unwrap().merkle_hash,
            "Nodos distintos deben tener hashes Merkle distintos"
        );

        // 2. Simular alteración maliciosa en memoria de un nodo anterior
        ledger.records[0].payload_digest[0] ^= 0xFF; // Modificar 1 bit del payload e1

        // 3. La verificación criptográfica del Merkle-DAG debe detectar el ataque
        assert!(
            !ledger.verify_merkle_integrity(),
            "La alteracion debe ser detectada inmediatamente por el Merkle-DAG"
        );
    }

    #[test]
    fn test_subgraph_integrity_and_explanation() {
        let mut ledger = CausalLedger::new();
        let branch = BranchId(0);

        let e1 = ledger.record_effect_with_caps(
            branch, DomainId(1), DomainId(2), vec![], vec![101, 102],
            SecurityLabel::TRUSTED_KERNEL, Reversibility::PurelyReversible, [0x11; 32],
        );
        let e2 = ledger.record_effect_with_caps(
            branch, DomainId(2), DomainId(3), vec![e1], vec![103],
            SecurityLabel::TRUSTED_KERNEL, Reversibility::PurelyReversible, [0x22; 32],
        );
        let e3 = ledger.record_effect(
            branch, DomainId(3), DomainId(4), vec![e2],
            SecurityLabel::TRUSTED_KERNEL, Reversibility::Irreversible, [0x33; 32],
        );

        // Subgrafo válido
        assert!(ledger.verify_subgraph_integrity(e3));

        // Explicación causal estructurada
        let explanation = ledger.explain(e3);
        assert_eq!(explanation.len(), 3);
        assert_eq!(explanation[0].id, e3);
        assert_eq!(explanation[1].id, e2);
        assert_eq!(explanation[2].id, e1);
        assert_eq!(explanation[2].used_capabilities, vec![101, 102]);
    }

    #[test]
    fn test_linear_chain_tamper_detection() {
        let mut ledger = CausalLedger::new();
        let branch = BranchId(0);

        let _e1 = ledger.record_effect(
            branch, DomainId(1), DomainId(2), vec![],
            SecurityLabel::TRUSTED_KERNEL, Reversibility::PurelyReversible, [0x10; 32],
        );
        let _e2 = ledger.record_effect(
            branch, DomainId(2), DomainId(3), vec![],
            SecurityLabel::TRUSTED_KERNEL, Reversibility::PurelyReversible, [0x20; 32],
        );

        assert!(ledger.verify_merkle_integrity());

        // Alterar previous_record_hash de e2 (simular eliminación de nodo e1)
        ledger.records[1].previous_record_hash = [0u8; 32];
        assert!(!ledger.verify_merkle_integrity(), "Debe detectar ruptura del encadenamiento lineal");
    }

    #[test]
    fn test_causal_record_pqc_signing_and_verification() {
        let mut ledger = CausalLedger::new();
        let keypair = PqcKeyPair::from_seed([0x77u8; 32]);

        let e1 = ledger.record_effect_signed(
            BranchId(0),
            DomainId(1),
            DomainId(2),
            vec![],
            vec![42],
            SecurityLabel::TRUSTED_KERNEL,
            Reversibility::PurelyReversible,
            [0x88; 32],
            &keypair,
        );

        let record = ledger.get_effect(e1).unwrap();
        assert!(record.pqc_signature.is_some());
        assert!(record.signer_pubkey.is_some());
        assert!(record.verify_pqc(), "La firma poscuantica WOTS+ debe ser valida");

        // Simular intento de falsificación (tampering)
        let mut forged_record = record.clone();
        forged_record.merkle_hash[0] ^= 0x01; // Alterar el hash firmado
        assert!(
            !forged_record.verify_pqc(),
            "Un registro con hash alterado debe fallar la verificacion poscuantica"
        );
    }

    #[test]
    fn test_causal_ledger_state_root_and_membership_proof() {
        let mut ledger = CausalLedger::new();
        let branch = BranchId(0);

        let e1 = ledger.record_effect(
            branch, DomainId(1), DomainId(2), vec![],
            SecurityLabel::TRUSTED_KERNEL, Reversibility::PurelyReversible, [1u8; 32],
        );
        let e2 = ledger.record_effect(
            branch, DomainId(2), DomainId(3), vec![e1],
            SecurityLabel::TRUSTED_KERNEL, Reversibility::PurelyReversible, [2u8; 32],
        );
        let _e3 = ledger.record_effect(
            branch, DomainId(3), DomainId(4), vec![e2],
            SecurityLabel::TRUSTED_KERNEL, Reversibility::PurelyReversible, [3u8; 32],
        );

        let state_root = ledger.compute_state_root();
        assert_ne!(state_root, [0u8; 32]);

        // Generar prueba de inclusión para e2
        let proof = ledger.generate_membership_proof(e2).expect("Debe existir la prueba de membresia");
        assert_eq!(proof.effect_id, e2);
        assert_eq!(proof.root_hash, state_root);
        assert!(proof.verify(), "La prueba de membresia generada debe ser valida contra state_root");

        // Falsificación de prueba: alterar root_hash
        let mut fake_proof = proof.clone();
        fake_proof.root_hash[0] ^= 0xFF;
        assert!(!fake_proof.verify(), "Prueba con root_hash falso debe ser rechazada");
    }
}

