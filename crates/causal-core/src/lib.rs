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

/// Registro atómico de un Efecto en el Libro Mayor Causal (Nodo del Merkle-DAG)
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
    /// Resumen o firma del payload
    pub payload_digest: [u8; 32],
    /// Hash criptográfico Merkle (sella id, procedencia, causas y payload)
    pub merkle_hash: [u8; 32],
}

/// El Libro Mayor Causal (Causal Ledger)
/// Almacén estructurado en Merkle-DAG que garantiza la inmutabilidad y verificabilidad criptográfica
#[derive(Default, Debug)]
pub struct CausalLedger {
    records: Vec<CausalRecord>,
    next_effect_id: u64,
}

impl CausalLedger {
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
            next_effect_id: 1,
        }
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
        let id = EffectId(self.next_effect_id);
        self.next_effect_id += 1;

        // Construir buffer para el hash Merkle del nodo
        let mut hash_input = Vec::with_capacity(128);
        hash_input.extend_from_slice(&id.0.to_be_bytes());
        hash_input.extend_from_slice(&branch.0.to_be_bytes());
        hash_input.extend_from_slice(&emitter.0.to_be_bytes());
        hash_input.extend_from_slice(&target.0.to_be_bytes());
        hash_input.extend_from_slice(&label.confidentiality.to_be_bytes());
        hash_input.extend_from_slice(&label.integrity.to_be_bytes());
        for &cause_id in &causes {
            if let Some(parent) = self.get_effect(cause_id) {
                hash_input.extend_from_slice(&parent.merkle_hash);
            } else {
                hash_input.extend_from_slice(&cause_id.0.to_be_bytes());
            }
        }
        hash_input.extend_from_slice(&payload_digest);
        let merkle_hash = hash::sha256(&hash_input);

        let record = CausalRecord {
            id,
            branch,
            emitter,
            target,
            label,
            reversibility,
            causes,
            payload_digest,
            merkle_hash,
        };

        self.records.push(record);
        id
    }

    /// Verifica criptográficamente que ningún nodo del Merkle-DAG haya sido alterado en memoria
    pub fn verify_merkle_integrity(&self) -> bool {
        for record in &self.records {
            let mut hash_input = Vec::with_capacity(128);
            hash_input.extend_from_slice(&record.id.0.to_be_bytes());
            hash_input.extend_from_slice(&record.branch.0.to_be_bytes());
            hash_input.extend_from_slice(&record.emitter.0.to_be_bytes());
            hash_input.extend_from_slice(&record.target.0.to_be_bytes());
            hash_input.extend_from_slice(&record.label.confidentiality.to_be_bytes());
            hash_input.extend_from_slice(&record.label.integrity.to_be_bytes());
            for &cause_id in &record.causes {
                if let Some(parent) = self.get_effect(cause_id) {
                    hash_input.extend_from_slice(&parent.merkle_hash);
                } else {
                    hash_input.extend_from_slice(&cause_id.0.to_be_bytes());
                }
            }
            hash_input.extend_from_slice(&record.payload_digest);
            let expected_hash = hash::sha256(&hash_input);

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
}
