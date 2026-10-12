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

/// Nivel de confianza y procedencia de datos (Information Flow Control)
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct SecurityLabel {
    /// Nivel de confidencialidad (quién puede leerlo)
    pub confidentiality: u16,
    /// Nivel de integridad (0 = entrada web no confiable, 100 = código firmado del kernel)
    pub integrity: u16,
}

impl SecurityLabel {
    pub const TRUSTED_KERNEL: Self = Self { confidentiality: 0, integrity: 100 };
    pub const UNTRUSTED_EXTERNAL: Self = Self { confidentiality: 0, integrity: 10 };

    /// Propagación conservadora de integridad (el resultado hereda la menor integridad)
    pub fn combine(&self, other: &Self) -> Self {
        Self {
            confidentiality: self.confidentiality.max(other.confidentiality),
            integrity: self.integrity.min(other.integrity),
        }
    }
}

/// Registro atómico de un Efecto en el Libro Mayor Causal
#[derive(Clone, Debug)]
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
}

/// El Libro Mayor Causal (Causal Ledger)
/// Almacén estructurado en DAG que garantiza la inmutabilidad y trazabilidad
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

    /// Registra un nuevo efecto en el DAG causal
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

        let record = CausalRecord {
            id,
            branch,
            emitter,
            target,
            label,
            reversibility,
            causes,
            payload_digest,
        };

        self.records.push(record);
        id
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
}
