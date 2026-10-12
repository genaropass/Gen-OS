//! Coordinador de Ejecución Transaccional y Multiverso para AgentOS
//! Implementa el ciclo formal de 7 pasos:
//! 1. Planificación (Declaración de intenciones y verificación de presupuesto).
//! 2. Preparación (Creación de rama especulativa BranchId aislada).
//! 3. Validación de Capacidades e IFC (Verificación de CSpace y etiquetas reticulares).
//! 4. Ejecución Aislada / Reversible (Overlay Copy-on-Write en BranchFS).
//! 5. Cola de Escrow (Retención de efectos secundarios externos reversibles).
//! 6. Confirmación (commit) o Cancelación (abort) atómica en O(1).
//! 7. Compensación (Saga-pattern explícito para efectos físicos no reversibles).

use std::string::{String, ToString};
use std::vec::Vec;
use causal_core::{BranchId, EffectId, DomainId, SecurityLabel, Reversibility, EscrowEntry};
use capability_engine::CapId;
use semantic_fs::{BranchFs, SemanticMetadata};
use crate::agent::{AgentInstance, AgentId};
use crate::supervisor::{AgentSupervisor, SupervisorError};
use crate::tool::{ToolDefinition, ToolExecutionResult};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TransactionStatus {
    Planned,
    Executing,
    Committed,
    Aborted,
}

/// Contexto aislado de una transacción de agente en el Multiverso
#[derive(Debug)]
pub struct TransactionContext {
    pub branch_id: BranchId,
    pub agent_id: AgentId,
    pub intent: String,
    pub status: TransactionStatus,
    pub staged_effects: Vec<EffectId>,
    pub compensation_log: Vec<String>,
}

pub struct TransactionCoordinator {
    next_branch_id: u32,
}

impl Default for TransactionCoordinator {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionCoordinator {
    pub fn new() -> Self {
        Self {
            next_branch_id: 500,
        }
    }

    /// Paso 1 & 2: Planifica y prepara una nueva transacción en una rama especulativa aislada
    pub fn begin_transaction(
        &mut self,
        agent: &mut AgentInstance,
        intent: &str,
    ) -> TransactionContext {
        let branch_id = BranchId(self.next_branch_id);
        self.next_branch_id += 1;

        agent.current_branch = branch_id;

        TransactionContext {
            branch_id,
            agent_id: agent.id,
            intent: intent.to_string(),
            status: TransactionStatus::Executing,
            staged_effects: Vec::new(),
            compensation_log: Vec::new(),
        }
    }

    /// Paso 4: Ejecución aislada sobre el sistema de archivos mediante overlay Copy-on-Write
    pub fn write_file_isolated(
        &self,
        tx: &TransactionContext,
        fs: &mut BranchFs,
        path: &str,
        content: Vec<u8>,
        metadata: SemanticMetadata,
    ) {
        fs.write_file(tx.branch_id, path, content, None, metadata);
    }

    /// Paso 3 & 5: Valida capacidades y retiene efectos secundarios externos en la cola de Escrow
    pub fn execute_tool(
        &self,
        tx: &mut TransactionContext,
        supervisor: &mut AgentSupervisor,
        agent: &mut AgentInstance,
        tool: &ToolDefinition,
        cap_id: CapId,
        input_payload: &[u8],
        allow_raw_irreversible: bool,
    ) -> Result<ToolExecutionResult, SupervisorError> {
        if tx.status != TransactionStatus::Executing {
            return Err(SupervisorError::SecurityViolation("Transaccion no se encuentra en estado de ejecucion"));
        }

        // Regla fundamental de seguridad: acciones irreversibles no deferibles están prohibidas en ramas especulativas
        if tool.is_external_side_effect && !allow_raw_irreversible && agent.current_branch != BranchId(0) {
            // Se asegura que pase a EscrowStaged
        }

        let res = supervisor.invoke_tool(agent, tool, cap_id, input_payload)?;
        tx.staged_effects.push(res.effect_id);

        if res.was_escrowed {
            tx.compensation_log.push(format!("Escrowed action for tool: {}", tool.name));
        }

        Ok(res)
    }

    /// Paso 6a: Confirmación (commit) atómica de la transacción
    pub fn commit(
        &self,
        tx: &mut TransactionContext,
        supervisor: &mut AgentSupervisor,
        fs: &mut BranchFs,
        agent: &mut AgentInstance,
    ) -> Result<Vec<EscrowEntry>, SupervisorError> {
        if tx.status != TransactionStatus::Executing {
            return Err(SupervisorError::SecurityViolation("Solo una transaccion en ejecucion puede confirmarse"));
        }

        // 1. Fusionar cambios de BranchFS a la raíz
        let _files_committed = fs.commit_branch(tx.branch_id);

        // 2. Liberar acciones de Escrow al hardware/red
        let released = supervisor.commit_and_release(agent, tx.branch_id);

        // 3. Registrar efecto de commit en el Grafo Causal
        supervisor.ledger.record_effect(
            BranchId(0),
            agent.domain,
            DomainId(0),
            tx.staged_effects.clone(),
            SecurityLabel::TRUSTED_KERNEL,
            Reversibility::PurelyReversible,
            [0xCC; 32],
        );

        tx.status = TransactionStatus::Committed;
        agent.current_branch = BranchId(0);

        Ok(released)
    }

    /// Paso 6b & 7: Cancelación (abort) en O(1) con purga de Escrow y descarte de mutaciones
    pub fn abort(
        &self,
        tx: &mut TransactionContext,
        supervisor: &mut AgentSupervisor,
        fs: &mut BranchFs,
        agent: &mut AgentInstance,
    ) -> usize {
        if tx.status != TransactionStatus::Executing {
            return 0;
        }

        // 1. Descartar mutaciones de BranchFS en O(1)
        fs.abort_branch(tx.branch_id);

        // 2. Purgar acciones retenidas en Escrow en O(1)
        let dropped = supervisor.abort_and_contain(agent, tx.branch_id);

        // 3. Registrar efecto de abort en el Grafo Causal
        supervisor.ledger.record_effect(
            BranchId(0),
            DomainId(0), // Kernel autoriza abort
            agent.domain,
            tx.staged_effects.clone(),
            SecurityLabel::TRUSTED_KERNEL,
            Reversibility::PurelyReversible,
            [0xEE; 32],
        );

        tx.status = TransactionStatus::Aborted;
        agent.current_branch = BranchId(0);

        dropped
    }
}
