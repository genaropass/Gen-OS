//! Supervisor de Seguridad y Orquestación Causal para AgentOS
//! Aplica Information Flow Control (IFC), verificación de capacidades,
//! retención de efectos en Escrow, auditoría retrospectiva `why()` y poda de ramas.

use causal_core::{
    CausalLedger, EscrowManager, DomainId, BranchId, EffectId,
    Reversibility, EscrowEntry,
};
use capability_engine::{CapId, CapError};
use crate::agent::{AgentInstance, AgentStatus};
use crate::tool::{ToolDefinition, ToolExecutionResult};

#[derive(Debug)]
pub enum SupervisorError {
    AgentNotFound,
    ToolNotFound,
    MissingCapability(CapError),
    BudgetExceeded(&'static str),
    SecurityViolation(&'static str),
}

/// El Supervisor de Agentes coordina la ejecución segura
pub struct AgentSupervisor {
    pub ledger: CausalLedger,
    pub escrow: EscrowManager,
}

impl Default for AgentSupervisor {
    fn default() -> Self {
        Self::new()
    }
}

impl AgentSupervisor {
    pub fn new() -> Self {
        Self {
            ledger: CausalLedger::new(),
            escrow: EscrowManager::new(),
        }
    }

    /// Ejecuta una herramienta en nombre del agente con verificación de capacidades y escrow
    pub fn invoke_tool(
        &mut self,
        agent: &mut AgentInstance,
        tool: &ToolDefinition,
        cap_id: CapId,
        input_payload: &[u8],
    ) -> Result<ToolExecutionResult, SupervisorError> {
        // 1. Verificación de capacidad en el CSpace del agente
        agent
            .cspace
            .verify(cap_id, tool.required_permissions)
            .map_err(SupervisorError::MissingCapability)?;

        // 2. Determinar causas (últimos efectos observados por el agente)
        let causes = agent.observed_effects.clone();

        // 3. Determinar reversibilidad y clasificación de Escrow
        let is_tainted = agent.is_tainted();
        let reversibility = if tool.is_external_side_effect {
            if is_tainted || agent.current_branch != BranchId(0) {
                // Tainted o especulativo: DEBE ser retenido en Escrow
                Reversibility::EscrowStaged
            } else {
                Reversibility::Irreversible
            }
        } else {
            Reversibility::PurelyReversible
        };

        // 4. Registrar efecto en el Libro Mayor Causal
        let mut digest = [0u8; 32];
        let copy_len = input_payload.len().min(32);
        digest[..copy_len].copy_from_slice(&input_payload[..copy_len]);

        let effect_id = self.ledger.record_effect(
            agent.current_branch,
            agent.domain,
            DomainId(tool.target_object.0 as u32),
            causes,
            agent.security_label,
            reversibility,
            digest,
        );

        // 5. Si es EscrowStaged, retener la acción en el EscrowManager
        let was_escrowed = reversibility == Reversibility::EscrowStaged;
        if was_escrowed {
            self.escrow.stage_action(
                agent.current_branch,
                effect_id,
                input_payload.to_vec(),
            );
        }

        // 6. Actualizar contabilidad del agente
        agent.observed_effects.push(effect_id);

        Ok(ToolExecutionResult {
            output: format!("Ejecutado {} con efecto {:?}", tool.name, effect_id),
            effect_id,
            was_escrowed,
        })
    }

    /// Realiza una auditoría causal retrospectiva: ¿Por qué ocurrió este efecto?
    pub fn audit_why(&self, effect_id: EffectId) -> Vec<EffectId> {
        self.ledger.why(effect_id)
    }

    /// Descarta una rama maliciosa o fallida: purga el escrow y aborta el agente
    pub fn abort_and_contain(
        &mut self,
        agent: &mut AgentInstance,
        branch: BranchId,
    ) -> usize {
        let dropped = self.escrow.abort_branch(branch);
        agent.status = AgentStatus::Aborted;
        dropped
    }

    /// Confirma una rama segura: libera los efectos en escrow al mundo real
    pub fn commit_and_release(
        &mut self,
        agent: &mut AgentInstance,
        branch: BranchId,
    ) -> Vec<EscrowEntry> {
        let released = self.escrow.commit_branch(branch);
        agent.status = AgentStatus::Completed;
        released
    }
}
