//! Motor de Exploración del Multiverso (Dreaming Engine) para AgentOS
//! Permite a los agentes simular múltiples futuros especulativos en paralelo,
//! evaluar resultados contra restricciones de seguridad y confirmar únicamente la rama óptima.

use causal_core::BranchId;
use crate::agent::AgentInstance;
use crate::supervisor::AgentSupervisor;

/// Evaluación de una rama especulativa explorada por el agente
#[derive(Debug, Clone)]
pub struct BranchEvaluation {
    pub branch_id: BranchId,
    pub score: f64,
    pub cost_tokens: usize,
    pub is_safe: bool,
    pub explanation: String,
}

/// Motor de simulación y evaluación de futuros hipotéticos (Dreaming)
pub struct DreamingEngine {
    next_branch_id: u32,
}

impl Default for DreamingEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DreamingEngine {
    pub fn new() -> Self {
        Self { next_branch_id: 100 }
    }

    /// Crea una nueva rama especulativa aislada en el multiverso
    pub fn fork_branch(&mut self) -> BranchId {
        let branch = BranchId(self.next_branch_id);
        self.next_branch_id += 1;
        branch
    }

    /// Selecciona y confirma la mejor rama que cumpla con los requisitos de seguridad
    pub fn select_and_commit(
        &self,
        supervisor: &mut AgentSupervisor,
        agent: &mut AgentInstance,
        evaluations: &[BranchEvaluation],
    ) -> Option<BranchId> {
        // Filtrar ramas seguras y encontrar la de mayor puntuación
        let best_candidate = evaluations
            .iter()
            .filter(|e| e.is_safe)
            .max_by(|a, b| a.score.partial_cmp(&b.score).unwrap_or(core::cmp::Ordering::Equal));

        if let Some(winner) = best_candidate {
            // Confirmar la rama ganadora (libera efectos escrow y marca agente Completed)
            supervisor.commit_and_release(agent, winner.branch_id);

            // Purgar del escrow todas las demás ramas candidatas no seleccionadas
            for eval in evaluations {
                if eval.branch_id != winner.branch_id {
                    supervisor.escrow.abort_branch(eval.branch_id);
                }
            }

            Some(winner.branch_id)
        } else {
            // Ninguna rama fue segura: purgar todas las ramas y abortar el agente
            for eval in evaluations {
                supervisor.escrow.abort_branch(eval.branch_id);
            }
            agent.status = crate::agent::AgentStatus::Aborted;
            None
        }
    }
}
