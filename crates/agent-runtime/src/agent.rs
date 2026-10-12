//! Modelo de Entidad Nativa de Agente para AgentOS
//! Define identidad, estado persistente, objetivos declarativos, presupuestos
//! y seguimiento de taint mediante Information Flow Control (IFC).

use capability_engine::{CSpace, Permissions, ObjectId, CapId};
use causal_core::{DomainId, BranchId, EffectId, SecurityLabel};

/// Identificador único del agente
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct AgentId(pub u32);

/// Objetivo declarativo y restricciones presupuestarias del agente
#[derive(Clone, Debug)]
pub struct AgentGoal {
    pub description: String,
    pub max_steps: usize,
    pub max_tokens: usize,
}

impl AgentGoal {
    pub fn new(description: &str, max_steps: usize, max_tokens: usize) -> Self {
        Self {
            description: description.to_string(),
            max_steps,
            max_tokens,
        }
    }
}

/// Ciclo de vida del agente
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AgentStatus {
    Ready,
    Executing,
    Suspended,
    Completed,
    Aborted,
}

/// Instancia nativa de un agente gestionada por el runtime
#[derive(Debug)]
pub struct AgentInstance {
    pub id: AgentId,
    pub domain: DomainId,
    pub goal: AgentGoal,
    pub status: AgentStatus,
    pub cspace: CSpace,
    pub current_branch: BranchId,
    pub security_label: SecurityLabel,
    pub step_count: usize,
    pub tokens_used: usize,
    pub context_history: Vec<String>,
    pub observed_effects: Vec<EffectId>,
}

impl AgentInstance {
    pub fn new(id: AgentId, domain: DomainId, goal: AgentGoal) -> Self {
        let mut cspace = CSpace::new();
        // Mintear capacidad inicial de espacio de memoria propio
        let _ = cspace.mint_root(ObjectId(id.0 as u64), Permissions::ALL, domain.0);

        Self {
            id,
            domain,
            goal,
            status: AgentStatus::Ready,
            cspace,
            current_branch: BranchId(0),
            // Todo agente inicia con confianza de dominio local
            security_label: SecurityLabel { confidentiality: 10, integrity: 90, taint_mask: 0 },
            step_count: 0,
            tokens_used: 0,
            context_history: Vec::new(),
            observed_effects: Vec::new(),
        }
    }

    /// Observa datos externos e incorpora el taint en su etiqueta de seguridad (IFC)
    pub fn observe(&mut self, content: &str, source_label: SecurityLabel, cause: EffectId) {
        self.context_history.push(content.to_string());
        self.observed_effects.push(cause);
        // Regla matemática de IFC: integridad = min(agente, fuente)
        self.security_label = self.security_label.combine(&source_label);
    }

    /// Comprueba si el contexto del agente ha sido contaminado por datos no confiables
    pub fn is_tainted(&self) -> bool {
        self.security_label.integrity < 50
    }

    /// Registra el consumo de un paso de cómputo y verifica presupuestos
    pub fn record_step(&mut self, tokens: usize) -> Result<(), &'static str> {
        self.step_count += 1;
        self.tokens_used += tokens;

        if self.step_count > self.goal.max_steps {
            self.status = AgentStatus::Suspended;
            return Err("Limite presupuestario de pasos excedido");
        }

        if self.tokens_used > self.goal.max_tokens {
            self.status = AgentStatus::Suspended;
            return Err("Limite presupuestario de tokens de inferencia excedido");
        }

        Ok(())
    }

    /// Otorga una capacidad adicional delegada por el sistema
    pub fn grant_capability(&mut self, object_id: ObjectId, perms: Permissions) -> CapId {
        self.cspace.mint_root(object_id, perms, self.domain.0)
    }
}
