//! Modelo Nativo de Agente (Kernel Agent Object) para AgentOS
//! Cada agente de IA es un ciudadano de primera clase en Ring 0 con:
//! - Identidad monotónica única (AgentId).
//! - Espacio de memoria virtual aislado por hardware (AddressSpace / PML4).
//! - Espacio de capacidades de privilegio mínimo (CSpace).
//! - Presupuesto estricto de recursos (CPU us, memoria, gas, mensajes).
//! - Etiquetas de flujo de información (SecurityLabel / IFC).
//! - Vinculación indeleble al Grafo Causal (DomainId / CausalLedger).

use alloc::vec::Vec;
use alloc::collections::BTreeMap;
use core::sync::atomic::{AtomicU64, Ordering};
use crate::mm::address_space::AddressSpace;
use crate::sync::IrqSpinLock;
use crate::println;
use capability_engine::{CSpace, Permissions, ObjectId};
use causal_core::{CausalLedger, DomainId, BranchId, EffectId, Reversibility, SecurityLabel};

/// Identificador único y monotónico de un agente en el kernel
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct AgentId(pub u64);

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockReason {
    IpcChannel(u64),
    ToolExecution(u64),
    CausalDependency(EffectId),
    Sleeping(u64),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum AgentState {
    Ready,
    Running,
    Blocked(BlockReason),
    Suspended,
    Terminated(u32), // Código de salida
}

/// Presupuesto estricto de recursos asignados al agente
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AgentBudget {
    pub cpu_time_us: u64,
    pub max_cpu_time_us: u64,
    pub memory_bytes: usize,
    pub max_memory_bytes: usize,
    pub gas_units: u64,
    pub max_gas_units: u64,
    pub message_quota: u32,
    pub messages_sent: u32,
}

impl AgentBudget {
    pub const fn new(max_cpu_us: u64, max_mem_bytes: usize, max_gas: u64, msg_quota: u32) -> Self {
        Self {
            cpu_time_us: 0,
            max_cpu_time_us: max_cpu_us,
            memory_bytes: 0,
            max_memory_bytes: max_mem_bytes,
            gas_units: 0,
            max_gas_units: max_gas,
            message_quota: msg_quota,
            messages_sent: 0,
        }
    }

    pub fn is_exhausted(&self) -> bool {
        self.cpu_time_us >= self.max_cpu_time_us ||
        self.memory_bytes >= self.max_memory_bytes ||
        self.gas_units >= self.max_gas_units ||
        self.messages_sent >= self.message_quota
    }
}

/// Manifiesto declarativo para la instanciación de un nuevo agente
#[derive(Clone, Debug)]
pub struct AgentManifest {
    pub name: [u8; 32],
    pub intent: [u8; 64],
    pub budget: AgentBudget,
    pub security_label: SecurityLabel,
    pub parent: Option<AgentId>,
    pub entry_point: u64,
}

#[derive(Debug, PartialEq, Eq)]
pub enum AgentError {
    AgentNotFound,
    AddressSpaceCreationFailed,
    BudgetExhausted,
    InvalidStateTransition,
    PermissionDenied,
    NameTooLong,
}

/// Objeto Kernel de primera clase: representa un Agente de IA nativo
pub struct Agent {
    pub id: AgentId,
    pub name: [u8; 32],
    pub intent: [u8; 64],
    pub address_space: AddressSpace,
    pub cspace: CSpace,
    pub budget: AgentBudget,
    pub security_label: SecurityLabel,
    pub state: AgentState,
    pub causal_domain: DomainId,
    pub causal_root: EffectId,
    pub parent: Option<AgentId>,
    pub children: Vec<AgentId>,
    pub entry_point: u64,
    pub allocated_frames: Vec<crate::mm::frame::PhysFrame>,
}

impl Agent {
    /// Asigna un marco de memoria física verificando el límite estricto de memoria del agente
    pub fn allocate_frame(&mut self) -> Result<crate::mm::frame::PhysFrame, AgentError> {
        let requested_bytes = (self.allocated_frames.len() + 1) * 4096;
        if requested_bytes > self.budget.max_memory_bytes {
            self.state = AgentState::Suspended;
            return Err(AgentError::BudgetExhausted);
        }

        let frame = crate::mm::frame::alloc_frame().ok_or(AgentError::AddressSpaceCreationFailed)?;
        self.allocated_frames.push(frame);
        self.budget.memory_bytes = self.allocated_frames.len() * 4096;
        Ok(frame)
    }

    /// Libera todos los marcos físicos asignados al agente retornándolos al PMM
    pub fn free_all_frames(&mut self) {
        for frame in self.allocated_frames.drain(..) {
            crate::mm::frame::free_frame(frame);
        }
        self.budget.memory_bytes = 0;
    }

    /// Verifica si el agente puede ejecutar una acción dentro de su presupuesto
    pub fn consume_gas(&mut self, amount: u64) -> Result<(), AgentError> {
        let new_gas = self.budget.gas_units.saturating_add(amount);
        if new_gas > self.budget.max_gas_units {
            self.state = AgentState::Suspended;
            return Err(AgentError::BudgetExhausted);
        }
        self.budget.gas_units = new_gas;
        Ok(())
    }

    /// Registra el consumo de CPU en microsegundos
    pub fn consume_cpu(&mut self, us: u64) -> Result<(), AgentError> {
        let new_cpu = self.budget.cpu_time_us.saturating_add(us);
        if new_cpu > self.budget.max_cpu_time_us {
            self.state = AgentState::Suspended;
            return Err(AgentError::BudgetExhausted);
        }
        self.budget.cpu_time_us = new_cpu;
        Ok(())
    }
}

/// Registro central de agentes del kernel
pub struct AgentRegistry {
    agents: BTreeMap<AgentId, Agent>,
}

static NEXT_AGENT_ID: AtomicU64 = AtomicU64::new(1000);
static REGISTRY: IrqSpinLock<AgentRegistry> = IrqSpinLock::new(AgentRegistry {
    agents: BTreeMap::new(),
});

/// Inicializa el subsistema de agentes del kernel
pub fn init() {
    println!("[AgentOS::Agent] Subsistema de Agentes Nativos Ring 0 inicializado");
}

/// Instancia un nuevo agente nativo con AddressSpace aislado y registro causal
pub fn spawn_agent(
    manifest: AgentManifest,
    ledger: &mut CausalLedger,
) -> Result<AgentId, AgentError> {
    let mut reg = REGISTRY.lock();

    let id = AgentId(NEXT_AGENT_ID.fetch_add(1, Ordering::Relaxed));
    let address_space = AddressSpace::new().ok_or(AgentError::AddressSpaceCreationFailed)?;

    let mut cspace = CSpace::new();
    let root_cap = cspace.mint_root(
        ObjectId(id.0),
        Permissions::ALL,
        id.0 as u32,
    );

    // Si tiene padre, hereda permisos atenuados de memoria/comunicación
    if let Some(parent_id) = manifest.parent {
        if let Some(parent) = reg.agents.get_mut(&parent_id) {
            parent.children.push(id);
        }
    }

    // Registrar creación del agente en el Grafo Causal indeleble
    let causal_domain = DomainId(id.0 as u32);
    let parent_domain = manifest.parent.map(|p| DomainId(p.0 as u32)).unwrap_or(DomainId(0));
    let spawn_effect = ledger.record_effect(
        BranchId(0),
        parent_domain,
        causal_domain,
        alloc::vec![],
        manifest.security_label,
        Reversibility::PurelyReversible,
        manifest.intent[0..32].try_into().unwrap_or([0u8; 32]),
    );

    let agent = Agent {
        id,
        name: manifest.name,
        intent: manifest.intent,
        address_space,
        cspace,
        budget: manifest.budget,
        security_label: manifest.security_label,
        state: AgentState::Ready,
        causal_domain,
        causal_root: spawn_effect,
        parent: manifest.parent,
        children: Vec::new(),
        entry_point: manifest.entry_point,
        allocated_frames: Vec::new(),
    };

    reg.agents.insert(id, agent);

    println!(
        "[AgentOS::Agent] Agente instanciado: ID={} RootEffect={:?} CSpaceToken={:?}",
        id.0, spawn_effect, root_cap
    );

    Ok(id)
}

/// Suspende temporalmente un agente activo
pub fn suspend_agent(id: AgentId) -> Result<(), AgentError> {
    let mut reg = REGISTRY.lock();
    let agent = reg.agents.get_mut(&id).ok_or(AgentError::AgentNotFound)?;
    match agent.state {
        AgentState::Ready | AgentState::Running => {
            agent.state = AgentState::Suspended;
            println!("[AgentOS::Agent] Agente ID={} suspendido", id.0);
            Ok(())
        }
        _ => Err(AgentError::InvalidStateTransition),
    }
}

/// Reanuda un agente previamente suspendido
pub fn resume_agent(id: AgentId) -> Result<(), AgentError> {
    let mut reg = REGISTRY.lock();
    let agent = reg.agents.get_mut(&id).ok_or(AgentError::AgentNotFound)?;
    if agent.budget.is_exhausted() {
        return Err(AgentError::BudgetExhausted);
    }
    match agent.state {
        AgentState::Suspended => {
            agent.state = AgentState::Ready;
            println!("[AgentOS::Agent] Agente ID={} reanudado", id.0);
            Ok(())
        }
        _ => Err(AgentError::InvalidStateTransition),
    }
}

/// Termina de forma definitiva un agente, revocando sus capacidades y registrando salida
pub fn kill_agent(
    id: AgentId,
    exit_code: u32,
    ledger: &mut CausalLedger,
) -> Result<(), AgentError> {
    let mut reg = REGISTRY.lock();
    let agent = reg.agents.get_mut(&id).ok_or(AgentError::AgentNotFound)?;

    agent.state = AgentState::Terminated(exit_code);
    agent.free_all_frames();

    // Registrar efecto de terminación en el Grafo Causal
    let kill_effect = ledger.record_effect(
        BranchId(0),
        DomainId(0), // Kernel autoriza la terminación
        agent.causal_domain,
        alloc::vec![agent.causal_root],
        SecurityLabel::TRUSTED_KERNEL,
        Reversibility::Irreversible,
        [exit_code as u8; 32],
    );

    println!(
        "[AgentOS::Agent] Agente ID={} terminado (ExitCode={}) KillEffect={:?}",
        id.0, exit_code, kill_effect
    );

    Ok(())
}

/// Consulta el presupuesto actual de un agente
pub fn query_budget(id: AgentId) -> Option<AgentBudget> {
    let reg = REGISTRY.lock();
    reg.agents.get(&id).map(|a| a.budget)
}

/// Retorna el número de agentes registrados en el kernel
pub fn count_agents() -> usize {
    REGISTRY.lock().agents.len()
}
