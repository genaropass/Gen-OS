//! # agent-scheduler
//!
//! Planificador Causal de Recursos e Inferencia (SchedCP) para AgentOS.
//! Implementa:
//! 1. Planificación consciente de presupuestos heterogéneos (CPU ms y Tokens de inferencia).
//! 2. Estados de tareas reactivos a dependencias del Grafo Causal (`BlockedOnCausal`).
//! 3. Herencia de Prioridad Causal (Causal Priority Inheritance):
//!    Si una tarea de alta prioridad depende de un efecto producido por una tarea de menor prioridad,
//!    la productora hereda temporalmente la prioridad para evitar la inversión de prioridades.
//! 4. Contención determinista de bucles infinitos y agotamiento de recursos.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{
    vec::Vec,
    collections::BTreeMap,
};

#[cfg(feature = "std")]
use std::collections::BTreeMap;

use causal_core::{DomainId, BranchId, EffectId};

/// Identificador único de una tarea de agente o proceso del sistema
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct TaskId(pub u64);

/// Estado de ejecución de una tarea en el planificador
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TaskState {
    Ready,
    Running,
    BlockedOnCausal(EffectId),
    Completed,
    BudgetExhausted,
}

/// Presupuesto estricto de recursos y consumo acumulado
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct ResourceBudget {
    pub max_cpu_ms: u64,
    pub max_tokens: u64,
    pub consumed_cpu_ms: u64,
    pub consumed_tokens: u64,
}

impl ResourceBudget {
    pub const fn new(max_cpu_ms: u64, max_tokens: u64) -> Self {
        Self {
            max_cpu_ms,
            max_tokens,
            consumed_cpu_ms: 0,
            consumed_tokens: 0,
        }
    }

    pub fn consume(&mut self, cpu_ms: u64, tokens: u64) -> Result<(), &'static str> {
        self.consumed_cpu_ms += cpu_ms;
        self.consumed_tokens += tokens;

        if self.consumed_cpu_ms > self.max_cpu_ms {
            return Err("Presupuesto de tiempo de CPU agotado");
        }
        if self.consumed_tokens > self.max_tokens {
            return Err("Presupuesto de tokens de inferencia agotado");
        }

        Ok(())
    }
}

/// Descriptor completo de una tarea en el planificador
#[derive(Clone, Debug)]
pub struct TaskDescriptor {
    pub id: TaskId,
    pub domain: DomainId,
    pub branch: BranchId,
    pub base_priority: u8,
    pub effective_priority: u8,
    pub state: TaskState,
    pub budget: ResourceBudget,
    pub waiting_on: Vec<EffectId>,
    pub produces: Vec<EffectId>,
    pub deadline_ms: Option<u64>,
    pub integrity_level: u16,
    pub created_at_ms: u64,
}

impl TaskDescriptor {
    pub fn new(
        id: TaskId,
        domain: DomainId,
        branch: BranchId,
        base_priority: u8,
        budget: ResourceBudget,
    ) -> Self {
        Self {
            id,
            domain,
            branch,
            base_priority,
            effective_priority: base_priority,
            state: TaskState::Ready,
            budget,
            waiting_on: Vec::new(),
            produces: Vec::new(),
            deadline_ms: None,
            integrity_level: 50,
            created_at_ms: 0,
        }
    }

    pub fn with_deadline(mut self, deadline_ms: u64) -> Self {
        self.deadline_ms = Some(deadline_ms);
        self
    }

    pub fn with_integrity(mut self, integrity_level: u16) -> Self {
        self.integrity_level = integrity_level;
        self
    }
}

/// Planificador Causal SchedCP
#[derive(Default, Debug)]
pub struct CausalScheduler {
    tasks: BTreeMap<TaskId, TaskDescriptor>,
    effect_producers: BTreeMap<EffectId, TaskId>,
    current_task: Option<TaskId>,
}

impl CausalScheduler {
    pub fn new() -> Self {
        Self {
            tasks: BTreeMap::new(),
            effect_producers: BTreeMap::new(),
            current_task: None,
        }
    }

    /// Admite una nueva tarea en el planificador
    pub fn admit_task(&mut self, task: TaskDescriptor) {
        for &effect in &task.produces {
            self.effect_producers.insert(effect, task.id);
        }
        self.tasks.insert(task.id, task);
    }

    /// Registra que una tarea producirá un efecto específico en el futuro
    pub fn register_producer(&mut self, task_id: TaskId, effect: EffectId) {
        if let Some(task) = self.tasks.get_mut(&task_id) {
            if !task.produces.contains(&effect) {
                task.produces.push(effect);
            }
            self.effect_producers.insert(effect, task_id);
        }
    }

    /// Bloquea una tarea hasta que se produzca un efecto causal requerido
    pub fn block_on_effect(&mut self, task_id: TaskId, effect: EffectId) {
        let task_prio = if let Some(task) = self.tasks.get_mut(&task_id) {
            task.state = TaskState::BlockedOnCausal(effect);
            if !task.waiting_on.contains(&effect) {
                task.waiting_on.push(effect);
            }
            task.effective_priority
        } else {
            return;
        };

        // Si la tarea actual era la que se bloqueó, liberar CPU
        if self.current_task == Some(task_id) {
            self.current_task = None;
        }

        // Herencia de Prioridad Causal:
        // Si el productor del efecto tiene menor prioridad, elevarla inmediatamente
        if let Some(&producer_id) = self.effect_producers.get(&effect) {
            if let Some(producer) = self.tasks.get_mut(&producer_id) {
                if producer.effective_priority < task_prio {
                    producer.effective_priority = task_prio;
                }
            }
        }
    }

    /// Resuelve un efecto: desbloquea a todas las tareas que esperaban por él
    pub fn resolve_effect(&mut self, effect: EffectId) -> usize {
        let mut unblocked_count = 0;

        for task in self.tasks.values_mut() {
            if task.state == TaskState::BlockedOnCausal(effect) {
                task.waiting_on.retain(|&e| e != effect);
                if task.waiting_on.is_empty() {
                    task.state = TaskState::Ready;
                    unblocked_count += 1;
                }
            }
        }

        // Recalcular prioridades efectivas de los productores
        self.recalculate_priorities();

        unblocked_count
    }

    /// Recalcula las prioridades efectivas de acuerdo a las dependencias causales activas
    fn recalculate_priorities(&mut self) {
        // Restaurar prioridades base primero
        for task in self.tasks.values_mut() {
            task.effective_priority = task.base_priority;
        }

        // Propagar herencia de prioridades de las tareas bloqueadas hacia sus productores
        let blocked_deps: Vec<(TaskId, EffectId, u8)> = self
            .tasks
            .values()
            .filter_map(|t| {
                if let TaskState::BlockedOnCausal(eff) = t.state {
                    Some((t.id, eff, t.base_priority))
                } else {
                    None
                }
            })
            .collect();

        for (_blocked_id, effect, waiter_prio) in blocked_deps {
            if let Some(&producer_id) = self.effect_producers.get(&effect) {
                if let Some(producer) = self.tasks.get_mut(&producer_id) {
                    producer.effective_priority = producer.effective_priority.max(waiter_prio);
                }
            }
        }
    }

    /// Registra el consumo de recursos de una tarea activa y detecta agotamiento
    pub fn consume_resources(
        &mut self,
        task_id: TaskId,
        cpu_ms: u64,
        tokens: u64,
    ) -> Result<(), &'static str> {
        let task = self.tasks.get_mut(&task_id).ok_or("Tarea no encontrada")?;
        if let Err(err) = task.budget.consume(cpu_ms, tokens) {
            task.state = TaskState::BudgetExhausted;
            if self.current_task == Some(task_id) {
                self.current_task = None;
            }
            return Err(err);
        }
        Ok(())
    }

    /// Selecciona la siguiente tarea Ready con mayor prioridad efectiva para ejecutar
    pub fn schedule_next(&mut self) -> Option<TaskId> {
        // Encontrar tarea Ready optimizando por prioridad efectiva, urgencia de plazo e integridad
        let best_candidate = self
            .tasks
            .values()
            .filter(|t| t.state == TaskState::Ready)
            .max_by_key(|t| {
                let deadline_score = match t.deadline_ms {
                    Some(d) => 10_000_000u64.saturating_sub(d),
                    None => 0,
                };
                (
                    (t.effective_priority as u64) * 10_000 + (t.integrity_level as u64),
                    deadline_score,
                    core::cmp::Reverse(t.id.0)
                )
            })
            .map(|t| t.id);

        if let Some(id) = best_candidate {
            if let Some(task) = self.tasks.get_mut(&id) {
                task.state = TaskState::Running;
            }
            self.current_task = Some(id);
            Some(id)
        } else {
            self.current_task = None;
            None
        }
    }

    /// Marca la tarea actual como completada
    pub fn complete_task(&mut self, task_id: TaskId) {
        if let Some(task) = self.tasks.get_mut(&task_id) {
            task.state = TaskState::Completed;
        }
        if self.current_task == Some(task_id) {
            self.current_task = None;
        }
    }

    /// Obtiene el descriptor de una tarea
    pub fn get_task(&self, task_id: TaskId) -> Option<&TaskDescriptor> {
        self.tasks.get(&task_id)
    }

    /// Tarea actualmente en ejecución
    pub fn current_task(&self) -> Option<TaskId> {
        self.current_task
    }
}

/// Planificador FIFO Convencional de Línea Base (para comparativas y benchmarks)
#[derive(Default, Debug)]
pub struct FifoScheduler {
    pub tasks: Vec<TaskDescriptor>,
    pub current_task: Option<TaskId>,
}

impl FifoScheduler {
    pub fn new() -> Self {
        Self {
            tasks: Vec::new(),
            current_task: None,
        }
    }

    pub fn admit_task(&mut self, task: TaskDescriptor) {
        self.tasks.push(task);
    }

    pub fn schedule_next(&mut self) -> Option<TaskId> {
        let idx = self.tasks.iter().position(|t| t.state == TaskState::Ready)?;
        self.tasks[idx].state = TaskState::Running;
        let id = self.tasks[idx].id;
        self.current_task = Some(id);
        Some(id)
    }

    pub fn complete_task(&mut self, id: TaskId) {
        if let Some(t) = self.tasks.iter_mut().find(|t| t.id == id) {
            t.state = TaskState::Completed;
        }
        if self.current_task == Some(id) {
            self.current_task = None;
        }
    }
}

/// Calcula el Índice de Equidad de Jain (Jain's Fairness Index)
/// Retorna un valor en [1/n, 1.0], donde 1.0 representa equidad perfecta
pub fn compute_jains_fairness_index(allocations: &[f64]) -> f64 {
    if allocations.is_empty() {
        return 1.0;
    }
    let sum: f64 = allocations.iter().sum();
    let sum_sq: f64 = allocations.iter().map(|&x| x * x).sum();
    if sum_sq == 0.0 {
        return 1.0;
    }
    (sum * sum) / ((allocations.len() as f64) * sum_sq)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_priority_scheduling() {
        let mut sched = CausalScheduler::new();
        let domain = DomainId(1);
        let branch = BranchId(0);

        let t1 = TaskDescriptor::new(TaskId(1), domain, branch, 50, ResourceBudget::new(100, 1000));
        let t2 = TaskDescriptor::new(TaskId(2), domain, branch, 120, ResourceBudget::new(100, 1000));
        let t3 = TaskDescriptor::new(TaskId(3), domain, branch, 90, ResourceBudget::new(100, 1000));

        sched.admit_task(t1);
        sched.admit_task(t2);
        sched.admit_task(t3);

        // La tarea 2 debe elegirse primero (prioridad 120 > 90 > 50)
        let next = sched.schedule_next().expect("Tarea elegible");
        assert_eq!(next, TaskId(2));
    }

    #[test]
    fn test_causal_priority_inheritance() {
        let mut sched = CausalScheduler::new();
        let domain = DomainId(1);
        let branch = BranchId(0);

        let effect_dep = EffectId(999);

        // Tarea de baja prioridad (50) que produce effect_dep
        let mut producer = TaskDescriptor::new(TaskId(1), domain, branch, 50, ResourceBudget::new(100, 1000));
        producer.produces.push(effect_dep);

        // Tarea de alta prioridad (200) que necesita effect_dep
        let consumer = TaskDescriptor::new(TaskId(2), domain, branch, 200, ResourceBudget::new(100, 1000));

        sched.admit_task(producer);
        sched.admit_task(consumer);

        // El consumidor de alta prioridad se bloquea en effect_dep:
        sched.block_on_effect(TaskId(2), effect_dep);

        // ¡Herencia de Prioridad Causal!
        // La tarea 1 ahora debe haber heredado prioridad 200:
        assert_eq!(
            sched.get_task(TaskId(1)).unwrap().effective_priority,
            200,
            "El productor debe heredar la prioridad del consumidor bloqueado"
        );

        // El planificador elige a la tarea 1 para desbloquear la ruta crítica:
        let next = sched.schedule_next().expect("Tarea elegible");
        assert_eq!(next, TaskId(1));

        // Tarea 1 completa su trabajo y resuelve el efecto:
        let unblocked = sched.resolve_effect(effect_dep);
        assert_eq!(unblocked, 1);

        // La prioridad de Tarea 1 regresa a su base (50):
        assert_eq!(sched.get_task(TaskId(1)).unwrap().effective_priority, 50);

        // Ahora la tarea 2 (prioridad 200) está Ready y debe elegirse:
        sched.complete_task(TaskId(1));
        let next_after_resolve = sched.schedule_next().expect("Consumidor desbloqueado");
        assert_eq!(next_after_resolve, TaskId(2));
    }

    #[test]
    fn test_budget_exhaustion_containment() {
        let mut sched = CausalScheduler::new();
        let domain = DomainId(1);
        let branch = BranchId(0);

        // Presupuesto de máximo 500 tokens
        let task = TaskDescriptor::new(TaskId(1), domain, branch, 100, ResourceBudget::new(1000, 500));
        sched.admit_task(task);

        let t = sched.schedule_next().unwrap();
        assert_eq!(t, TaskId(1));

        // Consumir 400 tokens (dentro del límite)
        assert!(sched.consume_resources(TaskId(1), 10, 400).is_ok());
        assert_eq!(sched.get_task(TaskId(1)).unwrap().state, TaskState::Running);

        // Intentar consumir 200 tokens más (total 600 > 500 max):
        let res = sched.consume_resources(TaskId(1), 10, 200);
        assert!(res.is_err(), "Debe fallar por exceso de tokens");
        assert_eq!(sched.get_task(TaskId(1)).unwrap().state, TaskState::BudgetExhausted);

        // La tarea ya no es elegible en el planificador:
        assert!(sched.schedule_next().is_none(), "Ninguna tarea debe poder ejecutarse");
    }
}
