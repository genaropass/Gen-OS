//! Planificador Preemptivo de Ring 0 para AgentOS
//! Implementa round-robin con quantum de tiempo, expulsión por hardware (preemption) desde IRQ 0,
//! cesión voluntaria (`yield_now`), creación de tareas (`spawn`) y telemetría de conmutaciones.

use alloc::boxed::Box;
use alloc::collections::VecDeque;
use crate::task::{KernelTask, TaskContext, TaskState, asm_context_switch};
use crate::sync::IrqSpinLock;
use crate::println;

pub struct Scheduler {
    ready_queue: VecDeque<Box<KernelTask>>,
    current: Option<Box<KernelTask>>,
    default_quantum: u32,
    context_switch_count: u64,
}

impl Scheduler {
    pub const fn new() -> Self {
        Self {
            ready_queue: VecDeque::new(),
            current: None,
            default_quantum: 10, // 10 ticks a 100 Hz = 100 ms de quantum
            context_switch_count: 0,
        }
    }

    /// Encola una nueva tarea lista para ejecutar
    pub fn enqueue(&mut self, mut task: Box<KernelTask>) {
        task.state = TaskState::Ready;
        self.ready_queue.push_back(task);
    }

    /// Retorna (tareas_activas, conmutaciones_totales)
    pub fn stats(&self) -> (usize, u64) {
        let active = self.ready_queue.len() + if self.current.is_some() { 1 } else { 0 };
        (active, self.context_switch_count)
    }
}

impl Default for Scheduler {
    fn default() -> Self {
        Self::new()
    }
}

static SCHEDULER: IrqSpinLock<Scheduler> = IrqSpinLock::new(Scheduler::new());

/// Inicializa el planificador registrando el hilo principal como tarea en ejecución
pub fn init() {
    let mut sched = SCHEDULER.lock();
    let main_task = KernelTask::for_current("kernel_main");
    sched.current = Some(main_task);
    println!("[AgentOS::Sched] Planificador preemptivo inicializado (Quantum: 100 ms)");
}

/// Instancia y encola una nueva tarea de fondo en Ring 0
pub fn spawn(name: &'static str, entry_point: fn() -> !) {
    let task = KernelTask::new(name, entry_point);
    let id = task.id;
    SCHEDULER.lock().enqueue(task);
    println!("[AgentOS::Sched] Tarea Ring 0 instanciada: '{}' [ID: {}]", name, id);
}

/// Cede voluntariamente la CPU a la siguiente tarea lista
pub fn yield_now() {
    let switch_data = {
        let mut sched = SCHEDULER.lock();
        let default_quantum = sched.default_quantum;
        if sched.ready_queue.is_empty() {
            if let Some(ref mut curr) = sched.current {
                curr.quantum_remaining = default_quantum;
            }
            return;
        }

        // Extraer la siguiente tarea lista
        let mut next = match sched.ready_queue.pop_front() {
            Some(t) => t,
            None => return,
        };
        next.state = TaskState::Running;
        next.quantum_remaining = default_quantum;

        // Desalojar tarea actual y encolarla como lista
        let mut prev = match sched.current.take() {
            Some(t) => t,
            None => return,
        };
        prev.state = TaskState::Ready;
        sched.ready_queue.push_back(prev);
        sched.current = Some(next);
        sched.context_switch_count += 1;

        let old_ctx = (&mut sched.ready_queue.back_mut().unwrap().context) as *mut TaskContext;
        let new_ctx = (&sched.current.as_ref().unwrap().context) as *const TaskContext;
        let old_fx = sched.ready_queue.back_mut().unwrap().fxsave.0.as_mut_ptr();
        let new_fx = sched.current.as_ref().unwrap().fxsave.0.as_ptr();
        (old_ctx, new_ctx, old_fx, new_fx)
    };

    unsafe {
        asm_context_switch(switch_data.0, switch_data.1, switch_data.2, switch_data.3);
    }
}

/// Invocado por el temporizador PIT (IRQ 0 / Vector 32) para gestionar preempción
pub fn check_preempt() {
    let switch_needed = {
        let mut sched = SCHEDULER.lock();
        if let Some(ref mut curr) = sched.current {
            curr.ticks_total += 1;
            if curr.quantum_remaining > 0 {
                curr.quantum_remaining -= 1;
            }
            curr.quantum_remaining == 0 && !sched.ready_queue.is_empty()
        } else {
            false
        }
    };

    if switch_needed {
        yield_now();
    }
}

/// Retorna estadísticas de planificación (tareas_activas, conmutaciones_totales)
pub fn sched_stats() -> (usize, u64) {
    SCHEDULER.lock().stats()
}
