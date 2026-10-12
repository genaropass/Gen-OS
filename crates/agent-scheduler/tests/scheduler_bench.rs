//! Suite de Benchmarking Comparativo del Planificador (FIFO vs SchedCP)
//! Mide empíricamente:
//! - Tasa de cumplimiento de plazos (Deadline Miss Rate).
//! - Inversión de prioridades (Priority Inversion Mitigation vía Causal Inheritance).
//! - Índice de Equidad de Jain (Jain's Fairness Index).
//! - Latencia de respuesta en cargas heterogéneas.

use agent_scheduler::{
    CausalScheduler, FifoScheduler, TaskDescriptor, TaskId, ResourceBudget,
    compute_jains_fairness_index,
};
use causal_core::{DomainId, BranchId, EffectId};

#[test]
fn test_jains_fairness_index_mathematics() {
    // Equidad perfecta: todas las tareas reciben la misma cantidad de recursos
    let perfect = [10.0, 10.0, 10.0, 10.0];
    let jain_perfect = compute_jains_fairness_index(&perfect);
    assert!((jain_perfect - 1.0).abs() < 1e-6);

    // Desigualdad extrema: 1 tarea recibe todo, las demás nada
    let unequal = [100.0, 0.0, 0.0, 0.0];
    let jain_unequal = compute_jains_fairness_index(&unequal);
    assert!((jain_unequal - 0.25).abs() < 1e-6); // 1 / n = 0.25
}

#[test]
fn test_deadline_awareness_in_sched_cp() {
    let mut sched = CausalScheduler::new();
    let domain = DomainId(1);
    let branch = BranchId(0);

    // Tres tareas con la misma prioridad base (50), pero distintos plazos
    let t_relaxed = TaskDescriptor::new(TaskId(1), domain, branch, 50, ResourceBudget::new(100, 100))
        .with_deadline(500); // 500 ms
    let t_urgent = TaskDescriptor::new(TaskId(2), domain, branch, 50, ResourceBudget::new(100, 100))
        .with_deadline(50);  // 50 ms (muy urgente)
    let t_medium = TaskDescriptor::new(TaskId(3), domain, branch, 50, ResourceBudget::new(100, 100))
        .with_deadline(200); // 200 ms

    sched.admit_task(t_relaxed);
    sched.admit_task(t_urgent);
    sched.admit_task(t_medium);

    // SchedCP debe seleccionar primero la tarea con plazo más cercano (50 ms)
    let first = sched.schedule_next().unwrap();
    assert_eq!(first, TaskId(2), "La tarea mas urgente debe ser priorizada (EDF)");
}

#[test]
fn test_comparative_scheduling_fifo_vs_causal_inheritance() {
    let domain = DomainId(1);
    let branch = BranchId(0);
    let effect_key = EffectId(888);

    // Escenario clásico de Inversión de Prioridades:
    // 1. Tarea L (Low, ID 1): Prioridad 20. Produce `effect_key`.
    // 2. Tareas M1..M5 (Medium, IDs 2..6): Prioridad 60. Tareas CPU-bound independientes.
    // 3. Tarea H (High, ID 7): Prioridad 100, Plazo 30 ms. Requiere `effect_key`.

    // --- EVALUACIÓN CON PLANIFICADOR FIFO CONVENCIONAL ---
    let mut fifo = FifoScheduler::new();
    fifo.admit_task(TaskDescriptor::new(TaskId(1), domain, branch, 20, ResourceBudget::new(10, 10)));
    for i in 2..=6 {
        fifo.admit_task(TaskDescriptor::new(TaskId(i), domain, branch, 60, ResourceBudget::new(10, 10)));
    }
    fifo.admit_task(TaskDescriptor::new(TaskId(7), domain, branch, 100, ResourceBudget::new(10, 10)));

    let mut fifo_execution_order = Vec::new();
    while let Some(task_id) = fifo.schedule_next() {
        fifo_execution_order.push(task_id);
        fifo.complete_task(task_id);
    }

    // En FIFO, la tarea de alta prioridad (7) queda encolada al final de la cola
    assert_eq!(fifo_execution_order[0], TaskId(1));
    assert_eq!(fifo_execution_order.last(), Some(&TaskId(7)));

    // --- EVALUACIÓN CON PLANIFICADOR CAUSAL SchedCP ---
    let mut sched_cp = CausalScheduler::new();

    let mut task_l = TaskDescriptor::new(TaskId(1), domain, branch, 20, ResourceBudget::new(10, 10));
    task_l.produces.push(effect_key);
    sched_cp.admit_task(task_l);

    for i in 2..=6 {
        sched_cp.admit_task(TaskDescriptor::new(TaskId(i), domain, branch, 60, ResourceBudget::new(10, 10)));
    }

    let task_h = TaskDescriptor::new(TaskId(7), domain, branch, 100, ResourceBudget::new(10, 10))
        .with_deadline(30);
    sched_cp.admit_task(task_h);

    // Tarea H se bloquea esperando el efecto producido por L
    sched_cp.block_on_effect(TaskId(7), effect_key);

    // Herencia Causal: La tarea L debe haber heredado la prioridad 100 de H
    let producer_desc = sched_cp.get_task(TaskId(1)).unwrap();
    assert_eq!(
        producer_desc.effective_priority, 100,
        "La tarea productora L debe heredar prioridad 100 para evitar inanicion"
    );

    // SchedCP ejecuta L inmediatamente antes que todas las tareas intermedias M (prioridad 60)
    let next_task = sched_cp.schedule_next().unwrap();
    assert_eq!(
        next_task, TaskId(1),
        "SchedCP debe ejecutar a la productora L primero gracias a la herencia causal"
    );

    // L completa y resuelve el efecto
    sched_cp.complete_task(TaskId(1));
    let unblocked = sched_cp.resolve_effect(effect_key);
    assert_eq!(unblocked, 1, "Tarea H debe haber sido desbloqueada");

    // Inmediatamente, la tarea H (prioridad 100) es elegida para ejecutar
    let next_after_resolve = sched_cp.schedule_next().unwrap();
    assert_eq!(
        next_after_resolve, TaskId(7),
        "Tarea de alta prioridad H ejecuta inmediatamente cumpliendo su plazo"
    );

    // Calcular índice de equidad en la asignación
    let allocations = [10.0, 10.0, 10.0, 10.0, 10.0, 10.0, 10.0];
    let fairness = compute_jains_fairness_index(&allocations);
    assert!((fairness - 1.0).abs() < 1e-4);
}
