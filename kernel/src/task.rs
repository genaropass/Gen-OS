//! Subsistema de Tareas Nativas y Cambio de Contexto para AgentOS (Ring 0)
//!
//! Permite la ejecución de hilos de kernel y agentes de fondo en Ring 0
//! con conmutación de contexto segura de registros de CPU callee-saved (x86-64).

use alloc::vec::Vec;
use alloc::boxed::Box;
use core::arch::global_asm;
use core::sync::atomic::{AtomicU64, Ordering};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    Ready,
    Running,
    Blocked,
    Terminated,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct TaskContext {
    pub rsp: u64,
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbx: u64,
    pub rbp: u64,
}

pub struct KernelTask {
    pub id: u64,
    pub name: &'static str,
    pub state: TaskState,
    pub context: TaskContext,
    pub stack: Vec<u8>,
}

static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);

extern "C" {
    fn asm_context_switch(old_ctx: *mut TaskContext, new_ctx: *const TaskContext);
}

global_asm!(
    r#"
    .global asm_context_switch
    asm_context_switch:
        /* rdi = &mut old_task.context, rsi = &new_task.context */
        push rbp
        push rbx
        push r12
        push r13
        push r14
        push r15
        mov [rdi], rsp      /* Guardar rsp del contexto actual */

        mov rsp, [rsi]      /* Cargar nuevo rsp */
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        ret                 /* Retorna al nuevo punto de ejecucion */
    "#
);

impl KernelTask {
    /// Crea una nueva tarea de kernel con una pila de 16 KiB
    pub fn new(name: &'static str, entry_point: fn() -> !) -> Box<Self> {
        let id = NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed);
        let stack_size = 16 * 1024; // 16 KiB
        let mut stack = Vec::with_capacity(stack_size);
        stack.resize(stack_size, 0);

        let stack_top = stack.as_ptr() as usize + stack_size;
        // Alinear a 16 bytes
        let mut aligned_sp = (stack_top & !0xF) as *mut u64;

        unsafe {
            // Configurar retorno simulado al entry_point
            aligned_sp = aligned_sp.sub(1);
            *aligned_sp = entry_point as usize as u64;

            // Espacio para 6 registros callee-saved (r15, r14, r13, r12, rbx, rbp) que pop restaurará
            aligned_sp = aligned_sp.sub(6);
            for i in 0..6 {
                *aligned_sp.add(i) = 0;
            }
        }

        let context = TaskContext {
            rsp: aligned_sp as u64,
            rbp: 0,
            rbx: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
        };

        Box::new(Self {
            id,
            name,
            state: TaskState::Ready,
            context,
            stack,
        })
    }
}

/// Conmuta la ejecución entre dos contextos de tarea de forma atómica
pub unsafe fn switch(old_ctx: &mut TaskContext, new_ctx: &TaskContext) {
    asm_context_switch(old_ctx as *mut TaskContext, new_ctx as *const TaskContext);
}
