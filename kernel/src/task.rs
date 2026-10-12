//! Subsistema de Tareas Nativas y Conmutación de Contexto para AgentOS (Ring 0)
//! Soporta preservación atómica de registros callee-saved, flags de CPU (RFLAGS con pushfq/popfq)
//! y reserva de área FXSAVE de 512 bytes alineada a 16 bytes para FPU/SIMD.

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
}

#[repr(C, align(16))]
#[derive(Clone, Copy)]
pub struct FxsaveArea(pub [u8; 512]);

impl Default for FxsaveArea {
    fn default() -> Self {
        Self([0; 512])
    }
}

pub struct KernelTask {
    pub id: u64,
    pub name: &'static str,
    pub state: TaskState,
    pub context: TaskContext,
    pub fxsave: FxsaveArea,
    pub stack: Vec<u8>,
    pub quantum_remaining: u32,
    pub ticks_total: u64,
}

static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);

extern "C" {
    pub fn asm_context_switch(old_ctx: *mut TaskContext, new_ctx: *const TaskContext);
}

global_asm!(
    r#"
    .global asm_context_switch
    asm_context_switch:
        /* rdi = &mut old_task.context, rsi = &new_task.context */
        pushfq              /* Guardar RFLAGS de la tarea saliente */
        push rbp
        push rbx
        push r12
        push r13
        push r14
        push r15
        mov [rdi], rsp      /* Guardar rsp en old_ctx.rsp */

        mov rsp, [rsi]      /* Cargar nuevo rsp desde new_ctx.rsp */
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        popfq               /* Restaurar RFLAGS de la tarea entrante */
        ret                 /* Retorna al nuevo punto de ejecución */
    "#
);

impl KernelTask {
    /// Crea una nueva tarea de kernel con una pila aislada de 16 KiB
    pub fn new(name: &'static str, entry_point: fn() -> !) -> Box<Self> {
        let id = NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed);
        let stack_size = 16 * 1024; // 16 KiB
        let mut stack = Vec::with_capacity(stack_size);
        stack.resize(stack_size, 0);

        let stack_top = stack.as_ptr() as usize + stack_size;
        // Alinear la cima de la pila a 16 bytes
        let mut aligned_sp = (stack_top & !0xF) as *mut u64;

        unsafe {
            // 1. Entry point al cual retornará el `ret` de asm_context_switch
            aligned_sp = aligned_sp.sub(1);
            *aligned_sp = entry_point as usize as u64;

            // 2. RFLAGS inicial con IF (Interrupt Flag) activo (0x202)
            aligned_sp = aligned_sp.sub(1);
            *aligned_sp = 0x202;

            // 3. Registros callee-saved (rbp, rbx, r12, r13, r14, r15)
            aligned_sp = aligned_sp.sub(6);
            for i in 0..6 {
                *aligned_sp.add(i) = 0;
            }
        }

        let context = TaskContext {
            rsp: aligned_sp as u64,
        };

        Box::new(Self {
            id,
            name,
            state: TaskState::Ready,
            context,
            fxsave: FxsaveArea::default(),
            stack,
            quantum_remaining: 10,
            ticks_total: 0,
        })
    }

    /// Crea un descriptor de tarea para el contexto principal ya en ejecución
    pub fn for_current(name: &'static str) -> Box<Self> {
        let id = NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed);
        Box::new(Self {
            id,
            name,
            state: TaskState::Running,
            context: TaskContext { rsp: 0 },
            fxsave: FxsaveArea::default(),
            stack: Vec::new(),
            quantum_remaining: 10,
            ticks_total: 0,
        })
    }
}
