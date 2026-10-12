//! Subsistema de Tareas Nativas y Conmutación de Contexto para AgentOS (Ring 0)
//! Soporta preservación atómica de registros callee-saved, flags de CPU (RFLAGS con pushfq/popfq),
//! reserva de área FXSAVE de 512 bytes alineada a 16 bytes y pilas con página de guarda virtual desmapeada.

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
    pub guard_page_virt: u64,
    pub stack_top_virt: u64,
    pub stack_frames: Vec<crate::mm::frame::PhysFrame>,
    pub fallback_stack: Vec<u8>,
    pub quantum_remaining: u32,
    pub ticks_total: u64,
}

static NEXT_TASK_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_STACK_VIRT: AtomicU64 = AtomicU64::new(0xffff_ff80_1000_0000);

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
    /// Crea una nueva tarea de kernel con pila de 16 KiB protegida por página de guarda no mapeada
    pub fn new(name: &'static str, entry_point: fn() -> !) -> Box<Self> {
        let id = NEXT_TASK_ID.fetch_add(1, Ordering::Relaxed);

        // Asignar 4 marcos físicos (16 KiB) para la pila
        let mut frames = Vec::with_capacity(4);
        for _ in 0..4 {
            if let Some(f) = crate::mm::frame::alloc_frame() {
                frames.push(f);
            }
        }

        let mut fallback_stack = Vec::new();

        let (guard_page_virt, stack_top_virt, rsp_val) = if frames.len() == 4 {
            let slot_base = NEXT_STACK_VIRT.fetch_add(32 * 1024, Ordering::Relaxed);
            let guard_page = slot_base; // Base del slot: Página de guarda NO MAPEADA
            let stack_base = slot_base + 4096;
            let hhdm = crate::mm::frame::hhdm_offset();
            let cr3 = crate::mm::paging::read_cr3();
            let pml4_phys = cr3 & 0x000f_ffff_ffff_f000;

            // Mapear las 4 páginas de la pila con WRITABLE + NO_EXECUTE
            for (i, frame) in frames.iter().enumerate() {
                let page_virt = stack_base + (i as u64) * 4096;
                let _ = crate::mm::paging::map_page(
                    pml4_phys,
                    page_virt,
                    frame.start_address(),
                    crate::mm::paging::flags::WRITABLE | crate::mm::paging::flags::NO_EXECUTE,
                    hhdm,
                );
            }

            let stack_top = stack_base + 16 * 1024;
            let mut aligned_sp = (stack_top & !0xF) as *mut u64;

            unsafe {
                aligned_sp = aligned_sp.sub(1);
                *aligned_sp = entry_point as usize as u64;

                aligned_sp = aligned_sp.sub(1);
                *aligned_sp = 0x202; // IF activo

                aligned_sp = aligned_sp.sub(6);
                for i in 0..6 {
                    *aligned_sp.add(i) = 0;
                }
            }

            (guard_page, stack_top, aligned_sp as u64)
        } else {
            // Fallback con vector en Heap si el PMM aún no estuviera disponible
            let stack_size = 16 * 1024;
            fallback_stack.resize(stack_size, 0);
            let stack_top = fallback_stack.as_ptr() as usize + stack_size;
            let mut aligned_sp = (stack_top & !0xF) as *mut u64;

            unsafe {
                aligned_sp = aligned_sp.sub(1);
                *aligned_sp = entry_point as usize as u64;
                aligned_sp = aligned_sp.sub(1);
                *aligned_sp = 0x202;
                aligned_sp = aligned_sp.sub(6);
                for i in 0..6 {
                    *aligned_sp.add(i) = 0;
                }
            }

            (0, stack_top as u64, aligned_sp as u64)
        };

        let context = TaskContext {
            rsp: rsp_val,
        };

        Box::new(Self {
            id,
            name,
            state: TaskState::Ready,
            context,
            fxsave: FxsaveArea::default(),
            guard_page_virt,
            stack_top_virt,
            stack_frames: frames,
            fallback_stack,
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
            guard_page_virt: 0,
            stack_top_virt: 0,
            stack_frames: Vec::new(),
            fallback_stack: Vec::new(),
            quantum_remaining: 10,
            ticks_total: 0,
        })
    }
}
