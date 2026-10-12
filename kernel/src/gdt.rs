//! Global Descriptor Table (GDT) y Task State Segment (TSS) para x86-64
//! Configura segmentos para Ring 0 (Kernel) y Ring 3 (User/Agentes con DPL=3),
//! así como la TSS con soporte de IST para Double Fault y `rsp[0]` para transición de privilegio.

use core::arch::asm;
use core::mem::size_of;

/// Selectores de segmento de Ring 0 (Kernel)
pub const KERNEL_CODE_SEL: u16 = 0x08;
pub const KERNEL_DATA_SEL: u16 = 0x10;

/// Selectores de segmento de Ring 3 (User / Agentes) con RPL = 3
pub const USER_DATA_SEL: u16 = 0x18 | 3; // 0x1B
pub const USER_CODE_SEL: u16 = 0x20 | 3; // 0x23

/// Selector de la TSS
pub const TSS_SEL: u16 = 0x28;

/// Pila dedicada para el manejador de Double Fault (IST 1)
const DOUBLE_FAULT_STACK_SIZE: usize = 4096 * 4; // 16 KiB
static mut DOUBLE_FAULT_STACK: [u8; DOUBLE_FAULT_STACK_SIZE] = [0; DOUBLE_FAULT_STACK_SIZE];

#[repr(C, packed)]
pub struct TaskStateSegment {
    reserved_1: u32,
    pub rsp: [u64; 3],
    reserved_2: u64,
    pub ist: [u64; 7],
    reserved_3: u64,
    reserved_4: u16,
    pub iopb_offset: u16,
}

static mut TSS: TaskStateSegment = TaskStateSegment {
    reserved_1: 0,
    rsp: [0; 3],
    reserved_2: 0,
    ist: [0; 7],
    reserved_3: 0,
    reserved_4: 0,
    iopb_offset: size_of::<TaskStateSegment>() as u16,
};

#[repr(C, packed)]
struct GdtDescriptor {
    limit: u16,
    base: u64,
}

// GDT de 7 entradas:
// 0x00: Null
// 0x08: Kernel Code 64-bit (Ring 0, RX)
// 0x10: Kernel Data 64-bit (Ring 0, RW)
// 0x18: User Data 64-bit   (Ring 3, RW, DPL=3)
// 0x20: User Code 64-bit   (Ring 3, RX, DPL=3)
// 0x28: TSS Low (16 bytes en x86-64)
// 0x30: TSS High
static mut GDT: [u64; 7] = [
    0,                                      // 0x00: Null
    0x00af9a000000ffff,                     // 0x08: Kernel Code 64-bit (DPL=0)
    0x00af92000000ffff,                     // 0x10: Kernel Data 64-bit (DPL=0)
    0x00aff2000000ffff,                     // 0x18: User Data 64-bit (DPL=3)
    0x00affa000000ffff,                     // 0x20: User Code 64-bit (DPL=3)
    0,                                      // 0x28: TSS low (rellenado en init)
    0,                                      // 0x30: TSS high
];

/// Actualiza la pila de Ring 0 en la TSS (`rsp[0]`) para la tarea activa
pub fn set_kernel_stack(stack_top: u64) {
    unsafe {
        TSS.rsp[0] = stack_top;
    }
}

pub fn init() {
    unsafe {
        // Configurar la pila IST[0] para Double Fault en la TSS (mapea a ist 1 en IDT)
        let stack_end = (&raw const DOUBLE_FAULT_STACK) as *const u8 as u64 + DOUBLE_FAULT_STACK_SIZE as u64;
        TSS.ist[0] = stack_end;

        // Configurar el descriptor de la TSS en la GDT
        let tss_base = (&raw const TSS) as u64;
        let tss_limit = (size_of::<TaskStateSegment>() - 1) as u64;

        let tss_low = (tss_limit & 0xffff)
            | ((tss_base & 0x00ff_ffff) << 16)
            | (0x89u64 << 40) // Tipo: 64-bit TSS Available, Present
            | ((tss_limit & 0x000f_0000) << 32)
            | ((tss_base & 0xff00_0000) << 32);

        let tss_high = tss_base >> 32;

        GDT[5] = tss_low;
        GDT[6] = tss_high;

        let descriptor = GdtDescriptor {
            limit: (size_of::<[u64; 7]>() - 1) as u16,
            base: (&raw const GDT) as u64,
        };

        // Cargar la nueva GDT
        asm!("lgdt [{}]", in(reg) &descriptor, options(readonly, nostack, preserves_flags));

        // Recargar los registros de segmento CS, DS, ES, SS
        asm!(
            "push {sel}",
            "lea {tmp}, [2f + rip]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov ax, {data_sel}",
            "mov ds, ax",
            "mov es, ax",
            "mov ss, ax",
            sel = const KERNEL_CODE_SEL,
            data_sel = const KERNEL_DATA_SEL,
            tmp = out(reg) _,
            options(nostack)
        );

        // Cargar el registro de tarea (TR) con la TSS
        asm!("ltr cx", in("cx") TSS_SEL, options(nomem, nostack, preserves_flags));
    }
}
