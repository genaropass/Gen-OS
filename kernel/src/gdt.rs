//! Global Descriptor Table (GDT) y Task State Segment (TSS) para x86-64

use core::arch::asm;
use core::mem::size_of;

/// Selector del segmento de código del kernel
pub const KERNEL_CODE_SEL: u16 = 0x08;
/// Selector del segmento de datos del kernel
pub const KERNEL_DATA_SEL: u16 = 0x10;
/// Selector de la TSS
pub const TSS_SEL: u16 = 0x18;

/// Pila dedicada para el manejador de Double Fault (evita triple fault por desbordamiento de pila)
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

// GDT con: Null (0), Kernel Code (0x08), Kernel Data (0x10), TSS (0x18, ocupa 16 bytes en x86-64)
static mut GDT: [u64; 5] = [
    0,                                      // 0x00: Null
    0x00af9a000000ffff,                     // 0x08: Kernel Code 64-bit (present, ring 0, exec/read, 64-bit)
    0x00af92000000ffff,                     // 0x10: Kernel Data 64-bit (present, ring 0, read/write)
    0,                                      // 0x18: TSS low (se rellena en tiempo de ejecución)
    0,                                      // 0x20: TSS high
];

pub fn init() {
    unsafe {
        // Configurar la pila IST[0] para Double Fault en la TSS
        let stack_end = (&raw const DOUBLE_FAULT_STACK) as *const u8 as u64 + DOUBLE_FAULT_STACK_SIZE as u64;
        TSS.ist[0] = stack_end;

        // Configurar el descriptor de la TSS en la GDT
        let tss_base = (&raw const TSS) as u64;
        let tss_limit = (size_of::<TaskStateSegment>() - 1) as u64;

        // Descriptor TSS en x86-64 ocupa dos entradas de 64 bits (16 bytes)
        let tss_low = (tss_limit & 0xffff)
            | ((tss_base & 0x00ff_ffff) << 16)
            | (0x89u64 << 40) // Tipo: 64-bit TSS Available, Present
            | ((tss_limit & 0x000f_0000) << 32)
            | ((tss_base & 0xff00_0000) << 32);

        let tss_high = tss_base >> 32;

        GDT[3] = tss_low;
        GDT[4] = tss_high;

        let descriptor = GdtDescriptor {
            limit: (size_of::<[u64; 5]>() - 1) as u16,
            base: (&raw const GDT) as u64,
        };

        // Cargar la nueva GDT
        asm!("lgdt [{}]", in(reg) &descriptor, options(readonly, nostack, preserves_flags));

        // Recargar el registro de segmento de código (CS) y los de datos (DS, SS, ES)
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
        asm!("ltr ax", in("ax") TSS_SEL, options(nostack, preserves_flags));
    }
}
