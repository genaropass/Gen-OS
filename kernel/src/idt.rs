//! Interrupt Descriptor Table (IDT) y Manejo de Excepciones para x86-64
//! Implementa los 32 vectores de excepción de arquitectura con volcado completo de registros,
//! `cld` según la ABI SysV x86-64, soporte de IST para Double Fault y despacho de interrupciones de hardware/syscalls.

use core::arch::global_asm;
use core::mem::size_of;
use crate::println;
use crate::gdt::KERNEL_CODE_SEL;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct IdtEntry {
    offset_low: u16,
    selector: u16,
    ist: u8,
    type_attr: u8,
    offset_mid: u16,
    offset_high: u32,
    zero: u32,
}

impl IdtEntry {
    pub const fn missing() -> Self {
        Self {
            offset_low: 0,
            selector: 0,
            ist: 0,
            type_attr: 0,
            offset_mid: 0,
            offset_high: 0,
            zero: 0,
        }
    }

    pub fn set_handler(&mut self, handler: usize, ist: u8) {
        self.offset_low = handler as u16;
        self.selector = KERNEL_CODE_SEL;
        self.ist = ist;
        self.type_attr = 0x8E; // Present, Ring 0, 64-bit Interrupt Gate
        self.offset_mid = (handler >> 16) as u16;
        self.offset_high = (handler >> 32) as u32;
        self.zero = 0;
    }
}

#[repr(C, packed)]
struct IdtDescriptor {
    limit: u16,
    base: u64,
}

static mut IDT: [IdtEntry; 256] = [IdtEntry::missing(); 256];

/// Estructura completa de registros capturados en la pila durante una interrupción
#[repr(C)]
#[derive(Debug)]
pub struct InterruptStackFrame {
    // Registros de propósito general guardados por PUSH_REGS (orden inverso a la pila)
    pub rax: u64,
    pub rbx: u64,
    pub rcx: u64,
    pub rdx: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rbp: u64,
    pub r8: u64,
    pub r9: u64,
    pub r10: u64,
    pub r11: u64,
    pub r12: u64,
    pub r13: u64,
    pub r14: u64,
    pub r15: u64,
    // Vector y código de error apilados por el stub
    pub vector: u64,
    pub error_code: u64,
    // Apilados automáticamente por el hardware CPU en la interrupción:
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

const EXCEPTION_NAMES: [&str; 32] = [
    "Divide-by-zero (#DE)",
    "Debug (#DB)",
    "Non-Maskable Interrupt (NMI)",
    "Breakpoint (#BP)",
    "Overflow (#OF)",
    "Bound Range Exceeded (#BR)",
    "Invalid Opcode (#UD)",
    "Device Not Available (#NM)",
    "Double Fault (#DF)",
    "Coprocessor Segment Overrun",
    "Invalid TSS (#TS)",
    "Segment Not Present (#NP)",
    "Stack-Segment Fault (#SS)",
    "General Protection Fault (#GP)",
    "Page Fault (#PF)",
    "Reserved (15)",
    "x87 Floating-Point Exception (#MF)",
    "Alignment Check (#AC)",
    "Machine Check (#MC)",
    "SIMD Floating-Point Exception (#XM)",
    "Virtualization Exception (#VE)",
    "Control Protection Exception (#CP)",
    "Reserved (22)",
    "Reserved (23)",
    "Reserved (24)",
    "Reserved (25)",
    "Reserved (26)",
    "Reserved (27)",
    "Hypervisor Injection Exception (#HV)",
    "VMM Communication Exception (#VC)",
    "Security Exception (#SX)",
    "Reserved (31)",
];

#[no_mangle]
pub extern "C" fn rust_interrupt_handler(frame: &mut InterruptStackFrame) {
    let vec = frame.vector;

    if vec < 32 {
        // Excepciones de la CPU
        if vec == 3 {
            // #BP Breakpoint (usado por autotest de arranque)
            println!("[CPU TRAP] Breakpoint (#BP) exitoso en RIP: 0x{:016x}", frame.rip);
            return;
        }

        let name = EXCEPTION_NAMES[vec as usize];
        println!("\n\x1b[1;31m========================================================================");
        println!("   [CPU EXCEPTION] {} (Vector {})", name, vec);
        println!("========================================================================\x1b[0m");
        println!("  RIP:    0x{:016x}   CS:  0x{:04x}   RFLAGS: 0x{:016x}", frame.rip, frame.cs, frame.rflags);
        println!("  RSP:    0x{:016x}   SS:  0x{:04x}   ERROR:  0x{:016x}", frame.rsp, frame.ss, frame.error_code);
        println!("  RAX:    0x{:016x}   RBX: 0x{:016x}   RCX:    0x{:016x}", frame.rax, frame.rbx, frame.rcx);
        println!("  RDX:    0x{:016x}   RSI: 0x{:016x}   RDI:    0x{:016x}", frame.rdx, frame.rsi, frame.rdi);
        println!("  RBP:    0x{:016x}   R8:  0x{:016x}   R9:     0x{:016x}", frame.rbp, frame.r8, frame.r9);
        println!("  R10:    0x{:016x}   R11: 0x{:016x}   R12:    0x{:016x}", frame.r10, frame.r11, frame.r12);
        println!("  R13:    0x{:016x}   R14: 0x{:016x}   R15:    0x{:016x}", frame.r13, frame.r14, frame.r15);

        if vec == 14 {
            let cr2: u64;
            unsafe {
                core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
            }
            println!("  CR2:    0x{:016x} (Dirección virtual que provocó el fallo de página)", cr2);
        }

        println!("\x1b[1;31m========================================================================\x1b[0m");
        crate::arch::hlt_loop();
    }

    match vec {
        32 => {
            // IRQ 0 - Hardware Timer PIT (100 Hz)
            crate::arch::pit::on_timer_tick();
            unsafe {
                crate::arch::pic::send_eoi(0);
            }
            // Verificar si el quantum de la tarea actual expiró y realizar preempción
            crate::sched::check_preempt();
        }
        36 => {
            // IRQ 4 - UART COM1 Serial RX
            crate::serial::on_serial_rx();
            unsafe {
                crate::arch::pic::send_eoi(4);
            }
        }
        128 => {
            // Syscall delegada vía software int 0x80
            let ret = crate::syscall::dispatch_syscall(
                frame.rax,
                frame.rdi,
                frame.rsi,
                frame.rdx,
                frame.r10,
            );
            frame.rax = ret as u64;
        }
        _ => {
            println!("[INTERRUPCION ESPURIA] Vector {} en RIP: 0x{:016x}", vec, frame.rip);
        }
    }
}

// Declaraciones de trampolines de ensamblador para los 32 vectores de excepción + IRQs
extern "C" {
    fn isr_0();  fn isr_1();  fn isr_2();  fn isr_3();
    fn isr_4();  fn isr_5();  fn isr_6();  fn isr_7();
    fn isr_8();  fn isr_9();  fn isr_10(); fn isr_11();
    fn isr_12(); fn isr_13(); fn isr_14(); fn isr_15();
    fn isr_16(); fn isr_17(); fn isr_18(); fn isr_19();
    fn isr_20(); fn isr_21(); fn isr_22(); fn isr_23();
    fn isr_24(); fn isr_25(); fn isr_26(); fn isr_27();
    fn isr_28(); fn isr_29(); fn isr_30(); fn isr_31();
    fn isr_32(); fn isr_36(); fn isr_128();
}

global_asm!(
    r#"
    .macro PUSH_REGS
        push r15
        push r14
        push r13
        push r12
        push r11
        push r10
        push r9
        push r8
        push rbp
        push rdi
        push rsi
        push rdx
        push rcx
        push rbx
        push rax
    .endm

    .macro POP_REGS
        pop rax
        pop rbx
        pop rcx
        pop rdx
        pop rsi
        pop rdi
        pop rbp
        pop r8
        pop r9
        pop r10
        pop r11
        pop r12
        pop r13
        pop r14
        pop r15
    .endm

    .global isr_common
    isr_common:
        PUSH_REGS
        cld                 /* Requisito de SysV ABI x86-64: DF=0 al invocar Rust */
        mov rdi, rsp        /* 1er argumento para rust_interrupt_handler */
        call rust_interrupt_handler
        POP_REGS
        add rsp, 16         /* Descartar vector y error_code */
        iretq

    /* Macro para ISRs sin error_code generado por hardware */
    .macro ISR_NO_ERR vec
        .global isr_\vec
        isr_\vec:
            push 0          /* Error code ficticio */
            push \vec       /* Vector de interrupción */
            jmp isr_common
    .endm

    /* Macro para ISRs con error_code generado por hardware */
    .macro ISR_ERR vec
        .global isr_\vec
        isr_\vec:
            push \vec       /* Vector de interrupción */
            jmp isr_common
    .endm

    /* 32 Excepciones de la Arquitectura x86-64 */
    ISR_NO_ERR 0
    ISR_NO_ERR 1
    ISR_NO_ERR 2
    ISR_NO_ERR 3
    ISR_NO_ERR 4
    ISR_NO_ERR 5
    ISR_NO_ERR 6
    ISR_NO_ERR 7
    ISR_ERR    8
    ISR_NO_ERR 9
    ISR_ERR    10
    ISR_ERR    11
    ISR_ERR    12
    ISR_ERR    13
    ISR_ERR    14
    ISR_NO_ERR 15
    ISR_NO_ERR 16
    ISR_ERR    17
    ISR_NO_ERR 18
    ISR_NO_ERR 19
    ISR_NO_ERR 20
    ISR_ERR    21
    ISR_NO_ERR 22
    ISR_NO_ERR 23
    ISR_NO_ERR 24
    ISR_NO_ERR 25
    ISR_NO_ERR 26
    ISR_NO_ERR 27
    ISR_NO_ERR 28
    ISR_ERR    29
    ISR_ERR    30
    ISR_NO_ERR 31

    /* IRQs y Software Syscall */
    ISR_NO_ERR 32
    ISR_NO_ERR 36
    ISR_NO_ERR 128
    "#
);

pub fn init() {
    unsafe {
        // Inicializar los 32 vectores de excepción
        IDT[0].set_handler(isr_0 as *const () as usize, 0);
        IDT[1].set_handler(isr_1 as *const () as usize, 0);
        IDT[2].set_handler(isr_2 as *const () as usize, 0);
        IDT[3].set_handler(isr_3 as *const () as usize, 0);
        IDT[4].set_handler(isr_4 as *const () as usize, 0);
        IDT[5].set_handler(isr_5 as *const () as usize, 0);
        IDT[6].set_handler(isr_6 as *const () as usize, 0);
        IDT[7].set_handler(isr_7 as *const () as usize, 0);
        // Double Fault usa IST 1 para stack dedicado inmune a desbordamientos
        IDT[8].set_handler(isr_8 as *const () as usize, 1);
        IDT[9].set_handler(isr_9 as *const () as usize, 0);
        IDT[10].set_handler(isr_10 as *const () as usize, 0);
        IDT[11].set_handler(isr_11 as *const () as usize, 0);
        IDT[12].set_handler(isr_12 as *const () as usize, 0);
        IDT[13].set_handler(isr_13 as *const () as usize, 0);
        IDT[14].set_handler(isr_14 as *const () as usize, 0);
        IDT[15].set_handler(isr_15 as *const () as usize, 0);
        IDT[16].set_handler(isr_16 as *const () as usize, 0);
        IDT[17].set_handler(isr_17 as *const () as usize, 0);
        IDT[18].set_handler(isr_18 as *const () as usize, 0);
        IDT[19].set_handler(isr_19 as *const () as usize, 0);
        IDT[20].set_handler(isr_20 as *const () as usize, 0);
        IDT[21].set_handler(isr_21 as *const () as usize, 0);
        IDT[22].set_handler(isr_22 as *const () as usize, 0);
        IDT[23].set_handler(isr_23 as *const () as usize, 0);
        IDT[24].set_handler(isr_24 as *const () as usize, 0);
        IDT[25].set_handler(isr_25 as *const () as usize, 0);
        IDT[26].set_handler(isr_26 as *const () as usize, 0);
        IDT[27].set_handler(isr_27 as *const () as usize, 0);
        IDT[28].set_handler(isr_28 as *const () as usize, 0);
        IDT[29].set_handler(isr_29 as *const () as usize, 0);
        IDT[30].set_handler(isr_30 as *const () as usize, 0);
        IDT[31].set_handler(isr_31 as *const () as usize, 0);

        // Dispositivos de hardware y Syscalls
        IDT[32].set_handler(isr_32 as *const () as usize, 0);
        IDT[36].set_handler(isr_36 as *const () as usize, 0);
        IDT[128].set_handler(isr_128 as *const () as usize, 0);

        let descriptor = IdtDescriptor {
            limit: (size_of::<[IdtEntry; 256]>() - 1) as u16,
            base: (&raw const IDT) as u64,
        };

        core::arch::asm!("lidt [{}]", in(reg) &descriptor, options(readonly, nostack, preserves_flags));
    }
}
