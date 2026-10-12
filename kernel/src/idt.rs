//! Interrupt Descriptor Table (IDT) y Manejo de Excepciones para x86-64
//! Implementado con trampolines de ensamblador estables (`global_asm!`)

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

#[repr(C)]
#[derive(Debug)]
pub struct InterruptStackFrame {
    // Registros guardados por el trampoline
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rax: u64,
    // Vector y codigo de error
    pub vector: u64,
    pub error_code: u64,
    // Pushed automaticamente por la CPU en la interrupcion:
    pub rip: u64,
    pub cs: u64,
    pub rflags: u64,
    pub rsp: u64,
    pub ss: u64,
}

#[no_mangle]
pub extern "C" fn rust_interrupt_handler(frame: &mut InterruptStackFrame) {
    match frame.vector {
        0 => {
            println!("\n[CPU EXCEPTION] Divide by Zero (#DE) en RIP: 0x{:016x}", frame.rip);
            crate::arch::hlt_loop();
        }
        3 => {
            println!("[CPU EXCEPTION] Breakpoint (#BP) en RIP: 0x{:016x}", frame.rip);
        }
        6 => {
            println!("\n[CPU EXCEPTION] Invalid Opcode (#UD) en RIP: 0x{:016x}", frame.rip);
            crate::arch::hlt_loop();
        }
        8 => {
            println!("\n[CPU EXCEPTION CRITICA] Double Fault (#DF) en RIP: 0x{:016x}", frame.rip);
            println!("Codigo de error: 0x{:x}", frame.error_code);
            crate::arch::hlt_loop();
        }
        13 => {
            println!("\n[CPU EXCEPTION] General Protection Fault (#GP) en RIP: 0x{:016x}", frame.rip);
            println!("Codigo de error: 0x{:x}", frame.error_code);
            crate::arch::hlt_loop();
        }
        14 => {
            let cr2: u64;
            unsafe {
                core::arch::asm!("mov {}, cr2", out(reg) cr2, options(nomem, nostack, preserves_flags));
            }
            println!("\n[CPU EXCEPTION] Page Fault (#PF) en direccion virtual: 0x{:016x}", cr2);
            println!("RIP causante: 0x{:016x}, Flags error: 0x{:x}", frame.rip, frame.error_code);
            crate::arch::hlt_loop();
        }
        32 => {
            crate::arch::pit::on_timer_tick();
            unsafe {
                crate::arch::pic::send_eoi(0);
            }
        }
        36 => {
            crate::serial::on_serial_rx();
            unsafe {
                crate::arch::pic::send_eoi(4);
            }
        }
        128 => {
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
            println!("[INTERRUPCION] Vector {} en RIP: 0x{:016x}", frame.vector, frame.rip);
        }
    }
}

// Declaraciones externas de los trampolines definidos en ensamblador
extern "C" {
    fn isr_0();
    fn isr_3();
    fn isr_6();
    fn isr_8();
    fn isr_13();
    fn isr_14();
    fn isr_32();
    fn isr_36();
    fn isr_128();
}

global_asm!(
    r#"
    .macro PUSH_REGS
        push rax
        push rcx
        push rdx
        push rsi
        push rdi
        push r8
        push r9
        push r10
        push r11
    .endm

    .macro POP_REGS
        pop r11
        pop r10
        pop r9
        pop r8
        pop rdi
        pop rsi
        pop rdx
        pop rcx
        pop rax
    .endm

    .global isr_common
    isr_common:
        PUSH_REGS
        mov rdi, rsp
        call rust_interrupt_handler
        POP_REGS
        add rsp, 16 /* descartar vector y error_code */
        iretq

    /* ISRs sin error_code empujado por hardware (empujamos 0 ficticio) */
    .global isr_0
    isr_0:
        push 0
        push 0
        jmp isr_common

    .global isr_3
    isr_3:
        push 0
        push 3
        jmp isr_common

    .global isr_6
    isr_6:
        push 0
        push 6
        jmp isr_common

    /* ISRs con error_code empujado por hardware */
    .global isr_8
    isr_8:
        push 8
        jmp isr_common

    .global isr_13
    isr_13:
        push 13
        jmp isr_common

    .global isr_14
    isr_14:
        push 14
        jmp isr_common

    /* IRQ 0 - Hardware PIT Timer (Vector 32) */
    .global isr_32
    isr_32:
        push 0
        push 32
        jmp isr_common

    /* IRQ 4 - COM1 Serial RX (Vector 36) */
    .global isr_36
    isr_36:
        push 0
        push 36
        jmp isr_common

    /* Syscall software interrupt (vector 128 / 0x80) */
    .global isr_128
    isr_128:
        push 0
        push 128
        jmp isr_common
    "#
);

pub fn init() {
    unsafe {
        IDT[0].set_handler(isr_0 as *const () as usize, 0);
        IDT[3].set_handler(isr_3 as *const () as usize, 0);
        IDT[6].set_handler(isr_6 as *const () as usize, 0);
        // Double Fault usa IST 1 (que mapea a ist[0] en la TSS)
        IDT[8].set_handler(isr_8 as *const () as usize, 1);
        IDT[13].set_handler(isr_13 as *const () as usize, 0);
        IDT[14].set_handler(isr_14 as *const () as usize, 0);
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
