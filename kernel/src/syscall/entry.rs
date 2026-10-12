//! Punto de entrada de llamadas al sistema mediante instrucciones de hardware SYSCALL / SYSRET
//! Configura los MSRs de x86-64 (STAR, LSTAR, FMASK, EFER.SCE) y el trampoline en ensamblador.

use core::arch::global_asm;
use crate::println;
use crate::gdt::{KERNEL_CODE_SEL, USER_DATA_SEL};

const IA32_STAR: u32 = 0xC0000081;
const IA32_LSTAR: u32 = 0xC0000082;
const IA32_FMASK: u32 = 0xC0000084;

#[repr(C, align(16))]
pub struct SyscallStack([u8; 16384]);
#[no_mangle]
#[used]
pub static mut SYSCALL_KERNEL_STACK: SyscallStack = SyscallStack([0; 16384]);

extern "C" {
    fn syscall_entry();
}

#[no_mangle]
pub extern "C" fn rust_syscall_entry_point(
    sys_num: u64,
    arg1: u64,
    arg2: u64,
    arg3: u64,
    arg4: u64,
) -> i64 {
    crate::syscall::dispatch_syscall(sys_num, arg1, arg2, arg3, arg4)
}

global_asm!(
    r#"
    .global syscall_entry
    syscall_entry:
        /* En la entrada de syscall:
           RCX = user RIP guardado por CPU
           R11 = user RFLAGS guardados por CPU
           RAX = syscall number
           RDI = arg1, RSI = arg2, RDX = arg3, R10 = arg4, R8 = arg5, R9 = arg6
           RSP = user RSP
        */
        mov [rip + USER_RSP_SAVE], rsp
        lea rsp, [rip + SYSCALL_KERNEL_STACK + 16384]

        push [rip + USER_RSP_SAVE]  /* Guardar user RSP */
        push r11                    /* Guardar user RFLAGS */
        push rcx                    /* Guardar user RIP */
        push rbp
        push rbx
        push r12
        push r13
        push r14
        push r15

        cld                         /* SysV ABI: DF = 0 */

        /* Alinear argumentos para llamar rust_syscall_entry_point:
           rdi = sys_num (rax)
           rsi = arg1 (rdi)
           rdx = arg2 (rsi)
           rcx = arg3 (rdx)
           r8  = arg4 (r10)
        */
        mov r8, r10
        mov rcx, rdx
        mov rdx, rsi
        mov rsi, rdi
        mov rdi, rax

        call rust_syscall_entry_point

        /* RAX contiene el valor de retorno de la llamada al sistema */
        pop r15
        pop r14
        pop r13
        pop r12
        pop rbx
        pop rbp
        pop rcx                     /* Restaurar user RIP en RCX */
        pop r11                     /* Restaurar user RFLAGS en R11 */
        pop rsp                     /* Restaurar user RSP */

        sysretq

    .section .bss
    .align 8
    USER_RSP_SAVE:
        .quad 0
    "#
);

pub fn init() {
    unsafe {
        // 1. Habilitar SCE (System Call Extensions - bit 0) en EFER
        let efer = crate::arch::cpu::read_efer();
        crate::arch::cpu::write_efer(efer | 1);

        // 2. Configurar STAR MSR:
        // Bits 47:32 = Kernel CS (0x08)
        // Bits 63:48 = User CS/SS base (0x18 -> SS=0x1B, CS=0x23)
        let star_val = ((KERNEL_CODE_SEL as u64) << 32) | (((USER_DATA_SEL & !3) as u64) << 48);
        let star_low = star_val as u32;
        let star_high = (star_val >> 32) as u32;
        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_STAR,
            in("eax") star_low,
            in("edx") star_high,
            options(nomem, nostack, preserves_flags)
        );

        // 3. Configurar LSTAR MSR con la dirección de syscall_entry
        let lstar_val = syscall_entry as *const () as usize as u64;
        let lstar_low = lstar_val as u32;
        let lstar_high = (lstar_val >> 32) as u32;
        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_LSTAR,
            in("eax") lstar_low,
            in("edx") lstar_high,
            options(nomem, nostack, preserves_flags)
        );

        // 4. Configurar FMASK MSR para limpiar flags críticas al entrar a Ring 0:
        // Bit 9 (IF), Bit 10 (DF), Bit 8 (TF)
        let fmask_val = (1u32 << 9) | (1u32 << 10) | (1u32 << 8);
        core::arch::asm!(
            "wrmsr",
            in("ecx") IA32_FMASK,
            in("eax") fmask_val,
            in("edx") 0u32,
            options(nomem, nostack, preserves_flags)
        );
    }

    println!("[GenOS::Syscall] Interfaz hardware SYSCALL / SYSRET configurada en MSRs (LSTAR/STAR)");
}
