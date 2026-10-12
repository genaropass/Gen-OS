//! Control de Características de Seguridad de CPU x86-64 (CR0, CR4, EFER, CPUID)
//! Habilita protecciones avanzadas contra ataques de Ring 3 y corrupción de memoria:
//! - `CR0.WP` (Write Protect): El kernel en Ring 0 no puede escribir en páginas Read-Only.
//! - `EFER.NXE` (No-Execute Enable): Activa el bit 63 (NX) para prevenir ejecución de código en datos.
//! - `CR4.SMEP` (Supervisor Mode Execution Prevention): El kernel no puede ejecutar código de usuario.
//! - `CR4.SMAP` (Supervisor Mode Access Prevention): El kernel no puede leer/escribir datos de usuario sin STAC/CLAC.
//! - `CR4.UMIP` (User Mode Instruction Prevention): Ring 3 no puede ejecutar SGDT, SIDT, SLDT, etc.

use core::arch::asm;
use crate::println;

const IA32_EFER: u32 = 0xC0000080;

/// Ejecuta la instrucción CPUID de forma segura preservando registros
pub fn cpuid(leaf: u32, sub_leaf: u32) -> (u32, u32, u32, u32) {
    let eax: u32;
    let ebx: u32;
    let ecx: u32;
    let edx: u32;
    unsafe {
        asm!(
            "mov r8, rbx",
            "cpuid",
            "xchg rbx, r8",
            inout("eax") leaf => eax,
            out("r8") ebx,
            inout("ecx") sub_leaf => ecx,
            out("edx") edx,
            options(nomem, nostack, preserves_flags)
        );
    }
    (eax, ebx, ecx, edx)
}

/// Lee el registro EFER (Extended Feature Enable Register) mediante RDMSR
pub fn read_efer() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!("rdmsr", in("ecx") IA32_EFER, out("eax") low, out("edx") high, options(nomem, nostack, preserves_flags));
    }
    ((high as u64) << 32) | (low as u64)
}

/// Escribe en el registro EFER mediante WRMSR
pub fn write_efer(val: u64) {
    let low = (val & 0xFFFF_FFFF) as u32;
    let high = (val >> 32) as u32;
    unsafe {
        asm!("wrmsr", in("ecx") IA32_EFER, in("eax") low, in("edx") high, options(nomem, nostack, preserves_flags));
    }
}

/// Lee el registro de control CR0
pub fn read_cr0() -> u64 {
    let val: u64;
    unsafe {
        asm!("mov {}, cr0", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Escribe en el registro de control CR0
pub fn write_cr0(val: u64) {
    unsafe {
        asm!("mov cr0, {}", in(reg) val, options(nomem, nostack, preserves_flags));
    }
}

/// Lee el registro de control CR4
pub fn read_cr4() -> u64 {
    let val: u64;
    unsafe {
        asm!("mov {}, cr4", out(reg) val, options(nomem, nostack, preserves_flags));
    }
    val
}

/// Escribe en el registro de control CR4
pub fn write_cr4(val: u64) {
    unsafe {
        asm!("mov cr4, {}", in(reg) val, options(nomem, nostack, preserves_flags));
    }
}

/// Permite el acceso temporal a memoria de usuario en Ring 0 (Set AC flag)
#[inline]
pub fn stac() {
    unsafe {
        asm!("stac", options(nomem, nostack, preserves_flags));
    }
}

/// Bloquea el acceso a memoria de usuario en Ring 0 (Clear AC flag)
#[inline]
pub fn clac() {
    unsafe {
        asm!("clac", options(nomem, nostack, preserves_flags));
    }
}

/// Inicializa y activa todas las características de seguridad soportadas por la CPU
pub fn init_cpu_security() {
    println!("[AgentOS::CPU] Evaluando caracteristicas de hardware de seguridad (CPUID)...");

    // 1. Activar CR0.WP (Write Protect - bit 16)
    let cr0 = read_cr0();
    let wp_bit = 1 << 16;
    if (cr0 & wp_bit) == 0 {
        write_cr0(cr0 | wp_bit);
        println!("  * CR0.WP (Write Protect) -> \x1b[1;32mHABILITADO\x1b[0m");
    } else {
        println!("  * CR0.WP (Write Protect) -> \x1b[1;32mYA ACTIVO\x1b[0m");
    }

    // 2. Comprobar y activar EFER.NXE (No-Execute Enable - bit 11)
    let (_, _, _, ext_edx) = cpuid(0x80000001, 0);
    let nx_supported = (ext_edx & (1 << 20)) != 0;
    if nx_supported {
        let efer = read_efer();
        let nxe_bit = 1 << 11;
        if (efer & nxe_bit) == 0 {
            write_efer(efer | nxe_bit);
            println!("  * EFER.NXE (No-Execute Bit) -> \x1b[1;32mHABILITADO\x1b[0m");
        } else {
            println!("  * EFER.NXE (No-Execute Bit) -> \x1b[1;32mYA ACTIVO\x1b[0m");
        }
    } else {
        println!("  * EFER.NXE -> \x1b[1;33mNO SOPORTADO POR CPU\x1b[0m");
    }

    // 3. Comprobar SMEP, SMAP y UMIP en CPUID leaf 7
    let (_, feat_ebx, feat_ecx, _) = cpuid(7, 0);
    let smep_supported = (feat_ebx & (1 << 7)) != 0;
    let smap_supported = (feat_ebx & (1 << 20)) != 0;
    let umip_supported = (feat_ecx & (1 << 2)) != 0;

    let mut cr4 = read_cr4();

    if smep_supported {
        cr4 |= 1 << 20; // CR4.SMEP bit 20
        println!("  * CR4.SMEP (Supervisor Mode Execution Prevention) -> \x1b[1;32mHABILITADO\x1b[0m");
    }

    if smap_supported {
        cr4 |= 1 << 21; // CR4.SMAP bit 21
        println!("  * CR4.SMAP (Supervisor Mode Access Prevention) -> \x1b[1;32mHABILITADO\x1b[0m");
    }

    if umip_supported {
        cr4 |= 1 << 11; // CR4.UMIP bit 11
        println!("  * CR4.UMIP (User Mode Instruction Prevention) -> \x1b[1;32mHABILITADO\x1b[0m");
    }

    write_cr4(cr4);
}
