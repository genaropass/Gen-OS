//! Operaciones de arquitectura x86-64 a bajo nivel (I/O ports, PIC, PIT y control de CPU)

pub mod pic;
pub mod pit;

use core::arch::asm;

/// Escribe un byte en un puerto de E/S de la CPU
#[inline]
pub unsafe fn outb(port: u16, val: u8) {
    asm!(
        "out dx, al",
        in("dx") port,
        in("al") val,
        options(nomem, nostack, preserves_flags)
    );
}

/// Lee un byte desde un puerto de E/S de la CPU
#[inline]
pub unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    asm!(
        "in al, dx",
        in("dx") port,
        out("al") val,
        options(nomem, nostack, preserves_flags)
    );
    val
}

/// Espera un ciclo de bus de E/S escribiendo a un puerto de diagnósticos libre
#[inline]
pub unsafe fn io_wait() {
    outb(0x80, 0);
}

/// Habilita las interrupciones de hardware en la CPU (sti)
#[inline]
pub unsafe fn sti() {
    asm!("sti", options(nomem, nostack, preserves_flags));
}

/// Deshabilita las interrupciones de hardware en la CPU (cli)
#[inline]
pub unsafe fn cli() {
    asm!("cli", options(nomem, nostack, preserves_flags));
}

/// Suspende el procesador hasta la próxima interrupción
#[inline]
pub fn hlt() {
    unsafe {
        asm!("hlt", options(nomem, nostack, preserves_flags));
    }
}

/// Bucle infinito de suspensión segura
pub fn hlt_loop() -> ! {
    loop {
        hlt();
    }
}

/// Lee el contador de sellos de tiempo de la CPU (Time Stamp Counter - TSC)
#[inline]
pub fn rdtsc() -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!("rdtsc", out("eax") low, out("edx") high, options(nomem, nostack, preserves_flags));
    }
    ((high as u64) << 32) | (low as u64)
}
