//! Operaciones de arquitectura x86-64 a bajo nivel (I/O ports y control de CPU)

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
