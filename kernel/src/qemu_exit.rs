//! Salida controlada de QEMU para pruebas automatizadas mediante el dispositivo `isa-debug-exit`
//! Puerto de E/S por defecto: 0xF4

use crate::arch::outb;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u32)]
pub enum QemuExitCode {
    Success = 0x10,
    Failed = 0x11,
}

pub fn exit_qemu(exit_code: QemuExitCode) -> ! {
    unsafe {
        // Enviar código de salida al puerto 0xf4 configurado en QEMU
        outb(0xf4, exit_code as u8);
    }
    // Si QEMU no tiene el dispositivo isa-debug-exit activo, suspender CPU
    crate::arch::hlt_loop();
}
