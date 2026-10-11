//! Driver para el puerto serie UART 16550 (COM1 en 0x3F8)
//! Permite diagnósticos en texto plano capturables por QEMU vía `-serial stdio`

use core::fmt;
use crate::arch::{inb, outb};

const COM1: u16 = 0x3F8;

pub struct SerialPort {
    port: u16,
}

impl SerialPort {
    pub const fn new(port: u16) -> Self {
        Self { port }
    }

    /// Inicializa el controlador UART 16550
    pub fn init(&self) {
        unsafe {
            // Desactivar interrupciones
            outb(self.port + 1, 0x00);
            // Habilitar DLAB (divisor baud rate)
            outb(self.port + 3, 0x80);
            // Configurar divisor para 38400 baud (divisor = 3)
            outb(self.port + 0, 0x03);
            outb(self.port + 1, 0x00);
            // 8 bits, sin paridad, 1 stop bit (8N1)
            outb(self.port + 3, 0x03);
            // Activar buffers FIFO, limpiar y fijar umbral en 14 bytes
            outb(self.port + 2, 0xC7);
            // Activar RTS, DTR y línea de salida auxiliar
            outb(self.port + 4, 0x0B);
        }
    }

    /// Comprueba si el buffer de transmisión está vacío y listo para enviar
    fn is_transmit_empty(&self) -> bool {
        unsafe { (inb(self.port + 5) & 0x20) != 0 }
    }

    /// Envía un byte individual por el puerto serie
    pub fn write_byte(&self, byte: u8) {
        while !self.is_transmit_empty() {
            // Espera activa (en emulación QEMU es prácticamente instantáneo)
        }
        unsafe {
            outb(self.port, byte);
        }
    }

    /// Envía un string de bytes
    pub fn write_str(&self, s: &str) {
        for byte in s.bytes() {
            if byte == b'\n' {
                self.write_byte(b'\r');
            }
            self.write_byte(byte);
        }
    }
}

impl fmt::Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        SerialPort::write_str(self, s);
        Ok(())
    }
}

pub static SERIAL1: SerialPort = SerialPort::new(COM1);

#[doc(hidden)]
pub fn _print(args: fmt::Arguments) {
    use core::fmt::Write;
    let mut port = SerialPort::new(COM1);
    port.write_fmt(args).unwrap();
}

/// Macro print para diagnósticos del kernel
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => ($crate::serial::_print(format_args!($($arg)*)));
}

/// Macro println para diagnósticos del kernel
#[macro_export]
macro_rules! println {
    () => ($crate::print!("\n"));
    ($($arg:tt)*) => ($crate::print!("{}\n", format_args!($($arg)*)));
}
