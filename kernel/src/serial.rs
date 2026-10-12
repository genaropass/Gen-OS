//! Driver para el puerto serie UART 16550 (COM1 en 0x3F8)
//! Permite diagnósticos en texto plano capturables por QEMU vía `-serial stdio`
//! y lectura de entrada para el Shell interactivo de Ring 0.

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
            // Desactivar interrupciones durante configuración
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
            // Activar RTS, DTR y línea de salida auxiliar OUT2 (habilita IRQs)
            outb(self.port + 4, 0x0B);
            // Habilitar interrupciones de datos recibidos (IER bit 0)
            outb(self.port + 1, 0x01);
        }
    }

    /// Comprueba si el buffer de transmisión está vacío y listo para enviar
    fn is_transmit_empty(&self) -> bool {
        unsafe { (inb(self.port + 5) & 0x20) != 0 }
    }

    /// Comprueba si hay datos listos en el buffer de recepción (LSR bit 0)
    pub fn is_data_ready(&self) -> bool {
        unsafe { (inb(self.port + 5) & 0x01) != 0 }
    }

    /// Lee un byte si está disponible en el buffer
    pub fn read_byte(&self) -> Option<u8> {
        if self.is_data_ready() {
            Some(unsafe { inb(self.port) })
        } else {
            None
        }
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

use crate::sync::IrqSpinLock;

const RX_BUFFER_CAPACITY: usize = 256;

pub struct RxRingBuffer {
    buffer: [u8; RX_BUFFER_CAPACITY],
    head: usize,
    tail: usize,
}

impl RxRingBuffer {
    pub const fn new() -> Self {
        Self {
            buffer: [0; RX_BUFFER_CAPACITY],
            head: 0,
            tail: 0,
        }
    }

    pub fn push(&mut self, byte: u8) -> bool {
        let next_head = (self.head + 1) % RX_BUFFER_CAPACITY;
        if next_head == self.tail {
            return false; // Buffer lleno, descartar para prevenir overflow
        }
        self.buffer[self.head] = byte;
        self.head = next_head;
        true
    }

    pub fn pop(&mut self) -> Option<u8> {
        if self.head == self.tail {
            return None;
        }
        let byte = self.buffer[self.tail];
        self.tail = (self.tail + 1) % RX_BUFFER_CAPACITY;
        Some(byte)
    }

    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }
}

static RX_QUEUE: IrqSpinLock<RxRingBuffer> = IrqSpinLock::new(RxRingBuffer::new());

/// Invocado por el manejador de interrupciones de IDT (IRQ 4 / Vector 36).
/// Exclusivamente encola bytes en el ring buffer de memoria sin I/O pesada (corrige H3).
pub fn on_serial_rx() {
    if let Some(mut queue) = RX_QUEUE.try_lock() {
        while let Some(b) = SERIAL1.read_byte() {
            let _ = queue.push(b);
        }
    }
}

/// Extrae el siguiente byte recibido del ring buffer
pub fn pop_rx_byte() -> Option<u8> {
    RX_QUEUE.lock().pop()
}

/// Sondeo activo de entrada y despacho seguro al shell en el contexto de tarea / bucle principal
pub fn poll_input() {
    if let Some(mut queue) = RX_QUEUE.try_lock() {
        while let Some(b) = SERIAL1.read_byte() {
            let _ = queue.push(b);
        }
    }
    while let Some(b) = pop_rx_byte() {
        crate::shell::handle_char(b);
    }
}

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
