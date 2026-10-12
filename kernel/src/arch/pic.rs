//! Controlador Programable de Interrupciones 8259 (Dual PIC)
//!
//! Remapea los IRQs de hardware 0..15 a los vectores de interrupción 32..47 de la IDT,
//! evitando colisiones con las excepciones de arquitectura de la CPU (vectores 0..31).

use super::{outb, inb, io_wait};

const PIC1_COMMAND: u16 = 0x20;
const PIC1_DATA: u16 = 0x21;
const PIC2_COMMAND: u16 = 0xA0;
const PIC2_DATA: u16 = 0xA1;

const PIC_EOI: u8 = 0x20;

const ICW1_INIT: u8 = 0x10;
const ICW1_ICW4: u8 = 0x01;
const ICW4_8086: u8 = 0x01;

/// Remapea el controlador 8259 PIC a los vectores especificados.
/// offset1: offset para el Master PIC (ej. 32 para IRQ 0..7)
/// offset2: offset para el Slave PIC (ej. 40 para IRQ 8..15)
pub unsafe fn remap(offset1: u8, offset2: u8) {
    let mask1 = inb(PIC1_DATA);
    let mask2 = inb(PIC2_DATA);

    // Iniciar secuencia de inicializacion (modo cascada)
    outb(PIC1_COMMAND, ICW1_INIT | ICW1_ICW4);
    io_wait();
    outb(PIC2_COMMAND, ICW1_INIT | ICW1_ICW4);
    io_wait();

    // ICW2: Vector offsets
    outb(PIC1_DATA, offset1);
    io_wait();
    outb(PIC2_DATA, offset2);
    io_wait();

    // ICW3: Master tiene Slave en IRQ2 (0000 0100)
    outb(PIC1_DATA, 4);
    io_wait();
    // Decirle al Slave PIC su cascada (0000 0010)
    outb(PIC2_DATA, 2);
    io_wait();

    // ICW4: Modo 8086/88
    outb(PIC1_DATA, ICW4_8086);
    io_wait();
    outb(PIC2_DATA, ICW4_8086);
    io_wait();

    // Restaurar mascaras guardadas
    outb(PIC1_DATA, mask1);
    outb(PIC2_DATA, mask2);
}

/// Envia senal de fin de interrupcion (EOI) al controlador PIC
pub unsafe fn send_eoi(irq: u8) {
    if irq >= 8 {
        outb(PIC2_COMMAND, PIC_EOI);
    }
    outb(PIC1_COMMAND, PIC_EOI);
}

/// Establece la mascara de interrupciones para una linea IRQ (0..15)
pub unsafe fn set_mask(irq: u8) {
    let port = if irq < 8 { PIC1_DATA } else { PIC2_DATA };
    let irq_line = if irq < 8 { irq } else { irq - 8 };
    let value = inb(port) | (1 << irq_line);
    outb(port, value);
}

/// Deshabilita la mascara (permite la interrupcion) para una linea IRQ (0..15)
pub unsafe fn clear_mask(irq: u8) {
    let port = if irq < 8 { PIC1_DATA } else { PIC2_DATA };
    let irq_line = if irq < 8 { irq } else { irq - 8 };
    let value = inb(port) & !(1 << irq_line);
    outb(port, value);
}

/// Enmascara todas las interrupciones del PIC
pub unsafe fn disable_all() {
    outb(PIC1_DATA, 0xFF);
    outb(PIC2_DATA, 0xFF);
}
