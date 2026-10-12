//! Temporizador de Intervalo Programable 8254 (PIT)
//!
//! Genera interrupciones periódicas de hardware en IRQ 0 (Vector 32)
//! para medición de tiempo, latencia, telemetría y preempción de tareas de agentes.

use core::sync::atomic::{AtomicU64, Ordering};
use super::outb;

const PIT_CHANNEL_0_DATA: u16 = 0x40;
const PIT_COMMAND: u16 = 0x43;
const PIT_BASE_FREQUENCY_HZ: u32 = 1_193_182;

/// Contador de ticks acumulados del sistema desde el arranque
pub static SYSTEM_TICKS: AtomicU64 = AtomicU64::new(0);

/// Frecuencia objetivo configurada en Hertz (por defecto 100 Hz = tick cada 10ms)
static mut TARGET_HZ: u32 = 100;

/// Inicializa el temporizador PIT a la frecuencia deseada en Hertz
pub unsafe fn init(target_hz: u32) {
    TARGET_HZ = target_hz;
    let divisor = (PIT_BASE_FREQUENCY_HZ / target_hz) as u16;

    // Canal 0, acceso LSB seguido de MSB, Modo 3 (Square Wave Generator), formato binario (0x36)
    outb(PIT_COMMAND, 0x36);

    // Enviar divisor LSB
    outb(PIT_CHANNEL_0_DATA, (divisor & 0xFF) as u8);
    // Enviar divisor MSB
    outb(PIT_CHANNEL_0_DATA, ((divisor >> 8) & 0xFF) as u8);
}

/// Manejador invocado en cada interrupción de temporizador de hardware (IRQ 0 / Vector 32)
#[inline]
pub fn on_timer_tick() {
    SYSTEM_TICKS.fetch_add(1, Ordering::Relaxed);
}

/// Retorna la cantidad total de ticks acumulados
pub fn ticks() -> u64 {
    SYSTEM_TICKS.load(Ordering::Relaxed)
}

/// Retorna el tiempo de actividad (uptime) en milisegundos
pub fn uptime_ms() -> u64 {
    let t = ticks();
    let hz = unsafe { TARGET_HZ as u64 };
    if hz > 0 {
        (t * 1000) / hz
    } else {
        0
    }
}
