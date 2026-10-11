#![no_std]
#![no_main]

pub mod arch;
pub mod limine;
pub mod serial;
pub mod panic;
pub mod qemu_exit;

use limine::{LimineBaseRevision, LimineHhdmRequest};
use serial::SERIAL1;
#[cfg(feature = "test-exit")]
use qemu_exit::{exit_qemu, QemuExitCode};

/// Solicitud de revisión base del protocolo Limine
#[used]
#[link_section = ".requests"]
static BASE_REVISION: LimineBaseRevision = LimineBaseRevision::new(2);

/// Solicitud del mapa directo de mitad superior (HHDM)
#[used]
#[link_section = ".requests"]
static HHDM_REQUEST: LimineHhdmRequest = LimineHhdmRequest::new();

/// Punto de entrada del kernel (llamado por el bootloader Limine en modo de 64 bits)
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. Inicializar salida serie COM1
    SERIAL1.init();

    // 2. Banner de arranque del kernel
    println!("========================================================");
    println!("  [AgentOS] Kernel Causal v0.1.0 (x86-64 Bare-Metal)");
    println!("  Arranque completado exitosamente via UEFI / Limine");
    println!("========================================================");

    // 3. Comprobar si el bootloader soporta la revisión solicitada
    if BASE_REVISION.is_supported() {
        println!("[AgentOS] Protocolo Limine: Revision base soportada OK");
    } else {
        println!("[AgentOS] ADVERTENCIA: Revision del protocolo Limine no soportada");
    }

    // 4. Comprobar respuesta HHDM si está disponible
    if let Some(hhdm) = HHDM_REQUEST.get_response() {
        println!("[AgentOS] HHDM Offset detectado: 0x{:016x}", hhdm.offset);
    } else {
        println!("[AgentOS] HHDM no provisto por el bootloader (arranque temprano)");
    }

    println!("[AgentOS] Hito M1: Diagnostico serie y kernel base OK");

    // Para la prueba automatizada M1 en QEMU, reportamos éxito a isa-debug-exit
    #[cfg(feature = "test-exit")]
    {
        println!("[AgentOS] Modo de prueba automatizada activo. Saliendo...");
        exit_qemu(QemuExitCode::Success);
    }

    // Mantener la CPU en reposo si no estamos en modo de prueba automatizada
    #[cfg(not(feature = "test-exit"))]
    arch::hlt_loop();
}
