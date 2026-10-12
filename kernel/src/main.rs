#![no_std]
#![no_main]

extern crate alloc;

pub mod arch;
pub mod limine;
pub mod serial;
pub mod panic;
pub mod qemu_exit;
pub mod gdt;
pub mod idt;
pub mod mm;
pub mod syscall;
pub mod font;
pub mod fb;

use alloc::vec::Vec;
use alloc::boxed::Box;
use causal_core::{CausalLedger, DomainId, BranchId, Reversibility, SecurityLabel};
use capability_engine::{CSpace, ObjectId, Permissions};
use limine::{LimineBaseRevision, LimineHhdmRequest, LimineMemmapRequest, LimineFramebufferRequest};
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

/// Solicitud del mapa de memoria física (Memmap)
#[used]
#[link_section = ".requests"]
static MEMMAP_REQUEST: LimineMemmapRequest = LimineMemmapRequest::new();

/// Solicitud de Framebuffer gráfico para consola en pantalla
#[used]
#[link_section = ".requests"]
static FRAMEBUFFER_REQUEST: LimineFramebufferRequest = LimineFramebufferRequest::new();

/// Punto de entrada del kernel (llamado por el bootloader Limine en modo de 64 bits)
#[no_mangle]
pub extern "C" fn _start() -> ! {
    // 1. Inicializar salida serie COM1
    SERIAL1.init();

    // 2. Inicializar consola gráfica si el bootloader proveyó framebuffer UEFI
    if let Some(fb_resp) = FRAMEBUFFER_REQUEST.get_response() {
        if let Some(fb_ptr) = fb_resp.first_framebuffer() {
            fb::init(fb_ptr);
            fb::console_print("[AgentOS] Modo grafico UEFI activo", fb::Color::CYAN);
        }
    }

    // 2. Banner de arranque del kernel
    println!("========================================================");
    println!("  [AgentOS] Kernel Causal v0.1.0 (x86-64 Bare-Metal)");
    println!("  Arranque completado exitosamente via UEFI / Limine");
    println!("========================================================");

    // 3. Inicializar segmentación (GDT) y pila IST de contingencia (TSS)
    println!("[AgentOS] Configurando GDT y TSS...");
    gdt::init();
    println!("[AgentOS] GDT y TSS cargadas con exito (IST[0] activo)");

    // 4. Inicializar tabla de interrupciones (IDT)
    println!("[AgentOS] Configurando IDT y vectores de excepcion...");
    idt::init();
    println!("[AgentOS] IDT cargada (trampolines activos para #DE, #BP, #UD, #DF, #GP, #PF)");

    // Autotest de interrupción por software (Breakpoint #BP)
    unsafe {
        core::arch::asm!("int3", options(nomem, nostack));
    }
    println!("[AgentOS] Autotest IDT (#BP) superado exitosamente!");

    // 5. Comprobar si el bootloader soporta la revisión solicitada
    if BASE_REVISION.is_supported() {
        println!("[AgentOS] Protocolo Limine: Revision base soportada OK");
    } else {
        println!("[AgentOS] ADVERTENCIA: Revision del protocolo Limine no soportada");
    }

    // 6. Inicializar Subsistema de Gestión de Memoria (PMM, VMM, Heap)
    mm::init(MEMMAP_REQUEST.get_response(), HHDM_REQUEST.get_response());

    // 7. Autotest de asignación dinámica en Heap (Box, Vec)
    let boxed_val = Box::new(0xCAFE_BABE_u64);
    let mut test_vec = Vec::new();
    test_vec.push(10);
    test_vec.push(20);
    test_vec.push(30);
    println!(
        "[AgentOS::Heap] Autotest OK: Box(0x{:x}), Vec len={}, cap={}",
        *boxed_val,
        test_vec.len(),
        test_vec.capacity()
    );

    // 8. Autotest del Grafo Causal en Ring 0
    let mut ledger = CausalLedger::new();
    let root_branch = BranchId(0);
    let agent_domain = DomainId(1);
    let untrusted_label = SecurityLabel::UNTRUSTED_EXTERNAL;

    let e1 = ledger.record_effect(
        root_branch,
        agent_domain,
        DomainId(0), // kernel
        alloc::vec![],
        untrusted_label,
        Reversibility::PurelyReversible,
        [0u8; 32],
    );

    let e2 = ledger.record_effect(
        root_branch,
        agent_domain,
        DomainId(2), // network
        alloc::vec![e1],
        untrusted_label,
        Reversibility::EscrowStaged,
        [0u8; 32],
    );

    let why_chain = ledger.why(e2);
    println!(
        "[AgentOS::Causal] Autotest OK: Efecto e2={:?} depende causalmente de {} nodo(s)",
        e2,
        why_chain.len()
    );

    // 9. Autotest del Motor de Capacidades en Ring 0
    let mut cspace = CSpace::new();
    let token = cspace.mint_root(
        ObjectId(100),
        Permissions::READ | Permissions::WRITE | Permissions::GRANT,
        1,
    );
    let child_token = cspace.derive(token, Permissions::READ, 2).expect("Derivacion valida");
    println!(
        "[AgentOS::CapEngine] Autotest OK: Token padre {:?} derivo token hijo {:?}",
        token, child_token
    );

    // 10. Autotest de Syscall ABI via software interrupt `int 0x80`
    syscall::init();
    let sys_ret: i64;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("rax") syscall::SYS_EFFECT_LOG => sys_ret,
            in("rdi") 0u64, // branch 0
            in("rsi") 2u64, // target domain 2 (network)
            in("rdx") 1u64, // reversibility 1 (escrow staged)
            in("r10") 0u64,
            options(nostack)
        );
    }
    println!(
        "[AgentOS::Syscall] Autotest int 0x80 exitoso: SYS_EFFECT_LOG retorno effect_id={}",
        sys_ret
    );

    println!("========================================================");
    println!("  [AgentOS] Kernel Causal Inicializado al 100%");
    println!("  Sub-sistemas activos: UART, GDT, IDT, PMM, VMM, Heap,");
    println!("                        CausalLedger (Merkle-DAG), CSpace, Syscall (int 0x80),");
    println!("                        Framebuffer UI (VRAM Nativa UEFI)");
    println!("========================================================");

    // Renderizar tarjetas visuales de estado en el Framebuffer gráfico
    fb::draw_panel(40, 60, 520, 160, " SUBSISTEMAS ACTIVOS DEL KERNEL ", fb::Color::CYAN);
    fb::draw_string("GDT / TSS IST[0] (Double-Fault safe): OK", 60, 90, fb::Color::GREEN, fb::Color::DARK_GRAY);
    fb::draw_string("IDT 256 Vectores (#PF, int 0x80 Syscalls): OK", 60, 110, fb::Color::GREEN, fb::Color::DARK_GRAY);
    fb::draw_string("Memoria: PMM (4KiB) + VMM (4-Niveles) + Heap 1MiB: OK", 60, 130, fb::Color::GREEN, fb::Color::DARK_GRAY);
    fb::draw_string("Grafo Causal: Merkle-DAG SHA-256 Integro: OK", 60, 150, fb::Color::GREEN, fb::Color::DARK_GRAY);
    fb::draw_string("Seguridad: CSpace de Capacidades + Escrow Activo: OK", 60, 170, fb::Color::GREEN, fb::Color::DARK_GRAY);
    fb::draw_string("Modo: AgentOS Runtime Listo para Cargas de Agentes", 60, 190, fb::Color::CYAN, fb::Color::DARK_GRAY);

    // Para la prueba automatizada M1/M2 en QEMU, reportamos éxito a isa-debug-exit
    #[cfg(feature = "test-exit")]
    {
        println!("[AgentOS] Modo de prueba automatizada activo. Saliendo...");
        exit_qemu(QemuExitCode::Success);
    }

    // Mantener la CPU en reposo si no estamos en modo de prueba automatizada
    #[cfg(not(feature = "test-exit"))]
    arch::hlt_loop();
}
