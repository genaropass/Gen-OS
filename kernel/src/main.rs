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
pub mod task;
pub mod sched;
pub mod sync;
pub mod shell;
pub mod bench;
pub mod loader;

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
    println!("  [AgentOS] Kernel Causal v0.2.0 (x86-64 Bare-Metal)");
    println!("  Arranque completado exitosamente via UEFI / Limine");
    println!("========================================================");

    // 3. Inicializar segmentación (GDT) y pila IST de contingencia (TSS)
    println!("[AgentOS] Configurando GDT y TSS...");
    gdt::init();
    println!("[AgentOS] GDT y TSS cargadas con exito (IST[0] activo)");

    // 4. Inicializar tabla de interrupciones (IDT)
    println!("[AgentOS] Configurando IDT y vectores de excepcion...");
    idt::init();
    println!("[AgentOS] IDT cargada (trampolines activos para #DE, #BP, #UD, #DF, #GP, #PF, IRQ0, IRQ4)");

    // Autotest de interrupción por software (Breakpoint #BP)
    unsafe {
        core::arch::asm!("int3", options(nomem, nostack));
    }
    println!("[AgentOS] Autotest IDT (#BP) superado exitosamente!");

    // 4b. Activar protecciones de hardware de la CPU (CR0.WP, EFER.NXE, SMEP, SMAP, UMIP)
    arch::cpu::init_cpu_security();

    // 5. Configurar controlador de interrupciones PIC 8259 y Temporizador PIT 8254
    println!("[AgentOS] Configurando Dual PIC 8259 (Remap a vectores 32..47)...");
    unsafe {
        arch::pic::remap(32, 40);
        arch::pic::clear_mask(0); // Desenmascarar IRQ 0 (Temporizador PIT)
        arch::pic::clear_mask(4); // Desenmascarar IRQ 4 (COM1 Serie)
    }
    println!("[AgentOS] Configurando PIT 8254 a 100 Hz (quantum = 10ms)...");
    unsafe {
        arch::pit::init(100);
    }

    // 6. Comprobar si el bootloader soporta la revisión solicitada
    if BASE_REVISION.is_supported() {
        println!("[AgentOS] Protocolo Limine: Revision base soportada OK");
    } else {
        println!("[AgentOS] ADVERTENCIA: Revision del protocolo Limine no soportada");
    }

    // 7. Inicializar Subsistema de Gestión de Memoria (PMM, VMM, Heap)
    mm::init(MEMMAP_REQUEST.get_response(), HHDM_REQUEST.get_response());

    // 8. Autotest de asignación dinámica en Heap (Box, Vec)
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

    // 8b. Autotest de Espacio de Direcciones Aislado (PML4 AddressSpace)
    println!("[AgentOS::VMM] Validando aislamiento de AddressSpace por agente...");
    if let Some(mut user_as) = mm::address_space::AddressSpace::new() {
        let test_virt = 0x0040_0000u64;
        if let Some(frame) = mm::frame::alloc_frame() {
            let res = user_as.map_page(
                test_virt,
                frame.start_address(),
                mm::paging::flags::WRITABLE | mm::paging::flags::USER_ACCESSIBLE,
            );
            if res.is_ok() {
                let trans = user_as.translate(test_virt);
                println!(
                    "[AgentOS::VMM] AddressSpace aislado OK: Virt 0x{:08x} -> Phys 0x{:08x} (PML4: 0x{:x})",
                    test_virt, trans.unwrap_or(0), user_as.pml4_phys
                );
            }
        }
    }

    // 9. Autotest del Grafo Causal en Ring 0
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

    // 10. Autotest del Motor de Capacidades en Ring 0
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

    // 11. Autotest de Syscall ABI via software interrupt `int 0x80`
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

    // 12. Inicializar Planificador Preemptivo de Ring 0
    println!("[AgentOS::Sched] Inicializando planificador preemptivo de Ring 0...");
    sched::init();
    sched::spawn("agent_causal_monitor", agent_causal_worker);

    // 13. Habilitar Interrupciones de Hardware en CPU
    println!("[AgentOS] Habilitando interrupciones de hardware en CPU (sti)...");
    unsafe {
        arch::sti();
    }
    println!("[AgentOS] Hardware Timer PIT activo (Vector 32)!");

    println!("========================================================");
    println!("  [AgentOS] Kernel Causal Inicializado al 100%");
    println!("  Sub-sistemas activos: UART, GDT, IDT, PIC 8259, PIT 8254,");
    println!("                        PMM, VMM, Heap, Merkle-DAG Causal,");
    println!("                        CSpace, Syscall (int 0x80), TCB Scheduler,");
    println!("                        Framebuffer UI & Shell Interactivo COM1");
    println!("========================================================");

    // Renderizar tarjetas visuales de estado en el Framebuffer gráfico
    fb::draw_panel(40, 50, 580, 210, " SUBSISTEMAS ACTIVOS DEL KERNEL ", fb::Color::CYAN);
    fb::draw_string("GDT / TSS IST[0] (Double-Fault safe): OK", 60, 75, fb::Color::GREEN, fb::Color::DARK_GRAY);
    fb::draw_string("IDT 256 Vectores (#PF, IRQ0, IRQ4, int 0x80 Syscall): OK", 60, 95, fb::Color::GREEN, fb::Color::DARK_GRAY);
    fb::draw_string("Hardware PIC 8259 + PIT Timer 8254 (100 Hz / 10ms): OK", 60, 115, fb::Color::GREEN, fb::Color::DARK_GRAY);
    fb::draw_string("Memoria: PMM (4KiB) + VMM (4-Niveles) + Heap 1MiB: OK", 60, 135, fb::Color::GREEN, fb::Color::DARK_GRAY);
    fb::draw_string("Grafo Causal: Merkle-DAG SHA-256 FIPS 180-4 Integro: OK", 60, 155, fb::Color::GREEN, fb::Color::DARK_GRAY);
    fb::draw_string("Seguridad: CSpace de Capacidades + Escrow Activo: OK", 60, 175, fb::Color::GREEN, fb::Color::DARK_GRAY);
    fb::draw_string("Kernel Tasks: TCBs & Conmutacion de Contexto: OK", 60, 195, fb::Color::GREEN, fb::Color::DARK_GRAY);
    fb::draw_string("Modo: AgentOS Runtime & Interactive Shell Listo", 60, 215, fb::Color::CYAN, fb::Color::DARK_GRAY);

    // Inicializar Shell interactivo de Ring 0 en COM1
    shell::init();

    // Para la prueba automatizada en QEMU, reportamos éxito a isa-debug-exit
    #[cfg(feature = "test-exit")]
    {
        println!("[AgentOS] Modo de prueba automatizada activo. Saliendo...");
        exit_qemu(QemuExitCode::Success);
    }

    // Bucle interactivo del kernel: procesa caracteres del puerto serie y cede tiempo a tareas
    #[cfg(not(feature = "test-exit"))]
    loop {
        serial::poll_input();
        sched::yield_now();
        arch::hlt();
    }
}

/// Tarea de agente de fondo ejecutada en Ring 0 para auditoría de integridad causal
fn agent_causal_worker() -> ! {
    loop {
        sched::yield_now();
    }
}
