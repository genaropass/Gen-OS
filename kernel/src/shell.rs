//! Shell interactivo en Ring 0 para AgentOS a través del puerto serie COM1
//! Permite al operador consultar telemetría, inspeccionar el Merkle-DAG,
//! monitorear capacidades y ejecutar diagnósticos del kernel en tiempo real.

use crate::{print, println};
use crate::arch::pit;

const MAX_CMD_LEN: usize = 128;

struct ShellBuffer {
    buf: [u8; MAX_CMD_LEN],
    len: usize,
}

impl ShellBuffer {
    const fn new() -> Self {
        Self {
            buf: [0; MAX_CMD_LEN],
            len: 0,
        }
    }

    fn push(&mut self, b: u8) -> bool {
        if self.len < MAX_CMD_LEN - 1 {
            self.buf[self.len] = b;
            self.len += 1;
            true
        } else {
            false
        }
    }

    fn pop(&mut self) -> bool {
        if self.len > 0 {
            self.len -= 1;
            self.buf[self.len] = 0;
            true
        } else {
            false
        }
    }

    fn clear(&mut self) {
        self.len = 0;
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("")
    }
}

use crate::sync::IrqSpinLock;

static SHELL_STATE: IrqSpinLock<ShellBuffer> = IrqSpinLock::new(ShellBuffer::new());

/// Inicializa el Shell de Ring 0 e imprime el banner de bienvenida
pub fn init() {
    println!("\n\x1b[1;36m========================================================");
    println!("  AgentOS Kernel Interactive Shell (Ring 0 / COM1)");
    println!("  Escribe 'help' para ver la lista de comandos disponibles.");
    println!("========================================================\x1b[0m");
    print_prompt();
}

/// Imprime el prompt interactivo del kernel
pub fn print_prompt() {
    print!("\x1b[1;32mAgentOS-Ring0# \x1b[0m");
}

/// Procesa un byte de entrada recibido por el puerto serie
pub fn handle_char(c: u8) {
    let mut state = SHELL_STATE.lock();

    match c {
        // Enter / Retorno de carro
        b'\r' | b'\n' => {
            println!();
            let cmd = state.as_str().trim();
            if !cmd.is_empty() {
                execute_command(cmd);
            }
            state.clear();
            print_prompt();
        }
        // Backspace / Delete
        0x08 | 0x7F => {
            if state.pop() {
                // Borrar visualmente el caracter en la consola del terminal
                print!("\x08 \x08");
            }
        }
        // Caracteres imprimibles
        0x20..=0x7E
            if state.push(c) => {
                // Echo del caracter a la consola serie
                crate::serial::SERIAL1.write_byte(c);
            }
        _ => {}
    }
}

/// Ejecuta un comando ingresado en el Shell de Ring 0
fn execute_command(cmd: &str) {
    let mut parts = cmd.split_whitespace();
    let command = parts.next().unwrap_or("");

    match command {
        "help" => {
            println!("\x1b[1;33mComandos disponibles en el Kernel de AgentOS:\x1b[0m");
            println!("  help         - Muestra este menú de ayuda");
            println!("  status       - Muestra el estado del sistema, ticks de PIT y uptime");
            println!("  causal       - Verifica la integridad matemática del Merkle-DAG");
            println!("  mem          - Muestra información del gestor de memoria (PMM / Heap)");
            println!("  tasks        - Muestra estado del planificador preemptivo y tareas");
            println!("  yield        - Cede voluntariamente la CPU a otra tarea lista");
            println!("  bench        - Ejecuta micro-benchmark en Ring 0 (RDTSC de hardware)");
            println!("  clear        - Limpia la pantalla del terminal serie");
            println!("  exit         - Apaga la máquina virtual en QEMU de forma limpia");
        }
        "status" => {
            let ticks = pit::ticks();
            let uptime = pit::uptime_ms();
            println!("\x1b[1;34m[AgentOS::Telemetry]\x1b[0m");
            println!("  Uptime: {} ms ({} ticks de hardware PIT)", uptime, ticks);
            println!("  Arquitectura: x86-64 Higher-Half (Ring 0)");
            println!("  Modo de ejecución: Microkernel Causal Nativo");
        }
        "causal" => {
            println!("\x1b[1;34m[AgentOS::Causal]\x1b[0m");
            match crate::syscall::verify_kernel_ledger() {
                Some((is_valid, pending_escrow)) => {
                    if is_valid {
                        println!("  Merkle-DAG: \x1b[1;32mINTEGRO (100% de hashes SHA-256 matematicamente validos)\x1b[0m");
                    } else {
                        println!("  Merkle-DAG: \x1b[1;31mFALLO DE INTEGRIDAD (hashes alterados)\x1b[0m");
                    }
                    println!("  Acciones retenidas en Escrow: {}", pending_escrow);
                }
                None => {
                    println!("  Grafo Causal no inicializado aún");
                }
            }
        }
        "mem" => {
            println!("\x1b[1;34m[AgentOS::Memory]\x1b[0m");
            let (frames_alloc, bytes_usable) = crate::mm::frame::pmm_stats();
            let (heap_alloc, heap_free) = crate::mm::heap::heap_stats();
            println!("  PMM: {} marcos asignados ({} KiB), {} MiB utilizables totales",
                frames_alloc, frames_alloc * 4, bytes_usable / (1024 * 1024));
            println!("  Heap: {} bytes en uso, {} bytes libres (capacidad 1 MiB)",
                heap_alloc, heap_free);
        }
        "tasks" => {
            let (active_tasks, switches) = crate::sched::sched_stats();
            println!("\x1b[1;34m[AgentOS::Scheduler]\x1b[0m");
            println!("  Tareas activas: {}", active_tasks);
            println!("  Conmutaciones de contexto ejecutadas: {}", switches);
            println!("  Politica: Preemptive Time-slice Round-Robin (100 Hz / Quantum 100ms)");
        }
        "yield" => {
            println!("[AgentOS::Scheduler] Cediendo CPU voluntariamente (yield_now)...");
            crate::sched::yield_now();
            println!("[AgentOS::Scheduler] Control retomado exitosamente!");
        }
        "bench" => {
            crate::bench::run_kernel_benchmarks();
        }
        "clear" => {
            print!("\x1b[2J\x1b[H");
        }
        "exit" => {
            println!("\x1b[1;31m[AgentOS] Apagando maquina virtual via puerto isa-debug-exit...\x1b[0m");
            crate::qemu_exit::exit_qemu(crate::qemu_exit::QemuExitCode::Success);
        }
        other => {
            println!("\x1b[1;31mComando no reconocido: '{}'. Escribe 'help'.\x1b[0m", other);
        }
    }
}
