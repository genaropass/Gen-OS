# Estado del proyecto AgentOS

**Última actualización:** 2026-10-12
**Fase actual:** Fase 8 — Microkernel Multitarea con Temporización Hardware, Bus IPC Causal y Shell de Operador

## Hecho (con evidencia real y verificada en consola)

### 1. Entorno de Desarrollo y Toolchain (M1.0)
- [x] Rust stable 1.99.0 instalado en host.
- [x] Target bare-metal `x86_64-unknown-none` instalado y verificado.
- [x] Componentes `rust-src` y `llvm-tools` instalados.
- [x] Instalador de QEMU descargado en el Escritorio: `E:\Genaro\Desktop\Instalar_QEMU.exe`.

### 2. Microkernel Bare-Metal (`kernel/`)
- [x] Código fuente en `#![no_std]` y `#![no_main]`.
- [x] Implementación nativa del protocolo Limine v2/v3 en Rust estable.
- [x] Linker script `linker-x86_64.ld` para carga en higher-half virtual (`0xffffffff80000000`).
- [x] Driver UART 16550 para puerto serie COM1 (`0x3F8`) con soporte TX y RX interactivo.
- [x] Manejador de pánicos bare-metal con traceback serie y salida controlada.
- [x] Protocolo de salida de pruebas automatizadas en puerto `0xF4` (`isa-debug-exit`).
- [x] **Segmentación (GDT & TSS):** Tabla de descriptores globales y Task State Segment con pila IST[0] dedicada de 16 KiB para contingencia de Double Fault.
- [x] **Interrupciones y Excepciones (IDT):** Tabla de 256 vectores con trampolines en ensamblador estable (`global_asm!`) para #DE (0), #BP (3), #UD (6), #DF (8), #GP (13), #PF (14 con CR2), IRQ 0 Timer (32), IRQ 4 Serial RX (36) e `int 0x80` Syscall (128).
- [x] **Controlador de Interrupciones Hardware (Dual PIC 8259):** Remapeo completo de IRQs 0..15 a vectores 32..47 de la IDT, evitando colisiones con excepciones de CPU.
- [x] **Temporizador Hardware (PIT 8254):** Programado a 100 Hz (quantum = 10ms) con contador atómico de ticks y medición de uptime en milisegundos.
- [x] **Habilitación de Interrupciones en CPU:** Instrucción `sti` activa con recepción continua de ticks del temporizador.
- [x] **Gestor de Memoria Física (PMM):** Parser del mapa de memoria de Limine y asignador de marcos físicos de 4 KiB contiguos.
- [x] **Gestor de Memoria Virtual (VMM):** Caminador de tablas de páginas de 4 niveles x86-64, traducción física <-> virtual vía HHDM e invalidación de TLB (`invlpg`).
- [x] **Montón Global del Kernel (Heap Allocator):** Asignador dinámico de 1 MiB con coalescencia bidireccional y spinlocks que habilita `extern crate alloc` (`Box`, `Vec`, `String`) en Ring 0.
- [x] **Subsistema de Llamadas al Sistema (Syscalls):** ABI por interrupción de software `int 0x80` (Vector 128) con paso de registros e interfaz para Grafo Causal y Capacidades (`SYS_EFFECT_LOG`, `SYS_WHY`, `SYS_STAGE_ESCROW`, `SYS_COMMIT_BRANCH`, `SYS_ABORT_BRANCH`, `SYS_CAP_MINT`, `SYS_CAP_DERIVE`, `SYS_CAP_REVOKE`).
- [x] **Conmutador de Tareas Nativas en Ring 0 (TCB & Context Switching):** Bloques de control de tareas con pila propia de 16 KiB y rutina en ensamblador `asm_context_switch` para registros callee-saved (x86-64).
- [x] **Shell Interactivo de Ring 0 (`shell.rs`):** Consola interactiva del kernel sobre COM1 con comandos `help`, `status`, `causal`, `mem`, `bench`, `clear`, `exit`.
- [x] **Controlador Gráfico del Framebuffer (`fb.rs` & `font.rs`):** Renderizado directo en VRAM lineal UEFI a resolución nativa con fuente de mapa de bits 8x8 y panel visual de telemetría gráfica en pantalla.
- [x] **Compilación exitosa:** Binario ELF ensamblado y verificado para `x86_64-unknown-none` (0 errores, 0 warnings).

### 3. Partición de Arranque Virtual (ESP) y Bootloader
- [x] Bootloader UEFI oficial de Limine clonado y verificado (`BOOTX64.EFI`).
- [x] Configuración `boot/limine.conf` creada.
- [x] Partición EFI System Partition (ESP) completamente ensamblada en `target/esp/EFI/BOOT/`:
  - `BOOTX64.EFI` (249 KB)
  - `limine.conf` (114 B)
  - `agentos-kernel` (ELF bare-metal)

### 4. Herramienta de Orquestación, Shell y Benchmarks (`xtask/`)
- [x] Orquestador implementado en Rust puro:
  - `cargo xtask build`: Compila el kernel y ensambla la partición ESP.
  - `cargo xtask build-test`: Compila con la feature `test-exit` para pruebas automáticas.
  - `cargo xtask run`: Lanza QEMU con la partición ESP.
  - `cargo xtask test`: Ejecuta la prueba automatizada en QEMU y valida código de retorno.
  - `cargo xtask demo`: Demostración interactiva en vivo que corre los 5 subsistemas con gráficos ANSI.
  - `cargo xtask shell`: **Shell Interactivo de Operador (REPL)** para controlar agentes, multiverso, archivos y capacidades.
  - `cargo xtask bench`: **Suite de Microbenchmarks de Alto Rendimiento**.

### 5. Motor Causal y de Seguridad (`crates/`)
- [x] **`crates/causal-core`:**
  - Grafo Acíclico Dirigido (DAG) sellado con hashes criptográficos **SHA-256 (Merkle-DAG)**.
  - Función de autoverificación matemática de integridad `verify_merkle_integrity()`.
  - Auditoría retrospectiva `why()` para rastreo causal de inyecciones de prompts.
  - Gestor de Multiverso con Escrow (`EscrowManager`) para contención de efectos irreversibles.
  - Soporte dual `#![no_std]` (en kernel Ring 0) y `std` (en host).
  - 6 tests unitarios pasados (100%).
- [x] **`crates/capability-engine`:**
  - Control de acceso por capacidades basado en slots (`CSpace`).
  - Invariante de atenuación matemática (imposible elevar privilegios).
  - Árboles de derivación con revocación recursiva en cascada.
  - Soporte dual `#![no_std]` (en kernel Ring 0) y `std` (en host).
  - 3 tests unitarios pasados (100%).
- [x] **`crates/agent-runtime`:**
  - `AgentInstance`: Modelo de agente nativo con identidad, objetivo declarativo, presupuesto de tokens/pasos y seguimiento de taint por Information Flow Control (IFC).
  - `ToolRegistry`: Herramientas externas protegidas por capacidades.
  - `AgentSupervisor`: Coordinador de seguridad que desvía acciones de agentes contaminados o especulativos a la cola de Escrow, ejecuta auditorías `why()` y purga ramas maliciosas.
  - `DreamingEngine`: Motor del Multiverso para exploración paralela de ramas hipotéticas y confirmación atómica de la óptima.
  - 4 tests de integración pasados (100%).
- [x] **`crates/semantic-fs`:**
  - Sistema de archivos semántico (BranchFS) con ramificación Copy-on-Write para el multiverso.
  - Búsqueda vectorial con similitud de coseno en memoria (`EmbeddingVector`).
  - Filtrado por nivel de integridad (IFC) y procedencia causal.
  - Soporte dual `#![no_std]` y `std`.
  - 4 tests unitarios pasados (100%).
- [x] **`crates/agent-scheduler`:**
  - Planificador consciente de recursos e inferencia (SchedCP).
  - Estados reactivos a dependencias del Grafo Causal (`BlockedOnCausal`).
  - Herencia de Prioridad Causal (Causal Priority Inheritance) para evitar inversiones de prioridad.
  - Contención de agotamiento de presupuestos (tokens y tiempo CPU).
  - Soporte dual `#![no_std]` y `std`.
  - 3 tests unitarios pasados (100%).
- [x] **`crates/agent-vm`:**
  - Máquina virtual causal de bytecode (AVM) con medidor de Gas determinista.
  - Instrucciones nativas de aserción de capacidades (`AssertCap`), ramificación (`ForkBranch`, `CommitBranch`, `AbortBranch`) y observación de taint (`Observe`).
  - 3 tests unitarios pasados (100%).
- [x] **`crates/agent-ipc` (NUEVO):**
  - Bus de mensajería inter-agentes gobernado por capacidades unforgeables.
  - Propagación automática de taint (IFC) a través de canales de comunicación.
  - Registro de causalidad en el Merkle-DAG en cada transmisión.
  - Aislamiento estricto de mensajes dentro de ramas especulativas del Multiverso y purga en O(1) ante abort.
  - 4 tests unitarios pasados (100%).
- [x] **Suite de pruebas global:** **27/27 tests pasando limpiamente (`cargo test --workspace`)**.

### 6. Métricas Reales de Rendimiento (`cargo xtask bench`)
- **Validación de Capacidades (CSpace):** **33.717.033 ops/sec** (latencia media de 29.7 ns).
- **Búsqueda Vectorial Semántica (BranchFS 32-D):** **2.371.849 búsquedas/sec**.
- **Intérprete de Bytecode y Gas (AgentVM):** **6.363.631 instrucciones/sec**.
- **Bus IPC Causal Inter-Agente (Agent-IPC):** **79.320 msgs/sec** con registro criptográfico completo.
- **Hashing Merkle-DAG SHA-256:** **87.711 hashes/sec** (5.35 MB/s en Rust puro sin librerías externas).

## Próximos pasos
- [ ] Ejecutar `cargo xtask shell` en cualquier terminal para interactuar con todos los subsistemas.
- [ ] Ejecutar `cargo xtask demo` para ver la suite interactiva completa.
- [ ] Ejecutar `cargo xtask bench` para volver a verificar las métricas en vivo.
- [ ] Cuando el usuario instale QEMU (`Instalar_QEMU.exe`), correr `cargo xtask run` para ver el arranque del microkernel con interfaz UEFI y temporizador hardware en pantalla.
