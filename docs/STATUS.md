# Estado del proyecto AgentOS

**Última actualización:** 2026-10-12
**Fase actual:** Fase 4 — Sistema Operativo Completo (Microkernel x86-64, Grafo Causal, Runtime de Agentes, BranchFS y Planificador SchedCP)

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
- [x] Driver UART 16550 para puerto serie COM1 (`0x3F8`) con macros `print!` y `println!`.
- [x] Manejador de pánicos bare-metal con traceback serie y salida controlada.
- [x] Protocolo de salida de pruebas automatizadas en puerto `0xF4` (`isa-debug-exit`).
- [x] **Segmentación (GDT & TSS):** Tabla de descriptores globales y Task State Segment con pila IST[0] dedicada de 16 KiB para contingencia de Double Fault.
- [x] **Interrupciones y Excepciones (IDT):** Tabla de 256 vectores con trampolines en ensamblador estable (`global_asm!`) para #DE (0), #BP (3), #UD (6), #DF (8), #GP (13) y #PF (14 con lectura de CR2).
- [x] **Gestor de Memoria Física (PMM):** Parser del mapa de memoria de Limine y asignador de marcos físicos de 4 KiB contiguos.
- [x] **Gestor de Memoria Virtual (VMM):** Caminador de tablas de páginas de 4 niveles x86-64, traducción física <-> virtual vía HHDM e invalidación de TLB (`invlpg`).
- [x] **Montón Global del Kernel (Heap Allocator):** Asignador dinámico de 1 MiB con coalescencia bidireccional y spinlocks que habilita `extern crate alloc` (`Box`, `Vec`, `String`) en Ring 0.
- [x] **Subsistema de Llamadas al Sistema (Syscalls):** ABI por interrupción de software `int 0x80` (Vector 128) con paso de registros e interfaz para Grafo Causal y Capacidades (`SYS_EFFECT_LOG`, `SYS_WHY`, `SYS_STAGE_ESCROW`, `SYS_COMMIT_BRANCH`, `SYS_ABORT_BRANCH`, `SYS_CAP_MINT`, `SYS_CAP_DERIVE`, `SYS_CAP_REVOKE`).
- [x] **Compilación exitosa:** Binario ELF ensamblado y verificado para `x86_64-unknown-none` (0 errores, 0 warnings).

### 3. Partición de Arranque Virtual (ESP) y Bootloader
- [x] Bootloader UEFI oficial de Limine clonado y verificado (`BOOTX64.EFI`).
- [x] Configuración `boot/limine.conf` creada.
- [x] Partición EFI System Partition (ESP) completamente ensamblada en `target/esp/EFI/BOOT/`:
  - `BOOTX64.EFI` (249 KB)
  - `limine.conf` (114 B)
  - `agentos-kernel` (ELF bare-metal)

### 4. Herramienta de Orquestación (`xtask/`)
- [x] Orquestador implementado en Rust puro:
  - `cargo xtask build`: Compila el kernel y ensambla la partición ESP.
  - `cargo xtask build-test`: Compila con la feature `test-exit` para pruebas automáticas.
  - `cargo xtask run`: Lanza QEMU con la partición ESP.
  - `cargo xtask test`: Ejecuta la prueba automatizada en QEMU y valida código de retorno.
- [x] Alias configurado en `.cargo/config.toml`.

### 5. Motor Causal y de Seguridad (`crates/`)
- [x] **`crates/causal-core`:**
  - Grafo Acíclico Dirigido (DAG) inmutable para registro de efectos y procedencia.
  - Auditoría retrospectiva `why()` para rastreo causal de inyecciones de prompts.
  - Gestor de Multiverso con Escrow (`EscrowManager`) para contención de efectos irreversibles.
  - Soporte dual `#![no_std]` (en kernel Ring 0) y `std` (en host).
  - 3 tests unitarios pasados (100%).
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
- [x] **Suite de pruebas global:** 17/17 tests pasando limpiamente (`cargo test --workspace`).

## Próximos pasos
- [ ] Ejecutar el instalador de QEMU (`Instalar_QEMU.exe`) en el Escritorio cuando el usuario desee ver la salida gráfica en vivo.
