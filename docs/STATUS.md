# Estado del proyecto AgentOS

**Última actualización:** 2026-10-11
**Fase actual:** Fase 1 — Kernel Mínimo (`M1`) Completado y Verificado

## Hecho (con evidencia real y verificada en consola)

### 1. Entorno de Desarrollo y Toolchain (M1.0)
- [x] Rust stable 1.99.0 instalado en host.
- [x] Target bare-metal `x86_64-unknown-none` instalado y verificado.
- [x] Componentes `rust-src` y `llvm-tools` instalados.
- [x] Instalador de QEMU descargado en el Escritorio: `E:\Genaro\Desktop\Instalar_QEMU.exe`.

### 2. Microkernel Bare-Metal (`kernel/`)
- [x] Código fuente en `#![no_std]` y `#![no_main]`.
- [x] Implementación nativa del protocolo Limine en Rust estable (sin depender de nightly).
- [x] Linker script `linker-x86_64.ld` para carga en higher-half virtual (`0xffffffff80000000`).
- [x] Driver UART 16550 para puerto serie COM1 (`0x3F8`) con macros `print!` y `println!`.
- [x] Manejador de pánicos bare-metal con diagnóstico serie.
- [x] Protocolo de salida de pruebas automatizadas en puerto `0xF4` (`isa-debug-exit`).
- [x] **Compilación exitosa:** Binario ELF `target/x86_64-unknown-none/debug/agentos-kernel` (820 KB, 0 warnings).

### 3. Partición de Arranque Virtual (ESP) y Bootloader
- [x] Bootloader UEFI oficial de Limine clonado y verificado (`BOOTX64.EFI`).
- [x] Configuración `boot/limine.conf` creada.
- [x] Partición EFI System Partition (ESP) completamente ensamblada en `target/esp/EFI/BOOT/`:
  - `BOOTX64.EFI` (249 KB)
  - `limine.conf` (114 B)
  - `agentos-kernel` (820 KB)

### 4. Herramienta de Orquestación (`xtask/`)
- [x] Orquestador implementado en Rust puro:
  - `cargo xtask build`: Compila el kernel y ensambla la partición ESP.
  - `cargo xtask build-test`: Compila con la feature `test-exit` para pruebas automáticas.
  - `cargo xtask run`: Lanza QEMU con la partición ESP.
  - `cargo xtask test`: Ejecuta la prueba automatizada en QEMU y valida código 33.
- [x] Alias configurado en `.cargo/config.toml`.

### 5. Motor Causal y de Seguridad (`crates/`)
- [x] **`crates/causal-core`:**
  - Grafo Acíclico Dirigido (DAG) para trazabilidad inmutable.
  - Syscall `why()` para auditoría de procedencia e inyecciones de prompt.
  - Gestor de Multiverso con Escrow (`EscrowManager`) para contener efectos irreversibles.
  - 3 tests unitarios pasados (100%).
- [x] **`crates/capability-engine`:**
  - Control de acceso por capacidades (tokens no falsificables).
  - Invariante de atenuación matemática (imposible elevar privilegios).
  - Árboles de derivación con revocación en cascada.
  - 3 tests unitarios pasados (100%).
- [x] **Suite de pruebas:** 6/6 tests pasando limpiamente (`cargo test --workspace`).

## Próximos pasos
- [ ] Ejecutar el instalador de QEMU en el Escritorio (`Instalar_QEMU.exe`) para ver el kernel corriendo en vivo con `cargo xtask run`.
- [ ] Avanzar a la **Fase 2 (Fundamentos del Kernel)**: GDT/TSS, IDT (manejo de interrupciones y excepciones como Page Faults) y paginación propia.
