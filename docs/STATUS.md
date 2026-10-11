# Estado del proyecto AgentOS

**Última actualización:** 2026-10-11
**Fase actual:** Fase 0 — Especificación y Primer Código Verificado (`crates/causal-core`)

## Hecho (con evidencia real y verificada)
- [x] Carpeta del proyecto: `E:\Genaro\Desktop\AgentOS`.
- [x] Repositorio Git inicializado con rama principal `main`.
- [x] Documento maestro v0.2: `docs/MASTER_PLAN.md`.
- [x] Especificación técnica del Kernel Causal: `docs/SPEC_CAUSAL_KERNEL.md`.
- [x] Lluvia de ideas e investigación de frontera: `research/BRAINSTORM.md`.
- [x] Registro de Decisiones Arquitectónicas (ADR 0001 al 0005).
- [x] Entorno de Rust instalado y verificado:
  - `rustc 1.99.0` (estable)
  - `cargo 1.99.0`
  - Target bare-metal: `x86_64-unknown-none`
- [x] **Primer código ejecutable del proyecto (`crates/causal-core`):**
  - Implementación del Grafo Causal (`CausalLedger`) e identificación de dependencias.
  - Implementación de la syscall de trazabilidad causal `why()`.
  - Implementación del gestor de Multiverso con Escrow (`EscrowManager`).
  - **Pruebas unitarias:** 3 tests pasados al 100% (`cargo test --workspace`).
  - **Compatibilidad bare-metal:** Verificada compilación exitosa para `x86_64-unknown-none` (`#![no_std]`).
- [x] Instalador de QEMU descargado y dejado en el Escritorio: `E:\Genaro\Desktop\Instalar_QEMU.exe`.

## En progreso
- [ ] Instalación de QEMU (requiere doble clic en `Instalar_QEMU.exe` para aceptar UAC en Windows).
- [ ] Construcción del esqueleto del kernel bare-metal (`kernel/`) para el Hito M1 en QEMU.
