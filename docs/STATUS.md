# Estado del proyecto AgentOS

**Última actualización:** 2026-10-11
**Fase actual:** Fase 0 — Investigación, Especificación y Arquitectura Causal

## Hecho (con evidencia)
- [x] Carpeta del proyecto creada: `E:\Genaro\Desktop\AgentOS`.
- [x] Repositorio Git inicializado con rama principal `main`.
- [x] Documento maestro actualizado a v0.2: `docs/MASTER_PLAN.md`.
- [x] Especificación técnica del Kernel Causal: `docs/SPEC_CAUSAL_KERNEL.md`.
- [x] Documento de lluvia de ideas e investigación de frontera: `research/BRAINSTORM.md`.
- [x] Registro de Decisiones Arquitectónicas (ADRs):
  - ADR-0001: Rust estable y target `x86_64-unknown-none`.
  - ADR-0002: Arranque UEFI con Limine.
  - ADR-0003: Microkernel por capacidades e IA fuera de Ring 0.
  - ADR-0004: Entorno de desarrollo (QEMU + serie + xtask).
  - ADR-0005: El Kernel Causal, Multiverso con Escrow y Análisis Contrafactual.
- [x] Inventario del entorno local (2026-10-11):
  - Git 2.50 ✅
  - Python 3.12 ✅
  - Virtualización por hipervisor activa ✅
  - Rust (`rustup` / `cargo`) ❌ No instalado
  - QEMU (`qemu-system-x86_64`) ❌ No instalado

## En progreso
- [ ] Aprobación de los ADRs (0001 al 0005) por el fundador.
- [ ] Decisión de inicio:
  - **Pista K:** Instalación de herramientas (Rust + QEMU) para el Hito M1.0 en QEMU.
  - **Pista R:** Estructuración del primer crate modular `crates/causal-core` para implementar el Grafo Causal y el buffer de Escrow.

## Código compilado o ejecutado
Ninguno todavía (Fase de especificación y diseño completada).
