# Guía y Reglas de Desarrollo de GenOS para Antigravity

Este repositorio contiene **GenOS**, un sistema operativo nativo para agentes de IA desarrollado en Rust.
Como asistente de IA de Antigravity en este espacio de trabajo, debes adherirte estrictamente a estas directrices.

## 1. Arquitectura y Restricciones de Carga
- **Microkernel Bare-Metal (`kernel/`):**
  - Debe permanecer estrictamente en modo `#![no_std]` y compatible con el target `x86_64-unknown-none`.
  - NUNCA introduzcas dependencias de `std` ni dependencias externas con runtime en `kernel/`.
  - Toda asignación dinámica en el kernel debe usar el heap global interno (`alloc::vec::Vec`, `alloc::boxed::Box`).
- **Rust Stable:**
  - Todo el código debe compilar en Rust Stable 1.99.0 sin banderas inestables `#![feature(...)]`.
- **Integridad de Tests:**
  - Mantén siempre el 100% de tests aprobados (`cargo test --workspace`).
  - Cada nuevo subsistema debe contar con pruebas unitarias y de integración adversariales.

## 2. Comandos Operativos de GenOS (`xtask`)
Usa siempre la herramienta de orquestación `cargo xtask`:
- `cargo xtask doctor` : Diagnóstico de toolchain, bootloader Limine, UEFI y QEMU.
- `cargo xtask build`  : Compilación del kernel y ensamblaje de la partición ESP UEFI (`target/esp/`).
- `cargo xtask demo`   : Demostración end-to-end de los 5 pilares en consola.
- `cargo xtask bench`  : Suite de benchmarks estadísticos de alto rendimiento.
- `cargo xtask shell`  : Shell interactivo de operador para gobernar agentes en tiempo real.

## 3. Principios de Seguridad Causal (DIFC)
- Toda interacción entre dominios debe pasar por el Grafo Causal (`CausalLedger`).
- Todo dato proveniente de fuentes no confiables (Web, correo, herramientas externas) debe recibir `TaintMask::WEB_UNTRUSTED` o `TOOL_OUTPUT`.
- Las acciones mutantes o irreversibles de agentes contaminados DEBEN retenerse en `Escrow` hasta su confirmación o aborto atómico $O(1)$.
