# ADR-0004 — Entorno de desarrollo: QEMU + OVMF, salida serie, `xtask` y pruebas automáticas desde M1

- **Estado:** Propuesto
- **Fecha:** 2026-10-11

## Contexto
El anfitrión es Windows. Hay que desarrollar sin arriesgar la instalación principal y con pruebas automatizables desde el primer día.

## Decisión
- **QEMU** (`qemu-system-x86_64`, máquina `q35`) con el firmware **OVMF** que trae el instalador de QEMU para Windows.
- Por defecto se usa la emulación **TCG** (determinista y fácil de depurar). WHPX es opcional, para rendimiento.
- **Salida de diagnóstico por puerto serie COM1** (`-serial stdio`). Es texto plano, fácil de capturar y validar en pruebas.
- **Pruebas:** dispositivo `isa-debug-exit` (puerto `0xf4`) para que el kernel comunique éxito o fallo como código de salida de QEMU, con tiempo límite.
- **Herramienta de build/run/test en Rust** (patrón `cargo xtask`), en lugar de scripts de PowerShell: es multiplataforma, se puede probar y sirve para una futura CI en Linux.
- Depuración con gdb conectado a QEMU (`-s -S`) desde la Fase 2.

## Consecuencias
- (+) Nada se ejecuta sobre el hardware real ni toca la instalación de Windows.
- (+) Cada hito se valida con un comando (`cargo xtask test`).
- (−) TCG es lento para cargas grandes (aceptable en las Fases 1–3).
- (−) El framebuffer queda para más adelante; al principio solo hay salida serie.
