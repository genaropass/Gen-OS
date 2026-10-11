# ADR-0002 — Arranque UEFI con Limine (herramienta reemplazable)

- **Estado:** Propuesto
- **Fecha:** 2026-10-11

## Contexto
El kernel necesita que algo lo cargue en memoria, lo ponga en modo de 64 bits con paginación y le entregue información del hardware (mapa de memoria, framebuffer). Escribir eso desde cero no aporta al primer hito.

## Decisión
- Arrancar mediante **UEFI** (firmware OVMF en QEMU) con el bootloader **Limine** y su protocolo.
- El kernel es un **ELF cargado en *higher half***, que usa el crate `limine` para leer las respuestas del bootloader.
- En Windows **no se arma ISO**: QEMU monta la carpeta `target/esp` como disco FAT virtual (`-drive format=raw,file=fat:rw:target\esp`).
- La versión de Limine queda fijada, y `xtask` verifica el SHA-256 de los binarios descargados.

## Consecuencias
- (+) Funciona con Rust estable.
- (+) El kernel recibe el mapa de memoria, el *direct map* (HHDM), el framebuffer y SMP sin escribir código de arranque.
- (+) El bootloader **no forma parte del kernel**: el kernel solo depende de la interfaz del protocolo y puede migrarse a un bootloader propio (por ejemplo, para el arranque verificado en la Fase 6).
- (−) Dependencia externa de C (Limine). Mitigación: versión fijada y verificación de hash.
- (−) La sintaxis de `limine.conf` cambia entre versiones mayores; se valida en M1.

## Alternativas descartadas
- **Crate `bootloader` 0.11:** 100 % Rust, pero su flujo recomendado depende de `bindeps` (nightly). **Queda como plan B** si Limine bloquea M1 durante más de 6 semanas.
- **Bootloader UEFI propio (`uefi-rs`):** postergado a la Fase 6.
- **GRUB + Multiboot2:** herramientas incómodas en Windows y exige la transición de 32 a 64 bits en ensamblador.
