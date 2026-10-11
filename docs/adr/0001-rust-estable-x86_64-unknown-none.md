# ADR-0001 — Rust estable con target `x86_64-unknown-none` como base del kernel

- **Estado:** Propuesto (pendiente de aprobación del fundador)
- **Fecha:** 2026-10-11

## Contexto
El kernel debe escribirse en Rust, ser reproducible y empezar en x86-64. Hay dos caminos habituales:

- **Nightly:** algunas funciones inestables de cargo y del compilador, como `build-std` o `bindeps`.
- **Estable:** usar el target `x86_64-unknown-none`, que el proyecto Rust distribuye precompilado (`rustup target add`).

## Decisión
- Usar **Rust estable**, con la versión exacta fijada en `rust-toolchain.toml` una vez instalada.
- Compilar el kernel para **`x86_64-unknown-none`**, con `#![no_std]` y `#![no_main]`.
- Usar `core` y, desde la Fase 2, `alloc` con un *heap* propio.

## Consecuencias
- (+) Compilaciones reproducibles, sin roturas por cambios en nightly.
- (+) El target ya desactiva la *red zone* y SSE/MMX (*soft-float*), como requiere un kernel.
- (−) Si más adelante hace falta una función inestable (por ejemplo, ciertas formas de `asm!` o `build-std` para un target propio), habrá que justificarla en un nuevo ADR.

## Alternativas descartadas
- **Nightly desde el inicio:** sin una necesidad concreta para M1, solo agrega inestabilidad.
- **C/C++:** contradice el requisito de Rust y pierde la seguridad de memoria en la mayor parte del código.
