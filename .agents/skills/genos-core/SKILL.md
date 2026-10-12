---
name: genos-core
description: Orquestación, desarrollo y gobernanza de GenOS en Antigravity. Permite ejecutar diagnósticos (doctor), compilación bare-metal UEFI, demostraciones en vivo (demo), benchmarks, auditorías causales why() y gestión de agentes en Multiverso/Escrow.
---

# GenOS Core: Guía de Orquestación para Antigravity

**GenOS** es un sistema operativo nativo para Inteligencia Artificial y agentes autónomos, concebido por Genaro Agustín Passero y construido en Rust. Esta habilidad enseña a los agentes de Antigravity cómo interactuar, compilar, testear y gobernar GenOS.

---

## 1. Comandos de Orquestación (`cargo xtask`)

Utiliza siempre la herramienta de soporte interna `cargo xtask` desde la raíz del repositorio (`E:\Genaro\Desktop\AgentOS`):

| Comando | Descripción | Contexto de Uso |
| :--- | :--- | :--- |
| `cargo xtask doctor` | Diagnóstico integral del entorno | Verifica Rust Stable 1.99.0, Limine bootloader, OVMF UEFI y QEMU. |
| `cargo xtask build` | Compilación y ensamblado ESP | Compila el kernel `#![no_std]` y monta la partición UEFI en `target/esp/`. |
| `cargo xtask demo` | Demostración en vivo de los 5 pilares | Ejecuta en segundos Merkle-DAG, Escrow, Multiverso, SchedCP y AVM. |
| `cargo xtask bench` | Benchmarks de rendimiento | Mide latencia de hashing SHA-256, cambio de contexto y gas AVM. |
| `cargo xtask shell` | Consola de operador GenOS | Shell interactivo para inspeccionar dominios, memoria y capacidades. |
| `cargo test --workspace` | Suite integral de pruebas | Ejecuta las 70+ pruebas unitarias, de integración y adversariales. |

---

## 2. Pilares de Seguridad e Integración con Agentes

### A. Taint Tracking (DIFC) & Escrow
Cualquier entrada externa procesada por un agente (mensajes web, llamadas a herramientas MCP, correos electrónicos) recibe automáticamente una máscara de contaminación:
```rust
// TaintMask::WEB_UNTRUSTED | TaintMask::TOOL_OUTPUT
```
- Si un agente contaminado intenta ejecutar un efecto externo (ej. enviar paquetes de red o modificar archivos fuera de su rama), el microkernel **retiene la acción en `Escrow`**.
- La acción solo se ejecuta si un verificador o el operador humano aprueba el commit; si se detecta hostilidad o prompt injection, la rama se **aborta en $O(1)$** purgando el escrow sin efectos colaterales.

### B. Multiverso y Copy-on-Write (BranchFS)
- Los agentes pueden ejecutar exploración especulativa (*DreamingEngine*).
- Cada hipótesis corre en su propio espacio de nombres de archivos (*Branch*).
- Si la hipótesis tiene éxito, se realiza un `merge` atómico a la raíz; si falla, se descarta instantáneamente.

### C. Auditoría Causal Retrospectiva (`why()`)
- Cada evento y efecto en GenOS genera un nodo en el `CausalLedger` firmado criptográficamente con SHA-256 (compatible FIPS 180-4).
- Al consultar `why(effect_id)`, el grafo reconstruye en reversa la cadena causal determinista completa hasta la entrada original.

---

## 3. Protocolo de Integración MCP & WASM

GenOS expone puertas de enlace seguras para agentes LLM:
1. **MCP Host Gateway (`crates/agent-runtime/src/mcp.rs`):** Permite a GenOS consumir herramientas estándar Model Context Protocol protegiendo al agente contra SSRF y exfiltración.
2. **WASM Sandboxed Runtimes (`crates/agent-vm/src/wasm.rs`):** Permite ejecutar binarios WASM con medición estricta de gas y límites de memoria aislados.

---

## 4. Reglas de Contribución para Modelos
1. **Microkernel `#![no_std]`:** En `kernel/`, no uses `std` ni dependencias con runtime externo.
2. **Estabilidad:** Mantén siempre compatibilidad con Rust Stable 1.99.0.
3. **Tests Obligatorios:** Ningún cambio debe romper las pruebas existentes (`cargo test --workspace` debe permanecer en 100% pasando).
