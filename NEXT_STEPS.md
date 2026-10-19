# Próximos pasos

> Archivo vivo. El agente que trabaje en el proyecto lo actualiza **al terminar cada sesión**.
> El plan completo está en [`docs/ROADMAP.md`](docs/ROADMAP.md).

**Fase actual:** Fase 6 (Distribución) / Fase 7 (Lanzamiento)  
**Última actualización:** 2026-10-18

---

## 1. Completado en esta sesión (Fases 0 a 5 — 100% Verificado)

1. [x] **Fase 0 (Honestidad y limpieza):**
   - Ejecutados `cargo test --workspace` (**87/87 tests pasando**, 0 fallos, 0 warnings) y `cargo run --release -p xtask -- bench` en hardware real (**AMD Ryzen 9 3900X 12-Core / 24-Thread, 32 GiB RAM**).
   - Registrada la salida cruda exacta en [`docs/EVIDENCIA.md`](docs/EVIDENCIA.md).
   - Actualizados [`docs/paper/genos_whitepaper.tex`](docs/paper/genos_whitepaper.tex) y [`docs/paper/GENOS_WHITEPAPER.md`](docs/paper/GENOS_WHITEPAPER.md) (v2) con las cifras reales, metodología en user-space, `genos-guard`, pruebas de inclusión de Merkle (`CausalMembershipProof`), URL oficial `https://github.com/genaropass/Gen-OS` y sección de Trabajo Futuro honesta.
2. [x] **Fase 1 (Proxy MCP transparente):**
   - Creado `crates/genos-guard` con cero dependencias externas (`jsonrpc.rs`, `proxy.rs`, `main.rs`) y el servidor de prueba [`echo_mcp_server`](crates/genos-guard/src/bin/echo_mcp_server.rs).
3. [x] **Fase 2 (Política TOML y seguimiento de Taint DIFC):**
   - Implementados `policy.rs` (fail-closed para herramientas desconocidas o archivos inválidos), [`genos.example.toml`](crates/genos-guard/genos.example.toml) y `session.rs` (`decide()` puro + integración con `causal-core` y `capability-engine`).
4. [x] **Fase 3 (Escrow con aprobación humana en `127.0.0.1`):**
   - Implementado `escrow_http.rs` vinculado exclusivamente a `127.0.0.1:<port>`, autenticado por token de sesión de 128 bits, consola web dark-mode en vivo y comandos CLI (`pending`, `approve`, `deny`, `reset`) sin bloquear llamadas no mutantes concurrentes.
5. [x] **Fase 4 (Ledger causal persistente SHA-256 y `why` / `verify`):**
   - Implementado `ledger.rs` con encadenamiento criptográfico `SHA-256(prev_hash || "|" || canonical_json)`, truncamiento seguro de previews a 200 caracteres, `genos-guard why <seq>` y `genos-guard verify`.
6. [x] **Fase 5 (Demo reproducible + Guía Antigravity):**
   - Creados [`examples/prompt-injection-demo/`](examples/prompt-injection-demo/README.md) y [`docs/guard/ANTIGRAVITY.md`](docs/guard/ANTIGRAVITY.md), y verificada la demostración en vivo de punta a punta.

---

## 2. Próximos pasos inmediatos (Fase 6 y 7)

1. [ ] **Usuario (Zenodo):** Subir el paper v2 (`docs/paper/genos_whitepaper.tex` compilado en Overleaf) a Zenodo usando **"New version"** sobre el registro existente si ya publicaste v1.
2. [ ] **Fase 6 (Distribución):**
   - Agregar workflow de GitHub Actions (`.github/workflows/ci.yml`) para correr `cargo test --workspace` en Windows, Linux y macOS.
   - Publicar release `v0.1.0` con binarios precompilados de `genos-guard`.
3. [ ] **Fase 7 (Lanzamiento):**
   - Preparar el post para Hacker News (*Show HN*) y Reddit (`r/rust`, `r/LocalLLaMA`) con el demo de `examples/prompt-injection-demo/`.
