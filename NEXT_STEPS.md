# Próximos pasos

> Archivo vivo. El agente que trabaje en el proyecto lo actualiza **al terminar cada sesión**.
> El plan completo está en [`docs/ROADMAP.md`](docs/ROADMAP.md).

**Fase actual:** Fase 6 completada (`genos-sentinel` + CI multiplataforma) / Fase 7 (Lanzamiento)  
**Última actualización:** 2026-10-31

---

## 1. Completado en esta sesión (Fases 0 a 6 + `genos-sentinel` — 100% Verificado, 94/94 Tests)

1. [x] **Fase 0 (Honestidad y limpieza):**
   - Ejecutados `cargo test --workspace` (**94/94 tests pasando**, 0 fallos, 0 warnings) y `cargo run --release -p xtask -- bench` en hardware real (**AMD Ryzen 9 3900X 12-Core / 24-Thread, 32 GiB RAM**).
   - Registrada la salida cruda exacta en [`docs/EVIDENCIA.md`](docs/EVIDENCIA.md).
   - Actualizados [`docs/paper/genos_whitepaper.tex`](docs/paper/genos_whitepaper.tex) y [`docs/paper/GENOS_WHITEPAPER.md`](docs/paper/GENOS_WHITEPAPER.md) (v2).
2. [x] **Fases 1 a 5 (`genos-guard` — Proxy MCP de Seguridad en Vivo):**
   - Implementados `jsonrpc.rs`, `policy.rs`, `session.rs`, `escrow_http.rs`, `ledger.rs`, `proxy.rs`, `main.rs`, demo reproducible en [`examples/prompt-injection-demo/`](examples/prompt-injection-demo/README.md) y guía en [`docs/guard/ANTIGRAVITY.md`](docs/guard/ANTIGRAVITY.md).
3. [x] **`crates/genos-sentinel` (Anillo 1: GenOS Shield + Anillo 2: GenOS Sentinel Anti-Lazarus):**
   - **Anillo 1 (`shield.rs` — Perímetro Zero-Trust):** Listas blancas IPv4/CIDR por nodo (`Ipv4Cidr`), registro de binarios firmados criptográficamente (`SignedBinaryManifest` + `BinaryIntegrityRegistry`), y sobres de petición firmados con clave poscuántica WOTS (`SignedPeerEnvelope`) con `nonce` monótono anti-replay y ventana TTL.
   - **Anillo 2A (`txdecode.rs` — Decodificador Independiente Anti-Blind-Signing):** Inspección de bytes crudos para detectar delegaciones EIP-7702 (`0x04` SetCode), `DELEGATECALL` (`operation == 1`) en `execTransaction` de Safe{Wallet}, engaño de interfaz web (`ClaimedUiSummary` vs bytes reales), aprobaciones ilimitadas ERC-20 y anomalías de comisión en PSBTs de Bitcoin.
   - **Anillo 2B (`policy.rs` — Velocity Limiter & Circuit Breaker):** Ventana deslizante de 1 hora por cadena y congelamiento global automático (`CircuitState::Frozen`) ante cualquier intento prohibido o exceso de velocidad.
   - **Anillo 2C (`quorum.rs` + `sentinel.rs` — Quórum Criptográfico M-de-N y Ledger Firmado):** Separación de roles (anti-auto-aprobación), verificación de firmas M-de-N sobre `ApprovalCommitment`, co-firma obligatoria `SentinelCoSignature` y `SignedAuditLedger` resistente a ataques de reescritura completa de disco.
4. [x] **Fase 6 (CI Multiplataforma):**
   - Creado [`.github/workflows/ci.yml`](.github/workflows/ci.yml) ejecutando `cargo test --workspace` y `cargo run -p genos-sentinel -- redteam` en Ubuntu, Windows y macOS.

---

## 2. Próximos pasos inmediatos (Fase 7)

1. [ ] **Usuario (Zenodo):** Subir el paper v2 (`docs/paper/genos_whitepaper.tex` compilado en Overleaf) a Zenodo usando **"New version"** sobre el registro existente si ya publicaste v1.
2. [ ] **Fase 7 (Lanzamiento):**
   - Publicar release `v0.2.0` en GitHub con `genos-guard` y `genos-sentinel`.
   - Compartir la suite Red-Team (`cargo run -p genos-sentinel -- redteam`) y el demo de MCP (`examples/prompt-injection-demo/`).
