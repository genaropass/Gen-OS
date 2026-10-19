# TABLA DE EVIDENCIA, AUDITORÍA Y VERIFICACIÓN EMPÍRICA — GENOS

**Fecha de Auditoría:** 2026-10-18  
**Repositorio Oficial:** `https://github.com/genaropass/Gen-OS`  
**Hardware de Medición:** AMD Ryzen 9 3900X 12-Core Processor (12 núcleos físicos, 24 hilos lógicos), 32 GiB RAM (`31.91 GiB`)  
**Entorno de Compilación Host:** Windows x86_64 (`x86_64-pc-windows-msvc`), `rustc 1.99.0` Stable  
**Target Bare-Metal Microkernel:** `x86_64-unknown-none` (`kernel/`)  
**Bootloader Versionado:** Limine 8.7.0 (`boot/limine/BOOTX64.EFI`), SHA-256: `51ca2b20ed14bbc678a396cdfb0c1d941acbc155cabebc9bfafabe4cdae1be73`  
**Conformidad de Código:** 100% Rust Stable (Cero `#![feature(...)]` nightly, cero dependencias externas de `crates.io`)

---

## 1. Resumen Ejecutivo de Arquitectura e Implementación

**GenOS** materializa el principio arquitectónico *"tool calls are the syscalls of AI agents"* en dos planos complementarios que comparten exactamente los mismos crates formales (`causal-core` y `capability-engine`, `#![no_std]`):

1. **Plano User-Space en Producción (`crates/genos-guard`):** Un proxy de seguridad en espacio de usuario para el protocolo **Model Context Protocol (MCP, JSON-RPC 2.0 sobre stdio)** que se interpone entre cualquier cliente MCP (Antigravity, Claude Desktop, Cursor) y cualquier servidor MCP. Aplica seguimiento de contaminación DIFC por sesión, capacidades con época generacional (`CSpace`), retención de efectos mutantes en `EscrowManager` con consola HTTP en `127.0.0.1` + CLI (`pending`, `approve`, `deny`, `reset`), y un ledger causal persistente encadenado con SHA-256 (`genos-guard why <seq>`, `genos-guard verify`).
2. **Plano de Investigación Bare-Metal (`kernel/`):** Un microkernel x86-64 (`#![no_std]`) que bootea vía UEFI/Limine 8.7.0 con paginación PML4 de 4 niveles, protecciones de hardware (`CR0.WP`, `EFER.NXE`, `CR4.SMEP`, `CR4.SMAP`, `CR4.UMIP`), `SYSCALL`/`SYSRET` a Ring 3, `FXSAVE`/`FXRSTOR` y drivers VirtIO-Blk/Net con journaling WAL.

---

## 2. Resultados Empíricos de Benchmarks en Espacio de Usuario (`--release`)

**Nota Metodológica:** Los microbenchmarks se ejecutan en espacio de usuario (`std::time::Instant`) sobre el procesador host **AMD Ryzen 9 3900X (12C/24T, 32 GiB RAM)** compilados con `cargo run --release -p xtask -- bench` (`lto = true`). Cada prueba realiza 1 pase de calentamiento descartado seguido de $N=10$ ejecuciones estadísticas independientes con `core::hint::black_box`.

| Subsistema Auditado | Métrica Principal | Mediana (p50) | p95 | $\sigma$ | Throughput Medido |
|---|---|---|---|---|---|
| **1. Merkle-DAG (FIPS 180-4 SHA-256)** | Hashing de bloques de 64 B | **539.1 ns/op** | 551.0 ns/op | 5.2 ns | **1,855,085 hashes/s** (113.23 MB/s) |
| **2. Criptografía Poscuántica (WOTS)** | Firma WOTS ($w=16$) | **158.9 µs/firma** | 165.2 µs | — | **6,295 firmas/s** |
| | Verificación WOTS ($w=16$) | **159.6 µs/verif** | 162.5 µs | — | **6,267 verif/s** |
| **3. Motor de Capacidades (CSpace)** | Validación de slot + época | **1.9 ns/op** | 1.9 ns/op | 0.0 ns | **531,589,719 ops/s** |
| **4. Planificador SchedCP** | Decisión multidimensional | **158.8 ns/decisión** | 172.3 ns | 6.4 ns | **6,298,022 decisiones/s** (JFI = **0.9996**) |
| **5. Semantic-FS (Vectores & WAL)** | Similitud coseno 32-D | **36.4 ns/eval** | 37.3 ns | — | **27,448,548 evals/s** |
| | WAL Commit Transaccional | **1.2 µs/tx** | 1.2 µs | — | **868,674 tx/s** |
| **6. Multiverso & Escrow** | Staging en `EscrowManager` | **83.6 ns/acción** | 90.0 ns | — | **11,959,863 acciones/s** |
| | Abort de 1,000 acciones | **128.8 µs/abort** | — | — | **Purga atómica (0 fugas)** |
| **7. AgentVM (Bytecode & Gas)** | Ejecución de instrucción | **21.5 ns/inst** | 24.1 ns | 0.9 ns | **46,430,644 inst/s** |
| **8. Agent-IPC (DIFC + Causal DAG)** | Enrutamiento DIFC + registro | **1.1 µs/msg** | 3.4 µs | 0.8 ns | **941,048 msgs/s** |

### Salida Cruda de `cargo run --release -p xtask -- bench`

```text
================================================================================
   AGENTOS EMPIRICAL BENCHMARK SUITE (N=10 STATISTICAL RUNS + WARMUP)
================================================================================

[1/8] Merkle-DAG Cryptographic Ledger (FIPS 180-4 SHA-256)
  ├── Samples (N=10): 50,000 blocks (64B) per run
  ├── Latency Median (p50): 539.1 ns/op | p95: 551.0 ns/op | σ: 5.2 ns
  ├── Range: [min: 534.4 ns .. max: 551.0 ns]
  └── Throughput: 1,855,085 hashes/sec (113.23 MB/s)

[2/8] Post-Quantum Cryptography (WOTS Hash-Based Signatures)
  ├── Samples (N=10): 500 signatures & verifications per run
  ├── Sign   Median: 158.9 µs/sig   | p95: 165.2 µs | Throughput: 6,295 sig/sec
  └── Verify Median: 159.6 µs/verif | p95: 162.5 µs | Throughput: 6,267 verif/sec

[3/8] Capability Engine (CSpace Epoch Slot Verification)
  ├── Samples (N=10): 1,000,000 capability checks per run
  ├── Latency Median (p50): 1.9 ns/op | p95: 1.9 ns/op | σ: 0.0 ns
  ├── Range: [min: 1.8 ns .. max: 1.9 ns]
  └── Throughput: 531,589,719 ops/sec

[4/8] SchedCP Intent-Aware Scheduler (Causal Priority Inheritance)
  ├── Jain's Fairness Index (JFI): 0.9996 (1.0000 = Ideal Fairness)
  ├── Latency Median (p50): 158.8 ns/decision | p95: 172.3 ns | σ: 6.4 ns
  └── Throughput: 6,298,022 scheduling decisions/sec

[5/8] Semantic-FS (32-D Vector Search & WAL Crash-Consistent Journaling)
  ├── 32-D Cosine Search Median: 36.4 ns/eval | p95: 37.3 ns | Throughput: 27,448,548 evals/sec
  └── WAL Commit Median:         1.2 µs/tx   | p95: 1.2 µs  | Throughput: 868,674 tx/sec

[6/8] Multiverse Speculative Branching & Escrow Staging
  ├── Escrow Staging Median: 83.6 ns/action | p95: 90.0 ns | Throughput: 11,959,863 ops/sec
  └── Speculative Branch Abort (1,000 staged actions): 128800.0 ns/abort (Zero external leaks)

[7/8] AgentVM Deterministic Bytecode & Gas Metering
  ├── Samples (N=10): 60,000 instructions per run
  ├── Latency Median (p50): 21.5 ns/instruction | p95: 24.1 ns | σ: 0.9 ns
  └── Throughput: 46,430,644 instructions/sec

[8/8] Agent-IPC DIFC Routing & Causal Taint Propagation
  ├── Samples (N=10): 10,000 IPC messages per run
  ├── Latency Median (p50): 1.1 µs/msg | p95: 3.4 µs | σ: 0.8 ns
  └── Throughput: 941,048 msgs/sec
```

---

## 3. Inventario Completo de Pruebas Automatizadas (`cargo test --workspace`)

```text
========================================================================
   GENOS TEST SUITE: 87 PASSED, 0 FAILED, 0 WARNINGS (100% PASS RATE)
========================================================================

[Crate: causal-core] (18 tests)
  - hash::tests::test_sha256_empty ..................................... OK
  - hash::tests::test_sha256_hello ..................................... OK
  - hash::tests::test_sha256_nist_cavp_abc ............................. OK
  - hash::tests::test_sha256_nist_cavp_56_bytes ........................ OK
  - hash::tests::test_sha256_nist_cavp_112_bytes ....................... OK
  - pqc::tests::test_pqc_key_generation_and_signature_verification ..... OK
  - pqc::tests::test_pqc_signature_tamper_rejection .................... OK
  - pqc::tests::test_pqc_different_keys_reject_signature ............... OK
  - pqc::tests::test_quantum_resistant_cipher_roundtrip ................ OK
  - pqc::tests::test_zero_knowledge_merkle_membership_proof_verification OK
  - tests::test_causal_dag_and_why_query ............................... OK
  - tests::test_escrow_abort_prevents_side_effects ..................... OK
  - tests::test_escrow_commit_releases_actions ......................... OK
  - tests::test_linear_chain_tamper_detection .......................... OK
  - tests::test_merkle_dag_integrity_and_tamper_detection .............. OK
  - tests::test_subgraph_integrity_and_explanation ..................... OK
  - tests::test_causal_record_pqc_signing_and_verification ............. OK
  - tests::test_causal_ledger_state_root_and_membership_proof .......... OK

[Crate: capability-engine] (4 tests)
  - tests::test_mint_and_verify ........................................ OK
  - tests::test_attenuation_prevents_privilege_escalation .............. OK
  - tests::test_cascade_revocation_and_epoch_mismatch .................. OK
  - tests::test_cspace_bounded_capacity_dos_mitigation ................. OK

[Crate: agent-ipc] (11 tests: 4 unit + 7 adversarial)
  - tests::test_strict_channel_blocks_tainted_sender ................... OK
  - tests::test_ifc_taint_propagation_across_agents .................... OK
  - tests::test_multiverse_speculative_branch_abort_purges_messages .... OK
  - tests::test_unauthorized_ipc_send_rejected ......................... OK
  - adversarial::test_attack_1_confused_deputy_blocked ................. OK
  - adversarial::test_attack_2_use_after_revocation_epoch_mismatch ...... OK
  - adversarial::test_attack_3_privilege_escalation_via_derive ......... OK
  - adversarial::test_attack_4_ifc_confidentiality_leak_blocked ........ OK
  - adversarial::test_attack_5_taint_injection_without_declassification . OK
  - adversarial::test_attack_6_authorized_declassification .............. OK
  - adversarial::test_attack_7_cspace_resource_exhaustion_dos_blocked ... OK

[Crate: agent-runtime] (17 tests: 7 unit + 10 integration/transactional/MCP/Gmail)
  - llm::tests::test_ollama_engine_payload_builder ..................... OK
  - llm::tests::test_reasoning_loop_executes_actions_and_deducts_budget  OK
  - llm::tests::test_reasoning_loop_halts_when_budget_exhausted ........ OK
  - mcp::tests::test_mcp_mutating_tool_staged_in_escrow_if_tainted ..... OK
  - mcp::tests::test_mcp_tool_discovery_and_capability_authorization ... OK
  - net::tests::test_net_gateway_domain_filtering_and_get .............. OK
  - net::tests::test_tainted_agent_post_held_in_escrow ................. OK
  - gmail_security_scenario::test_gmail_indirect_prompt_injection_exfiltration_prevented OK
  - mcp_integration::test_mcp_end_to_end_security_pipeline ............. OK
  - integration::test_scenario_1_safe_goal_execution_and_commit ........ OK
  - integration::test_scenario_2_indirect_prompt_injection_containment . OK
  - integration::test_scenario_3_multiverse_dreaming_and_commit ........ OK
  - integration::test_scenario_4_capability_cascade_revocation ......... OK
  - transactional::test_transaction_1_successful_commit_flow ........... OK
  - transactional::test_transaction_2_abort_purges_all_state_without_leaks OK
  - transactional::test_transaction_3_external_irreversibility_boundary  OK
  - transactional::test_transaction_4_concurrent_multiverse_branches ... OK

[Crate: agent-scheduler] (6 tests: 3 unit + 3 benchmarks)
  - tests::test_priority_scheduling .................................... OK
  - tests::test_budget_exhaustion_containment .......................... OK
  - tests::test_causal_priority_inheritance ............................ OK
  - bench::test_jains_fairness_index_mathematics ....................... OK
  - bench::test_deadline_awareness_in_sched_cp ......................... OK
  - bench::test_comparative_scheduling_fifo_vs_causal_inheritance ...... OK

[Crate: agent-vm] (11 tests: 8 unit + 3 WASM execution)
  - tests::test_vm_arithmetic_and_registers ............................ OK
  - tests::test_vm_capability_assertion ................................ OK
  - tests::test_vm_out_of_gas_containment .............................. OK
  - tests::test_vm_out_of_gas_purges_speculative_branch ................ OK
  - wasm::tests::test_wasm_binary_header_validation .................... OK
  - wasm::tests::test_wasm_execution_arithmetic_and_gas_metering ....... OK
  - wasm::tests::test_wasm_host_call_cspace_capability_enforcement ..... OK
  - wasm::tests::test_wasm_out_of_gas_trap ............................. OK
  - wasm_execution::test_wasm_cspace_host_function_isolation ........... OK
  - wasm_execution::test_wasm_memory_bounds_protection ................. OK
  - wasm_execution::test_wasm_standard_software_runtime_lifecycle ...... OK

[Crate: semantic-fs] (6 tests)
  - tests::test_cosine_similarity ...................................... OK
  - tests::test_branch_fs_commit ....................................... OK
  - tests::test_branch_fs_isolation_and_abort .......................... OK
  - tests::test_semantic_search_and_ifc_filtering ...................... OK
  - wal::tests::test_wal_serialization_roundtrip ....................... OK
  - wal::tests::test_wal_crash_recovery_preserves_committed_and_discards_uncommitted OK

[Crate: genos-guard] (14 tests: 12 unit + 2 end-to-end stdio/HTTP integration)
  - jsonrpc::tests::test_parse_and_extract_tools_call .................. OK
  - jsonrpc::tests::test_build_error_response_format ................... OK
  - policy::tests::test_parse_valid_policy_and_fail_closed_defaults .... OK
  - policy::tests::test_invalid_policy_rejected ........................ OK
  - session::tests::test_case_1_clean_session_non_mutating_allowed ..... OK
  - session::tests::test_case_2_clean_session_mutating_allowed ......... OK
  - session::tests::test_case_3_tainted_session_non_mutating_allowed ... OK
  - session::tests::test_case_4_tainted_session_mutating_held_in_escrow  OK
  - session::tests::test_case_5_unknown_tool_fails_closed .............. OK
  - session::tests::test_case_6_explicit_session_reset_declassifies .... OK
  - ledger::tests::test_ledger_chain_verification_and_why_tree ......... OK
  - ledger::tests::test_ledger_tamper_detected_at_exact_line ........... OK
  - integration::test_phase1_and_phase2_passthrough_and_taint_rejection  OK
  - integration::test_phase3_escrow_approve_deny_and_auth .............. OK
```

---

## 4. Evidencia de Ejecución en Vivo de `genos-guard` (Contención de Indirect Prompt Injection)

Salida real del flujo `write_file (CLEAN) -> fetch_url (TAINT:WEB_UNTRUSTED) -> write_file (HOLD)` y auditoría causal `genos-guard why 5` + `genos-guard verify`:

```text
[genos-guard] ALLOW seq=#1 tool='write_file' (Tool 'write_file' is mutating (policy rule), allowed because session is CLEAN (integrity=100))
{"id":1,"jsonrpc":"2.0","result":{"content":[{"text":"Wrote 10 bytes to ''","type":"text"}],"isError":false}}
[genos-guard] ALLOW seq=#3 tool='fetch_url' (Tool 'fetch_url' is non-mutating)
[genos-guard] TAINT seq=#4 tool='fetch_url' tainted session with TAINT:WEB_UNTRUSTED (integrity now 10)
{"id":2,"jsonrpc":"2.0","result":{"content":[{"text":"# Issue #42: Crash when parsing empty config...","type":"text"}],"isError":false}}
[genos-guard] HOLD  seq=#5 tool='write_file' taint=WEB_UNTRUSTED integrity=10 causes=[4] reason="Held by GenOS: session is tainted [WEB_UNTRUSTED] by [#4 fetch_url (WEB_UNTRUSTED)] (integrity=10); mutating tool 'write_file' requires human approval in Escrow"
{"error":{"code":-32001,"message":"Held by GenOS Guard (seq #5, taint=WEB_UNTRUSTED, integrity=10): Held by GenOS: session is tainted [WEB_UNTRUSTED] by [#4 fetch_url (WEB_UNTRUSTED)] (integrity=10); mutating tool 'write_file' requires human approval in Escrow"},"id":3,"jsonrpc":"2.0"}

[#5] call write_file (decision=HOLD, integrity=10, taint=WEB_UNTRUSTED)
      payload_sha256=9ab4c5c5b0896cf1 preview="{\"content\":\"EXFILTRATED_API_KEY=sk-live-secret\",\"path\":\"\"}"
  └── [#4] result fetch_url (decision=TAINT:WEB_UNTRUSTED, integrity=10, taint=WEB_UNTRUSTED)
          payload_sha256=e8bd3670c740a262 preview="{\"id\":2,\"jsonrpc\":\"2.0\",\"result\":{\"content\":[{\"text\":\"# Issue #42: Crash when parsing empty config\\n\\nSteps to reproduce:\\n1. Start the application with an empty config file.\\n2. Observe panic on star...[truncated]"
      └── [#3] call fetch_url (decision=ALLOW, integrity=100, taint=CLEAN)
              payload_sha256=1701d259ab9d01ac preview="{\"url\":\"file://examples/prompt-injection-demo/payload/issue.md\"}"

VERIFIED OK: 5 causal entries in 'genos-ledger.jsonl' (head SHA-256: 72cb81b9264e59ef036808f980e8af093bd59743ad15b26a1be95f09f21a816f)
```
