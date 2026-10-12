# GenOS 🪐
### The AI-Native Operating System with Hardware Isolation, Causal Merkle-DAG, and Post-Quantum Security
*Created by Genaro Agustín Passero*

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Build: x86_64](https://img.shields.io/badge/Architecture-x86__64%20Bare--Metal-blue.svg)]()
[![Rust Stable: 1.99.0](https://img.shields.io/badge/Rust-1.99.0%20Stable-orange.svg)]()
[![Tests: 57/57 Passed](https://img.shields.io/badge/Tests-57%2F57%20Passed%20(100%25)-green.svg)]()

**GenOS** is an experimental, purpose-built operating system written in pure Rust (`no_std` microkernel, `std` runtime) where **Autonomous AI Agents are native first-class OS citizens**, not conventional user applications.

Unlike traditional operating systems (Windows, Linux) designed decades ago for human interaction, GenOS provides hardware-enforced sandboxing, capability-based security, decentralized information flow control (DIFC), speculative transactional multiverse execution with $O(1)$ rollbacks, and quantum-safe cryptographic audit trails.

---

## ⚡ Highlights & Key Capabilities

- **Bare-Metal x86-64 Microkernel (`no_std`):**
  - UEFI Booting via pinned Limine 8.7.0 (`BOOTX64.EFI`).
  - 4-level Paging (PML4) with per-agent `AddressSpace` memory isolation.
  - Hardware protections enforced: `CR0.WP`, `EFER.NXE` ($W \oplus X$), `CR4.SMEP`, `CR4.SMAP`, `CR4.UMIP`.
  - True Ring 3 user-space transitions with hardware `SYSCALL`/`SYSRET` MSRs and SMAP-guarded uaccess.
  - 512-byte `FXSAVE`/`FXRSTOR` FPU/SSE context switching.
  - Recyclable Physical Memory Manager (PMM) with frame free-list.
- **Multiverse & Escrow Transactions:**
  - Speculative branch execution with instant $O(1)$ rollback.
  - External irreversibility barrier: side-effects staged in `EscrowManager` until explicit commit.
- **Adversarial Security & DIFC:**
  - Bell-LaPadula & Biba decentralized lattice information flow control (DIFC).
  - Generational capability IDs (`CapId(slot, generation)`) eliminating Use-After-Revocation.
  - Taint tracking mitigating indirect prompt injection attacks.
- **Post-Quantum Cryptography (PQC) & Zero-Knowledge Proofs:**
  - Hash-based Winternitz One-Time Signatures (WOTS+, $w=16$), provably immune to Shor's algorithm (1994) and resistant to Grover (1996) with 128 bits of quantum security.
  - Zero-Knowledge Merkle Membership Proofs (`CausalMembershipProof`) enabling external verification without leaking private agent data.
- **Persistent Storage & VirtIO:**
  - PCI VirtIO-Blk driver with sector LBA I/O and resilient 512 KiB ramdisk fallback.
  - Write-Ahead Logging (WAL) engine with `AGENTWAL` headers, 32-bit FNV-1a checksums, atomic `CommitTx`/`AbortTx`, and automatic crash recovery.
- **Intent-Aware Scheduling (SchedCP):**
  - Multi-dimensional task scheduler factoring in Earliest Deadline First (EDF), integrity levels, and Causal Priority Inheritance (CPI) defeating priority inversion.
  - Measured Jain's Fairness Index of **0.9996** (1.0 = ideal mathematical fairness).

---

## 📊 Empirical Benchmarks (Release Mode)

Evaluated across $N=10$ independent statistical runs with warm-up eviction and LLVM optimization barrier:

| Subsystem | Metric | Median (p50) | Percentile 95 (p95) | Peak Throughput |
|---|---|---|---|---|
| **Merkle-DAG (SHA-256)** | Hashing Latency | **578.0 ns/op** | 585.7 ns/op | **1.73M hashes/sec** (105.6 MB/s) |
| **PQC Signatures (WOTS+)** | Sign Latency | **189.5 µs/sig** | 195.1 µs/sig | **5,278 signatures/sec** |
| | Verify Latency | **145.2 µs/verify**| 148.0 µs/verify | **6,888 verifications/sec** |
| **Capability Engine (CSpace)**| Verification Latency | **1.9 ns/op** | 1.9 ns/op | **519,035,632 validations/sec**|
| **Scheduler (SchedCP)** | Decision Latency | **158.4 ns/decision**| 187.9 ns/decision | **6,314,128 decisions/sec** |
| **Semantic-FS (32-D Cosine)** | Vector Similarity | **38.0 ns/eval** | 38.3 ns/eval | **26,325,835 searches/sec** |
| **Storage (WAL Commit)** | Transaction Commit | **1.2 µs/tx** | 1.3 µs/tx | **829,483 tx/sec** |
| **Multiverse Escrow** | Action Staging | **91.8 ns/action** | 97.3 ns/action | **10,895,145 actions/sec** |
| | Speculative Abort | **$O(1)$ Instant** | $O(1)$ Instant | Zero state leakage |
| **AgentVM** | Bytecode Evaluation | **19.4 ns/instruction**| 23.0 ns/instruction | **51,646,223 inst/sec** |
| **Agent-IPC** | DIFC Routing + DAG | **0.9 µs/msg** | 3.4 µs/msg | **1,074,229 msgs/sec** |

---

## 🚀 Quick Start

### 1. Diagnostics & Toolchain Check
```powershell
cargo xtask doctor
```

### 2. Run Comprehensive Test Suite (57/57 Tests)
```powershell
cargo test --workspace
```

### 3. Run Statistical Benchmarks
```powershell
cargo run --release -p xtask -- bench
```

### 4. Interactive Operator Shell
```powershell
cargo xtask shell
```

### 5. Build Kernel & Assemble UEFI ESP Partition
```powershell
cargo xtask build
```

### 6. Boot in Virtual Machine (QEMU with UEFI)
```powershell
cargo xtask run
```

---

## 📜 Documentation

- [Detailed Evidence & Audit Log (`docs/EVIDENCIA.md`)](docs/EVIDENCIA.md)
- [System Architecture & Roadmap (`docs/STATUS.md`)](docs/STATUS.md)
- [Causal Microkernel Specification (`docs/SPEC_CAUSAL_KERNEL.md`)](docs/SPEC_CAUSAL_KERNEL.md)

---

## ⚖️ License

GenOS is released under the **MIT License**. See [LICENSE](LICENSE) for details.
