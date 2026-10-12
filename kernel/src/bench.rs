//! Microbenchmarking interno del kernel mediante el Time Stamp Counter (RDTSC)
//! Mide con precisión de ciclo de CPU de hardware:
//! - Latencia de lectura base de TSC
//! - Latencia de despacho de llamadas al sistema (int 0x80)
//! - Hashing criptográfico de bloques Merkle-DAG en Ring 0
//! - Verificación de capacidades en CSpace

use crate::arch::rdtsc;
use crate::println;

pub fn run_kernel_benchmarks() {
    println!("\n\x1b[1;36m========================================================");
    println!("  AGENTOS RING 0 RDTSC HARDWARE MICROBENCHMARKS");
    println!("========================================================\x1b[0m");

    // 1. Sobrecarga base de lectura de rdtsc
    let t0 = rdtsc();
    let t1 = rdtsc();
    let rdtsc_overhead = t1.saturating_sub(t0);
    println!("  * Sobrecarga base de rdtsc: {} ciclos CPU", rdtsc_overhead);

    // 2. Syscall int 0x80 roundtrip latency
    let start_sc = rdtsc();
    let sys_ret: i64;
    unsafe {
        core::arch::asm!(
            "int 0x80",
            inout("rax") crate::syscall::SYS_EFFECT_LOG => sys_ret,
            in("rdi") 0u64,
            in("rsi") 0u64,
            in("rdx") 0u64,
            in("r10") 0u64,
            options(nostack)
        );
    }
    let end_sc = rdtsc();
    let sc_cycles = end_sc.saturating_sub(start_sc).saturating_sub(rdtsc_overhead);
    println!("  * Syscall int 0x80 roundtrip: \x1b[1;32m{} ciclos CPU\x1b[0m (Retorno: {})", sc_cycles, sys_ret);

    // 3. Merkle SHA-256 en Ring 0 (bloque 64 bytes)
    let block = [0x5Au8; 64];
    let start_sha = rdtsc();
    let hash = causal_core::hash::sha256(&block);
    let end_sha = rdtsc();
    let sha_cycles = end_sha.saturating_sub(start_sha).saturating_sub(rdtsc_overhead);
    println!("  * SHA-256 Ring 0 (bloque 64B): \x1b[1;32m{} ciclos CPU\x1b[0m (Muestra: {:02x?}...)", sha_cycles, &hash[..4]);

    // 4. Verificación de capacidad en CSpace
    let mut cspace = capability_engine::CSpace::new();
    let root = cspace.mint_root(capability_engine::ObjectId(1), capability_engine::Permissions::ALL, 0);
    let child = cspace.derive(root, capability_engine::Permissions::READ, 1).unwrap();
    let start_cap = rdtsc();
    let _ = cspace.verify(child, capability_engine::Permissions::READ);
    let end_cap = rdtsc();
    let cap_cycles = end_cap.saturating_sub(start_cap).saturating_sub(rdtsc_overhead);
    println!("  * CSpace slot verify: \x1b[1;32m{} ciclos CPU\x1b[0m", cap_cycles);

    println!("========================================================\x1b[0m\n");
}
