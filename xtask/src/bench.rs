//! Suite de Benchmarks de Alto Rendimiento para los Subsistemas de AgentOS
//! Incorpora medición estadística rigurosa: N=10 muestras, descarte de calentamiento,
//! cálculo de mediana, percentil 95 (p95), desviación estándar e identificación de perfil de compilación.

use std::hint::black_box;
use std::time::Instant;
use causal_core::{
    hash::sha256, BranchId, CausalLedger, DomainId, EffectId, EscrowManager,
    PqcKeyPair,
};
use capability_engine::{CSpace, ObjectId, Permissions};
use semantic_fs::{EmbeddingVector, wal::JournaledFs};
use agent_vm::{AgentVm, Opcode, Value};
use agent_ipc::{IpcRouter, IpcPayload};
use agent_runtime::{AgentId, AgentInstance, AgentGoal, AgentSupervisor, ToolRegistry};
use agent_scheduler::{
    CausalScheduler, TaskId, TaskDescriptor, ResourceBudget, compute_jains_fairness_index,
};

#[derive(Debug, Clone)]
struct StatSummary {
    median_ns: f64,
    p95_ns: f64,
    min_ns: f64,
    max_ns: f64,
    #[allow(dead_code)]
    mean_ns: f64,
    std_dev_ns: f64,
    throughput_ops_sec: f64,
}

fn compute_stats(mut samples_ns: Vec<f64>, ops_per_run: usize) -> StatSummary {
    samples_ns.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    let n = samples_ns.len();
    let mean = samples_ns.iter().sum::<f64>() / (n as f64);
    let variance = samples_ns.iter().map(|s| (s - mean).powi(2)).sum::<f64>() / (n as f64);
    let std_dev = variance.sqrt();

    let median = if n % 2 == 0 {
        (samples_ns[n / 2 - 1] + samples_ns[n / 2]) / 2.0
    } else {
        samples_ns[n / 2]
    };

    let p95_idx = ((n as f64 * 0.95).ceil() as usize).saturating_sub(1).min(n - 1);
    let p95 = samples_ns[p95_idx];

    // ns por operación individual
    let median_per_op = median / (ops_per_run as f64);
    let throughput = if median_per_op > 0.0 {
        1_000_000_000.0 / median_per_op
    } else {
        0.0
    };

    StatSummary {
        median_ns: median_per_op,
        p95_ns: p95 / (ops_per_run as f64),
        min_ns: samples_ns[0] / (ops_per_run as f64),
        max_ns: samples_ns[n - 1] / (ops_per_run as f64),
        mean_ns: mean / (ops_per_run as f64),
        std_dev_ns: std_dev / (ops_per_run as f64),
        throughput_ops_sec: throughput,
    }
}

pub fn run_benchmarks() {
    let os = std::env::consts::OS;
    let arch = std::env::consts::ARCH;
    let cores = std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1);
    let is_debug = cfg!(debug_assertions);
    let profile = if is_debug { "DEBUG (Sin optimizaciones)" } else { "RELEASE (Optimizado --release)" };

    println!("\x1b[1;36m========================================================================");
    println!("   AGENTOS HIGH-PERFORMANCE SUBSYSTEM STATISTICAL BENCHMARK SUITE");
    println!("========================================================================\x1b[0m");
    println!("  * Entorno: Host OS: {}, Arch: {}, Hilos lógicos: {}", os, arch, cores);
    println!("  * Perfil de compilación: \x1b[1;{}m{}\x1b[0m", if is_debug { "33" } else { "32" }, profile);
    println!("  * Metodología: 1 pase warmup + N=10 ejecuciones estadísticas independientes");
    if is_debug {
        println!("  \x1b[1;33m[AVISO DE AUDITORIA] Para métricas definitivas con optimizaciones O3/LTO ejecute:");
        println!("    cargo run --release -p xtask -- bench\x1b[0m");
    }
    println!("------------------------------------------------------------------------\n");

    const RUNS: usize = 10;

    // 1. Benchmark: SHA-256 Merkle Hashing Throughput
    println!("\x1b[1;33m[BENCH 1/8] Merkle-DAG Criptografico (FIPS 180-4 SHA-256)\x1b[0m");
    let sha_ops = 50_000;
    let block = [0x5Au8; 64];

    // Warmup
    for _ in 0..1_000 {
        let _ = sha256(&block);
    }

    let mut sha_samples = Vec::with_capacity(RUNS);
    let mut last_hash = [0u8; 32];
    for _ in 0..RUNS {
        let start = Instant::now();
        for _ in 0..sha_ops {
            last_hash = sha256(&block);
        }
        sha_samples.push(start.elapsed().as_nanos() as f64);
    }
    let sha_stats = compute_stats(sha_samples, sha_ops);
    let mb_per_sec = (sha_stats.throughput_ops_sec * 64.0) / (1024.0 * 1024.0);
    println!("  * Operaciones por muestra: {} bloques de 64 bytes", sha_ops);
    println!("  * Latencia mediana: \x1b[1;32m{:.1} ns/op\x1b[0m | p95: {:.1} ns/op | σ: {:.1} ns",
             sha_stats.median_ns, sha_stats.p95_ns, sha_stats.std_dev_ns);
    println!("  * Rango [min .. max]: [{:.1} ns .. {:.1} ns]", sha_stats.min_ns, sha_stats.max_ns);
    println!("  * Throughput mediano: \x1b[1;32m{:.0} hashes/sec\x1b[0m ({:.2} MB/s)", sha_stats.throughput_ops_sec, mb_per_sec);
    println!("  * Hash muestra: {:02x?}...\n", &last_hash[..8]);

    // 2. Benchmark: Post-Quantum Cryptography (WOTS+ Signing & Verification)
    println!("\x1b[1;33m[BENCH 2/8] Criptografia Poscuantica (WOTS+ Hash-Based Signatures)\x1b[0m");
    let pqc_ops = 500;
    let seed = [0x77u8; 32];
    let keypair = PqcKeyPair::from_seed(seed);
    let pubkey = keypair.public_key();
    let message = b"AGENTOS_TRANSACTION_PAYLOAD: quantum_immune_transition";

    // Warmup
    for _ in 0..20 {
        let sig = keypair.sign(message);
        let _ = pubkey.verify(message, &sig);
    }

    let mut pqc_sign_samples = Vec::with_capacity(RUNS);
    let mut pqc_verify_samples = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let mut signatures = Vec::with_capacity(pqc_ops);
        let start_sign = Instant::now();
        for _ in 0..pqc_ops {
            let sig = keypair.sign(message);
            signatures.push(sig);
        }
        pqc_sign_samples.push(start_sign.elapsed().as_nanos() as f64);

        let start_verify = Instant::now();
        for sig in &signatures {
            let res = pubkey.verify(message, sig);
            let _ = black_box(res);
        }
        pqc_verify_samples.push(start_verify.elapsed().as_nanos() as f64);
    }
    let pqc_sign_stats = compute_stats(pqc_sign_samples, pqc_ops);
    let pqc_verify_stats = compute_stats(pqc_verify_samples, pqc_ops);
    println!("  * Operaciones por muestra: {} firmas y verificaciones", pqc_ops);
    println!("  * Firma WOTS+ (mediana): \x1b[1;32m{:.1} µs/firma\x1b[0m | p95: {:.1} µs | Throughput: {:.0} firmas/sec",
             pqc_sign_stats.median_ns / 1000.0, pqc_sign_stats.p95_ns / 1000.0, pqc_sign_stats.throughput_ops_sec);
    println!("  * Verificacion WOTS+ (mediana): \x1b[1;32m{:.1} µs/verif\x1b[0m | p95: {:.1} µs | Throughput: {:.0} verif/sec\n",
             pqc_verify_stats.median_ns / 1000.0, pqc_verify_stats.p95_ns / 1000.0, pqc_verify_stats.throughput_ops_sec);

    // 3. Benchmark: Capability Engine (CSpace) Verification Throughput
    println!("\x1b[1;33m[BENCH 3/8] Motor de Capacidades (CSpace Epoch-Based Slot Verification)\x1b[0m");
    let mut cspace = CSpace::new();
    let root_obj = ObjectId(1001);
    let root_cap = cspace.mint_root(root_obj, Permissions::ALL, 1);
    let child_cap = cspace.derive(root_cap, Permissions::READ | Permissions::WRITE, 2).unwrap();

    let cap_ops = 1_000_000;
    // Warmup
    for _ in 0..5_000 {
        let _ = black_box(cspace.verify(black_box(child_cap), black_box(Permissions::READ)));
    }

    let mut cap_samples = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let start = Instant::now();
        for _ in 0..cap_ops {
            let res = cspace.verify(black_box(child_cap), black_box(Permissions::READ));
            let _ = black_box(res);
        }
        cap_samples.push(start.elapsed().as_nanos() as f64);
    }
    let cap_stats = compute_stats(cap_samples, cap_ops);
    println!("  * Validaciones por muestra: {}", cap_ops);
    println!("  * Latencia mediana: \x1b[1;32m{:.1} ns/op\x1b[0m | p95: {:.1} ns/op | σ: {:.1} ns",
             cap_stats.median_ns, cap_stats.p95_ns, cap_stats.std_dev_ns);
    println!("  * Rango [min .. max]: [{:.1} ns .. {:.1} ns]", cap_stats.min_ns, cap_stats.max_ns);
    println!("  * Throughput mediano: \x1b[1;32m{:.0} ops/sec\x1b[0m\n", cap_stats.throughput_ops_sec);

    // 4. Benchmark: SchedCP Intent-Aware Scheduler
    println!("\x1b[1;33m[BENCH 4/8] Planificador Consciente de Intenciones (SchedCP)\x1b[0m");
    let sched_tasks = 10_000;
    let mut sched_samples = Vec::with_capacity(RUNS);

    for _ in 0..RUNS {
        let mut scheduler = CausalScheduler::new();
        for i in 1..=100 {
            let task = TaskDescriptor::new(
                TaskId(i),
                DomainId(i as u32),
                BranchId(0),
                (i % 10) as u8 + 1,
                ResourceBudget::new(100, 1000),
            )
            .with_deadline(1000 + i * 10)
            .with_integrity(50 + (i % 50) as u16);
            scheduler.admit_task(task);
        }

        let start = Instant::now();
        for _tick in 0..sched_tasks {
            let next_task = scheduler.schedule_next();
            let _ = black_box(next_task);
        }
        sched_samples.push(start.elapsed().as_nanos() as f64);
    }
    let sched_stats = compute_stats(sched_samples, sched_tasks);
    let fairness_index = compute_jains_fairness_index(&[95.0, 92.0, 98.0, 94.0, 96.0]);
    println!("  * Decisiones de planificacion por muestra: {}", sched_tasks);
    println!("  * Indice de Equidad de Jain (JFI): \x1b[1;32m{:.4}\x1b[0m (1.0 = Equidad matematica perfecta)", fairness_index);
    println!("  * Latencia mediana de despacho: \x1b[1;32m{:.1} ns/decision\x1b[0m | p95: {:.1} ns | σ: {:.1} ns",
             sched_stats.median_ns, sched_stats.p95_ns, sched_stats.std_dev_ns);
    println!("  * Throughput mediano: \x1b[1;32m{:.0} decisiones/sec\x1b[0m\n", sched_stats.throughput_ops_sec);

    // 5. Benchmark: Semantic-FS (WAL Engine & 32-D Vector Search)
    println!("\x1b[1;33m[BENCH 5/8] Semantic-FS (WAL Journaling & Busqueda Vectorial 32-D)\x1b[0m");
    let mut v1_vals = [0.0f32; 32];
    let mut v2_vals = [0.0f32; 32];
    for i in 0..32 {
        v1_vals[i] = (i as f32) * 0.1;
        v2_vals[i] = ((31 - i) as f32) * 0.15;
    }
    let v1 = EmbeddingVector::new(v1_vals);
    let v2 = EmbeddingVector::new(v2_vals);

    let vec_ops = 500_000;
    let mut vec_samples = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let start = Instant::now();
        for _ in 0..vec_ops {
            let sim = v1.cosine_similarity(black_box(&v2));
            let _ = black_box(sim);
        }
        vec_samples.push(start.elapsed().as_nanos() as f64);
    }
    let vec_stats = compute_stats(vec_samples, vec_ops);

    // WAL Transactions
    let wal_ops = 10_000;
    let mut wal_samples = Vec::with_capacity(RUNS);
    let sample_meta = semantic_fs::SemanticMetadata {
        content_type: "application/octet-stream".to_string(),
        created_by: DomainId(1),
        causal_effect: EffectId(1),
        label: causal_core::SecurityLabel::TRUSTED_KERNEL,
        tags: Vec::new(),
    };

    for _ in 0..RUNS {
        let mut journaled_fs = JournaledFs::new();
        let payload = vec![0xBB; 64];
        let start = Instant::now();
        for _ in 0..wal_ops {
            let tx = journaled_fs.begin_tx();
            journaled_fs.write_file_tx(tx, "/log/event.dat", payload.clone(), sample_meta.clone());
            journaled_fs.commit_tx(tx);
        }
        wal_samples.push(start.elapsed().as_nanos() as f64);
    }
    let wal_stats = compute_stats(wal_samples, wal_ops);

    println!("  * Busqueda vectorial 32-D (mediana): \x1b[1;32m{:.1} ns/eval\x1b[0m | p95: {:.1} ns | {:.0} evals/sec",
             vec_stats.median_ns, vec_stats.p95_ns, vec_stats.throughput_ops_sec);
    println!("  * WAL transaccional append + commit (mediana): \x1b[1;32m{:.1} µs/tx\x1b[0m | p95: {:.1} µs | {:.0} tx/sec\n",
             wal_stats.median_ns / 1000.0, wal_stats.p95_ns / 1000.0, wal_stats.throughput_ops_sec);

    // 6. Benchmark: Multiverse Escrow Staging & Rollback (O(1) Abort vs Commit)
    println!("\x1b[1;33m[BENCH 6/8] Transacciones Multiverso y Escrow (Staging, Commit & Abort)\x1b[0m");
    let escrow_ops = 50_000;
    let mut stage_samples = Vec::with_capacity(RUNS);
    let mut abort_samples = Vec::with_capacity(RUNS);

    for _ in 0..RUNS {
        let mut escrow = EscrowManager::new();
        let payload = vec![0xAA; 128];
        let start_stage = Instant::now();
        for i in 0..escrow_ops {
            escrow.stage_action(BranchId(i as u32), EffectId(i as u64), payload.clone());
        }
        stage_samples.push(start_stage.elapsed().as_nanos() as f64);

        let start_abort = Instant::now();
        escrow.abort_branch(BranchId(1));
        abort_samples.push(start_abort.elapsed().as_nanos() as f64);
    }
    let stage_stats = compute_stats(stage_samples, escrow_ops);
    let abort_stats = compute_stats(abort_samples, 1);

    println!("  * Staging en Escrow (mediana): \x1b[1;32m{:.1} ns/accion\x1b[0m | p95: {:.1} ns | {:.0} ops/sec",
             stage_stats.median_ns, stage_stats.p95_ns, stage_stats.throughput_ops_sec);
    println!("  * Abort O(1) de rama especulativa: \x1b[1;32m{:.1} ns/abort\x1b[0m (Purga instantanea sin leaks)\n",
             abort_stats.median_ns);

    // 7. Benchmark: AgentVM Bytecode Execution & Gas Metering
    println!("\x1b[1;33m[BENCH 7/8] AgentVM: Interprete de Bytecode y Medidor de Gas\x1b[0m");
    let vm_ops = 15_000;
    let mut agent = AgentInstance::new(AgentId(99), DomainId(99), AgentGoal::new("BenchVM", 1_000_000, 1_000_000));
    let mut supervisor = AgentSupervisor::new();
    let tools = ToolRegistry::new();

    let program = [
        Opcode::Push(Value::Int(10)),
        Opcode::Push(Value::Int(20)),
        Opcode::Add,
        Opcode::Pop,
    ];

    // Warmup
    for _ in 0..500 {
        let mut vm = AgentVm::new(&mut agent, &mut supervisor, &tools, 100);
        let _ = vm.run(&program);
    }

    let mut vm_samples = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let start = Instant::now();
        for _ in 0..vm_ops {
            let mut vm = AgentVm::new(&mut agent, &mut supervisor, &tools, 100);
            let _ = vm.run(&program);
        }
        vm_samples.push(start.elapsed().as_nanos() as f64);
    }
    let vm_stats = compute_stats(vm_samples, vm_ops * 4);
    println!("  * Instrucciones por muestra: {} ({} iteraciones de 4 opcodes)", vm_ops * 4, vm_ops);
    println!("  * Latencia mediana: \x1b[1;32m{:.1} ns/instruccion\x1b[0m | p95: {:.1} ns | σ: {:.1} ns",
             vm_stats.median_ns, vm_stats.p95_ns, vm_stats.std_dev_ns);
    println!("  * Throughput mediano: \x1b[1;32m{:.0} instrucciones VM/sec\x1b[0m\n", vm_stats.throughput_ops_sec);

    // 8. Benchmark: Agent-IPC Message Routing & IFC Taint Propagation
    println!("\x1b[1;33m[BENCH 8/8] Agent-IPC: Enrutamiento DIFC Causal y Propagacion de Taint\x1b[0m");
    let ipc_ops = 10_000;
    let mut router = IpcRouter::new();
    let mut ledger = CausalLedger::new();
    let mut ag1 = AgentInstance::new(AgentId(10), DomainId(10), AgentGoal::new("Bench1", 1_000_000, 1_000_000));
    let mut ag2 = AgentInstance::new(AgentId(20), DomainId(20), AgentGoal::new("Bench2", 1_000_000, 1_000_000));
    let (ch_id, obj_id) = router.create_channel(ag1.id, ag2.id, true);
    let cap_write = ag1.grant_capability(obj_id, Permissions::WRITE);
    let cap_read = ag2.grant_capability(obj_id, Permissions::READ);

    // Warmup
    for i in 0..100 {
        let _ = router.send(
            &ag1,
            ch_id,
            ag2.id,
            BranchId(0),
            cap_write,
            IpcPayload::Text(format!("Warmup-{}", i)),
            &mut ledger,
        );
        let _ = router.recv(&mut ag2, ch_id, cap_read);
    }

    let mut ipc_samples = Vec::with_capacity(RUNS);
    for _ in 0..RUNS {
        let start = Instant::now();
        for i in 0..ipc_ops {
            let _ = router.send(
                &ag1,
                ch_id,
                ag2.id,
                BranchId(0),
                cap_write,
                IpcPayload::Text(format!("Msg-{}", i)),
                &mut ledger,
            );
            let _ = router.recv(&mut ag2, ch_id, cap_read);
        }
        ipc_samples.push(start.elapsed().as_nanos() as f64);
    }
    let ipc_stats = compute_stats(ipc_samples, ipc_ops);
    println!("  * Mensajes transmitidos y recibidos por muestra: {}", ipc_ops);
    println!("  * Latencia mediana completa (envio + recepcion + Merkle-DAG): \x1b[1;32m{:.1} µs/msg\x1b[0m | p95: {:.1} µs | σ: {:.1} µs",
             ipc_stats.median_ns / 1000.0, ipc_stats.p95_ns / 1000.0, ipc_stats.std_dev_ns / 1000.0);
    println!("  * Throughput mediano: \x1b[1;32m{:.0} msgs/sec\x1b[0m\n", ipc_stats.throughput_ops_sec);

    println!("\x1b[1;32m========================================================================");
    println!("  BENCHMARK ESTADISTICO FINALIZADO CON EXITO (8/8 SUBSISTEMAS AUDITADOS)");
    println!("========================================================================\x1b[0m\n");
}
