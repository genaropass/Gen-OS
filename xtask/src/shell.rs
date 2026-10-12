//! Shell Interactivo de Operador para AgentOS
//! Permite interactuar directamente en consola con los 6 subsistemas nativos:
//! - Agentes (spawn, inspección, taint tracking)
//! - Grafo Causal (why queries, verificación Merkle-DAG)
//! - Multiverso (fork, commit, abort)
//! - BranchFS (escritura y búsqueda vectorial semántica)
//! - Bus IPC (mensajería con verificación de capacidades)
//! - Benchmarks y máquina virtual

use std::io::{self, Write};
use causal_core::{CausalLedger, DomainId, BranchId, EffectId, SecurityLabel, Reversibility};
use capability_engine::Permissions;
use agent_runtime::{AgentId, AgentGoal, AgentInstance, AgentSupervisor, ToolRegistry};
use semantic_fs::{BranchFs, SemanticMetadata, EmbeddingVector};
use agent_ipc::{IpcRouter, IpcPayload};
use agent_vm::{AgentVm, Opcode, Value};

pub fn run_interactive_shell() {
    println!("\x1b[1;36m");
    println!("========================================================================");
    println!("   ___                    _    ___  ____  ");
    println!("  / _ \\                  | |  / _ \\/ ___| ");
    println!(" / /_\\ \\ __ _  ___ _ __  | |_| | | \\___ \\ ");
    println!(" |  _  |/ _` |/ _ \\ '_ \\ | __| | | |___) |");
    println!(" |_| |_|\\__, |\\___|_| |_| \\__|\\___/|____/ ");
    println!("         __/ |                            ");
    println!("        |___/                             ");
    println!("   AGENTOS OPERATOR SHELL — TERMINAL DE CONTROL INTERACTIVO");
    println!("   Escribe 'help' para ver la lista de comandos o 'demo' para la suite.");
    println!("========================================================================\x1b[0m\n");

    let mut ledger = CausalLedger::new();
    let mut supervisor = AgentSupervisor::new();
    let tools = ToolRegistry::new();
    let mut router = IpcRouter::new();
    let mut fs = BranchFs::new();
    let mut agents: Vec<AgentInstance> = Vec::new();
    let mut next_agent_id = 1u32;
    let mut current_branch = BranchId(0);

    // Sembrar dos agentes iniciales y un canal de comunicación
    let mut ag1 = AgentInstance::new(
        AgentId(next_agent_id),
        DomainId(next_agent_id),
        AgentGoal::new("Investigador Web", 20, 2000),
    );
    next_agent_id += 1;

    let mut ag2 = AgentInstance::new(
        AgentId(next_agent_id),
        DomainId(next_agent_id),
        AgentGoal::new("Analista Financiero", 15, 1500),
    );
    next_agent_id += 1;

    let (_ch_id, obj_id) = router.create_channel(ag1.id, ag2.id, true);
    let _cap1 = ag1.grant_capability(obj_id, Permissions::WRITE);
    let _cap2 = ag2.grant_capability(obj_id, Permissions::READ);

    agents.push(ag1);
    agents.push(ag2);

    // Sembrar archivo inicial en BranchFS
    let meta = SemanticMetadata {
        content_type: "text/plain".into(),
        created_by: DomainId(0),
        causal_effect: EffectId(0),
        label: SecurityLabel::TRUSTED_KERNEL,
        tags: vec!["seguridad".into(), "escrow".into()],
    };
    fs.write_file(
        BranchId(0),
        "protocolo_seguridad.txt",
        b"Las acciones irreversibles deben ser puestas en Escrow antes de su confirmacion.".to_vec(),
        Some(EmbeddingVector::new([0.8; 32])),
        meta,
    );

    loop {
        print!("\x1b[1;32mAgentOS [Branch:{}] > \x1b[0m", current_branch.0);
        let _ = io::stdout().flush();

        let mut input = String::new();
        if io::stdin().read_line(&mut input).is_err() {
            break;
        }

        let trimmed = input.trim();
        if trimmed.is_empty() {
            continue;
        }

        let mut parts = trimmed.split_whitespace();
        let cmd = parts.next().unwrap_or("");
        let rest: Vec<&str> = parts.collect();

        match cmd {
            "help" => {
                println!("\x1b[1;33mComandos disponibles en el Shell de AgentOS:\x1b[0m");
                println!("  status                      - Muestra telemetría global del sistema");
                println!("  agents                      - Lista los agentes activos y su estado IFC");
                println!("  spawn <nombre> [pasos]      - Instancia un nuevo agente nativo");
                println!("  taint <agent_id>            - Simula inyección externa contaminando al agente");
                println!("  ipc send <from> <to> <txt>  - Envía mensaje IPC con comprobación de capacidades e IFC");
                println!("  fs list                     - Lista archivos en BranchFS");
                println!("  fs put <nombre> <texto>     - Almacena un archivo con embedding semántico");
                println!("  fs search                   - Realiza búsqueda vectorial por similitud de coseno");
                println!("  why <effect_id>             - Traza la genealogía causal retrospectiva de una acción");
                println!("  verify                      - Verifica la integridad criptográfica del Merkle-DAG");
                println!("  fork <branch_id>            - Crea/cambia a una rama especulativa del Multiverso");
                println!("  commit [branch_id]          - Confirma atómicamente una rama del Multiverso");
                println!("  abort [branch_id]           - Descarta en O(1) una rama especulativa");
                println!("  vm eval                     - Ejecuta un programa de bytecode AVM con gas");
                println!("  bench                       - Ejecuta la suite de microbenchmarks");
                println!("  demo                        - Ejecuta la demostración automatizada completa");
                println!("  clear                       - Limpia la pantalla");
                println!("  exit                        - Sale del Shell interactivo");
            }
            "status" => {
                println!("\x1b[1;34m[TELEMETRIA AGENTOS]\x1b[0m");
                println!("  * Rama actual del Multiverso: {:?}", current_branch);
                println!("  * Agentes registrados: {}", agents.len());
                println!("  * Acciones pendientes en Escrow: {}", supervisor.escrow.pending_count());
                println!("  * Verificacion Merkle-DAG: \x1b[1;32m{}\x1b[0m", if ledger.verify_merkle_integrity() { "INTEGRO (100%)" } else { "CORRUPTO" });
            }
            "agents" => {
                println!("\x1b[1;33m--- AGENTES NATIVOS ACTIVOS ---\x1b[0m");
                for a in &agents {
                    let taint_str = if a.is_tainted() {
                        "\x1b[1;31mTAINTED (Contaminado / Untrusted)\x1b[0m"
                    } else {
                        "\x1b[1;32mCLEAN (Trusted Kernel)\x1b[0m"
                    };
                    println!("  [ID:{:?}] {} | Pasos: {}/{} | Tokens: {}/{} | Estado IFC: {}",
                        a.id.0, a.goal.description, a.step_count, a.goal.max_steps, a.tokens_used, a.goal.max_tokens, taint_str);
                }
            }
            "spawn" => {
                if rest.is_empty() {
                    println!("\x1b[1;31mUso: spawn <nombre_objetivo> [max_pasos]\x1b[0m");
                    continue;
                }
                let name = rest[0];
                let steps = rest.get(1).and_then(|s| s.parse().ok()).unwrap_or(10);
                let new_ag = AgentInstance::new(
                    AgentId(next_agent_id),
                    DomainId(next_agent_id),
                    AgentGoal::new(name, steps, steps * 100),
                );
                next_agent_id += 1;
                println!("\x1b[1;32m[+] Agente '{:?}' instanciado exitosamente (ID: {}).\x1b[0m", new_ag.goal.description, new_ag.id.0);
                agents.push(new_ag);
            }
            "taint" => {
                let id: u32 = match rest.first().and_then(|s| s.parse().ok()) {
                    Some(v) => v,
                    None => {
                        println!("\x1b[1;31mUso: taint <agent_id>\x1b[0m");
                        continue;
                    }
                };

                if let Some(ag) = agents.iter_mut().find(|a| a.id.0 == id) {
                    let effect_id = ledger.record_effect(
                        current_branch,
                        ag.domain,
                        DomainId(0),
                        vec![],
                        SecurityLabel::UNTRUSTED_EXTERNAL,
                        Reversibility::PurelyReversible,
                        [0xEE; 32],
                    );
                    ag.observe("Inyeccion hostil simulada desde fuente externa", SecurityLabel::UNTRUSTED_EXTERNAL, effect_id);
                    println!("\x1b[1;31m[!] Agente ID:{} contaminado por IFC! Estado: TAINTED (EffectId: {:?})\x1b[0m", id, effect_id);
                } else {
                    println!("\x1b[1;31mError: Agente con ID {} no encontrado.\x1b[0m", id);
                }
            }
            "ipc" => {
                if rest.len() < 4 || rest[0] != "send" {
                    println!("\x1b[1;31mUso: ipc send <from_id> <to_id> <mensaje>\x1b[0m");
                    continue;
                }
                let from_id: u32 = rest[1].parse().unwrap_or(1);
                let to_id: u32 = rest[2].parse().unwrap_or(2);
                let msg_text = rest[3..].join(" ");

                let sender_idx = agents.iter().position(|a| a.id.0 == from_id);
                let recip_idx = agents.iter().position(|a| a.id.0 == to_id);

                if let (Some(s_idx), Some(r_idx)) = (sender_idx, recip_idx) {
                    let sender_id = agents[s_idx].id;
                    let recipient_id = agents[r_idx].id;

                    let (channel_id, obj_id) = match router.find_channel(sender_id, recipient_id) {
                        Some(pair) => pair,
                        None => {
                            let (new_ch, new_obj) = router.create_channel(sender_id, recipient_id, true);
                            let _ = agents[s_idx].grant_capability(new_obj, Permissions::WRITE);
                            let _ = agents[r_idx].grant_capability(new_obj, Permissions::READ);
                            (new_ch, new_obj)
                        }
                    };

                    let cap_token = match agents[s_idx]
                        .cspace
                        .caps()
                        .iter()
                        .find(|c| c.object_id == obj_id && c.permissions.contains(Permissions::WRITE))
                    {
                        Some(c) => c.id,
                        None => {
                            println!("\x1b[1;31m[IPC ERROR] El emisor (ID:{}) no posee capacidad WRITE sobre el canal (ObjectId: {:?})\x1b[0m", from_id, obj_id);
                            continue;
                        }
                    };

                    let res = router.send(
                        &agents[s_idx],
                        channel_id,
                        recipient_id,
                        current_branch,
                        cap_token,
                        IpcPayload::Text(msg_text.clone()),
                        &mut ledger,
                    );

                    match res {
                        Ok(eff_id) => {
                            println!("\x1b[1;32m[IPC OK] Mensaje enviado! Registrado en Merkle-DAG con EffectId: {:?}\x1b[0m", eff_id);
                            let cap_read = match agents[r_idx]
                                .cspace
                                .caps()
                                .iter()
                                .find(|c| c.object_id == obj_id && c.permissions.contains(Permissions::READ))
                            {
                                Some(c) => c.id,
                                None => {
                                    println!("\x1b[1;33m[IPC AVISO] El receptor no posee capacidad READ para desapilar el mensaje del buffer.\x1b[0m");
                                    continue;
                                }
                            };
                            if let Ok(Some(msg)) = router.recv(&mut agents[r_idx], channel_id, cap_read) {
                                println!("  -> Receptor (ID:{}) recibio: '{:?}'", to_id, msg.payload);
                                if agents[r_idx].is_tainted() {
                                    println!("  -> \x1b[1;31m[ALERTA IFC] El receptor ha sido CONTAMINADO automaticamente por el mensaje!\x1b[0m");
                                }
                            }
                        }
                        Err(e) => {
                            println!("\x1b[1;31m[IPC ERROR] Envio rechazado por seguridad del Kernel: {:?}\x1b[0m", e);
                        }
                    }
                } else {
                    println!("\x1b[1;31mError: Agente emisor o receptor invalido.\x1b[0m");
                }
            }
            "fs" => {
                let subcmd = rest.first().copied().unwrap_or("list");
                match subcmd {
                    "list" => {
                        println!("\x1b[1;33m--- ARCHIVOS EN BRANCHFS (Rama: {:?}) ---\x1b[0m", current_branch);
                        for file in fs.list_files(current_branch) {
                            println!("  * {} ({} bytes)", file.path, file.content.len());
                        }
                    }
                    "put" => {
                        if rest.len() < 3 {
                            println!("\x1b[1;31mUso: fs put <nombre> <contenido>\x1b[0m");
                            continue;
                        }
                        let filename = rest[1];
                        let content = rest[2..].join(" ");
                        let metadata = SemanticMetadata {
                            content_type: "text/plain".into(),
                            created_by: DomainId(1),
                            causal_effect: EffectId(1),
                            label: SecurityLabel::TRUSTED_KERNEL,
                            tags: vec!["usuario".into()],
                        };
                        fs.write_file(
                            current_branch,
                            filename,
                            content.as_bytes().to_vec(),
                            Some(EmbeddingVector::new([0.5; 32])),
                            metadata,
                        );
                        println!("\x1b[1;32m[+] Archivo '{}' guardado en BranchFS con embedding 32-D.\x1b[0m", filename);
                    }
                    "search" => {
                        println!("\x1b[1;34m[BUSQUEDA SEMANTICA VECTORIAL]\x1b[0m");
                        let query_vec = EmbeddingVector::new([0.75; 32]);
                        let results = fs.search_semantic(current_branch, &query_vec, 5, 0.1);
                        println!("  Encontrados {} archivos relevantes:", results.len());
                        for (file, score) in results {
                            println!("  * {} (Similitud Coseno: \x1b[1;32m{:.4}\x1b[0m)", file.path, score);
                        }
                    }
                    _ => println!("Comandos fs: list, put, search"),
                }
            }
            "why" => {
                let eff_id: u64 = match rest.first().and_then(|s| s.parse().ok()) {
                    Some(v) => v,
                    None => {
                        println!("\x1b[1;31mUso: why <effect_id>\x1b[0m");
                        continue;
                    }
                };

                let chain = ledger.why(EffectId(eff_id));
                println!("\x1b[1;35m--- AUDITORIA CAUSAL RETROSPECTIVA: why(EffectId({})) ---\x1b[0m", eff_id);
                if chain.is_empty() {
                    println!("  No se encontraron ancestros causales o el efecto es raíz.");
                } else {
                    for (i, id) in chain.iter().enumerate() {
                        if let Some(rec) = ledger.get_effect(*id) {
                            let indent = "  ".repeat(i + 1);
                            println!("{}└── [Nodo {}] Emitter:{:?} -> Target:{:?} | Merkle Hash: {:02x?} | Label: {:?}",
                                indent, rec.id.0, rec.emitter.0, rec.target.0, &rec.merkle_hash[..8], rec.label);
                        }
                    }
                }
            }
            "verify" => {
                println!("\x1b[1;33mVerificando integridad criptográfica de todos los nodos del Merkle-DAG...\x1b[0m");
                if ledger.verify_merkle_integrity() {
                    println!("\x1b[1;32m[VERIFICACION EXITOSA] Todos los hashes SHA-256 coinciden. El historial es matematicamente inmutable.\x1b[0m");
                } else {
                    println!("\x1b[1;31m[ALERTA DE SEGURIDAD] Se detecto alteracion en los hashes del grafo causal!\x1b[0m");
                }
            }
            "fork" => {
                let branch_num: u32 = rest.first().and_then(|s| s.parse().ok()).unwrap_or(1);
                current_branch = BranchId(branch_num);
                println!("\x1b[1;36m[+] Rama del Multiverso seleccionada: {:?}. Entorno Copy-on-Write activo.\x1b[0m", current_branch);
            }
            "commit" => {
                let branch_num: u32 = rest.first().and_then(|s| s.parse().ok()).unwrap_or(current_branch.0);
                let applied = fs.commit_branch(BranchId(branch_num));
                router.commit_branch(BranchId(branch_num));
                current_branch = BranchId(0);
                println!("\x1b[1;32m[+] Rama {:?} CONFIRMADA atomicamente ({} archivos fusionados en Branch 0).\x1b[0m", branch_num, applied);
            }
            "abort" => {
                let branch_num: u32 = rest.first().and_then(|s| s.parse().ok()).unwrap_or(current_branch.0);
                let discarded = fs.abort_branch(BranchId(branch_num));
                router.abort_branch(BranchId(branch_num));
                current_branch = BranchId(0);
                println!("\x1b[1;31m[-] Rama {:?} PURGADA en O(1) ({} cambios descartados).\x1b[0m", branch_num, discarded);
            }
            "vm" => {
                println!("\x1b[1;34m[AgentVM Bytecode Interpreter]\x1b[0m");
                if let Some(ag) = agents.first_mut() {
                    let mut vm = AgentVm::new(ag, &mut supervisor, &tools, 100);
                    let program = [
                        Opcode::Push(Value::Int(100)),
                        Opcode::Push(Value::Int(250)),
                        Opcode::Add,
                        Opcode::SetReg(0),
                    ];
                    let res = vm.run(&program);
                    println!("  Resultado de ejecucion: {:?}", res);
                    println!("  Gas consumido: {} | Registro R0: {:?}", 100 - vm.gas_remaining, vm.registers[0]);
                }
            }
            "bench" => {
                crate::bench::run_benchmarks();
            }
            "demo" => {
                crate::run_live_demo();
            }
            "clear" => {
                print!("\x1b[2J\x1b[H");
            }
            "exit" | "quit" => {
                println!("Saliendo de AgentOS Operator Shell. Hasta luego!");
                break;
            }
            other => {
                println!("\x1b[1;31mComando desconocido: '{}'. Escribe 'help' para ver la lista.\x1b[0m", other);
            }
        }
    }
}
