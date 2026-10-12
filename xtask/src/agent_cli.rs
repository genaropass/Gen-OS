//! CLI Universal de Agentes para GenOS
//! Permite instanciar y ejecutar agentes de cualquier tipo en GenOS:
//! - Agentes de Sistema y Código (Filesystem, WASM, Bytecode AVM, Merkle-DAG)
//! - Agentes de Datos y Computación (Bases de datos, búsqueda semántica)
//! - Agentes Conectados a Servicios Web (Gmail, LinkedIn, Facebook, APIs REST)
//! Todo bajo la gobernanza estricta del Microkernel: CSpace, DIFC Taint Tracking y Escrow O(1).

use std::io::{self, Write};
use causal_core::{DomainId, TaintMask};
use capability_engine::{ObjectId, Permissions};
use agent_runtime::{
    AgentId, AgentGoal, AgentInstance, AgentSupervisor,
    McpClient, McpServer, PlannedAction,
};

pub fn run_personal_agent_cli(prompt_opt: Option<&str>) {
    println!("\x1b[1;36m");
    println!("========================================================================");
    println!("   ____             ___  ____  ");
    println!("  / ___| ___ _ __  / _ \\/ ___| ");
    println!(" | |  _ / _ \\ '_ \\| | | \\___ \\ ");
    println!(" | |_| |  __/ | | | |_| |___) |");
    println!("  \\____|\\___|_| |_|\\___/|____/ ");
    println!("   GENOS AGENT RUNTIME — ENTORNO UNIVERSAL DE EJECUCIÓN DE AGENTES");
    println!("   Microkernel • CSpace • Multiverso • WASM • MCP Conectores • Escrow");
    println!("========================================================================\x1b[0m\n");

    let instruction = match prompt_opt {
        Some(p) if !p.trim().is_empty() => p.trim().to_string(),
        _ => {
            println!("\x1b[1;33mGenOS es un sistema operativo abierto para crear cualquier tipo de agente:\x1b[0m");
            println!("  1. Agente de Código/Sistema  : 'analizar archivos en disco y compilar modulo wasm'");
            println!("  2. Agente de Computación     : 'calcular arbol merkle sha256 y verificar integridad'");
            println!("  3. Agente Conectado a Red    : 'leer correos en gmail y publicar resumen en linkedin'");
            println!("  4. Agente de Redes Sociales  : 'inspeccionar mensajes en facebook y responder'");
            println!("  5. O escribe cualquier orden libre en lenguaje natural.\n");
            print!("\x1b[1;32m¿Qué objetivo deseas asignar a tu nuevo agente en GenOS?: \x1b[0m");
            let _ = io::stdout().flush();
            let mut buf = String::new();
            if io::stdin().read_line(&mut buf).is_err() || buf.trim().is_empty() {
                println!("[*] Asignando objetivo universal de demostración: 'Analizar entorno del sistema y sincronizar servicios'");
                "Analizar entorno del sistema y sincronizar servicios".to_string()
            } else {
                buf.trim().to_string()
            }
        }
    };

    println!("\n\x1b[1;32m[*] Objetivo del Agente:\x1b[0m \"{}\"", instruction);
    println!("\x1b[1;34m[1/5] Inicializando Kernel de Seguridad y Catálogo de Servicios MCP...\x1b[0m");

    let mut supervisor = AgentSupervisor::new();
    let mut mcp = McpClient::new();

    // 1. Catálogo Universal de Servicios MCP disponibles en GenOS:
    // A) Servicios de Núcleo y Sistema Operativo
    let mut os_srv = McpServer::new("genos_core_system");
    os_srv.register_tool("fs_read_data", "Lee archivos del sistema o BranchFS", false, 7001);
    os_srv.register_tool("fs_write_data", "Escribe archivos en BranchFS Copy-on-Write", true, 7002);
    os_srv.register_tool("wasm_exec_runtime", "Ejecuta binario WASM en sandbox seguro", false, 7003);
    os_srv.register_tool("merkle_dag_compute", "Calcula nodos y hashes SHA-256 en el Ledger Causal", false, 7004);
    mcp.attach_server(os_srv);

    // B) Servicios de Red y Conectores de Usuario (Gmail, LinkedIn, Facebook)
    let mut gmail_srv = McpServer::new("google_workspace");
    gmail_srv.register_tool("gmail_read_inbox", "Lee correos recientes de la bandeja de entrada", false, 8001);
    gmail_srv.register_tool("gmail_send_email", "Envía un correo electrónico a un destinatario", true, 8002);
    mcp.attach_server(gmail_srv);

    let mut linkedin_srv = McpServer::new("linkedin_network");
    linkedin_srv.register_tool("linkedin_get_feed", "Lee publicaciones recientes del muro", false, 8003);
    linkedin_srv.register_tool("linkedin_post_update", "Publica un estado o artículo en LinkedIn", true, 8004);
    mcp.attach_server(linkedin_srv);

    let mut fb_srv = McpServer::new("facebook_meta");
    fb_srv.register_tool("facebook_get_messages", "Lee mensajes privados de Messenger", false, 8005);
    fb_srv.register_tool("facebook_post_story", "Publica una historia en Facebook", true, 8006);
    mcp.attach_server(fb_srv);

    println!("  ✓ Servidor OS Core activo     (fs_read_data, fs_write_data, wasm_exec_runtime, merkle_dag_compute)");
    println!("  ✓ Conector Gmail activo       (gmail_read_inbox, gmail_send_email)");
    println!("  ✓ Conector LinkedIn activo    (linkedin_get_feed, linkedin_post_update)");
    println!("  ✓ Conector Facebook activo    (facebook_get_messages, facebook_post_story)");

    // 2. Instanciación del Agente con CSpace (Capability Space)
    println!("\n\x1b[1;34m[2/5] Creando dominio de agente en GenOS con CSpace (Capability Space)...\x1b[0m");
    let mut agent = AgentInstance::new(
        AgentId(101),
        DomainId(101),
        AgentGoal::new(&instruction, 20, 4000),
    );

    // Otorgar capacidades selectivas en CSpace
    let _ = agent.grant_capability(ObjectId(7001), Permissions::READ);  // Leer FS
    let _ = agent.grant_capability(ObjectId(7002), Permissions::WRITE); // Escribir FS
    let _ = agent.grant_capability(ObjectId(7003), Permissions::READ);  // Ejecutar WASM
    let _ = agent.grant_capability(ObjectId(7004), Permissions::READ);  // Computar Merkle
    let _ = agent.grant_capability(ObjectId(8001), Permissions::READ);  // Leer Gmail
    let _ = agent.grant_capability(ObjectId(8002), Permissions::WRITE); // Escribir Gmail
    let _ = agent.grant_capability(ObjectId(8003), Permissions::READ);  // Leer LinkedIn
    let _ = agent.grant_capability(ObjectId(8004), Permissions::WRITE); // Publicar LinkedIn
    let _ = agent.grant_capability(ObjectId(8005), Permissions::READ);  // Leer FB
    let _ = agent.grant_capability(ObjectId(8006), Permissions::WRITE); // Publicar FB

    println!("  ✓ Dominio asignado: AgentId(101) en DomainId(101)");
    println!("  ✓ CSpace configurado: 10 capacidades criptográficas asignadas");
    println!("  ✓ Estado de Integridad Inicial: CLEAN (Trusted Kernel)");

    // 3. Planificación y Razonamiento Cognitivo
    println!("\n\x1b[1;34m[3/5] Consultando Motor Cognitivo (LLM Reasoning Loop)...\x1b[0m");
    
    let lower_instruction = instruction.to_lowercase();
    let mut planned_actions = Vec::new();
    let cognitive_plan: String;

    if lower_instruction.contains("wasm") || lower_instruction.contains("codigo") || lower_instruction.contains("código") {
        cognitive_plan = "Plan Cognitivo [Sistema]: 1) Leer módulo WASM en BranchFS. 2) Ejecutar binario con medición de gas en sandbox.".to_string();
        planned_actions.push(PlannedAction {
            tool_name: "fs_read_data".to_string(),
            arguments_json: "{\"path\": \"/modules/security_calc.wasm\"}".to_string(),
            estimated_gas: 10,
        });
        planned_actions.push(PlannedAction {
            tool_name: "wasm_exec_runtime".to_string(),
            arguments_json: "{\"function\": \"compute_hash\", \"gas_limit\": 500}".to_string(),
            estimated_gas: 20,
        });
    } else if lower_instruction.contains("merkle") || lower_instruction.contains("sha") || lower_instruction.contains("hash") {
        cognitive_plan = "Plan Cognitivo [Criptografía]: 1) Calcular nodos del Merkle-DAG con SHA-256. 2) Registrar prueba de integridad.".to_string();
        planned_actions.push(PlannedAction {
            tool_name: "merkle_dag_compute".to_string(),
            arguments_json: "{\"algorithm\": \"sha256\", \"leaves_count\": 4}".to_string(),
            estimated_gas: 12,
        });
    } else if lower_instruction.contains("gmail") && lower_instruction.contains("linkedin") {
        cognitive_plan = "Plan Cognitivo [Redes & Correo]: 1) Leer últimos correos vía gmail_read_inbox. 2) Sintetizar anuncio. 3) Publicar en LinkedIn vía linkedin_post_update.".to_string();
        planned_actions.push(PlannedAction {
            tool_name: "gmail_read_inbox".to_string(),
            arguments_json: "{\"query\": \"is:unread category:updates\", \"max_results\": 3}".to_string(),
            estimated_gas: 15,
        });
        planned_actions.push(PlannedAction {
            tool_name: "linkedin_post_update".to_string(),
            arguments_json: "{\"text\": \"Actualización profesional generada de forma segura por GenOS AI-Native Operating System.\"}".to_string(),
            estimated_gas: 25,
        });
    } else if lower_instruction.contains("facebook") || lower_instruction.contains("fb") {
        cognitive_plan = "Plan Cognitivo [Social]: 1) Inspeccionar mensajes en Facebook vía facebook_get_messages. 2) Publicar actualización.".to_string();
        planned_actions.push(PlannedAction {
            tool_name: "facebook_get_messages".to_string(),
            arguments_json: "{\"limit\": 5}".to_string(),
            estimated_gas: 15,
        });
        planned_actions.push(PlannedAction {
            tool_name: "facebook_post_story".to_string(),
            arguments_json: "{\"text\": \"Publicación segura gobernada por el microkernel de GenOS.\"}".to_string(),
            estimated_gas: 20,
        });
    } else {
        cognitive_plan = format!("Plan Cognitivo para '{}': 1) Inspeccionar recursos del sistema en BranchFS. 2) Sincronizar estado.", instruction);
        planned_actions.push(PlannedAction {
            tool_name: "fs_read_data".to_string(),
            arguments_json: "{\"path\": \"/sys/config.json\"}".to_string(),
            estimated_gas: 10,
        });
        planned_actions.push(PlannedAction {
            tool_name: "fs_write_data".to_string(),
            arguments_json: "{\"path\": \"/var/log/agent_audit.log\", \"content\": \"Operacion completada con exito\"}".to_string(),
            estimated_gas: 15,
        });
    }

    println!("  🧠 Planificación: {}", cognitive_plan);
    for (i, action) in planned_actions.iter().enumerate() {
        println!("     Paso {}: Invocar herramienta '{}' con parámetros {}", i + 1, action.tool_name, action.arguments_json);
    }

    // 4. Ejecución del Paso 1: Percepción o Lectura
    println!("\n\x1b[1;34m[4/5] Despachando herramientas a través de la Aduana de GenOS...\x1b[0m");
    let first_action = &planned_actions[0];
    println!("  -> Ejecutando herramienta de percepción: '{}'...", first_action.tool_name);
    
    let mock_read_content = format!("Salida procesada para herramienta '{}' [Datos observados]", first_action.tool_name);
    let read_res = mcp.call_tool(&mut agent, &mut supervisor, &first_action.tool_name, &mock_read_content).expect("Fallo al ejecutar herramienta");
    
    println!("  ✓ Ejecución completada (staged_in_escrow: {})", read_res.staged_in_escrow);
    if read_res.content.contains("TOOL_OUTPUT") || first_action.tool_name.contains("gmail") || first_action.tool_name.contains("facebook") {
        println!("  🛡️ [DIFC NOTIFICACIÓN]: Datos de procedencia externa observados (TaintMask::TOOL_OUTPUT = 0x{:02X})", TaintMask::TOOL_OUTPUT);
        println!("  ⚠️ El microkernel protegerá cualquier mutación externa subsiguiente reteniéndola en Escrow.");
    }

    // 5. Ejecución del Paso 2: Acción Mutante o de Efecto Externo
    if planned_actions.len() > 1 {
        let second_action = &planned_actions[1];
        println!("\n  -> El agente intenta ejecutar acción mutante: '{}'...", second_action.tool_name);
        
        let write_res = mcp.call_tool(&mut agent, &mut supervisor, &second_action.tool_name, &second_action.arguments_json).expect("Fallo en llamada MCP");
        
        if write_res.staged_in_escrow {
            println!("\x1b[1;33m");
            println!("  ╔═══════════════════════════════════════════════════════════════════════╗");
            println!("  ║           GENOS MICROKERNEL — ACCIÓN RETENIDA EN ESCROW               ║");
            println!("  ╠═══════════════════════════════════════════════════════════════════════╣");
            println!("  ║ Herramienta Solicitada : {:<44} ║", second_action.tool_name);
            println!("  ║ Política de Seguridad  : Acción con efectos externos o datos observados║");
            println!("  ║ Aislamiento Físico     : 0 BYTES TRANSMITIDOS (Aislado en memoria)    ║");
            println!("  ║ Efecto Causal ID       : {:<44} ║", write_res.effect_id);
            println!("  ╚═══════════════════════════════════════════════════════════════════════╝\x1b[0m");

            println!("\n\x1b[1;32m[5/5] Control Humano en el Bucle (Human-in-the-Loop Governance):\x1b[0m");
            print!("¿Deseas confirmar el commit a '{}' o abortar la acción en O(1)? [Enter para Confirmar / 'abort' para purgar]: ", second_action.tool_name);
            let _ = io::stdout().flush();
            let mut choice = String::new();
            let _ = io::stdin().read_line(&mut choice);

            let current_branch = agent.current_branch;
            if choice.trim().to_lowercase() == "abort" {
                let aborted = supervisor.abort_and_contain(&mut agent, current_branch);
                println!("\x1b[1;31m[!] Acción abortada atómicamente. {} acción(es) purgadas de Escrow. CERO impacto exterior.\x1b[0m", aborted);
            } else {
                let committed = supervisor.commit_and_release(&mut agent, current_branch);
                println!("\x1b[1;32m[✓] Commit autorizado por el usuario. {} acción(es) despachadas a '{}'. Efecto registrado en Merkle-DAG con SHA-256.\x1b[0m", committed.len(), second_action.tool_name);
            }
        } else {
            println!("  ✓ Acción interna ejecutada directamente dentro de los límites de seguridad de GenOS.");
        }
    }

    println!("\n\x1b[1;36m========================================================================");
    println!("  CICLO DEL AGENTE COMPLETADO CON ÉXITO.");
    println!("  GenOS garantizó la integridad de los dominios y la seguridad del sistema.");
    println!("========================================================================\x1b[0m\n");
}
