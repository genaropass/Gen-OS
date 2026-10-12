//! Suite de Pruebas de Ejecución Transaccional, Multiverso y Escrow para AgentOS
//! Valida el modelo formal de 7 pasos:
//! - Prueba 1: Transacción pura confirmada (Commit atómico de BranchFS y Escrow).
//! - Prueba 2: Transacción abortada (Abort limpia BranchFS y Escrow sin fugas de estado).
//! - Prueba 3: Demostración empírica de no-reversión de efectos físicos ya liberados.
//! - Prueba 4: Ramas especulativas concurrentes en el Multiverso (Branch isolation).

use agent_runtime::{
    AgentId, AgentGoal, AgentInstance, AgentStatus, AgentSupervisor,
    ToolDefinition, TransactionCoordinator, TransactionStatus
};
use capability_engine::{Permissions, ObjectId};
use causal_core::{DomainId, BranchId, SecurityLabel};
use semantic_fs::{BranchFs, SemanticMetadata};

#[test]
fn test_transaction_1_successful_commit_flow() {
    let mut coordinator = TransactionCoordinator::new();
    let mut supervisor = AgentSupervisor::new();
    let mut fs = BranchFs::new();

    let agent_id = AgentId(1);
    let mut agent = AgentInstance::new(
        agent_id,
        DomainId(1),
        AgentGoal::new("Agente financiero para transferencias y balance", 10, 100),
    );

    // Herramienta externa para emisión de transferencia bancaria
    let bank_obj = ObjectId(1001);
    let bank_tool = ToolDefinition::new(
        "wire_transfer",
        bank_obj,
        Permissions::WRITE,
        true, // Efecto secundario externo -> se retiene en Escrow
        SecurityLabel::TRUSTED_KERNEL,
    );
    let bank_cap = agent.grant_capability(bank_obj, Permissions::WRITE);

    // 1. Iniciar transacción en rama aislada
    let mut tx = coordinator.begin_transaction(&mut agent, "Transferir fondos y asentar en libro");
    let tx_branch = tx.branch_id;
    assert_ne!(tx_branch, BranchId(0));
    assert_eq!(tx.status, TransactionStatus::Executing);

    // 2. Modificar archivo de balance en BranchFS de forma aislada
    coordinator.write_file_isolated(
        &tx,
        &mut fs,
        "/accounts/ledger.txt",
        b"Saldo anterior: $1000 | Transferido: $200 | Nuevo Saldo: $800".to_vec(),
        SemanticMetadata {
            content_type: "text/plain".into(),
            created_by: DomainId(1),
            causal_effect: causal_core::EffectId(1),
            label: SecurityLabel::TRUSTED_KERNEL,
            tags: vec!["finance".into()],
        },
    );

    // En la raíz (Branch 0), el archivo aún NO debe existir
    assert!(fs.read_file(BranchId(0), "/accounts/ledger.txt").is_none());
    // Pero en la rama transaccional sí existe
    assert!(fs.read_file(tx_branch, "/accounts/ledger.txt").is_some());

    // 3. Ejecutar herramienta con efecto secundario externo (se desvía a Escrow)
    let payload = b"WIRE_TRANSFER_TO_IBAN_ES1234567890_AMOUNT_200";
    let tool_res = coordinator.execute_tool(
        &mut tx,
        &mut supervisor,
        &mut agent,
        &bank_tool,
        bank_cap,
        payload,
        false,
    ).unwrap();

    assert!(tool_res.was_escrowed);
    assert_eq!(supervisor.escrow.pending_count(), 1);

    // 4. Confirmar la transacción (Commit)
    let released_actions = coordinator.commit(&mut tx, &mut supervisor, &mut fs, &mut agent).unwrap();

    // Verificaciones post-commit
    assert_eq!(tx.status, TransactionStatus::Committed);
    assert_eq!(agent.status, AgentStatus::Completed);
    assert_eq!(agent.current_branch, BranchId(0)); // Retorna a la línea base

    // El archivo ahora existe en la raíz
    let root_file = fs.read_file(BranchId(0), "/accounts/ledger.txt");
    assert!(root_file.is_some());
    assert!(core::str::from_utf8(&root_file.unwrap().content).unwrap().contains("Nuevo Saldo: $800"));

    // La acción de Escrow fue liberada para ejecución real
    assert_eq!(released_actions.len(), 1);
    assert_eq!(released_actions[0].payload, payload.to_vec());
    assert_eq!(supervisor.escrow.pending_count(), 0);
}

#[test]
fn test_transaction_2_abort_purges_all_state_without_leaks() {
    let mut coordinator = TransactionCoordinator::new();
    let mut supervisor = AgentSupervisor::new();
    let mut fs = BranchFs::new();

    let agent_id = AgentId(2);
    let mut agent = AgentInstance::new(
        agent_id,
        DomainId(2),
        AgentGoal::new("Agente explorador especulativo", 10, 100),
    );

    let deploy_obj = ObjectId(2002);
    let deploy_tool = ToolDefinition::new(
        "deploy_infrastructure",
        deploy_obj,
        Permissions::WRITE,
        true,
        SecurityLabel::TRUSTED_KERNEL,
    );
    let deploy_cap = agent.grant_capability(deploy_obj, Permissions::WRITE);

    // 1. Iniciar transacción
    let mut tx = coordinator.begin_transaction(&mut agent, "Despliegue experimental");
    let tx_branch = tx.branch_id;

    // 2. Modificar FS en la rama
    coordinator.write_file_isolated(
        &tx,
        &mut fs,
        "/infra/config.yaml",
        b"servers: 1000\ninstance_type: gpu.large".to_vec(),
        SemanticMetadata {
            content_type: "text/yaml".into(),
            created_by: DomainId(2),
            causal_effect: causal_core::EffectId(2),
            label: SecurityLabel::TRUSTED_KERNEL,
            tags: vec!["infra".into()],
        },
    );

    // 3. Ejecutar herramienta de infraestructura (retiene acción de despliegue en Escrow)
    let _res = coordinator.execute_tool(
        &mut tx,
        &mut supervisor,
        &mut agent,
        &deploy_tool,
        deploy_cap,
        b"PROVISION_1000_SERVERS",
        false,
    ).unwrap();

    assert_eq!(supervisor.escrow.pending_count(), 1);

    // 4. Se detecta un fallo o costo excesivo y se ABORTA la transacción
    let dropped_actions = coordinator.abort(&mut tx, &mut supervisor, &mut fs, &mut agent);

    // Verificaciones post-abort
    assert_eq!(dropped_actions, 1);
    assert_eq!(tx.status, TransactionStatus::Aborted);
    assert_eq!(agent.status, AgentStatus::Aborted);
    assert_eq!(agent.current_branch, BranchId(0));

    // El sistema de archivos raíz queda completamente limpio
    assert!(fs.read_file(BranchId(0), "/infra/config.yaml").is_none());
    // El overlay de la rama fue purgado
    assert!(fs.read_file(tx_branch, "/infra/config.yaml").is_none());

    // La cola de Escrow fue purgada: cero servidores fueron aprovisionados
    assert_eq!(supervisor.escrow.pending_count(), 0);
}

#[test]
fn test_transaction_3_external_irreversibility_boundary() {
    let mut supervisor = AgentSupervisor::new();

    let agent_id = AgentId(3);
    let mut agent = AgentInstance::new(
        agent_id,
        DomainId(3),
        AgentGoal::new("Demostracion de limite de irreversibilidad fisica", 10, 100),
    );

    let thermal_print_obj = ObjectId(3003);
    let print_tool = ToolDefinition::new(
        "hardware_thermal_print",
        thermal_print_obj,
        Permissions::WRITE,
        true,
        SecurityLabel::TRUSTED_KERNEL,
    );
    let print_cap = agent.grant_capability(thermal_print_obj, Permissions::WRITE);

    // Si el agente ejecuta en Branch 0 (directo sin rama especulativa),
    // la accion ocurre de forma irreversible en hardware:
    agent.current_branch = BranchId(0);
    let res = supervisor.invoke_tool(&mut agent, &print_tool, print_cap, b"IMPRESION_FISICA_PAPEL").unwrap();

    assert!(!res.was_escrowed, "En Branch 0 sin taint, una accion irreversible no pasa por escrow");
    assert_eq!(supervisor.escrow.pending_count(), 0);

    // Si el agente intentara llamar abort ahora:
    let dropped = supervisor.abort_and_contain(&mut agent, BranchId(0));
    assert_eq!(dropped, 0); // abort NO puede deshacer papel ya impreso físicamente

    // Esto valida la regla de diseño: efectos físicos reales irreversibles fuera de escrow
    // deben bloquearse en ramas o requerir compensación explícita (Saga pattern).
}

#[test]
fn test_transaction_4_concurrent_multiverse_branches() {
    let mut coordinator = TransactionCoordinator::new();
    let mut supervisor = AgentSupervisor::new();
    let mut fs = BranchFs::new();

    // Archivo base en la raíz
    fs.write_file(
        BranchId(0),
        "/doc/spec.txt",
        b"Version 1.0 Original".to_vec(),
        None,
        SemanticMetadata {
            content_type: "text/plain".into(),
            created_by: DomainId(0),
            causal_effect: causal_core::EffectId(0),
            label: SecurityLabel::TRUSTED_KERNEL,
            tags: vec![],
        },
    );

    let mut agent_a = AgentInstance::new(AgentId(10), DomainId(10), AgentGoal::new("Explorador Rama A", 5, 50));
    let mut agent_b = AgentInstance::new(AgentId(20), DomainId(20), AgentGoal::new("Explorador Rama B", 5, 50));

    // Rama A modifica el documento
    let mut tx_a = coordinator.begin_transaction(&mut agent_a, "Revision A");
    coordinator.write_file_isolated(
        &tx_a, &mut fs, "/doc/spec.txt", b"Version 1.1 Modificada por Rama A".to_vec(),
        SemanticMetadata {
            content_type: "text/plain".into(),
            created_by: DomainId(10),
            causal_effect: causal_core::EffectId(10),
            label: SecurityLabel::TRUSTED_KERNEL,
            tags: vec![],
        },
    );

    // Rama B modifica el mismo documento con otra alternativa
    let mut tx_b = coordinator.begin_transaction(&mut agent_b, "Revision B");
    coordinator.write_file_isolated(
        &tx_b, &mut fs, "/doc/spec.txt", b"Version 2.0 Radical por Rama B".to_vec(),
        SemanticMetadata {
            content_type: "text/plain".into(),
            created_by: DomainId(20),
            causal_effect: causal_core::EffectId(20),
            label: SecurityLabel::TRUSTED_KERNEL,
            tags: vec![],
        },
    );

    // Ambas ramas ven su propia versión sin interferirse
    let view_a = fs.read_file(tx_a.branch_id, "/doc/spec.txt").unwrap();
    let view_b = fs.read_file(tx_b.branch_id, "/doc/spec.txt").unwrap();
    assert_eq!(view_a.content, b"Version 1.1 Modificada por Rama A");
    assert_eq!(view_b.content, b"Version 2.0 Radical por Rama B");

    // Rama A es descartada (Abort)
    coordinator.abort(&mut tx_a, &mut supervisor, &mut fs, &mut agent_a);

    // Rama B es seleccionada y confirmada (Commit)
    coordinator.commit(&mut tx_b, &mut supervisor, &mut fs, &mut agent_b).unwrap();

    // La raíz ahora tiene la versión de Rama B
    let final_root = fs.read_file(BranchId(0), "/doc/spec.txt").unwrap();
    assert_eq!(final_root.content, b"Version 2.0 Radical por Rama B");
}
