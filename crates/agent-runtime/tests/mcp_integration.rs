//! Test de Integración: Protocolo MCP con CSpace, DIFC y Escrow en GenOS

use capability_engine::{ObjectId, Permissions};
use causal_core::DomainId;
use agent_runtime::{
    AgentId, AgentGoal, AgentInstance, AgentSupervisor,
    McpClient, McpServer, McpError
};

#[test]
fn test_mcp_end_to_end_security_pipeline() {
    // 1. Configurar servidor MCP simulando servicios externos (Health AI / Vector DB)
    let mut client = McpClient::new();
    let mut health_mcp = McpServer::new("health_ai_service");
    health_mcp.register_tool("query_medical_records", "Consulta registros médicos del paciente", false, 3001);
    health_mcp.register_tool("update_dosage_prescription", "Actualiza la dosis del medicamento", true, 3002);
    client.attach_server(health_mcp);

    let mut supervisor = AgentSupervisor::new();
    let mut agent = AgentInstance::new(AgentId(101), DomainId(1), AgentGoal::new("DoctorAssistant", 20, 2000));

    // 2. Intentar llamar a 'query_medical_records' sin capacidad CSpace -> DEBE FALLAR
    let denied = client.call_tool(&mut agent, &mut supervisor, "query_medical_records", "{\"patient_id\": 42}");
    assert!(matches!(denied, Err(McpError::CapabilityDenied(_))));

    // 3. Conceder capacidad READ al agente sobre el objeto 3001
    let _ = agent.grant_capability(ObjectId(3001), Permissions::READ);

    // 4. Invocación autorizada -> ÉXITO, pero contamina al agente con TOOL_OUTPUT
    let read_result = client.call_tool(&mut agent, &mut supervisor, "query_medical_records", "{\"patient_id\": 42}").unwrap();
    assert!(!read_result.staged_in_escrow);
    assert!(read_result.content.contains("MCP_SUCCESS"));
    assert!(agent.is_tainted(), "La salida de la herramienta MCP debe marcar el agente como contaminado");

    // 5. Conceder capacidad WRITE para 'update_dosage_prescription'
    let _ = agent.grant_capability(ObjectId(3002), Permissions::WRITE);

    // 6. Intentar ejecutar acción mutante mientras el agente está contaminado por datos externos:
    // El supervisor de GenOS NO la ejecuta inmediatamente, sino que la retiene en ESCROW
    let mutate_result = client.call_tool(&mut agent, &mut supervisor, "update_dosage_prescription", "{\"dose_mg\": 50}").unwrap();
    assert!(mutate_result.staged_in_escrow, "Acción mutante debe ser retenida en Escrow");
    assert_eq!(supervisor.escrow.pending_count(), 1);

    // 7. Liberación atómica tras revisión humana / supervisor
    let released_effects = supervisor.escrow.commit_branch(agent.current_branch);
    assert_eq!(released_effects.len(), 1);
    assert_eq!(supervisor.escrow.pending_count(), 0);
}
