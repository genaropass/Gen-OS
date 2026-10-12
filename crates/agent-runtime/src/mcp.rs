//! Cliente y Aduana de Model Context Protocol (MCP - JSON-RPC 2.0) para GenOS
//! Permite que los agentes descubran e invoquen herramientas externas (bases de datos, APIs, GitHub, Gmail)
//! pasando obligatoriamente por la verificación de capacidades, retención en Escrow y seguimiento de Taint.

use std::collections::BTreeMap;
use capability_engine::{Permissions, ObjectId};
use causal_core::{SecurityLabel, TaintMask};
use crate::agent::AgentInstance;
use crate::supervisor::AgentSupervisor;
use crate::tool::ToolDefinition;

/// Error en operaciones del protocolo MCP
#[derive(Debug, PartialEq, Eq)]
pub enum McpError {
    ToolNotFound(String),
    CapabilityDenied(String),
    EscrowHeld(String),
    ProtocolError(String),
}

/// Definición de una herramienta descubierta vía MCP
#[derive(Clone, Debug, PartialEq)]
pub struct McpTool {
    pub name: String,
    pub description: String,
    pub is_mutating: bool, // ¿Tiene efectos secundarios externos irreversibles?
    pub object_id: ObjectId,
}

/// Resultado de la invocación de una herramienta MCP
#[derive(Clone, Debug, PartialEq)]
pub struct McpToolResult {
    pub content: String,
    pub is_error: bool,
    pub staged_in_escrow: bool,
    pub effect_id: u64,
}

/// Servidor MCP registrado en GenOS
pub struct McpServer {
    pub server_name: String,
    pub tools: BTreeMap<String, McpTool>,
}

impl McpServer {
    pub fn new(server_name: &str) -> Self {
        Self {
            server_name: server_name.to_string(),
            tools: BTreeMap::new(),
        }
    }

    /// Registra una herramienta disponible en este servidor MCP
    pub fn register_tool(&mut self, name: &str, description: &str, is_mutating: bool, object_id: u64) {
        self.tools.insert(
            name.to_string(),
            McpTool {
                name: name.to_string(),
                description: description.to_string(),
                is_mutating,
                object_id: ObjectId(object_id),
            },
        );
    }
}

/// Cliente de MCP integrado con el Supervisor de Seguridad de GenOS
pub struct McpClient {
    servers: BTreeMap<String, McpServer>,
}

impl Default for McpClient {
    fn default() -> Self {
        Self::new()
    }
}

impl McpClient {
    pub fn new() -> Self {
        Self {
            servers: BTreeMap::new(),
        }
    }

    /// Conecta un servidor MCP al entorno de GenOS
    pub fn attach_server(&mut self, server: McpServer) {
        self.servers.insert(server.server_name.clone(), server);
    }

    /// Lista todas las herramientas disponibles a través de MCP
    pub fn list_tools(&self) -> Vec<&McpTool> {
        let mut list = Vec::new();
        for server in self.servers.values() {
            for tool in server.tools.values() {
                list.push(tool);
            }
        }
        list
    }

    /// Invoca una herramienta MCP con verificación obligatoria de Capacidades, Escrow y Taint Tracking
    pub fn call_tool(
        &self,
        agent: &mut AgentInstance,
        supervisor: &mut AgentSupervisor,
        tool_name: &str,
        params_json: &str,
    ) -> Result<McpToolResult, McpError> {
        // 1. Localizar la herramienta en los servidores registrados
        let tool = self
            .list_tools()
            .into_iter()
            .find(|t| t.name == tool_name)
            .ok_or_else(|| McpError::ToolNotFound(tool_name.to_string()))?;

        // 2. Determinar permisos requeridos: Si es mutante requiere WRITE; si es lectura requiere READ
        let required_perm = if tool.is_mutating {
            Permissions::WRITE
        } else {
            Permissions::READ
        };

        // 3. Buscar la capacidad correspondiente en el CSpace del agente
        let cap_opt = agent
            .cspace
            .caps()
            .iter()
            .find(|c| c.object_id == tool.object_id && c.permissions.contains(required_perm))
            .map(|c| c.id);

        let cap_id = match cap_opt {
            Some(id) => id,
            None => {
                return Err(McpError::CapabilityDenied(format!(
                    "El agente {:?} no posee capacidad {:?} para usar la herramienta MCP '{}'",
                    agent.id, required_perm, tool.name
                )));
            }
        };

        // 4. Mapear a ToolDefinition para que el Supervisor de GenOS aplique la aduana
        let tool_def = ToolDefinition {
            name: tool.name.clone(),
            target_object: tool.object_id,
            required_permissions: required_perm,
            is_external_side_effect: tool.is_mutating,
            output_label: SecurityLabel {
                confidentiality: agent.security_label.confidentiality,
                integrity: 40,
                taint_mask: TaintMask::TOOL_OUTPUT,
            },
        };

        // 5. Invocar mediante el Supervisor de GenOS
        let exec_result = supervisor
            .invoke_tool(agent, &tool_def, cap_id, params_json.as_bytes())
            .map_err(|e| McpError::ProtocolError(format!("Supervisor rechazo la invocacion: {:?}", e)))?;

        // 6. Si fue retenida en Escrow, no se entrega salida real al exterior todavía
        if exec_result.was_escrowed {
            return Ok(McpToolResult {
                content: format!("[ESCROW HELD] Accion mutante en '{}' retenida en cola de Escrow hasta confirmacion", tool.name),
                is_error: false,
                staged_in_escrow: true,
                effect_id: exec_result.effect_id.0,
            });
        }

        // 7. Simulación de ejecución real de herramienta externa (MCP tool output)
        let simulated_output = format!("MCP_SUCCESS[{}]: processed payload of {} bytes", tool.name, params_json.len());

        // 8. Taint Tracking Automático: La salida de una herramienta externa recibe TaintMask::TOOL_OUTPUT
        let tool_output_label = SecurityLabel {
            confidentiality: agent.security_label.confidentiality,
            integrity: 40, // Integridad reducida por provenir del exterior
            taint_mask: TaintMask::TOOL_OUTPUT,
        };
        agent.observe(&simulated_output, tool_output_label, exec_result.effect_id);

        Ok(McpToolResult {
            content: simulated_output,
            is_error: false,
            staged_in_escrow: false,
            effect_id: exec_result.effect_id.0,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{AgentGoal, AgentId};
    use causal_core::DomainId;

    #[test]
    fn test_mcp_tool_discovery_and_capability_authorization() {
        let mut client = McpClient::new();
        let mut server = McpServer::new("google_workspace");
        server.register_tool("gmail_read_inbox", "Lee correos entrantes de Gmail", false, 1001);
        server.register_tool("gmail_send_email", "Envia un correo saliente", true, 1002);
        client.attach_server(server);

        assert_eq!(client.list_tools().len(), 2);

        let mut supervisor = AgentSupervisor::new();
        let mut agent = AgentInstance::new(AgentId(1), DomainId(1), AgentGoal::new("Mailbot", 10, 1000));

        // 1. El agente intenta leer sin permiso: RECHAZADO
        let err = client.call_tool(&mut agent, &mut supervisor, "gmail_read_inbox", "{}");
        assert!(matches!(err, Err(McpError::CapabilityDenied(_))));

        // 2. Conceder capacidad de lectura al agente
        let _ = agent.grant_capability(ObjectId(1001), Permissions::READ);

        // 3. Ejecución autorizada exitosa
        let ok_res = client.call_tool(&mut agent, &mut supervisor, "gmail_read_inbox", "{}").unwrap();
        assert!(!ok_res.staged_in_escrow);
        assert!(agent.is_tainted(), "La salida de la herramienta externa debe contaminar al agente con TaintMask::TOOL_OUTPUT");
    }

    #[test]
    fn test_mcp_mutating_tool_staged_in_escrow_if_tainted() {
        let mut client = McpClient::new();
        let mut server = McpServer::new("database_server");
        server.register_tool("sql_delete_records", "Elimina registros de la base de datos", true, 2001);
        client.attach_server(server);

        let mut supervisor = AgentSupervisor::new();
        let mut agent = AgentInstance::new(AgentId(2), DomainId(2), AgentGoal::new("DbCleaner", 10, 1000));
        let _ = agent.grant_capability(ObjectId(2001), Permissions::WRITE);

        // Contaminar al agente previamente con entrada web
        let bad_label = SecurityLabel { confidentiality: 0, integrity: 10, taint_mask: TaintMask::WEB_UNTRUSTED };
        agent.observe("inyeccion web", bad_label, causal_core::EffectId(99));
        assert!(agent.is_tainted());

        // La herramienta es mutante y el agente está tainted: DEBE SER RETENIDA EN ESCROW
        let res = client.call_tool(&mut agent, &mut supervisor, "sql_delete_records", "DELETE FROM users").unwrap();
        assert!(res.staged_in_escrow, "Accion externa de agente tainted debe ser retenida en Escrow");
        assert_eq!(supervisor.escrow.pending_count(), 1);
    }
}
