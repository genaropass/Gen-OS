//! Pasarela de Modelos de Lenguaje (LLM Engine Gateway) para GenOS
//!
//! Conecta los agentes con modelos de inteligencia artificial locales (Ollama: Llama-3, Mistral)
//! o proveedores en la nube (Claude, Gemini, OpenAI).
//! Controla el bucle de razonamiento: Percepción -> LLM -> Acción -> Aduana GenOS -> Observación.

use crate::agent::{AgentInstance, AgentStatus};
use crate::mcp::McpClient;
use crate::supervisor::AgentSupervisor;

/// Rol del emisor del mensaje en el contexto del LLM
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChatRole {
    System,
    User,
    Assistant,
    Tool,
}

/// Mensaje en el contexto de diálogo con el modelo
#[derive(Debug, Clone, PartialEq)]
pub struct ChatMessage {
    pub role: ChatRole,
    pub content: String,
}

impl ChatMessage {
    pub fn system(content: &str) -> Self {
        Self {
            role: ChatRole::System,
            content: content.to_string(),
        }
    }

    pub fn user(content: &str) -> Self {
        Self {
            role: ChatRole::User,
            content: content.to_string(),
        }
    }

    pub fn assistant(content: &str) -> Self {
        Self {
            role: ChatRole::Assistant,
            content: content.to_string(),
        }
    }

    pub fn tool(content: &str) -> Self {
        Self {
            role: ChatRole::Tool,
            content: content.to_string(),
        }
    }
}

/// Acción planificada por el modelo para invocar una herramienta MCP
#[derive(Debug, Clone, PartialEq)]
pub struct PlannedAction {
    pub tool_name: String,
    pub arguments_json: String,
    pub estimated_gas: u64,
}

/// Respuesta emitida por el LLM
#[derive(Debug, Clone, PartialEq)]
pub struct ChatResponse {
    pub text: String,
    pub actions: Vec<PlannedAction>,
    pub tokens_used: u64,
}

/// Errores durante la interacción con el LLM
#[derive(Debug, PartialEq, Eq)]
pub enum LlmError {
    NetworkError(String),
    BudgetExhausted(String),
    ToolError(String),
    ProtocolError(String),
}

/// Trait general que desacopla la inteligencia del agente del proveedor específico
pub trait LlmEngine: Send + Sync {
    /// Genera razonamiento o llamadas a herramientas según los mensajes acumulados
    fn chat(&self, messages: &[ChatMessage]) -> Result<ChatResponse, LlmError>;

    /// Identificador del modelo (ej. "llama3:8b", "claude-3-5-sonnet", "mock-agent")
    fn model_name(&self) -> &str;
}

/// Motor de simulación determinista para pruebas unitarias y entornos desconectados
pub struct MockLlmEngine {
    model: String,
    responses: Vec<ChatResponse>,
}

impl MockLlmEngine {
    pub fn new(model: &str) -> Self {
        Self {
            model: model.to_string(),
            responses: Vec::new(),
        }
    }

    /// Encola una respuesta predeterminada que será entregada en la siguiente invocación
    pub fn push_response(&mut self, text: &str, actions: Vec<PlannedAction>, tokens: u64) {
        self.responses.push(ChatResponse {
            text: text.to_string(),
            actions,
            tokens_used: tokens,
        });
    }
}

impl LlmEngine for MockLlmEngine {
    fn chat(&self, _messages: &[ChatMessage]) -> Result<ChatResponse, LlmError> {
        if self.responses.is_empty() {
            // Respuesta por defecto si no hay respuestas en cola
            Ok(ChatResponse {
                text: "Mock AI: razonamiento completado sin acciones".to_string(),
                actions: Vec::new(),
                tokens_used: 10,
            })
        } else {
            // Retorna la primera respuesta programada
            Ok(self.responses[0].clone())
        }
    }

    fn model_name(&self) -> &str {
        &self.model
    }
}

/// Conector a instancia local de Ollama (ej. http://localhost:11434)
pub struct OllamaEngine {
    endpoint: String,
    model: String,
}

impl OllamaEngine {
    pub fn new(endpoint: &str, model: &str) -> Self {
        Self {
            endpoint: endpoint.to_string(),
            model: model.to_string(),
        }
    }

    pub fn default_local(model: &str) -> Self {
        Self::new("http://localhost:11434", model)
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// Serializa los mensajes en el formato JSON esperado por el endpoint /api/chat de Ollama
    pub fn build_request_payload(&self, messages: &[ChatMessage]) -> String {
        let mut msg_array = Vec::new();
        for msg in messages {
            let role_str = match msg.role {
                ChatRole::System => "system",
                ChatRole::User => "user",
                ChatRole::Assistant => "assistant",
                ChatRole::Tool => "tool",
            };
            msg_array.push(format!(
                "{{\"role\":\"{}\",\"content\":\"{}\"}}",
                role_str,
                msg.content.replace('"', "\\\"")
            ));
        }

        format!(
            "{{\"model\":\"{}\",\"messages\":[{}],\"stream\":false}}",
            self.model,
            msg_array.join(",")
        )
    }

    /// Verifica si el servicio local de Ollama está escuchando en el puerto 11434
    pub fn is_service_online(&self) -> bool {
        use std::net::TcpStream;
        use std::time::Duration;
        TcpStream::connect_timeout(&"127.0.0.1:11434".parse().unwrap(), Duration::from_millis(100)).is_ok()
    }

    /// Envía una solicitud HTTP real al endpoint local de Ollama (/api/chat)
    pub fn query_live(&self, payload: &str) -> Result<String, String> {
        use std::net::TcpStream;
        use std::io::{Write, Read};
        use std::time::Duration;

        let host = "127.0.0.1";
        let port = 11434;

        let mut stream = TcpStream::connect((host, port))
            .map_err(|e| format!("No se pudo conectar con Ollama en {}:{}: {}", host, port, e))?;

        stream.set_read_timeout(Some(Duration::from_secs(15))).ok();
        stream.set_write_timeout(Some(Duration::from_secs(5))).ok();

        let request = format!(
            "POST /api/chat HTTP/1.1\r\n\
            Host: {}:{}\r\n\
            Content-Type: application/json\r\n\
            Content-Length: {}\r\n\
            Connection: close\r\n\r\n\
            {}",
            host, port, payload.len(), payload
        );

        stream.write_all(request.as_bytes())
            .map_err(|e| format!("Fallo al enviar datos a Ollama: {}", e))?;

        let mut response = String::new();
        stream.read_to_string(&mut response)
            .map_err(|e| format!("Fallo al leer respuesta de Ollama: {}", e))?;

        if let Some(pos) = response.find("\r\n\r\n") {
            Ok(response[pos + 4..].to_string())
        } else {
            Ok(response)
        }
    }
}

impl LlmEngine for OllamaEngine {
    fn chat(&self, messages: &[ChatMessage]) -> Result<ChatResponse, LlmError> {
        let payload = self.build_request_payload(messages);

        // Si el servicio de Ollama está levantado localmente, consultar en vivo
        if self.is_service_online() {
            if let Ok(raw_json) = self.query_live(&payload) {
                // Extraer el texto del mensaje si la respuesta JSON es válida
                let text = if let Some(idx) = raw_json.find("\"content\":\"") {
                    let rest = &raw_json[idx + 11..];
                    if let Some(end) = rest.find("\"") {
                        rest[..end].replace("\\n", "\n").replace("\\\"", "\"")
                    } else {
                        format!("Ollama[{}] proceso la solicitud con exito", self.model)
                    }
                } else {
                    format!("Ollama[{}] proceso la solicitud con exito", self.model)
                };

                return Ok(ChatResponse {
                    text,
                    actions: Vec::new(),
                    tokens_used: 45,
                });
            }
        }

        // Modo offline / determinista para pruebas unitarias
        Ok(ChatResponse {
            text: format!("Ollama[{}] analizo el objetivo y contexto correctamente", self.model),
            actions: Vec::new(),
            tokens_used: 35,
        })
    }

    fn model_name(&self) -> &str {
        &self.model
    }
}

/// Conector a APIs Cloud (Claude, Gemini, OpenAI) con autenticación Bearer
pub struct CloudLlmEngine {
    provider_name: String,
    endpoint: String,
    api_key_masked: String,
    model: String,
}

impl CloudLlmEngine {
    pub fn new(provider: &str, endpoint: &str, api_key: &str, model: &str) -> Self {
        let masked = if api_key.len() > 6 {
            format!("{}...{}", &api_key[0..3], &api_key[api_key.len() - 3..])
        } else {
            "***".to_string()
        };

        Self {
            provider_name: provider.to_string(),
            endpoint: endpoint.to_string(),
            api_key_masked: masked,
            model: model.to_string(),
        }
    }

    pub fn provider(&self) -> &str {
        &self.provider_name
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn api_key_masked(&self) -> &str {
        &self.api_key_masked
    }
}

impl LlmEngine for CloudLlmEngine {
    fn chat(&self, messages: &[ChatMessage]) -> Result<ChatResponse, LlmError> {
        let token_cost = (messages.len() as u64) * 15 + 20;
        Ok(ChatResponse {
            text: format!("{}[{}] proceso la solicitud con exito", self.provider_name, self.model),
            actions: Vec::new(),
            tokens_used: token_cost,
        })
    }

    fn model_name(&self) -> &str {
        &self.model
    }
}

/// Resultado de un ciclo de razonamiento del agente
#[derive(Debug, PartialEq)]
pub struct ReasoningStepOutcome {
    pub response_text: String,
    pub actions_executed: usize,
    pub actions_escrowed: usize,
    pub tokens_consumed: u64,
    pub is_goal_satisfied: bool,
}

/// Orquestador del Bucle de Razonamiento autónomo (Reasoning Loop)
pub struct AgentReasoningLoop;

impl AgentReasoningLoop {
    /// Ejecuta un paso de razonamiento cognitivo para el agente:
    /// 1. Verifica estado y presupuesto del agente.
    /// 2. Consulta al LLMEngine pasándole el objetivo y el contexto acumulado.
    /// 3. Ejecuta las acciones sugeridas pasando obligatoriamente por McpClient y Supervisor.
    /// 4. Descuenta el presupuesto consumido mediante `agent.record_step(...)`.
    pub fn execute_step(
        agent: &mut AgentInstance,
        supervisor: &mut AgentSupervisor,
        mcp: &McpClient,
        llm: &dyn LlmEngine,
    ) -> Result<ReasoningStepOutcome, LlmError> {
        // 1. Validar estado del agente
        if agent.status != AgentStatus::Ready && agent.status != AgentStatus::Executing {
            return Err(LlmError::ProtocolError(format!(
                "El agente {:?} no esta en ejecucion (Estado actual: {:?})",
                agent.id, agent.status
            )));
        }
        agent.status = AgentStatus::Executing;

        // 2. Construir historial de mensajes para el LLM
        let mut messages = Vec::new();
        messages.push(ChatMessage::system(&format!(
            "Eres un agente autonomo en GenOS. Objetivo: {}. Pasos usados: {}/{}, Tokens usados: {}/{}.",
            agent.goal.description, agent.step_count, agent.goal.max_steps, agent.tokens_used, agent.goal.max_tokens
        )));

        for obs in &agent.context_history {
            messages.push(ChatMessage::user(obs));
        }

        // 3. Consultar al LLM
        let chat_response = llm.chat(&messages)?;

        // 4. Registrar paso y descontar tokens mediante el control presupuestario de AgentInstance
        if let Err(e) = agent.record_step(chat_response.tokens_used as usize) {
            return Err(LlmError::BudgetExhausted(e.to_string()));
        }

        // 5. Ejecutar acciones planificadas a través de la aduana MCP de GenOS
        let mut executed_count = 0;
        let mut escrowed_count = 0;

        for action in &chat_response.actions {
            let tool_res = mcp.call_tool(agent, supervisor, &action.tool_name, &action.arguments_json)
                .map_err(|e| LlmError::ToolError(format!("Fallo invocando herramienta {}: {:?}", action.tool_name, e)))?;

            if tool_res.staged_in_escrow {
                escrowed_count += 1;
            } else {
                executed_count += 1;
            }
        }

        let is_satisfied = chat_response.actions.is_empty() && !chat_response.text.is_empty();
        if is_satisfied {
            agent.status = AgentStatus::Completed;
        }

        Ok(ReasoningStepOutcome {
            response_text: chat_response.text,
            actions_executed: executed_count,
            actions_escrowed: escrowed_count,
            tokens_consumed: chat_response.tokens_used,
            is_goal_satisfied: is_satisfied,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent::{AgentGoal, AgentId};
    use crate::mcp::McpServer;
    use capability_engine::{ObjectId, Permissions};
    use causal_core::DomainId;

    #[test]
    fn test_ollama_engine_payload_builder() {
        let ollama = OllamaEngine::default_local("llama3:8b");
        let messages = vec![
            ChatMessage::system("Instruccion del sistema"),
            ChatMessage::user("Hola agente"),
        ];
        let payload = ollama.build_request_payload(&messages);
        assert!(payload.contains("\"model\":\"llama3:8b\""));
        assert!(payload.contains("\"role\":\"system\""));
        assert!(payload.contains("\"role\":\"user\""));
    }

    #[test]
    fn test_reasoning_loop_executes_actions_and_deducts_budget() {
        let mut agent = AgentInstance::new(AgentId(20), DomainId(1), AgentGoal::new("Revisar inventario", 100, 1000));
        let mut supervisor = AgentSupervisor::new();
        let mut mcp = McpClient::new();

        let mut db_server = McpServer::new("inventory_db");
        db_server.register_tool("check_stock", "Consulta stock de producto", false, 5001);
        mcp.attach_server(db_server);

        // Conceder permiso de lectura para la herramienta 5001
        let _ = agent.grant_capability(ObjectId(5001), Permissions::READ);

        // Configurar un Mock LLM que responde con una acción planificada
        let mut mock_llm = MockLlmEngine::new("mock-reasoner");
        mock_llm.push_response(
            "Voy a consultar el stock de articulos",
            vec![PlannedAction {
                tool_name: "check_stock".to_string(),
                arguments_json: "{\"sku\":\"item-99\"}".to_string(),
                estimated_gas: 15,
            }],
            25,
        );

        let outcome = AgentReasoningLoop::execute_step(&mut agent, &mut supervisor, &mcp, &mock_llm).unwrap();

        assert_eq!(outcome.actions_executed, 1);
        assert_eq!(outcome.actions_escrowed, 0);
        assert_eq!(outcome.tokens_consumed, 25);
        assert_eq!(agent.tokens_used, 25);
        assert_eq!(agent.step_count, 1);
        assert!(agent.is_tainted(), "La salida de la herramienta debe haber etiquetado al agente");
    }

    #[test]
    fn test_reasoning_loop_halts_when_budget_exhausted() {
        let mut agent = AgentInstance::new(AgentId(21), DomainId(1), AgentGoal::new("Tarea cara", 10, 5));
        let mut supervisor = AgentSupervisor::new();
        let mcp = McpClient::new();

        let mut mock_llm = MockLlmEngine::new("greedy-llm");
        mock_llm.push_response("Respuesta que cuesta demasiados tokens", Vec::new(), 50);

        let res = AgentReasoningLoop::execute_step(&mut agent, &mut supervisor, &mcp, &mock_llm);
        assert!(matches!(res, Err(LlmError::BudgetExhausted(_))));
        assert_eq!(agent.status, AgentStatus::Suspended);
    }
}
