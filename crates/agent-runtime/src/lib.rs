//! # agent-runtime
//!
//! Runtime de Agentes Autónomos, Supervisor de Seguridad y Motor del Multiverso para AgentOS.
//! Proporciona las abstracciones de alto nivel que interactúan con el kernel causal:
//! - Agentes con identidad, objetivos declarativos y presupuestos.
//! - Propagación de etiquetas de flujo de información (IFC / Taint Tracking).
//! - Herramientas protegidas por capacidades de privilegio mínimo.
//! - Contención de efectos en Escrow para ramas especulativas o sospechosas.
//! - Auditoría retrospectiva `why()` mediante grafos de causalidad.
//! - Exploración de ramas en paralelo y confirmación atómica (Dreaming Engine).

pub mod agent;
pub mod tool;
pub mod supervisor;
pub mod multiverse;
pub mod transaction;
pub mod mcp;
pub mod net;
pub mod llm;

pub use agent::{AgentId, AgentGoal, AgentInstance, AgentStatus};
pub use tool::{ToolDefinition, ToolRegistry, ToolExecutionResult};
pub use supervisor::{AgentSupervisor, SupervisorError};
pub use multiverse::{DreamingEngine, BranchEvaluation};
pub use transaction::{TransactionCoordinator, TransactionContext, TransactionStatus};
pub use mcp::{McpClient, McpServer, McpTool, McpToolResult, McpError};
pub use net::{NetGateway, HttpRequest, HttpResponse, HttpMethod, NetError};
pub use llm::{
    LlmEngine, MockLlmEngine, OllamaEngine, CloudLlmEngine,
    ChatMessage, ChatResponse, ChatRole, PlannedAction, LlmError,
    AgentReasoningLoop, ReasoningStepOutcome,
};


