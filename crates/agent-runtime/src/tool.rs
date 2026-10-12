//! Subsistema de Herramientas Protegidas por Capacidades y Escrow
//! Valida permisos de acceso antes de invocar cualquier herramienta externa
//! y desvía efectos secundarios a la cola de Escrow si el contexto está contaminado.

use capability_engine::{ObjectId, Permissions};
use causal_core::{SecurityLabel, EffectId};

/// Definición de una herramienta registrada en el sistema
#[derive(Clone, Debug)]
pub struct ToolDefinition {
    pub name: String,
    pub target_object: ObjectId,
    pub required_permissions: Permissions,
    pub is_external_side_effect: bool,
    pub output_label: SecurityLabel,
}

impl ToolDefinition {
    pub fn new(
        name: &str,
        target_object: ObjectId,
        required_permissions: Permissions,
        is_external_side_effect: bool,
        output_label: SecurityLabel,
    ) -> Self {
        Self {
            name: name.to_string(),
            target_object,
            required_permissions,
            is_external_side_effect,
            output_label,
        }
    }
}

/// Resultado de la invocación de una herramienta
#[derive(Clone, Debug)]
pub struct ToolExecutionResult {
    pub output: String,
    pub effect_id: EffectId,
    pub was_escrowed: bool,
}

/// Registro central de herramientas del sistema
pub struct ToolRegistry {
    tools: Vec<ToolDefinition>,
}

impl Default for ToolRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self { tools: Vec::new() }
    }

    pub fn register(&mut self, tool: ToolDefinition) {
        self.tools.push(tool);
    }

    pub fn find(&self, name: &str) -> Option<&ToolDefinition> {
        self.tools.iter().find(|t| t.name == name)
    }
}
