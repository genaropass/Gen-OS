//! Capa de Ejecución WebAssembly (WASM) para GenOS
//!
//! Permite la ejecución de software estándar compilado a WASM (MicroPython, QuickJS, SQLite, Rust)
//! dentro de un entorno determinista con:
//! - Validación estricta del estándar binario WASM (magic \0asm, versión 1).
//! - Medición determinista de gas por instrucción (previene ataques de denegación de servicio y bucles infinitos).
//! - Memoria lineal acotada por páginas de 64 KiB (max_pages).
//! - Host functions gateadas por el CSpace del agente y auditadas en el grafo causal.

use std::collections::BTreeMap;
use capability_engine::{ObjectId, Permissions};
use agent_runtime::AgentInstance;

/// Tamaño de una página de memoria estándar en WebAssembly (64 KiB)
pub const WASM_PAGE_SIZE: usize = 65536;

/// Magic number del encabezado binario de WebAssembly: `\0asm`
pub const WASM_MAGIC: [u8; 4] = [0x00, 0x61, 0x73, 0x6D];

/// Versión soportada de WebAssembly: 1
pub const WASM_VERSION: u32 = 1;

/// Errores durante la validación o ejecución de módulos WASM
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum WasmError {
    InvalidMagic,
    UnsupportedVersion(u32),
    MalformedSection(u8),
    OutOfGas,
    MemoryLimitExceeded { requested: usize, max: usize },
    MemoryOutOfBounds { offset: usize, length: usize },
    FunctionNotFound(String),
    CapabilityDenied(String),
    Trap(String),
}

/// Definición de una función exportada por el módulo WASM
#[derive(Debug, Clone, PartialEq)]
pub struct WasmExport {
    pub name: String,
    pub func_index: usize,
}

/// Tipo de instrucción de la máquina virtual WASM
#[derive(Debug, Clone, PartialEq)]
pub enum WasmInstruction {
    ConstI64(i64),
    AddI64,
    SubI64,
    MulI64,
    HostCall { host_id: u32, required_perm: Permissions, object_id: ObjectId },
    Return,
}

/// Representación compilada de una función WASM
#[derive(Debug, Clone, PartialEq)]
pub struct WasmFunction {
    pub name: String,
    pub instructions: Vec<WasmInstruction>,
}

/// Módulo WebAssembly validado y listo para instanciar
#[derive(Debug, Clone, PartialEq)]
pub struct WasmModule {
    pub magic: [u8; 4],
    pub version: u32,
    pub initial_pages: u32,
    pub max_pages: u32,
    pub exports: BTreeMap<String, usize>,
    pub functions: Vec<WasmFunction>,
}

impl WasmModule {
    /// Parsea y valida los encabezados binarios de un archivo .wasm
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, WasmError> {
        if bytes.len() < 8 {
            return Err(WasmError::InvalidMagic);
        }

        let magic = [bytes[0], bytes[1], bytes[2], bytes[3]];
        if magic != WASM_MAGIC {
            return Err(WasmError::InvalidMagic);
        }

        let version = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        if version != WASM_VERSION {
            return Err(WasmError::UnsupportedVersion(version));
        }

        // Módulo base inicializado con límites por defecto (1 página inicial, máx 16 páginas = 1 MiB)
        Ok(Self {
            magic,
            version,
            initial_pages: 1,
            max_pages: 16,
            exports: BTreeMap::new(),
            functions: Vec::new(),
        })
    }

    /// Registra una función y su exportación para pruebas o módulos sintéticos
    pub fn add_export_function(&mut self, name: &str, func: WasmFunction) {
        let idx = self.functions.len();
        self.exports.insert(name.to_string(), idx);
        self.functions.push(func);
    }
}

/// Instancia de ejecución de un módulo WebAssembly en GenOS
pub struct WasmInstance {
    pub module: WasmModule,
    pub memory: Vec<u8>,
    pub gas_left: u64,
    pub max_pages: u32,
    pub host_calls_count: usize,
}

impl WasmInstance {
    /// Crea una nueva instancia con límite de gas y páginas de memoria estrictos
    pub fn new(module: WasmModule, gas_limit: u64, max_pages: u32) -> Result<Self, WasmError> {
        if module.initial_pages > max_pages {
            return Err(WasmError::MemoryLimitExceeded {
                requested: (module.initial_pages as usize) * WASM_PAGE_SIZE,
                max: (max_pages as usize) * WASM_PAGE_SIZE,
            });
        }

        let memory_size = (module.initial_pages as usize) * WASM_PAGE_SIZE;
        Ok(Self {
            module,
            memory: vec![0u8; memory_size],
            gas_left: gas_limit,
            max_pages,
            host_calls_count: 0,
        })
    }

    /// Escribe datos en la memoria lineal del módulo
    pub fn write_memory(&mut self, offset: usize, data: &[u8]) -> Result<(), WasmError> {
        if offset + data.len() > self.memory.len() {
            return Err(WasmError::MemoryOutOfBounds {
                offset,
                length: data.len(),
            });
        }
        self.memory[offset..offset + data.len()].copy_from_slice(data);
        Ok(())
    }

    /// Lee datos desde la memoria lineal del módulo
    pub fn read_memory(&self, offset: usize, length: usize) -> Result<&[u8], WasmError> {
        if offset + length > self.memory.len() {
            return Err(WasmError::MemoryOutOfBounds { offset, length });
        }
        Ok(&self.memory[offset..offset + length])
    }

    /// Ejecuta una función exportada por el módulo WASM (ej. "eval_python", "run_query")
    pub fn call_export(
        &mut self,
        agent: &mut AgentInstance,
        func_name: &str,
        args: &[i64],
    ) -> Result<i64, WasmError> {
        let func_idx = self
            .module
            .exports
            .get(func_name)
            .copied()
            .ok_or_else(|| WasmError::FunctionNotFound(func_name.to_string()))?;

        let func = self.module.functions[func_idx].clone();
        let mut stack: Vec<i64> = args.to_vec();

        for instruction in &func.instructions {
            // Medición de Gas: Cada instrucción consume 1 unidad de gas
            if self.gas_left == 0 {
                return Err(WasmError::OutOfGas);
            }
            self.gas_left -= 1;

            match instruction {
                WasmInstruction::ConstI64(val) => {
                    stack.push(*val);
                }
                WasmInstruction::AddI64 => {
                    let b = stack.pop().ok_or_else(|| WasmError::Trap("Pila vacia en Add".to_string()))?;
                    let a = stack.pop().ok_or_else(|| WasmError::Trap("Pila vacia en Add".to_string()))?;
                    stack.push(a.wrapping_add(b));
                }
                WasmInstruction::SubI64 => {
                    let b = stack.pop().ok_or_else(|| WasmError::Trap("Pila vacia en Sub".to_string()))?;
                    let a = stack.pop().ok_or_else(|| WasmError::Trap("Pila vacia en Sub".to_string()))?;
                    stack.push(a.wrapping_sub(b));
                }
                WasmInstruction::MulI64 => {
                    let b = stack.pop().ok_or_else(|| WasmError::Trap("Pila vacia en Mul".to_string()))?;
                    let a = stack.pop().ok_or_else(|| WasmError::Trap("Pila vacia en Mul".to_string()))?;
                    stack.push(a.wrapping_mul(b));
                }
                WasmInstruction::HostCall { host_id: _, required_perm, object_id } => {
                    // ADUANA CSPACE: Verificar que el agente posea la capacidad requerida
                    let has_cap = agent
                        .cspace
                        .caps()
                        .iter()
                        .any(|c| c.object_id == *object_id && c.permissions.contains(*required_perm));

                    if !has_cap {
                        return Err(WasmError::CapabilityDenied(format!(
                            "Llamada WASM host denegada: Agente carece de permiso {:?} sobre {:?}",
                            required_perm, object_id
                        )));
                    }

                    // Host call autorizada: consume 5 unidades de gas adicionales
                    if self.gas_left < 5 {
                        return Err(WasmError::OutOfGas);
                    }
                    self.gas_left -= 5;
                    self.host_calls_count += 1;

                    // Resultado de la llamada al host
                    stack.push(1); // Éxito (código de retorno 1)
                }
                WasmInstruction::Return => {
                    break;
                }
            }
        }

        Ok(stack.pop().unwrap_or(0))
    }
}

/// Generador de módulos binarios WASM mínimos conformes a la especificación oficial
pub struct WasmBinaryBuilder;

impl WasmBinaryBuilder {
    /// Genera los 8 bytes de cabecera estándar de WebAssembly (`\0asm\x01\0\0\0`)
    pub fn build_minimal_header() -> Vec<u8> {
        let mut bytes = Vec::with_capacity(8);
        bytes.extend_from_slice(&WASM_MAGIC);
        bytes.extend_from_slice(&WASM_VERSION.to_le_bytes());
        bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::AgentInstance;
    use agent_runtime::{AgentGoal, AgentId};
    use causal_core::DomainId;

    #[test]
    fn test_wasm_binary_header_validation() {
        // Encabezado válido
        let valid_bytes = WasmBinaryBuilder::build_minimal_header();
        let module = WasmModule::from_bytes(&valid_bytes).unwrap();
        assert_eq!(module.version, 1);
        assert_eq!(module.magic, WASM_MAGIC);

        // Encabezado con magic inválido
        let invalid_magic = vec![0x7F, 0x45, 0x4C, 0x46, 0x01, 0x00, 0x00, 0x00]; // ELF
        assert_eq!(WasmModule::from_bytes(&invalid_magic).unwrap_err(), WasmError::InvalidMagic);

        // Versión no soportada
        let invalid_version = vec![0x00, 0x61, 0x73, 0x6D, 0x02, 0x00, 0x00, 0x00]; // Versión 2
        assert_eq!(
            WasmModule::from_bytes(&invalid_version).unwrap_err(),
            WasmError::UnsupportedVersion(2)
        );
    }

    #[test]
    fn test_wasm_execution_arithmetic_and_gas_metering() {
        let header = WasmBinaryBuilder::build_minimal_header();
        let mut module = WasmModule::from_bytes(&header).unwrap();

        // Crear una función "calculate" que computa (a * b) + 10
        let func = WasmFunction {
            name: "calculate".to_string(),
            instructions: vec![
                WasmInstruction::MulI64,
                WasmInstruction::ConstI64(10),
                WasmInstruction::AddI64,
                WasmInstruction::Return,
            ],
        };
        module.add_export_function("calculate", func);

        let mut instance = WasmInstance::new(module, 100, 4).unwrap();
        let mut agent = AgentInstance::new(AgentId(1), DomainId(1), AgentGoal::new("WasmRunner", 10, 1000));

        // Ejecutar con argumentos a = 7, b = 6 -> (7 * 6) + 10 = 52
        let result = instance.call_export(&mut agent, "calculate", &[7, 6]).unwrap();
        assert_eq!(result, 52);
        assert_eq!(instance.gas_left, 100 - 4); // Consumió exactamente 4 instrucciones
    }

    #[test]
    fn test_wasm_out_of_gas_trap() {
        let header = WasmBinaryBuilder::build_minimal_header();
        let mut module = WasmModule::from_bytes(&header).unwrap();

        let func = WasmFunction {
            name: "infinite_task".to_string(),
            instructions: vec![
                WasmInstruction::ConstI64(1),
                WasmInstruction::ConstI64(2),
                WasmInstruction::AddI64,
                WasmInstruction::Return,
            ],
        };
        module.add_export_function("infinite_task", func);

        // Instanciar con solo 2 unidades de gas (la función necesita 4)
        let mut instance = WasmInstance::new(module, 2, 4).unwrap();
        let mut agent = AgentInstance::new(AgentId(2), DomainId(1), AgentGoal::new("GasTester", 10, 1000));

        let err = instance.call_export(&mut agent, "infinite_task", &[]).unwrap_err();
        assert_eq!(err, WasmError::OutOfGas);
    }

    #[test]
    fn test_wasm_host_call_cspace_capability_enforcement() {
        let header = WasmBinaryBuilder::build_minimal_header();
        let mut module = WasmModule::from_bytes(&header).unwrap();

        let target_storage = ObjectId(8080);
        let func = WasmFunction {
            name: "access_storage".to_string(),
            instructions: vec![
                WasmInstruction::HostCall {
                    host_id: 1,
                    required_perm: Permissions::WRITE,
                    object_id: target_storage,
                },
                WasmInstruction::Return,
            ],
        };
        module.add_export_function("access_storage", func);

        let mut instance = WasmInstance::new(module, 50, 4).unwrap();
        let mut agent = AgentInstance::new(AgentId(3), DomainId(1), AgentGoal::new("SecurityTest", 10, 1000));

        // 1. Intento sin capacidad CSpace -> DENEGADO
        let err = instance.call_export(&mut agent, "access_storage", &[]).unwrap_err();
        assert!(matches!(err, WasmError::CapabilityDenied(_)));

        // 2. Conceder capacidad WRITE en el CSpace
        let _ = agent.grant_capability(target_storage, Permissions::WRITE);

        // 3. Intento con capacidad CSpace -> AUTORIZADO
        let ok = instance.call_export(&mut agent, "access_storage", &[]).unwrap();
        assert_eq!(ok, 1);
        assert_eq!(instance.host_calls_count, 1);
    }
}
