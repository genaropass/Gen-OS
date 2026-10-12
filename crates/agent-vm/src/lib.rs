//! # agent-vm
//!
//! Máquina Virtual Causal y Motor de Bytecode para Agentes de AgentOS.
//! Proporciona un entorno de ejecución determinista y aislado donde los agentes
//! ejecutan planes algorítmicos con:
//! 1. Medidor de Gas estricto para evitar bucles infinitos y costos descontrolados.
//! 2. Instrucciones nativas de comprobación de capacidades (`AssertCap`).
//! 3. Instrucciones de ramificación especulativa en el Multiverso (`ForkBranch`, `CommitBranch`, `AbortBranch`).
//! 4. Invocación de herramientas protegidas por Escrow y seguimiento de taint IFC (`Observe`, `InvokeTool`).

use causal_core::{BranchId, SecurityLabel, EffectId};
use capability_engine::{ObjectId, Permissions};
use agent_runtime::{AgentInstance, AgentSupervisor, ToolRegistry, ToolExecutionResult};

/// Valores primitivos operables dentro de la AVM
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    Int(i64),
    Bool(bool),
    Str(String),
}

/// Conjunto de instrucciones de bytecode para agentes
#[derive(Clone, Debug)]
pub enum Opcode {
    /// Empuja un valor a la pila de evaluación
    Push(Value),
    /// Descarta el valor en la cima de la pila
    Pop,
    /// Operaciones aritméticas enteras
    Add,
    Sub,
    Mul,
    /// Almacena el valor de la cima en un registro local (0..15)
    SetReg(u8),
    /// Lee un registro local y lo empuja a la pila
    GetReg(u8),
    /// Salto incondicional a la posición del contador de programa
    Jump(usize),
    /// Salto condicional si la cima de la pila es `Value::Bool(true)`
    JumpIfTrue(usize),
    /// Observa datos externos con una etiqueta de integridad IFC
    Observe { content: String, integrity: u16 },
    /// Valida que el agente posea una capacidad activa antes de proceder
    AssertCap { object_id: u64, perms: u32 },
    /// Invoca una herramienta registrada a través del Supervisor
    InvokeTool { tool_name: String, payload: Vec<u8> },
    /// Bifurca la ejecución actual en una nueva rama del Multiverso
    ForkBranch(u32),
    /// Confirma la rama actual y libera los efectos retenidos en Escrow
    CommitBranch,
    /// Aborta la rama actual y purga el Escrow sin tocar el mundo real
    AbortBranch,
    /// Detiene la ejecución con éxito
    Halt,
}

#[derive(Clone, Debug, PartialEq)]
pub enum VmError {
    StackUnderflow,
    OutOfGas,
    InvalidRegister(u8),
    TypeMismatch,
    CapabilityViolation,
    ToolNotFound(String),
    BranchError(&'static str),
    Halted,
}

/// Estado de la Máquina Virtual de Agente
pub struct AgentVm<'a> {
    pub pc: usize,
    pub stack: Vec<Value>,
    pub registers: [Value; 16],
    pub gas_remaining: u64,
    pub agent: &'a mut AgentInstance,
    pub supervisor: &'a mut AgentSupervisor,
    pub tools: &'a ToolRegistry,
    pub last_effect: Option<EffectId>,
}

impl<'a> AgentVm<'a> {
    pub fn new(
        agent: &'a mut AgentInstance,
        supervisor: &'a mut AgentSupervisor,
        tools: &'a ToolRegistry,
        gas_limit: u64,
    ) -> Self {
        Self {
            pc: 0,
            stack: Vec::with_capacity(64),
            registers: core::array::from_fn(|_| Value::Int(0)),
            gas_remaining: gas_limit,
            agent,
            supervisor,
            tools,
            last_effect: None,
        }
    }

    /// Descuenta gas según el costo de la instrucción
    fn deduct_gas(&mut self, cost: u64) -> Result<(), VmError> {
        if self.gas_remaining < cost {
            self.gas_remaining = 0;
            Err(VmError::OutOfGas)
        } else {
            self.gas_remaining -= cost;
            Ok(())
        }
    }

    /// Ejecuta un programa de bytecode completo hasta `Halt` o error
    pub fn run(&mut self, program: &[Opcode]) -> Result<Option<Value>, VmError> {
        while self.pc < program.len() {
            let op = &program[self.pc];
            self.pc += 1;

            match op {
                Opcode::Push(val) => {
                    self.deduct_gas(1)?;
                    self.stack.push(val.clone());
                }

                Opcode::Pop => {
                    self.deduct_gas(1)?;
                    self.stack.pop().ok_or(VmError::StackUnderflow)?;
                }

                Opcode::Add => {
                    self.deduct_gas(2)?;
                    let b = self.stack.pop().ok_or(VmError::StackUnderflow)?;
                    let a = self.stack.pop().ok_or(VmError::StackUnderflow)?;
                    match (a, b) {
                        (Value::Int(va), Value::Int(vb)) => self.stack.push(Value::Int(va + vb)),
                        _ => return Err(VmError::TypeMismatch),
                    }
                }

                Opcode::Sub => {
                    self.deduct_gas(2)?;
                    let b = self.stack.pop().ok_or(VmError::StackUnderflow)?;
                    let a = self.stack.pop().ok_or(VmError::StackUnderflow)?;
                    match (a, b) {
                        (Value::Int(va), Value::Int(vb)) => self.stack.push(Value::Int(va - vb)),
                        _ => return Err(VmError::TypeMismatch),
                    }
                }

                Opcode::Mul => {
                    self.deduct_gas(3)?;
                    let b = self.stack.pop().ok_or(VmError::StackUnderflow)?;
                    let a = self.stack.pop().ok_or(VmError::StackUnderflow)?;
                    match (a, b) {
                        (Value::Int(va), Value::Int(vb)) => self.stack.push(Value::Int(va * vb)),
                        _ => return Err(VmError::TypeMismatch),
                    }
                }

                Opcode::SetReg(idx) => {
                    self.deduct_gas(1)?;
                    if (*idx as usize) >= self.registers.len() {
                        return Err(VmError::InvalidRegister(*idx));
                    }
                    let val = self.stack.pop().ok_or(VmError::StackUnderflow)?;
                    self.registers[*idx as usize] = val;
                }

                Opcode::GetReg(idx) => {
                    self.deduct_gas(1)?;
                    if (*idx as usize) >= self.registers.len() {
                        return Err(VmError::InvalidRegister(*idx));
                    }
                    let val = self.registers[*idx as usize].clone();
                    self.stack.push(val);
                }

                Opcode::Jump(target) => {
                    self.deduct_gas(1)?;
                    self.pc = *target;
                }

                Opcode::JumpIfTrue(target) => {
                    self.deduct_gas(2)?;
                    let cond = self.stack.pop().ok_or(VmError::StackUnderflow)?;
                    if let Value::Bool(true) = cond {
                        self.pc = *target;
                    }
                }

                Opcode::Observe { content, integrity } => {
                    self.deduct_gas(5)?;
                    let effect = self.last_effect.unwrap_or(EffectId(0));
                    self.agent.observe(
                        content,
                        SecurityLabel {
                            confidentiality: 10,
                            integrity: *integrity,
                            taint_mask: 0,
                        },
                        effect,
                    );
                }

                Opcode::AssertCap { object_id, perms } => {
                    self.deduct_gas(5)?;
                    // Validar si el agente posee alguna capacidad para ese objeto con esos permisos
                    let obj = ObjectId(*object_id);
                    let required = Permissions(*perms);
                    let has_cap = self.agent.cspace.caps().iter().any(|c| {
                        c.object_id == obj && c.permissions.contains(required)
                    });

                    if !has_cap {
                        return Err(VmError::CapabilityViolation);
                    }
                }

                Opcode::InvokeTool { tool_name, payload } => {
                    self.deduct_gas(20)?;
                    let tool = self.tools.find(tool_name).ok_or_else(|| VmError::ToolNotFound(tool_name.clone()))?;

                    // Buscar token de capacidad válido en el CSpace
                    let cap_id = self.agent.cspace.caps().into_iter().find(|c| {
                        c.object_id == tool.target_object && c.permissions.contains(tool.required_permissions)
                    }).map(|c| c.id).ok_or(VmError::CapabilityViolation)?;
                    let result: ToolExecutionResult = self.supervisor
                        .invoke_tool(self.agent, tool, cap_id, payload)
                        .map_err(|_| VmError::CapabilityViolation)?;

                    self.last_effect = Some(result.effect_id);
                    self.stack.push(Value::Str(result.output));
                }

                Opcode::ForkBranch(branch_id) => {
                    self.deduct_gas(15)?;
                    self.agent.current_branch = BranchId(*branch_id);
                }

                Opcode::CommitBranch => {
                    self.deduct_gas(15)?;
                    let branch = self.agent.current_branch;
                    let _ = self.supervisor.commit_and_release(self.agent, branch);
                    self.agent.current_branch = BranchId(0);
                }

                Opcode::AbortBranch => {
                    self.deduct_gas(15)?;
                    let branch = self.agent.current_branch;
                    let _ = self.supervisor.abort_and_contain(self.agent, branch);
                    self.agent.current_branch = BranchId(0);
                }

                Opcode::Halt => {
                    self.deduct_gas(1)?;
                    return Ok(self.stack.pop());
                }
            }
        }

        Ok(self.stack.pop())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_runtime::{AgentId, AgentGoal};
    use causal_core::DomainId;

    #[test]
    fn test_vm_arithmetic_and_registers() {
        let mut supervisor = AgentSupervisor::new();
        let tools = ToolRegistry::new();
        let mut agent = AgentInstance::new(AgentId(1), DomainId(1), AgentGoal::new("calc", 10, 100));

        let mut vm = AgentVm::new(&mut agent, &mut supervisor, &tools, 1000);

        // Programa: (10 + 20) * 3 = 90
        let program = vec![
            Opcode::Push(Value::Int(10)),
            Opcode::Push(Value::Int(20)),
            Opcode::Add,
            Opcode::SetReg(0),
            Opcode::GetReg(0),
            Opcode::Push(Value::Int(3)),
            Opcode::Mul,
            Opcode::Halt,
        ];

        let result = vm.run(&program).expect("Ejecucion exitosa");
        assert_eq!(result, Some(Value::Int(90)));
        assert!(vm.gas_remaining < 1000, "El gas debe haberse consumido");
    }

    #[test]
    fn test_vm_out_of_gas_containment() {
        let mut supervisor = AgentSupervisor::new();
        let tools = ToolRegistry::new();
        let mut agent = AgentInstance::new(AgentId(2), DomainId(2), AgentGoal::new("loop", 10, 100));

        // Asignar solo 10 unidades de gas
        let mut vm = AgentVm::new(&mut agent, &mut supervisor, &tools, 10);

        // Bucle infinito: Jump(0)
        let program = vec![
            Opcode::Push(Value::Int(1)),
            Opcode::Jump(0),
        ];

        let err = vm.run(&program).unwrap_err();
        assert_eq!(err, VmError::OutOfGas, "El bucle infinito debe ser abortado por falta de gas");
        assert_eq!(vm.gas_remaining, 0);
    }

    #[test]
    fn test_vm_capability_assertion() {
        let mut supervisor = AgentSupervisor::new();
        let tools = ToolRegistry::new();
        let mut agent = AgentInstance::new(AgentId(3), DomainId(3), AgentGoal::new("sec", 10, 100));

        let obj = ObjectId(777);
        // Otorgar permiso solo de lectura
        let _ = agent.grant_capability(obj, Permissions::READ);

        let mut vm = AgentVm::new(&mut agent, &mut supervisor, &tools, 1000);

        // Validar que READ pasa
        let ok_program = vec![
            Opcode::AssertCap { object_id: 777, perms: Permissions::READ.0 },
            Opcode::Halt,
        ];
        assert!(vm.run(&ok_program).is_ok());

        // Validar que WRITE falla con CapabilityViolation
        let mut vm2 = AgentVm::new(&mut agent, &mut supervisor, &tools, 1000);
        let fail_program = vec![
            Opcode::AssertCap { object_id: 777, perms: Permissions::WRITE.0 },
            Opcode::Halt,
        ];
        assert_eq!(vm2.run(&fail_program).unwrap_err(), VmError::CapabilityViolation);
    }
}
