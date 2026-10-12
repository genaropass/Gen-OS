//! Test de Integración (Fase 18): Ejecución Segura de Módulos WebAssembly (WASM) en GenOS
//!
//! Demuestra que software compilado a WASM (MicroPython, QuickJS, SQLite)
//! se ejecuta de forma aislada en Ring 3, con contención estricta de gas, memoria lineal
//! y verificación obligatoria de capacidades CSpace en cada llamada al sistema.

use capability_engine::{ObjectId, Permissions};
use agent_runtime::{AgentId, AgentGoal, AgentInstance};
use causal_core::DomainId;
use agent_vm::{
    WasmBinaryBuilder, WasmModule, WasmInstance, WasmFunction,
    WasmInstruction, WasmError, WASM_PAGE_SIZE,
};

#[test]
fn test_wasm_standard_software_runtime_lifecycle() {
    // 1. Validar binario WASM estándar (\0asm\x01\0\0\0)
    let binary = WasmBinaryBuilder::build_minimal_header();
    let mut module = WasmModule::from_bytes(&binary).unwrap();

    // 2. Simular rutina de cálculo compilada desde MicroPython / Rust:
    // func run_script(x, y) -> (x + y) * 2
    let script_func = WasmFunction {
        name: "run_script".to_string(),
        instructions: vec![
            WasmInstruction::AddI64,
            WasmInstruction::ConstI64(2),
            WasmInstruction::MulI64,
            WasmInstruction::Return,
        ],
    };
    module.add_export_function("run_script", script_func);

    // 3. Crear instancia con 2 páginas de memoria (128 KiB) y 50 unidades de gas
    let mut instance = WasmInstance::new(module, 50, 4).unwrap();
    let mut agent = AgentInstance::new(
        AgentId(55),
        DomainId(1),
        AgentGoal::new("WasmPythonRunner", 10, 1000),
    );

    // 4. Escribir y leer datos en la memoria lineal aislada (simulando paso de cadenas de script)
    let script_input = b"def calculate(a, b): return (a + b) * 2";
    instance.write_memory(0x100, script_input).unwrap();
    let read_back = instance.read_memory(0x100, script_input.len()).unwrap();
    assert_eq!(read_back, script_input);

    // 5. Ejecutar la función con parámetros 15 y 25 -> (15 + 25) * 2 = 80
    let result = instance.call_export(&mut agent, "run_script", &[15, 25]).unwrap();
    assert_eq!(result, 80);
    assert_eq!(instance.gas_left, 50 - 4); // 4 instrucciones ejecutadas
}

#[test]
fn test_wasm_memory_bounds_protection() {
    let binary = WasmBinaryBuilder::build_minimal_header();
    let module = WasmModule::from_bytes(&binary).unwrap();

    let mut instance = WasmInstance::new(module, 100, 1).unwrap(); // 1 página = 65536 bytes
    assert_eq!(instance.memory.len(), WASM_PAGE_SIZE);

    // Intento de escribir más allá del límite de la página asignada -> Bloqueado
    let large_buffer = vec![0xFF; 100];
    let err = instance.write_memory(WASM_PAGE_SIZE - 50, &large_buffer).unwrap_err();
    assert!(matches!(err, WasmError::MemoryOutOfBounds { .. }));
}

#[test]
fn test_wasm_cspace_host_function_isolation() {
    let binary = WasmBinaryBuilder::build_minimal_header();
    let mut module = WasmModule::from_bytes(&binary).unwrap();

    let db_obj = ObjectId(9090);

    // Módulo WASM con una llamada de importación host (ej. sqlite_open / db_query)
    let query_func = WasmFunction {
        name: "sqlite_query".to_string(),
        instructions: vec![
            WasmInstruction::HostCall {
                host_id: 10,
                required_perm: Permissions::READ,
                object_id: db_obj,
            },
            WasmInstruction::Return,
        ],
    };
    module.add_export_function("sqlite_query", query_func);

    let mut instance = WasmInstance::new(module, 100, 2).unwrap();
    let mut agent = AgentInstance::new(
        AgentId(56),
        DomainId(1),
        AgentGoal::new("WasmSqlite", 10, 1000),
    );

    // 1. Intento sin capacidad CSpace -> DENEGADO por el kernel
    let denied = instance.call_export(&mut agent, "sqlite_query", &[]);
    assert!(matches!(denied, Err(WasmError::CapabilityDenied(_))));

    // 2. Conceder capacidad en el CSpace
    let _ = agent.grant_capability(db_obj, Permissions::READ);

    // 3. Intento con capacidad concedida -> ÉXITO
    let ok = instance.call_export(&mut agent, "sqlite_query", &[]).unwrap();
    assert_eq!(ok, 1);
    assert_eq!(instance.host_calls_count, 1);
}
