# Guía Universal de Creación de Agentes en GenOS
**GenOS: El Sistema Operativo Nativo para Inteligencia Artificial y Agentes Autónomos**  
*Autor y Creador: Genaro Agustín Passero*

---

## 1. Visión General: GenOS como Plataforma Abierta y Universal

**GenOS no es un script de Python ni una aplicación específica para una sola red social.**  
Es un **Sistema Operativo completo y universal** que gestiona la memoria, los procesos, la seguridad criptográfica y la ejecución de agentes de inteligencia artificial de cualquier índole:

- **Agentes de Código Nativo:** Escritos en Rust u otros lenguajes de bajo nivel, con acceso a memoria y capacidades del sistema.
- **Agentes en WebAssembly (WASM):** Binarios universales compilados desde C, C++, Rust, Zig o Go, ejecutados en un sandbox con medición estricta de gas.
- **Agentes Cognitivos / Sin Código:** Orquestados mediante lenguaje natural y razonamiento de modelos de lenguaje (Antigravity, Gemini, Claude, Ollama local).
- **Agentes Conectados a Servicios Externos:** Conectores modulares mediante el protocolo estándar **MCP (Model Context Protocol)** para comunicarse con Gmail, LinkedIn, Facebook, bases de datos PostgreSQL, terminales o cualquier API del mundo real.

---

## 2. Método 1: Crear un Agente con Código Nativo desde Cero (Rust)

Puedes escribir un agente en Rust utilizando los módulos del núcleo de GenOS:

```rust
use causal_core::{DomainId, SecurityLabel, TaintMask};
use capability_engine::{ObjectId, Permissions};
use agent_runtime::{
    AgentId, AgentGoal, AgentInstance, AgentSupervisor,
    ToolDefinition, ToolRegistry
};

fn main() {
    // 1. Instanciar el supervisor de seguridad y el registro de herramientas de GenOS
    let mut supervisor = AgentSupervisor::new();
    let mut tools = ToolRegistry::new();

    // 2. Crear una herramienta propia con su lógica personalizada
    let mi_herramienta_id = ObjectId(9001);
    let tool_def = ToolDefinition {
        name: "analizar_datos_mercado".to_string(),
        target_object: mi_herramienta_id,
        required_permissions: Permissions::READ,
        is_external_side_effect: false, // Es puramente reversible
        output_label: SecurityLabel::TRUSTED_KERNEL,
    };
    tools.register(tool_def.clone());

    // 3. Crear el agente nativo desde cero
    let mut mi_agente = AgentInstance::new(
        AgentId(1),
        DomainId(1),
        AgentGoal::new("Analizar tendencias y predecir inflación", 50, 10000), // objetivo, max_pasos, max_tokens
    );

    // 4. Otorgar permisos en su CSpace (Capability Space)
    // El agente SOLO podrá acceder a los recursos que tú le autorices expresamente
    let cap_id = mi_agente.grant_capability(mi_herramienta_id, Permissions::READ);

    // 5. El agente invoca la herramienta a través de la aduana de GenOS
    let payload = b"{\"activo\": \"BTC-USD\", \"periodo\": \"1h\"}";
    let resultado = supervisor.invoke_tool(&mut mi_agente, &tool_def, cap_id, payload).unwrap();

    println!("Resultado del agente: {}", resultado.output);
    println!("Efecto registrado en Merkle-DAG: {:?}", resultado.effect_id);

    // 6. Auditoría Causal Retrospectiva: ¿Por qué ocurrió este efecto?
    let genealogia = supervisor.audit_why(resultado.effect_id);
    println!("Cadena causal determinista: {:?}", genealogia);
}
```

---

## 3. Método 2: Crear un Agente en WebAssembly (WASM)

GenOS soporta la ejecución de binarios estándar compilados a WebAssembly (`\0asm` v1) en un sandbox con aislamiento estricto de memoria en páginas de 64KB y medición de gas:

```rust
use agent_vm::wasm::{WasmEngine, WasmModule};
use capability_engine::{ObjectId, Permissions};

fn main() {
    // 1. Inicializar el motor WASM de GenOS con cuota máxima de gas
    let mut wasm_engine = WasmEngine::new(50_000); // 50,000 unidades de gas

    // 2. Cargar el binario WASM (compilado desde Rust, C, C++, Zig o Go)
    let wasm_binary = include_bytes!("../modules/algoritmo_agente.wasm");
    let modulo = WasmModule::parse(wasm_binary).expect("Binario WASM válido");

    // 3. Registrar funciones del host que el binario puede invocar con verificación de CSpace
    wasm_engine.register_host_gate("leer_sensor", ObjectId(4001), Permissions::READ);

    // 4. Ejecutar el código en el sandbox aislado
    let resultado = wasm_engine.execute(&modulo, "ejecutar_tarea", &[42]);
    println!("WASM ejecutado exitosamente: {:?}", resultado);
    println!("Gas consumido: {}", wasm_engine.gas_consumed());
}
```

---

## 4. Método 3: Crear un Agente en Lenguaje Natural / Sin Código

GenOS incluye interfaces para que cualquier usuario pueda crear y gobernar agentes sin necesidad de escribir código:

### A. Desde la Consola de Operador (`cargo xtask shell`)
Inicia el shell interactivo:
```powershell
cargo xtask shell
```
Comandos disponibles para gobernar agentes:
- `spawn "Agente de Análisis" 20` : Crea un agente autónomo con un objetivo y límite de 20 pasos.
- `agents` : Lista todos los agentes activos, sus dominios, tokens consumidos y estado de integridad (CLEAN o TAINTED).
- `taint <id>` : Simula una inyección de datos externos para ver cómo el kernel protege al agente.
- `why <effect_id>` : Audita matemáticamente la causa raíz de cualquier decisión del agente.
- `status` : Muestra la telemetría del microkernel, el Merkle-DAG y la cola de Escrow.

### B. Ejecución Directa de Objetivos (`cargo xtask agent`)
Puedes pasarle a GenOS cualquier orden en lenguaje natural:
```powershell
cargo xtask agent "Analizar archivos de configuración y compilar módulo WASM"
```
O también:
```powershell
cargo xtask agent "Calcular árbol Merkle SHA-256 y verificar integridad"
```

---

## 5. Método 4: Conectar Servicios y APIs Externas (Gmail, LinkedIn, Facebook, DBs)

Para conectar tu agente al mundo exterior, GenOS utiliza el estándar **Model Context Protocol (MCP)** junto con su sistema de seguridad **DIFC (Decentralized Information Flow Control)** y **Escrow**:

### Registro de un Servidor MCP Personalizado
```rust
use agent_runtime::{McpClient, McpServer};

let mut mcp = McpClient::new();

// 1. Conector a Gmail
let mut gmail = McpServer::new("google_workspace");
gmail.register_tool("gmail_read_inbox", "Lee correos recientes", false, 8001); // no mutante
gmail.register_tool("gmail_send_email", "Envía correo electrónico", true, 8002); // mutante -> Escrow
mcp.attach_server(gmail);

// 2. Conector a LinkedIn
let mut linkedin = McpServer::new("linkedin_network");
linkedin.register_tool("linkedin_get_feed", "Lee publicaciones", false, 8003);
linkedin.register_tool("linkedin_post_update", "Publica en el muro", true, 8004); // mutante -> Escrow
mcp.attach_server(linkedin);

// 3. Conector a Base de Datos Corporativa
let mut db = McpServer::new("postgres_cluster");
db.register_tool("db_query", "Consulta tablas SQL", false, 8005);
db.register_tool("db_update", "Actualiza registros", true, 8006);
mcp.attach_server(db);
```

### La Protección de Escrow $O(1)$
- **Lectura:** Cuando el agente lee datos externos (Gmail, Facebook o una web), GenOS le asigna `TaintMask::TOOL_OUTPUT`.
- **Escritura Mutante:** Si el agente intenta realizar una acción irreversible (publicar en LinkedIn, enviar dinero o modificar la base de datos), el microkernel **congela la llamada en memoria dentro de Escrow**.
- **Tú decides:** GenOS te muestra la acción en pantalla. Si la apruebas, se envía al servicio exterior. Si fue provocada por un engaño o prompt injection, la purga en $O(1)$ sin que nunca salga de tu máquina.

---

## 6. Resumen de Comandos Principales

| Comando | Función |
| :--- | :--- |
| `cargo xtask build` | Compila el microkernel x86-64 y arma la partición UEFI ESP. |
| `cargo xtask demo` | Demostración en vivo de los 5 pilares (Merkle, Escrow, Multiverso, SchedCP, AVM). |
| `cargo xtask shell` | Consola viva de operador para crear agentes (`spawn`), auditar (`why`) e inspeccionar. |
| `cargo xtask agent [orden]` | Ejecutor universal de agentes con catálogo de herramientas (OS, WASM, Gmail, LinkedIn, etc.). |
| `cargo xtask bench` | Benchmarks de alto rendimiento del microkernel y hashing. |
| `cargo xtask doctor` | Diagnóstico de compatibilidad de herramientas (Rust, Limine, QEMU). |
| `cargo test --workspace` | Ejecuta las 70 pruebas unitarias y de integración del sistema. |
