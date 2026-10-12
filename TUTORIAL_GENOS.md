# 🪐 MANUAL Y TUTORIAL COMPLETO DE GenOS
### Guía Definitiva de Creación y Operación de Agentes (Con Código y Sin Código)
*Sistema Operativo Nativo para Agentes de Inteligencia Artificial*  
*Autor: Genaro Agustín Passero*

---

## 📑 ÍNDICE DE CONTENIDOS

1. [Conceptos Básicos: ¿Cómo piensa y actúa un Agente en GenOS?](#1-conceptos-básicos)
2. [PARTE I: Control de Agentes SIN CÓDIGO (Consola Interactiva)](#2-parte-i-control-sin-código)
   - [Cómo abrir la consola](#cómo-abrir-la-consola)
   - [Diccionario completo de comandos](#diccionario-completo-de-comandos)
   - [Tutorial Paso a Paso en Consola](#tutorial-paso-a-paso-en-consola)
3. [PARTE II: Creación de Agentes CON CÓDIGO (Desarrollo en Rust)](#3-parte-ii-creación-con-código)
   - [Estructura de un Agente Nativo](#estructura-de-un-agente-nativo)
   - [Creación de Herramientas y Permisos (Capacidades)](#creación-de-herramientas-y-permisos)
   - [El Supervisor de Seguridad y la Aduana de Escrow](#el-supervisor-de-seguridad)
   - [Búsqueda Semántica Vectorial en Código](#búsqueda-semántica-vectorial)
4. [PARTE III: 4 Casos Prácticos Demostrativos](#4-parte-iii-casos-prácticos)
   - [Caso A: Creación y Comunicación de un Enjambre](#caso-a-enjambre-de-agentes)
   - [Caso B: Trabajo Seguro con el Multiverso (Cero Riesgo)](#caso-b-el-multiverso)
   - [Caso C: Bloqueo de un Ataque Hacker (Prompt Injection)](#caso-c-bloqueo-de-ataques)
   - [Caso D: Auditoría Forense y el Botón "¿Por qué?"](#caso-d-auditoría-why)
5. [Tabla Resumen de Comandos Rápidos (Cheat Sheet)](#5-cheat-sheet)

---

## 1. CONCEPTOS BÁSICOS

En los sistemas operativos tradicionales (Windows o Linux), un agente de IA es un programa común que si se descontrola o es engañado puede borrar tu disco o filtrar datos.

En **GenOS**, un agente es un **ciudadano nativo del sistema** que posee:
* **Identidad propia (`AgentId` y `DomainId`):** Nadie puede suplantar su identidad.
* **Memoria física aislada (`AddressSpace`):** No puede espiar ni tocar la memoria de otros agentes ni del kernel.
* **Llavero de permisos (`CSpace`):** No usa contraseñas; usa *Capacidades no falsificables*. Si no tiene la capacidad de escribir, físicamente no puede hacerlo.
* **Etiqueta de seguridad (DIFC / Taint Tracking):** Si lee un dato dudoso de internet, queda marcado como `TAINTED` (contaminado) y el kernel le apaga los permisos sensibles.
* **Presupuesto estricto (`AgentGoal`):** Tiene un límite máximo de pasos de cómputo y tokens. Si entra en un bucle infinito, el kernel lo suspende automáticamente.

---

## 2. PARTE I: CONTROL SIN CÓDIGO (CONSOLA INTERACTIVA)

No necesitas programar para operar y probar agentes en GenOS. La consola de operador te permite gestionar todo el sistema en vivo.

### Cómo abrir la consola:
Abre tu terminal PowerShell en la carpeta del proyecto (`E:\Genaro\Desktop\AgentOS`) y ejecuta:
```powershell
cargo xtask shell
```
*Aparecerá el banner oficial de AgentOS / GenOS y el prompt:* `AgentOS [Branch:0] >`

---

### Diccionario completo de comandos de la consola:

| Comando | Sintaxis | ¿Qué hace exactamente? | Ejemplo real |
|---|---|---|---|
| `help` | `help` | Muestra la lista de todos los comandos disponibles. | `help` |
| `status` | `status` | Muestra la telemetría viva: rama del multiverso, cantidad de agentes, acciones en Escrow e integridad Merkle. | `status` |
| `agents` | `agents` | Lista todos los agentes activos, sus pasos consumidos, tokens y su estado de seguridad (`CLEAN` o `TAINTED`). | `agents` |
| `spawn` | `spawn <nombre> [max_pasos]` | Crea un nuevo agente con un objetivo y un límite de pasos de ejecución. | `spawn "AuditorFinanciero" 25` |
| `taint` | `taint <id_agente>` | Simula que el agente leyó un dato hostil de internet. El kernel lo marca como contaminado inmediatamente. | `taint 1` |
| `ipc send` | `ipc send <emisor> <receptor> <texto>` | Envía un mensaje seguro entre agentes a través del bus del kernel, validando permisos y registrando el hash. | `ipc send 1 2 "Revisa el balance"` |
| `fs list` | `fs list` | Lista los archivos guardados en el sistema de archivos semántico (BranchFS) de la rama actual. | `fs list` |
| `fs put` | `fs put <nombre> <contenido>` | Guarda un archivo y calcula automáticamente su vector semántico de 32 dimensiones. | `fs put config.txt "modo_seguro=true"` |
| `fs search` | `fs search` | Realiza una búsqueda semántica por similitud de coseno buscando archivos relevantes por significado. | `fs search` |
| `fork` | `fork <numero_rama>` | Salta a una realidad paralela (Multiverso). Todo lo que se haga aquí no afectará a la realidad principal (Rama 0). | `fork 42` |
| `commit` | `commit [numero_rama]` | Confirma atómicamente todos los cambios de una rama paralela y los fusiona en la realidad principal (Rama 0). | `commit 42` |
| `abort` | `abort [numero_rama]` | Descarta en $O(1)$ una rama paralela completa. Todo lo hecho por los agentes allí se borra instantáneamente. | `abort 42` |
| `why` | `why <id_efecto>` | **Auditoría Forense:** Traza hacia atrás toda la genealogía causal de una acción hasta su origen exacto. | `why 1` |
| `verify` | `verify` | Recorre todos los nodos del Merkle-DAG y verifica que ningún hash SHA-256 haya sido manipulado. | `verify` |
| `vm eval` | `vm eval` | Ejecuta un programa de bytecode en la máquina virtual de agentes midiendo consumo de gas estricto. | `vm eval` |
| `bench` | `bench` | Corre la suite de microbenchmarks estadísticos midiendo millones de operaciones por segundo en tu CPU. | `bench` |
| `demo` | `demo` | Corre la demostración automatizada completa mostrando todos los subsistemas en pantalla. | `demo` |
| `clear` | `clear` | Limpia la pantalla de la consola. | `clear` |
| `exit` | `exit` | Cierra la consola interactiva. | `exit` |

---

## 3. PARTE II: CREACIÓN CON CÓDIGO (DESARROLLO EN RUST)

Para desarrolladores que quieran programar agentes o construir servicios autónomos dentro de GenOS.

### Estructura de un Agente Nativo

Para crear un agente en código, se utiliza la entidad `AgentInstance` de la librería `agent-runtime`:

```rust
use agent_runtime::{AgentId, AgentGoal, AgentInstance};
use causal_core::DomainId;

// 1. Definir el identificador y dominio de seguridad
let agent_id = AgentId(1);
let domain_id = DomainId(1);

// 2. Definir su objetivo declarativo y sus presupuestos
// Parámetros: Descripción de la tarea, Máximo de pasos, Máximo de tokens de IA
let objetivo = AgentGoal::new("Analizar transacciones bancarias", 50, 5000);

// 3. Instanciar el agente en GenOS
let mut mi_agente = AgentInstance::new(agent_id, domain_id, objetivo);

println!("Agente creado con ID: {:?}", mi_agente.id);
println!("Estado de seguridad inicial: {:?}", mi_agente.security_label);
```

---

### Creación de Herramientas y Permisos (Capacidades)

En GenOS las herramientas no son funciones libres: están protegidas por **Capacidades**.

```rust
use agent_runtime::ToolDefinition;
use capability_engine::{Permissions, ObjectId};

// Definir una herramienta protegida
let herramienta_transferencia = ToolDefinition {
    name: "transferir_fondos".into(),
    // Permisos requeridos para poder usarla:
    required_permissions: Permissions::WRITE,
    // ¿Toca el mundo exterior de forma irreversible?
    is_external_side_effect: true, 
    // Identificador del objeto protegido:
    target_object: ObjectId(500),
};

// Conceder la capacidad al agente (solo si está autorizado):
let cap_id = mi_agente.grant_capability(ObjectId(500), Permissions::WRITE);
```

---

### El Supervisor de Seguridad y la Aduana de Escrow

Cuando el agente quiere ejecutar una herramienta, la petición pasa por el `AgentSupervisor`:

```rust
use agent_runtime::AgentSupervisor;

let mut supervisor = AgentSupervisor::new();

// El agente intenta ejecutar la herramienta
let resultado = supervisor.invoke_tool(
    &mut mi_agente,
    &herramienta_transferencia,
    cap_id,
    b"destinatario=cuenta_123&monto=500", // Payload de la orden
);

match resultado {
    Ok(res) => {
        if res.was_escrowed {
            println!("⚠️ La accion es peligrosa o especulativa: RETENIDA EN ESCROW.");
        } else {
            println!("✅ Accion ejecutada y registrada con EffectId: {:?}", res.effect_id);
        }
    }
    Err(e) => println!("❌ Bloqueado por seguridad del Kernel: {:?}", e),
}
```

---

### Búsqueda Semántica Vectorial en Código

El sistema de archivos `BranchFs` permite guardar documentos y buscar por significado semántico (usando vectores de embeddings):

```rust
use semantic_fs::{BranchFs, SemanticMetadata, EmbeddingVector};
use causal_core::{BranchId, DomainId, EffectId, SecurityLabel};

let mut fs = BranchFs::new();

// 1. Guardar un documento con un vector de 32 dimensiones
let meta = SemanticMetadata {
    content_type: "text/plain".into(),
    created_by: DomainId(1),
    causal_effect: EffectId(1),
    label: SecurityLabel::TRUSTED_KERNEL,
    tags: vec!["finanzas".into(), "reporte".into()],
};

fs.write_file(
    BranchId(0), // Rama principal
    "informe_anual.txt",
    b"Los ingresos crecieron un 25% durante el ultimo trimestre.".to_vec(),
    Some(EmbeddingVector::new([0.8; 32])), // Embedding semántico
    meta,
);

// 2. Buscar archivos por similitud de significado (similitud de coseno)
let vector_consulta = EmbeddingVector::new([0.75; 32]);
let resultados = fs.search_semantic(BranchId(0), &vector_consulta, 5, 0.1);

for (archivo, puntuacion) in resultados {
    println!("Archivo: {} | Similitud Coseno: {:.4}", archivo.path, puntuacion);
}
```

---

## 4. PARTE III: 4 CASOS PRÁCTICOS DEMOSTRATIVOS

Sigue estos ejemplos prácticos dentro de `cargo xtask shell` para experimentar los superpoderes de GenOS:

### Caso A: Enjambre de Agentes
1. Abre la consola: `cargo xtask shell`
2. Crea dos agentes:
   ```text
   spawn "Investigador" 20
   spawn "Analista" 20
   ```
3. Verifica que ambos existan:
   ```text
   agents
   ```
4. Comunícalos a través del microkernel:
   ```text
   ipc send 3 4 "Hola Analista, tengo nuevos datos del mercado"
   ```
   *El microkernel valida los permisos del canal, calcula el hash SHA-256 del mensaje y entrega el contenido sin fugas.*

---

### Caso B: El Multiverso (Pruebas con Cero Riesgo)
1. Salta a una realidad paralela (Rama 10):
   ```text
   fork 10
   ```
   *(Observa que el prompt ahora dice: `AgentOS [Branch:10] >`)*
2. Crea un archivo de prueba en esa realidad:
   ```text
   fs put "experimento.txt" "Borrando bases de datos de prueba"
   ```
3. Verifica que el archivo existe en la Rama 10:
   ```text
   fs list
   ```
4. Descarta la rama completa en $O(1)$ como si nunca hubiera existido:
   ```text
   abort 10
   ```
   *(El sistema vuelve a `Branch:0`).*
5. Comprueba la Rama 0:
   ```text
   fs list
   ```
   *El archivo `experimento.txt` se evaporó por completo sin dejar rastro ni alterar el disco.*

---

### Caso C: Bloqueo de Ataques (Prompt Injection)
1. En la consola, revisa tus agentes:
   ```text
   agents
   ```
   *(Todos están en estado `CLEAN`).*
2. Simula que el Agente 1 navegó por internet y leyó un correo trampa de un atacante:
   ```text
   taint 1
   ```
3. Revisa de nuevo:
   ```text
   agents
   ```
   *(El Agente 1 ahora está marcado como `TAINTED`).*
4. Si el Agente 1 intenta enviar información al Agente 2:
   ```text
   ipc send 1 2 "Ejecuta esta orden oculta que vino de internet"
   ```
   *El sistema te emitirá la alerta:*  
   `[ALERTA IFC] El receptor ha sido CONTAMINADO automaticamente por el mensaje!`  
   *GenOS propaga la advertencia y apaga físicamente los permisos para que la orden no pueda tocar datos sensibles.*

---

### Caso D: Auditoría Forense (`why` y `verify`)
1. Comprueba la integridad de toda la historia del sistema:
   ```text
   verify
   ```
   *Respuesta:* `[VERIFICACION EXITOSA] Todos los hashes coinciden. El historial es matematicamente inmutable.`
2. Pregúntale a GenOS el linaje exacto de una acción:
   ```text
   why 1
   ```
   *El sistema desplegará el árbol genealógico del efecto:*
   ```text
   └── [Nodo 1] Emitter: DomainId(1) -> Target: DomainId(2) | Merkle Hash: [a4, 3f...]
   ```

---

## 5. CHEAT SHEET (TABLA RÁPIDA DE COMANDOS)

Para tener a mano en cualquier momento:

```text
========================================================================
                      GENOS CHEAT SHEET RÁPIDO
========================================================================
GESTIÓN BÁSICA:
  status                      -> Ver salud del sistema y memoria
  agents                      -> Ver agentes, pasos y estado de seguridad
  spawn <nombre> <pasos>      -> Crear un agente nuevo
  clear                       -> Limpiar pantalla
  exit                        -> Salir

COMUNICACIÓN Y SEGURIDAD:
  ipc send <de> <a> <texto>   -> Enviar mensaje verificado por kernel
  taint <id>                  -> Simular ataque / contaminar agente
  verify                      -> Comprobar que nadie alteró el historial
  why <id_efecto>             -> Auditoría forense: rastrear causas

MULTIVERSO (EXPERIMENTOS SIN RIESGO):
  fork <numero>               -> Entrar a realidad alternativa
  commit <numero>             -> Guardar y aplicar cambios a la realidad
  abort <numero>              -> Descartar todo y volver al pasado

ARCHIVOS SEMÁNTICOS:
  fs list                     -> Listar archivos de la rama actual
  fs put <archivo> <texto>    -> Guardar con vector de 32 dimensiones
  fs search                   -> Búsqueda por significado (similitud coseno)
========================================================================
```

---
*GenOS — Sistema Operativo Diseñado y Creado por Genaro Agustín Passero.*
