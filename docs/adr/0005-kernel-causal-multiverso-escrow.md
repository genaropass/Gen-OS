# ADR-0005 — El Kernel Causal: libro mayor inmutable, multiverso con escrow y análisis contrafactual

- **Estado:** Propuesto (incorporado tras la sesión de lluvia de ideas del 2026-10-11)
- **Fecha:** 2026-10-11

## Contexto
El análisis del estado del arte demostró que la mayoría de los "sistemas operativos para agentes" (AIOS, MemGPT, runtimes sobre Linux) operan como middleware en espacio de usuario. En Linux, las aplicaciones sufren de efectos colaterales no rastreables (carreras de memoria compartida, syscalls no deterministas, inyecciones de prompt que se propagan silenciosamente). 

Necesitamos una primitiva central propia del sistema que justifique plenamente un kernel nuevo desde cero, proporcionando propiedades que en Linux o Windows son matemáticamente imposibles de garantizar sin una sobrecarga destructiva.

## Decisión
AgentOS adoptará la tesis del **Kernel Causal** (*The Causal Operating System*):

1. **La Primitiva Fundamental:**
   En lugar de la abstracción clásica de Unix (*"todo es un archivo"*), en AgentOS **"toda interacción entre dominios es un efecto causalmente registrado"**.
   - Cada dominio (agente o servicio) es una máquina de estados estrictamente delimitada.
   - No existe memoria compartida mutable entre dominios; toda interacción ocurre mediante mensajes tipados mediados por capacidades.

2. **Libro Mayor Causal (*Causal Ledger*):**
   El kernel mantiene una estructura append-only indexada criptográficamente donde cada mensaje/syscall se registra como un vértice en un Grafo Acíclico Dirigido (DAG) de causas y consecuencias:
   $$\text{Efecto} = \langle \text{ID}, \text{Dominio Emisor}, \text{Capacidad}, \text{Causas Inmediatas}, \text{Payload}, \text{Etiquetas IFC}, \text{Estado de Reversibilidad} \rangle$$

3. **Multiverso y Escrow de Efectos Externos:**
   - **Ramas especulativas:** Los agentes pueden invocar ramas de exploración paralelas con aislamiento Copy-on-Write total.
   - **Barrera de Escrow:** Las acciones clasificadas como *irreversibles* (ej. enviar paquetes a una red real, borrar almacenamiento no versionado) no tocan el mundo exterior; se retienen en una cola de *Escrow* del kernel. Si la rama se descarta (`abort`), los efectos en escrow se evaporan sin dejar rastro externo. Si la rama hace `commit`, el kernel libera los efectos previa validación determinista.
   - **Entrelazamiento de ramas:** Si el Dominio A en la rama $\alpha$ envía un mensaje al Dominio B, B se ramifica implícitamente en el contexto de $\alpha$, garantizando que el commit o rollback sea atómico a través de todo el sistema.

4. **Syscalls Causal-Nativas:**
   - `why(effect_id) -> ProvenanceGraph`: Traza hacia atrás la cadena exacta de mensajes que desencadenaron un evento.
   - `counterfactual(effect_id, altered_input) -> SimulationDiff`: Re-ejecuta el subgrafo causal eliminando o alterando una entrada específica para probar causalidad forense ante ataques de inyección de prompt.

5. **Modo Sueño (*Dreaming / Self-Evolution*):**
   Durante periodos ociosos, el sistema operativo puede tomar su propio libro mayor histórico y reproducir escenarios reales en mundos paralelos aislados para evaluar optimizaciones de políticas o parches propuestos por agentes de IA, promoviéndolos a producción únicamente si no generan regresiones comprobadas.

## Consecuencias
- **(+) Causalidad y explicabilidad por construcción:** Las inyecciones de prompt dejan de ser misteriosas; el sistema puede demostrar matemáticamente de qué entrada provino una acción peligrosa.
- **(+) Aislamiento especulativo total:** Los agentes pueden "equivocarse" o explorar soluciones en paralelo sin riesgo de romper el entorno real.
- **(+) Reproducibilidad determinista:** Al tratar a los modelos de lenguaje como dispositivos generadores de interrupciones cuyos tokens de salida se registran en el log, cualquier corrida puede ser reproducida bit a bit.
- **(−) Crecimiento del Libro Mayor:** Requiere poda periódica (*log compaction*) mediante puntos de control de estado (*state checkpoints*) y árboles de Merkle.
- **(−) Sobrecarga de mediación:** Cada invocación tiene un costo de registro en el DAG causal; debe optimizarse en Rust a nivel de punteros y buffers circulares `no_std`.

## Alternativas descartadas
- **Log tradicional de auditoría (auditd / syslog):** Solo guarda texto plano no estructurado sin dependencias causales matemáticas ni capacidad de replay.
- **Transacciones de base de datos a nivel de aplicación:** Depende de que cada desarrollador de agentes programe bien el rollback; no ofrece garantías a nivel de kernel.
