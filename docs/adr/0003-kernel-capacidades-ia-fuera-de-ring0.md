# ADR-0003 — Kernel mínimo por capacidades; agentes y la IA fuera de ring 0

- **Estado:** Propuesto
- **Fecha:** 2026-10-11

## Contexto
AgentOS busca tratar a los agentes como entidades nativas. Hay que decidir qué parte de esa noción vive en el kernel. Meter semántica inmadura o modelos de IA en ring 0 agranda la superficie de ataque y congela abstracciones que todavía no entendemos.

## Decisión
1. **Estructura híbrida evolutiva:**
   - Fases 1–2: un único binario en ring 0, con límites de módulo limpios.
   - Desde la Fase 3: espacio de usuario, capacidades e IPC.
   - Después, drivers y servicios migran a ring 3 progresivamente.
2. **El kernel ofrece mecanismos genéricos** inspirados en seL4: `Domain`, `AddressSpace`, `Thread`, `Budget`, `Endpoint`, `Notification`, `CSpace`, además de *hooks* de auditoría. **No define un objeto `Agent`.**
3. **Un agente es un `Domain` administrado por el Supervisor de agentes** (servicio en ring 3). Objetivos, herramientas y memoria semántica viven en el runtime y en los servicios.
4. **Ningún modelo de IA corre en ring 0.** Las decisiones de IA son *propuestas* que pasan por un verificador determinista de políticas antes de cualquier invocación privilegiada.
5. El aislamiento entre agentes se basa en **hardware** (anillos y paginación). El aislamiento por lenguaje queda, como mucho, como complemento.

## Consecuencias
- (+) Kernel más pequeño, auditable y potencialmente verificable.
- (+) La semántica de "agente" puede evolucionar sin cambiar el kernel.
- (+) Comparaciones justas contra la línea base (Linux + AIOS).
- (−) La "nativeza" depende de que el Supervisor sea inevitable; lo garantizan las capacidades y debe probarse (criterios N1–N6).
- (−) Más IPC que en un diseño monolítico; su costo debe medirse.

## Revisión
Promover un concepto de agente al kernel **solo** si un experimento muestra que es necesario. Por ejemplo, si la planificación requiere plazos de objetivos (H6).

## Alternativas descartadas
Monolítico, microkernel puro desde el día 1, unikernel, aislamiento solo por lenguaje, construir sobre seL4, Linux + capa. Ver MASTER_PLAN §6.4.
