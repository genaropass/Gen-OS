# AgentOS

Sistema operativo experimental, con **kernel propio en Rust (x86-64)**, diseñado para investigar el soporte nativo a agentes autónomos:

- identidad;
- capacidades;
- presupuestos de recursos;
- auditoría;
- ejecución transaccional;
- persistencia.

> **Estado:** Fase 0 (investigación y especificación). Todavía no hay código ejecutable.

## Documentación
- [Documento maestro de arquitectura e investigación](docs/MASTER_PLAN.md)
- [Estado actual](docs/STATUS.md)
- [Decisiones arquitectónicas (ADR)](docs/adr/)

## Principios
1. Kernel propio, no una distribución de Linux.
2. El kernel ofrece mecanismos deterministas; la IA vive en servicios de usuario y solo **propone**.
3. Mínimo privilegio y aislamiento por hardware.
4. Cada hito se verifica con pruebas automáticas en QEMU.
5. Ninguna afirmación de novedad sin evidencia.
