# 🪐 Guía Oficial de Ejecución de GenOS

Esta guía contiene el paso a paso para ejecutar **GenOS** tanto de forma directa en tu terminal de PowerShell como en la máquina virtual **QEMU**.

---

## 📌 Requisitos Previos (Verificación rápida)

Para asegurarte de que tu entorno está listo, abre PowerShell en la carpeta del proyecto (`E:\Genaro\Desktop\AgentOS`) y ejecuta:

```powershell
cargo xtask doctor
```

Deberás ver los 6 componentes con el indicador verde **[OK]**:
* Compilador Rust
* Target bare-metal `x86_64-unknown-none`
* Bootloader Limine 8.7.0 (SHA-256 verificado)
* Archivo de configuración `limine.conf`
* Emulador QEMU (instalado en `E:\qemu`)
* Firmware UEFI OVMF (`edk2-x86_64-code.fd`)

---

## 🚀 MODO 1: En PowerShell Directo (Instantáneo, sin máquina virtual)

Este modo corre los motores de GenOS directamente sobre el host de Windows. No abre ventanas pesadas y es el más rápido para interactuar con agentes.

### 1. Iniciar el Shell Interactivo de Operador (REPL)
```powershell
cargo xtask shell
```
* **¿Qué hace?** Abre la consola de GenOS donde puedes crear agentes, asignar metas, enviar mensajes y ver las ramas del multiverso.
* **Comandos útiles dentro del shell:**
  * `help`: Muestra la lista de todos los comandos disponibles.
  * `status`: Muestra el estado del sistema y recursos.
  * `agents`: Lista los agentes activos y su consumo.
  * `spawn <nombre> <meta>`: Crea un agente nuevo con un objetivo.
  * `exit`: Sale de la consola.

### 2. Ejecutar la Batería de Pruebas de Seguridad (57 tests)
```powershell
cargo test --workspace
```
* **¿Qué hace?** Corre todas las pruebas unitarias y los 7 ataques de hackers simulados para verificar que el sistema es impenetrable.

### 3. Ejecutar los Benchmarks Estadísticos de Rendimiento
```powershell
cargo run --release -p xtask -- bench
```
* **¿Qué hace?** Evalúa la velocidad real de los 8 subsistemas principales (capacidades, hashes, criptografía poscuántica WOTS+, planificador SchedCP, etc.).

---

## 🖥️ MODO 2: En Máquina Virtual QEMU (Arranque Bare-Metal UEFI)

Este modo arranca el microkernel genuino de GenOS como si estuvieras encendiendo una computadora física independiente con BIOS UEFI.

### Paso 1: Compilar el Kernel y Ensamblar la Partición Virtual UEFI
```powershell
cargo xtask build
```
* **¿Qué hace?** Compila el código en `#![no_std]` para procesadores `x86_64-unknown-none`, copia el bootloader oficial Limine 8.7.0 y genera la partición virtual UEFI en `target/esp`.

### Paso 2: Arrancar la Máquina Virtual en QEMU
```powershell
cargo xtask run
```
* **¿Qué hace?** 
  * Abre una ventana gráfica de QEMU.
  * Carga el firmware UEFI OVMF.
  * Limine inicia el microkernel de GenOS.
  * El kernel inicializa el reloj PIT, la memoria virtual paginada de 4 niveles, las tablas de descriptores y el puerto serial.

### ¿Cómo cerrar la Máquina Virtual?
* Puedes cerrar la ventana de QEMU con la cruz roja como cualquier programa, o presionar `Ctrl + C` en tu terminal de PowerShell.

---

## 🛠️ Atajos y Limpieza

* **Si alguna vez quieres limpiar archivos de compilación para empezar de cero:**
  ```powershell
  cargo clean
  ```
* **Para recompilar todo limpio:**
  ```powershell
  cargo xtask build
  ```
