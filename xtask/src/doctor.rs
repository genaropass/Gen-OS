//! Diagnóstico del entorno de desarrollo y dependencias de AgentOS (cargo xtask doctor)

use std::path::{Path, PathBuf};
use std::process::Command;
use std::fs;
use causal_core::hash::sha256;

pub const EXPECTED_BOOTX64_SHA256: &str = "51ca2b20ed14bbc678a396cdfb0c1d941acbc155cabebc9bfafabe4cdae1be73";

pub fn run_doctor() {
    println!("\x1b[1;36m========================================================================");
    println!("   AGENTOS DIAGNOSTIC TOOL (cargo xtask doctor)");
    println!("   Verificación de Toolchain, Bootloader, QEMU y Firmware UEFI");
    println!("========================================================================\x1b[0m\n");

    let mut all_ok = true;

    // 1. Verificar rustc
    print!("  [1/6] Compilador Rust (rustc): ");
    if let Ok(out) = Command::new("rustc").arg("--version").output() {
        let ver = String::from_utf8_lossy(&out.stdout).trim().to_string();
        println!("\x1b[1;32mOK\x1b[0m ({})", ver);
    } else {
        println!("\x1b[1;31mFALLO\x1b[0m (rustc no encontrado en PATH)");
        all_ok = false;
    }

    // 2. Verificar target x86_64-unknown-none
    print!("  [2/6] Target bare-metal (x86_64-unknown-none): ");
    let target_check = Command::new("rustup")
        .args(["target", "list", "--installed"])
        .output();
    let has_target = match target_check {
        Ok(out) => String::from_utf8_lossy(&out.stdout).contains("x86_64-unknown-none"),
        Err(_) => false,
    };
    if has_target {
        println!("\x1b[1;32mOK\x1b[0m (Instalado)");
    } else {
        println!("\x1b[1;31mFALLO\x1b[0m (Ejecutar: rustup target add x86_64-unknown-none)");
        all_ok = false;
    }

    // 3. Verificar bootloader Limine versionado y hash SHA-256
    print!("  [3/6] Bootloader Limine (boot/limine/BOOTX64.EFI): ");
    let efi_path = Path::new("boot/limine/BOOTX64.EFI");
    if efi_path.exists() {
        match fs::read(efi_path) {
            Ok(bytes) => {
                let hash = compute_sha256_hex(&bytes);
                if hash.eq_ignore_ascii_case(EXPECTED_BOOTX64_SHA256) {
                    println!("\x1b[1;32mOK\x1b[0m (SHA-256 verificado: {:.12}...) [Limine 8.7.0]", hash);
                } else {
                    println!("\x1b[1;31mHASH INVALIDO\x1b[0m");
                    println!("        Esperado: {}", EXPECTED_BOOTX64_SHA256);
                    println!("        Obtenido: {}", hash);
                    all_ok = false;
                }
            }
            Err(e) => {
                println!("\x1b[1;31mERROR DE LECTURA\x1b[0m ({})", e);
                all_ok = false;
            }
        }
    } else {
        println!("\x1b[1;31mNO ENCONTRADO\x1b[0m (Falta boot/limine/BOOTX64.EFI)");
        all_ok = false;
    }

    // 4. Verificar configuración de arranque (boot/limine.conf)
    print!("  [4/6] Configuración de arranque (boot/limine.conf): ");
    let conf_path = Path::new("boot/limine.conf");
    if conf_path.exists() {
        println!("\x1b[1;32mOK\x1b[0m (Presente)");
    } else {
        println!("\x1b[1;31mFALLO\x1b[0m (No existe boot/limine.conf)");
        all_ok = false;
    }

    // 5. Verificar QEMU (emulador x86_64)
    print!("  [5/6] Emulador QEMU (qemu-system-x86_64): ");
    let qemu_bin = find_qemu();
    match &qemu_bin {
        Some(path) => {
            let ver_out = Command::new(path).arg("--version").output();
            let ver_str = match ver_out {
                Ok(o) => String::from_utf8_lossy(&o.stdout).lines().next().unwrap_or("").to_string(),
                Err(_) => path.display().to_string(),
            };
            println!("\x1b[1;32mOK\x1b[0m ({})", ver_str);
        }
        None => {
            println!("\x1b[1;33mPENDIENTE DE INSTALACION\x1b[0m");
            println!("        -> El instalador oficial está listo en: E:\\Genaro\\Desktop\\Instalar_QEMU.exe");
            println!("        -> Ejecútalo en Windows para completar la instalación.");
        }
    }

    // 6. Verificar Firmware UEFI (OVMF / edk2)
    print!("  [6/6] Firmware UEFI (OVMF / edk2-x86_64-code.fd): ");
    let ovmf_path = find_ovmf(&qemu_bin);
    match ovmf_path {
        Some(path) => {
            println!("\x1b[1;32mOK\x1b[0m ({})", path.display());
        }
        None => {
            if qemu_bin.is_some() {
                println!("\x1b[1;33mNO DETECTADO\x1b[0m (Se buscará automáticamente en la carpeta de QEMU)");
            } else {
                println!("\x1b[1;33mPENDIENTE\x1b[0m (Se incluirá automáticamente al instalar QEMU)");
            }
        }
    }

    println!("\n------------------------------------------------------------------------");
    if all_ok && qemu_bin.is_some() {
        println!("\x1b[1;32mTODO LISTO: Tu entorno está 100% configurado para compilar y arrancar AgentOS en QEMU.\x1b[0m");
        println!("Comandos recomendados:");
        println!("  cargo xtask build      - Compila el kernel y ensambla la partición UEFI ESP");
        println!("  cargo xtask run        - Arranca el microkernel en QEMU con UEFI");
        println!("  cargo xtask test-qemu  - Ejecuta la prueba automatizada bare-metal en QEMU");
    } else if all_ok {
        println!("\x1b[1;33mTOOLCHAIN Y BOOTLOADER LISTOS (100%):\x1b[0m");
        println!("Solo falta ejecutar el instalador de QEMU en tu Escritorio:");
        println!("  -> \x1b[1;37mE:\\Genaro\\Desktop\\Instalar_QEMU.exe\x1b[0m");
        println!("Una vez instalado, corre nuevamente 'cargo xtask doctor'.");
    } else {
        println!("\x1b[1;31mATENCION: Existen problemas en los componentes base. Revisa las alertas arriba.\x1b[0m");
    }
    println!("------------------------------------------------------------------------\n");
}

pub fn find_qemu() -> Option<PathBuf> {
    let candidates = [
        "qemu-system-x86_64",
        "qemu-system-x86_64.exe",
        r"C:\Program Files\qemu\qemu-system-x86_64.exe",
        r"C:\Program Files (x86)\qemu\qemu-system-x86_64.exe",
        r"E:\Genaro\qemu\qemu-system-x86_64.exe",
    ];

    for cand in &candidates {
        let path = PathBuf::from(cand);
        if path.exists() || Command::new(cand).arg("--version").output().is_ok() {
            return Some(path);
        }
    }
    None
}

pub fn find_ovmf(qemu_bin: &Option<PathBuf>) -> Option<PathBuf> {
    let mut search_dirs = Vec::new();

    if let Some(ref qemu_path) = qemu_bin {
        if let Some(parent) = qemu_path.parent() {
            search_dirs.push(parent.join("share"));
            search_dirs.push(parent.to_path_buf());
        }
    }

    search_dirs.push(PathBuf::from(r"C:\Program Files\qemu\share"));
    search_dirs.push(PathBuf::from(r"C:\Program Files\qemu"));
    search_dirs.push(PathBuf::from(r"C:\Program Files (x86)\qemu\share"));
    search_dirs.push(PathBuf::from(r"boot"));

    let filenames = [
        "edk2-x86_64-code.fd",
        "OVMF.fd",
        "ovmf-x86_64-code.bin",
        "OVMF_CODE.fd",
    ];

    for dir in &search_dirs {
        for name in &filenames {
            let candidate = dir.join(name);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    None
}

fn compute_sha256_hex(data: &[u8]) -> String {
    let hash_bytes = sha256(data);
    let mut s = String::with_capacity(64);
    for b in hash_bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
