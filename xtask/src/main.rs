use std::process::{Command, ExitStatus};
use std::path::PathBuf;
use std::fs;

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let command = args.get(1).map(|s| s.as_str()).unwrap_or("build");

    match command {
        "build" => {
            build_kernel(false);
            assemble_esp();
            println!("\n[xtask] Build completado. Particion ESP lista en target/esp");
        }
        "build-test" => {
            build_kernel(true);
            assemble_esp();
            println!("\n[xtask] Build de prueba completado con feature test-exit.");
        }
        "run" => {
            build_kernel(false);
            assemble_esp();
            run_qemu(false);
        }
        "test" => {
            build_kernel(true);
            assemble_esp();
            run_qemu(true);
        }
        _ => {
            eprintln!("Uso: cargo xtask [build | build-test | run | test]");
            std::process::exit(1);
        }
    }
}

fn build_kernel(test_mode: bool) {
    println!("[xtask] Compilando agentos-kernel para x86_64-unknown-none...");
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let mut cmd = Command::new(cargo);
    cmd.args(["build", "--package", "agentos-kernel", "--target", "x86_64-unknown-none"]);
    if test_mode {
        cmd.args(["--features", "test-exit"]);
    }

    let status = cmd.status().expect("Fallo al ejecutar cargo build");
    if !status.success() {
        eprintln!("[xtask] Error: La compilacion del kernel fallo.");
        std::process::exit(status.code().unwrap_or(1));
    }
}

fn assemble_esp() {
    println!("[xtask] Ensamblando particion virtual ESP en target/esp/EFI/BOOT...");
    let esp_boot = PathBuf::from("target/esp/EFI/BOOT");
    fs::create_dir_all(&esp_boot).expect("No se pudo crear target/esp/EFI/BOOT");

    // 1. Copiar kernel compilado
    let kernel_src = PathBuf::from("target/x86_64-unknown-none/debug/agentos-kernel");
    let kernel_dst = esp_boot.join("agentos-kernel");
    fs::copy(&kernel_src, &kernel_dst).expect("Fallo al copiar agentos-kernel a la ESP");

    // 2. Copiar configuracion de Limine
    let conf_src = PathBuf::from("boot/limine.conf");
    let conf_dst = esp_boot.join("limine.conf");
    fs::copy(&conf_src, &conf_dst).expect("Fallo al copiar limine.conf a la ESP");

    // 3. Copiar bootloader EFI de Limine si existe en target/limine
    let limine_efi_src = PathBuf::from("target/limine/BOOTX64.EFI");
    let limine_efi_dst = esp_boot.join("BOOTX64.EFI");
    if limine_efi_src.exists() {
        fs::copy(&limine_efi_src, &limine_efi_dst).expect("Fallo al copiar BOOTX64.EFI a la ESP");
    } else {
        println!("[xtask] AVISO: target/limine/BOOTX64.EFI no encontrado. Descargalo con git clone.");
    }
}

fn run_qemu(test_mode: bool) {
    println!("[xtask] Lanzando QEMU...");
    let qemu_path = find_qemu();

    let mut cmd = Command::new(&qemu_path);
    cmd.args([
        "-machine", "q35",
        "-m", "256M",
        "-drive", "format=raw,file=fat:rw:target/esp",
        "-serial", "stdio",
        "-no-reboot",
    ]);

    // Buscar OVMF firmware para UEFI
    if let Some(ovmf) = find_ovmf() {
        cmd.args(["-drive", &format!("if=pflash,format=raw,readonly=on,file={}", ovmf.display())]);
    }

    if test_mode {
        cmd.args([
            "-display", "none",
            "-device", "isa-debug-exit,iobase=0xf4,iosize=0x04",
        ]);
    }

    let status = cmd.status().unwrap_or_else(|e| {
        eprintln!("[xtask] Error al iniciar QEMU en '{}': {}", qemu_path.display(), e);
        eprintln!("[xtask] Asegurate de que QEMU este instalado o en el PATH.");
        std::process::exit(1);
    });

    handle_qemu_status(status, test_mode);
}

fn find_qemu() -> PathBuf {
    let standard_paths = [
        PathBuf::from("C:\\Program Files\\qemu\\qemu-system-x86_64.exe"),
        PathBuf::from("C:\\Program Files (x86)\\qemu\\qemu-system-x86_64.exe"),
        PathBuf::from("E:\\Genaro\\qemu\\qemu-system-x86_64.exe"),
    ];

    for path in &standard_paths {
        if path.exists() {
            return path.clone();
        }
    }

    PathBuf::from("qemu-system-x86_64")
}

fn find_ovmf() -> Option<PathBuf> {
    let candidates = [
        PathBuf::from("C:\\Program Files\\qemu\\share\\edk2-x86_64-code.fd"),
        PathBuf::from("C:\\Program Files\\qemu\\edk2-x86_64-code.fd"),
        PathBuf::from("E:\\Genaro\\qemu\\share\\edk2-x86_64-code.fd"),
    ];

    for c in &candidates {
        if c.exists() {
            return Some(c.clone());
        }
    }
    None
}

fn handle_qemu_status(status: ExitStatus, test_mode: bool) {
    if test_mode {
        // isa-debug-exit en QEMU:
        // Codigo 0x10 (Success) produce exit code = (0x10 << 1) | 1 = 33
        if status.code() == Some(33) {
            println!("\n=======================================================");
            println!("[xtask TEST PASS] QEMU retorno codigo 33 (Success).");
            println!("El kernel de AgentOS arranco y ejecuto correctamente!");
            println!("=======================================================");
            std::process::exit(0);
        } else {
            eprintln!("\n[xtask TEST FAIL] QEMU retorno codigo: {:?}", status.code());
            std::process::exit(status.code().unwrap_or(1));
        }
    } else {
        std::process::exit(status.code().unwrap_or(0));
    }
}
