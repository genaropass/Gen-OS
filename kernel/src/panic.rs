//! Manejador de pánicos del kernel en modo bare-metal (`no_std`)

use core::panic::PanicInfo;
use crate::println;
use crate::qemu_exit::{exit_qemu, QemuExitCode};

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    println!("\n=======================================================");
    println!("[GENOS KERNEL PANIC]");
    if let Some(location) = info.location() {
        println!("Origen: {}:{}:{}", location.file(), location.line(), location.column());
    }
    println!("Mensaje: {}", info.message());
    println!("=======================================================");

    exit_qemu(QemuExitCode::Failed);
}
