//! Subsistema de Gestión de Memoria (MM - Memory Management) para AgentOS
//! Integra PMM (marcos físicos), VMM (paginación x86-64) y Heap global del kernel.

pub mod frame;
pub mod paging;
pub mod heap;
pub mod address_space;

use crate::limine::{LimineMemmapResponse, LimineHhdmResponse};
use crate::println;

/// Inicializa todos los componentes del subsistema de memoria
pub fn init(memmap: Option<&LimineMemmapResponse>, hhdm: Option<&LimineHhdmResponse>) {
    println!("[GenOS::MM] Inicializando subsistema de gestion de memoria...");

    let offset = hhdm.map(|h| h.offset).unwrap_or(0);

    // 1. Inicializar PMM si el bootloader proveyó el mapa de memoria
    if let Some(map) = memmap {
        frame::init(map, offset);
    } else {
        println!("[GenOS::MM] ADVERTENCIA: Mapa de memoria Limine no disponible en este arranque");
    }

    // 2. Diagnóstico de VMM / paginación
    paging::test_paging(offset);

    // 3. Inicializar el montón dinámico del kernel (habilita alloc::Vec, alloc::Box, etc.)
    heap::init();

    println!("[GenOS::MM] Subsistema de memoria operativo al 100%");
}
