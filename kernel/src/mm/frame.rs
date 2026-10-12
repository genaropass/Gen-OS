//! Gestor de Memoria Física (PMM - Physical Memory Manager)
//! Asigna y rastrea marcos físicos de 4 KiB a partir del mapa de memoria de Limine.

use crate::limine::{LimineMemmapResponse, LIMINE_MEMMAP_USABLE};
use crate::println;

pub const PAGE_SIZE: u64 = 4096;

/// Representa un marco de memoria física alineado a 4 KiB
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct PhysFrame {
    start_address: u64,
}

impl PhysFrame {
    pub const fn from_start_address(addr: u64) -> Self {
        Self {
            start_address: addr & !(PAGE_SIZE - 1),
        }
    }

    pub const fn start_address(&self) -> u64 {
        self.start_address
    }
}

/// Asignador de marcos físicos por avance (Bump Allocator con soporte de regiones múltiples)
pub struct PhysicalMemoryManager {
    hhdm_offset: u64,
    current_entry_idx: usize,
    next_frame_addr: u64,
    total_usable_bytes: u64,
    allocated_frames: u64,
    initialized: bool,
}

use crate::sync::IrqSpinLock;

static PMM: IrqSpinLock<PhysicalMemoryManager> = IrqSpinLock::new(PhysicalMemoryManager {
    hhdm_offset: 0,
    current_entry_idx: 0,
    next_frame_addr: 0,
    total_usable_bytes: 0,
    allocated_frames: 0,
    initialized: false,
});

impl PhysicalMemoryManager {
    pub fn init(&mut self, memmap: &LimineMemmapResponse, hhdm_offset: u64) {
        self.hhdm_offset = hhdm_offset;
        self.current_entry_idx = 0;
        self.next_frame_addr = 0;
        self.total_usable_bytes = 0;
        self.allocated_frames = 0;

        let count = memmap.entry_count();
        for i in 0..count {
            if let Some(entry) = memmap.get_entry(i) {
                if entry.typ == LIMINE_MEMMAP_USABLE {
                    self.total_usable_bytes += entry.length;
                    if self.next_frame_addr == 0 {
                        self.current_entry_idx = i;
                        // Alinear la dirección base al límite de página hacia arriba
                        self.next_frame_addr = (entry.base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                    }
                }
            }
        }

        self.initialized = true;
    }

    /// Asigna un marco de memoria física contiguo de 4 KiB
    pub fn alloc_frame(&mut self, memmap: &LimineMemmapResponse) -> Option<PhysFrame> {
        if !self.initialized {
            return None;
        }

        let count = memmap.entry_count();
        while self.current_entry_idx < count {
            if let Some(entry) = memmap.get_entry(self.current_entry_idx) {
                if entry.typ == LIMINE_MEMMAP_USABLE {
                    let entry_end = entry.base + entry.length;
                    if self.next_frame_addr + PAGE_SIZE <= entry_end {
                        let frame = PhysFrame::from_start_address(self.next_frame_addr);
                        self.next_frame_addr += PAGE_SIZE;
                        self.allocated_frames += 1;
                        return Some(frame);
                    }
                }
            }

            // Pasar a la siguiente entrada utilizable
            self.current_entry_idx += 1;
            if self.current_entry_idx < count {
                if let Some(next_entry) = memmap.get_entry(self.current_entry_idx) {
                    if next_entry.typ == LIMINE_MEMMAP_USABLE {
                        self.next_frame_addr = (next_entry.base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                    }
                }
            }
        }

        None
    }

    pub fn total_usable_bytes(&self) -> u64 {
        self.total_usable_bytes
    }

    pub fn allocated_frames(&self) -> u64 {
        self.allocated_frames
    }

    pub fn hhdm_offset(&self) -> u64 {
        self.hhdm_offset
    }
}

/// Inicializa el PMM global
pub fn init(memmap: &LimineMemmapResponse, hhdm_offset: u64) {
    let mut pmm = PMM.lock();
    pmm.init(memmap, hhdm_offset);
    println!(
        "[AgentOS::PMM] Memoria fisica utilizable: {} MiB ({} KiB)",
        pmm.total_usable_bytes() / (1024 * 1024),
        pmm.total_usable_bytes() / 1024
    );
}

/// Asigna un marco físico global
pub fn alloc_frame(memmap: &LimineMemmapResponse) -> Option<PhysFrame> {
    PMM.lock().alloc_frame(memmap)
}

/// Obtiene el offset del HHDM
pub fn hhdm_offset() -> u64 {
    PMM.lock().hhdm_offset()
}

/// Retorna estadisticas reales de PMM: (marcos_asignados, total_bytes_usables)
pub fn pmm_stats() -> (u64, u64) {
    let pmm = PMM.lock();
    (pmm.allocated_frames, pmm.total_usable_bytes)
}
