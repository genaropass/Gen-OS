//! Gestor de Memoria Física (PMM - Physical Memory Manager)
//! Asigna y rastrea marcos físicos de 4 KiB a partir del mapa de memoria de Limine.
//! Almacena las regiones utilizables en memoria interna para asignaciones autónomas libres de dependencias externas.

use crate::limine::{LimineMemmapResponse, LIMINE_MEMMAP_USABLE};
use crate::println;
use crate::sync::IrqSpinLock;

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

/// Descriptor de región física utilizable
#[derive(Clone, Copy, Default)]
pub struct UsableRegion {
    pub base: u64,
    pub length: u64,
}

/// Asignador de marcos físicos con lista libre de reciclaje y bump allocator
pub struct PhysicalMemoryManager {
    hhdm_offset: u64,
    regions: [UsableRegion; 32],
    region_count: usize,
    current_region_idx: usize,
    next_frame_addr: u64,
    total_usable_bytes: u64,
    allocated_frames: u64,
    free_frames: [u64; 256],
    free_frame_count: usize,
    initialized: bool,
}

static PMM: IrqSpinLock<PhysicalMemoryManager> = IrqSpinLock::new(PhysicalMemoryManager {
    hhdm_offset: 0,
    regions: [UsableRegion { base: 0, length: 0 }; 32],
    region_count: 0,
    current_region_idx: 0,
    next_frame_addr: 0,
    total_usable_bytes: 0,
    allocated_frames: 0,
    free_frames: [0; 256],
    free_frame_count: 0,
    initialized: false,
});

impl PhysicalMemoryManager {
    pub fn init(&mut self, memmap: &LimineMemmapResponse, hhdm_offset: u64) {
        self.hhdm_offset = hhdm_offset;
        self.region_count = 0;
        self.current_region_idx = 0;
        self.next_frame_addr = 0;
        self.total_usable_bytes = 0;
        self.allocated_frames = 0;

        let count = memmap.entry_count();
        for i in 0..count {
            if let Some(entry) = memmap.get_entry(i) {
                if entry.typ == LIMINE_MEMMAP_USABLE {
                    self.total_usable_bytes += entry.length;
                    if self.region_count < 32 {
                        self.regions[self.region_count] = UsableRegion {
                            base: entry.base,
                            length: entry.length,
                        };
                        if self.region_count == 0 {
                            self.next_frame_addr = (entry.base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
                        }
                        self.region_count += 1;
                    }
                }
            }
        }

        self.initialized = true;
    }

    /// Asigna un marco de memoria física contiguo de 4 KiB
    pub fn alloc_frame(&mut self) -> Option<PhysFrame> {
        if !self.initialized {
            return None;
        }

        // 1. Reutilizar marco reciclado de la lista libre si existe
        if self.free_frame_count > 0 {
            self.free_frame_count -= 1;
            let addr = self.free_frames[self.free_frame_count];
            self.allocated_frames += 1;
            return Some(PhysFrame::from_start_address(addr));
        }

        // 2. Bump allocator sobre las regiones descubiertas
        while self.current_region_idx < self.region_count {
            let reg = self.regions[self.current_region_idx];
            let reg_end = reg.base + reg.length;
            if self.next_frame_addr + PAGE_SIZE <= reg_end {
                let frame = PhysFrame::from_start_address(self.next_frame_addr);
                self.next_frame_addr += PAGE_SIZE;
                self.allocated_frames += 1;
                return Some(frame);
            }

            // Pasar a la siguiente región utilizable
            self.current_region_idx += 1;
            if self.current_region_idx < self.region_count {
                let next_reg = self.regions[self.current_region_idx];
                self.next_frame_addr = (next_reg.base + PAGE_SIZE - 1) & !(PAGE_SIZE - 1);
            }
        }

        None
    }

    /// Recicla un marco de memoria física liberado
    pub fn free_frame(&mut self, frame: PhysFrame) {
        if self.free_frame_count < self.free_frames.len() {
            self.free_frames[self.free_frame_count] = frame.start_address();
            self.free_frame_count += 1;
            if self.allocated_frames > 0 {
                self.allocated_frames -= 1;
            }
        }
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
        "[AgentOS::PMM] Memoria fisica utilizable: {} MiB ({} KiB en {} regiones)",
        pmm.total_usable_bytes() / (1024 * 1024),
        pmm.total_usable_bytes() / 1024,
        pmm.region_count
    );
}

/// Asigna un marco físico global
pub fn alloc_frame() -> Option<PhysFrame> {
    PMM.lock().alloc_frame()
}

/// Libera un marco físico global y lo retorna al PMM para reciclaje
pub fn free_frame(frame: PhysFrame) {
    PMM.lock().free_frame(frame);
}

/// Obtiene el offset del HHDM
pub fn hhdm_offset() -> u64 {
    PMM.lock().hhdm_offset()
}

/// Retorna estadísticas reales de PMM: (marcos_asignados, total_bytes_usables)
pub fn pmm_stats() -> (u64, u64) {
    let pmm = PMM.lock();
    (pmm.allocated_frames, pmm.total_usable_bytes)
}
