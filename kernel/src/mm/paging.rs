//! Gestor de Memoria Virtual (VMM - Virtual Memory Manager / Paging)
//! Soporte para paginación de 4 niveles x86-64 y traducción HHDM.

use core::arch::asm;
use crate::println;

pub const PAGE_SIZE: u64 = 4096;
pub const ENTRY_COUNT: usize = 512;

/// Banderas estándar de entradas de tablas de páginas x86-64
pub mod flags {
    pub const PRESENT: u64 = 1 << 0;
    pub const WRITABLE: u64 = 1 << 1;
    pub const USER_ACCESSIBLE: u64 = 1 << 2;
    pub const WRITE_THROUGH: u64 = 1 << 3;
    pub const NO_CACHE: u64 = 1 << 4;
    pub const ACCESSED: u64 = 1 << 5;
    pub const DIRTY: u64 = 1 << 6;
    pub const HUGE_PAGE: u64 = 1 << 7;
    pub const GLOBAL: u64 = 1 << 8;
    pub const NO_EXECUTE: u64 = 1 << 63;
}

/// Representa una tabla de páginas de 512 entradas (4 KiB)
#[repr(align(4096))]
pub struct PageTable {
    pub entries: [u64; ENTRY_COUNT],
}

impl PageTable {
    pub const fn empty() -> Self {
        Self {
            entries: [0; ENTRY_COUNT],
        }
    }

    pub fn zero(&mut self) {
        for entry in self.entries.iter_mut() {
            *entry = 0;
        }
    }
}

/// Lee el valor actual del registro de control CR3 (dirección física de la PML4 activa)
#[inline]
pub fn read_cr3() -> u64 {
    let cr3: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) cr3, options(nomem, nostack, preserves_flags));
    }
    cr3
}

/// Invalida la entrada del Translation Lookaside Buffer (TLB) para una dirección virtual
#[inline]
pub fn flush_tlb(virt_addr: u64) {
    unsafe {
        asm!("invlpg [{}]", in(reg) virt_addr, options(nostack, preserves_flags));
    }
}

/// Convierte una dirección física a su correspondiente dirección virtual a través del HHDM
#[inline]
pub fn phys_to_virt(phys_addr: u64, hhdm_offset: u64) -> u64 {
    phys_addr + hhdm_offset
}

/// Convierte una dirección virtual dentro del HHDM a su dirección física subyacente
#[inline]
pub fn virt_to_phys(virt_addr: u64, hhdm_offset: u64) -> Option<u64> {
    if virt_addr >= hhdm_offset {
        Some(virt_addr - hhdm_offset)
    } else {
        None
    }
}

/// Obtiene los índices de paginación de 4 niveles para una dirección virtual de 48 bits
#[inline]
pub fn page_indices(virt_addr: u64) -> (usize, usize, usize, usize, u64) {
    let pml4_idx = ((virt_addr >> 39) & 0x1ff) as usize;
    let pdpt_idx = ((virt_addr >> 30) & 0x1ff) as usize;
    let pd_idx = ((virt_addr >> 21) & 0x1ff) as usize;
    let pt_idx = ((virt_addr >> 12) & 0x1ff) as usize;
    let offset = virt_addr & 0xfff;
    (pml4_idx, pdpt_idx, pd_idx, pt_idx, offset)
}

/// Traduce una dirección virtual a física recorriendo la PML4 activa
pub fn translate_addr(virt_addr: u64, hhdm_offset: u64) -> Option<u64> {
    let cr3 = read_cr3();
    let pml4_phys = cr3 & 0x000f_ffff_ffff_f000;
    let pml4_ptr = phys_to_virt(pml4_phys, hhdm_offset) as *const PageTable;

    let (pml4_i, pdpt_i, pd_i, pt_i, offset) = page_indices(virt_addr);

    unsafe {
        let pml4 = &*pml4_ptr;
        let pml4_entry = pml4.entries[pml4_i];
        if (pml4_entry & flags::PRESENT) == 0 {
            return None;
        }

        let pdpt_phys = pml4_entry & 0x000f_ffff_ffff_f000;
        let pdpt_ptr = phys_to_virt(pdpt_phys, hhdm_offset) as *const PageTable;
        let pdpt = &*pdpt_ptr;
        let pdpt_entry = pdpt.entries[pdpt_i];
        if (pdpt_entry & flags::PRESENT) == 0 {
            return None;
        }

        // Si es una página gigante de 1 GiB
        if (pdpt_entry & flags::HUGE_PAGE) != 0 {
            let page_base = pdpt_entry & 0x000f_ffff_c000_0000;
            return Some(page_base + (virt_addr & 0x3fff_ffff));
        }

        let pd_phys = pdpt_entry & 0x000f_ffff_ffff_f000;
        let pd_ptr = phys_to_virt(pd_phys, hhdm_offset) as *const PageTable;
        let pd = &*pd_ptr;
        let pd_entry = pd.entries[pd_i];
        if (pd_entry & flags::PRESENT) == 0 {
            return None;
        }

        // Si es una página grande de 2 MiB
        if (pd_entry & flags::HUGE_PAGE) != 0 {
            let page_base = pd_entry & 0x000f_ffff_ffe0_0000;
            return Some(page_base + (virt_addr & 0x001f_ffff));
        }

        let pt_phys = pd_entry & 0x000f_ffff_ffff_f000;
        let pt_ptr = phys_to_virt(pt_phys, hhdm_offset) as *const PageTable;
        let pt = &*pt_ptr;
        let pt_entry = pt.entries[pt_i];
        if (pt_entry & flags::PRESENT) == 0 {
            return None;
        }

        let frame_base = pt_entry & 0x000f_ffff_ffff_f000;
        Some(frame_base + offset)
    }
}

/// Diagnóstico de paginación activa en el arranque
pub fn test_paging(hhdm_offset: u64) {
    let cr3 = read_cr3();
    println!("[AgentOS::VMM] CR3 activo (PML4 base): 0x{:016x}", cr3);

    // Probar traducción de una dirección conocida (ej. la base de código del kernel)
    let sample_virt = 0xffffffff80000000u64;
    if let Some(phys) = translate_addr(sample_virt, hhdm_offset) {
        println!("[AgentOS::VMM] Traduccion verificada: Virt 0x{:016x} -> Phys 0x{:016x}", sample_virt, phys);
    } else {
        println!("[AgentOS::VMM] Nota: Direccion 0x{:016x} no mapeada o usa paginas fuera de nivel 4", sample_virt);
    }
}
