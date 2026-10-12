//! Gestor de Memoria Virtual (VMM - Virtual Memory Manager / Paging)
//! Soporte para paginación de 4 niveles x86-64, traducción HHDM, mapeo dinámico de páginas,
//! desmapeo con invalidación de TLB (`invlpg`), protección W^X y cambio de PML4 vía CR3.

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

/// Escribe un nuevo valor en el registro de control CR3
#[inline]
pub fn write_cr3(cr3: u64) {
    unsafe {
        asm!("mov cr3, {}", in(reg) cr3, options(nostack, preserves_flags));
    }
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

/// Traduce una dirección virtual a física recorriendo la PML4 dada
pub fn translate_addr_in_pml4(pml4_phys: u64, virt_addr: u64, hhdm_offset: u64) -> Option<u64> {
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

/// Traduce una dirección virtual a física en la PML4 activa de CR3
pub fn translate_addr(virt_addr: u64, hhdm_offset: u64) -> Option<u64> {
    let cr3 = read_cr3();
    let pml4_phys = cr3 & 0x000f_ffff_ffff_f000;
    translate_addr_in_pml4(pml4_phys, virt_addr, hhdm_offset)
}

/// Mapea una página virtual de 4 KiB a un marco físico en la PML4 especificada
/// Asigna automáticamente tablas intermedias (PDPT, PD, PT) desde el PMM si no existen.
pub fn map_page(
    pml4_phys: u64,
    virt_addr: u64,
    phys_addr: u64,
    entry_flags: u64,
    hhdm_offset: u64,
) -> Result<(), &'static str> {
    let (pml4_i, pdpt_i, pd_i, pt_i, _) = page_indices(virt_addr);
    let intermediate_flags = flags::PRESENT | flags::WRITABLE | (entry_flags & flags::USER_ACCESSIBLE);

    unsafe {
        // 1. PML4 -> PDPT
        let pml4 = &mut *(phys_to_virt(pml4_phys, hhdm_offset) as *mut PageTable);
        if (pml4.entries[pml4_i] & flags::PRESENT) == 0 {
            let frame = crate::mm::frame::alloc_frame().ok_or("PMM agotado al asignar PDPT")?;
            let table = &mut *(phys_to_virt(frame.start_address(), hhdm_offset) as *mut PageTable);
            table.zero();
            pml4.entries[pml4_i] = frame.start_address() | intermediate_flags;
        } else if (entry_flags & flags::USER_ACCESSIBLE) != 0 {
            pml4.entries[pml4_i] |= flags::USER_ACCESSIBLE;
        }

        let pdpt_phys = pml4.entries[pml4_i] & 0x000f_ffff_ffff_f000;
        let pdpt = &mut *(phys_to_virt(pdpt_phys, hhdm_offset) as *mut PageTable);

        // 2. PDPT -> PD
        if (pdpt.entries[pdpt_i] & flags::PRESENT) == 0 {
            let frame = crate::mm::frame::alloc_frame().ok_or("PMM agotado al asignar PD")?;
            let table = &mut *(phys_to_virt(frame.start_address(), hhdm_offset) as *mut PageTable);
            table.zero();
            pdpt.entries[pdpt_i] = frame.start_address() | intermediate_flags;
        } else if (entry_flags & flags::USER_ACCESSIBLE) != 0 {
            pdpt.entries[pdpt_i] |= flags::USER_ACCESSIBLE;
        }

        let pd_phys = pdpt.entries[pdpt_i] & 0x000f_ffff_ffff_f000;
        let pd = &mut *(phys_to_virt(pd_phys, hhdm_offset) as *mut PageTable);

        // 3. PD -> PT
        if (pd.entries[pd_i] & flags::PRESENT) == 0 {
            let frame = crate::mm::frame::alloc_frame().ok_or("PMM agotado al asignar PT")?;
            let table = &mut *(phys_to_virt(frame.start_address(), hhdm_offset) as *mut PageTable);
            table.zero();
            pd.entries[pd_i] = frame.start_address() | intermediate_flags;
        } else if (entry_flags & flags::USER_ACCESSIBLE) != 0 {
            pd.entries[pd_i] |= flags::USER_ACCESSIBLE;
        }

        let pt_phys = pd.entries[pd_i] & 0x000f_ffff_ffff_f000;
        let pt = &mut *(phys_to_virt(pt_phys, hhdm_offset) as *mut PageTable);

        // 4. PT -> Marco físico destino
        pt.entries[pt_i] = (phys_addr & 0x000f_ffff_ffff_f000) | entry_flags | flags::PRESENT;
    }

    flush_tlb(virt_addr);
    Ok(())
}

/// Desmapea una página virtual de 4 KiB e invalida el TLB
pub fn unmap_page(
    pml4_phys: u64,
    virt_addr: u64,
    hhdm_offset: u64,
) -> Result<u64, &'static str> {
    let (pml4_i, pdpt_i, pd_i, pt_i, _) = page_indices(virt_addr);

    unsafe {
        let pml4 = &*(phys_to_virt(pml4_phys, hhdm_offset) as *const PageTable);
        if (pml4.entries[pml4_i] & flags::PRESENT) == 0 {
            return Err("PML4 entry no presente");
        }

        let pdpt_phys = pml4.entries[pml4_i] & 0x000f_ffff_ffff_f000;
        let pdpt = &*(phys_to_virt(pdpt_phys, hhdm_offset) as *const PageTable);
        if (pdpt.entries[pdpt_i] & flags::PRESENT) == 0 {
            return Err("PDPT entry no presente");
        }

        let pd_phys = pdpt.entries[pdpt_i] & 0x000f_ffff_ffff_f000;
        let pd = &*(phys_to_virt(pd_phys, hhdm_offset) as *const PageTable);
        if (pd.entries[pd_i] & flags::PRESENT) == 0 {
            return Err("PD entry no presente");
        }

        let pt_phys = pd.entries[pd_i] & 0x000f_ffff_ffff_f000;
        let pt = &mut *(phys_to_virt(pt_phys, hhdm_offset) as *mut PageTable);
        let old_entry = pt.entries[pt_i];
        if (old_entry & flags::PRESENT) == 0 {
            return Err("PT entry no presente");
        }

        pt.entries[pt_i] = 0;
        flush_tlb(virt_addr);
        Ok(old_entry & 0x000f_ffff_ffff_f000)
    }
}

/// Actualiza las banderas de protección de una página virtual mapeada
pub fn protect_page(
    pml4_phys: u64,
    virt_addr: u64,
    new_flags: u64,
    hhdm_offset: u64,
) -> Result<(), &'static str> {
    let (pml4_i, pdpt_i, pd_i, pt_i, _) = page_indices(virt_addr);

    unsafe {
        let pml4 = &*(phys_to_virt(pml4_phys, hhdm_offset) as *const PageTable);
        if (pml4.entries[pml4_i] & flags::PRESENT) == 0 {
            return Err("PML4 entry no presente");
        }

        let pdpt_phys = pml4.entries[pml4_i] & 0x000f_ffff_ffff_f000;
        let pdpt = &*(phys_to_virt(pdpt_phys, hhdm_offset) as *const PageTable);
        if (pdpt.entries[pdpt_i] & flags::PRESENT) == 0 {
            return Err("PDPT entry no presente");
        }

        let pd_phys = pdpt.entries[pdpt_i] & 0x000f_ffff_ffff_f000;
        let pd = &*(phys_to_virt(pd_phys, hhdm_offset) as *const PageTable);
        if (pd.entries[pd_i] & flags::PRESENT) == 0 {
            return Err("PD entry no presente");
        }

        let pt_phys = pd.entries[pd_i] & 0x000f_ffff_ffff_f000;
        let pt = &mut *(phys_to_virt(pt_phys, hhdm_offset) as *mut PageTable);
        let old_entry = pt.entries[pt_i];
        if (old_entry & flags::PRESENT) == 0 {
            return Err("PT entry no presente");
        }

        let phys = old_entry & 0x000f_ffff_ffff_f000;
        pt.entries[pt_i] = phys | new_flags | flags::PRESENT;
    }

    flush_tlb(virt_addr);
    Ok(())
}

/// Diagnóstico de paginación activa en el arranque
pub fn test_paging(hhdm_offset: u64) {
    let cr3 = read_cr3();
    println!("[GenOS::VMM] CR3 activo (PML4 base): 0x{:016x}", cr3);

    // Probar traducción de una dirección conocida (código del kernel)
    let sample_virt = 0xffffffff80000000u64;
    if let Some(phys) = translate_addr(sample_virt, hhdm_offset) {
        println!("[GenOS::VMM] Traduccion verificada: Virt 0x{:016x} -> Phys 0x{:016x}", sample_virt, phys);
    } else {
        println!("[GenOS::VMM] Nota: Direccion 0x{:016x} no mapeada o usa paginas fuera de nivel 4", sample_virt);
    }
}
