//! Abstracción de Espacio de Direcciones (AddressSpace) para Agentes y Procesos Nativos
//! Cada agente o proceso posee una PML4 física independiente de 4 niveles:
//! - Entradas 256..512 (Mitad superior / Higher Half): Compartidas con el kernel (HHDM, drivers, syscalls).
//! - Entradas 0..256 (Mitad inferior / Lower Half): Exclusivas y aisladas por hardware para cada agente.

use crate::mm::paging::{
    PageTable, read_cr3, write_cr3, map_page, unmap_page, protect_page,
    phys_to_virt, translate_addr_in_pml4
};
use crate::mm::frame::{alloc_frame, hhdm_offset};

#[derive(Debug)]
pub struct AddressSpace {
    pub pml4_phys: u64,
}

impl AddressSpace {
    /// Crea un nuevo espacio de direcciones aislando Ring 3 / agentes
    pub fn new() -> Option<Self> {
        let frame = alloc_frame()?;
        let hhdm = hhdm_offset();
        let new_pml4_ptr = phys_to_virt(frame.start_address(), hhdm) as *mut PageTable;

        unsafe {
            let new_pml4 = &mut *new_pml4_ptr;
            new_pml4.zero();

            // Clonar la mitad superior del kernel (entradas 256..512) desde la PML4 activa
            let current_cr3 = read_cr3();
            let current_pml4_phys = current_cr3 & 0x000f_ffff_ffff_f000;
            let current_pml4 = &*(phys_to_virt(current_pml4_phys, hhdm) as *const PageTable);

            for i in 256..512 {
                new_pml4.entries[i] = current_pml4.entries[i];
            }
        }

        Some(Self {
            pml4_phys: frame.start_address(),
        })
    }

    /// Mapea una página virtual de 4 KiB en este espacio de direcciones
    pub fn map_page(&mut self, virt_addr: u64, phys_addr: u64, flags: u64) -> Result<(), &'static str> {
        let hhdm = hhdm_offset();
        map_page(self.pml4_phys, virt_addr, phys_addr, flags, hhdm)
    }

    /// Desmapea una página virtual de este espacio de direcciones
    pub fn unmap_page(&mut self, virt_addr: u64) -> Result<u64, &'static str> {
        let hhdm = hhdm_offset();
        unmap_page(self.pml4_phys, virt_addr, hhdm)
    }

    /// Modifica los permisos de una página virtual
    pub fn protect(&mut self, virt_addr: u64, flags: u64) -> Result<(), &'static str> {
        let hhdm = hhdm_offset();
        protect_page(self.pml4_phys, virt_addr, flags, hhdm)
    }

    /// Traduce una dirección virtual de este espacio a su marco físico correspondiente
    pub fn translate(&self, virt_addr: u64) -> Option<u64> {
        let hhdm = hhdm_offset();
        translate_addr_in_pml4(self.pml4_phys, virt_addr, hhdm)
    }

    /// Activa este espacio de direcciones en la CPU cargando CR3
    pub fn activate(&self) {
        write_cr3(self.pml4_phys);
    }
}
