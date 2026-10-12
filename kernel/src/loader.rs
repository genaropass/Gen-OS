//! Cargador de Binarios ELF de 64 bits para AgentOS (Ring 3)
//! Implementa la verificación estricta de encabezados ELF64, validación de rangos canónicos
//! en espacio de usuario (< 0x0000_8000_0000_0000), carga de segmentos PT_LOAD y protección W^X.

use crate::mm::address_space::AddressSpace;
use crate::mm::paging::flags;
use crate::mm::frame::{alloc_frame, hhdm_offset};
use crate::println;

pub const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const EM_X86_64: u16 = 62;
pub const PT_LOAD: u32 = 1;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

/// Límite canónico superior de la mitad inferior de memoria de usuario x86-64
pub const USER_CANONICAL_LIMIT: u64 = 0x0000_8000_0000_0000;

#[derive(Debug, PartialEq, Eq)]
pub enum ElfLoadError {
    BufferTooSmall,
    InvalidMagic,
    Not64Bit,
    NotLittleEndian,
    UnsupportedArchitecture,
    InvalidHeaderSize,
    ProgramHeadersOutOfBounds,
    SegmentOutOfBounds,
    OutOfMemory,
    PagingError(&'static str),
    InvalidUserAddress(u64),
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Header {
    pub e_ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Elf64Phdr {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// Parsea un encabezado ELF64 desde una porción de bytes
pub fn parse_header(bytes: &[u8]) -> Result<Elf64Header, ElfLoadError> {
    if bytes.len() < core::mem::size_of::<Elf64Header>() {
        return Err(ElfLoadError::BufferTooSmall);
    }

    let hdr_ptr = bytes.as_ptr() as *const Elf64Header;
    let hdr = unsafe { *hdr_ptr };

    if &hdr.e_ident[0..4] != ELFMAG {
        return Err(ElfLoadError::InvalidMagic);
    }
    if hdr.e_ident[4] != ELFCLASS64 {
        return Err(ElfLoadError::Not64Bit);
    }
    if hdr.e_ident[5] != ELFDATA2LSB {
        return Err(ElfLoadError::NotLittleEndian);
    }
    if hdr.e_machine != EM_X86_64 {
        return Err(ElfLoadError::UnsupportedArchitecture);
    }

    Ok(hdr)
}

/// Carga un binario ELF64 estático en el espacio de direcciones de un agente
pub fn load_elf(
    bytes: &[u8],
    address_space: &mut AddressSpace,
) -> Result<u64, ElfLoadError> {
    let hdr = parse_header(bytes)?;
    let hhdm = hhdm_offset();

    let phoff = hdr.e_phoff as usize;
    let phentsize = hdr.e_phentsize as usize;
    let phnum = hdr.e_phnum as usize;

    if phoff + phnum * phentsize > bytes.len() {
        return Err(ElfLoadError::ProgramHeadersOutOfBounds);
    }

    for i in 0..phnum {
        let entry_offset = phoff + i * phentsize;
        let phdr_ptr = unsafe { bytes.as_ptr().add(entry_offset) as *const Elf64Phdr };
        let phdr = unsafe { *phdr_ptr };

        if phdr.p_type != PT_LOAD {
            continue;
        }

        // Validar que el segmento no se extienda al espacio del kernel
        let vaddr_end = phdr.p_vaddr.checked_add(phdr.p_memsz)
            .ok_or(ElfLoadError::SegmentOutOfBounds)?;

        if vaddr_end > USER_CANONICAL_LIMIT || phdr.p_vaddr >= USER_CANONICAL_LIMIT {
            return Err(ElfLoadError::InvalidUserAddress(phdr.p_vaddr));
        }

        let file_offset = phdr.p_offset as usize;
        let file_size = phdr.p_filesz as usize;
        if file_offset + file_size > bytes.len() {
            return Err(ElfLoadError::SegmentOutOfBounds);
        }

        // Determinar flags de página con cumplimiento W^X estricto
        let mut page_flags = flags::USER_ACCESSIBLE;
        if (phdr.p_flags & PF_W) != 0 {
            page_flags |= flags::WRITABLE;
        }
        if (phdr.p_flags & PF_X) == 0 {
            page_flags |= flags::NO_EXECUTE;
        }

        // Mapear cada página virtual del segmento
        let page_start = phdr.p_vaddr & !0xFFF;
        let page_end = (vaddr_end + 0xFFF) & !0xFFF;

        for page_virt in (page_start..page_end).step_by(4096) {
            let phys_addr = match address_space.translate(page_virt) {
                Some(p) => p,
                None => {
                    let frame = alloc_frame().ok_or(ElfLoadError::OutOfMemory)?;
                    let p = frame.start_address();
                    // Limpiar el nuevo marco a ceros
                    unsafe {
                        let dst = (hhdm + p) as *mut u8;
                        core::ptr::write_bytes(dst, 0, 4096);
                    }
                    address_space.map_page(page_virt, p, page_flags)
                        .map_err(|e| ElfLoadError::PagingError(e))?;
                    p
                }
            };

            // Copiar los datos correspondientes del segmento si se solapan con esta página
            let page_offset = if phdr.p_vaddr > page_virt {
                phdr.p_vaddr - page_virt
            } else {
                0
            };

            if page_virt + page_offset < phdr.p_vaddr + phdr.p_filesz {
                let seg_offset = (page_virt + page_offset - phdr.p_vaddr) as usize;
                let copy_len = core::cmp::min(
                    (4096 - page_offset) as usize,
                    file_size.saturating_sub(seg_offset),
                );

                if copy_len > 0 {
                    unsafe {
                        let src = bytes.as_ptr().add(file_offset + seg_offset);
                        let dst = (hhdm + phys_addr + page_offset) as *mut u8;
                        core::ptr::copy_nonoverlapping(src, dst, copy_len);
                    }
                }
            }
        }
    }

    println!(
        "[AgentOS::Loader] Binario ELF cargado exitosamente. Punto de entrada: 0x{:08x}",
        hdr.e_entry
    );

    Ok(hdr.e_entry)
}

/// Asigna y mapea una pila de usuario aislada en el espacio de direcciones del agente
pub fn setup_user_stack(
    address_space: &mut AddressSpace,
    stack_top_virt: u64,
    num_pages: usize,
) -> Result<u64, ElfLoadError> {
    if stack_top_virt > USER_CANONICAL_LIMIT {
        return Err(ElfLoadError::InvalidUserAddress(stack_top_virt));
    }

    let stack_bytes = (num_pages as u64) * 4096;
    let stack_base = stack_top_virt.checked_sub(stack_bytes)
        .ok_or(ElfLoadError::SegmentOutOfBounds)?;

    let hhdm = hhdm_offset();
    let stack_flags = flags::USER_ACCESSIBLE | flags::WRITABLE | flags::NO_EXECUTE;

    for i in 0..num_pages {
        let page_virt = stack_base + (i as u64) * 4096;
        let frame = alloc_frame().ok_or(ElfLoadError::OutOfMemory)?;
        let phys_addr = frame.start_address();

        unsafe {
            let dst = (hhdm + phys_addr) as *mut u8;
            core::ptr::write_bytes(dst, 0, 4096);
        }

        address_space.map_page(page_virt, phys_addr, stack_flags)
            .map_err(|e| ElfLoadError::PagingError(e))?;
    }

    // Retornar stack_top alineado a 16 bytes
    Ok(stack_top_virt & !0xF)
}
