//! Protocolo de arranque Limine (especificación v2/v3 en Rust estable sin dependencias)

#[repr(C)]
pub struct LimineBaseRevision {
    pub id: [u64; 2],
    pub revision: u64,
}

unsafe impl Sync for LimineBaseRevision {}

impl LimineBaseRevision {
    pub const fn new(revision: u64) -> Self {
        Self {
            id: [0xf9562b2d5c9516b6, 0xa4f121aa35c61474],
            revision,
        }
    }

    pub fn is_supported(&self) -> bool {
        // En el protocolo Limine, el bootloader sobreescribe `revision` con 0 si soporta la revisión solicitada
        self.revision == 0
    }
}

#[repr(C)]
pub struct LimineHhdmResponse {
    pub revision: u64,
    pub offset: u64,
}

#[repr(C)]
pub struct LimineHhdmRequest {
    pub id: [u64; 4],
    pub revision: u64,
    pub response: *const LimineHhdmResponse,
}

unsafe impl Sync for LimineHhdmRequest {}

impl LimineHhdmRequest {
    pub const fn new() -> Self {
        Self {
            id: [
                0xc7b1dd30df4c8b88,
                0x0a82e883a194f07b,
                0x48d15021a2b6364b,
                0xff907040e5761a34,
            ],
            revision: 0,
            response: core::ptr::null(),
        }
    }

    pub fn get_response(&self) -> Option<&LimineHhdmResponse> {
        if self.response.is_null() {
            None
        } else {
            unsafe { Some(&*self.response) }
        }
    }
}

impl Default for LimineHhdmRequest {
    fn default() -> Self {
        Self::new()
    }
}

pub const LIMINE_MEMMAP_USABLE: u64 = 0;
pub const LIMINE_MEMMAP_RESERVED: u64 = 1;
pub const LIMINE_MEMMAP_ACPI_RECLAIMABLE: u64 = 2;
pub const LIMINE_MEMMAP_ACPI_NVS: u64 = 3;
pub const LIMINE_MEMMAP_BAD_MEMORY: u64 = 4;
pub const LIMINE_MEMMAP_BOOTLOADER_RECLAIMABLE: u64 = 5;
pub const LIMINE_MEMMAP_EXECUTABLE_AND_MODULES: u64 = 6;
pub const LIMINE_MEMMAP_FRAMEBUFFER: u64 = 7;

#[repr(C)]
pub struct LimineMemmapEntry {
    pub base: u64,
    pub length: u64,
    pub typ: u64,
}

#[repr(C)]
pub struct LimineMemmapResponse {
    pub revision: u64,
    pub entry_count: u64,
    pub entries: *const *const LimineMemmapEntry,
}

impl LimineMemmapResponse {
    pub fn entry_count(&self) -> usize {
        self.entry_count as usize
    }

    pub fn get_entry(&self, index: usize) -> Option<&'static LimineMemmapEntry> {
        if index >= self.entry_count as usize || self.entries.is_null() {
            None
        } else {
            unsafe {
                let ptr = *self.entries.add(index);
                if ptr.is_null() {
                    None
                } else {
                    Some(&*ptr)
                }
            }
        }
    }
}

#[repr(C)]
pub struct LimineMemmapRequest {
    pub id: [u64; 4],
    pub revision: u64,
    pub response: *const LimineMemmapResponse,
}

unsafe impl Sync for LimineMemmapRequest {}

impl LimineMemmapRequest {
    pub const fn new() -> Self {
        Self {
            id: [
                0xc7b1dd30df4c8b88,
                0x0a82e883a194f07b,
                0x67cf3d9d378a806f,
                0xe304acdfc50c3c62,
            ],
            revision: 0,
            response: core::ptr::null(),
        }
    }

    pub fn get_response(&self) -> Option<&LimineMemmapResponse> {
        if self.response.is_null() {
            None
        } else {
            unsafe { Some(&*self.response) }
        }
    }
}

impl Default for LimineMemmapRequest {
    fn default() -> Self {
        Self::new()
    }
}

#[repr(C)]
pub struct LimineFramebuffer {
    pub address: *mut u8,
    pub width: u64,
    pub height: u64,
    pub pitch: u64,
    pub bpp: u16,
    pub memory_model: u8,
    pub red_mask_size: u8,
    pub red_mask_shift: u8,
    pub green_mask_size: u8,
    pub green_mask_shift: u8,
    pub blue_mask_size: u8,
    pub blue_mask_shift: u8,
}

#[repr(C)]
pub struct LimineFramebufferResponse {
    pub revision: u64,
    pub framebuffer_count: u64,
    pub framebuffers: *const *const LimineFramebuffer,
}

impl LimineFramebufferResponse {
    pub fn first_framebuffer(&self) -> Option<&'static LimineFramebuffer> {
        if self.framebuffer_count == 0 || self.framebuffers.is_null() {
            None
        } else {
            unsafe {
                let ptr = *self.framebuffers;
                if ptr.is_null() {
                    None
                } else {
                    Some(&*ptr)
                }
            }
        }
    }
}

#[repr(C)]
pub struct LimineFramebufferRequest {
    pub id: [u64; 4],
    pub revision: u64,
    pub response: *const LimineFramebufferResponse,
}

unsafe impl Sync for LimineFramebufferRequest {}

impl LimineFramebufferRequest {
    pub const fn new() -> Self {
        Self {
            id: [
                0xc7b1dd30df4c8b88,
                0x0a82e883a194f07b,
                0x9d5827dcd881dd75,
                0xa3148604f6fab11b,
            ],
            revision: 0,
            response: core::ptr::null(),
        }
    }

    pub fn get_response(&self) -> Option<&LimineFramebufferResponse> {
        if self.response.is_null() {
            None
        } else {
            unsafe { Some(&*self.response) }
        }
    }
}

impl Default for LimineFramebufferRequest {
    fn default() -> Self {
        Self::new()
    }
}


