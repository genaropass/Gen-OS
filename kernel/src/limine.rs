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
