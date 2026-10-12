//! Asignador Global del Montón del Kernel (Kernel Heap Allocator)
//! Habilita `extern crate alloc` (`Box`, `Vec`, `String`, etc.) mediante un asignador
//! de bloques con coalescencia bidireccional y protección por spinlock.

use core::alloc::{GlobalAlloc, Layout};
use core::sync::atomic::{AtomicBool, AtomicPtr, Ordering};
use crate::println;

/// Tamaño del montón inicial del kernel (1 MiB reservado en BSS, 0 bytes en disco)
pub const HEAP_SIZE: usize = 1024 * 1024; // 1 MiB

#[repr(align(16))]
struct HeapStorage {
    data: [u8; HEAP_SIZE],
}

static mut HEAP_STORAGE: HeapStorage = HeapStorage {
    data: [0; HEAP_SIZE],
};

#[repr(C, align(16))]
struct BlockHeader {
    size: usize,           // Tamaño utilizable del bloque (excluyendo este encabezado)
    is_free: bool,         // true si el bloque está disponible
    next: *mut BlockHeader,
    prev: *mut BlockHeader,
}

const HEADER_SIZE: usize = core::mem::size_of::<BlockHeader>();

pub struct Spinlock {
    locked: AtomicBool,
}

impl Spinlock {
    pub const fn new() -> Self {
        Self {
            locked: AtomicBool::new(false),
        }
    }

    pub fn lock(&self) {
        while self.locked.swap(true, Ordering::Acquire) {
            core::hint::spin_loop();
        }
    }

    pub fn unlock(&self) {
        self.locked.store(false, Ordering::Release);
    }
}

impl Default for Spinlock {
    fn default() -> Self {
        Self::new()
    }
}

pub struct KernelAllocator {
    lock: Spinlock,
    head: AtomicPtr<BlockHeader>,
    initialized: AtomicBool,
}

unsafe impl Sync for KernelAllocator {}

impl KernelAllocator {
    pub const fn new() -> Self {
        Self {
            lock: Spinlock::new(),
            head: AtomicPtr::new(core::ptr::null_mut()),
            initialized: AtomicBool::new(false),
        }
    }

    pub fn init(&self) {
        self.lock.lock();
        unsafe {
            let start = (&raw mut HEAP_STORAGE.data) as *mut u8;
            let first_block = start as *mut BlockHeader;

            (*first_block).size = HEAP_SIZE - HEADER_SIZE;
            (*first_block).is_free = true;
            (*first_block).next = core::ptr::null_mut();
            (*first_block).prev = core::ptr::null_mut();

            self.head.store(first_block, Ordering::Release);
        }
        self.initialized.store(true, Ordering::Release);
        self.lock.unlock();
    }
}

impl Default for KernelAllocator {
    fn default() -> Self {
        Self::new()
    }
}

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !self.initialized.load(Ordering::Acquire) {
            return core::ptr::null_mut();
        }

        self.lock.lock();

        let req_size = (layout.size() + 15) & !15; // Alinear a múltiplos de 16 bytes
        let align = layout.align().max(16);

        let mut curr = self.head.load(Ordering::Relaxed);
        let mut result = core::ptr::null_mut();

        while !curr.is_null() {
            let block = &mut *curr;
            if block.is_free && block.size >= req_size {
                let payload_addr = (curr as usize) + HEADER_SIZE;
                // Si la alineación requerida ya se cumple:
                if payload_addr.is_multiple_of(align) {
                    // ¿Es posible dividir el bloque?
                    let excess = block.size.saturating_sub(req_size);
                    if excess >= HEADER_SIZE + 32 {
                        let new_block_ptr = (payload_addr + req_size) as *mut BlockHeader;
                        let new_block = &mut *new_block_ptr;
                        new_block.size = excess - HEADER_SIZE;
                        new_block.is_free = true;
                        new_block.next = block.next;
                        new_block.prev = curr;

                        if !block.next.is_null() {
                            (*block.next).prev = new_block_ptr;
                        }
                        block.next = new_block_ptr;
                        block.size = req_size;
                    }

                    block.is_free = false;
                    result = payload_addr as *mut u8;
                    break;
                }
            }
            curr = block.next;
        }

        self.lock.unlock();
        result
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if ptr.is_null() || !self.initialized.load(Ordering::Acquire) {
            return;
        }

        self.lock.lock();

        let block_ptr = (ptr as usize - HEADER_SIZE) as *mut BlockHeader;
        let block = &mut *block_ptr;
        block.is_free = true;

        // Coalescencia con el bloque siguiente si está libre
        if !block.next.is_null() && (*block.next).is_free {
            let next_block = &mut *block.next;
            block.size += HEADER_SIZE + next_block.size;
            block.next = next_block.next;
            if !block.next.is_null() {
                (*block.next).prev = block_ptr;
            }
        }

        // Coalescencia con el bloque previo si está libre
        if !block.prev.is_null() && (*block.prev).is_free {
            let prev_block = &mut *block.prev;
            prev_block.size += HEADER_SIZE + block.size;
            prev_block.next = block.next;
            if !block.next.is_null() {
                (*block.next).prev = block.prev;
            }
        }

        self.lock.unlock();
    }
}

#[global_allocator]
pub static ALLOCATOR: KernelAllocator = KernelAllocator::new();

/// Inicializa el montón del kernel
pub fn init() {
    ALLOCATOR.init();
    println!(
        "[AgentOS::Heap] Monton dinamico del kernel inicializado: {} KiB (1 MiB)",
        HEAP_SIZE / 1024
    );
}

impl KernelAllocator {
    pub fn stats(&self) -> (usize, usize) {
        self.lock.lock();
        let mut total_free = 0;
        let mut total_allocated = 0;
        let mut curr = self.head.load(Ordering::Acquire);
        while !curr.is_null() {
            unsafe {
                if (*curr).is_free {
                    total_free += (*curr).size;
                } else {
                    total_allocated += (*curr).size;
                }
                curr = (*curr).next;
            }
        }
        self.lock.unlock();
        (total_allocated, total_free)
    }
}

/// Retorna estadisticas reales del Heap: (bytes_asignados, bytes_libres)
pub fn heap_stats() -> (usize, usize) {
    ALLOCATOR.stats()
}
