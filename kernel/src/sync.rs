//! Primitivas de sincronización seguras para el kernel bare-metal
//! `IrqSpinLock<T>` guarda RFLAGS, ejecuta `cli` y restaura el estado de interrupciones
//! al soltar el `IrqGuard`, garantizando exclusión mutua estricta libre de carreras con ISRs.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use core::ops::{Deref, DerefMut};

pub struct IrqSpinLock<T> {
    locked: AtomicBool,
    data: UnsafeCell<T>,
}

unsafe impl<T: Send> Sync for IrqSpinLock<T> {}
unsafe impl<T: Send> Send for IrqSpinLock<T> {}

pub struct IrqGuard<'a, T> {
    lock: &'a IrqSpinLock<T>,
    rflags: u64,
}

impl<T> IrqSpinLock<T> {
    pub const fn new(data: T) -> Self {
        Self {
            locked: AtomicBool::new(false),
            data: UnsafeCell::new(data),
        }
    }

    /// Adquiere el bloqueo guardando RFLAGS y deshabilitando interrupciones locales (`cli`)
    pub fn lock(&self) -> IrqGuard<'_, T> {
        let rflags = save_and_disable_interrupts();
        while self.locked.compare_exchange_weak(
            false,
            true,
            Ordering::Acquire,
            Ordering::Relaxed,
        ).is_err() {
            core::hint::spin_loop();
        }

        IrqGuard {
            lock: self,
            rflags,
        }
    }

    /// Intenta adquirir el bloqueo sin esperar. Si falla, restaura inmediatamente RFLAGS.
    pub fn try_lock(&self) -> Option<IrqGuard<'_, T>> {
        let rflags = save_and_disable_interrupts();
        if self.locked.compare_exchange(
            false,
            true,
            Ordering::Acquire,
            Ordering::Relaxed,
        ).is_ok() {
            Some(IrqGuard {
                lock: self,
                rflags,
            })
        } else {
            restore_interrupts(rflags);
            None
        }
    }
}

impl<'a, T> Deref for IrqGuard<'a, T> {
    type Target = T;
    fn deref(&self) -> &Self::Target {
        unsafe { &*self.lock.data.get() }
    }
}

impl<'a, T> DerefMut for IrqGuard<'a, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        unsafe { &mut *self.lock.data.get() }
    }
}

impl<'a, T> Drop for IrqGuard<'a, T> {
    fn drop(&mut self) {
        self.lock.locked.store(false, Ordering::Release);
        restore_interrupts(self.rflags);
    }
}

#[inline(always)]
fn save_and_disable_interrupts() -> u64 {
    let rflags: u64;
    unsafe {
        core::arch::asm!(
            "pushfq",
            "pop {}",
            "cli",
            out(reg) rflags,
            options(nomem, preserves_flags)
        );
    }
    rflags
}

#[inline(always)]
fn restore_interrupts(rflags: u64) {
    // Bit 9 de RFLAGS es el IF (Interrupt Enable Flag)
    if (rflags & (1 << 9)) != 0 {
        unsafe {
            core::arch::asm!("sti", options(nomem, nostack, preserves_flags));
        }
    }
}
