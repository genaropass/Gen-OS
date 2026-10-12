//! Acceso seguro a memoria de espacio de usuario desde Ring 0 (uaccess)
//! Implementa verificación estricta de límites canónicos inferiores y control de SMAP (STAC / CLAC).

pub const EPERM: i64 = -1;
pub const ENOENT: i64 = -2;
pub const ESRCH: i64 = -3;
pub const EIO: i64 = -5;
pub const EBADF: i64 = -9;
pub const ENOMEM: i64 = -12;
pub const EACCES: i64 = -13;
pub const EFAULT: i64 = -14;
pub const EINVAL: i64 = -22;
pub const ENOSYS: i64 = -38;

/// Límite superior del espacio de direcciones de usuario en x86-64 (mitad inferior canónica)
pub const USER_SPACE_LIMIT: u64 = 0x0000_7fff_ffff_ffff;

/// Copia datos desde la memoria de usuario hacia un búfer del kernel con verificación y SMAP
pub fn copy_from_user(dst: &mut [u8], user_src: u64, len: usize) -> Result<(), i64> {
    if len == 0 {
        return Ok(());
    }

    // 1. Verificar que la dirección no desborde y resida enteramente en espacio de usuario
    let end = user_src.checked_add(len as u64).ok_or(EFAULT)?;
    if end > USER_SPACE_LIMIT || user_src == 0 {
        return Err(EFAULT);
    }
    if dst.len() < len {
        return Err(EINVAL);
    }

    // 2. Desbloquear SMAP temporalmente para lectura en Ring 0
    crate::arch::cpu::stac();

    unsafe {
        core::ptr::copy_nonoverlapping(user_src as *const u8, dst.as_mut_ptr(), len);
    }

    // 3. Re-bloquear SMAP
    crate::arch::cpu::clac();

    Ok(())
}

/// Copia datos desde un búfer del kernel hacia la memoria de usuario con verificación y SMAP
pub fn copy_to_user(user_dst: u64, src: &[u8], len: usize) -> Result<(), i64> {
    if len == 0 {
        return Ok(());
    }

    let end = user_dst.checked_add(len as u64).ok_or(EFAULT)?;
    if end > USER_SPACE_LIMIT || user_dst == 0 {
        return Err(EFAULT);
    }
    if src.len() < len {
        return Err(EINVAL);
    }

    crate::arch::cpu::stac();

    unsafe {
        core::ptr::copy_nonoverlapping(src.as_ptr(), user_dst as *mut u8, len);
    }

    crate::arch::cpu::clac();

    Ok(())
}
