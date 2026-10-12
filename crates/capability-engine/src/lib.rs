//! # capability-engine
//!
//! Subsistema formal de capacidades v2 para AgentOS.
//! Implementa seguridad de privilegio mínimo por diseño y contención adversarial:
//! - Ningún dominio accede a un recurso sin un token de capacidad explícito.
//! - Tokens con época/generación contra Use-After-Revocation (`CapId { slot, generation }`).
//! - Derechos de acceso finos: READ, WRITE, EXECUTE, GRANT, REVOKE, DECLASSIFY.
//! - Atenuación estricta de permisos: `child_rights <= parent_rights`.
//! - Revocación en cascada en árbol con avance de época por ranura.
//! - CSpace con capacidad máxima acotada para prevenir DoS por agotamiento de recursos.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::vec::Vec;

/// Identificador único de un objeto del sistema (memoria, endpoint, archivo, agente)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ObjectId(pub u64);

/// Identificador de una capacidad en el espacio de capacidades.
/// Empaqueta (generation: u32, slot: u32) en 64 bits para protección temporal contra Use-After-Revocation.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct CapId(pub u64);

impl CapId {
    pub const fn new(slot: u32, generation: u32) -> Self {
        Self(((generation as u64) << 32) | (slot as u64))
    }

    pub const fn slot(&self) -> u32 {
        (self.0 & 0xFFFF_FFFF) as u32
    }

    pub const fn generation(&self) -> u32 {
        (self.0 >> 32) as u32
    }
}

/// Máscara de permisos por capacidades
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Permissions(pub u32);

impl core::ops::BitOr for Permissions {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        Self(self.0 | rhs.0)
    }
}

impl core::ops::BitAnd for Permissions {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self {
        Self(self.0 & rhs.0)
    }
}

impl Permissions {
    pub const NONE: Self = Self(0);
    pub const READ: Self = Self(1 << 0);
    pub const WRITE: Self = Self(1 << 1);
    pub const EXECUTE: Self = Self(1 << 2);
    pub const GRANT: Self = Self(1 << 3);      // Permiso de delegar/derivar a otros
    pub const REVOKE: Self = Self(1 << 4);     // Permiso de revocar derivados
    pub const DECLASSIFY: Self = Self(1 << 5); // Permiso de desclasificar datos contaminados (IFC)

    pub const ALL: Self = Self(
        Self::READ.0 | Self::WRITE.0 | Self::EXECUTE.0 | Self::GRANT.0 | Self::REVOKE.0 | Self::DECLASSIFY.0
    );

    pub fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn intersect(&self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

/// Token de Capacidad
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Capability {
    pub id: CapId,
    pub object_id: ObjectId,
    pub permissions: Permissions,
    /// Capacidad padre de la cual fue derivada (si existe)
    pub parent: Option<CapId>,
    /// Identificador del dominio dueño
    pub owner: u32,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CapError {
    NotFound,
    PermissionDenied,
    AttenuationViolation, // Intento de derivar con más permisos que el padre
    InvalidSlot,
    EpochMismatch,        // Token revocado o caduco (Use-After-Revocation)
    CSpaceFull,           // Límite de tabla alcanzado (Mitigación DoS)
}

/// Ranura interna en la tabla de capacidades con época para validación de generación
#[derive(Clone, Debug)]
pub struct CapSlot {
    pub generation: u32,
    pub cap: Option<Capability>,
}

/// Tabla de Capacidades (CSpace) con protección temporal y límite de capacidad
#[derive(Debug)]
pub struct CSpace {
    slots: Vec<CapSlot>,
    max_slots: usize,
}

impl Default for CSpace {
    fn default() -> Self {
        Self::new()
    }
}

impl CSpace {
    pub const DEFAULT_MAX_SLOTS: usize = 1024;

    pub fn new() -> Self {
        Self::with_capacity(Self::DEFAULT_MAX_SLOTS)
    }

    pub fn with_capacity(max_slots: usize) -> Self {
        Self {
            slots: Vec::new(),
            max_slots,
        }
    }

    /// Emite una capacidad raíz inicial (solo invocable por el supervisor o kernel)
    pub fn mint_root(
        &mut self,
        object_id: ObjectId,
        permissions: Permissions,
        owner: u32,
    ) -> CapId {
        let (slot_idx, gen) = if let Some((idx, slot)) = self.slots.iter_mut().enumerate().find(|(_, s)| s.cap.is_none()) {
            slot.generation = slot.generation.wrapping_add(1);
            (idx as u32, slot.generation)
        } else {
            let idx = self.slots.len() as u32;
            self.slots.push(CapSlot { generation: 1, cap: None });
            (idx, 1)
        };

        let id = CapId::new(slot_idx, gen);
        let cap = Capability {
            id,
            object_id,
            permissions,
            parent: None,
            owner,
        };

        self.slots[slot_idx as usize].cap = Some(cap);
        id
    }

    /// Deriva una capacidad con permisos atenuados (iguales o menores)
    pub fn derive(
        &mut self,
        parent_id: CapId,
        requested_perms: Permissions,
        new_owner: u32,
    ) -> Result<CapId, CapError> {
        let (parent_obj, parent_perms) = {
            let slot_idx = parent_id.slot() as usize;
            let slot = self.slots.get(slot_idx).ok_or(CapError::NotFound)?;
            if slot.generation != parent_id.generation() {
                return Err(CapError::EpochMismatch);
            }
            let parent = slot.cap.as_ref().ok_or(CapError::NotFound)?;

            // Requiere permiso de GRANT para delegar
            if !parent.permissions.contains(Permissions::GRANT) {
                return Err(CapError::PermissionDenied);
            }

            // Invariante de atenuación: no se pueden otorgar permisos que el padre no posee
            if !parent.permissions.contains(requested_perms) {
                return Err(CapError::AttenuationViolation);
            }

            (parent.object_id, requested_perms)
        };

        if self.len() >= self.max_slots {
            return Err(CapError::CSpaceFull);
        }

        let (slot_idx, gen) = if let Some((idx, slot)) = self.slots.iter_mut().enumerate().find(|(_, s)| s.cap.is_none()) {
            slot.generation = slot.generation.wrapping_add(1);
            (idx as u32, slot.generation)
        } else {
            let idx = self.slots.len() as u32;
            self.slots.push(CapSlot { generation: 1, cap: None });
            (idx, 1)
        };

        let child_id = CapId::new(slot_idx, gen);
        let child_cap = Capability {
            id: child_id,
            object_id: parent_obj,
            permissions: parent_perms,
            parent: Some(parent_id),
            owner: new_owner,
        };

        self.slots[slot_idx as usize].cap = Some(child_cap);
        Ok(child_id)
    }

    /// Retorna una lista con las capacidades actualmente activas
    pub fn caps(&self) -> Vec<Capability> {
        self.slots.iter().filter_map(|s| s.cap.clone()).collect()
    }

    /// Obtiene una capacidad por ID comprobando concordancia de época
    pub fn get(&self, id: CapId) -> Option<&Capability> {
        let slot_idx = id.slot() as usize;
        let slot = self.slots.get(slot_idx)?;
        if slot.generation != id.generation() {
            return None; // Época no coincide: token caducado o revocado
        }
        slot.cap.as_ref()
    }

    /// Verifica si una capacidad existe, no fue revocada y posee los permisos requeridos
    pub fn verify(&self, id: CapId, required: Permissions) -> Result<ObjectId, CapError> {
        let slot_idx = id.slot() as usize;
        let slot = self.slots.get(slot_idx).ok_or(CapError::NotFound)?;
        if slot.generation != id.generation() {
            return Err(CapError::EpochMismatch);
        }
        let cap = slot.cap.as_ref().ok_or(CapError::NotFound)?;
        if cap.permissions.contains(required) {
            Ok(cap.object_id)
        } else {
            Err(CapError::PermissionDenied)
        }
    }

    /// Revoca recursivamente una capacidad y todos sus descendientes en el árbol
    pub fn revoke(&mut self, root_id: CapId) -> Result<usize, CapError> {
        let root_slot_idx = root_id.slot() as usize;
        let root_slot = self.slots.get(root_slot_idx).ok_or(CapError::NotFound)?;
        if root_slot.generation != root_id.generation() || root_slot.cap.is_none() {
            return Err(CapError::EpochMismatch);
        }

        // Buscar todos los descendientes recursivamente en el árbol
        let mut to_revoke_slots: Vec<usize> = Vec::new();
        to_revoke_slots.push(root_slot_idx);

        let mut i = 0;
        while i < to_revoke_slots.len() {
            let parent_slot_idx = to_revoke_slots[i];
            let parent_id = self.slots[parent_slot_idx].cap.as_ref().map(|c| c.id);
            if let Some(p_id) = parent_id {
                for (idx, slot) in self.slots.iter().enumerate() {
                    if let Some(ref cap) = slot.cap {
                        if cap.parent == Some(p_id) && !to_revoke_slots.contains(&idx) {
                            to_revoke_slots.push(idx);
                        }
                    }
                }
            }
            i += 1;
        }

        let count = to_revoke_slots.len();
        for slot_idx in to_revoke_slots {
            let slot = &mut self.slots[slot_idx];
            slot.cap = None;
            slot.generation = slot.generation.wrapping_add(1); // Invalida de inmediato todos los tokens antiguos
        }

        Ok(count)
    }

    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.cap.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_mint_and_verify() {
        let mut cspace = CSpace::new();
        let obj = ObjectId(42);

        let cap = cspace.mint_root(obj, Permissions::READ | Permissions::WRITE, 1);
        assert_eq!(cspace.verify(cap, Permissions::READ), Ok(obj));
        assert_eq!(cspace.verify(cap, Permissions::WRITE), Ok(obj));
        assert_eq!(cspace.verify(cap, Permissions::EXECUTE), Err(CapError::PermissionDenied));
    }

    #[test]
    fn test_attenuation_prevents_privilege_escalation() {
        let mut cspace = CSpace::new();
        let obj = ObjectId(100);

        let parent = cspace.mint_root(obj, Permissions::READ | Permissions::GRANT, 1);

        // Intentar derivar con ESCRITURA (debe fallar por atenuación)
        let attempt = cspace.derive(parent, Permissions::WRITE, 2);
        assert_eq!(attempt, Err(CapError::AttenuationViolation));

        // Derivar con solo LECTURA (debe triunfar)
        let child = cspace.derive(parent, Permissions::READ, 2);
        assert!(child.is_ok());
    }

    #[test]
    fn test_cascade_revocation_and_epoch_mismatch() {
        let mut cspace = CSpace::new();
        let obj = ObjectId(500);

        let root = cspace.mint_root(obj, Permissions::ALL, 1);
        let child1 = cspace.derive(root, Permissions::READ | Permissions::GRANT, 2).unwrap();
        let child2 = cspace.derive(root, Permissions::WRITE, 3).unwrap();
        let grandchild = cspace.derive(child1, Permissions::READ, 4).unwrap();

        assert_eq!(cspace.len(), 4);

        // Revocar child1 revoca child1 y grandchild
        let revoked = cspace.revoke(child1).unwrap();
        assert_eq!(revoked, 2);

        assert!(cspace.get(root).is_some());
        assert!(cspace.get(child2).is_some());
        assert!(cspace.get(child1).is_none());
        assert!(cspace.get(grandchild).is_none());

        // Verificación de los tokens revocados debe retornar EpochMismatch
        assert_eq!(cspace.verify(child1, Permissions::READ), Err(CapError::EpochMismatch));
        assert_eq!(cspace.verify(grandchild, Permissions::READ), Err(CapError::EpochMismatch));
    }

    #[test]
    fn test_cspace_bounded_capacity_dos_mitigation() {
        let mut cspace = CSpace::with_capacity(3);
        let obj = ObjectId(777);

        let cap1 = cspace.mint_root(obj, Permissions::ALL, 1);
        let cap2 = cspace.derive(cap1, Permissions::READ | Permissions::GRANT, 1).unwrap();
        let _cap3 = cspace.derive(cap2, Permissions::READ, 1).unwrap();

        assert_eq!(cspace.len(), 3);

        // Intentar agregar una 4ta capacidad en un CSpace de límite 3 debe fallar con CSpaceFull
        let overflow = cspace.derive(cap1, Permissions::READ, 1);
        assert_eq!(overflow, Err(CapError::CSpaceFull));
    }
}
