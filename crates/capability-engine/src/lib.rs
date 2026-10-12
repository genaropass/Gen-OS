//! # capability-engine
//!
//! Subsistema formal de capacidades para AgentOS.
//! Implementa seguridad de privilegio mínimo por diseño:
//! - Ningún dominio accede a un objeto sin un token de capacidad explícito.
//! - Atenuación de permisos (una capacidad derivada nunca puede tener más permisos que su padre).
//! - Revocación en cascada (al revocar un padre, se destruyen todos los hijos en el árbol).

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Identificador único de un objeto del sistema (memoria, endpoint, archivo, agente)
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ObjectId(pub u64);

/// Identificador de una capacidad en el espacio de capacidades
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct CapId(pub u64);

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
    pub const GRANT: Self = Self(1 << 3);   // Permiso de delegar/derivar a otros
    pub const REVOKE: Self = Self(1 << 4);  // Permiso de revocar derivados

    pub const ALL: Self = Self(
        Self::READ.0 | Self::WRITE.0 | Self::EXECUTE.0 | Self::GRANT.0 | Self::REVOKE.0
    );

    pub fn contains(&self, other: Self) -> bool {
        (self.0 & other.0) == other.0
    }

    pub fn intersect(&self, other: Self) -> Self {
        Self(self.0 & other.0)
    }
}

/// Token de Capacidad
#[derive(Clone, Debug)]
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
}

/// Tabla de Capacidades (CSpace)
#[derive(Default, Debug)]
pub struct CSpace {
    caps: Vec<Capability>,
    next_id: u64,
}

impl CSpace {
    pub fn new() -> Self {
        Self {
            caps: Vec::new(),
            next_id: 1,
        }
    }

    /// Emite una capacidad raíz inicial (solo invocable por el supervisor o kernel)
    pub fn mint_root(
        &mut self,
        object_id: ObjectId,
        permissions: Permissions,
        owner: u32,
    ) -> CapId {
        let id = CapId(self.next_id);
        self.next_id += 1;

        let cap = Capability {
            id,
            object_id,
            permissions,
            parent: None,
            owner,
        };

        self.caps.push(cap);
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
            let parent = self.get(parent_id).ok_or(CapError::NotFound)?;
            
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

        let child_id = CapId(self.next_id);
        self.next_id += 1;

        let child_cap = Capability {
            id: child_id,
            object_id: parent_obj,
            permissions: parent_perms,
            parent: Some(parent_id),
            owner: new_owner,
        };

        self.caps.push(child_cap);
        Ok(child_id)
    }

    /// Retorna una referencia a la lista de capacidades del espacio
    pub fn caps(&self) -> &[Capability] {
        &self.caps
    }

    /// Obtiene una capacidad por ID
    pub fn get(&self, id: CapId) -> Option<&Capability> {
        self.caps.iter().find(|c| c.id == id)
    }

    /// Verifica si una capacidad existe y tiene los permisos requeridos
    pub fn verify(&self, id: CapId, required: Permissions) -> Result<ObjectId, CapError> {
        let cap = self.get(id).ok_or(CapError::NotFound)?;
        if cap.permissions.contains(required) {
            Ok(cap.object_id)
        } else {
            Err(CapError::PermissionDenied)
        }
    }

    /// Revoca recursivamente una capacidad y todos sus descendientes en el árbol
    pub fn revoke(&mut self, root_id: CapId) -> Result<usize, CapError> {
        // Verificar que existe
        if self.get(root_id).is_none() {
            return Err(CapError::NotFound);
        }

        // Buscar todos los descendientes en anchura/profundidad
        let mut to_revoke = Vec::new();
        to_revoke.push(root_id);

        let mut i = 0;
        while i < to_revoke.len() {
            let current = to_revoke[i];
            for cap in &self.caps {
                if cap.parent == Some(current) && !to_revoke.contains(&cap.id) {
                    to_revoke.push(cap.id);
                }
            }
            i += 1;
        }

        let count = to_revoke.len();
        self.caps.retain(|c| !to_revoke.contains(&c.id));
        Ok(count)
    }

    pub fn len(&self) -> usize {
        self.caps.len()
    }

    pub fn is_empty(&self) -> bool {
        self.caps.is_empty()
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

        // Padre con solo LECTURA y GRANT
        let parent = cspace.mint_root(obj, Permissions::READ | Permissions::GRANT, 1);

        // Intentar derivar con ESCRITURA (debe fallar por atenuación)
        let attempt = cspace.derive(parent, Permissions::WRITE, 2);
        assert_eq!(attempt, Err(CapError::AttenuationViolation));

        // Derivar con solo LECTURA (debe triunfar)
        let child = cspace.derive(parent, Permissions::READ, 2);
        assert!(child.is_ok());
    }

    #[test]
    fn test_cascade_revocation() {
        let mut cspace = CSpace::new();
        let obj = ObjectId(500);

        let root = cspace.mint_root(obj, Permissions::ALL, 1);
        let child1 = cspace.derive(root, Permissions::READ | Permissions::GRANT, 2).unwrap();
        let child2 = cspace.derive(root, Permissions::WRITE, 3).unwrap();
        let grandchild = cspace.derive(child1, Permissions::READ, 4).unwrap();

        assert_eq!(cspace.len(), 4);

        // Revocar child1 debe revocar a child1 y a grandchild, pero dejar a root y child2 intactos
        let revoked = cspace.revoke(child1).unwrap();
        assert_eq!(revoked, 2); // child1 + grandchild

        assert!(cspace.get(root).is_some());
        assert!(cspace.get(child2).is_some());
        assert!(cspace.get(child1).is_none());
        assert!(cspace.get(grandchild).is_none());
    }
}
