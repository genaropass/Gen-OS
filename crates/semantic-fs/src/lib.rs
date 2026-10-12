//! # semantic-fs
//!
//! Sistema de Archivos Semántico y Ramas Copy-on-Write (BranchFS) para AgentOS.
//! Combina:
//! 1. Jerarquía tradicional de rutas de archivos (`/agents/agent_1/data.txt`).
//! 2. Índices vectoriales integrados y búsqueda por similitud de coseno.
//! 3. Trazabilidad causal y etiquetas de seguridad (IFC) por archivo.
//! 4. Ramificación Copy-on-Write para el Multiverso (BranchFS):
//!    - Los agentes pueden escribir en ramas especulativas sin alterar el sistema base.
//!    - `commit_branch`: Fusiona los deltas atómicamente.
//!    - `abort_branch`: Descarta las modificaciones especulativas en O(1).

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(not(feature = "std"))]
use alloc::{
    string::{String, ToString},
    vec::Vec,
    collections::BTreeMap,
};

#[cfg(feature = "std")]
use std::collections::BTreeMap;

use causal_core::{DomainId, BranchId, EffectId, SecurityLabel};

/// Vector semántico de dimensión fija en memoria para búsqueda vectorial en el kernel/runtime
#[derive(Clone, Copy, PartialEq, Debug)]
pub struct EmbeddingVector<const D: usize = 32> {
    pub values: [f32; D],
}

/// Raíz cuadrada precisa mediante el método de Newton-Raphson compatible con `#![no_std]`
#[inline]
fn sqrt_f32(x: f32) -> f32 {
    if x <= 0.0 {
        return 0.0;
    }
    let mut guess = x;
    for _ in 0..8 {
        guess = 0.5 * (guess + x / guess);
    }
    guess
}

impl<const D: usize> EmbeddingVector<D> {
    pub const fn zero() -> Self {
        Self { values: [0.0; D] }
    }

    pub fn new(values: [f32; D]) -> Self {
        Self { values }
    }

    /// Calcula la norma euclídea (L2) del vector
    pub fn norm(&self) -> f32 {
        let mut sum = 0.0f32;
        for &val in &self.values {
            sum += val * val;
        }
        sqrt_f32(sum)
    }

    /// Calcula la similitud de coseno entre dos vectores: (A · B) / (||A|| * ||B||)
    pub fn cosine_similarity(&self, other: &Self) -> f32 {
        let mut dot = 0.0f32;
        let mut norm_a = 0.0f32;
        let mut norm_b = 0.0f32;

        for i in 0..D {
            dot += self.values[i] * other.values[i];
            norm_a += self.values[i] * self.values[i];
            norm_b += other.values[i] * other.values[i];
        }

        let denom = sqrt_f32(norm_a) * sqrt_f32(norm_b);
        if denom == 0.0 {
            0.0
        } else {
            dot / denom
        }
    }
}

/// Metadatos semánticos y de procedencia de un archivo en AgentOS
#[derive(Clone, Debug, PartialEq)]
pub struct SemanticMetadata {
    pub content_type: String,
    pub created_by: DomainId,
    pub causal_effect: EffectId,
    pub label: SecurityLabel,
    pub tags: Vec<String>,
}

/// Entrada de archivo con soporte de contenido, embedding y procedencia
#[derive(Clone, Debug)]
pub struct FileEntry {
    pub path: String,
    pub content: Vec<u8>,
    pub embedding: Option<EmbeddingVector<32>>,
    pub metadata: SemanticMetadata,
    pub version: u64,
}

/// Sistema de Archivos Semántico con soporte de Ramas Copy-on-Write (BranchFS)
#[derive(Default, Debug)]
pub struct BranchFs {
    /// Archivos confirmados en la raíz del sistema
    root_files: BTreeMap<String, FileEntry>,
    /// Deltas de ramas especulativas: BranchId -> (Path -> Option<FileEntry>)
    /// Si el valor es None, indica que el archivo fue eliminado en esa rama.
    branches: BTreeMap<BranchId, BTreeMap<String, Option<FileEntry>>>,
    next_version: u64,
}

impl BranchFs {
    pub fn new() -> Self {
        Self {
            root_files: BTreeMap::new(),
            branches: BTreeMap::new(),
            next_version: 1,
        }
    }

    /// Escribe o actualiza un archivo en una rama específica (Copy-on-Write)
    pub fn write_file(
        &mut self,
        branch: BranchId,
        path: &str,
        content: Vec<u8>,
        embedding: Option<EmbeddingVector<32>>,
        metadata: SemanticMetadata,
    ) {
        let version = self.next_version;
        self.next_version += 1;

        let entry = FileEntry {
            path: path.to_string(),
            content,
            embedding,
            metadata,
            version,
        };

        if branch == BranchId(0) {
            // Escritura directa a la raíz confirmada
            self.root_files.insert(path.to_string(), entry);
        } else {
            // Escritura en el overlay Copy-on-Write de la rama especulativa
            let branch_overlay = self.branches.entry(branch).or_default();
            branch_overlay.insert(path.to_string(), Some(entry));
        }
    }

    /// Lee un archivo con resolución de ramas (Overlay de Rama -> Raíz)
    pub fn read_file(&self, branch: BranchId, path: &str) -> Option<&FileEntry> {
        if branch != BranchId(0) {
            if let Some(branch_overlay) = self.branches.get(&branch) {
                if let Some(delta) = branch_overlay.get(path) {
                    return delta.as_ref();
                }
            }
        }

        self.root_files.get(path)
    }

    /// Elimina un archivo en una rama (registra tombstone en el overlay CoW)
    pub fn delete_file(&mut self, branch: BranchId, path: &str) -> bool {
        if branch == BranchId(0) {
            self.root_files.remove(path).is_some()
        } else {
            if self.read_file(branch, path).is_some() {
                let branch_overlay = self.branches.entry(branch).or_default();
                branch_overlay.insert(path.to_string(), None);
                true
            } else {
                false
            }
        }
    }

    /// Confirma una rama especulativa: fusiona sus cambios en la raíz
    pub fn commit_branch(&mut self, branch: BranchId) -> usize {
        if let Some(overlay) = self.branches.remove(&branch) {
            let mut changes_applied = 0;
            for (path, delta) in overlay {
                match delta {
                    Some(file_entry) => {
                        self.root_files.insert(path, file_entry);
                        changes_applied += 1;
                    }
                    None => {
                        if self.root_files.remove(&path).is_some() {
                            changes_applied += 1;
                        }
                    }
                }
            }
            changes_applied
        } else {
            0
        }
    }

    /// Aborta una rama especulativa: descarta todos los deltas en O(1)
    pub fn abort_branch(&mut self, branch: BranchId) -> usize {
        if let Some(overlay) = self.branches.remove(&branch) {
            overlay.len()
        } else {
            0
        }
    }

    /// Lista todos los archivos visibles para una rama determinada
    pub fn list_files(&self, branch: BranchId) -> Vec<&FileEntry> {
        let mut visible: BTreeMap<&str, &FileEntry> = BTreeMap::new();

        // 1. Cargar archivos raíz
        for (path, entry) in &self.root_files {
            visible.insert(path.as_str(), entry);
        }

        // 2. Aplicar overlay de la rama si no es raíz
        if branch != BranchId(0) {
            if let Some(overlay) = self.branches.get(&branch) {
                for (path, delta) in overlay {
                    match delta {
                        Some(entry) => {
                            visible.insert(path.as_str(), entry);
                        }
                        None => {
                            visible.remove(path.as_str());
                        }
                    }
                }
            }
        }

        visible.into_values().collect()
    }

    /// Búsqueda semántica por similitud de coseno
    pub fn search_semantic(
        &self,
        branch: BranchId,
        query: &EmbeddingVector<32>,
        top_k: usize,
        min_similarity: f32,
    ) -> Vec<(&FileEntry, f32)> {
        let mut scored_results: Vec<(&FileEntry, f32)> = Vec::new();

        for file in self.list_files(branch) {
            if let Some(ref emb) = file.embedding {
                let sim = emb.cosine_similarity(query);
                if sim >= min_similarity {
                    scored_results.push((file, sim));
                }
            }
        }

        // Ordenar descendentemente por puntuación de similitud
        scored_results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(core::cmp::Ordering::Equal));
        scored_results.truncate(top_k);
        scored_results
    }

    /// Filtrado de procedencia por nivel de integridad (Information Flow Control)
    pub fn filter_by_integrity(&self, branch: BranchId, min_integrity: u16) -> Vec<&FileEntry> {
        self.list_files(branch)
            .into_iter()
            .filter(|f| f.metadata.label.integrity >= min_integrity)
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cosine_similarity() {
        let mut vec_a = [0.0f32; 32];
        vec_a[0] = 1.0;
        vec_a[1] = 0.5;

        let mut vec_b = [0.0f32; 32];
        vec_b[0] = 1.0;
        vec_b[1] = 0.5;

        let emb_a = EmbeddingVector::new(vec_a);
        let emb_b = EmbeddingVector::new(vec_b);

        let sim = emb_a.cosine_similarity(&emb_b);
        assert!((sim - 1.0).abs() < 1e-4, "Vectores identicos deben tener similitud 1.0");

        let mut vec_orthogonal = [0.0f32; 32];
        vec_orthogonal[2] = 1.0;
        let emb_ortho = EmbeddingVector::new(vec_orthogonal);
        let sim_ortho = emb_a.cosine_similarity(&emb_ortho);
        assert!((sim_ortho - 0.0).abs() < 1e-4, "Vectores ortogonales deben tener similitud 0.0");
    }

    #[test]
    fn test_branch_fs_isolation_and_abort() {
        let mut fs = BranchFs::new();
        let root = BranchId(0);
        let branch_1 = BranchId(101);

        let meta = SemanticMetadata {
            content_type: "text/markdown".to_string(),
            created_by: DomainId(1),
            causal_effect: EffectId(1),
            label: SecurityLabel::TRUSTED_KERNEL,
            tags: vec!["kernel".to_string()],
        };

        // Escribir archivo en la raíz
        fs.write_file(root, "/system/config.toml", b"version = 1".to_vec(), None, meta.clone());

        // Bifurcar en branch_1 y modificar el archivo
        fs.write_file(branch_1, "/system/config.toml", b"version = 2 (experimental)".to_vec(), None, meta.clone());
        // Crear un nuevo archivo privado en la rama
        fs.write_file(branch_1, "/temp/draft.txt", b"draft data".to_vec(), None, meta.clone());

        // Verificar aislamiento:
        assert_eq!(fs.read_file(root, "/system/config.toml").unwrap().content, b"version = 1");
        assert_eq!(fs.read_file(branch_1, "/system/config.toml").unwrap().content, b"version = 2 (experimental)");
        assert!(fs.read_file(root, "/temp/draft.txt").is_none());
        assert!(fs.read_file(branch_1, "/temp/draft.txt").is_some());

        // Abortar la rama:
        let discarded = fs.abort_branch(branch_1);
        assert_eq!(discarded, 2);

        // La raíz debe permanecer intacta:
        assert_eq!(fs.read_file(root, "/system/config.toml").unwrap().content, b"version = 1");
        assert!(fs.read_file(branch_1, "/temp/draft.txt").is_none());
    }

    #[test]
    fn test_branch_fs_commit() {
        let mut fs = BranchFs::new();
        let root = BranchId(0);
        let branch_2 = BranchId(102);

        let meta = SemanticMetadata {
            content_type: "text/plain".to_string(),
            created_by: DomainId(2),
            causal_effect: EffectId(2),
            label: SecurityLabel::TRUSTED_KERNEL,
            tags: vec![],
        };

        fs.write_file(branch_2, "/notes/idea.txt", b"groundbreaking idea".to_vec(), None, meta);
        assert!(fs.read_file(root, "/notes/idea.txt").is_none());

        // Confirmar rama en el multiverso:
        let applied = fs.commit_branch(branch_2);
        assert_eq!(applied, 1);
        assert_eq!(fs.read_file(root, "/notes/idea.txt").unwrap().content, b"groundbreaking idea");
    }

    #[test]
    fn test_semantic_search_and_ifc_filtering() {
        let mut fs = BranchFs::new();
        let root = BranchId(0);

        let mut v1 = [0.0f32; 32];
        v1[0] = 0.9;
        v1[1] = 0.1; // Vector relacionado con "sistemas operativos"

        let mut v2 = [0.0f32; 32];
        v2[0] = 0.85;
        v2[1] = 0.15; // Vector similar

        let mut v3 = [0.0f32; 32];
        v3[5] = 1.0; // Vector no relacionado (ej. "receta de cocina")

        let meta_trusted = SemanticMetadata {
            content_type: "text/plain".to_string(),
            created_by: DomainId(1),
            causal_effect: EffectId(1),
            label: SecurityLabel::TRUSTED_KERNEL,
            tags: vec!["os".to_string()],
        };

        let meta_untrusted = SemanticMetadata {
            content_type: "text/plain".to_string(),
            created_by: DomainId(99),
            causal_effect: EffectId(99),
            label: SecurityLabel::UNTRUSTED_EXTERNAL,
            tags: vec!["web".to_string()],
        };

        fs.write_file(root, "/docs/kernel_architecture.md", b"OS docs".to_vec(), Some(EmbeddingVector::new(v1)), meta_trusted.clone());
        fs.write_file(root, "/docs/scheduling.md", b"Sched docs".to_vec(), Some(EmbeddingVector::new(v2)), meta_trusted.clone());
        fs.write_file(root, "/untrusted/phishing.txt", b"evil docs".to_vec(), Some(EmbeddingVector::new(v1)), meta_untrusted);
        fs.write_file(root, "/misc/recipes.txt", b"cooking".to_vec(), Some(EmbeddingVector::new(v3)), meta_trusted);

        // Búsqueda semántica para vector cercano a v1:
        let query = EmbeddingVector::new(v1);
        let results = fs.search_semantic(root, &query, 5, 0.7);

        // Debe retornar los 3 documentos cercanos (similitud > 0.7), ordenados por afinidad
        assert_eq!(results.len(), 3);
        assert_eq!(results[0].0.path, "/docs/kernel_architecture.md");

        // Filtrado por integridad IFC:
        let trusted_only = fs.filter_by_integrity(root, 50);
        // Debe excluir "/untrusted/phishing.txt" porque su integridad es 10 (< 50)
        assert!(!trusted_only.iter().any(|f| f.path == "/untrusted/phishing.txt"));
        assert!(trusted_only.iter().any(|f| f.path == "/docs/kernel_architecture.md"));
    }
}
