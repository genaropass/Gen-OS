//! Journal Transaccional de Disco (Write-Ahead Logging / WAL) para Semantic-FS
//! Garantiza que una caída repentina (crash o corte de energía) no corrompa el sistema de archivos:
//! - Registro previo de toda mutación antes de su aplicación en el almacenamiento base.
//! - Marcadores atómicos de CommitTx y AbortTx.
//! - Procedimiento de recuperación automática post-crash: re-aplica únicamente transacciones confirmadas.

#[cfg(not(feature = "std"))]
use alloc::{
    string::{String, ToString},
    vec::Vec,
    collections::BTreeSet,
};

#[cfg(feature = "std")]
use std::{
    string::{String, ToString},
    vec::Vec,
    collections::BTreeSet,
};

use causal_core::{BranchId, DomainId, EffectId, SecurityLabel};
use crate::{BranchFs, SemanticMetadata};

pub const WAL_MAGIC: [u8; 8] = *b"AGENTWAL";

#[derive(Clone, Debug, PartialEq)]
pub enum WalOp {
    WriteFile { path: String, content: Vec<u8> },
    DeleteFile { path: String },
    CommitTx { tx_id: u64 },
    AbortTx { tx_id: u64 },
}

#[derive(Clone, Debug, PartialEq)]
pub struct WalRecord {
    pub sequence: u64,
    pub tx_id: u64,
    pub op: WalOp,
    pub checksum: u32,
}

impl WalRecord {
    /// Calcula un checksum determinista simple de 32 bits
    pub fn compute_checksum(sequence: u64, tx_id: u64, payload: &[u8]) -> u32 {
        let mut sum = 0x811c9dc5u32; // FNV-1a 32-bit offset basis
        for b in &sequence.to_be_bytes() {
            sum ^= *b as u32;
            sum = sum.wrapping_mul(0x01000193);
        }
        for b in &tx_id.to_be_bytes() {
            sum ^= *b as u32;
            sum = sum.wrapping_mul(0x01000193);
        }
        for b in payload {
            sum ^= *b as u32;
            sum = sum.wrapping_mul(0x01000193);
        }
        sum
    }

    /// Serializa el registro a bytes con encabezado mágico
    pub fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&WAL_MAGIC);
        buf.extend_from_slice(&self.sequence.to_be_bytes());
        buf.extend_from_slice(&self.tx_id.to_be_bytes());

        match &self.op {
            WalOp::WriteFile { path, content } => {
                buf.push(1); // OpCode 1: WriteFile
                let path_bytes = path.as_bytes();
                buf.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(path_bytes);
                buf.extend_from_slice(&(content.len() as u32).to_be_bytes());
                buf.extend_from_slice(content);
            }
            WalOp::DeleteFile { path } => {
                buf.push(2); // OpCode 2: DeleteFile
                let path_bytes = path.as_bytes();
                buf.extend_from_slice(&(path_bytes.len() as u32).to_be_bytes());
                buf.extend_from_slice(path_bytes);
            }
            WalOp::CommitTx { tx_id } => {
                buf.push(3); // OpCode 3: CommitTx
                buf.extend_from_slice(&tx_id.to_be_bytes());
            }
            WalOp::AbortTx { tx_id } => {
                buf.push(4); // OpCode 4: AbortTx
                buf.extend_from_slice(&tx_id.to_be_bytes());
            }
        }

        let checksum = Self::compute_checksum(self.sequence, self.tx_id, &buf[24..]);
        buf.extend_from_slice(&checksum.to_be_bytes());
        buf
    }

    /// Deserializa registros a partir de un flujo de bytes crudo
    pub fn parse_all(mut data: &[u8]) -> Result<Vec<WalRecord>, &'static str> {
        let mut records = Vec::new();

        while data.len() >= 24 {
            if data[0..8] != WAL_MAGIC {
                break; // Corrupción o fin del flujo válido
            }

            let seq = u64::from_be_bytes(data[8..16].try_into().unwrap());
            let tx_id = u64::from_be_bytes(data[16..24].try_into().unwrap());

            if data.len() < 25 {
                break;
            }

            let opcode = data[24];
            let payload_start = 24;

            match opcode {
                1 => {
                    // WriteFile
                    if data.len() < 29 { break; }
                    let path_len = u32::from_be_bytes(data[25..29].try_into().unwrap()) as usize;
                    if data.len() < 29 + path_len + 4 { break; }
                    let path_bytes = &data[29..29 + path_len];
                    let path = core::str::from_utf8(path_bytes).map_err(|_| "Ruta no es UTF-8")?.to_string();

                    let cont_len_offset = 29 + path_len;
                    let cont_len = u32::from_be_bytes(data[cont_len_offset..cont_len_offset + 4].try_into().unwrap()) as usize;
                    let cont_offset = cont_len_offset + 4;
                    if data.len() < cont_offset + cont_len + 4 { break; }
                    let content = data[cont_offset..cont_offset + cont_len].to_vec();

                    let chk_offset = cont_offset + cont_len;
                    let expected_chk = u32::from_be_bytes(data[chk_offset..chk_offset + 4].try_into().unwrap());
                    let actual_chk = Self::compute_checksum(seq, tx_id, &data[payload_start..chk_offset]);

                    if expected_chk != actual_chk {
                        return Err("Checksum invalido en registro WAL");
                    }

                    records.push(WalRecord {
                        sequence: seq,
                        tx_id,
                        op: WalOp::WriteFile { path, content },
                        checksum: actual_chk,
                    });

                    data = &data[chk_offset + 4..];
                }
                2 => {
                    // DeleteFile
                    if data.len() < 29 { break; }
                    let path_len = u32::from_be_bytes(data[25..29].try_into().unwrap()) as usize;
                    let chk_offset = 29 + path_len;
                    if data.len() < chk_offset + 4 { break; }
                    let path = core::str::from_utf8(&data[29..chk_offset]).map_err(|_| "Ruta no es UTF-8")?.to_string();
                    let expected_chk = u32::from_be_bytes(data[chk_offset..chk_offset + 4].try_into().unwrap());
                    let actual_chk = Self::compute_checksum(seq, tx_id, &data[payload_start..chk_offset]);

                    if expected_chk != actual_chk {
                        return Err("Checksum invalido en registro WAL");
                    }

                    records.push(WalRecord {
                        sequence: seq,
                        tx_id,
                        op: WalOp::DeleteFile { path },
                        checksum: actual_chk,
                    });

                    data = &data[chk_offset + 4..];
                }
                3 => {
                    // CommitTx
                    if data.len() < 37 { break; }
                    let commit_tx = u64::from_be_bytes(data[25..33].try_into().unwrap());
                    let expected_chk = u32::from_be_bytes(data[33..37].try_into().unwrap());
                    let actual_chk = Self::compute_checksum(seq, tx_id, &data[payload_start..33]);

                    if expected_chk != actual_chk {
                        return Err("Checksum invalido en CommitTx");
                    }

                    records.push(WalRecord {
                        sequence: seq,
                        tx_id,
                        op: WalOp::CommitTx { tx_id: commit_tx },
                        checksum: actual_chk,
                    });

                    data = &data[37..];
                }
                4 => {
                    // AbortTx
                    if data.len() < 37 { break; }
                    let abort_tx = u64::from_be_bytes(data[25..33].try_into().unwrap());
                    let expected_chk = u32::from_be_bytes(data[33..37].try_into().unwrap());
                    let actual_chk = Self::compute_checksum(seq, tx_id, &data[payload_start..33]);

                    if expected_chk != actual_chk {
                        return Err("Checksum invalido en AbortTx");
                    }

                    records.push(WalRecord {
                        sequence: seq,
                        tx_id,
                        op: WalOp::AbortTx { tx_id: abort_tx },
                        checksum: actual_chk,
                    });

                    data = &data[37..];
                }
                _ => break,
            }
        }

        Ok(records)
    }
}

/// Sistema de Archivos con Soporte de Write-Ahead Logging (WAL) y Recuperación ante Caídas
#[derive(Default, Debug)]
pub struct JournaledFs {
    pub fs: BranchFs,
    pub wal_bytes: Vec<u8>,
    next_sequence: u64,
    next_tx_id: u64,
}

impl JournaledFs {
    pub fn new() -> Self {
        Self {
            fs: BranchFs::new(),
            wal_bytes: Vec::new(),
            next_sequence: 1,
            next_tx_id: 1,
        }
    }

    /// Inicia una nueva transacción con WAL
    pub fn begin_tx(&mut self) -> u64 {
        let tx = self.next_tx_id;
        self.next_tx_id += 1;
        tx
    }

    /// Registra en el WAL y escribe en el BranchFs
    pub fn write_file_tx(
        &mut self,
        tx_id: u64,
        path: &str,
        content: Vec<u8>,
        metadata: SemanticMetadata,
    ) {
        let seq = self.next_sequence;
        self.next_sequence += 1;

        let record = WalRecord {
            sequence: seq,
            tx_id,
            op: WalOp::WriteFile {
                path: path.to_string(),
                content: content.clone(),
            },
            checksum: 0,
        };

        self.wal_bytes.extend_from_slice(&record.serialize());
        self.fs.write_file(BranchId(tx_id as u32), path, content, None, metadata);
    }

    /// Confirma la transacción en el WAL y fusiona los cambios a la raíz
    pub fn commit_tx(&mut self, tx_id: u64) {
        let seq = self.next_sequence;
        self.next_sequence += 1;

        let record = WalRecord {
            sequence: seq,
            tx_id,
            op: WalOp::CommitTx { tx_id },
            checksum: 0,
        };

        self.wal_bytes.extend_from_slice(&record.serialize());
        self.fs.commit_branch(BranchId(tx_id as u32));
    }

    /// Cancela la transacción en el WAL y purga los deltas no confirmados
    pub fn abort_tx(&mut self, tx_id: u64) {
        let seq = self.next_sequence;
        self.next_sequence += 1;

        let record = WalRecord {
            sequence: seq,
            tx_id,
            op: WalOp::AbortTx { tx_id },
            checksum: 0,
        };

        self.wal_bytes.extend_from_slice(&record.serialize());
        self.fs.abort_branch(BranchId(tx_id as u32));
    }

    /// Recupera el estado del sistema de archivos a partir del WAL descartando transacciones incompletas
    pub fn recover_from_wal(wal_data: &[u8]) -> Result<Self, &'static str> {
        let records = WalRecord::parse_all(wal_data)?;
        let mut committed_txs = BTreeSet::new();

        // 1. Identificar qué transacciones registraron un CommitTx definitivo
        for r in &records {
            if let WalOp::CommitTx { tx_id } = r.op {
                committed_txs.insert(tx_id);
            }
        }

        // 2. Re-aplicar solo las operaciones pertenecientes a transacciones confirmadas
        let mut recovered_fs = Self::new();
        recovered_fs.wal_bytes = wal_data.to_vec();

        for r in records {
            if committed_txs.contains(&r.tx_id) {
                match r.op {
                    WalOp::WriteFile { path, content } => {
                        let meta = SemanticMetadata {
                            content_type: "recovered".into(),
                            created_by: DomainId(0),
                            causal_effect: EffectId(0),
                            label: SecurityLabel::TRUSTED_KERNEL,
                            tags: Vec::new(),
                        };
                        recovered_fs.fs.write_file(BranchId(0), &path, content, None, meta);
                    }
                    WalOp::DeleteFile { path } => {
                        recovered_fs.fs.delete_file(BranchId(0), &path);
                    }
                    _ => {}
                }
            }
        }

        Ok(recovered_fs)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wal_serialization_roundtrip() {
        let record = WalRecord {
            sequence: 1,
            tx_id: 42,
            op: WalOp::WriteFile {
                path: "/data/file.txt".into(),
                content: b"contenido importante".to_vec(),
            },
            checksum: 0,
        };

        let bytes = record.serialize();
        let parsed = WalRecord::parse_all(&bytes).unwrap();
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].sequence, 1);
        assert_eq!(parsed[0].tx_id, 42);
        if let WalOp::WriteFile { path, content } = &parsed[0].op {
            assert_eq!(path, "/data/file.txt");
            assert_eq!(content, b"contenido importante");
        } else {
            panic!("Opcode no coincide");
        }
    }

    #[test]
    fn test_wal_crash_recovery_preserves_committed_and_discards_uncommitted() {
        let mut jfs = JournaledFs::new();

        // Transacción 1: Confirmada exitosamente
        let tx1 = jfs.begin_tx();
        jfs.write_file_tx(
            tx1,
            "/config/system.json",
            b"{\"status\": \"active\"}".to_vec(),
            SemanticMetadata {
                content_type: "application/json".into(),
                created_by: DomainId(1),
                causal_effect: EffectId(1),
                label: SecurityLabel::TRUSTED_KERNEL,
                tags: vec![],
            },
        );
        jfs.commit_tx(tx1);

        // Transacción 2: Se escribe pero se simula una caída súbita ANTES del commit
        let tx2 = jfs.begin_tx();
        jfs.write_file_tx(
            tx2,
            "/uncommitted/trash.txt",
            b"datos corruptos de transaccion incompleta".to_vec(),
            SemanticMetadata {
                content_type: "text/plain".into(),
                created_by: DomainId(2),
                causal_effect: EffectId(2),
                label: SecurityLabel::UNTRUSTED_EXTERNAL,
                tags: vec![],
            },
        );
        // NO se llama commit_tx(tx2) -> Simulación de crash!

        // Simular recuperación post-crash escaneando los bytes del WAL en disco
        let recovered = JournaledFs::recover_from_wal(&jfs.wal_bytes).unwrap();

        // El archivo confirmado en tx1 DEBE existir en la raíz
        let f1 = recovered.fs.read_file(BranchId(0), "/config/system.json");
        assert!(f1.is_some());
        assert_eq!(f1.unwrap().content, b"{\"status\": \"active\"}");

        // El archivo de tx2 NO DEBE existir porque tx2 nunca fue confirmada
        let f2 = recovered.fs.read_file(BranchId(0), "/uncommitted/trash.txt");
        assert!(f2.is_none(), "Los datos de la transaccion incompleta deben ser descartados");
    }
}
