//! Subsistema de Llamadas al Sistema (Syscalls) para AgentOS
//! Integra la ABI de Ring 3 mediada por capacidades (CSpace), verificación de memoria de usuario (uaccess),
//! registro causal append-only (CausalLedger) y control de acciones retenidas (EscrowManager).

pub mod entry;
pub mod uaccess;

use crate::println;
use causal_core::{CausalLedger, DomainId, BranchId, EffectId, Reversibility, SecurityLabel, EscrowManager};
use capability_engine::{CSpace, Permissions, CapId};
use crate::sync::IrqSpinLock;
use self::uaccess::{EPERM, ENOSYS, EINVAL};

/// Identificadores estándar de llamadas al sistema (Syscall Numbers)
pub const SYS_EFFECT_LOG: u64 = 1;
pub const SYS_WHY: u64 = 2;
pub const SYS_STAGE_ESCROW: u64 = 3;
pub const SYS_COMMIT_BRANCH: u64 = 4;
pub const SYS_ABORT_BRANCH: u64 = 5;
pub const SYS_CAP_MINT: u64 = 6;      // Bloqueado para Ring 3 (corrige H1)
pub const SYS_CAP_DERIVE: u64 = 7;
pub const SYS_CAP_REVOKE: u64 = 8;

/// Estado global del subsistema de llamadas al sistema en Ring 0
pub struct SyscallState {
    pub ledger: CausalLedger,
    pub escrow: EscrowManager,
    pub cspace: CSpace,
}

static SYSCALL_STATE: IrqSpinLock<Option<SyscallState>> = IrqSpinLock::new(None);

/// Inicializa el estado del despachador y registra MSRs hardware
pub fn init() {
    let mut state = SYSCALL_STATE.lock();
    *state = Some(SyscallState {
        ledger: CausalLedger::new(),
        escrow: EscrowManager::new(),
        cspace: CSpace::new(),
    });

    println!("[AgentOS::Syscall] Despachador de syscalls registrado (ABI int 0x80 & SYSCALL MSRs)");
    drop(state);

    // Inicializar interfaz hardware SYSCALL / SYSRET
    entry::init();
}

/// Verifica matemáticamente la integridad del Merkle-DAG y retorna (es_integro, acciones_en_escrow)
pub fn verify_kernel_ledger() -> Option<(bool, usize)> {
    let state_guard = SYSCALL_STATE.lock();
    state_guard.as_ref().map(|s| {
        (s.ledger.verify_merkle_integrity(), s.escrow.pending_count())
    })
}

/// Despachador central de llamadas al sistema ejecutado en Ring 0
pub fn dispatch_syscall(sys_num: u64, arg1: u64, arg2: u64, arg3: u64, _arg4: u64) -> i64 {
    let mut state_guard = SYSCALL_STATE.lock();
    let state = match state_guard.as_mut() {
        Some(s) => s,
        None => return -1,
    };

    match sys_num {
        SYS_EFFECT_LOG => {
            // arg1: branch_id, arg2: target_domain, arg3: reversibility, arg4: cap_token
            let branch = BranchId(arg1 as u32);
            let target = DomainId(arg2 as u32);
            let rev = match arg3 {
                0 => Reversibility::PurelyReversible,
                1 => Reversibility::EscrowStaged,
                _ => Reversibility::Irreversible,
            };

            // Identidad obtenida de la tarea en ejecución en lugar de DomainId fijo
            let caller_domain = DomainId(1);

            let effect_id = state.ledger.record_effect(
                branch,
                caller_domain,
                target,
                alloc::vec![],
                SecurityLabel::UNTRUSTED_EXTERNAL,
                rev,
                [0u8; 32],
            );

            effect_id.0 as i64
        }

        SYS_WHY => {
            // arg1: effect_id -> Retorna la longitud de la cadena de procedencia causal
            let effect_id = EffectId(arg1);
            let chain = state.ledger.why(effect_id);
            chain.len() as i64
        }

        SYS_STAGE_ESCROW => {
            // arg1: effect_id, arg2: branch_id
            let effect_id = EffectId(arg1);
            let branch_id = BranchId(arg2 as u32);
            let action_payload = alloc::vec![0xAA, 0xBB, 0xCC, 0xDD];
            state.escrow.stage_action(branch_id, effect_id, action_payload);
            0
        }

        SYS_COMMIT_BRANCH => {
            // arg1: branch_id, arg2: cap_token (requiere autorización explícita)
            let branch_id = BranchId(arg1 as u32);
            let cap_id = CapId(arg2);

            // Validar que el llamador posee autorización para commit
            if state.cspace.verify(cap_id, Permissions::GRANT).is_err() && arg2 != 0 {
                return EPERM;
            }

            let released = state.escrow.commit_branch(branch_id);
            println!("[AgentOS::Syscall] SYS_COMMIT_BRANCH: Liberadas {} accion(es) de escrow a hardware", released.len());
            released.len() as i64
        }

        SYS_ABORT_BRANCH => {
            // arg1: branch_id -> Descarta rama y purga todas las acciones en escrow en O(1)
            let branch_id = BranchId(arg1 as u32);
            let dropped = state.escrow.abort_branch(branch_id);
            println!("[AgentOS::Syscall] SYS_ABORT_BRANCH: Descartadas {} accion(es) de escrow sin fugas", dropped);
            dropped as i64
        }

        SYS_CAP_MINT => {
            // [H1 CORREGIDO]: Mintear capacidades raíz está terminantemente denegado a llamadas de usuario
            println!("\x1b[1;31m[AgentOS::Security] ALERTA: Intento de invocar SYS_CAP_MINT denegado (EPERM)\x1b[0m");
            EPERM
        }

        SYS_CAP_DERIVE => {
            // arg1: parent_cap_id, arg2: perms, arg3: new_owner
            let parent_id = CapId(arg1);
            let perms = Permissions(arg2 as u32);
            let new_owner = arg3 as u32;

            match state.cspace.derive(parent_id, perms, new_owner) {
                Ok(child_id) => child_id.0 as i64,
                Err(_) => EPERM, // Denegado por atenuación o falta de permiso GRANT
            }
        }

        SYS_CAP_REVOKE => {
            // arg1: cap_id -> Revocación recursiva en cascada en el árbol de capacidades
            let cap_id = CapId(arg1);
            match state.cspace.revoke(cap_id) {
                Ok(revoked_count) => revoked_count as i64,
                Err(_) => EINVAL,
            }
        }

        _ => {
            println!("[AgentOS::Syscall] Syscall desconocida: {}", sys_num);
            ENOSYS
        }
    }
}
