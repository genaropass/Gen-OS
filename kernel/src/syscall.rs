//! Subsistema de Llamadas al Sistema (Syscalls) para AgentOS
//! Proporciona las primitivas de interfaz binaria (ABI) para agentes de IA y servicios.

use crate::println;
use causal_core::{CausalLedger, DomainId, BranchId, EffectId, Reversibility, SecurityLabel, EscrowManager};
use capability_engine::{CSpace, ObjectId, Permissions, CapId};
use core::cell::UnsafeCell;

/// Identificadores de llamadas al sistema (Syscall Numbers)
pub const SYS_EFFECT_LOG: u64 = 1;
pub const SYS_WHY: u64 = 2;
pub const SYS_STAGE_ESCROW: u64 = 3;
pub const SYS_COMMIT_BRANCH: u64 = 4;
pub const SYS_ABORT_BRANCH: u64 = 5;
pub const SYS_CAP_MINT: u64 = 6;
pub const SYS_CAP_DERIVE: u64 = 7;
pub const SYS_CAP_REVOKE: u64 = 8;

/// Estado global del subsistema de llamadas al sistema en Ring 0
struct SyscallState {
    ledger: CausalLedger,
    escrow: EscrowManager,
    cspace: CSpace,
}

struct SyscallWrapper(UnsafeCell<Option<SyscallState>>);
unsafe impl Sync for SyscallWrapper {}

static SYSCALL_STATE: SyscallWrapper = SyscallWrapper(UnsafeCell::new(None));

/// Inicializa el estado del despachador de llamadas al sistema
pub fn init() {
    unsafe {
        *SYSCALL_STATE.0.get() = Some(SyscallState {
            ledger: CausalLedger::new(),
            escrow: EscrowManager::new(),
            cspace: CSpace::new(),
        });
    }
    println!("[AgentOS::Syscall] Despachador de syscalls registrado (ABI int 0x80)");
}

/// Despachador central de llamadas al sistema ejecutado en Ring 0
pub fn dispatch_syscall(sys_num: u64, arg1: u64, arg2: u64, arg3: u64, _arg4: u64) -> i64 {
    let state_opt = unsafe { &mut *SYSCALL_STATE.0.get() };
    let state = match state_opt.as_mut() {
        Some(s) => s,
        None => return -1, // Syscalls no inicializadas
    };

    match sys_num {
        SYS_EFFECT_LOG => {
            // arg1: branch_id, arg2: target_domain, arg3: reversibility (0=Rev, 1=Escrow, 2=Irrev)
            let branch = BranchId(arg1 as u32);
            let emitter = DomainId(1); // agente llamante
            let target = DomainId(arg2 as u32);
            let rev = match arg3 {
                0 => Reversibility::PurelyReversible,
                1 => Reversibility::EscrowStaged,
                _ => Reversibility::Irreversible,
            };

            let effect_id = state.ledger.record_effect(
                branch,
                emitter,
                target,
                alloc::vec![],
                SecurityLabel::UNTRUSTED_EXTERNAL,
                rev,
                [0u8; 32],
            );

            effect_id.0 as i64
        }

        SYS_WHY => {
            // arg1: effect_id -> Retorna la profundidad/longitud de la cadena causal
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
            0 // Éxito
        }

        SYS_COMMIT_BRANCH => {
            // arg1: branch_id -> Confirma rama y descarga acciones staged a hardware
            let branch_id = BranchId(arg1 as u32);
            let released = state.escrow.commit_branch(branch_id);
            println!("[AgentOS::Syscall] SYS_COMMIT_BRANCH: Liberadas {} accion(es) de escrow a hardware", released.len());
            released.len() as i64
        }

        SYS_ABORT_BRANCH => {
            // arg1: branch_id -> Descarta rama y purga todas las acciones en escrow
            let branch_id = BranchId(arg1 as u32);
            let dropped = state.escrow.abort_branch(branch_id);
            println!("[AgentOS::Syscall] SYS_ABORT_BRANCH: Descartadas {} accion(es) de escrow sin fugas", dropped);
            dropped as i64
        }

        SYS_CAP_MINT => {
            // arg1: object_id, arg2: perms, arg3: owner
            let obj = ObjectId(arg1);
            let perms = Permissions(arg2 as u32);
            let owner = arg3 as u32;
            let cap_id = state.cspace.mint_root(obj, perms, owner);
            cap_id.0 as i64
        }

        SYS_CAP_DERIVE => {
            // arg1: parent_cap_id, arg2: perms, arg3: new_owner
            let parent_id = CapId(arg1);
            let perms = Permissions(arg2 as u32);
            let new_owner = arg3 as u32;
            match state.cspace.derive(parent_id, perms, new_owner) {
                Ok(child_id) => child_id.0 as i64,
                Err(_) => -1, // Denegado por violación de atenuación o falta de permiso GRANT
            }
        }

        SYS_CAP_REVOKE => {
            // arg1: cap_id -> Revocación recursiva en cascada
            let cap_id = CapId(arg1);
            match state.cspace.revoke(cap_id) {
                Ok(revoked_count) => revoked_count as i64,
                Err(_) => -1,
            }
        }

        _ => {
            println!("[AgentOS::Syscall] Syscall desconocida: {}", sys_num);
            -38 // -ENOSYS
        }
    }
}
