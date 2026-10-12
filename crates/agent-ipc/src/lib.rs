#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::collections::VecDeque;
use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicU64, Ordering};

use capability_engine::{CapId, ObjectId, Permissions};
use causal_core::{BranchId, CausalLedger, DomainId, EffectId, Reversibility, SecurityLabel};
use agent_runtime::{AgentId, AgentInstance};

/// Identificador único de canal de comunicación
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChannelId(pub u64);

/// Identificador único de mensaje IPC
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MessageId(pub u64);

static NEXT_CHANNEL_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_MESSAGE_ID: AtomicU64 = AtomicU64::new(1);

/// Cargas útiles tipadas transmitidas a través de AgentOS IPC
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcPayload {
    Text(String),
    Query {
        prompt: String,
        max_tokens: u32,
    },
    Response {
        answer: String,
        tokens_used: u32,
    },
    TaskDelegation {
        subtask_id: u64,
        description: String,
        token_budget: u64,
    },
    CapabilityGrant {
        target_object: ObjectId,
        permissions: Permissions,
    },
    MultiverseVote {
        branch_id: u64,
        commit: bool,
    },
}

/// Mensaje IPC de AgentOS con procedencia causal y etiquetas de seguridad
#[derive(Debug, Clone)]
pub struct IpcMessage {
    pub id: MessageId,
    pub channel_id: ChannelId,
    pub sender: AgentId,
    pub recipient: AgentId,
    pub branch_id: BranchId,
    pub causal_parent: Option<EffectId>,
    pub taint_label: SecurityLabel,
    pub payload: IpcPayload,
}

/// Configuración de seguridad de un canal IPC
#[derive(Debug, Clone)]
pub struct IpcChannel {
    pub id: ChannelId,
    pub object_id: ObjectId,
    pub endpoint_a: AgentId,
    pub endpoint_b: AgentId,
    pub allow_untrusted: bool,
    pub max_confidentiality: u16,
    pub queue: VecDeque<IpcMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpcError {
    ChannelNotFound(ChannelId),
    UnauthorizedSender,
    UnauthorizedRecipient,
    CapabilityDenied,
    TaintedSenderBlocked,
    QueueFull,
    FlowPolicyViolation,
}

/// Router central del Bus IPC de Agentes
pub struct IpcRouter {
    channels: Vec<IpcChannel>,
    speculative_queues: Vec<(BranchId, IpcMessage)>,
}

impl IpcRouter {
    pub fn new() -> Self {
        Self {
            channels: Vec::new(),
            speculative_queues: Vec::new(),
        }
    }

    /// Crea y registra un nuevo canal bidireccional entre dos agentes
    pub fn create_channel(
        &mut self,
        endpoint_a: AgentId,
        endpoint_b: AgentId,
        allow_untrusted: bool,
    ) -> (ChannelId, ObjectId) {
        let max_conf = if allow_untrusted { 10 } else { 100 };
        self.create_channel_with_confidentiality(endpoint_a, endpoint_b, allow_untrusted, max_conf)
    }

    /// Crea un canal con nivel máximo de confidencialidad explícito (DIFC)
    pub fn create_channel_with_confidentiality(
        &mut self,
        endpoint_a: AgentId,
        endpoint_b: AgentId,
        allow_untrusted: bool,
        max_confidentiality: u16,
    ) -> (ChannelId, ObjectId) {
        let ch_id = ChannelId(NEXT_CHANNEL_ID.fetch_add(1, Ordering::Relaxed));
        let obj_id = ObjectId(ch_id.0 + 10_000);

        let channel = IpcChannel {
            id: ch_id,
            object_id: obj_id,
            endpoint_a,
            endpoint_b,
            allow_untrusted,
            max_confidentiality,
            queue: VecDeque::new(),
        };

        self.channels.push(channel);
        (ch_id, obj_id)
    }

    /// Busca un canal existente entre dos agentes (en cualquier dirección)
    pub fn find_channel(&self, a: AgentId, b: AgentId) -> Option<(ChannelId, ObjectId)> {
        self.channels.iter().find(|ch| {
            (ch.endpoint_a == a && ch.endpoint_b == b) || (ch.endpoint_a == b && ch.endpoint_b == a)
        }).map(|ch| (ch.id, ch.object_id))
    }

    /// Envía un mensaje IPC verificando capacidades, propagando taint y registrando en el Merkle-DAG
    pub fn send(
        &mut self,
        sender: &AgentInstance,
        channel_id: ChannelId,
        recipient: AgentId,
        branch_id: BranchId,
        cap_token: CapId,
        payload: IpcPayload,
        ledger: &mut CausalLedger,
    ) -> Result<EffectId, IpcError> {
        let ch = self
            .channels
            .iter_mut()
            .find(|c| c.id == channel_id)
            .ok_or(IpcError::ChannelNotFound(channel_id))?;

        // 1. Verificación de identidad de endpoint
        if ch.endpoint_a != sender.id && ch.endpoint_b != sender.id {
            return Err(IpcError::UnauthorizedSender);
        }
        if ch.endpoint_a != recipient && ch.endpoint_b != recipient {
            return Err(IpcError::UnauthorizedRecipient);
        }

        // 2. Verificación de capacidad (debe poseer WRITE sobre el ObjectId del canal)
        match sender.cspace.verify(cap_token, Permissions::WRITE) {
            Ok(obj) if obj == ch.object_id => {}
            _ => return Err(IpcError::CapabilityDenied),
        }

        // 3. Information Flow Control (IFC): Teorema de No-Interferencia y Desclasificación
        let mut effective_label = sender.security_label;
        let has_declassify = sender.cspace.verify(cap_token, Permissions::DECLASSIFY).is_ok();
        if has_declassify {
            effective_label = effective_label.declassify(
                causal_core::TaintMask::WEB_UNTRUSTED | causal_core::TaintMask::TOOL_OUTPUT,
            );
        }

        // Bloqueo de fuga de confidencialidad a canales con menor clasificación
        if effective_label.confidentiality > ch.max_confidentiality {
            return Err(IpcError::FlowPolicyViolation);
        }

        // Bloqueo de contaminación hacia canales de alta integridad sin desclasificación
        let is_effectively_tainted = (effective_label.taint_mask != 0) || (sender.is_tainted() && !has_declassify);
        if is_effectively_tainted && !ch.allow_untrusted {
            return Err(IpcError::TaintedSenderBlocked);
        }

        let taint_label = if is_effectively_tainted {
            SecurityLabel::UNTRUSTED_EXTERNAL
        } else {
            SecurityLabel::TRUSTED_KERNEL
        };

        // 4. Registro de procedencia causal en el Merkle-DAG del Kernel
        let parent_effects = sender.observed_effects.clone();
        let effect_id = ledger.record_effect(
            branch_id,
            DomainId(sender.id.0),
            DomainId(recipient.0),
            parent_effects,
            taint_label,
            Reversibility::PurelyReversible,
            [0xAA; 32],
        );

        let msg = IpcMessage {
            id: MessageId(NEXT_MESSAGE_ID.fetch_add(1, Ordering::Relaxed)),
            channel_id,
            sender: sender.id,
            recipient,
            branch_id,
            causal_parent: Some(effect_id),
            taint_label,
            payload,
        };

        // 5. Aislamiento del Multiverso: Si el mensaje se emite en una rama hipotética
        if branch_id != BranchId(0) {
            self.speculative_queues.push((branch_id, msg));
        } else {
            ch.queue.push_back(msg);
        }

        Ok(effect_id)
    }

    /// Recibe el siguiente mensaje disponible para el agente destinatario y propaga taint automáticamente
    pub fn recv(
        &mut self,
        recipient: &mut AgentInstance,
        channel_id: ChannelId,
        cap_token: CapId,
    ) -> Result<Option<IpcMessage>, IpcError> {
        let ch = self
            .channels
            .iter_mut()
            .find(|c| c.id == channel_id)
            .ok_or(IpcError::ChannelNotFound(channel_id))?;

        if ch.endpoint_a != recipient.id && ch.endpoint_b != recipient.id {
            return Err(IpcError::UnauthorizedRecipient);
        }

        match recipient.cspace.verify(cap_token, Permissions::READ) {
            Ok(obj) if obj == ch.object_id => {}
            _ => return Err(IpcError::CapabilityDenied),
        }

        // Extraer mensaje de la cola
        if let Some(msg) = ch.queue.pop_front() {
            // IFC: Si el mensaje entrante está marcado como UNTRUSTED, contamina automáticamente al receptor
            if msg.taint_label == SecurityLabel::UNTRUSTED_EXTERNAL {
                recipient.observe("IPC message tainted by sender", SecurityLabel::UNTRUSTED_EXTERNAL, msg.causal_parent.unwrap_or(EffectId(0)));
            }
            Ok(Some(msg))
        } else {
            Ok(None)
        }
    }

    /// Purga en O(1) todos los mensajes especulativos de una rama abortada
    pub fn abort_branch(&mut self, branch_id: BranchId) {
        self.speculative_queues.retain(|(b, _)| *b != branch_id);
    }

    /// Confirma los mensajes de una rama especulativa encolándolos en sus canales principales
    pub fn commit_branch(&mut self, branch_id: BranchId) {
        let mut committed = Vec::new();
        self.speculative_queues.retain(|(b, msg)| {
            if *b == branch_id {
                committed.push(msg.clone());
                false
            } else {
                true
            }
        });

        for msg in committed {
            if let Some(ch) = self.channels.iter_mut().find(|c| c.id == msg.channel_id) {
                ch.queue.push_back(msg);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agent_runtime::AgentGoal;

    #[test]
    fn test_unauthorized_ipc_send_rejected() {
        let mut router = IpcRouter::new();
        let mut ledger = CausalLedger::new();

        let agent1 = AgentInstance::new(AgentId(1), DomainId(1), AgentGoal::new("Goal 1", 5, 100));
        let agent2 = AgentInstance::new(AgentId(2), DomainId(2), AgentGoal::new("Goal 2", 5, 100));
        let (ch_id, _obj_id) = router.create_channel(agent1.id, agent2.id, true);

        // Agente 1 intenta enviar SIN haber recibido el capability token
        let fake_token = CapId(999);
        let res = router.send(
            &agent1,
            ch_id,
            agent2.id,
            BranchId(0),
            fake_token,
            IpcPayload::Text("Mensaje no autorizado".into()),
            &mut ledger,
        );

        assert_eq!(res, Err(IpcError::CapabilityDenied));
    }

    #[test]
    fn test_ifc_taint_propagation_across_agents() {
        let mut router = IpcRouter::new();
        let mut ledger = CausalLedger::new();

        let mut agent1 = AgentInstance::new(AgentId(1), DomainId(1), AgentGoal::new("Web Reader", 5, 100));
        let mut agent2 = AgentInstance::new(AgentId(2), DomainId(2), AgentGoal::new("DB Writer", 5, 100));
        let (ch_id, obj_id) = router.create_channel(agent1.id, agent2.id, true);

        let cap1 = agent1.grant_capability(obj_id, Permissions::WRITE);
        let cap2 = agent2.grant_capability(obj_id, Permissions::READ);

        // Agente 1 se contamina al leer una web externa
        agent1.observe("Malicious web payload", SecurityLabel::UNTRUSTED_EXTERNAL, EffectId(1));
        assert!(agent1.is_tainted());
        assert!(!agent2.is_tainted());

        // Agente 1 envía un mensaje al Agente 2
        let effect_id = router.send(
            &agent1,
            ch_id,
            agent2.id,
            BranchId(0),
            cap1,
            IpcPayload::Text("Lee esto por favor".into()),
            &mut ledger,
        ).expect("Envio permitido con canal allow_untrusted");

        // Agente 2 recibe el mensaje
        let received = router.recv(&mut agent2, ch_id, cap2).expect("Recepcion valida").unwrap();
        assert_eq!(received.causal_parent, Some(effect_id));

        // Invariante de seguridad: Agente 2 queda AUTOMÁTICAMENTE contaminado por IFC!
        assert!(agent2.is_tainted());
    }

    #[test]
    fn test_strict_channel_blocks_tainted_sender() {
        let mut router = IpcRouter::new();
        let mut ledger = CausalLedger::new();

        let mut agent1 = AgentInstance::new(AgentId(1), DomainId(1), AgentGoal::new("Untrusted Bot", 5, 100));
        let agent2 = AgentInstance::new(AgentId(2), DomainId(2), AgentGoal::new("Secure Kernel Service", 5, 100));
        
        // Canal estricto: allow_untrusted = false
        let (ch_id, obj_id) = router.create_channel(agent1.id, agent2.id, false);
        let cap1 = agent1.grant_capability(obj_id, Permissions::WRITE);

        // Agente 1 está contaminado
        agent1.observe("External untrusted source", SecurityLabel::UNTRUSTED_EXTERNAL, EffectId(1));

        // Intento de envío al servicio seguro
        let res = router.send(
            &agent1,
            ch_id,
            agent2.id,
            BranchId(0),
            cap1,
            IpcPayload::Text("Payload hostil".into()),
            &mut ledger,
        );

        assert_eq!(res, Err(IpcError::TaintedSenderBlocked));
    }

    #[test]
    fn test_multiverse_speculative_branch_abort_purges_messages() {
        let mut router = IpcRouter::new();
        let mut ledger = CausalLedger::new();

        let mut agent1 = AgentInstance::new(AgentId(1), DomainId(1), AgentGoal::new("Agent 1", 5, 100));
        let mut agent2 = AgentInstance::new(AgentId(2), DomainId(2), AgentGoal::new("Agent 2", 5, 100));
        let (ch_id, obj_id) = router.create_channel(agent1.id, agent2.id, true);

        let cap1 = agent1.grant_capability(obj_id, Permissions::WRITE);
        let cap2 = agent2.grant_capability(obj_id, Permissions::READ);

        let branch_sim = BranchId(42);

        // Envío dentro de una rama hipotética (Multiverso)
        router.send(
            &agent1,
            ch_id,
            agent2.id,
            branch_sim,
            cap1,
            IpcPayload::Text("Accion tentativa".into()),
            &mut ledger,
        ).unwrap();

        // No debe estar en la cola principal aún
        assert!(router.recv(&mut agent2, ch_id, cap2).unwrap().is_none());

        // Si la rama se aborta
        router.abort_branch(branch_sim);

        // Confirmar la rama no entrega nada porque fue purgada
        router.commit_branch(branch_sim);
        assert!(router.recv(&mut agent2, ch_id, cap2).unwrap().is_none());
    }
}
