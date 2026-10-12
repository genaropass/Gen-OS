//! Suite de Pruebas Adversariales de Seguridad para AgentOS
//! Valida matemáticamente y empíricamente la resistencia del sistema frente a:
//! - Ataque 1: Confusión de privilegios (Confused Deputy).
//! - Ataque 2: Reuso de token revocado (Use-After-Revocation / Epoch Mismatch).
//! - Ataque 3: Elevación de privilegios vía derivación no autorizada (Attenuation Violation).
//! - Ataque 4: Fuga de datos clasificados a canales públicos (IFC Confidentiality Leak).
//! - Ataque 5: Inyección de datos contaminados en dominio estricto (Taint Injection).
//! - Ataque 6: Desclasificación autorizada con token de capacidades explícito (DECLASSIFY).
//! - Ataque 7: Agotamiento de recursos por explosión de capacidades (DoS CSpaceFull).

use agent_ipc::{IpcRouter, IpcPayload, IpcError};
use agent_runtime::{AgentId, AgentGoal, AgentInstance};
use capability_engine::{CSpace, Permissions, ObjectId, CapId, CapError};
use causal_core::{CausalLedger, DomainId, BranchId, SecurityLabel};

#[test]
fn test_attack_1_confused_deputy_blocked() {
    let mut cspace = CSpace::new();
    let root_secret_obj = ObjectId(999);

    // Dominio 1 (Supervisor legítimo) posee capacidad sobre root_secret_obj
    let _sup_cap = cspace.mint_root(root_secret_obj, Permissions::ALL, 1);

    // Dominio 2 (Agente no confiable) NO posee capacidad sobre root_secret_obj
    let fake_token = CapId::new(0, 99); // Token falso inventado

    // Intento del agente 2 de engañar al sistema usando el token falso
    let verify_res = cspace.verify(fake_token, Permissions::READ);
    assert_eq!(verify_res, Err(CapError::EpochMismatch));
}

#[test]
fn test_attack_2_use_after_revocation_epoch_mismatch() {
    let mut cspace = CSpace::new();
    let file_obj = ObjectId(42);

    let root_cap = cspace.mint_root(file_obj, Permissions::ALL, 1);
    let child_cap = cspace.derive(root_cap, Permissions::READ | Permissions::WRITE, 2).unwrap();

    // El token derivado es inicialmente válido
    assert_eq!(cspace.verify(child_cap, Permissions::READ), Ok(file_obj));

    // El supervisor revoca el token derivado
    let revoked = cspace.revoke(child_cap).unwrap();
    assert_eq!(revoked, 1);

    // El agente intenta reutilizar el token revocado (Use-After-Revocation)
    // El motor de capacidades DEBE rechazarlo por discordancia de época (EpochMismatch)
    assert_eq!(cspace.verify(child_cap, Permissions::READ), Err(CapError::EpochMismatch));

    // Incluso si se mintea una nueva capacidad en la misma ranura, la generación avanzó:
    let new_cap = cspace.mint_root(ObjectId(100), Permissions::READ, 3);
    assert_eq!(child_cap.slot(), new_cap.slot()); // Misma ranura reciclada
    assert_ne!(child_cap.generation(), new_cap.generation()); // Pero épocas distintas

    // El token antiguo sigue siendo inválido
    assert_eq!(cspace.verify(child_cap, Permissions::READ), Err(CapError::EpochMismatch));
}

#[test]
fn test_attack_3_privilege_escalation_via_derive() {
    let mut cspace = CSpace::new();
    let db_obj = ObjectId(777);

    // Agente recibe capacidad con solo READ y GRANT
    let read_only_cap = cspace.mint_root(db_obj, Permissions::READ | Permissions::GRANT, 10);

    // Ataque: el agente intenta derivar un token con WRITE o EXECUTE
    let escalation_attempt = cspace.derive(read_only_cap, Permissions::WRITE, 10);
    assert_eq!(escalation_attempt, Err(CapError::AttenuationViolation));

    let all_attempt = cspace.derive(read_only_cap, Permissions::ALL, 10);
    assert_eq!(all_attempt, Err(CapError::AttenuationViolation));
}

#[test]
fn test_attack_4_ifc_confidentiality_leak_blocked() {
    let mut router = IpcRouter::new();
    let mut ledger = CausalLedger::new();

    let secret_agent_id = AgentId(1);
    let public_agent_id = AgentId(2);

    let mut secret_agent = AgentInstance::new(
        secret_agent_id,
        DomainId(1),
        AgentGoal::new("Agente con claves criptograficas privadas", 10, 100),
    );
    // Asignar nivel alto de confidencialidad (secreto)
    secret_agent.security_label.confidentiality = 80;

    let public_agent = AgentInstance::new(
        public_agent_id,
        DomainId(2),
        AgentGoal::new("Agente publico conectado a internet", 10, 100),
    );

    // Canal público con max_confidentiality = 10
    let (ch_id, obj_id) = router.create_channel_with_confidentiality(
        secret_agent_id,
        public_agent_id,
        true, // allow_untrusted
        10,   // max_confidentiality = 10
    );

    let write_cap = secret_agent.grant_capability(obj_id, Permissions::WRITE);

    // Ataque: intentar filtrar datos de confidencialidad 80 por un canal de confidencialidad 10
    let send_result = router.send(
        &secret_agent,
        ch_id,
        public_agent.id,
        BranchId(0),
        write_cap,
        IpcPayload::Text("CLAVE_PRIVADA_FILTRADA_12345".into()),
        &mut ledger,
    );

    // El Teorema de No-Interferencia bloquea la fuga
    assert_eq!(send_result, Err(IpcError::FlowPolicyViolation));
}

#[test]
fn test_attack_5_taint_injection_without_declassification() {
    let mut router = IpcRouter::new();
    let mut ledger = CausalLedger::new();

    let untrusted_agent_id = AgentId(10);
    let kernel_agent_id = AgentId(1);

    let mut untrusted_agent = AgentInstance::new(
        untrusted_agent_id,
        DomainId(10),
        AgentGoal::new("Navegador web leyendo datos no confiables", 10, 100),
    );
    // Simular contaminación externa
    untrusted_agent.observe(
        "Payload malicioso de prompt injection",
        SecurityLabel::UNTRUSTED_EXTERNAL,
        causal_core::EffectId(1),
    );
    assert!(untrusted_agent.is_tainted());

    // Canal estricto de alta integridad (allow_untrusted = false)
    let (strict_ch, obj_id) = router.create_channel(
        untrusted_agent_id,
        kernel_agent_id,
        false, // Estricto: rechaza datos contaminados
    );

    let cap_write = untrusted_agent.grant_capability(obj_id, Permissions::WRITE);

    // Ataque: enviar mensaje contaminado sin capacidad DECLASSIFY
    let res = router.send(
        &untrusted_agent,
        strict_ch,
        kernel_agent_id,
        BranchId(0),
        cap_write,
        IpcPayload::Text("DROP TABLE users;".into()),
        &mut ledger,
    );

    // Debe ser bloqueado terminantemente por IFC
    assert_eq!(res, Err(IpcError::TaintedSenderBlocked));
}

#[test]
fn test_attack_6_authorized_declassification() {
    let mut router = IpcRouter::new();
    let mut ledger = CausalLedger::new();

    let sanitizer_agent_id = AgentId(20);
    let kernel_agent_id = AgentId(1);

    let mut sanitizer_agent = AgentInstance::new(
        sanitizer_agent_id,
        DomainId(20),
        AgentGoal::new("Filtro de sanitizacion y auditoria de seguridad", 10, 100),
    );
    sanitizer_agent.observe(
        "Dato con riesgo potencial analizado",
        SecurityLabel::UNTRUSTED_EXTERNAL,
        causal_core::EffectId(2),
    );

    let (strict_ch, obj_id) = router.create_channel(
        sanitizer_agent_id,
        kernel_agent_id,
        false, // Estricto
    );

    // Otorgar capacidad con WRITE y DECLASSIFY explícito
    let declassify_cap = sanitizer_agent.grant_capability(
        obj_id,
        Permissions::WRITE | Permissions::DECLASSIFY,
    );

    // Enviar a través del canal estricto con autorización de desclasificación
    let res = router.send(
        &sanitizer_agent,
        strict_ch,
        kernel_agent_id,
        BranchId(0),
        declassify_cap,
        IpcPayload::Text("PARAMETRO_LIMPIO_Y_SANITIZADO".into()),
        &mut ledger,
    );

    // Debe triunfar porque posee la capacidad DECLASSIFY autorizada
    assert!(res.is_ok());
}

#[test]
fn test_attack_7_cspace_resource_exhaustion_dos_blocked() {
    let mut cspace = CSpace::with_capacity(10);
    let obj = ObjectId(888);

    let root = cspace.mint_root(obj, Permissions::ALL, 1);

    // Crear 9 capacidades derivadas para llenar la tabla hasta el límite de 10
    for _ in 0..9 {
        let derived = cspace.derive(root, Permissions::READ | Permissions::GRANT, 1);
        assert!(derived.is_ok());
    }

    assert_eq!(cspace.len(), 10);

    // Ataque DoS: intentar desbordar la tabla con la 11va capacidad
    let dos_attempt = cspace.derive(root, Permissions::READ, 1);
    assert_eq!(dos_attempt, Err(CapError::CSpaceFull));
}
