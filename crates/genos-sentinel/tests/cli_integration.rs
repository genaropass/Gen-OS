//! End-to-end CLI integration tests for `genos-sentinel`.

use std::process::Command;

use genos_sentinel::txdecode::builders;

fn sentinel_bin() -> String {
    env!("CARGO_BIN_EXE_genos-sentinel").to_string()
}

fn to_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 + bytes.len() * 2);
    s.push_str("0x");
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

#[test]
fn test_cli_redteam_and_inspect_rlp_and_safe_json() {
    // 1. `genos-sentinel redteam` exits 0 and verifies all 4 scenarios
    let out_redteam = Command::new(sentinel_bin())
        .arg("redteam")
        .output()
        .expect("run redteam");
    assert!(out_redteam.status.success());
    let stdout_rt = String::from_utf8_lossy(&out_redteam.stdout);
    assert!(stdout_rt.contains("ALL 4 ADVERSARIAL SCENARIOS CONTAINED"));

    // 2. `genos-sentinel inspect-tx` rejects a real RLP-encoded EIP-7702 (`0x04`) SetCode transaction with exit code 1
    let rlp_7702 = builders::build_real_rlp_eip7702_tx(1, [0xAA; 20], 0, 0, [0xDE; 20]);
    let hex_7702 = to_hex(&rlp_7702);
    let out_inspect = Command::new(sentinel_bin())
        .args(["inspect-tx", "--chain", "eth", "--raw", &hex_7702])
        .output()
        .expect("run inspect-tx");
    assert!(!out_inspect.status.success());
    let stdout_ins = String::from_utf8_lossy(&out_inspect.stdout);
    assert!(stdout_ins.contains("FORBIDDEN EIP-7702 RLP SetCode Delegation"));
    assert!(stdout_ins.contains("VERDICT: REJECT & FREEZE CIRCUIT BREAKER"));

    // 3. `genos-sentinel verify-safe-tx` blocks a Bybit-style DELEGATECALL (`operation: 1`)
    let bad_safe = r#"{"to":"0xdededededededededededededededededededede","value":0,"operation":1,"data":"0x"}"#;
    let out_safe_bad = Command::new(sentinel_bin())
        .args(["verify-safe-tx", "--json", bad_safe])
        .output()
        .expect("run verify-safe-tx bad");
    assert!(!out_safe_bad.status.success());
    let stdout_sb = String::from_utf8_lossy(&out_safe_bad.stdout);
    assert!(stdout_sb.contains("VERDICT: BLOCKED (Bybit Feb-2025 DELEGATECALL Vector Detected!)"));

    // 4. `genos-sentinel verify-safe-tx` allows a clean CALL (`operation: 0`, empty data)
    let good_safe = r#"{"to":"0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","value":5000,"operation":0,"data":"0x","nonce":42}"#;
    let out_safe_ok = Command::new(sentinel_bin())
        .args(["verify-safe-tx", "--json", good_safe])
        .output()
        .expect("run verify-safe-tx good");
    assert!(out_safe_ok.status.success());
    let stdout_so = String::from_utf8_lossy(&out_safe_ok.stdout);
    assert!(stdout_so.contains("VERDICT: SAFE CALL VERIFIED"));
}
