use hacp::secure::{
    envelope::{decode_hex, encode_hex, Kind, SecureEnvelope},
    SecureError,
};
use serde_json::{json, Value};
fn msg() -> SecureEnvelope {
    SecureEnvelope {
        v: 1,
        kind: Kind::Msg,
        from: "urn:hacp:agent:a".into(),
        to: "urn:hacp:agent:b".into(),
        contract: String::new(),
        sid: Some("01".repeat(16)),
        seq: Some(0),
        epub: None,
        nonce: None,
        sig: Some("02".repeat(64)),
        ct: Some("03".repeat(16)),
        ts: None,
    }
}
fn parse(value: Value) -> Result<SecureEnvelope, SecureError> {
    SecureEnvelope::from_json(&serde_json::to_vec(&value).unwrap())
}
#[test]
fn exact_canonical_aad_signature_bytes_and_roundtrip() {
    let env = msg();
    let expected=b"{\"contract\":\"\",\"from\":\"urn:hacp:agent:a\",\"kind\":\"msg\",\"seq\":0,\"sid\":\"01010101010101010101010101010101\",\"to\":\"urn:hacp:agent:b\",\"v\":1}";
    assert_eq!(env.aad_bytes().unwrap(), expected);
    let mut signature = b"HACP-SECURE/v1/msg".to_vec();
    signature.extend(expected);
    signature.extend([3; 16]);
    assert_eq!(env.message_signing_input().unwrap(), signature);
    assert_eq!(
        SecureEnvelope::from_json(&env.canonical_bytes().unwrap()).unwrap(),
        env
    );
    let mut unsigned = env.clone();
    unsigned.ct = None;
    unsigned.sig = None;
    assert_eq!(unsigned.aad_bytes().unwrap(), expected);
    assert_eq!(unsigned.validate(), Err(SecureError::SchemaViolation));
}
#[test]
fn all_required_and_unknown_null_duplicate_fields_fail() {
    let v = serde_json::to_value(msg()).unwrap();
    for key in [
        "v", "kind", "from", "to", "contract", "sid", "seq", "ct", "sig",
    ] {
        let mut bad = v.clone();
        bad.as_object_mut().unwrap().remove(key);
        assert!(parse(bad).is_err(), "missing {key}");
    }
    for key in ["sid", "seq", "epub", "nonce", "sig", "ct", "ts"] {
        let mut bad = v.clone();
        bad[key] = Value::Null;
        assert!(parse(bad).is_err(), "null {key}");
    }
    let mut bad = v;
    bad["skip_verify"] = json!(true);
    assert!(parse(bad).is_err());
    let bytes = String::from_utf8(msg().canonical_bytes().unwrap()).unwrap();
    let duplicate = bytes.replacen("{", "{\"seq\":99,", 1);
    assert!(SecureEnvelope::from_json(duplicate.as_bytes()).is_err());
}
#[test]
fn malformed_shapes_reject_without_normalizing() {
    for (key, value) in [
        ("v", json!(2)),
        ("v", json!(1.0)),
        ("kind", json!("MSG")),
        ("seq", json!(-1)),
        ("seq", json!(0.5)),
        ("from", json!("urn:hacp:agent:A")),
        ("to", json!("urn:hacp:agent:-b")),
        ("sid", json!("AA".repeat(16))),
        ("ct", json!("0".repeat(33))),
        ("ct", json!("00")),
        ("sig", json!("00".repeat(63))),
        ("contract", json!("sha256:")),
        ("ts", json!("2026-02-31T00:00:00Z")),
    ] {
        let mut v = serde_json::to_value(msg()).unwrap();
        v[key] = value;
        assert!(parse(v).is_err(), "{key}");
    }
    let mut v = serde_json::to_value(msg()).unwrap();
    v["seq"] = json!(u64::MAX);
    assert!(parse(v).is_ok());
}
#[test]
fn timestamp_is_signed_verbatim_and_schema_allowed_headers_are_preserved() {
    let mut env = msg();
    env.ts = Some("2026-09-13T12:00:00.25-07:00".into());
    env.epub = Some("00".repeat(32));
    env.validate().unwrap();
    let aad = String::from_utf8(env.aad_bytes().unwrap()).unwrap();
    assert!(aad.contains("2026-09-13T12:00:00.25-07:00"));
    assert!(aad.contains("epub"));
    let signature = env.message_signing_input().unwrap();
    env.ts = Some("2026-09-13T19:00:00.25Z".into());
    assert_ne!(signature, env.message_signing_input().unwrap());
}
#[test]
fn handshake_transcripts_are_exact_domain_and_raw_bytes() {
    let mut hello = msg();
    hello.kind = Kind::Hello;
    hello.sid = None;
    hello.seq = None;
    hello.ct = None;
    hello.epub = Some("04".repeat(32));
    hello.nonce = Some("05".repeat(32));
    hello.sig = None;
    let mut expected = b"HACP-SECURE/v1/hellos-1urn:hacp:agent:aurn:hacp:agent:b".to_vec();
    expected.extend([4; 32]);
    expected.extend([5; 32]);
    assert_eq!(hello.hello_signing_input("s-1").unwrap(), expected);
    let mut ack = hello.clone();
    ack.kind = Kind::Ack;
    ack.from = hello.to.clone();
    ack.to = hello.from.clone();
    ack.sid = Some("06".repeat(16));
    ack.epub = Some("07".repeat(32));
    ack.nonce = Some("08".repeat(32));
    let mut expected = b"HACP-SECURE/v1/acks-1urn:hacp:agent:burn:hacp:agent:a".to_vec();
    for b in [4, 5, 7, 8] {
        expected.extend([b; 32]);
    }
    assert_eq!(ack.ack_signing_input("s-1", &hello).unwrap(), expected);
    for mut env in [hello, ack] {
        env.sig = Some("00".repeat(64));
        env.validate().unwrap();
        env.contract = format!("sha256:{}", "00".repeat(32));
        assert!(env.validate().is_err());
    }
}
#[test]
fn hex_bytes_roundtrip_and_reject_ambiguous_forms() {
    let bytes: Vec<u8> = (0..=255).collect();
    assert_eq!(decode_hex(&encode_hex(&bytes)).unwrap(), bytes);
    for bad in ["f", "FF", "0x00", " 00", "gg", "é"] {
        assert!(decode_hex(bad).is_err());
    }
}

#[test]
fn complete_kind_goldens_match_frozen_shape() {
    let message = msg();
    let mut hello = message.clone();
    hello.kind = Kind::Hello;
    hello.sid = None;
    hello.seq = None;
    hello.ct = None;
    hello.epub = Some("04".repeat(32));
    hello.nonce = Some("05".repeat(32));
    let mut ack = hello.clone();
    ack.kind = Kind::Ack;
    ack.from = hello.to.clone();
    ack.to = hello.from.clone();
    ack.sid = Some("06".repeat(16));
    let goldens: Vec<Value> = [hello, ack, message]
        .iter()
        .map(|env| {
            let bytes = env.canonical_bytes().unwrap();
            assert_eq!(SecureEnvelope::from_json(&bytes).unwrap(), *env);
            serde_json::from_slice(&bytes).unwrap()
        })
        .collect();
    // Test-only export for independent Draft 2020-12 validation, never a CLI path.
    if let Some(path) = std::env::var_os("HACP_TEST_SCHEMA_FIXTURES") {
        std::fs::write(path, serde_json::to_vec(&goldens).unwrap()).unwrap();
    }
}
