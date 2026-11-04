//! The verified core driving the real TPM backend: CTAP requests end to end on swtpm.

mod support;

use passkey_tpm_core::ctap2::{status, Authenticator, Command, Step, UserInfo, UvOutcome};
use passkey_tpm_core::evidence::UvEvidence;
use passkey_tpm_core::pin_protocol::{parse_platform_key, KeyAgreement, Protocol};
use passkey_tpm_core::tpm_iface::Uid;
use passkey_tpm_tpm::adapter::TpmBackend;
use passkey_tpm_wire::cbor::{self, Value};
use support::swtpm::Swtpm;

const ALICE: Uid = Uid(1000);
const ENROLLED: UserInfo = UserInfo { uv_enrolled: true };
const RP: &str = "example.com";

fn state_dir(name: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("passkey-tpm-ctap-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

fn int(i: i64) -> Value {
    Value::int_key(i)
}

fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

fn req(command: Command, params: Vec<(Value, Value)>) -> Vec<u8> {
    let mut r = vec![command.code()];
    r.extend_from_slice(&cbor::encode(&Value::Map(params)));
    r
}

fn body(resp: &[u8]) -> Value {
    assert_eq!(resp[0], status::OK, "status {:#04x}", resp[0]);
    cbor::decode(&resp[1..]).expect("CBOR response")
}

/// Runs a request that needs a fingerprint and answers with a match.
fn with_touch(a: &mut Authenticator<TpmBackend>, request: &[u8]) -> Vec<u8> {
    match a.prepare(ALICE, ENROLLED, request, 1_000) {
        Step::NeedUv(p) => a.complete(
            p,
            UvOutcome::Matched(UvEvidence::from_fprintd_match(ALICE.0)),
            1_000,
        ),
        Step::NeedPresence(p) => panic!("expected a fingerprint prompt for {}", p.rp_id()),
        Step::Done(r) => panic!("expected a prompt, got status {:#04x}", r[0]),
    }
}

fn make_credential(a: &mut Authenticator<TpmBackend>, extensions: Option<Value>) -> Vec<u8> {
    let mut params = vec![
        (int(1), Value::Bytes(vec![9; 32])),
        (int(2), Value::Map(vec![(text("id"), text(RP))])),
        (
            int(3),
            Value::Map(vec![
                (text("id"), Value::Bytes(vec![7; 16])),
                (text("name"), text("alice")),
            ]),
        ),
        (
            int(4),
            Value::Array(vec![Value::Map(vec![
                (text("alg"), int(-7)),
                (text("type"), text("public-key")),
            ])]),
        ),
    ];
    if let Some(ext) = extensions {
        params.push((int(6), ext));
    }
    let resp = body(&with_touch(a, &req(Command::MakeCredential, params)));
    let auth = resp
        .map_get(&int(2))
        .and_then(Value::as_bytes)
        .expect("authData");
    let len = usize::from(u16::from_be_bytes([auth[53], auth[54]]));
    auth[55..55 + len].to_vec()
}

/// A getAssertion hmac-secret extension input with one salt.
fn hmac_secret_input(a: &mut Authenticator<TpmBackend>) -> Value {
    let protocol = Protocol::Two;
    let resp = match a.prepare(
        ALICE,
        ENROLLED,
        &req(
            Command::ClientPin,
            vec![
                (int(1), Value::Uint(protocol.as_u64())),
                (int(2), Value::Uint(2)),
            ],
        ),
        1_000,
    ) {
        Step::Done(r) => body(&r),
        Step::NeedUv(_) | Step::NeedPresence(_) => panic!("getKeyAgreement needs no prompt"),
    };
    let auth_key = parse_platform_key(resp.map_get(&int(1)).expect("key")).expect("COSE key");
    let key = KeyAgreement::generate().expect("key agreement");
    let shared = key
        .shared_secret(protocol, &auth_key)
        .expect("shared secret");
    let salt_enc = shared.encrypt(&[1u8; 32]).expect("encrypt");
    Value::Map(vec![
        (int(1), key.cose_public()),
        (int(2), Value::Bytes(salt_enc.clone())),
        (int(3), Value::Bytes(shared.authenticate(&salt_enc))),
        (int(4), Value::Uint(protocol.as_u64())),
    ])
}

/// HARD-08: hmac-secret requested for a credential created without it.
#[test]
fn hmac_secret_for_a_credential_without_it_is_omitted() {
    let tpm = Swtpm::start();
    let dir = state_dir("hmac-omitted");
    let mut a = Authenticator::new(TpmBackend::new(tpm.context(), dir.clone()));
    let id = make_credential(&mut a, None);

    let hmac_in = hmac_secret_input(&mut a);
    let ga = req(
        Command::GetAssertion,
        vec![
            (int(1), text(RP)),
            (int(2), Value::Bytes(vec![8; 32])),
            (
                int(3),
                Value::Array(vec![Value::Map(vec![
                    (text("type"), text("public-key")),
                    (text("id"), Value::Bytes(id)),
                ])]),
            ),
            (int(4), Value::Map(vec![(text("hmac-secret"), hmac_in)])),
        ],
    );
    let resp = body(&with_touch(&mut a, &ga));
    let auth = resp
        .map_get(&int(2))
        .and_then(Value::as_bytes)
        .expect("authData");
    assert_eq!(auth[32] & 0x80, 0, "no ED flag");
    assert_eq!(auth.len(), 37, "no extension output");
    std::fs::remove_dir_all(dir).expect("cleanup");
}
