use std::collections::HashMap;

use passkey_tpm_wire::cbor::{self, Value};
use passkey_tpm_wire::credid::KeyBlobs;
use proptest::prelude::*;

use super::common::{
    cmd, get, get_text, int, sha256, status, text, AAGUID, MAX_CREDENTIAL_COUNT_IN_LIST,
    MAX_MSG_SIZE, MAX_UV_RETRIES,
};
use super::{Authenticator, Step, UserInfo, UvOutcome};
use crate::evidence::UvEvidence;
use crate::gates::GateKind;
use crate::pin_protocol::{parse_platform_key, KeyAgreement, Protocol, SharedSecret};
use crate::tpm_iface::{CredBlobs, CredProtect, ResidentEntry, RpIdHash, TpmError, TpmOps, Uid};

/// In-memory backend. Credential IDs are `uid ‖ rpIdHash ‖ counter ‖ hmac flag` and open
/// only for that pair; hmac-secret is SHA-256(private ‖ salt).
#[derive(Debug, Default)]
struct MockTpm {
    created: u32,
    signed: Vec<(Uid, GateKind, [u8; 32])>,
    pins: HashMap<u32, [u8; 16]>,
    retries: HashMap<u32, u8>,
    resident: HashMap<u32, Vec<ResidentEntry>>,
    resets: Vec<u32>,
    revoked: Vec<Vec<u8>>,
    /// Forced `verify_pin` outcome (TPM-wide lockout, TPM gone) before any comparison.
    verify_error: Option<TpmError>,
}

impl TpmOps for MockTpm {
    fn create_credential(
        &mut self,
        _: Uid,
        _: &RpIdHash,
        protect: CredProtect,
        with_hmac: bool,
    ) -> Result<CredBlobs, TpmError> {
        assert_eq!(protect, CredProtect::UvRequired);
        self.created += 1;
        let key = KeyBlobs {
            public: vec![1],
            private: self.created.to_be_bytes().to_vec(),
        };
        let hmac = with_hmac.then(|| passkey_tpm_wire::credid::HmacBlobs {
            with_uv: key.clone(),
            without_uv: key.clone(),
        });
        Ok(CredBlobs { protect, key, hmac })
    }
    fn credential_id(
        &mut self,
        uid: Uid,
        rp: &RpIdHash,
        blobs: &CredBlobs,
    ) -> Result<Vec<u8>, TpmError> {
        let mut id = uid.0.to_be_bytes().to_vec();
        id.extend_from_slice(&rp.0);
        id.extend_from_slice(&blobs.key.private);
        id.push(u8::from(blobs.hmac.is_some()));
        Ok(id)
    }
    fn open_credential_id(
        &mut self,
        uid: Uid,
        rp: &RpIdHash,
        id: &[u8],
    ) -> Result<Option<CredBlobs>, TpmError> {
        if id.len() == 41
            && id[..4] == uid.0.to_be_bytes()
            && id[4..36] == rp.0
            && !self.resets.contains(&uid.0)
        {
            let key = KeyBlobs {
                public: vec![1],
                private: id[36..40].to_vec(),
            };
            let hmac = (id[40] == 1).then(|| passkey_tpm_wire::credid::HmacBlobs {
                with_uv: key.clone(),
                without_uv: key.clone(),
            });
            Ok(Some(CredBlobs {
                protect: CredProtect::UvRequired,
                key,
                hmac,
            }))
        } else {
            Ok(None)
        }
    }
    fn public_key(&mut self, _: &CredBlobs) -> Result<([u8; 32], [u8; 32]), TpmError> {
        Ok(([0xaa; 32], [0xbb; 32]))
    }
    fn sign(
        &mut self,
        uid: Uid,
        _: &CredBlobs,
        _: &RpIdHash,
        gate: GateKind,
        digest: &[u8; 32],
    ) -> Result<Vec<u8>, TpmError> {
        self.signed.push((uid, gate, *digest));
        Ok(vec![0x30, 0x00])
    }
    fn hmac(
        &mut self,
        _: Uid,
        blobs: &CredBlobs,
        _: &RpIdHash,
        gate: GateKind,
        salt: &[u8; 32],
    ) -> Result<[u8; 32], TpmError> {
        assert!(gate.is_uv(), "UV always set, so CredRandomWithUV");
        if blobs.hmac.is_none() {
            // Like the TPM backend: no hmac-secret keys behaves like a foreign credential.
            return Err(TpmError::PolicyFailed);
        }
        Ok(sha256(&[&blobs.key.private, salt]))
    }
    fn change_pin(
        &mut self,
        uid: Uid,
        old: Option<&[u8; 16]>,
        new: &[u8; 16],
    ) -> Result<(), TpmError> {
        if self.pins.get(&uid.0) != old {
            return Err(TpmError::WrongPin);
        }
        self.pins.insert(uid.0, *new);
        Ok(())
    }
    fn verify_pin(&mut self, uid: Uid, pin_hash: &[u8; 16]) -> Result<(), TpmError> {
        if let Some(e) = self.verify_error {
            return Err(e);
        }
        match self.pins.get(&uid.0) {
            Some(p) if p == pin_hash => Ok(()),
            Some(_) => Err(TpmError::WrongPin),
            None => Err(TpmError::Unavailable),
        }
    }
    fn pin_is_set(&mut self, uid: Uid) -> Result<bool, TpmError> {
        Ok(self.pins.contains_key(&uid.0))
    }
    fn pin_retries(&mut self, uid: Uid) -> Result<u8, TpmError> {
        Ok(*self.retries.get(&uid.0).unwrap_or(&8))
    }
    fn set_pin_retries(&mut self, uid: Uid, retries: u8) -> Result<(), TpmError> {
        self.retries.insert(uid.0, retries);
        Ok(())
    }
    fn resident_entries(&mut self, uid: Uid) -> Result<Vec<ResidentEntry>, TpmError> {
        Ok(self.resident.get(&uid.0).cloned().unwrap_or_default())
    }
    fn store_resident_entries(
        &mut self,
        uid: Uid,
        entries: &[ResidentEntry],
    ) -> Result<(), TpmError> {
        self.resident.insert(uid.0, entries.to_vec());
        Ok(())
    }
    fn revoke_credential(&mut self, _: Uid, id: &[u8]) -> Result<(), TpmError> {
        self.revoked.push(id.to_vec());
        Ok(())
    }
    fn reset_user(&mut self, uid: Uid) -> Result<(), TpmError> {
        self.resets.push(uid.0);
        self.pins.remove(&uid.0);
        self.retries.remove(&uid.0);
        self.resident.remove(&uid.0);
        Ok(())
    }
    fn health(&mut self) -> Result<(), TpmError> {
        Ok(())
    }
}

const ALICE: Uid = Uid(1000);
const BOB: Uid = Uid(1001);
const ENROLLED: UserInfo = UserInfo { uv_enrolled: true };
const NO_READER: UserInfo = UserInfo { uv_enrolled: false };
const RP: &str = "example.com";
const PIN: &[u8] = b"123456";

type A = Authenticator<MockTpm>;

fn auth() -> A {
    Authenticator::new(MockTpm::default())
}

fn req(command: u8, params: Vec<(Value, Value)>) -> Vec<u8> {
    let mut r = vec![command];
    if !params.is_empty() {
        r.extend_from_slice(&cbor::encode(&Value::Map(params)));
    }
    r
}

fn descriptor(id: &[u8]) -> Value {
    Value::Map(vec![
        (text("type"), text("public-key")),
        (text("id"), Value::Bytes(id.to_vec())),
    ])
}

fn mc_params(extra: Vec<(Value, Value)>) -> Vec<(Value, Value)> {
    let mut m = vec![
        (int(1), Value::Bytes(vec![9; 32])),
        (
            int(2),
            Value::Map(vec![
                (text("id"), text(RP)),
                (text("name"), text("Example")),
            ]),
        ),
        (
            int(3),
            Value::Map(vec![
                (text("id"), Value::Bytes(vec![7; 16])),
                (text("name"), text("alice")),
                (text("displayName"), text("Alice")),
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
    m.extend(extra);
    m
}

fn ga_params(allow: Option<Vec<Value>>, extra: Vec<(Value, Value)>) -> Vec<(Value, Value)> {
    let mut m = vec![(int(1), text(RP)), (int(2), Value::Bytes(vec![8; 32]))];
    if let Some(list) = allow {
        m.push((int(3), Value::Array(list)));
    }
    m.extend(extra);
    m
}

fn prep(a: &mut A, uid: Uid, request: &[u8]) -> Step {
    a.prepare(uid, ENROLLED, request, 1_000)
}

fn need_uv(step: Step) -> Box<super::Pending> {
    match step {
        Step::NeedUv(p) => p,
        Step::NeedPresence(p) => panic!("expected NeedUv, got NeedPresence for {}", p.rp_id()),
        Step::Done(r) => panic!("expected NeedUv, got status {:#04x}", r[0]),
    }
}

fn need_presence(step: Step) -> Box<super::Pending> {
    match step {
        Step::NeedPresence(p) => p,
        Step::NeedUv(p) => panic!("expected NeedPresence, got NeedUv for {}", p.rp_id()),
        Step::Done(r) => panic!("expected NeedPresence, got status {:#04x}", r[0]),
    }
}

fn done(step: Step) -> Vec<u8> {
    match step {
        Step::Done(r) => r,
        Step::NeedUv(p) | Step::NeedPresence(p) => {
            panic!("unexpected prompt for {}", p.rp_id())
        }
    }
}

fn touch(a: &mut A, uid: Uid, step: Step) -> Vec<u8> {
    a.complete(
        need_uv(step),
        UvOutcome::Matched(UvEvidence::from_fprintd_match(uid.0)),
        1_000,
    )
}

fn body(resp: &[u8]) -> Value {
    assert_eq!(resp[0], status::OK, "status {:#04x}", resp[0]);
    if resp.len() == 1 {
        return Value::Map(Vec::new());
    }
    cbor::decode(&resp[1..]).unwrap()
}

fn cred_id_from_auth_data(auth: &[u8]) -> Vec<u8> {
    let len = usize::from(u16::from_be_bytes([auth[53], auth[54]]));
    auth[55..55 + len].to_vec()
}

fn register(a: &mut A, extra: Vec<(Value, Value)>) -> Vec<u8> {
    let step = prep(a, ALICE, &req(cmd::MAKE_CREDENTIAL, mc_params(extra)));
    let resp = body(&touch(a, ALICE, step));
    cred_id_from_auth_data(get(&resp, 2).and_then(Value::as_bytes).unwrap())
}

/// The platform side of PIN/UV auth protocol `protocol` with this authenticator.
struct Platform {
    protocol: Protocol,
    key: KeyAgreement,
    shared: SharedSecret,
}

impl Platform {
    fn new(a: &mut A, uid: Uid, protocol: Protocol) -> Self {
        let p = Value::Uint(protocol.as_u64());
        let resp = body(&done(prep(
            a,
            uid,
            &req(cmd::CLIENT_PIN, vec![(int(1), p), (int(2), Value::Uint(2))]),
        )));
        let auth_key = parse_platform_key(get(&resp, 1).unwrap()).unwrap();
        let key = KeyAgreement::generate().unwrap();
        let shared = key.shared_secret(protocol, &auth_key).unwrap();
        Self {
            protocol,
            key,
            shared,
        }
    }

    fn base(&self, sub: u64) -> Vec<(Value, Value)> {
        vec![
            (int(1), Value::Uint(self.protocol.as_u64())),
            (int(2), Value::Uint(sub)),
            (int(3), self.key.cose_public()),
        ]
    }

    fn padded(pin: &[u8]) -> Vec<u8> {
        let mut p = pin.to_vec();
        p.resize(64, 0);
        p
    }

    fn pin_hash_enc(&self, pin: &[u8]) -> Vec<u8> {
        self.shared.encrypt(&sha256(&[pin])[..16]).unwrap()
    }

    fn set_pin(&self, pin: &[u8]) -> Vec<u8> {
        let enc = self.shared.encrypt(&Self::padded(pin)).unwrap();
        let mut m = self.base(3);
        m.push((int(4), Value::Bytes(self.shared.authenticate(&enc))));
        m.push((int(5), Value::Bytes(enc)));
        req(cmd::CLIENT_PIN, m)
    }

    fn change_pin(&self, old: &[u8], new: &[u8]) -> Vec<u8> {
        let new_enc = self.shared.encrypt(&Self::padded(new)).unwrap();
        let hash_enc = self.pin_hash_enc(old);
        let mut msg = new_enc.clone();
        msg.extend_from_slice(&hash_enc);
        let mut m = self.base(4);
        m.push((int(4), Value::Bytes(self.shared.authenticate(&msg))));
        m.push((int(5), Value::Bytes(new_enc)));
        m.push((int(6), Value::Bytes(hash_enc)));
        req(cmd::CLIENT_PIN, m)
    }

    fn token_using_pin(&self, pin: &[u8], perms: u8, rp: Option<&str>) -> Vec<u8> {
        let mut m = self.base(9);
        m.push((int(6), Value::Bytes(self.pin_hash_enc(pin))));
        m.push((int(9), Value::Uint(u64::from(perms))));
        if let Some(rp) = rp {
            m.push((int(10), text(rp)));
        }
        req(cmd::CLIENT_PIN, m)
    }

    fn token_using_uv(&self, perms: u8, rp: &str) -> Vec<u8> {
        let mut m = self.base(6);
        m.push((int(9), Value::Uint(u64::from(perms))));
        m.push((int(10), text(rp)));
        req(cmd::CLIENT_PIN, m)
    }

    fn decrypt_token(&self, resp: &[u8]) -> [u8; 32] {
        let enc = get(&body(resp), 2)
            .and_then(Value::as_bytes)
            .unwrap()
            .to_vec();
        self.shared
            .decrypt(&enc)
            .unwrap()
            .as_slice()
            .try_into()
            .unwrap()
    }

    fn auth_param(&self, token: &[u8; 32], message: &[u8]) -> Value {
        Value::Bytes(crate::pin_protocol::authenticate_with_token(
            self.protocol,
            token,
            message,
        ))
    }
}

fn set_pin(a: &mut A, uid: Uid, protocol: Protocol) {
    let p = Platform::new(a, uid, protocol);
    assert_eq!(done(prep(a, uid, &p.set_pin(PIN))), vec![status::OK]);
}

// ---------------------------------------------------------------- getInfo / basics

#[test]
fn get_info_advertises_ctap_2_1() {
    let mut a = auth();
    let info = body(&done(prep(&mut a, ALICE, &[cmd::GET_INFO])));
    assert_eq!(
        get(&info, 1),
        Some(&Value::Array(vec![text("FIDO_2_0"), text("FIDO_2_1")]))
    );
    assert_eq!(
        get(&info, 2),
        Some(&Value::Array(vec![
            text("credProtect"),
            text("hmac-secret")
        ]))
    );
    let opts = get(&info, 4).unwrap();
    for (k, v) in [
        ("rk", true),
        ("uv", true),
        ("clientPin", false),
        ("pinUvAuthToken", true),
        ("credMgmt", true),
    ] {
        assert_eq!(get_text(opts, k), Some(&Value::Bool(v)), "{k}");
    }
    assert_eq!(
        get(&info, 6),
        Some(&Value::Array(vec![Value::Uint(2), Value::Uint(1)]))
    );
    set_pin(&mut a, ALICE, Protocol::Two);
    let info = body(&done(prep(&mut a, ALICE, &[cmd::GET_INFO])));
    assert_eq!(
        get_text(get(&info, 4).unwrap(), "clientPin"),
        Some(&Value::Bool(true))
    );
    let info = body(&done(prep(&mut a, BOB, &[cmd::GET_INFO])));
    assert_eq!(
        get_text(get(&info, 4).unwrap(), "clientPin"),
        Some(&Value::Bool(false)),
        "per user"
    );
}

/// M3.1: the advertisement must match the implementation, and nothing unimplemented may be
/// advertised. A wrong value here silently changes what every platform offers the user, so
/// each member and option is pinned to the code that enforces it.
#[test]
fn get_info_advertisement_matches_implemented_features() {
    let mut a = auth();
    let info = body(&done(prep(&mut a, ALICE, &[cmd::GET_INFO])));

    // Members a platform may act on.
    for key in [
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0D, 0x0E, 0x12, 0x14,
    ] {
        assert!(get(&info, key).is_some(), "missing member {key:#04x}");
    }
    // Features with no implementation must not be advertised.
    for key in [0x0B, 0x0C, 0x0F, 0x10, 0x11, 0x13, 0x15] {
        assert!(
            get(&info, key).is_none(),
            "member {key:#04x} must be absent"
        );
    }

    assert_eq!(
        get(&info, 1),
        Some(&Value::Array(vec![text("FIDO_2_0"), text("FIDO_2_1")]))
    );
    assert_eq!(
        get(&info, 2),
        Some(&Value::Array(vec![
            text("credProtect"),
            text("hmac-secret")
        ]))
    );
    assert_eq!(
        get(&info, 5),
        Some(&Value::Uint(MAX_MSG_SIZE)),
        "maxMsgSize"
    );
    assert_eq!(
        MAX_MSG_SIZE,
        crate::ctaphid::MAX_MSG as u64,
        "maxMsgSize must be the enforced HID limit"
    );
    assert_eq!(
        get(&info, 6),
        Some(&Value::Array(vec![Value::Uint(2), Value::Uint(1)])),
        "both PIN/UV auth protocols are implemented"
    );
    assert_eq!(
        get(&info, 7),
        Some(&Value::Uint(MAX_CREDENTIAL_COUNT_IN_LIST as u64))
    );
    assert_eq!(
        get(&info, 8),
        Some(&Value::Uint(passkey_tpm_wire::credid::MAX_LEN as u64))
    );
    assert_eq!(get(&info, 9), Some(&Value::Array(vec![text("usb")])));
    assert_eq!(get(&info, 0x0D), Some(&Value::Uint(4)), "minPINLength");
    assert_eq!(
        get(&info, 0x0E),
        Some(&Value::Uint(super::info::firmware_version())),
        "firmwareVersion follows the crate version"
    );
    assert_eq!(
        get(&info, 0x12),
        Some(&Value::Uint(0x02)),
        "uvModality is fingerprint"
    );
    assert_eq!(get(&info, 0x14), Some(&Value::Uint(64)), "remaining rk");

    // Options are capability flags, not current configuration.
    let opts = get(&info, 4).unwrap();
    for (name, value) in [
        ("rk", true),
        ("up", true),
        ("uv", true),
        ("plat", false),
        ("credMgmt", true),
        ("clientPin", false),
        ("pinUvAuthToken", true),
        ("makeCredUvNotRqd", false),
    ] {
        assert_eq!(get_text(opts, name), Some(&Value::Bool(value)), "{name}");
    }
    for name in [
        "alwaysUv",
        "authnrCfg",
        "bioEnroll",
        "largeBlobs",
        "ep",
        "noMcGaPermissionsWithClientPin",
        "setMinPINLength",
        "credentialMgmtPreview",
        "userVerificationMgmtPreview",
        "uvBioEnroll",
        "uvAcfg",
    ] {
        assert_eq!(get_text(opts, name), None, "{name} must not be advertised");
    }

    // A missing finger keeps `uv` present and turns it false; a missing PIN does the same for
    // `clientPin`. Both mean "capable, not configured" (CTAP 2.1 §6.4), not "unsupported".
    let no_reader = body(&done(a.prepare(ALICE, NO_READER, &[cmd::GET_INFO], 1_000)));
    let opts = get(&no_reader, 4).unwrap();
    assert_eq!(get_text(opts, "uv"), Some(&Value::Bool(false)));
    assert_eq!(get_text(opts, "clientPin"), Some(&Value::Bool(false)));

    // The advertised boundary values are enforced, not decorative: a resident credential
    // draws down `remainingDiscoverableCredentials`, and one ID over the advertised list
    // limit is rejected.
    let _ = register(
        &mut a,
        vec![(int(7), Value::Map(vec![(text("rk"), Value::Bool(true))]))],
    );
    let info = body(&done(prep(&mut a, ALICE, &[cmd::GET_INFO])));
    assert_eq!(get(&info, 0x14), Some(&Value::Uint(63)));

    let over_limit = u8::try_from(MAX_CREDENTIAL_COUNT_IN_LIST).unwrap();
    let too_many: Vec<Value> = (0..=over_limit).map(|i| descriptor(&[i])).collect();
    assert_eq!(
        done(prep(
            &mut a,
            ALICE,
            &req(cmd::GET_ASSERTION, ga_params(Some(too_many), vec![]))
        )),
        vec![status::LIMIT_EXCEEDED]
    );
}

#[test]
fn gesture_registration_and_assertion_still_work() {
    let mut a = auth();
    let id = register(&mut a, vec![]);
    let step = prep(
        &mut a,
        ALICE,
        &req(
            cmd::GET_ASSERTION,
            ga_params(Some(vec![descriptor(&[0xee; 41]), descriptor(&id)]), vec![]),
        ),
    );
    let resp = body(&touch(&mut a, ALICE, step));
    assert_eq!(
        get_text(get(&resp, 1).unwrap(), "id"),
        Some(&Value::Bytes(id))
    );
    let auth_data = get(&resp, 2).and_then(Value::as_bytes).unwrap();
    assert_eq!(auth_data[32], 0x05);
    assert!(get(&resp, 4).is_none(), "no user for non-discoverable");
    assert_eq!(a.tpm_mut().signed.last().unwrap().1, GateKind::Uv);
}

#[test]
fn make_credential_layout_and_attestation() {
    let mut a = auth();
    let step = prep(&mut a, ALICE, &req(cmd::MAKE_CREDENTIAL, mc_params(vec![])));
    assert_eq!(
        need_uv(prep(
            &mut a,
            ALICE,
            &req(cmd::MAKE_CREDENTIAL, mc_params(vec![]))
        ))
        .rp_id(),
        RP
    );
    let resp = body(&touch(&mut a, ALICE, step));
    assert_eq!(get(&resp, 1), Some(&text("packed")));
    let auth_data = get(&resp, 2).and_then(Value::as_bytes).unwrap();
    assert_eq!(auth_data[32], 0x45);
    assert_eq!(&auth_data[37..53], &AAGUID);
    assert!(get_text(get(&resp, 3).unwrap(), "x5c").is_none());
}

#[test]
fn errors_and_outcomes() {
    let mut a = auth();
    let opts = |k: &str, v: bool| (int(7), Value::Map(vec![(text(k), Value::Bool(v))]));
    assert_eq!(
        done(prep(
            &mut a,
            ALICE,
            &req(cmd::MAKE_CREDENTIAL, mc_params(vec![opts("up", false)]))
        )),
        vec![status::INVALID_OPTION]
    );
    assert_eq!(
        done(prep(&mut a, ALICE, &[cmd::MAKE_CREDENTIAL, 0xff])),
        vec![status::INVALID_CBOR]
    );
    assert_eq!(
        done(prep(&mut a, ALICE, &[0x40])),
        vec![status::INVALID_COMMAND]
    );
    assert_eq!(
        done(a.prepare(
            ALICE,
            NO_READER,
            &req(cmd::MAKE_CREDENTIAL, mc_params(vec![])),
            0
        )),
        vec![status::NOT_ALLOWED]
    );
    for (outcome, code) in [
        (UvOutcome::NoMatch, status::OPERATION_DENIED),
        (UvOutcome::Cancelled, status::KEEPALIVE_CANCEL),
        (UvOutcome::TimedOut, status::USER_ACTION_TIMEOUT),
        (UvOutcome::Unavailable, status::NOT_ALLOWED),
        (
            UvOutcome::Matched(UvEvidence::from_fprintd_match(BOB.0)),
            status::OPERATION_DENIED,
        ),
    ] {
        let p = need_uv(prep(
            &mut a,
            ALICE,
            &req(cmd::MAKE_CREDENTIAL, mc_params(vec![])),
        ));
        assert_eq!(a.complete(p, outcome, 0), vec![code]);
    }
    assert!(a.tpm_mut().signed.is_empty());
}

#[test]
fn exclude_list_is_honoured() {
    let mut a = auth();
    let id = register(&mut a, vec![]);
    let step = prep(
        &mut a,
        ALICE,
        &req(
            cmd::MAKE_CREDENTIAL,
            mc_params(vec![(int(5), Value::Array(vec![descriptor(&id)]))]),
        ),
    );
    assert_eq!(
        touch(&mut a, ALICE, step),
        vec![status::CREDENTIAL_EXCLUDED]
    );
}

// ---------------------------------------------------------------- clientPIN

#[test]
fn set_pin_then_token_using_pin_needs_presence_gesture() {
    for protocol in [Protocol::One, Protocol::Two] {
        let mut a = auth();
        set_pin(&mut a, ALICE, protocol);
        let p = Platform::new(&mut a, ALICE, protocol);
        assert_eq!(
            done(prep(&mut a, ALICE, &p.set_pin(b"999999"))),
            vec![status::NOT_ALLOWED],
            "setPIN once"
        );
        let token = p.decrypt_token(&done(prep(
            &mut a,
            ALICE,
            &p.token_using_pin(PIN, 0x03, Some(RP)),
        )));
        let param = p.auth_param(&token, &[9; 32]);
        let mc = req(
            cmd::MAKE_CREDENTIAL,
            mc_params(vec![
                (int(8), param),
                (int(9), Value::Uint(protocol.as_u64())),
            ]),
        );
        // PIN gives UV but not presence: a fingerprint touch is still needed.
        let step = prep(&mut a, ALICE, &mc);
        let resp = body(&touch(&mut a, ALICE, step));
        assert_eq!(get(&resp, 2).and_then(Value::as_bytes).unwrap()[32], 0x45);
    }
}

// ------------------------------------------------- no fingerprint: PIN + presence (AD-022)

/// A PIN token for makeCredential + getAssertion on [`RP`], and the platform that got it.
fn pin_token(a: &mut A) -> (Platform, [u8; 32]) {
    set_pin(a, ALICE, Protocol::Two);
    let p = Platform::new(a, ALICE, Protocol::Two);
    let token = p.decrypt_token(&done(prep(
        a,
        ALICE,
        &p.token_using_pin(PIN, 0x03, Some(RP)),
    )));
    (p, token)
}

fn mc_with(p: &Platform, token: &[u8; 32]) -> Vec<u8> {
    req(
        cmd::MAKE_CREDENTIAL,
        mc_params(vec![
            (int(8), p.auth_param(token, &[9; 32])),
            (int(9), Value::Uint(2)),
        ]),
    )
}

fn ga_with(p: &Platform, token: &[u8; 32], allow: Vec<Value>) -> Vec<u8> {
    req(
        cmd::GET_ASSERTION,
        ga_params(
            Some(allow),
            vec![
                (int(6), p.auth_param(token, &[8; 32])),
                (int(7), Value::Uint(2)),
            ],
        ),
    )
}

#[test]
fn without_fingerprint_pin_and_presence_register_and_sign() {
    let mut a = auth();
    let (p, token) = pin_token(&mut a);
    let pending = need_presence(a.prepare(ALICE, NO_READER, &mc_with(&p, &token), 1_000));
    assert_eq!(pending.rp_id(), RP);
    let resp = body(&a.complete(pending, UvOutcome::Present, 1_000));
    let auth_data = get(&resp, 2).and_then(Value::as_bytes).unwrap();
    assert_eq!(auth_data[32], 0x45, "UP + UV + AT");
    let id = cred_id_from_auth_data(auth_data);

    let pending = need_presence(a.prepare(
        ALICE,
        NO_READER,
        &ga_with(&p, &token, vec![descriptor(&id)]),
        1_000,
    ));
    let resp = body(&a.complete(pending, UvOutcome::Present, 1_000));
    assert_eq!(get(&resp, 2).and_then(Value::as_bytes).unwrap()[32], 0x05);
    // Both signatures went through the UV gate (the PIN is not a policy branch, ADR 0003).
    let gates: Vec<GateKind> = a.tpm_mut().signed.iter().map(|s| s.1).collect();
    assert_eq!(gates, vec![GateKind::Uv, GateKind::Uv]);
}

#[test]
fn without_fingerprint_refused_presence_signs_nothing() {
    for (outcome, code) in [
        (UvOutcome::Denied, status::OPERATION_DENIED),
        (UvOutcome::Cancelled, status::KEEPALIVE_CANCEL),
        (UvOutcome::TimedOut, status::USER_ACTION_TIMEOUT),
        (UvOutcome::Unavailable, status::NOT_ALLOWED),
        (
            UvOutcome::Matched(UvEvidence::from_fprintd_match(BOB.0)),
            status::OPERATION_DENIED,
        ),
    ] {
        let mut a = auth();
        let (p, token) = pin_token(&mut a);
        let pending = need_presence(a.prepare(ALICE, NO_READER, &mc_with(&p, &token), 1_000));
        assert_eq!(a.complete(pending, outcome, 1_000), vec![code]);
        assert!(a.tpm_mut().signed.is_empty());
        // Refusals are not UV failures.
        assert_eq!(a.user(ALICE).uv_failures, 0);
    }
}

#[test]
fn presence_never_completes_a_fingerprint_request() {
    let mut a = auth();
    for request in [
        req(cmd::MAKE_CREDENTIAL, mc_params(vec![])),
        req(cmd::SELECTION, vec![]),
    ] {
        let pending = need_uv(prep(&mut a, ALICE, &request));
        assert_eq!(
            a.complete(pending, UvOutcome::Present, 1_000),
            vec![status::OPERATION_DENIED]
        );
    }
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    let pending = need_uv(prep(&mut a, ALICE, &p.token_using_uv(0x03, RP)));
    assert_eq!(
        a.complete(pending, UvOutcome::Present, 1_000),
        vec![status::OPERATION_DENIED]
    );
    assert!(a.tpm_mut().signed.is_empty());
}

#[test]
fn without_fingerprint_uv_is_never_assumed() {
    let mut a = auth();
    let mc = req(cmd::MAKE_CREDENTIAL, mc_params(vec![]));
    let ga = req(cmd::GET_ASSERTION, ga_params(None, vec![]));
    // No PIN: nothing can give UV.
    assert_eq!(
        done(a.prepare(ALICE, NO_READER, &mc, 0)),
        vec![status::NOT_ALLOWED]
    );
    // PIN set: the platform must use it.
    set_pin(&mut a, ALICE, Protocol::Two);
    assert_eq!(
        done(a.prepare(ALICE, NO_READER, &mc, 0)),
        vec![status::PUAT_REQUIRED]
    );
    assert_eq!(
        done(a.prepare(ALICE, NO_READER, &ga, 0)),
        vec![status::PUAT_REQUIRED]
    );
    // Built-in UV token: there is none.
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    assert_eq!(
        done(a.prepare(ALICE, NO_READER, &p.token_using_uv(0x03, RP), 0)),
        vec![status::NOT_ALLOWED]
    );
}

#[test]
fn without_fingerprint_select_touch_and_reset_need_presence() {
    let mut a = auth();
    let selection = need_presence(a.prepare(ALICE, NO_READER, &req(cmd::SELECTION, vec![]), 0));
    assert_eq!(
        a.complete(selection, UvOutcome::Present, 0),
        vec![status::OK]
    );

    let touch_to_select = req(
        cmd::MAKE_CREDENTIAL,
        mc_params(vec![
            (int(8), Value::Bytes(Vec::new())),
            (int(9), Value::Uint(2)),
        ]),
    );
    let pending = need_presence(a.prepare(ALICE, NO_READER, &touch_to_select, 0));
    assert_eq!(
        a.complete(pending, UvOutcome::Present, 0),
        vec![status::PIN_NOT_SET]
    );

    let reset = need_presence(a.prepare(ALICE, NO_READER, &req(cmd::RESET, vec![]), 0));
    assert_eq!(
        a.complete(reset, UvOutcome::Denied, 0),
        vec![status::OPERATION_DENIED]
    );
}

#[test]
fn without_fingerprint_blocked_pin_stops_before_prompting() {
    let mut a = auth();
    let (p, token) = pin_token(&mut a);
    a.tpm_mut().set_pin_retries(ALICE, 0).unwrap();
    assert_eq!(
        done(a.prepare(ALICE, NO_READER, &mc_with(&p, &token), 1_000)),
        vec![status::PIN_BLOCKED]
    );
}

#[test]
fn token_using_uv_skips_the_second_gesture_once() {
    let mut a = auth();
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    let step = prep(&mut a, ALICE, &p.token_using_uv(0x03, RP));
    let token = p.decrypt_token(&touch(&mut a, ALICE, step));
    let mc = |a: &mut A, token: &[u8; 32]| {
        let param = p.auth_param(token, &[9; 32]);
        prep(
            a,
            ALICE,
            &req(
                cmd::MAKE_CREDENTIAL,
                mc_params(vec![(int(8), param), (int(9), Value::Uint(2))]),
            ),
        )
    };
    let resp = body(&done(mc(&mut a, &token)));
    assert_eq!(
        get(&resp, 1),
        Some(&text("packed")),
        "no prompt: the token carried presence"
    );
    assert!(
        matches!(mc(&mut a, &token), Step::NeedUv(_)),
        "presence is consumed after one use"
    );
}

#[test]
fn wrong_pins_decrement_retries_then_block() {
    let mut a = auth();
    set_pin(&mut a, ALICE, Protocol::Two);
    let mut codes = Vec::new();
    for _ in 0..3 {
        let p = Platform::new(&mut a, ALICE, Protocol::Two);
        codes.push(
            done(prep(
                &mut a,
                ALICE,
                &p.token_using_pin(b"000000", 0x03, Some(RP)),
            ))[0],
        );
    }
    assert_eq!(
        codes,
        vec![
            status::PIN_INVALID,
            status::PIN_INVALID,
            status::PIN_AUTH_BLOCKED
        ]
    );
    assert_eq!(
        a.tpm_mut().retries[&ALICE.0],
        5,
        "decremented before each check"
    );
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    assert_eq!(
        done(prep(&mut a, ALICE, &p.token_using_pin(PIN, 0x03, Some(RP))))[0],
        status::PIN_AUTH_BLOCKED,
        "until restart"
    );

    // A new broker (power cycle) allows the correct PIN, which restores the retries.
    let mut fresh = Authenticator::new(std::mem::take(a.tpm_mut()));
    let p = Platform::new(&mut fresh, ALICE, Protocol::Two);
    assert_eq!(
        done(prep(
            &mut fresh,
            ALICE,
            &p.token_using_pin(PIN, 0x03, Some(RP))
        ))[0],
        status::OK
    );
    assert_eq!(fresh.tpm_mut().retries[&ALICE.0], 8);

    // At zero retries the PIN is blocked, and so is built-in UV.
    fresh.tpm_mut().retries.insert(ALICE.0, 0);
    let p = Platform::new(&mut fresh, ALICE, Protocol::Two);
    assert_eq!(
        done(prep(
            &mut fresh,
            ALICE,
            &p.token_using_pin(PIN, 0x03, Some(RP))
        ))[0],
        status::PIN_BLOCKED
    );
    assert_eq!(
        done(prep(&mut fresh, ALICE, &p.token_using_uv(0x03, RP)))[0],
        status::PIN_BLOCKED
    );
}

#[test]
fn pin_retries_survive_a_check_the_tpm_never_ran() {
    // HARD-03: a TPM-wide DA lockout (maybe caused by another user) or a TPM failure
    // means the PIN was never compared, so this user's retry must not be burnt.
    for (error, code) in [
        (TpmError::Lockout, status::PIN_AUTH_BLOCKED),
        (TpmError::Unavailable, status::OTHER),
    ] {
        let mut a = auth();
        set_pin(&mut a, ALICE, Protocol::Two);
        a.tpm_mut().retries.insert(ALICE.0, 3);
        a.tpm_mut().verify_error = Some(error);
        let p = Platform::new(&mut a, ALICE, Protocol::Two);
        assert_eq!(
            done(prep(&mut a, ALICE, &p.token_using_pin(PIN, 0x03, Some(RP))))[0],
            code,
            "{error:?} via getPinUvAuthTokenUsingPin"
        );
        assert_eq!(a.tpm_mut().retries[&ALICE.0], 3, "{error:?}: token");
        let p = Platform::new(&mut a, ALICE, Protocol::Two);
        assert_eq!(
            done(prep(&mut a, ALICE, &p.change_pin(PIN, b"654321")))[0],
            code,
            "{error:?} via changePIN"
        );
        assert_eq!(a.tpm_mut().retries[&ALICE.0], 3, "{error:?}: changePIN");

        // Once the TPM answers again, a wrong PIN still costs a retry.
        a.tpm_mut().verify_error = None;
        let p = Platform::new(&mut a, ALICE, Protocol::Two);
        assert_eq!(
            done(prep(
                &mut a,
                ALICE,
                &p.token_using_pin(b"000000", 0x03, Some(RP))
            ))[0],
            status::PIN_INVALID
        );
        assert_eq!(a.tpm_mut().retries[&ALICE.0], 2, "{error:?}: wrong PIN");
    }
}

#[test]
fn change_pin_invalidates_the_token() {
    let mut a = auth();
    set_pin(&mut a, ALICE, Protocol::Two);
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    let token = p.decrypt_token(&done(prep(
        &mut a,
        ALICE,
        &p.token_using_pin(PIN, 0x03, Some(RP)),
    )));
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    assert_eq!(
        done(prep(&mut a, ALICE, &p.change_pin(PIN, b"654321"))),
        vec![status::OK]
    );
    let param = p.auth_param(&token, &[9; 32]);
    let mc = req(
        cmd::MAKE_CREDENTIAL,
        mc_params(vec![(int(8), param), (int(9), Value::Uint(2))]),
    );
    assert_eq!(
        done(prep(&mut a, ALICE, &mc)),
        vec![status::PIN_AUTH_INVALID]
    );
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    assert_eq!(
        done(prep(
            &mut a,
            ALICE,
            &p.token_using_pin(b"654321", 0x03, Some(RP))
        ))[0],
        status::OK
    );
}

#[test]
fn failed_fingerprints_block_the_gesture_path() {
    // HARD-04: the uvRetries limit applies to makeCredential/getAssertion too, not only to
    // getPinUvAuthTokenUsingUv.
    let mut a = auth();
    let id = register(&mut a, vec![]);
    let mc = req(cmd::MAKE_CREDENTIAL, mc_params(vec![]));
    let ga = req(
        cmd::GET_ASSERTION,
        ga_params(Some(vec![descriptor(&id)]), vec![]),
    );
    for i in 0..MAX_UV_RETRIES {
        let request = if i % 2 == 0 { &mc } else { &ga };
        let p = need_uv(prep(&mut a, ALICE, request));
        assert_eq!(
            a.complete(p, UvOutcome::NoMatch, 1_000),
            vec![status::OPERATION_DENIED]
        );
    }
    assert_eq!(done(prep(&mut a, ALICE, &mc)), vec![status::UV_BLOCKED]);
    assert_eq!(done(prep(&mut a, ALICE, &ga)), vec![status::UV_BLOCKED]);
    let touch_select = req(
        cmd::MAKE_CREDENTIAL,
        mc_params(vec![
            (int(8), Value::Bytes(Vec::new())),
            (int(9), Value::Uint(2)),
        ]),
    );
    assert_eq!(
        done(prep(&mut a, ALICE, &touch_select)),
        vec![status::UV_BLOCKED]
    );
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    assert_eq!(
        done(prep(&mut a, ALICE, &p.token_using_uv(0x03, RP))),
        vec![status::UV_BLOCKED]
    );

    // The PIN stays a fallback: its UV is not the fingerprint's, only presence is asked.
    set_pin(&mut a, ALICE, Protocol::Two);
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    let token = p.decrypt_token(&done(prep(
        &mut a,
        ALICE,
        &p.token_using_pin(PIN, 0x03, Some(RP)),
    )));
    let with_pin = req(
        cmd::MAKE_CREDENTIAL,
        mc_params(vec![
            (int(8), p.auth_param(&token, &[9; 32])),
            (int(9), Value::Uint(2)),
        ]),
    );
    let step = prep(&mut a, ALICE, &with_pin);
    let resp = body(&touch(&mut a, ALICE, step));
    assert_eq!(get(&resp, 1), Some(&text("packed")));
    // That match ended the run of failures.
    assert!(matches!(prep(&mut a, ALICE, &ga), Step::NeedUv(_)));
}

#[test]
fn blocked_pin_blocks_the_gesture_path() {
    // AD-010: at 0 PIN retries built-in UV is disabled everywhere until reset.
    let mut a = auth();
    let id = register(&mut a, vec![]);
    set_pin(&mut a, ALICE, Protocol::Two);
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    let token = p.decrypt_token(&done(prep(
        &mut a,
        ALICE,
        &p.token_using_pin(PIN, 0x03, Some(RP)),
    )));
    a.tpm_mut().retries.insert(ALICE.0, 0);
    let mc = req(cmd::MAKE_CREDENTIAL, mc_params(vec![]));
    let ga = req(
        cmd::GET_ASSERTION,
        ga_params(Some(vec![descriptor(&id)]), vec![]),
    );
    assert_eq!(done(prep(&mut a, ALICE, &mc)), vec![status::PIN_BLOCKED]);
    assert_eq!(done(prep(&mut a, ALICE, &ga)), vec![status::PIN_BLOCKED]);
    let with_token = req(
        cmd::MAKE_CREDENTIAL,
        mc_params(vec![
            (int(8), p.auth_param(&token, &[9; 32])),
            (int(9), Value::Uint(2)),
        ]),
    );
    assert_eq!(
        done(prep(&mut a, ALICE, &with_token)),
        vec![status::PIN_BLOCKED],
        "a token issued before the block can't be completed with a fingerprint either"
    );
    assert!(
        matches!(prep(&mut a, BOB, &mc), Step::NeedUv(_)),
        "per user"
    );
}

#[test]
fn token_is_bound_to_its_rp_and_permissions_and_user() {
    let mut a = auth();
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    let step = prep(&mut a, ALICE, &p.token_using_uv(0x02, RP));
    let token = p.decrypt_token(&touch(&mut a, ALICE, step));
    let param = p.auth_param(&token, &[9; 32]);
    let mc = req(
        cmd::MAKE_CREDENTIAL,
        mc_params(vec![(int(8), param), (int(9), Value::Uint(2))]),
    );
    assert_eq!(
        done(prep(&mut a, ALICE, &mc)),
        vec![status::PIN_AUTH_INVALID],
        "ga-only token can't register"
    );
    assert_eq!(
        done(prep(&mut a, BOB, &mc)),
        vec![status::PIN_AUTH_INVALID],
        "other user's token"
    );
    let param_ga = p.auth_param(&token, &[8; 32]);
    let other_rp = req(
        cmd::GET_ASSERTION,
        vec![
            (int(1), text("evil.example")),
            (int(2), Value::Bytes(vec![8; 32])),
            (int(6), param_ga),
            (int(7), Value::Uint(2)),
        ],
    );
    assert_eq!(
        done(prep(&mut a, ALICE, &other_rp)),
        vec![status::PIN_AUTH_INVALID],
        "bound to example.com"
    );
}

#[test]
fn pin_policy_and_zero_length_auth() {
    let mut a = auth();
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    assert_eq!(
        done(prep(&mut a, ALICE, &p.set_pin(b"123"))),
        vec![status::PIN_POLICY_VIOLATION]
    );
    let mc = req(
        cmd::MAKE_CREDENTIAL,
        mc_params(vec![
            (int(8), Value::Bytes(vec![])),
            (int(9), Value::Uint(2)),
        ]),
    );
    let step = prep(&mut a, ALICE, &mc);
    assert_eq!(touch(&mut a, ALICE, step), vec![status::PIN_NOT_SET]);
    set_pin(&mut a, ALICE, Protocol::Two);
    let step = prep(&mut a, ALICE, &mc);
    assert_eq!(touch(&mut a, ALICE, step), vec![status::PIN_INVALID]);
    let retries = body(&done(prep(
        &mut a,
        ALICE,
        &req(
            cmd::CLIENT_PIN,
            vec![(int(1), Value::Uint(2)), (int(2), Value::Uint(1))],
        ),
    )));
    assert_eq!(get(&retries, 3), Some(&Value::Uint(8)));
}

// ---------------------------------------------------------------- discoverable + extensions

#[test]
fn discoverable_credentials_multiple_accounts_and_next_assertion() {
    let mut a = auth();
    let rk = (int(7), Value::Map(vec![(text("rk"), Value::Bool(true))]));
    let first = register(&mut a, vec![rk.clone()]);
    let mut params = mc_params(vec![rk]);
    params[2] = (
        int(3),
        Value::Map(vec![
            (text("id"), Value::Bytes(vec![8; 16])),
            (text("name"), text("bob")),
        ]),
    );
    let step = prep(&mut a, ALICE, &req(cmd::MAKE_CREDENTIAL, params));
    let resp = body(&touch(&mut a, ALICE, step));
    let second = cred_id_from_auth_data(get(&resp, 2).and_then(Value::as_bytes).unwrap());
    assert_eq!(a.tpm_mut().resident[&ALICE.0].len(), 2);

    let step = prep(
        &mut a,
        ALICE,
        &req(cmd::GET_ASSERTION, ga_params(None, vec![])),
    );
    let resp = body(&touch(&mut a, ALICE, step));
    assert_eq!(get(&resp, 5), Some(&Value::Uint(2)), "numberOfCredentials");
    assert!(get_text(get(&resp, 4).unwrap(), "id").is_some());
    let mut all = vec![get_text(get(&resp, 1).unwrap(), "id").unwrap().clone()];
    let next = body(&done(prep(&mut a, ALICE, &[cmd::GET_NEXT_ASSERTION])));
    all.push(get_text(get(&next, 1).unwrap(), "id").unwrap().clone());
    assert!(all.contains(&Value::Bytes(first)) && all.contains(&Value::Bytes(second)));
    assert_eq!(
        done(prep(&mut a, ALICE, &[cmd::GET_NEXT_ASSERTION])),
        vec![status::NOT_ALLOWED],
        "exhausted"
    );

    let step = prep(
        &mut a,
        BOB,
        &req(cmd::GET_ASSERTION, ga_params(None, vec![])),
    );
    assert_eq!(
        touch(&mut a, BOB, step),
        vec![status::NO_CREDENTIALS],
        "another user sees nothing"
    );
}

#[test]
fn same_user_and_rp_replaces_the_discoverable_credential() {
    let mut a = auth();
    let rk = (int(7), Value::Map(vec![(text("rk"), Value::Bool(true))]));
    register(&mut a, vec![rk.clone()]);
    let second = register(&mut a, vec![rk]);
    let entries = &a.tpm_mut().resident[&ALICE.0];
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].credential_id, second);
}

/// The applied `credProtect` level from a makeCredential response, or `None` when the
/// authenticator emitted no extension output. Assumes the mock's fixed public key.
fn cred_protect_echo(resp: &Value) -> Option<u64> {
    let auth_data = get(resp, 2).and_then(Value::as_bytes)?;
    if auth_data[32] & 0x80 == 0 {
        return None;
    }
    let id = cred_id_from_auth_data(auth_data);
    let cose_len = cbor::encode(&super::common::cose_es256([0xaa; 32], [0xbb; 32])).len();
    let ext = cbor::decode(&auth_data[55 + id.len() + cose_len..]).ok()?;
    get_text(&ext, "credProtect").and_then(Value::as_uint)
}

/// CTAP 2.1 §6.1.3: the RP may request 1 or 2, but this authenticator upgrades every
/// credential to level 3 and must report the level it actually applied, not the request.
#[test]
fn cred_protect_upgrades_every_requested_level_to_three() {
    for level in 1..=3u64 {
        let mut a = auth();
        let ext = Value::Map(vec![
            (text("credProtect"), Value::Uint(level)),
            (text("enforceCredentialProtectionPolicy"), Value::Bool(true)),
        ]);
        let step = prep(
            &mut a,
            ALICE,
            &req(cmd::MAKE_CREDENTIAL, mc_params(vec![(int(6), ext)])),
        );
        let resp = body(&touch(&mut a, ALICE, step));
        assert_eq!(
            cred_protect_echo(&resp),
            Some(3),
            "requested level {level} must report the applied level"
        );
        assert_eq!(a.tpm_mut().created, 1, "exactly one credential at level 3");
    }
}

#[test]
fn enforce_credential_protection_policy_needs_a_policy() {
    let mut a = auth();
    let ext = Value::Map(vec![(
        text("enforceCredentialProtectionPolicy"),
        Value::Bool(true),
    )]);
    assert_eq!(
        done(prep(
            &mut a,
            ALICE,
            &req(cmd::MAKE_CREDENTIAL, mc_params(vec![(int(6), ext)])),
        )),
        vec![status::INVALID_OPTION],
        "enforce=true without credProtect names nothing to enforce"
    );
    assert_eq!(a.tpm_mut().created, 0);

    // `false` may stand alone and is a no-op; `true` with a policy is honorable at level 3.
    for enforce in [false, true] {
        let mut a = auth();
        let mut ext = vec![(
            text("enforceCredentialProtectionPolicy"),
            Value::Bool(enforce),
        )];
        if enforce {
            ext.push((text("credProtect"), Value::Uint(1)));
        }
        let step = prep(
            &mut a,
            ALICE,
            &req(
                cmd::MAKE_CREDENTIAL,
                mc_params(vec![(int(6), Value::Map(ext))]),
            ),
        );
        let resp = body(&touch(&mut a, ALICE, step));
        assert_eq!(
            cred_protect_echo(&resp),
            enforce.then_some(3),
            "enforce={enforce}"
        );
    }
}

#[test]
fn cred_protect_extension_types_and_levels_are_validated() {
    for level in [0u64, 4] {
        let mut a = auth();
        let ext = Value::Map(vec![(text("credProtect"), Value::Uint(level))]);
        assert_eq!(
            done(prep(
                &mut a,
                ALICE,
                &req(cmd::MAKE_CREDENTIAL, mc_params(vec![(int(6), ext)])),
            )),
            vec![status::INVALID_OPTION],
            "credProtect {level} is out of range"
        );
    }
    for ext in [
        Value::Map(vec![(text("credProtect"), text("3"))]),
        Value::Map(vec![
            (text("credProtect"), Value::Uint(1)),
            (text("enforceCredentialProtectionPolicy"), Value::Uint(1)),
        ]),
    ] {
        let mut a = auth();
        assert_eq!(
            done(prep(
                &mut a,
                ALICE,
                &req(cmd::MAKE_CREDENTIAL, mc_params(vec![(int(6), ext)])),
            )),
            vec![status::CBOR_UNEXPECTED_TYPE]
        );
    }
}

/// A credential created under `credProtect` can never be exercised with presence alone:
/// without a fingerprint and without a PIN there is no UV, so there is no signature.
#[test]
fn cred_protect_credential_is_never_used_without_uv() {
    let mut a = auth();
    let ext = Value::Map(vec![
        (text("credProtect"), Value::Uint(1)),
        (text("enforceCredentialProtectionPolicy"), Value::Bool(true)),
    ]);
    let id = register(&mut a, vec![(int(6), ext)]);
    let signed_before = a.tpm_mut().signed.len();
    let ga = req(
        cmd::GET_ASSERTION,
        ga_params(Some(vec![descriptor(&id)]), vec![]),
    );

    // No reader and no PIN: UV is impossible, so the request is refused outright.
    assert_eq!(
        done(a.prepare(ALICE, NO_READER, &ga, 1_000)),
        vec![status::NOT_ALLOWED]
    );
    // A silent probe never degrades into a presence-only signature either.
    let silent = req(
        cmd::GET_ASSERTION,
        ga_params(
            Some(vec![descriptor(&id)]),
            vec![(int(5), Value::Map(vec![(text("up"), Value::Bool(false))]))],
        ),
    );
    assert_eq!(
        done(prep(&mut a, ALICE, &silent)),
        vec![status::UNSUPPORTED_OPTION]
    );
    assert_eq!(
        a.tpm_mut().signed.len(),
        signed_before,
        "nothing signed without UV"
    );

    // With a fingerprint the signature goes through the UV gate, never UP.
    let step = prep(&mut a, ALICE, &ga);
    body(&touch(&mut a, ALICE, step));
    assert_eq!(
        a.tpm_mut().signed.last().map(|signed| signed.1),
        Some(GateKind::Uv)
    );
}

#[test]
fn hmac_secret_round_trip_and_cred_protect_echo() {
    let mut a = auth();
    let ext = Value::Map(vec![
        (text("hmac-secret"), Value::Bool(true)),
        (text("credProtect"), Value::Uint(1)),
    ]);
    let step = prep(
        &mut a,
        ALICE,
        &req(cmd::MAKE_CREDENTIAL, mc_params(vec![(int(6), ext)])),
    );
    let resp = body(&touch(&mut a, ALICE, step));
    let auth_data = get(&resp, 2).and_then(Value::as_bytes).unwrap().to_vec();
    assert_eq!(auth_data[32] & 0x80, 0x80, "ED flag");
    let id = cred_id_from_auth_data(&auth_data);
    let cose_len = cbor::encode(&super::common::cose_es256([0xaa; 32], [0xbb; 32])).len();
    let ext_out = cbor::decode(&auth_data[55 + id.len() + cose_len..]).unwrap();
    assert_eq!(get_text(&ext_out, "hmac-secret"), Some(&Value::Bool(true)));
    assert_eq!(
        get_text(&ext_out, "credProtect"),
        Some(&Value::Uint(3)),
        "applied level echoed"
    );

    for protocol in [Protocol::One, Protocol::Two] {
        let p = Platform::new(&mut a, ALICE, protocol);
        let salts = [[1u8; 32], [2u8; 32]].concat();
        let salt_enc = p.shared.encrypt(&salts).unwrap();
        let hmac_in = Value::Map(vec![
            (int(1), p.key.cose_public()),
            (int(2), Value::Bytes(salt_enc.clone())),
            (int(3), Value::Bytes(p.shared.authenticate(&salt_enc))),
            (int(4), Value::Uint(protocol.as_u64())),
        ]);
        let ga = req(
            cmd::GET_ASSERTION,
            ga_params(
                Some(vec![descriptor(&id)]),
                vec![(int(4), Value::Map(vec![(text("hmac-secret"), hmac_in)]))],
            ),
        );
        let step = prep(&mut a, ALICE, &ga);
        let resp = body(&touch(&mut a, ALICE, step));
        let auth_data = get(&resp, 2).and_then(Value::as_bytes).unwrap();
        let out = cbor::decode(&auth_data[37..]).unwrap();
        let enc = get_text(&out, "hmac-secret")
            .and_then(Value::as_bytes)
            .unwrap();
        let plain = p.shared.decrypt(enc).unwrap();
        let private = &id[36..40];
        assert_eq!(&plain[..32], &sha256(&[private, &[1u8; 32]]));
        assert_eq!(&plain[32..], &sha256(&[private, &[2u8; 32]]));
    }

    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    let salt_enc = p.shared.encrypt(&[1u8; 32]).unwrap();
    let bad = Value::Map(vec![
        (int(1), p.key.cose_public()),
        (int(2), Value::Bytes(salt_enc)),
        (int(3), Value::Bytes(vec![0; 32])),
        (int(4), Value::Uint(2)),
    ]);
    let ga = req(
        cmd::GET_ASSERTION,
        ga_params(
            Some(vec![descriptor(&id)]),
            vec![(int(4), Value::Map(vec![(text("hmac-secret"), bad)]))],
        ),
    );
    assert_eq!(
        done(prep(&mut a, ALICE, &ga)),
        vec![status::PIN_AUTH_INVALID],
        "bad saltAuth"
    );
}

#[test]
fn hmac_secret_outputs_are_zeroized_on_drop() {
    use super::state::{Found, HmacRequest};
    use zeroize::Zeroizing;
    type Output = Result<Zeroizing<Vec<u8>>, u8>;
    let _: fn(&mut A, Uid, &RpIdHash, &Found, &UvEvidence, &HmacRequest) -> Output =
        A::hmac_secret_output;
}

#[test]
fn hmac_secret_for_a_credential_without_it_is_omitted() {
    let mut a = auth();
    let id = register(&mut a, Vec::new());
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    let salt_enc = p.shared.encrypt(&[1u8; 32]).unwrap();
    let hmac_in = Value::Map(vec![
        (int(1), p.key.cose_public()),
        (int(2), Value::Bytes(salt_enc.clone())),
        (int(3), Value::Bytes(p.shared.authenticate(&salt_enc))),
        (int(4), Value::Uint(2)),
    ]);
    let ga = req(
        cmd::GET_ASSERTION,
        ga_params(
            Some(vec![descriptor(&id)]),
            vec![(int(4), Value::Map(vec![(text("hmac-secret"), hmac_in)]))],
        ),
    );
    let step = prep(&mut a, ALICE, &ga);
    let resp = body(&touch(&mut a, ALICE, step));
    let auth_data = get(&resp, 2).and_then(Value::as_bytes).unwrap();
    assert_eq!(auth_data[32] & 0x80, 0, "no ED flag");
    assert_eq!(auth_data.len(), 37, "no extension output");
}

/// Builds a valid `hmac-secret` extension input encrypted to this authenticator.
fn hmac_secret_input(p: &Platform, salts: &[u8]) -> Value {
    let salt_enc = p.shared.encrypt(salts).unwrap();
    Value::Map(vec![
        (int(1), p.key.cose_public()),
        (int(2), Value::Bytes(salt_enc.clone())),
        (int(3), Value::Bytes(p.shared.authenticate(&salt_enc))),
        (int(4), Value::Uint(p.protocol.as_u64())),
    ])
}

/// Removes one member from a well-formed `hmac-secret` input.
fn hmac_secret_input_without(p: &Platform, salts: &[u8], drop: u64) -> Value {
    let Value::Map(mut map) = hmac_secret_input(p, salts) else {
        unreachable!()
    };
    map.retain(|(k, _)| k.as_uint() != Some(drop));
    Value::Map(map)
}

/// Replaces one member of a well-formed `hmac-secret` input.
fn hmac_secret_input_with(p: &Platform, salts: &[u8], key: u64, value: Value) -> Value {
    let Value::Map(mut map) = hmac_secret_input(p, salts) else {
        unreachable!()
    };
    for (k, v) in &mut map {
        if k.as_uint() == Some(key) {
            *v = value.clone();
        }
    }
    Value::Map(map)
}

fn hmac_assertion(id: &[u8], input: Value) -> Vec<u8> {
    req(
        cmd::GET_ASSERTION,
        ga_params(
            Some(vec![descriptor(id)]),
            vec![(int(4), Value::Map(vec![(text("hmac-secret"), input)]))],
        ),
    )
}

/// Decodes the authenticator-data extension map from a makeCredential response.
fn credential_extensions(resp: &Value) -> Option<Value> {
    let auth_data = get(resp, 2).and_then(Value::as_bytes)?;
    if auth_data[32] & 0x80 == 0 {
        return None;
    }
    let id = cred_id_from_auth_data(auth_data);
    let cose_len = cbor::encode(&super::common::cose_es256([0xaa; 32], [0xbb; 32])).len();
    cbor::decode(&auth_data[55 + id.len() + cose_len..]).ok()
}

#[test]
fn hmac_secret_is_advertised_but_prf_is_not() {
    let mut a = auth();
    let info = body(&done(prep(&mut a, ALICE, &[cmd::GET_INFO])));
    let extensions = get(&info, 2).and_then(Value::as_array).unwrap();
    assert!(extensions.contains(&text("hmac-secret")));
    // PRF-adjacent behavior is only implemented through hmac-secret; advertising `prf`
    // would promise the WebAuthn PRF extension, which has no CTAP wiring here.
    assert!(!extensions.iter().any(|e| e.as_text() == Some("prf")));
}

#[test]
fn make_credential_hmac_secret_false_or_absent_omits_the_extension() {
    let mut a = auth();

    for ext in [Value::Bool(false), Value::Bool(true)] {
        let step = prep(
            &mut a,
            ALICE,
            &req(
                cmd::MAKE_CREDENTIAL,
                mc_params(vec![(
                    int(6),
                    Value::Map(vec![(text("hmac-secret"), ext.clone())]),
                )]),
            ),
        );
        let resp = body(&touch(&mut a, ALICE, step));
        let out = credential_extensions(&resp);
        let expected = ext.as_bool().unwrap();
        assert_eq!(
            out.as_ref().and_then(|o| get_text(o, "hmac-secret")),
            expected.then_some(&Value::Bool(true)),
            "hmac-secret: {expected}"
        );
    }

    // An absent extension means "no hmac-secret key", so no output is returned either.
    let step = prep(&mut a, ALICE, &req(cmd::MAKE_CREDENTIAL, mc_params(vec![])));
    let resp = body(&touch(&mut a, ALICE, step));
    assert!(credential_extensions(&resp).is_none());

    // The extension member must be a boolean, not a truthy string or number.
    let step = prep(
        &mut a,
        ALICE,
        &req(
            cmd::MAKE_CREDENTIAL,
            mc_params(vec![(
                int(6),
                Value::Map(vec![(text("hmac-secret"), text("true"))]),
            )]),
        ),
    );
    assert_eq!(
        done(step),
        vec![status::CBOR_UNEXPECTED_TYPE],
        "non-boolean hmac-secret is a CBOR type error"
    );
}

#[test]
fn hmac_secret_rejects_malformed_inputs_with_specific_statuses() {
    let mut a = auth();
    let id = register(
        &mut a,
        vec![(
            int(6),
            Value::Map(vec![(text("hmac-secret"), Value::Bool(true))]),
        )],
    );
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    let salt = [7u8; 32];

    let cases = [
        (
            hmac_secret_input_without(&p, &salt, 1),
            status::MISSING_PARAMETER,
            "missing platform key",
        ),
        (
            hmac_secret_input_without(&p, &salt, 2),
            status::MISSING_PARAMETER,
            "missing saltEnc",
        ),
        (
            hmac_secret_input_without(&p, &salt, 3),
            status::MISSING_PARAMETER,
            "missing saltAuth",
        ),
        (
            hmac_secret_input_with(&p, &salt, 1, text("not-a-cose-key")),
            status::INVALID_PARAMETER,
            "malformed platform key",
        ),
        (
            hmac_secret_input_with(&p, &salt, 4, Value::Uint(3)),
            status::INVALID_PARAMETER,
            "unsupported PIN/UV auth protocol",
        ),
        (
            hmac_secret_input(&p, &[0u8; 16]),
            status::INVALID_LENGTH,
            "16-byte plaintext is neither one nor two salts",
        ),
        (
            hmac_secret_input(&p, &[0u8; 48]),
            status::INVALID_LENGTH,
            "48-byte plaintext is neither one nor two salts",
        ),
    ];

    for (input, expected, label) in cases {
        assert_eq!(
            done(prep(&mut a, ALICE, &hmac_assertion(&id, input))),
            vec![expected],
            "{label}"
        );
    }
}

#[test]
fn hmac_secret_single_salt_is_deterministic_and_stays_encrypted() {
    let mut a = auth();
    let id = register(
        &mut a,
        vec![(
            int(6),
            Value::Map(vec![(text("hmac-secret"), Value::Bool(true))]),
        )],
    );
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    let salt = [3u8; 32];
    let private = &id[36..40];
    let expected = sha256(&[private, &salt]);

    let mut outputs = Vec::new();
    for _ in 0..2 {
        let step = prep(
            &mut a,
            ALICE,
            &hmac_assertion(&id, hmac_secret_input(&p, &salt)),
        );
        let resp = body(&touch(&mut a, ALICE, step));
        let auth_data = get(&resp, 2).and_then(Value::as_bytes).unwrap();
        let out = cbor::decode(&auth_data[37..]).unwrap();
        let encrypted = get_text(&out, "hmac-secret")
            .and_then(Value::as_bytes)
            .unwrap();
        assert_ne!(
            encrypted,
            expected.as_slice(),
            "the raw output must never appear in the response"
        );
        let plain = p.shared.decrypt(encrypted).unwrap();
        assert_eq!(plain.len(), 32, "one salt yields one 32-byte output");
        assert_eq!(&plain[..], &expected);
        outputs.push(plain);
    }
    assert_eq!(outputs[0], outputs[1], "same salt, same output");

    // Omitting pinUvAuthProtocol defaults to protocol one (CTAP 2.1 §12.5).
    let p1 = Platform::new(&mut a, ALICE, Protocol::One);
    let salts = [[4u8; 32], [5u8; 32]].concat();
    let input = hmac_secret_input_without(&p1, &salts, 4);
    let step = prep(&mut a, ALICE, &hmac_assertion(&id, input));
    let resp = body(&touch(&mut a, ALICE, step));
    let auth_data = get(&resp, 2).and_then(Value::as_bytes).unwrap();
    let out = cbor::decode(&auth_data[37..]).unwrap();
    let encrypted = get_text(&out, "hmac-secret")
        .and_then(Value::as_bytes)
        .unwrap();
    let plain = p1.shared.decrypt(encrypted).unwrap();
    assert_eq!(&plain[..32], &sha256(&[private, &[4u8; 32]]), "salt 1");
    assert_eq!(&plain[32..], &sha256(&[private, &[5u8; 32]]), "salt 2");
}

#[test]
fn hmac_secret_applies_only_to_the_first_assertion() {
    let mut a = auth();
    let rk = (int(7), Value::Map(vec![(text("rk"), Value::Bool(true))]));
    let hmac = (
        int(6),
        Value::Map(vec![(text("hmac-secret"), Value::Bool(true))]),
    );
    register(&mut a, vec![rk.clone(), hmac.clone()]);
    let mut params = mc_params(vec![rk, hmac]);
    params[2] = (
        int(3),
        Value::Map(vec![
            (text("id"), Value::Bytes(vec![8; 16])),
            (text("name"), text("bob")),
        ]),
    );
    let step = prep(&mut a, ALICE, &req(cmd::MAKE_CREDENTIAL, params));
    let second = body(&touch(&mut a, ALICE, step));
    assert!(
        credential_extensions(&second).is_some(),
        "second cred has hmac"
    );

    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    let step = prep(
        &mut a,
        ALICE,
        &req(
            cmd::GET_ASSERTION,
            ga_params(
                None,
                vec![(
                    int(4),
                    Value::Map(vec![(
                        text("hmac-secret"),
                        hmac_secret_input(&p, &[6u8; 32]),
                    )]),
                )],
            ),
        ),
    );
    let resp = body(&touch(&mut a, ALICE, step));
    assert_eq!(get(&resp, 5), Some(&Value::Uint(2)), "two accounts");
    let auth_data = get(&resp, 2).and_then(Value::as_bytes).unwrap();
    assert_eq!(auth_data[32] & 0x80, 0x80, "first assertion has extensions");

    // CTAP 2.1 §6.3: the remaining assertions reuse the verification but carry no hmac-secret.
    let next = body(&done(prep(&mut a, ALICE, &[cmd::GET_NEXT_ASSERTION])));
    let auth_data = get(&next, 2).and_then(Value::as_bytes).unwrap();
    assert_eq!(auth_data[32] & 0x80, 0, "no ED flag on getNextAssertion");
    assert_eq!(
        auth_data.len(),
        37,
        "no extension output on getNextAssertion"
    );
}

// ---------------------------------------------------------------- credMgmt, reset, selection

fn cm_token(a: &mut A, p: &Platform) -> [u8; 32] {
    p.decrypt_token(&done(prep(a, ALICE, &p.token_using_pin(PIN, 0x04, None))))
}

fn cm(p: &Platform, token: &[u8; 32], sub: u8, params: Option<Value>) -> Vec<u8> {
    let mut msg = vec![sub];
    if let Some(sp) = &params {
        msg.extend_from_slice(&cbor::encode(sp));
    }
    let mut m = vec![(int(1), Value::Uint(u64::from(sub)))];
    if let Some(sp) = params {
        m.push((int(2), sp));
    }
    m.push((int(3), Value::Uint(p.protocol.as_u64())));
    m.push((int(4), p.auth_param(token, &msg)));
    req(cmd::CREDENTIAL_MANAGEMENT, m)
}

#[test]
fn credential_management_enumerate_update_delete() {
    let mut a = auth();
    let rk = (int(7), Value::Map(vec![(text("rk"), Value::Bool(true))]));
    let id = register(&mut a, vec![rk]);
    set_pin(&mut a, ALICE, Protocol::Two);
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    let token = cm_token(&mut a, &p);

    let meta = body(&done(prep(&mut a, ALICE, &cm(&p, &token, 1, None))));
    assert_eq!(get(&meta, 1), Some(&Value::Uint(1)));
    let rps = body(&done(prep(&mut a, ALICE, &cm(&p, &token, 2, None))));
    assert_eq!(get_text(get(&rps, 3).unwrap(), "id"), Some(&text(RP)));
    assert_eq!(get(&rps, 5), Some(&Value::Uint(1)));
    let scope = Value::Map(vec![(
        int(1),
        Value::Bytes(sha256(&[RP.as_bytes()]).to_vec()),
    )]);
    let creds = body(&done(prep(&mut a, ALICE, &cm(&p, &token, 4, Some(scope)))));
    assert_eq!(
        get_text(get(&creds, 7).unwrap(), "id"),
        Some(&Value::Bytes(id.clone()))
    );
    assert_eq!(get(&creds, 0x0A), Some(&Value::Uint(3)));

    let update = Value::Map(vec![
        (int(2), descriptor(&id)),
        (
            int(3),
            Value::Map(vec![
                (text("id"), Value::Bytes(vec![7; 16])),
                (text("name"), text("alice2")),
            ]),
        ),
    ]);
    assert_eq!(
        done(prep(&mut a, ALICE, &cm(&p, &token, 7, Some(update)))),
        vec![status::OK]
    );
    assert_eq!(a.tpm_mut().resident[&ALICE.0][0].user_name, "alice2");

    let delete = Value::Map(vec![(int(2), descriptor(&id))]);
    assert_eq!(
        done(prep(
            &mut a,
            ALICE,
            &cm(&p, &token, 6, Some(delete.clone()))
        )),
        vec![status::OK]
    );
    assert!(a.tpm_mut().resident[&ALICE.0].is_empty());
    assert_eq!(
        done(prep(&mut a, ALICE, &cm(&p, &token, 6, Some(delete)))),
        vec![status::NO_CREDENTIALS]
    );

    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    let ga_token = p.decrypt_token(&done(prep(
        &mut a,
        ALICE,
        &p.token_using_pin(PIN, 0x02, Some(RP)),
    )));
    assert_eq!(
        done(prep(&mut a, ALICE, &cm(&p, &ga_token, 1, None))),
        vec![status::PIN_AUTH_INVALID],
        "no cm permission"
    );
}

#[test]
fn rp_bound_cm_token_manages_only_that_rps_credentials() {
    let mut a = auth();
    let rk = (int(7), Value::Map(vec![(text("rk"), Value::Bool(true))]));
    let id = register(&mut a, vec![rk.clone()]);
    let mut other = mc_params(vec![rk]);
    other[1] = (
        int(2),
        Value::Map(vec![(text("id"), text("other.example"))]),
    );
    let step = prep(&mut a, ALICE, &req(cmd::MAKE_CREDENTIAL, other));
    let other_id = cred_id_from_auth_data(
        get(&body(&touch(&mut a, ALICE, step)), 2)
            .and_then(Value::as_bytes)
            .unwrap(),
    );
    set_pin(&mut a, ALICE, Protocol::Two);
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    let token = p.decrypt_token(&done(prep(
        &mut a,
        ALICE,
        &p.token_using_pin(PIN, 0x04, Some(RP)),
    )));
    let del = |id: &[u8]| Value::Map(vec![(int(2), descriptor(id))]);
    assert_eq!(
        done(prep(
            &mut a,
            ALICE,
            &cm(&p, &token, 6, Some(del(&other_id)))
        )),
        vec![status::PIN_AUTH_INVALID],
        "other RP"
    );
    assert_eq!(
        done(prep(&mut a, ALICE, &cm(&p, &token, 1, None))),
        vec![status::PIN_AUTH_INVALID],
        "metadata needs an unbound token"
    );
    assert_eq!(
        done(prep(&mut a, ALICE, &cm(&p, &token, 6, Some(del(&id))))),
        vec![status::OK],
        "own RP"
    );
}

#[test]
fn cred_mgmt_checks_the_auth_param_before_looking_up_the_credential() {
    let mut a = auth();
    let rk = (int(7), Value::Map(vec![(text("rk"), Value::Bool(true))]));
    let id = register(&mut a, vec![rk]);
    set_pin(&mut a, ALICE, Protocol::Two);
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    let token = cm_token(&mut a, &p);
    let wrong = [0x55; 32];
    let unknown = vec![9; 41];
    let user = Value::Map(vec![(text("id"), Value::Bytes(vec![7; 16]))]);
    for cred in [&id, &unknown] {
        let delete = Value::Map(vec![(int(2), descriptor(cred))]);
        let update = Value::Map(vec![(int(2), descriptor(cred)), (int(3), user.clone())]);
        for (sub, params) in [(6, delete), (7, update)] {
            assert_eq!(
                done(prep(&mut a, ALICE, &cm(&p, &wrong, sub, Some(params)))),
                vec![status::PIN_AUTH_INVALID],
                "a bad pinUvAuthParam must not reveal whether the credential exists"
            );
        }
    }
    let delete = Value::Map(vec![(int(2), descriptor(&unknown))]);
    assert_eq!(
        done(prep(&mut a, ALICE, &cm(&p, &token, 6, Some(delete)))),
        vec![status::NO_CREDENTIALS],
        "after a valid param the lookup still runs"
    );
}

/// A credMgmt request whose `subCommandParams` are the given raw bytes, MACed over `mac_msg`.
fn cm_raw(p: &Platform, token: &[u8; 32], sub: u8, raw_params: &[u8], mac_msg: &[u8]) -> Vec<u8> {
    let mut r = vec![cmd::CREDENTIAL_MANAGEMENT, 0xA4];
    for part in [int(1), Value::Uint(u64::from(sub)), int(2)] {
        r.extend(cbor::encode(&part));
    }
    r.extend_from_slice(raw_params);
    for part in [
        int(3),
        Value::Uint(p.protocol.as_u64()),
        int(4),
        p.auth_param(token, mac_msg),
    ] {
        r.extend(cbor::encode(&part));
    }
    r
}

#[test]
fn cred_mgmt_macs_the_sub_command_params_as_received() {
    let mut a = auth();
    let rk = (int(7), Value::Map(vec![(text("rk"), Value::Bool(true))]));
    let id = register(&mut a, vec![rk]);
    set_pin(&mut a, ALICE, Protocol::Two);
    let p = Platform::new(&mut a, ALICE, Protocol::Two);
    let token = cm_token(&mut a, &p);
    // {2: {"type": "public-key", "id": id}}: the descriptor keys are out of canonical order.
    let mut raw = vec![0xA1];
    raw.extend(cbor::encode(&int(2)));
    raw.push(0xA2);
    for part in [
        text("type"),
        text("public-key"),
        text("id"),
        Value::Bytes(id.clone()),
    ] {
        raw.extend(cbor::encode(&part));
    }
    let canonical = cbor::encode(&cbor::decode(&raw).unwrap());
    assert_ne!(raw, canonical);

    let mut reencoded = vec![6];
    reencoded.extend_from_slice(&canonical);
    assert_eq!(
        done(prep(
            &mut a,
            ALICE,
            &cm_raw(&p, &token, 6, &raw, &reencoded)
        )),
        vec![status::PIN_AUTH_INVALID],
        "a MAC over a re-encoding is not a MAC over what was sent"
    );
    assert_eq!(a.tpm_mut().resident[&ALICE.0].len(), 1);
    let mut received = vec![6];
    received.extend_from_slice(&raw);
    assert_eq!(
        done(prep(&mut a, ALICE, &cm_raw(&p, &token, 6, &raw, &received))),
        vec![status::OK]
    );
    assert!(a.tpm_mut().resident[&ALICE.0].is_empty());
}

#[test]
fn reset_wipes_only_the_callers_state_and_selection_needs_a_touch() {
    let mut a = auth();
    let id = register(&mut a, vec![]);
    set_pin(&mut a, ALICE, Protocol::Two);
    set_pin(&mut a, BOB, Protocol::Two);
    let step = prep(&mut a, ALICE, &[cmd::RESET]);
    assert_eq!(touch(&mut a, ALICE, step), vec![status::OK]);
    assert_eq!(a.tpm_mut().resets, vec![ALICE.0]);
    assert!(!a.tpm_mut().pins.contains_key(&ALICE.0));
    assert!(a.tpm_mut().pins.contains_key(&BOB.0), "Bob untouched");
    let step = prep(
        &mut a,
        ALICE,
        &req(
            cmd::GET_ASSERTION,
            ga_params(Some(vec![descriptor(&id)]), vec![]),
        ),
    );
    assert_eq!(
        touch(&mut a, ALICE, step),
        vec![status::NO_CREDENTIALS],
        "old credential IDs are dead"
    );
    let step = prep(&mut a, ALICE, &[cmd::SELECTION]);
    assert_eq!(touch(&mut a, ALICE, step), vec![status::OK]);
}

proptest! {
    #[test]
    fn prepare_never_panics(bytes in prop::collection::vec(any::<u8>(), 0..600)) {
        let mut a = auth();
        if let Step::NeedUv(p) = a.prepare(ALICE, ENROLLED, &bytes, 0) {
            let _ = a.complete(p, UvOutcome::Cancelled, 0);
        }
    }

    #[test]
    fn client_pin_and_cred_mgmt_never_panic(sub in 0u8..12, junk in prop::collection::vec(any::<u8>(), 0..200)) {
        let mut a = auth();
        let mut r = vec![cmd::CLIENT_PIN];
        r.extend(cbor::encode(&Value::Map(vec![(int(1), Value::Uint(2)), (int(2), Value::Uint(u64::from(sub))), (int(5), Value::Bytes(junk.clone()))])));
        let _ = a.prepare(ALICE, ENROLLED, &r, 0);
        let mut r = vec![cmd::CREDENTIAL_MANAGEMENT];
        r.extend(cbor::encode(&Value::Map(vec![(int(1), Value::Uint(u64::from(sub))), (int(4), Value::Bytes(junk))])));
        let _ = a.prepare(ALICE, ENROLLED, &r, 0);
    }
}
