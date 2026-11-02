//! Status codes, command bytes and CBOR helpers shared by the CTAP2 commands.

use passkey_tpm_wire::cbor::{self, Value};
use sha2::{Digest as _, Sha256};

use crate::tpm_iface::TpmError;

/// CTAP command bytes (CTAP 2.1 §6).
pub mod cmd {
    pub const MAKE_CREDENTIAL: u8 = 0x01;
    pub const GET_ASSERTION: u8 = 0x02;
    pub const GET_INFO: u8 = 0x04;
    pub const CLIENT_PIN: u8 = 0x06;
    pub const RESET: u8 = 0x07;
    pub const GET_NEXT_ASSERTION: u8 = 0x08;
    pub const CREDENTIAL_MANAGEMENT: u8 = 0x0A;
    pub const SELECTION: u8 = 0x0B;
    /// Pre-release credentialManagement command byte still sent by some platforms.
    pub const CREDENTIAL_MANAGEMENT_PREVIEW: u8 = 0x41;
}

/// CTAP status codes (CTAP 2.1 §8.2).
pub mod status {
    pub const OK: u8 = 0x00;
    pub const INVALID_COMMAND: u8 = 0x01;
    pub const INVALID_PARAMETER: u8 = 0x02;
    pub const INVALID_LENGTH: u8 = 0x03;
    pub const CBOR_UNEXPECTED_TYPE: u8 = 0x11;
    pub const INVALID_CBOR: u8 = 0x12;
    pub const MISSING_PARAMETER: u8 = 0x14;
    pub const LIMIT_EXCEEDED: u8 = 0x15;
    pub const CREDENTIAL_EXCLUDED: u8 = 0x19;
    pub const UNSUPPORTED_ALGORITHM: u8 = 0x26;
    pub const OPERATION_DENIED: u8 = 0x27;
    pub const KEY_STORE_FULL: u8 = 0x28;
    pub const UNSUPPORTED_OPTION: u8 = 0x2B;
    pub const INVALID_OPTION: u8 = 0x2C;
    pub const KEEPALIVE_CANCEL: u8 = 0x2D;
    pub const NO_CREDENTIALS: u8 = 0x2E;
    pub const USER_ACTION_TIMEOUT: u8 = 0x2F;
    pub const NOT_ALLOWED: u8 = 0x30;
    pub const PIN_INVALID: u8 = 0x31;
    pub const PIN_BLOCKED: u8 = 0x32;
    pub const PIN_AUTH_INVALID: u8 = 0x33;
    pub const PIN_AUTH_BLOCKED: u8 = 0x34;
    pub const PIN_NOT_SET: u8 = 0x35;
    pub const PUAT_REQUIRED: u8 = 0x36;
    pub const PIN_POLICY_VIOLATION: u8 = 0x37;
    pub const UV_BLOCKED: u8 = 0x3C;
    pub const INVALID_SUBCOMMAND: u8 = 0x3E;
    pub const UV_INVALID: u8 = 0x3F;
    pub const UNAUTHORIZED_PERMISSION: u8 = 0x40;
    pub const OTHER: u8 = 0x7F;
}

/// AAGUID: all zero (packed self-attestation identifies no model; no tracking ID).
pub const AAGUID: [u8; 16] = [0; 16];
/// Largest CTAP message the HID layer accepts, and the `maxMsgSize` we advertise (0x05).
///
/// Taken from [`crate::ctaphid::MAX_MSG`] so the promise and the enforced limit cannot drift.
pub const MAX_MSG_SIZE: u64 = crate::ctaphid::MAX_MSG as u64;
/// Maximum credential IDs accepted in one list, and `maxCredentialCountInList` (0x07).
pub const MAX_CREDENTIAL_COUNT_IN_LIST: usize = 8;
/// WebAuthn L3 credential-ID cap, shared with the wire format; also `maxCredentialIdLength`
/// (0x08).
pub const MAX_CREDENTIAL_ID_LENGTH: u64 = passkey_tpm_wire::credid::MAX_LEN as u64;
pub const MAX_RESIDENT: usize = 64;
pub const MIN_PIN_LENGTH: usize = 4;
/// COSE algorithm ES256.
pub const ES256: i64 = -7;
/// Consecutive fingerprint mismatches before built-in UV is blocked (PIN fallback).
pub const MAX_UV_RETRIES: u8 = 5;
/// getNextAssertion must follow within 30 s (CTAP 2.1 §6.3).
pub const NEXT_ASSERTION_TIMEOUT_MS: u64 = 30_000;

pub type Parsed<T> = Result<T, u8>;

pub fn error(code: u8) -> Vec<u8> {
    vec![code]
}

pub fn ok_empty() -> Vec<u8> {
    vec![status::OK]
}

pub fn ok(body: &Value) -> Vec<u8> {
    let mut out = vec![status::OK];
    out.extend_from_slice(&cbor::encode(body));
    out
}

pub fn text(s: &str) -> Value {
    Value::Text(s.to_owned())
}

pub fn int(i: i64) -> Value {
    Value::int_key(i)
}

pub fn get(map: &Value, key: i64) -> Option<&Value> {
    map.map_get(&int(key))
}

pub fn get_text<'a>(map: &'a Value, key: &str) -> Option<&'a Value> {
    map.map_get(&text(key))
}

pub fn sha256(parts: &[&[u8]]) -> [u8; 32] {
    let mut h = Sha256::new();
    for p in parts {
        h.update(p);
    }
    h.finalize().into()
}

/// Decodes a CBOR parameter map (an empty request body is an empty map).
pub fn parse_map(params: &[u8]) -> Parsed<Value> {
    if params.is_empty() {
        return Ok(Value::Map(Vec::new()));
    }
    let req = cbor::decode(params).map_err(|_| status::INVALID_CBOR)?;
    let _ = req.as_map().ok_or(status::CBOR_UNEXPECTED_TYPE)?;
    Ok(req)
}

pub fn bytes32(v: Option<&Value>) -> Parsed<[u8; 32]> {
    let b = v
        .ok_or(status::MISSING_PARAMETER)?
        .as_bytes()
        .ok_or(status::CBOR_UNEXPECTED_TYPE)?;
    b.try_into().map_err(|_| status::INVALID_LENGTH)
}

pub fn opt_bytes(v: Option<&Value>) -> Parsed<Option<&[u8]>> {
    v.map(|v| v.as_bytes().ok_or(status::CBOR_UNEXPECTED_TYPE))
        .transpose()
}

pub fn opt_text(v: Option<&Value>) -> Parsed<Option<&str>> {
    v.map(|v| v.as_text().ok_or(status::CBOR_UNEXPECTED_TYPE))
        .transpose()
}

pub fn opt_uint(v: Option<&Value>) -> Parsed<Option<u64>> {
    v.map(|v| v.as_uint().ok_or(status::CBOR_UNEXPECTED_TYPE))
        .transpose()
}

/// Reads a boolean from an options map.
pub fn option(req: &Value, key: i64, name: &str) -> Parsed<Option<bool>> {
    match get(req, key) {
        None => Ok(None),
        Some(opts) => {
            let _ = opts.as_map().ok_or(status::CBOR_UNEXPECTED_TYPE)?;
            match get_text(opts, name) {
                None => Ok(None),
                Some(v) => v.as_bool().map(Some).ok_or(status::CBOR_UNEXPECTED_TYPE),
            }
        }
    }
}

/// `PublicKeyCredentialDescriptor` list → credential IDs of type "public-key".
pub fn descriptor_ids(list: &Value) -> Parsed<Vec<&[u8]>> {
    let items = list.as_array().ok_or(status::CBOR_UNEXPECTED_TYPE)?;
    let mut ids = Vec::with_capacity(items.len());
    for item in items {
        let _ = item.as_map().ok_or(status::CBOR_UNEXPECTED_TYPE)?;
        let kind = get_text(item, "type")
            .and_then(Value::as_text)
            .ok_or(status::MISSING_PARAMETER)?;
        let id = get_text(item, "id")
            .and_then(Value::as_bytes)
            .ok_or(status::MISSING_PARAMETER)?;
        if kind == "public-key" {
            ids.push(id);
        }
    }
    Ok(ids)
}

pub fn descriptor(id: &[u8]) -> Value {
    Value::Map(vec![
        (text("id"), Value::Bytes(id.to_vec())),
        (text("type"), text("public-key")),
    ])
}

pub fn map_tpm_error(e: TpmError) -> u8 {
    match e {
        TpmError::PolicyFailed | TpmError::Reset => status::NO_CREDENTIALS,
        TpmError::Lockout => status::PIN_AUTH_BLOCKED,
        TpmError::WrongPin => status::PIN_INVALID,
        TpmError::Unavailable => status::OTHER,
    }
}

/// COSE_Key for an ES256 public key (RFC 9053): {1: 2, 3: -7, -1: 1, -2: x, -3: y}.
pub fn cose_es256(x: [u8; 32], y: [u8; 32]) -> Value {
    Value::Map(vec![
        (int(1), int(2)),
        (int(3), int(ES256)),
        (int(-1), int(1)),
        (int(-2), Value::Bytes(x.to_vec())),
        (int(-3), Value::Bytes(y.to_vec())),
    ])
}

/// Truncates at a UTF-8 boundary to at most `max` bytes (CTAP 2.1 §6.1.2 name truncation).
pub fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    s.get(..end).unwrap_or_default().to_owned()
}
