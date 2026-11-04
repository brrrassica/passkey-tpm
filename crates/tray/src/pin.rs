//! Platform side of clientPIN (PIN/UV auth protocol 2) over the broker's `Ctap` method:
//! read whether a PIN is set, set it, change it. The broker derives the user from the bus,
//! so this only ever touches the calling user's PIN.

use passkey_tpm_core::ctap2::{ClientPinSub, Command};
use passkey_tpm_core::pin_protocol::{parse_platform_key, KeyAgreement, Protocol, SharedSecret};
use passkey_tpm_wire::cbor::{self, Value};
use sha2::{Digest, Sha256};
use zbus::Connection;
use zeroize::Zeroizing;

use crate::probe::{BROKER_NAME, BROKER_PATH};

/// CTAP 2.1 minimum PIN length, in Unicode code points.
pub const MIN_PIN_CHARS: usize = 4;
/// Maximum PIN length in bytes (the padded block is 64 bytes and must end with a zero).
pub const MAX_PIN_BYTES: usize = 63;

/// Why a PIN operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PinError {
    /// The broker couldn't be reached.
    Bus(String),
    /// The authenticator answered with this CTAP status.
    Status(u8),
    /// The reply didn't parse.
    Protocol(String),
}

impl PinError {
    /// A sentence for a notification.
    #[must_use]
    pub fn describe(&self) -> String {
        match self {
            Self::Bus(e) => format!("The passkey-tpm service is not reachable ({e})."),
            Self::Protocol(e) => format!("Unexpected answer from passkey-tpm ({e})."),
            Self::Status(code) => match *code {
                0x27 => "Only the user at the active session can change the PIN.",
                0x30 => "A PIN is already set. Use Change PIN instead.",
                0x31 => "The current PIN is wrong.",
                0x32 => "The PIN is blocked after too many wrong attempts. Reset the security key to use it again.",
                0x34 => "Too many wrong PINs in a row. Log out and back in, then try again.",
                0x35 => "No PIN is set yet. Use Set PIN instead.",
                0x37 => "The new PIN doesn't meet the PIN rules (at least 4 characters).",
                code => return format!("passkey-tpm refused the request (CTAP error {code:#04x})."),
            }
            .to_owned(),
        }
    }
}

/// Checks a new PIN against the CTAP rules before sending it.
///
/// # Errors
///
/// A sentence describing the problem.
pub fn check_new_pin(pin: &str, confirm: &str) -> Result<(), String> {
    if pin != confirm {
        return Err("The PINs don't match.".to_owned());
    }
    if pin.chars().count() < MIN_PIN_CHARS {
        return Err(format!(
            "The PIN needs at least {MIN_PIN_CHARS} characters."
        ));
    }
    if pin.len() > MAX_PIN_BYTES {
        return Err(format!(
            "The PIN can be at most {MAX_PIN_BYTES} bytes long."
        ));
    }
    if pin.contains('\0') {
        return Err("The PIN can't contain a NUL character.".to_owned());
    }
    Ok(())
}

async fn ctap(conn: &Connection, request: &[u8]) -> Result<Vec<u8>, PinError> {
    let reply = conn
        .call_method(
            Some(BROKER_NAME),
            BROKER_PATH,
            Some(BROKER_NAME),
            "Ctap",
            &(request.to_vec(),),
        )
        .await
        .map_err(|e| PinError::Bus(e.to_string()))?;
    reply
        .body()
        .deserialize::<Vec<u8>>()
        .map_err(|e| PinError::Protocol(e.to_string()))
}

/// The CBOR body of a successful response.
fn ok_body(response: &[u8]) -> Result<Option<Value>, PinError> {
    match response.split_first() {
        Some((0, [])) => Ok(None),
        Some((0, rest)) => cbor::decode(rest)
            .map(Some)
            .map_err(|e| PinError::Protocol(format!("{e:?}"))),
        Some((&code, _)) => Err(PinError::Status(code)),
        None => Err(PinError::Protocol("empty response".to_owned())),
    }
}

fn request(command: Command, params: Vec<(Value, Value)>) -> Vec<u8> {
    let mut r = vec![command.code()];
    r.extend(cbor::encode(&Value::Map(params)));
    r
}

/// Whether the calling user has a PIN (`clientPin` option of getInfo).
///
/// # Errors
///
/// [`PinError`] if the broker can't be asked.
pub async fn is_set(conn: &Connection) -> Result<bool, PinError> {
    let info = ok_body(&ctap(conn, &[Command::GetInfo.code()]).await?)?
        .ok_or_else(|| PinError::Protocol("empty getInfo".to_owned()))?;
    Ok(info
        .map_get(&Value::int_key(4))
        .and_then(|o| o.map_get(&Value::Text("clientPin".to_owned())))
        == Some(&Value::Bool(true)))
}

/// A key agreement with the authenticator.
struct Session {
    key: KeyAgreement,
    shared: SharedSecret,
}

impl Session {
    async fn open(conn: &Connection) -> Result<Self, PinError> {
        let resp = ctap(
            conn,
            &request(
                Command::ClientPin,
                vec![
                    (Value::int_key(1), Value::Uint(Protocol::Two.as_u64())),
                    (
                        Value::int_key(2),
                        Value::Uint(ClientPinSub::GetKeyAgreement.code()),
                    ),
                ],
            ),
        )
        .await?;
        let body = ok_body(&resp)?.ok_or_else(|| PinError::Protocol("no key".to_owned()))?;
        let auth_key = body
            .map_get(&Value::int_key(1))
            .ok_or_else(|| PinError::Protocol("no keyAgreement".to_owned()))
            .and_then(|k| {
                parse_platform_key(k).map_err(|e| PinError::Protocol(format!("{e:?}")))
            })?;
        let key = KeyAgreement::generate().map_err(|e| PinError::Protocol(format!("{e:?}")))?;
        let shared = key
            .shared_secret(Protocol::Two, &auth_key)
            .map_err(|e| PinError::Protocol(format!("{e:?}")))?;
        Ok(Self { key, shared })
    }

    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>, PinError> {
        self.shared
            .encrypt(data)
            .map_err(|e| PinError::Protocol(format!("{e:?}")))
    }

    /// `newPinEnc`: the PIN zero-padded to 64 bytes, encrypted.
    fn new_pin_enc(&self, pin: &str) -> Result<Vec<u8>, PinError> {
        let mut padded = Zeroizing::new(pin.as_bytes().to_vec());
        padded.resize(64, 0);
        self.encrypt(&padded)
    }

    fn request(&self, sub: ClientPinSub, extra: Vec<(Value, Value)>) -> Vec<u8> {
        let mut m = vec![
            (Value::int_key(1), Value::Uint(Protocol::Two.as_u64())),
            (Value::int_key(2), Value::Uint(sub.code())),
            (Value::int_key(3), self.key.cose_public()),
        ];
        m.extend(extra);
        request(Command::ClientPin, m)
    }
}

/// Sets the first PIN (clientPIN setPIN). Call [`check_new_pin`] first.
///
/// # Errors
///
/// [`PinError::Status`] with the CTAP status, e.g. `0x30` if a PIN is already set.
pub async fn set(conn: &Connection, pin: &str) -> Result<(), PinError> {
    let s = Session::open(conn).await?;
    let enc = s.new_pin_enc(pin)?;
    let auth = s.shared.authenticate(&enc);
    let req = s.request(
        ClientPinSub::SetPin,
        vec![
            (Value::int_key(4), Value::Bytes(auth)),
            (Value::int_key(5), Value::Bytes(enc)),
        ],
    );
    ok_body(&ctap(conn, &req).await?).map(|_| ())
}

/// Changes the PIN (clientPIN changePIN). A wrong `old` PIN uses up one retry.
///
/// # Errors
///
/// [`PinError::Status`] with the CTAP status, e.g. `0x31` for a wrong current PIN.
pub async fn change(conn: &Connection, old: &str, new: &str) -> Result<(), PinError> {
    let s = Session::open(conn).await?;
    let new_enc = s.new_pin_enc(new)?;
    let digest = Zeroizing::new(Sha256::digest(old.as_bytes()));
    let hash_enc = s.encrypt(digest.get(..16).unwrap_or_default())?;
    let mut message = new_enc.clone();
    message.extend_from_slice(&hash_enc);
    let auth = s.shared.authenticate(&message);
    let req = s.request(
        ClientPinSub::ChangePin,
        vec![
            (Value::int_key(4), Value::Bytes(auth)),
            (Value::int_key(5), Value::Bytes(new_enc)),
            (Value::int_key(6), Value::Bytes(hash_enc)),
        ],
    );
    ok_body(&ctap(conn, &req).await?).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_pin_rules() {
        assert!(check_new_pin("1234", "1234").is_ok());
        assert!(check_new_pin("ção!", "ção!").is_ok(), "4 code points");
        assert!(check_new_pin("123", "123").is_err());
        assert!(check_new_pin("1234", "1235").is_err());
        assert!(check_new_pin(&"x".repeat(63), &"x".repeat(63)).is_ok());
        assert!(check_new_pin(&"x".repeat(64), &"x".repeat(64)).is_err());
        assert!(check_new_pin("12\u{0}4", "12\u{0}4").is_err());
    }

    #[test]
    fn responses() {
        assert_eq!(ok_body(&[0]), Ok(None));
        assert_eq!(ok_body(&[0x31]), Err(PinError::Status(0x31)));
        assert!(ok_body(&[]).is_err());
        assert_eq!(
            PinError::Status(0x31).describe(),
            "The current PIN is wrong."
        );
    }
}
