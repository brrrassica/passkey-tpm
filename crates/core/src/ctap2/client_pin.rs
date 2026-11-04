//! authenticatorClientPIN (CTAP 2.1 §6.5.5, M2-02..05).

use passkey_tpm_wire::cbor::Value;
use zeroize::Zeroizing;

use super::authn::{Authenticator, Pending, PendingKind, Step, UserInfo};
use super::common::{
    get, int, map_tpm_error, ok, ok_empty, opt_bytes, opt_text, opt_uint, parse_map, sha256,
    status, ClientPinSub, Parsed, MAX_UV_RETRIES, MIN_PIN_LENGTH,
};
use super::state::IssuedToken;
use crate::pin_protocol::{self, Protocol, SharedSecret};
use crate::pin_retries::MAX_PIN_RETRIES;
use crate::token::{PinUvAuthToken, TokenGrant, PERM_GA, PERM_MC, SUPPORTED_PERMS};
use crate::tpm_iface::{TpmError, TpmOps, Uid};

/// A getPinUvAuthTokenUsingUvWithPermissions request waiting for the fingerprint.
#[derive(Debug)]
pub struct TokenRequest {
    protocol: Protocol,
    shared: SharedSecret,
    permissions: u8,
    rp_id_hash: Option<[u8; 32]>,
}

fn random_token() -> Parsed<Zeroizing<[u8; 32]>> {
    let mut t = Zeroizing::new([0u8; 32]);
    getrandom::fill(t.as_mut_slice()).map_err(|_| status::OTHER)?;
    Ok(t)
}

/// Strips the zero padding of a decrypted 64-byte `paddedNewPin` and applies the PIN policy.
fn parse_new_pin(padded: &[u8]) -> Parsed<Zeroizing<[u8; 16]>> {
    if padded.len() != 64 {
        return Err(status::INVALID_PARAMETER);
    }
    let end = padded.iter().position(|&b| b == 0).unwrap_or(padded.len());
    let pin = padded.get(..end).ok_or(status::INVALID_PARAMETER)?;
    if padded
        .get(end..)
        .is_some_and(|rest| rest.iter().any(|&b| b != 0))
    {
        return Err(status::PIN_POLICY_VIOLATION);
    }
    let text = core::str::from_utf8(pin).map_err(|_| status::PIN_POLICY_VIOLATION)?;
    if pin.len() > 63 || text.chars().count() < MIN_PIN_LENGTH {
        return Err(status::PIN_POLICY_VIOLATION);
    }
    pin_hash(pin)
}

fn pin_hash(pin: &[u8]) -> Parsed<Zeroizing<[u8; 16]>> {
    let digest = Zeroizing::new(sha256(&[pin]));
    digest
        .get(..16)
        .and_then(|h| h.try_into().ok())
        .map(Zeroizing::new)
        .ok_or(status::OTHER)
}

impl<T: TpmOps> Authenticator<T> {
    pub(super) fn client_pin(
        &mut self,
        uid: Uid,
        user: UserInfo,
        params: &[u8],
        now_ms: u64,
    ) -> Parsed<Step> {
        let req = parse_map(params)?;
        let subcommand = opt_uint(get(&req, 2))?.ok_or(status::MISSING_PARAMETER)?;
        let protocol = opt_uint(get(&req, 1))?;
        match ClientPinSub::from_code(subcommand) {
            Some(ClientPinSub::GetPinRetries) => {
                let retries = self.tpm.pin_retries(uid).map_err(map_tpm_error)?;
                Ok(Step::Done(ok(&Value::Map(vec![(
                    int(3),
                    Value::Uint(u64::from(retries)),
                )]))))
            }
            Some(ClientPinSub::GetUvRetries) => {
                let left = MAX_UV_RETRIES.saturating_sub(self.user(uid).uv_failures);
                Ok(Step::Done(ok(&Value::Map(vec![(
                    int(5),
                    Value::Uint(u64::from(left)),
                )]))))
            }
            Some(ClientPinSub::GetKeyAgreement) => {
                let _ = Self::protocol(protocol)?;
                let key = self.user(uid).key_agreement()?.cose_public();
                Ok(Step::Done(ok(&Value::Map(vec![(int(1), key)]))))
            }
            Some(ClientPinSub::SetPin) => self.set_pin(uid, &req, protocol).map(Step::Done),
            Some(ClientPinSub::ChangePin) => self.change_pin(uid, &req, protocol).map(Step::Done),
            Some(ClientPinSub::GetPinToken) => {
                if get(&req, 9).is_some() || get(&req, 10).is_some() {
                    return Err(status::INVALID_PARAMETER);
                }
                self.token_using_pin(uid, &req, protocol, PERM_MC | PERM_GA, None, now_ms)
                    .map(Step::Done)
            }
            Some(ClientPinSub::GetTokenUsingPin) => {
                let (permissions, rp) = Self::permissions(&req)?;
                self.token_using_pin(uid, &req, protocol, permissions, rp, now_ms)
                    .map(Step::Done)
            }
            Some(ClientPinSub::GetTokenUsingUv) => {
                self.prepare_token_using_uv(uid, user, &req, protocol)
            }
            _ => Err(status::INVALID_SUBCOMMAND),
        }
    }

    fn protocol(protocol: Option<u64>) -> Parsed<Protocol> {
        Protocol::from_u64(protocol.ok_or(status::MISSING_PARAMETER)?)
            .ok_or(status::INVALID_PARAMETER)
    }

    fn shared_secret(&mut self, uid: Uid, req: &Value, protocol: Protocol) -> Parsed<SharedSecret> {
        let key = get(req, 3).ok_or(status::MISSING_PARAMETER)?;
        let platform =
            pin_protocol::parse_platform_key(key).map_err(|_| status::INVALID_PARAMETER)?;
        self.user(uid)
            .key_agreement()?
            .shared_secret(protocol, &platform)
            .map_err(|_| status::INVALID_PARAMETER)
    }

    fn permissions(req: &Value) -> Parsed<(u8, Option<[u8; 32]>)> {
        let perms = opt_uint(get(req, 9))?.ok_or(status::MISSING_PARAMETER)?;
        let perms = u8::try_from(perms).map_err(|_| status::UNAUTHORIZED_PERMISSION)?;
        if perms == 0 {
            return Err(status::INVALID_PARAMETER);
        }
        if perms & !SUPPORTED_PERMS != 0 {
            return Err(status::UNAUTHORIZED_PERMISSION);
        }
        let rp = opt_text(get(req, 10))?.map(|id| sha256(&[id.as_bytes()]));
        if perms & (PERM_MC | PERM_GA) != 0 && rp.is_none() {
            return Err(status::MISSING_PARAMETER);
        }
        Ok((perms, rp))
    }

    fn set_pin(&mut self, uid: Uid, req: &Value, protocol: Option<u64>) -> Parsed<Vec<u8>> {
        let protocol = Self::protocol(protocol)?;
        let new_pin_enc = opt_bytes(get(req, 5))?.ok_or(status::MISSING_PARAMETER)?;
        let auth = opt_bytes(get(req, 4))?.ok_or(status::MISSING_PARAMETER)?;
        if self.pin_is_set(uid)? {
            return Err(status::NOT_ALLOWED);
        }
        let shared = self.shared_secret(uid, req, protocol)?;
        if !shared.verify(new_pin_enc, auth) {
            return Err(status::PIN_AUTH_INVALID);
        }
        let padded = shared
            .decrypt(new_pin_enc)
            .map_err(|_| status::INVALID_PARAMETER)?;
        let hash = parse_new_pin(&padded)?;
        self.tpm
            .change_pin(uid, None, &hash)
            .map_err(map_tpm_error)?;
        self.tpm
            .set_pin_retries(uid, MAX_PIN_RETRIES)
            .map_err(map_tpm_error)?;
        Ok(ok_empty())
    }

    /// Decrements and persists the retry counter, then has the TPM check `pinHashEnc`
    /// (CTAP 2.1 §6.5.5.7.2). Returns the verified PIN hash. Only a wrong PIN keeps the
    /// decrement; any other TPM error restores the counter (HARD-03).
    fn check_pin(
        &mut self,
        uid: Uid,
        shared: &SharedSecret,
        pin_hash_enc: &[u8],
    ) -> Parsed<Zeroizing<[u8; 16]>> {
        if !self.pin_is_set(uid)? {
            return Err(status::PIN_NOT_SET);
        }
        let retries = self.tpm.pin_retries(uid).map_err(map_tpm_error)?;
        if retries == 0 {
            return Err(status::PIN_BLOCKED);
        }
        if self.user(uid).mismatches.blocked() {
            return Err(status::PIN_AUTH_BLOCKED);
        }
        let left = retries.saturating_sub(1);
        self.tpm.set_pin_retries(uid, left).map_err(map_tpm_error)?;
        let decrypted = shared
            .decrypt(pin_hash_enc)
            .map_err(|_| status::INVALID_PARAMETER)?;
        let hash: Zeroizing<[u8; 16]> = decrypted
            .as_slice()
            .try_into()
            .map(Zeroizing::new)
            .map_err(|_| status::INVALID_PARAMETER)?;
        match self.tpm.verify_pin(uid, &hash) {
            Ok(()) => {
                self.tpm
                    .set_pin_retries(uid, MAX_PIN_RETRIES)
                    .map_err(map_tpm_error)?;
                self.user(uid).mismatches.reset();
                Ok(hash)
            }
            Err(TpmError::WrongPin) => {
                let state = self.user(uid);
                state.regenerate_key_agreement();
                let blocked = state.mismatches.record();
                Err(if left == 0 {
                    status::PIN_BLOCKED
                } else if blocked {
                    status::PIN_AUTH_BLOCKED
                } else {
                    status::PIN_INVALID
                })
            }
            Err(e) => {
                // The TPM never compared the PIN (DA lockout, TPM gone): the attempt wasn't
                // made, so give the retry back. A lockout maps to PIN_AUTH_BLOCKED (temporary).
                self.tpm
                    .set_pin_retries(uid, retries)
                    .map_err(map_tpm_error)?;
                Err(map_tpm_error(e))
            }
        }
    }

    fn change_pin(&mut self, uid: Uid, req: &Value, protocol: Option<u64>) -> Parsed<Vec<u8>> {
        let protocol = Self::protocol(protocol)?;
        let new_pin_enc = opt_bytes(get(req, 5))?.ok_or(status::MISSING_PARAMETER)?;
        let pin_hash_enc = opt_bytes(get(req, 6))?.ok_or(status::MISSING_PARAMETER)?;
        let auth = opt_bytes(get(req, 4))?.ok_or(status::MISSING_PARAMETER)?;
        let shared = self.shared_secret(uid, req, protocol)?;
        let mut message = new_pin_enc.to_vec();
        message.extend_from_slice(pin_hash_enc);
        if !shared.verify(&message, auth) {
            return Err(status::PIN_AUTH_INVALID);
        }
        let old = self.check_pin(uid, &shared, pin_hash_enc)?;
        let padded = shared
            .decrypt(new_pin_enc)
            .map_err(|_| status::INVALID_PARAMETER)?;
        let new = parse_new_pin(&padded)?;
        self.tpm
            .change_pin(uid, Some(&*old), &new)
            .map_err(map_tpm_error)?;
        self.user(uid).invalidate_token();
        Ok(ok_empty())
    }

    fn issue_token(
        &mut self,
        uid: Uid,
        shared: &SharedSecret,
        protocol: Protocol,
        grant: TokenGrant,
    ) -> Parsed<Vec<u8>> {
        let secret = random_token()?;
        let encrypted = shared
            .encrypt(secret.as_slice())
            .map_err(|_| status::OTHER)?;
        self.user(uid).token = Some(IssuedToken {
            token: PinUvAuthToken::new(secret, grant),
            protocol,
        });
        Ok(ok(&Value::Map(vec![(int(2), Value::Bytes(encrypted))])))
    }

    fn token_using_pin(
        &mut self,
        uid: Uid,
        req: &Value,
        protocol: Option<u64>,
        permissions: u8,
        rp: Option<[u8; 32]>,
        now_ms: u64,
    ) -> Parsed<Vec<u8>> {
        let protocol = Self::protocol(protocol)?;
        let pin_hash_enc = opt_bytes(get(req, 6))?.ok_or(status::MISSING_PARAMETER)?;
        let shared = self.shared_secret(uid, req, protocol)?;
        self.check_pin(uid, &shared, pin_hash_enc)?;
        self.user(uid).invalidate_token();
        // A PIN proves the user's identity, not presence: UP needs a gesture later.
        let grant = TokenGrant::new(permissions, rp, true, false, now_ms);
        self.issue_token(uid, &shared, protocol, grant)
    }

    fn prepare_token_using_uv(
        &mut self,
        uid: Uid,
        user: UserInfo,
        req: &Value,
        protocol: Option<u64>,
    ) -> Parsed<Step> {
        let protocol = Self::protocol(protocol)?;
        if !user.uv_enrolled {
            return Err(status::NOT_ALLOWED);
        }
        self.check_builtin_uv(uid)?;
        let (permissions, rp_id_hash) = Self::permissions(req)?;
        let shared = self.shared_secret(uid, req, protocol)?;
        let rp_id = opt_text(get(req, 10))?.unwrap_or("passkey-tpm").to_owned();
        Ok(Step::NeedUv(Box::new(Pending {
            uid,
            rp_id,
            kind: PendingKind::TokenUsingUv(TokenRequest {
                protocol,
                shared,
                permissions,
                rp_id_hash,
            }),
            presence_only: false,
        })))
    }

    pub(super) fn finish_token_using_uv(
        &mut self,
        uid: Uid,
        req: TokenRequest,
        now_ms: u64,
    ) -> Parsed<Vec<u8>> {
        self.user(uid).invalidate_token();
        // The fingerprint touch is also a presence gesture.
        let grant = TokenGrant::new(req.permissions, req.rp_id_hash, true, true, now_ms);
        self.issue_token(uid, &req.shared, req.protocol, grant)
    }
}

#[cfg(test)]
mod tests {
    use zeroize::Zeroizing;

    use super::{parse_new_pin, pin_hash, status};

    fn padded(pin: &[u8]) -> Vec<u8> {
        let mut p = pin.to_vec();
        p.resize(64, 0);
        p
    }

    #[test]
    fn pin_policy() {
        assert!(parse_new_pin(&padded(b"1234")).is_ok());
        assert_eq!(
            parse_new_pin(&padded(b"123")),
            Err(status::PIN_POLICY_VIOLATION)
        );
        assert!(
            parse_new_pin(&padded("ééé€".as_bytes())).is_ok(),
            "4 code points"
        );
        assert_eq!(parse_new_pin(&padded(&[b'1'; 63])).map(|_| ()), Ok(()));
        assert_eq!(
            parse_new_pin(&[b'1'; 64]),
            Err(status::PIN_POLICY_VIOLATION),
            "64 bytes leaves no padding"
        );
        assert_eq!(
            parse_new_pin(&padded(b"12")[..32]),
            Err(status::INVALID_PARAMETER)
        );
        let mut gap = padded(b"1234");
        gap[10] = b'x';
        assert_eq!(
            parse_new_pin(&gap),
            Err(status::PIN_POLICY_VIOLATION),
            "data after padding"
        );
    }

    #[test]
    fn pin_hashes_are_zeroized_on_drop() {
        let hash: Result<Zeroizing<[u8; 16]>, u8> = pin_hash(b"1234");
        assert_eq!(hash, parse_new_pin(&padded(b"1234")));
    }
}
