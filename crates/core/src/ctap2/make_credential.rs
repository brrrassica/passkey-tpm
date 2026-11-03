//! authenticatorMakeCredential (CTAP 2.1 §6.1, M2-06..09).

use passkey_tpm_wire::cbor::{self, Value};
use passkey_tpm_wire::resident::{self, ResidentEntry};

use super::authn::{AuthCheck, Authenticator, Pending, PendingKind, Step, UserInfo, Verification};
use super::common::{
    bytes32, cose_es256, descriptor_ids, get, get_text, int, map_tpm_error, ok, opt_bytes,
    opt_text, opt_uint, option, parse_map, sha256, status, text, truncate, Parsed, AAGUID, ES256,
    MAX_RESIDENT,
};
use crate::evidence::{auth_data, UvEvidence};
use crate::token::PERM_MC;
use crate::tpm_iface::{CredProtect, RpIdHash, TpmOps, Uid};

/// Every credential is created at credProtect level 3 (AD-012, M2-08).
pub const APPLIED_CRED_PROTECT: CredProtect = CredProtect::UvRequired;

/// A validated makeCredential request.
#[derive(Debug)]
pub struct Request {
    rp_id: String,
    rp_name: String,
    rp_id_hash: RpIdHash,
    client_data_hash: [u8; 32],
    user_id: Vec<u8>,
    user_name: String,
    user_display_name: String,
    resident: bool,
    excluded: bool,
    hmac_secret: bool,
    cred_protect_requested: bool,
}

impl<T: TpmOps> Authenticator<T> {
    pub(super) fn prepare_make_credential(
        &mut self,
        uid: Uid,
        user: UserInfo,
        params: &[u8],
        now_ms: u64,
    ) -> Parsed<Step> {
        let req = parse_map(params)?;
        let cdh = bytes32(get(&req, 1))?;
        let rp = get(&req, 2).ok_or(status::MISSING_PARAMETER)?;
        let rp_id = get_text(rp, "id")
            .and_then(Value::as_text)
            .ok_or(status::MISSING_PARAMETER)?;
        if rp_id.is_empty() {
            return Err(status::INVALID_PARAMETER);
        }
        let rp_name = opt_text(get_text(rp, "name"))?.unwrap_or("");
        let user_entity = get(&req, 3).ok_or(status::MISSING_PARAMETER)?;
        let user_id = get_text(user_entity, "id")
            .and_then(Value::as_bytes)
            .ok_or(status::MISSING_PARAMETER)?;
        if user_id.is_empty() || user_id.len() > 64 {
            return Err(status::INVALID_LENGTH);
        }
        let user_name = opt_text(get_text(user_entity, "name"))?.unwrap_or("");
        let user_display_name = opt_text(get_text(user_entity, "displayName"))?.unwrap_or("");
        let algs = get(&req, 4)
            .and_then(Value::as_array)
            .ok_or(status::MISSING_PARAMETER)?;
        let es256 = algs.iter().any(|p| {
            get_text(p, "alg").and_then(Value::as_i64) == Some(ES256)
                && get_text(p, "type").and_then(Value::as_text) == Some("public-key")
        });
        if !es256 {
            return Err(status::UNSUPPORTED_ALGORITHM);
        }
        if get(&req, 0x0A).is_some() {
            // Enterprise attestation is not supported.
            return Err(status::INVALID_PARAMETER);
        }
        if option(&req, 7, "up")? == Some(false) {
            return Err(status::INVALID_OPTION);
        }
        // WebAuthn `userVerification: required|preferred|discouraged` reaches CTAP as
        // `uv: true|absent|false`. Every credential is created at credProtect level 3
        // ([`APPLIED_CRED_PROTECT`]), so UV is always verified and `uv: false` cannot lower
        // that — which CTAP 2.1 §6.1.2 permits. The option is still type-checked, so a
        // non-boolean value is rejected like every other option.
        let _ = option(&req, 7, "uv")?;
        let resident = option(&req, 7, "rk")? == Some(true);
        let rp_id_hash = RpIdHash(sha256(&[rp_id.as_bytes()]));

        // Extensions: hmac-secret (bool), credProtect (1..=3), and credProtect's
        // enforceCredentialProtectionPolicy flag; others are ignored. Every credential is
        // created at level 3 (`APPLIED_CRED_PROTECT`), which is at least as strict as any
        // request, so the enforcement flag is always honorable and changes no outcome.
        let mut hmac_secret = false;
        let mut cred_protect_requested = false;
        if let Some(ext) = get(&req, 6) {
            let _ = ext.as_map().ok_or(status::CBOR_UNEXPECTED_TYPE)?;
            if let Some(v) = get_text(ext, "hmac-secret") {
                hmac_secret = v.as_bool().ok_or(status::CBOR_UNEXPECTED_TYPE)?;
            }
            if let Some(v) = get_text(ext, "credProtect") {
                let level = v.as_uint().ok_or(status::CBOR_UNEXPECTED_TYPE)?;
                if !(1..=3).contains(&level) {
                    return Err(status::INVALID_OPTION);
                }
                cred_protect_requested = true;
            }
            // CTAP 2.1 §6.1.3: the enforcement flag may only accompany a policy. Asking to
            // enforce nothing is invalid, not a reason to silently ignore the flag.
            let enforce = match get_text(ext, "enforceCredentialProtectionPolicy") {
                Some(v) => Some(v.as_bool().ok_or(status::CBOR_UNEXPECTED_TYPE)?),
                None => None,
            };
            if enforce == Some(true) && !cred_protect_requested {
                return Err(status::INVALID_OPTION);
            }
        }

        let param = opt_bytes(get(&req, 8))?;
        let protocol = opt_uint(get(&req, 9))?;
        let pin_set = self.pin_is_set(uid)?;
        let verification = match param {
            Some([]) => {
                // Zero-length pinUvAuthParam: "touch to select" (CTAP 2.1 §6.1.2 step 1).
                let code = if pin_set {
                    status::PIN_INVALID
                } else {
                    status::PIN_NOT_SET
                };
                return self.gesture(uid, user, rp_id, PendingKind::TouchThen(code), true);
            }
            Some(p) => {
                let check = AuthCheck {
                    protocol,
                    param: p,
                    message: &cdh,
                    perm: PERM_MC,
                    rp: Some(&rp_id_hash),
                };
                self.verify_auth_param(uid, &check, now_ms)?
            }
            None if !user.uv_enrolled && pin_set => return Err(status::PUAT_REQUIRED),
            None => Verification::Gesture,
        };

        let mut excluded = false;
        if let Some(list) = get(&req, 5) {
            for id in descriptor_ids(list)? {
                if self
                    .tpm
                    .open_credential_id(uid, &rp_id_hash, id)
                    .map_err(map_tpm_error)?
                    .is_some()
                {
                    excluded = true;
                    break;
                }
            }
        }
        let request = Request {
            rp_id: rp_id.to_owned(),
            rp_name: truncate(rp_name, 64),
            rp_id_hash,
            client_data_hash: cdh,
            user_id: user_id.to_vec(),
            user_name: truncate(user_name, 64),
            user_display_name: truncate(user_display_name, 64),
            resident,
            excluded,
            hmac_secret,
            cred_protect_requested,
        };
        match verification {
            // The token carries both UV and a fresh presence gesture: no new prompt.
            Verification::Token { user_present: true } => Ok(Step::Done(
                self.finish_make_credential(uid, request, UvEvidence::from_token(uid.0))
                    .unwrap_or_else(super::common::error),
            )),
            // UV via the token (PIN) but presence still needed.
            Verification::Token {
                user_present: false,
            } => self.gesture(
                uid,
                user,
                rp_id,
                PendingKind::MakeCredential(request),
                false,
            ),
            // No token at all: the fingerprint gives UP and UV.
            Verification::Gesture => {
                self.gesture(uid, user, rp_id, PendingKind::MakeCredential(request), true)
            }
        }
    }

    /// Asks the broker for a fingerprint match. `fingerprint_uv`: the match is the request's
    /// UV, so the uvRetries limit applies; otherwise a PIN token already gave UV and the
    /// match only proves presence (the PIN stays a fallback for blocked UV). A blocked PIN
    /// stops both (HARD-04, AD-010).
    ///
    /// Without an enrolled fingerprint, presence comes from a confirmation the broker asks
    /// for ([`Step::NeedPresence`], AD-022) — but only where nothing else is missing: UV
    /// already proven by the token, or a touch-to-select that needs no UV.
    pub(super) fn gesture(
        &mut self,
        uid: Uid,
        user: UserInfo,
        rp_id: &str,
        kind: PendingKind,
        fingerprint_uv: bool,
    ) -> Parsed<Step> {
        if !user.uv_enrolled {
            let touch_to_select = matches!(kind, PendingKind::TouchThen(_));
            if fingerprint_uv && !touch_to_select {
                // The request needs UV and there is no fingerprint to give it.
                return Err(status::NOT_ALLOWED);
            }
            if !fingerprint_uv {
                self.check_pin_not_blocked(uid)?;
            }
            return Ok(Step::NeedPresence(Box::new(Pending {
                uid,
                rp_id: rp_id.to_owned(),
                kind,
                presence_only: true,
            })));
        }
        if fingerprint_uv {
            self.check_builtin_uv(uid)?;
        } else {
            self.check_pin_not_blocked(uid)?;
        }
        Ok(Step::NeedUv(Box::new(Pending {
            uid,
            rp_id: rp_id.to_owned(),
            kind,
            presence_only: false,
        })))
    }

    pub(super) fn finish_make_credential(
        &mut self,
        uid: Uid,
        r: Request,
        ev: UvEvidence,
    ) -> Parsed<Vec<u8>> {
        if r.excluded {
            return Err(status::CREDENTIAL_EXCLUDED);
        }
        let mut entries = if r.resident {
            self.tpm.resident_entries(uid).map_err(map_tpm_error)?
        } else {
            Vec::new()
        };
        if r.resident
            && entries.len() >= MAX_RESIDENT
            && resident::for_rp(&entries, &r.rp_id)
                .iter()
                .all(|e| e.user_id != r.user_id)
        {
            return Err(status::KEY_STORE_FULL);
        }

        let blobs = self
            .tpm
            .create_credential(uid, &r.rp_id_hash, APPLIED_CRED_PROTECT, r.hmac_secret)
            .map_err(map_tpm_error)?;
        let id = self
            .tpm
            .credential_id(uid, &r.rp_id_hash, &blobs)
            .map_err(map_tpm_error)?;
        let (x, y) = self.tpm.public_key(&blobs).map_err(map_tpm_error)?;
        let id_len = u16::try_from(id.len()).map_err(|_| status::OTHER)?;

        let mut attested = Vec::with_capacity(18 + id.len() + 77);
        attested.extend_from_slice(&AAGUID);
        attested.extend_from_slice(&id_len.to_be_bytes());
        attested.extend_from_slice(&id);
        attested.extend_from_slice(&cbor::encode(&cose_es256(x, y)));

        let mut ext = Vec::new();
        if r.cred_protect_requested {
            ext.push((
                text("credProtect"),
                Value::Uint(u64::from(APPLIED_CRED_PROTECT.level())),
            ));
        }
        if r.hmac_secret {
            ext.push((text("hmac-secret"), Value::Bool(true)));
        }
        let ext_bytes = (!ext.is_empty()).then(|| cbor::encode(&Value::Map(ext)));

        let auth = auth_data(&r.rp_id_hash.0, &ev, Some(&attested), ext_bytes.as_deref());
        let digest = sha256(&[&auth, &r.client_data_hash]);
        let sig = self
            .tpm
            .sign(uid, &blobs, &r.rp_id_hash, ev.gate(), &digest)
            .map_err(map_tpm_error)?;

        if r.resident {
            let entry = ResidentEntry {
                rp_id: r.rp_id.clone(),
                rp_name: r.rp_name.clone(),
                user_id: r.user_id.clone(),
                user_name: r.user_name.clone(),
                user_display_name: r.user_display_name.clone(),
                credential_id: id.clone(),
                created: now_unix(),
            };
            resident::upsert(&mut entries, entry).map_err(|_| status::KEY_STORE_FULL)?;
            self.tpm
                .store_resident_entries(uid, &entries)
                .map_err(map_tpm_error)?;
        }

        Ok(ok(&Value::Map(vec![
            (int(1), text("packed")),
            (int(2), Value::Bytes(auth)),
            (
                int(3),
                Value::Map(vec![
                    (text("alg"), int(ES256)),
                    (text("sig"), Value::Bytes(sig)),
                ]),
            ),
        ])))
    }
}

/// Seconds since the Unix epoch (credential creation time, for ordering only).
fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}
