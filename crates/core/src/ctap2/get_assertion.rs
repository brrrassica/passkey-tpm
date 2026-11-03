//! authenticatorGetAssertion and authenticatorGetNextAssertion (CTAP 2.1 §6.2–6.3,
//! M2-06/07/09/10).

use passkey_tpm_wire::cbor::{self, Value};
use passkey_tpm_wire::resident;

use super::authn::{AuthCheck, Authenticator, PendingKind, Step, UserInfo, Verification};
use super::common::{
    bytes32, descriptor, descriptor_ids, get, get_text, int, map_tpm_error, ok, opt_bytes,
    opt_uint, option, parse_map, sha256, status, text, Parsed, MAX_CREDENTIAL_COUNT_IN_LIST,
    NEXT_ASSERTION_TIMEOUT_MS,
};
use super::state::{Found, HmacRequest, NextAssertion};
use crate::evidence::{auth_data, UvEvidence};
use crate::token::PERM_GA;
use crate::tpm_iface::{RpIdHash, TpmOps, Uid};
use zeroize::Zeroizing;

/// A validated getAssertion request.
#[derive(Debug)]
pub struct Request {
    rp_id_hash: RpIdHash,
    client_data_hash: [u8; 32],
    found: Vec<Found>,
    discoverable: bool,
    hmac: Option<HmacRequest>,
}

impl<T: TpmOps> Authenticator<T> {
    pub(super) fn prepare_get_assertion(
        &mut self,
        uid: Uid,
        user: UserInfo,
        params: &[u8],
        now_ms: u64,
    ) -> Parsed<Step> {
        let req = parse_map(params)?;
        let rp_id = get(&req, 1)
            .and_then(Value::as_text)
            .ok_or(status::MISSING_PARAMETER)?;
        if rp_id.is_empty() {
            return Err(status::INVALID_PARAMETER);
        }
        let cdh = bytes32(get(&req, 2))?;
        if option(&req, 5, "rk")?.is_some() {
            return Err(status::INVALID_OPTION);
        }
        let silent = option(&req, 5, "up")? == Some(false);
        // Same mapping as makeCredential: `uv: true|absent|false` is
        // required|preferred|discouraged. UV is always verified (credProtect level 3), so
        // the option can never weaken the request, but it must still be well-typed
        // (CTAP 2.1 §6.2.2).
        let _ = option(&req, 5, "uv")?;
        let rp_id_hash = RpIdHash(sha256(&[rp_id.as_bytes()]));

        let param = opt_bytes(get(&req, 6))?;
        let protocol = opt_uint(get(&req, 7))?;
        let pin_set = self.pin_is_set(uid)?;
        let verification = match param {
            Some([]) => {
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
                    perm: PERM_GA,
                    rp: Some(&rp_id_hash),
                };
                Some(self.verify_auth_param(uid, &check, now_ms)?)
            }
            None => None,
        };

        let (found, discoverable) = self.locate(uid, &rp_id_hash, rp_id, get(&req, 3))?;
        if silent {
            // Every credential requires UV and a signature needs it: silent probes can only
            // learn that nothing is here.
            return Err(if found.is_empty() {
                status::NO_CREDENTIALS
            } else {
                status::UNSUPPORTED_OPTION
            });
        }

        let hmac = match get(&req, 4).and_then(|ext| get_text(ext, "hmac-secret")) {
            Some(h) => Some(self.parse_hmac_secret(uid, h)?),
            None => None,
        };
        let request = Request {
            rp_id_hash,
            client_data_hash: cdh,
            found,
            discoverable,
            hmac,
        };
        match verification {
            Some(Verification::Token { user_present: true }) => Ok(Step::Done(
                self.finish_get_assertion(uid, request, UvEvidence::from_token(uid.0), now_ms)
                    .unwrap_or_else(super::common::error),
            )),
            // PIN token without presence: the fingerprint only adds UP.
            Some(Verification::Token {
                user_present: false,
            }) => self.gesture(uid, user, rp_id, PendingKind::GetAssertion(request), false),
            // No fingerprint to give UV, but a PIN could (same as makeCredential, M2-06).
            Some(Verification::Gesture) | None if !user.uv_enrolled && pin_set => {
                Err(status::PUAT_REQUIRED)
            }
            // No token: the fingerprint gives UP and UV.
            Some(Verification::Gesture) | None => {
                self.gesture(uid, user, rp_id, PendingKind::GetAssertion(request), true)
            }
        }
    }

    /// Credentials for this request: the first own entry of the allowList, or this RP's
    /// discoverable credentials (most recent first).
    fn locate(
        &mut self,
        uid: Uid,
        rp_id_hash: &RpIdHash,
        rp_id: &str,
        allow: Option<&Value>,
    ) -> Parsed<(Vec<Found>, bool)> {
        if let Some(list) = allow {
            let ids = descriptor_ids(list)?;
            if ids.len() > MAX_CREDENTIAL_COUNT_IN_LIST {
                return Err(status::LIMIT_EXCEEDED);
            }
            for id in ids {
                if let Some(blobs) = self
                    .tpm
                    .open_credential_id(uid, rp_id_hash, id)
                    .map_err(map_tpm_error)?
                {
                    return Ok((
                        vec![Found {
                            id: id.to_vec(),
                            blobs,
                            user: None,
                        }],
                        false,
                    ));
                }
            }
            return Ok((Vec::new(), false));
        }
        let entries = self.tpm.resident_entries(uid).map_err(map_tpm_error)?;
        let mut found = Vec::new();
        for entry in resident::for_rp(&entries, rp_id) {
            if let Some(blobs) = self
                .tpm
                .open_credential_id(uid, rp_id_hash, &entry.credential_id)
                .map_err(map_tpm_error)?
            {
                found.push(Found {
                    id: entry.credential_id.clone(),
                    blobs,
                    user: Some(entry.clone()),
                });
            }
        }
        Ok((found, true))
    }

    pub(super) fn finish_get_assertion(
        &mut self,
        uid: Uid,
        mut r: Request,
        ev: UvEvidence,
        now_ms: u64,
    ) -> Parsed<Vec<u8>> {
        if r.found.is_empty() {
            return Err(status::NO_CREDENTIALS);
        }
        let first = r.found.remove(0);
        let total = r.found.len().saturating_add(1);
        let response = self.assertion(
            uid,
            &r.rp_id_hash,
            &r.client_data_hash,
            &first,
            &ev,
            r.hmac.as_ref(),
            (r.discoverable && total > 1).then_some(total),
        )?;
        if !r.found.is_empty() {
            // hmac-secret applies to the first assertion only; later ones carry no extension.
            self.user(uid).next_assertion = Some(NextAssertion {
                rp_id_hash: r.rp_id_hash,
                client_data_hash: r.client_data_hash,
                remaining: r.found,
                started_ms: now_ms,
            });
        }
        Ok(response)
    }

    pub(super) fn get_next_assertion(&mut self, uid: Uid, now_ms: u64) -> Parsed<Vec<u8>> {
        let state = self.user(uid);
        let Some(mut next) = state.next_assertion.take() else {
            return Err(status::NOT_ALLOWED);
        };
        if now_ms.saturating_sub(next.started_ms) > NEXT_ASSERTION_TIMEOUT_MS
            || next.remaining.is_empty()
        {
            return Err(status::NOT_ALLOWED);
        }
        let found = next.remaining.remove(0);
        // The user was verified for this getAssertion; the same verification covers the
        // remaining accounts (CTAP 2.1 §6.3), still through the UV gate.
        let ev = UvEvidence::from_token(uid.0);
        let response = self.assertion(
            uid,
            &next.rp_id_hash,
            &next.client_data_hash,
            &found,
            &ev,
            None,
            None,
        )?;
        if !next.remaining.is_empty() {
            self.user(uid).next_assertion = Some(next);
        }
        Ok(response)
    }

    /// `output1 ‖ output2` of hmac-secret (CTAP 2.1 §12.5), wiped on drop (HARD-17).
    pub(super) fn hmac_secret_output(
        &mut self,
        uid: Uid,
        rp_id_hash: &RpIdHash,
        found: &Found,
        ev: &UvEvidence,
        h: &HmacRequest,
    ) -> Parsed<Zeroizing<Vec<u8>>> {
        let mut out = Zeroizing::new(Vec::with_capacity(64));
        for salt in core::iter::once(&h.salt1).chain(h.salt2.as_ref()) {
            let output = Zeroizing::new(
                self.tpm
                    .hmac(uid, &found.blobs, rp_id_hash, ev.gate(), salt)
                    .map_err(map_tpm_error)?,
            );
            out.extend_from_slice(output.as_slice());
        }
        Ok(out)
    }

    #[allow(clippy::too_many_arguments)]
    fn assertion(
        &mut self,
        uid: Uid,
        rp_id_hash: &RpIdHash,
        client_data_hash: &[u8; 32],
        found: &Found,
        ev: &UvEvidence,
        hmac: Option<&HmacRequest>,
        number_of_credentials: Option<usize>,
    ) -> Parsed<Vec<u8>> {
        // A credential created without hmac-secret has no CredRandom: the extension output
        // is omitted, the assertion itself still succeeds (CTAP 2.1 §12.5).
        let ext = match hmac.filter(|_| found.blobs.hmac.is_some()) {
            None => None,
            Some(h) => {
                let out = self.hmac_secret_output(uid, rp_id_hash, found, ev, h)?;
                let enc = h.shared.encrypt(&out).map_err(|_| status::OTHER)?;
                Some(cbor::encode(&Value::Map(vec![(
                    text("hmac-secret"),
                    Value::Bytes(enc),
                )])))
            }
        };
        let auth = auth_data(&rp_id_hash.0, ev, None, ext.as_deref());
        let digest = sha256(&[&auth, client_data_hash]);
        let sig = self
            .tpm
            .sign(uid, &found.blobs, rp_id_hash, ev.gate(), &digest)
            .map_err(map_tpm_error)?;

        let mut body = vec![
            (int(1), descriptor(&found.id)),
            (int(2), Value::Bytes(auth)),
            (int(3), Value::Bytes(sig)),
        ];
        if let Some(entry) = &found.user {
            // UV always happened, so all user fields may be returned (CTAP 2.1 §6.2.2).
            let mut user = vec![(text("id"), Value::Bytes(entry.user_id.clone()))];
            if !entry.user_name.is_empty() {
                user.push((text("name"), text(&entry.user_name)));
            }
            if !entry.user_display_name.is_empty() {
                user.push((text("displayName"), text(&entry.user_display_name)));
            }
            body.push((int(4), Value::Map(user)));
        }
        if let Some(n) = number_of_credentials {
            body.push((int(5), Value::Uint(u64::try_from(n).unwrap_or(u64::MAX))));
        }
        Ok(ok(&Value::Map(body)))
    }
}
