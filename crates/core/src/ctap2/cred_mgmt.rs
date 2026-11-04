//! authenticatorCredentialManagement (CTAP 2.1 §6.8, M2-11).

use passkey_tpm_wire::cbor::{self, Value};
use passkey_tpm_wire::resident::{self, ResidentEntry};

use super::authn::{AuthCheck, Authenticator};
use super::common::{
    bytes32, cose_es256, descriptor, get, get_text, int, map_tpm_error, ok, ok_empty, opt_bytes,
    opt_text, opt_uint, parse_map, sha256, status, text, truncate, CredMgmtSub, Parsed,
    MAX_RESIDENT,
};
use super::make_credential::APPLIED_CRED_PROTECT;
use super::state::CredMgmtCursor;
use crate::evidence::Presence;
use crate::token::PERM_CM;
use crate::tpm_iface::{RpIdHash, TpmOps, Uid};

fn count(n: usize) -> Value {
    Value::Uint(u64::try_from(n).unwrap_or(u64::MAX))
}

fn rp_entry(rp_id: &str, rp_name: &str, total: Option<usize>) -> Value {
    let mut rp = vec![(text("id"), text(rp_id))];
    if !rp_name.is_empty() {
        rp.push((text("name"), text(rp_name)));
    }
    let mut body = vec![
        (int(3), Value::Map(rp)),
        (int(4), Value::Bytes(sha256(&[rp_id.as_bytes()]).to_vec())),
    ];
    if let Some(t) = total {
        body.push((int(5), count(t)));
    }
    Value::Map(body)
}

fn user_entity(e: &ResidentEntry) -> Value {
    let mut user = vec![(text("id"), Value::Bytes(e.user_id.clone()))];
    if !e.user_name.is_empty() {
        user.push((text("name"), text(&e.user_name)));
    }
    if !e.user_display_name.is_empty() {
        user.push((text("displayName"), text(&e.user_display_name)));
    }
    Value::Map(user)
}

impl<T: TpmOps> Authenticator<T> {
    pub(super) fn credential_management(
        &mut self,
        uid: Uid,
        params: &[u8],
        now_ms: u64,
    ) -> Parsed<Vec<u8>> {
        let req = parse_map(params)?;
        let subcommand = opt_uint(get(&req, 1))?.ok_or(status::MISSING_PARAMETER)?;
        let sub = CredMgmtSub::from_code(subcommand);
        let sub_params = get(&req, 2);
        let protocol = opt_uint(get(&req, 3))?;

        // The GetNext* subcommands carry no authentication; they continue a cursor.
        match sub {
            Some(CredMgmtSub::EnumerateRpsNext) => return self.next_rp(uid),
            Some(CredMgmtSub::EnumerateCredentialsNext) => return self.next_credential(uid),
            _ => {}
        }

        // pinUvAuthParam = authenticate(token, subCommand ‖ subCommandParams), over the
        // subCommandParams bytes as received: decoding accepts any map key order, so a
        // re-encoding may differ from what the platform MACed (HARD-15).
        let param = opt_bytes(get(&req, 4))?.ok_or(status::PUAT_REQUIRED)?;
        let sub_byte = u8::try_from(subcommand).map_err(|_| status::INVALID_SUBCOMMAND)?;
        let mut message = vec![sub_byte];
        if let Some(raw) = cbor::map_value_raw(params, &int(2)).map_err(|_| status::INVALID_CBOR)? {
            message.extend_from_slice(raw);
        }
        let mut entries = self.tpm.resident_entries(uid).map_err(map_tpm_error)?;
        // Delete/update are scoped to the credential's RP, so a token bound to that RP may
        // manage its credentials (CTAP 2.1 §6.8).
        let rp_scope = match sub {
            Some(CredMgmtSub::EnumerateCredentialsBegin) => {
                Some(RpIdHash(bytes32(sub_params.and_then(|p| get(p, 1)))?))
            }
            Some(CredMgmtSub::DeleteCredential | CredMgmtSub::UpdateUserInformation) => {
                // Authenticate before the lookup so NO_CREDENTIALS is no oracle for an
                // unauthenticated caller (HARD-14); the RP scope is checked below.
                self.verify_auth_mac(uid, protocol, param, &message)?;
                let id = sub_params
                    .and_then(|p| get(p, 2))
                    .and_then(|d| get_text(d, "id"))
                    .and_then(Value::as_bytes)
                    .ok_or(status::MISSING_PARAMETER)?;
                let entry = entries
                    .iter()
                    .find(|e| e.credential_id == id)
                    .ok_or(status::NO_CREDENTIALS)?;
                Some(RpIdHash(sha256(&[entry.rp_id.as_bytes()])))
            }
            _ => None,
        };
        let check = AuthCheck {
            protocol,
            param,
            message: &message,
            perm: PERM_CM,
            rp: rp_scope.as_ref(),
            presence: Presence::Required,
        };
        self.verify_auth_param(uid, &check, now_ms)?;

        match sub {
            Some(CredMgmtSub::GetCredsMetadata) => Ok(ok(&Value::Map(vec![
                (int(1), count(entries.len())),
                (int(2), count(MAX_RESIDENT.saturating_sub(entries.len()))),
            ]))),
            Some(CredMgmtSub::EnumerateRpsBegin) => {
                let rps: Vec<(String, String)> = resident::rps(&entries)
                    .into_iter()
                    .map(|(id, name)| (id.to_owned(), name.to_owned()))
                    .collect();
                let Some(((id, name), rest)) = rps.split_first() else {
                    return Err(status::NO_CREDENTIALS);
                };
                let response = ok(&rp_entry(id, name, Some(rps.len())));
                self.user(uid).cred_mgmt = Some(CredMgmtCursor::Rps(rest.to_vec()));
                Ok(response)
            }
            Some(CredMgmtSub::EnumerateCredentialsBegin) => {
                let rp_id_hash = rp_scope.ok_or(status::MISSING_PARAMETER)?;
                let mut matching: Vec<ResidentEntry> = entries
                    .into_iter()
                    .filter(|e| sha256(&[e.rp_id.as_bytes()]) == rp_id_hash.0)
                    .collect();
                if matching.is_empty() {
                    return Err(status::NO_CREDENTIALS);
                }
                let first = matching.remove(0);
                let total = matching.len().saturating_add(1);
                let response = self.credential_entry(uid, &rp_id_hash, &first, Some(total))?;
                self.user(uid).cred_mgmt = Some(CredMgmtCursor::Credentials {
                    rp_id_hash,
                    entries: matching,
                });
                Ok(response)
            }
            Some(CredMgmtSub::DeleteCredential) => {
                let id = sub_params
                    .and_then(|p| get(p, 2))
                    .and_then(|d| get_text(d, "id"))
                    .and_then(Value::as_bytes)
                    .ok_or(status::MISSING_PARAMETER)?;
                if !resident::remove_credential(&mut entries, id) {
                    return Err(status::NO_CREDENTIALS);
                }
                // Revoke first: the ID must stop working even if an RP still holds it.
                self.tpm.revoke_credential(uid, id).map_err(map_tpm_error)?;
                self.tpm
                    .store_resident_entries(uid, &entries)
                    .map_err(map_tpm_error)?;
                Ok(ok_empty())
            }
            Some(CredMgmtSub::UpdateUserInformation) => {
                let p = sub_params.ok_or(status::MISSING_PARAMETER)?;
                let id = get(p, 2)
                    .and_then(|d| get_text(d, "id"))
                    .and_then(Value::as_bytes)
                    .ok_or(status::MISSING_PARAMETER)?;
                let user = get(p, 3).ok_or(status::MISSING_PARAMETER)?;
                let user_id = get_text(user, "id")
                    .and_then(Value::as_bytes)
                    .ok_or(status::MISSING_PARAMETER)?;
                let entry = entries
                    .iter_mut()
                    .find(|e| e.credential_id == id)
                    .ok_or(status::NO_CREDENTIALS)?;
                if entry.user_id != user_id {
                    return Err(status::INVALID_PARAMETER);
                }
                entry.user_name = truncate(opt_text(get_text(user, "name"))?.unwrap_or(""), 64);
                entry.user_display_name =
                    truncate(opt_text(get_text(user, "displayName"))?.unwrap_or(""), 64);
                self.tpm
                    .store_resident_entries(uid, &entries)
                    .map_err(map_tpm_error)?;
                Ok(ok_empty())
            }
            _ => Err(status::INVALID_SUBCOMMAND),
        }
    }

    fn credential_entry(
        &mut self,
        uid: Uid,
        rp_id_hash: &RpIdHash,
        e: &ResidentEntry,
        total: Option<usize>,
    ) -> Parsed<Vec<u8>> {
        let blobs = self
            .tpm
            .open_credential_id(uid, rp_id_hash, &e.credential_id)
            .map_err(map_tpm_error)?
            .ok_or(status::NO_CREDENTIALS)?;
        let (x, y) = self.tpm.public_key(&blobs).map_err(map_tpm_error)?;
        let mut body = vec![
            (int(6), user_entity(e)),
            (int(7), descriptor(&e.credential_id)),
            (int(8), cose_es256(x, y)),
        ];
        if let Some(t) = total {
            body.push((int(9), count(t)));
        }
        body.push((
            int(0x0A),
            Value::Uint(u64::from(APPLIED_CRED_PROTECT.level())),
        ));
        Ok(ok(&Value::Map(body)))
    }

    fn next_rp(&mut self, uid: Uid) -> Parsed<Vec<u8>> {
        let Some(CredMgmtCursor::Rps(mut rest)) = self.user(uid).cred_mgmt.take() else {
            return Err(status::NOT_ALLOWED);
        };
        if rest.is_empty() {
            return Err(status::NOT_ALLOWED);
        }
        let (id, name) = rest.remove(0);
        if !rest.is_empty() {
            self.user(uid).cred_mgmt = Some(CredMgmtCursor::Rps(rest));
        }
        Ok(ok(&rp_entry(&id, &name, None)))
    }

    fn next_credential(&mut self, uid: Uid) -> Parsed<Vec<u8>> {
        let Some(CredMgmtCursor::Credentials {
            rp_id_hash,
            mut entries,
        }) = self.user(uid).cred_mgmt.take()
        else {
            return Err(status::NOT_ALLOWED);
        };
        if entries.is_empty() {
            return Err(status::NOT_ALLOWED);
        }
        let e = entries.remove(0);
        let response = self.credential_entry(uid, &rp_id_hash, &e, None)?;
        if !entries.is_empty() {
            self.user(uid).cred_mgmt = Some(CredMgmtCursor::Credentials {
                rp_id_hash,
                entries,
            });
        }
        Ok(response)
    }
}

/// `getInfo` needs these.
impl<T: TpmOps> Authenticator<T> {
    pub(super) fn get_info(&mut self, uid: Uid, user: super::authn::UserInfo) -> Vec<u8> {
        let pin_set = self.pin_is_set(uid).unwrap_or(false);
        let used = self.tpm.resident_entries(uid).map(|e| e.len()).unwrap_or(0);
        super::info::get_info(super::info::InfoFacts {
            uv_enrolled: user.uv_enrolled,
            pin_set,
            remaining_resident: MAX_RESIDENT.saturating_sub(used),
        })
    }
}
