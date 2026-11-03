//! The authenticator: two-phase request processing over a [`TpmOps`] backend.
//!
//! [`Authenticator::prepare`] parses and validates a request and either answers it or asks
//! the broker for a fingerprint match ([`Step::NeedUv`]) or, for users without an enrolled
//! fingerprint, for a presence confirmation ([`Step::NeedPresence`], AD-022);
//! [`Authenticator::complete`] finishes it with the outcome. A signature is only produced
//! from a [`UvEvidence`], built either from a fingerprint match or from a verified
//! pinUvAuthToken.

use std::collections::HashMap;

use super::common::{error, status, Parsed};
use super::state::{HmacRequest, UserState};
use crate::evidence::UvEvidence;
use crate::pin_protocol::{self, Protocol};
use crate::tpm_iface::{RpIdHash, TpmOps, Uid};

/// Per-request facts the core can't discover itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserInfo {
    /// fprintd has at least one enrolled finger for this user.
    pub uv_enrolled: bool,
}

/// Result of [`Authenticator::prepare`].
#[derive(Debug)]
pub enum Step {
    /// Final response (status byte followed by CBOR, if any).
    Done(Vec<u8>),
    /// A fingerprint match is required; show a prompt naming `pending.rp_id()`.
    NeedUv(Box<Pending>),
    /// The user has no enrolled fingerprint: only presence is missing (UV, where needed,
    /// came from a verified PIN token). Ask the user to confirm `pending.rp_id()` and
    /// complete with [`UvOutcome::Present`] or [`UvOutcome::Denied`].
    NeedPresence(Box<Pending>),
}

/// Outcome of the fingerprint check or presence confirmation the broker ran for a
/// [`Pending`] request.
#[derive(Debug)]
pub enum UvOutcome {
    Matched(UvEvidence),
    /// The user confirmed presence. Accepted only for [`Step::NeedPresence`] requests.
    Present,
    /// The user refused the presence confirmation.
    Denied,
    NoMatch,
    Cancelled,
    TimedOut,
    Unavailable,
}

/// A validated request waiting for user verification.
#[derive(Debug)]
pub struct Pending {
    pub(super) uid: Uid,
    pub(super) rp_id: String,
    pub(super) kind: PendingKind,
    /// Created by [`Step::NeedPresence`]: presence alone completes it.
    pub(super) presence_only: bool,
}

impl Pending {
    /// The relying party (or purpose) to name in the prompt.
    #[must_use]
    pub fn rp_id(&self) -> &str {
        &self.rp_id
    }
}

#[derive(Debug)]
pub(super) enum PendingKind {
    MakeCredential(super::make_credential::Request),
    GetAssertion(super::get_assertion::Request),
    /// A zero-length pinUvAuthParam: the platform asks for a touch to select this device.
    TouchThen(u8),
    TokenUsingUv(super::client_pin::TokenRequest),
    Reset,
    Selection,
}

/// The CTAP2 authenticator logic over a TPM backend.
#[derive(Debug)]
pub struct Authenticator<T: TpmOps> {
    pub(super) tpm: T,
    pub(super) users: HashMap<u32, UserState>,
}

/// A pinUvAuthParam to check: over `message`, for permission `perm` and relying party `rp`.
#[derive(Debug, Clone, Copy)]
pub(super) struct AuthCheck<'a> {
    pub protocol: Option<u64>,
    pub param: &'a [u8],
    pub message: &'a [u8],
    pub perm: u8,
    pub rp: Option<&'a RpIdHash>,
}

/// Where a request's user verification comes from.
#[derive(Debug)]
pub(super) enum Verification {
    /// A valid pinUvAuthParam; `user_present` if the token still carried presence.
    Token { user_present: bool },
    /// No pinUvAuthParam: a fingerprint gesture provides UP and UV.
    Gesture,
}

impl<T: TpmOps> Authenticator<T> {
    #[must_use]
    pub fn new(tpm: T) -> Self {
        Self {
            tpm,
            users: HashMap::new(),
        }
    }

    /// Access to the backend (health checks).
    pub fn tpm_mut(&mut self) -> &mut T {
        &mut self.tpm
    }

    pub(super) fn user(&mut self, uid: Uid) -> &mut UserState {
        self.users.entry(uid.0).or_default()
    }

    /// Phase 1. `now_ms` is a monotonic clock in milliseconds.
    pub fn prepare(&mut self, uid: Uid, user: UserInfo, request: &[u8], now_ms: u64) -> Step {
        use super::common::cmd;
        let Some((&command, params)) = request.split_first() else {
            return Step::Done(error(status::INVALID_LENGTH));
        };
        // Any command other than getNextAssertion ends a multi-credential assertion
        // (CTAP 2.1 §6.3); any command other than the credMgmt GetNext* ends enumeration.
        if command != cmd::GET_NEXT_ASSERTION {
            self.user(uid).next_assertion = None;
        }
        if command != cmd::CREDENTIAL_MANAGEMENT && command != cmd::CREDENTIAL_MANAGEMENT_PREVIEW {
            self.user(uid).cred_mgmt = None;
        }
        let result = match command {
            cmd::GET_INFO => Ok(Step::Done(self.get_info(uid, user))),
            cmd::MAKE_CREDENTIAL => self.prepare_make_credential(uid, user, params, now_ms),
            cmd::GET_ASSERTION => self.prepare_get_assertion(uid, user, params, now_ms),
            cmd::GET_NEXT_ASSERTION => self.get_next_assertion(uid, now_ms).map(Step::Done),
            cmd::CLIENT_PIN => self.client_pin(uid, user, params, now_ms),
            cmd::CREDENTIAL_MANAGEMENT | cmd::CREDENTIAL_MANAGEMENT_PREVIEW => self
                .credential_management(uid, params, now_ms)
                .map(Step::Done),
            cmd::RESET => Self::need_gesture(uid, user, "reset passkey-tpm", PendingKind::Reset),
            cmd::SELECTION => {
                Self::need_gesture(uid, user, "select passkey-tpm", PendingKind::Selection)
            }
            _ => Err(status::INVALID_COMMAND),
        };
        result.unwrap_or_else(|code| Step::Done(error(code)))
    }

    /// Phase 2: finish a request after the fingerprint check.
    pub fn complete(&mut self, pending: Box<Pending>, outcome: UvOutcome, now_ms: u64) -> Vec<u8> {
        let uid = pending.uid;
        let ev = match outcome {
            UvOutcome::Matched(ev) if ev.uid() == uid.0 => {
                self.user(uid).uv_failures = 0;
                Some(ev)
            }
            UvOutcome::Matched(_) => return error(status::OPERATION_DENIED),
            // Presence never stands in for a fingerprint the request asked for.
            UvOutcome::Present if pending.presence_only => None,
            UvOutcome::Present | UvOutcome::Denied => return error(status::OPERATION_DENIED),
            UvOutcome::NoMatch => {
                let state = self.user(uid);
                state.uv_failures = state.uv_failures.saturating_add(1);
                let blocked = state.uv_failures >= super::common::MAX_UV_RETRIES;
                return error(match pending.kind {
                    PendingKind::TokenUsingUv(_) if blocked => status::UV_BLOCKED,
                    PendingKind::TokenUsingUv(_) => status::UV_INVALID,
                    // CTAP 2.1 §6.5.2.2: the mismatch that reaches the uvRetries limit is
                    // reported as UV_BLOCKED, not as a generic denial; later requests are
                    // refused with the same code by `check_builtin_uv`.
                    _ if blocked => status::UV_BLOCKED,
                    // A single mismatch is an ordinary refusal; the platform may retry.
                    _ => status::OPERATION_DENIED,
                });
            }
            UvOutcome::Cancelled => return error(status::KEEPALIVE_CANCEL),
            UvOutcome::TimedOut => return error(status::USER_ACTION_TIMEOUT),
            UvOutcome::Unavailable => return error(status::NOT_ALLOWED),
        };
        // A presence-only makeCredential/getAssertion was created only after its
        // pinUvAuthParam verified against a userVerified token (`gesture`, AD-022).
        let token_ev = || UvEvidence::from_token(uid.0);
        let result = match pending.kind {
            PendingKind::TouchThen(code) => Err(code),
            PendingKind::MakeCredential(req) => {
                self.finish_make_credential(uid, req, ev.unwrap_or_else(token_ev))
            }
            PendingKind::GetAssertion(req) => {
                self.finish_get_assertion(uid, req, ev.unwrap_or_else(token_ev), now_ms)
            }
            // Built-in UV only: never completed by presence.
            PendingKind::TokenUsingUv(_) if ev.is_none() => Err(status::OPERATION_DENIED),
            PendingKind::TokenUsingUv(req) => self.finish_token_using_uv(uid, req, now_ms),
            PendingKind::Reset => {
                let r = self
                    .tpm
                    .reset_user(uid)
                    .map_err(super::common::map_tpm_error);
                self.users.remove(&uid.0);
                r.map(|()| super::common::ok_empty())
            }
            PendingKind::Selection => Ok(super::common::ok_empty()),
        };
        result.unwrap_or_else(error)
    }

    /// Reset and selection only need presence: a fingerprint touch, or a presence
    /// confirmation for users without an enrolled fingerprint (AD-022).
    fn need_gesture(uid: Uid, user: UserInfo, prompt: &str, kind: PendingKind) -> Parsed<Step> {
        let pending = |presence_only| {
            Box::new(Pending {
                uid,
                rp_id: prompt.to_owned(),
                kind,
                presence_only,
            })
        };
        Ok(if user.uv_enrolled {
            Step::NeedUv(pending(false))
        } else {
            Step::NeedPresence(pending(true))
        })
    }

    pub(super) fn pin_is_set(&mut self, uid: Uid) -> Parsed<bool> {
        self.tpm
            .pin_is_set(uid)
            .map_err(super::common::map_tpm_error)
    }

    /// Fails with `PIN_BLOCKED` once the persisted PIN retries reach 0 (AD-010).
    pub(super) fn check_pin_not_blocked(&mut self, uid: Uid) -> Parsed<()> {
        let retries = self
            .tpm
            .pin_retries(uid)
            .map_err(super::common::map_tpm_error)?;
        if retries == 0 {
            return Err(status::PIN_BLOCKED);
        }
        Ok(())
    }

    /// Whether built-in UV (a fingerprint match) may be attempted: `UV_BLOCKED` after
    /// [`MAX_UV_RETRIES`](super::common::MAX_UV_RETRIES) consecutive mismatches, and
    /// `PIN_BLOCKED` when the PIN is blocked, which disables built-in UV too
    /// (CTAP 2.1 §6.5.2.2, AD-010). Checked before any fingerprint prompt.
    pub(super) fn check_builtin_uv(&mut self, uid: Uid) -> Parsed<()> {
        if self.user(uid).uv_failures >= super::common::MAX_UV_RETRIES {
            return Err(status::UV_BLOCKED);
        }
        self.check_pin_not_blocked(uid)
    }

    /// Checks only that `param` is a valid MAC over `message` under the current token, with
    /// no permission or RP check. Lets a command authenticate the caller before a lookup
    /// whose result it must not reveal to an unauthenticated one (HARD-14);
    /// [`verify_auth_param`](Self::verify_auth_param) must still run afterwards.
    pub(super) fn verify_auth_mac(
        &mut self,
        uid: Uid,
        protocol: Option<u64>,
        param: &[u8],
        message: &[u8],
    ) -> Parsed<()> {
        let protocol = protocol.ok_or(status::MISSING_PARAMETER)?;
        let protocol = Protocol::from_u64(protocol).ok_or(status::INVALID_PARAMETER)?;
        let Some(issued) = self.user(uid).token.as_ref() else {
            return Err(status::PIN_AUTH_INVALID);
        };
        if issued.protocol != protocol
            || !pin_protocol::verify_with_token(protocol, issued.token.secret(), message, param)
        {
            return Err(status::PIN_AUTH_INVALID);
        }
        Ok(())
    }

    /// Validates `pinUvAuthParam` over `message` for permission `perm` and relying party
    /// `rp` (CTAP 2.1 §6.1.2 steps 1–9 and §6.2.2). Binds an unbound token to `rp`.
    pub(super) fn verify_auth_param(
        &mut self,
        uid: Uid,
        check: &AuthCheck<'_>,
        now_ms: u64,
    ) -> Parsed<Verification> {
        let AuthCheck {
            protocol,
            param,
            message,
            perm,
            rp,
        } = *check;
        self.verify_auth_mac(uid, protocol, param, message)?;
        let Some(issued) = self.user(uid).token.as_mut() else {
            return Err(status::PIN_AUTH_INVALID);
        };
        let grant = &mut issued.token.grant;
        let permitted = match rp {
            Some(rp) => grant.allows(perm, &rp.0, now_ms),
            // Commands without an RP (credMgmt metadata, RP enumeration) need an unbound token.
            None => grant.allows_unbound(perm, now_ms),
        };
        if !permitted {
            return Err(status::PIN_AUTH_INVALID);
        }
        if !grant.user_verified() {
            return Err(status::PIN_AUTH_INVALID);
        }
        // Binding on first use applies to makeCredential/getAssertion (CTAP 2.1 §6.1.2,
        // §6.2.2); credential management only checks an existing binding.
        if let Some(rp) = rp {
            if perm & (crate::token::PERM_MC | crate::token::PERM_GA) != 0 {
                grant.bind_rp(&rp.0);
            }
        }
        Ok(Verification::Token {
            user_present: grant.take_user_present(),
        })
    }

    /// hmac-secret salts for getAssertion (CTAP 2.1 §12.5).
    pub(super) fn parse_hmac_secret(
        &mut self,
        uid: Uid,
        ext: &passkey_tpm_wire::cbor::Value,
    ) -> Parsed<HmacRequest> {
        use super::common::{get, opt_uint};
        let key = get(ext, 1).ok_or(status::MISSING_PARAMETER)?;
        let salt_enc = get(ext, 2)
            .and_then(|v| v.as_bytes())
            .ok_or(status::MISSING_PARAMETER)?;
        let salt_auth = get(ext, 3)
            .and_then(|v| v.as_bytes())
            .ok_or(status::MISSING_PARAMETER)?;
        let protocol = opt_uint(get(ext, 4))?.unwrap_or(1);
        let protocol = Protocol::from_u64(protocol).ok_or(status::INVALID_PARAMETER)?;
        let platform =
            pin_protocol::parse_platform_key(key).map_err(|_| status::INVALID_PARAMETER)?;
        let shared = self
            .user(uid)
            .key_agreement()?
            .shared_secret(protocol, &platform)
            .map_err(|_| status::INVALID_PARAMETER)?;
        if !shared.verify(salt_enc, salt_auth) {
            return Err(status::PIN_AUTH_INVALID);
        }
        let salts = shared
            .decrypt(salt_enc)
            .map_err(|_| status::INVALID_LENGTH)?;
        let (salt1, salt2) = match salts.len() {
            32 => (salts.get(..32), None),
            64 => (salts.get(..32), salts.get(32..)),
            _ => return Err(status::INVALID_LENGTH),
        };
        let salt1: [u8; 32] = salt1
            .and_then(|s| s.try_into().ok())
            .ok_or(status::INVALID_LENGTH)?;
        let salt2 = salt2
            .map(|s| s.try_into().map_err(|_| status::INVALID_LENGTH))
            .transpose()?;
        Ok(HmacRequest {
            shared,
            salt1,
            salt2,
        })
    }
}
