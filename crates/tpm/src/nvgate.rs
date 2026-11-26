//! Gates as NV indexes (ADR 0003, AD-011, AD-013).
//!
//! Credentials reference a gate by Name through `PolicySecret`. An NV index can be used as
//! the `PolicySecret` authorisation object without `TPM2_Load`, which on firmware TPMs saves
//! hundreds of milliseconds per assertion compared with a sealed object.
//!
//! An NV index's Name is `nameAlg ‖ H(TPMS_NV_PUBLIC)` and doesn't cover the authValue, so
//! changing a gate's secret (the PIN) undefines and redefines the index with the same public
//! area: the Name, and every policy referring to it, stays the same, and nothing remains
//! that the old secret could unlock.
//!
//! The PIN gate is dictionary-attack protected (`noDA` clear); the UV and UP gates have
//! high-entropy secrets and set `noDA`, so they keep working during a DA lockout.

use tss_esapi::attributes::NvIndexAttributesBuilder;
use tss_esapi::constants::{CapabilityType, SessionType};
use tss_esapi::handles::{
    AuthHandle, NvIndexHandle, NvIndexTpmHandle, ObjectHandle, SessionHandle, TpmHandle,
};
use tss_esapi::interface_types::algorithm::HashingAlgorithm;
use tss_esapi::interface_types::resource_handles::Provision;
use tss_esapi::interface_types::session_handles::PolicySession;
use tss_esapi::structures::{
    Auth, CapabilityData, Digest, Nonce, NvPublic, NvPublicBuilder, SymmetricDefinition,
};
use tss_esapi::Context;

use crate::error::{Error, Result};
use crate::session;
use crate::srk::Srk;

/// First NV index we allocate from. The range is kept narrow (64 Ki indexes) because other
/// software (systemd, OEM tools) defines indexes elsewhere in the 0x01xxxxxx owner space;
/// confirming it against the TCG handle registry is a tracked todo.
pub const NV_BASE: u32 = 0x0150_0000;
/// Last index of our allocation range.
pub const NV_LAST: u32 = 0x0150_FFFF;

/// Whether a gate counts wrong secrets towards dictionary-attack lockout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lockout {
    /// PIN gate: low-entropy secret, protected by DA lockout.
    Protected,
    /// UV/UP gates: 32 random bytes, `noDA`.
    Exempt,
}

/// The public area of a gate. Must never change: it determines the Name.
///
/// # Errors
/// If `index` is not a valid NV index handle.
pub fn public(index: u32, lockout: Lockout) -> Result<NvPublic> {
    let attributes = NvIndexAttributesBuilder::new()
        .with_auth_read(true)
        .with_auth_write(true)
        .with_no_da(lockout == Lockout::Exempt)
        .build()?;
    Ok(NvPublicBuilder::new()
        .with_nv_index(NvIndexTpmHandle::new(index)?)
        .with_index_name_algorithm(HashingAlgorithm::Sha256)
        .with_index_attributes(attributes)
        .with_data_area_size(1)
        .build()?)
}

fn handle(ctx: &mut Context, index: u32) -> Result<NvIndexHandle> {
    let object = ctx.tr_from_tpm_public(TpmHandle::NvIndex(NvIndexTpmHandle::new(index)?))?;
    Ok(NvIndexHandle::from(object))
}

fn set_auth(ctx: &mut Context, nv: NvIndexHandle, auth: &[u8; 32]) -> Result<()> {
    Ok(ctx.tr_set_auth(ObjectHandle::from(nv), Auth::try_from(auth.to_vec())?)?)
}

fn clear_auth(ctx: &mut Context, nv: NvIndexHandle) -> Result<()> {
    Ok(ctx.tr_set_auth(ObjectHandle::from(nv), Auth::default())?)
}

/// Defines a gate at `index` with `auth` and returns its Name.
///
/// # Errors
/// TPM errors, e.g. if the index exists or the Owner hierarchy has a password.
pub fn define(
    ctx: &mut Context,
    srk: &Srk,
    index: u32,
    lockout: Lockout,
    auth: &[u8; 32],
) -> Result<Vec<u8>> {
    let tpm_auth = Auth::try_from(auth.to_vec())?;
    let public = public(index, lockout)?;
    // The new authValue is a command parameter: encrypted on a discrete TPM.
    let nv = session::with_auth(ctx, srk, |ctx| {
        Ok(ctx.nv_define_space(Provision::Owner, Some(tpm_auth), public)?)
    })?;
    let (_, name) = ctx.nv_read_public(nv)?;
    Ok(name.value().to_vec())
}

/// The gate's Name, checking its public area is still ours.
///
/// # Errors
/// [`Error::Corrupt`] if a different index occupies `index`.
pub fn name(ctx: &mut Context, index: u32, lockout: Lockout) -> Result<Vec<u8>> {
    let nv = handle(ctx, index)?;
    let (public_area, name) = ctx.nv_read_public(nv)?;
    if public_area != public(index, lockout)? {
        return Err(Error::Corrupt(
            "gate NV index has an unexpected public area",
        ));
    }
    Ok(name.value().to_vec())
}

/// `TPM2_PolicySecret(gate, policyRef)` inside `policy`, authorised with `auth`.
///
/// # Errors
/// TPM errors, including authorisation failure for a wrong `auth`.
pub fn satisfy(
    ctx: &mut Context,
    srk: &Srk,
    policy: PolicySession,
    index: u32,
    auth: &[u8; 32],
    policy_ref: &[u8],
) -> Result<()> {
    let nv = handle(ctx, index)?;
    set_auth(ctx, nv, auth)?;
    let policy_ref = Nonce::try_from(policy_ref.to_vec())?;
    let result = session::with_auth(ctx, srk, |ctx| {
        Ok(ctx.policy_secret(
            policy,
            AuthHandle::from(nv),
            Nonce::default(),
            Digest::default(),
            policy_ref,
            None,
        )?)
    });
    let clear = clear_auth(ctx, nv);
    result.and(clear).map(|_| ())
}

/// Checks `auth` against the gate with `PolicySecret` in a trial session. A wrong value is a
/// real authorisation failure and counts towards DA lockout for a protected gate.
///
/// # Errors
/// TPM errors (`TPM_RC_AUTH_FAIL`, lockout) if `auth` is wrong.
pub fn check(ctx: &mut Context, srk: &Srk, index: u32, auth: &[u8; 32]) -> Result<()> {
    let trial = ctx
        .start_auth_session(
            None,
            None,
            None,
            SessionType::Trial,
            SymmetricDefinition::AES_128_CFB,
            HashingAlgorithm::Sha256,
        )?
        .ok_or(Error::Corrupt("TPM returned no session"))?;
    let result = PolicySession::try_from(trial)
        .map_err(Error::from)
        .and_then(|policy| satisfy(ctx, srk, policy, index, auth, &[]));
    let _ = ctx.flush_context(SessionHandle::from(trial).into());
    result
}

/// Replaces a gate's secret: verifies `old`, then undefines and redefines the index with
/// `new`. The Name is unchanged. The caller must persist `new` first, so a crash between
/// the two steps can be repaired by [`redefine`] on the next start.
///
/// # Errors
/// TPM errors if `old` is wrong (nothing is changed then) or the TPM refuses.
pub fn rotate(
    ctx: &mut Context,
    srk: &Srk,
    index: u32,
    lockout: Lockout,
    old: &[u8; 32],
    new: &[u8; 32],
) -> Result<Vec<u8>> {
    check(ctx, srk, index, old)?;
    redefine(ctx, srk, index, lockout, new)
}

/// Defines the gate at `index` with `new`, first undefining it if it exists. Needs no old
/// secret, so it can complete a rotation that was interrupted between the undefine and the
/// define (or before either); the caller must have verified the old secret beforehand.
///
/// # Errors
/// [`Error::Corrupt`] if a different index occupies `index`; TPM errors otherwise.
pub fn redefine(
    ctx: &mut Context,
    srk: &Srk,
    index: u32,
    lockout: Lockout,
    new: &[u8; 32],
) -> Result<Vec<u8>> {
    let before = if exists(ctx, index)? {
        let before = name(ctx, index, lockout)?;
        undefine(ctx, index)?;
        Some(before)
    } else {
        None
    };
    let after = define(ctx, srk, index, lockout, new)?;
    if before.is_some_and(|b| b != after) {
        return Err(Error::Corrupt("gate Name changed on redefinition"));
    }
    Ok(after)
}

/// Whether an NV index is defined at `index`.
///
/// # Errors
/// TPM errors.
pub fn exists(ctx: &mut Context, index: u32) -> Result<bool> {
    let (data, _) =
        ctx.execute_without_session(|ctx| ctx.get_capability(CapabilityType::Handles, index, 1))?;
    let CapabilityData::Handles(list) = data else {
        return Err(Error::Corrupt("handle list"));
    };
    Ok(list.iter().next().is_some_and(|h| u32::from(*h) == index))
}

/// Removes a gate (Owner authorisation, empty by default).
///
/// # Errors
/// TPM errors.
pub fn undefine(ctx: &mut Context, index: u32) -> Result<()> {
    let nv = handle(ctx, index)?;
    ctx.execute_with_session(
        Some(tss_esapi::interface_types::session_handles::AuthSession::Password),
        |ctx| ctx.nv_undefine_space(Provision::Owner, nv),
    )?;
    Ok(())
}
