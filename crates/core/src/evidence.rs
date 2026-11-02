//! User-verification evidence and the authenticator-data flags it allows (MVP1-05).
//!
//! A [`UvEvidence`] value stands for "the broker verified this uid during this request":
//! either fprintd reported `verify-match`, or polkit authorized the caller through the
//! desktop prompt (whose PAM stack performs the scan). The broker creates one only after
//! that happens, and the core consumes it to build authenticator data and to choose the
//! TPM gate. Verus proves the UV flag is set
//! exactly when evidence is present, and that evidence always selects a UV gate, so the TPM
//! policy and the flags in the signed data can't disagree.

use vstd::prelude::*;

use crate::gates::GateKind;

verus! {

/// `authenticatorData` flag bits (WebAuthn §6.1).
pub const FLAG_UP: u8 = 0x01;
pub const FLAG_UV: u8 = 0x04;
pub const FLAG_AT: u8 = 0x40;
pub const FLAG_ED: u8 = 0x80;

/// How the user was verified.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UvMethod {
    /// fprintd reported `verify-match` in this request.
    Fingerprint,
    /// polkit authorized the caller through the desktop prompt in this request. PAM
    /// performed the check; Omarchy's agent uses the fingerprint reader when
    /// `pam_fprintd.so` is in `/etc/pam.d/polkit-1`.
    Polkit,
    /// A valid pinUvAuthParam on a token with `userVerified` (PIN or earlier fingerprint).
    PinUvAuthToken,
}

/// Proof that the calling user was verified for this request.
#[derive(Debug, PartialEq, Eq)]
pub struct UvEvidence {
    uid: u32,
    method: UvMethod,
}

impl UvEvidence {
    pub closed spec fn spec_uid(&self) -> u32 {
        self.uid
    }

    /// Call **only** after fprintd reported `verify-match` (done) for `uid` in the current
    /// request. Deliberately not `Clone`: one gesture, one use.
    pub fn from_fprintd_match(uid: u32) -> (ev: Self)
        ensures
            ev.spec_uid() == uid,
    {
        UvEvidence { uid, method: UvMethod::Fingerprint }
    }

    /// Call **only** after polkit authorized `uid` for the passkey action in this request.
    /// The desktop PAM stack performed the verification (fingerprint, or its configured
    /// password fallback). Deliberately not `Clone`: one authorization, one use.
    pub fn from_polkit_authorization(uid: u32) -> (ev: Self)
        ensures
            ev.spec_uid() == uid,
    {
        UvEvidence { uid, method: UvMethod::Polkit }
    }

    /// Call **only** after verifying a pinUvAuthParam against a token issued to `uid` with
    /// `userVerified` set.
    pub fn from_token(uid: u32) -> (ev: Self)
        ensures
            ev.spec_uid() == uid,
    {
        UvEvidence { uid, method: UvMethod::PinUvAuthToken }
    }

    pub fn method(&self) -> UvMethod {
        self.method
    }

    pub fn uid(&self) -> (u: u32)
        ensures
            u == self.spec_uid(),
    {
        self.uid
    }

    /// The TPM gate this evidence unlocks: always a UV gate.
    pub fn gate(&self) -> (g: GateKind)
        ensures
            g.spec_is_uv(),
            g == GateKind::Uv,
    {
        GateKind::Uv
    }
}

pub open spec fn spec_has_flag(flags: u8, bit: u8) -> bool {
    flags & bit == bit
}

/// Flags for authenticator data produced with UV evidence. UP is always set: every
/// operation includes a presence gesture (fingerprint touch or a token's consumed presence).
/// AT marks attested credential data, ED extension outputs.
pub fn uv_flags(_ev: &UvEvidence, attested: bool, extensions: bool) -> (f: u8)
    ensures
        spec_has_flag(f, FLAG_UP),
        spec_has_flag(f, FLAG_UV),
        spec_has_flag(f, FLAG_AT) == attested,
        spec_has_flag(f, FLAG_ED) == extensions,
        // No other bits (BE, BS, reserved) are ever set.
        f & !(FLAG_UP | FLAG_UV | FLAG_AT | FLAG_ED) == 0,
{
    // Four possible values; each one's bits are proven below.
    let f: u8 = match (attested, extensions) {
        (false, false) => 0x05,
        (true, false) => 0x45,
        (false, true) => 0x85,
        (true, true) => 0xC5,
    };
    assert(0x05u8 & 0x01u8 == 0x01u8 && 0x05u8 & 0x04u8 == 0x04u8 && 0x05u8 & 0x40u8 != 0x40u8 && 0x05u8 & 0x80u8 != 0x80u8 && 0x05u8 & !(0x01u8 | 0x04u8 | 0x40u8 | 0x80u8) == 0) by (bit_vector);
    assert(0x45u8 & 0x01u8 == 0x01u8 && 0x45u8 & 0x04u8 == 0x04u8 && 0x45u8 & 0x40u8 == 0x40u8 && 0x45u8 & 0x80u8 != 0x80u8 && 0x45u8 & !(0x01u8 | 0x04u8 | 0x40u8 | 0x80u8) == 0) by (bit_vector);
    assert(0x85u8 & 0x01u8 == 0x01u8 && 0x85u8 & 0x04u8 == 0x04u8 && 0x85u8 & 0x40u8 != 0x40u8 && 0x85u8 & 0x80u8 == 0x80u8 && 0x85u8 & !(0x01u8 | 0x04u8 | 0x40u8 | 0x80u8) == 0) by (bit_vector);
    assert(0xC5u8 & 0x01u8 == 0x01u8 && 0xC5u8 & 0x04u8 == 0x04u8 && 0xC5u8 & 0x40u8 == 0x40u8 && 0xC5u8 & 0x80u8 == 0x80u8 && 0xC5u8 & !(0x01u8 | 0x04u8 | 0x40u8 | 0x80u8) == 0) by (bit_vector);
    f
}

} // verus!

/// `authenticatorData` (WebAuthn §6.1): `rpIdHash ‖ flags ‖ signCount (always 0, AD-010)
/// ‖ attestedCredentialData? ‖ extensions?` (`extensions` is an encoded CBOR map).
#[must_use]
pub fn auth_data(
    rp_id_hash: &[u8; 32],
    ev: &UvEvidence,
    attested: Option<&[u8]>,
    extensions: Option<&[u8]>,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        37 + attested.map_or(0, <[u8]>::len) + extensions.map_or(0, <[u8]>::len),
    );
    out.extend_from_slice(rp_id_hash);
    out.push(uv_flags(ev, attested.is_some(), extensions.is_some()));
    out.extend_from_slice(&0u32.to_be_bytes());
    if let Some(data) = attested {
        out.extend_from_slice(data);
    }
    if let Some(ext) = extensions {
        out.extend_from_slice(ext);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn auth_data_layout() {
        let ev = UvEvidence::from_fprintd_match(1000);
        let ad = auth_data(&[7; 32], &ev, None, None);
        assert_eq!(ad.len(), 37);
        assert_eq!(&ad[..32], &[7; 32]);
        assert_eq!(ad[32], FLAG_UP | FLAG_UV);
        assert_eq!(&ad[33..], &[0, 0, 0, 0]);
        let ad = auth_data(&[7; 32], &ev, Some(&[1, 2, 3]), None);
        assert_eq!(ad[32], FLAG_UP | FLAG_UV | FLAG_AT);
        assert_eq!(&ad[37..], &[1, 2, 3]);
        let ad = auth_data(&[7; 32], &ev, None, Some(&[0xa0]));
        assert_eq!(ad[32], FLAG_UP | FLAG_UV | FLAG_ED);
        assert_eq!(UvEvidence::from_token(5).method(), UvMethod::PinUvAuthToken);
        let polkit = UvEvidence::from_polkit_authorization(1000);
        assert_eq!(polkit.method(), UvMethod::Polkit);
        assert_eq!(polkit.uid(), 1000);
        assert_eq!(polkit.gate(), GateKind::Uv);
        assert_eq!(ev.gate(), GateKind::Uv);
        assert_eq!(ev.uid(), 1000);
    }
}
