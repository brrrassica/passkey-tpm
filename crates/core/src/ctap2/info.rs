//! authenticatorGetInfo (CTAP 2.1 §6.4, M2-01).
//!
//! Every member here is a promise the rest of the authenticator has to keep, so the 0.2.0
//! audit (M3.1) checked each one against the implementation:
//!
//! - `plat` stays `false` on purpose: this is a virtual *cross-platform* security key, and
//!   `true` would make platforms treat it as a platform authenticator (the wrong UI).
//! - `uv` and `clientPin` are capability flags, not configuration: they stay present and
//!   switch to `false` while the fingerprint is not enrolled or the PIN is not set.
//! - `pinUvAuthToken` is true because both `getPinUvAuthTokenUsingPinWithPermissions` and
//!   `getPinUvAuthTokenUsingUvWithPermissions` are implemented.
//! - `makeCredUvNotRqd` is `false` because makeCredential always requires user verification
//!   (fingerprint or a PIN token).
//! - `alwaysUv` is absent because the toggleable Always-UV feature (with its CTAP1/U2F
//!   consequences) is not implemented; per-operation UV enforcement plus
//!   `makeCredUvNotRqd: false` carries the same information.
//! - `authnrCfg`, `bioEnroll`, `largeBlobs`, `ep`, `credentialMgmtPreview`, `uvBioEnroll`,
//!   `uvAcfg`, `setMinPINLength`, and `noMcGaPermissionsWithClientPin` are absent because the
//!   matching commands or features are not implemented.
//! - `extensions` lists only `credProtect` and `hmac-secret`, both implemented end to end.
//! - the size, count, and ID-length limits are taken from the enforcing code, not literals.

use passkey_tpm_wire::cbor::Value;

use super::common::{
    int, ok, text, AAGUID, ES256, MAX_CREDENTIAL_COUNT_IN_LIST, MAX_CREDENTIAL_ID_LENGTH,
    MAX_MSG_SIZE, MIN_PIN_LENGTH,
};

/// Fingerprint, from the FIDORegistry "User Verification Methods" bit-flags.
///
/// `clientPin` must not be included in `uvModality`: it is not a built-in verification method.
const UV_MODALITY_FINGERPRINT: u64 = 0x02;

/// Facts about the user the response depends on.
#[derive(Debug, Clone, Copy)]
pub struct InfoFacts {
    pub uv_enrolled: bool,
    pub pin_set: bool,
    pub remaining_resident: usize,
}

/// One `major.minor.patch` field of `version`, or 0 when it is absent or unparsable.
fn version_field(version: &str, index: usize) -> u64 {
    version
        .split(|c: char| !c.is_ascii_digit())
        .filter(|part| !part.is_empty())
        .nth(index)
        .and_then(|part| part.parse::<u64>().ok())
        .filter(|n| *n <= 0xFF)
        .unwrap_or(0)
}

/// `firmwareVersion` encoding: `major << 16 | minor << 8 | patch` (CTAP 2.1 §6.4).
///
/// A pre-release suffix (`-beta.2`) is not representable and is dropped, but the numeric
/// release still changes, which is what the spec requires ("MUST increase the version").
#[must_use]
pub fn encode_firmware_version(version: &str) -> u64 {
    (version_field(version, 0) << 16) | (version_field(version, 1) << 8) | version_field(version, 2)
}

/// The advertised `firmwareVersion`, derived from the crate version so it cannot go stale.
#[must_use]
pub fn firmware_version() -> u64 {
    encode_firmware_version(env!("CARGO_PKG_VERSION"))
}

pub fn get_info(f: InfoFacts) -> Vec<u8> {
    let count = |n: u64| Value::Uint(n);
    ok(&Value::Map(vec![
        (
            int(0x01),
            Value::Array(vec![text("FIDO_2_0"), text("FIDO_2_1")]),
        ),
        (
            int(0x02),
            Value::Array(vec![text("credProtect"), text("hmac-secret")]),
        ),
        (int(0x03), Value::Bytes(AAGUID.to_vec())),
        (
            int(0x04),
            Value::Map(vec![
                (text("rk"), Value::Bool(true)),
                (text("up"), Value::Bool(true)),
                // Built-in UV exists; `false` means "capable but not configured" (§6.4).
                (text("uv"), Value::Bool(f.uv_enrolled)),
                (text("plat"), Value::Bool(false)),
                (text("credMgmt"), Value::Bool(true)),
                // Both token subcommands exist; `false` means "supported, no PIN set".
                (text("clientPin"), Value::Bool(f.pin_set)),
                (text("pinUvAuthToken"), Value::Bool(true)),
                (text("makeCredUvNotRqd"), Value::Bool(false)),
            ]),
        ),
        (int(0x05), Value::Uint(MAX_MSG_SIZE)),
        (
            int(0x06),
            Value::Array(vec![Value::Uint(2), Value::Uint(1)]),
        ),
        (int(0x07), count(MAX_CREDENTIAL_COUNT_IN_LIST as u64)),
        (int(0x08), Value::Uint(MAX_CREDENTIAL_ID_LENGTH)),
        (int(0x09), Value::Array(vec![text("usb")])),
        (
            int(0x0A),
            Value::Array(vec![Value::Map(vec![
                (text("alg"), int(ES256)),
                (text("type"), text("public-key")),
            ])]),
        ),
        (int(0x0D), count(MIN_PIN_LENGTH as u64)),
        (int(0x0E), Value::Uint(firmware_version())),
        // Hint for the platform's UV dialog; matches how UV is actually performed.
        (int(0x12), Value::Uint(UV_MODALITY_FINGERPRINT)),
        (int(0x14), count(f.remaining_resident as u64)),
    ]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn firmware_version_is_a_derived_encoding() {
        assert_eq!(encode_firmware_version("0.1.0-beta.2"), 0x0000_0100);
        assert_eq!(encode_firmware_version("0.2.0"), 0x0000_0200);
        assert_eq!(encode_firmware_version("2.3.4"), 0x0002_0304);
        // Missing or junk fields degrade to 0 instead of panicking.
        assert_eq!(encode_firmware_version("7"), 0x0007_0000);
        assert_eq!(encode_firmware_version(""), 0);
        assert_eq!(encode_firmware_version("not-a-version"), 0);
        // The advertised value always follows the crate version.
        assert_eq!(
            firmware_version(),
            encode_firmware_version(env!("CARGO_PKG_VERSION"))
        );
    }
}
