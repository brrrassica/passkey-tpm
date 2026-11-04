mod support;

use p256::ecdsa::signature::hazmat::PrehashVerifier;
use p256::ecdsa::{Signature, VerifyingKey};
use passkey_tpm_core::ctap2::{status, Authenticator, Command, Step, UserInfo};
use passkey_tpm_core::tpm_iface::{CredProtect, GateKind, RpIdHash, TpmOps, Uid};
use passkey_tpm_tpm::adapter::TpmBackend;
use passkey_tpm_tpm::nvgate;
use support::swtpm::Swtpm;
use tss_esapi::constants::CapabilityType;
use tss_esapi::structures::CapabilityData;

const RP: RpIdHash = RpIdHash([0x61; 32]);

fn state_dir(name: &str) -> std::path::PathBuf {
    let dir =
        std::env::temp_dir().join(format!("passkey-tpm-adapter-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    dir
}

/// NV indexes defined in our allocation range.
fn our_nv_indexes(ctx: &mut tss_esapi::Context) -> Vec<u32> {
    let (data, _) = ctx
        .get_capability(CapabilityType::Handles, nvgate::NV_BASE, 1024)
        .expect("handles");
    let CapabilityData::Handles(list) = data else {
        panic!("not a handle list");
    };
    list.iter()
        .map(|h| u32::from(*h))
        .filter(|i| (nvgate::NV_BASE..=nvgate::NV_LAST).contains(i))
        .collect()
}

/// HARD-09: read-only calls from a uid that never registered leave no trace.
#[test]
fn read_only_calls_provision_nothing() {
    let tpm = Swtpm::start();
    let dir = state_dir("readonly");
    let alice = Uid(1000);
    {
        let mut a = Authenticator::new(TpmBackend::new(tpm.context(), dir.clone()));
        let info = UserInfo { uv_enrolled: true };
        let Step::Done(resp) = a.prepare(alice, info, &[Command::GetInfo.code()], 0) else {
            panic!("getInfo needs no prompt");
        };
        assert_eq!(resp[0], status::OK);
        let backend = a.tpm_mut();
        assert_eq!(backend.pin_is_set(alice), Ok(false));
        assert_eq!(backend.pin_retries(alice), Ok(8));
        assert_eq!(backend.open_credential_id(alice, &RP, &[0; 80]), Ok(None));
        assert_eq!(backend.resident_entries(alice), Ok(Vec::new()));
        assert!(backend.verify_pin(alice, &[0; 16]).is_err(), "no PIN set");
    }
    assert!(!dir.join("1000").exists(), "no state dir");
    assert_eq!(our_nv_indexes(&mut tpm.context()), Vec::<u32>::new());
    {
        let mut backend = TpmBackend::new(tpm.context(), dir.clone());
        backend.reset_user(alice).expect("reset of an unknown user");
    }
    assert!(!dir.join("1000").exists(), "no state dir after reset");
    assert_eq!(our_nv_indexes(&mut tpm.context()), Vec::<u32>::new());
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn provisions_users_lazily_and_isolates_them() {
    let tpm = Swtpm::start();
    let dir = state_dir("isolate");
    let mut backend = TpmBackend::new(tpm.context(), dir.clone());
    let alice = Uid(1000);
    // authd/Entra-style uid far beyond the NV range: indexes are allocated, not derived.
    let bob = Uid(1_879_048_193);

    let blobs = backend
        .create_credential(alice, &RP, CredProtect::UvOptional, false)
        .expect("create");
    let id = backend.credential_id(alice, &RP, &blobs).expect("id");
    assert_eq!(
        backend.open_credential_id(alice, &RP, &id).expect("open"),
        Some(blobs.clone())
    );
    assert_eq!(
        backend
            .open_credential_id(bob, &RP, &id)
            .expect("open as bob"),
        None
    );
    assert_eq!(
        backend
            .open_credential_id(alice, &RpIdHash([0; 32]), &id)
            .expect("open other rp"),
        None
    );

    let digest = [0x5c; 32];
    let der = backend
        .sign(alice, &blobs, &RP, GateKind::Uv, &digest)
        .expect("sign");
    let (x, y) = backend.public_key(&blobs).expect("public key");
    let mut sec1 = vec![4u8];
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    VerifyingKey::from_sec1_bytes(&sec1)
        .expect("key")
        .verify_prehash(&digest, &Signature::from_der(&der).expect("der"))
        .expect("valid signature");

    assert!(
        backend
            .sign(bob, &blobs, &RP, GateKind::Uv, &digest)
            .is_err(),
        "bob can't use alice's key"
    );

    let mode = std::fs::metadata(dir.join("1000"))
        .expect("dir")
        .permissions();
    assert_eq!(
        std::os::unix::fs::PermissionsExt::mode(&mode) & 0o777,
        0o700
    );
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn state_survives_a_broker_restart() {
    let tpm = Swtpm::start();
    let dir = state_dir("restart");
    let alice = Uid(1000);
    let (blobs, id) = {
        let mut backend = TpmBackend::new(tpm.context(), dir.clone());
        let blobs = backend
            .create_credential(alice, &RP, CredProtect::UvOptional, false)
            .expect("create");
        let id = backend.credential_id(alice, &RP, &blobs).expect("id");
        (blobs, id)
    };
    let mut backend = TpmBackend::new(tpm.context(), dir.clone());
    assert_eq!(
        backend.open_credential_id(alice, &RP, &id).expect("open"),
        Some(blobs.clone())
    );
    backend
        .sign(alice, &blobs, &RP, GateKind::Uv, &[1; 32])
        .expect("sign after restart");
    backend.health().expect("healthy");
    std::fs::remove_dir_all(dir).expect("cleanup");
}

#[test]
fn revoked_credentials_stop_opening_and_survive_restart() {
    let tpm = Swtpm::start();
    let dir = state_dir("revoke");
    let alice = Uid(1000);
    let (keep, gone) = {
        let mut backend = TpmBackend::new(tpm.context(), dir.clone());
        let a = backend
            .create_credential(alice, &RP, CredProtect::UvRequired, false)
            .expect("create");
        let b = backend
            .create_credential(alice, &RP, CredProtect::UvRequired, false)
            .expect("create");
        let keep = backend.credential_id(alice, &RP, &a).expect("id");
        let gone = backend.credential_id(alice, &RP, &b).expect("id");
        backend.revoke_credential(alice, &gone).expect("revoke");
        backend.revoke_credential(alice, &gone).expect("idempotent");
        assert_eq!(
            backend.open_credential_id(alice, &RP, &gone).expect("open"),
            None
        );
        (keep, gone)
    };
    let mut backend = TpmBackend::new(tpm.context(), dir.clone());
    assert!(
        backend
            .open_credential_id(alice, &RP, &keep)
            .expect("open")
            .is_some(),
        "others unaffected"
    );
    assert_eq!(
        backend.open_credential_id(alice, &RP, &gone).expect("open"),
        None,
        "persisted"
    );
    std::fs::remove_dir_all(dir).expect("cleanup");
}
