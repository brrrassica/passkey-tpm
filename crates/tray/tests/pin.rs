//! The tray's PIN client against the real broker (swtpm, private bus, user without
//! fingerprints).

use std::time::Duration;

use passkey_tpm_testkit::bus::PrivateBus;
use passkey_tpm_testkit::swtpm::Swtpm;
use passkey_tpm_tpm::adapter::TpmBackend;
use passkey_tpm_tray::pin::{self, PinError};
use passkey_tpm_uv::mock::{self, MockFprintd};
use passkey_tpm_uvd::{serve, Broker, SessionPolicy, TpmWorker, UserLookup};
use tss_esapi::Context;

struct Alice;
impl UserLookup for Alice {
    fn username(&self, _uid: u32) -> Option<String> {
        Some("alice".to_owned())
    }
}

struct AtSeat;
impl SessionPolicy for AtSeat {
    fn is_active<'a>(
        &'a self,
        _uid: u32,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = bool> + Send + 'a>> {
        Box::pin(std::future::ready(true))
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn set_then_change_the_pin_through_the_broker() {
    let tpm = Swtpm::start();
    let bus = PrivateBus::start();
    let fprintd = bus.connect().await;
    mock::serve(&fprintd, MockFprintd::default().without_enrolled())
        .await
        .unwrap();
    let state = std::env::temp_dir().join(format!("passkey-tpm-tray-pin-{}", std::process::id()));
    let (tcti, dir) = (tpm.tcti(), state.clone());
    let worker =
        TpmWorker::spawn(move || TpmBackend::new(Context::new(tcti).unwrap(), dir)).unwrap();
    let broker_conn = bus.connect().await;
    let broker = Broker::new(
        worker,
        broker_conn.clone(),
        Box::new(Alice),
        Box::new(AtSeat),
        Duration::from_secs(5),
        passkey_tpm_uvd::PromptBackend::Fprintd,
    );
    serve(&broker_conn, broker).await.unwrap();
    let client = bus.connect().await;

    assert_eq!(pin::is_set(&client).await, Ok(false));
    assert_eq!(
        pin::change(&client, "1234", "5678").await,
        Err(PinError::Status(0x35)),
        "PIN_NOT_SET"
    );
    pin::set(&client, "1234").await.unwrap();
    assert_eq!(pin::is_set(&client).await, Ok(true));
    assert_eq!(
        pin::set(&client, "9999").await,
        Err(PinError::Status(0x30)),
        "already set"
    );
    assert_eq!(
        pin::change(&client, "0000", "5678").await,
        Err(PinError::Status(0x31)),
        "wrong current PIN"
    );
    pin::change(&client, "1234", "5678").await.unwrap();
    assert_eq!(
        pin::change(&client, "1234", "9999").await,
        Err(PinError::Status(0x31)),
        "old PIN no longer works"
    );
    let _ = std::fs::remove_dir_all(&state);
}
