//! `passkey-tpm-uvd`: the passkey-tpm broker daemon (system service).
#![allow(clippy::print_stderr)]

use std::path::PathBuf;
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use passkey_tpm_tpm::adapter::TpmBackend;
use passkey_tpm_uvd::{serve, Broker, Logind, NssUsers, PromptBackend, TpmWorker};
use tss_esapi::tcti_ldr::TctiNameConf;
use tss_esapi::Context;

/// Default fingerprint window. A WebAuthn operation may legitimately take longer than the
/// old 30 s while the user finds the reader or retries a scan, and a browser that gives up
/// first produces a confusing failure. Override with `PASSKEY_UV_TIMEOUT_SECS`.
const DEFAULT_VERIFY_TIMEOUT_SECS: u64 = 60;

fn verify_timeout() -> Duration {
    let secs = std::env::var("PASSKEY_UV_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| *s > 0)
        .unwrap_or(DEFAULT_VERIFY_TIMEOUT_SECS);
    Duration::from_secs(secs)
}

#[tokio::main]
async fn main() -> ExitCode {
    let state_dir = std::env::var_os("STATE_DIRECTORY")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/passkey-tpm"));
    let tcti =
        std::env::var("PASSKEY_TPM_TCTI").unwrap_or_else(|_| "device:/dev/tpmrm0".to_owned());
    let tcti = match TctiNameConf::from_str(&tcti) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("invalid PASSKEY_TPM_TCTI: {e}");
            return ExitCode::FAILURE;
        }
    };

    // Fail early if the TPM is unreachable, then hand the context to the worker thread.
    if let Err(e) = Context::new(tcti.clone()) {
        eprintln!("cannot open TPM: {e}");
        return ExitCode::FAILURE;
    }
    let worker = match TpmWorker::spawn(move || {
        let ctx = Context::new(tcti).unwrap_or_else(|e| {
            eprintln!("cannot open TPM: {e}");
            std::process::exit(1);
        });
        TpmBackend::new(ctx, state_dir)
    }) {
        Ok(w) => w,
        Err(e) => {
            eprintln!("cannot start TPM worker: {e}");
            return ExitCode::FAILURE;
        }
    };

    let conn = match zbus::Connection::system().await {
        Ok(c) => c,
        Err(e) => {
            eprintln!("cannot connect to the system bus: {e}");
            return ExitCode::FAILURE;
        }
    };
    let watchdog = worker.clone();
    let prompt = PromptBackend::detect();
    eprintln!("user-verification prompt: {prompt:?}");
    let broker = Broker::new(
        worker,
        conn.clone(),
        Box::new(NssUsers),
        Box::new(Logind::new(conn.clone())),
        verify_timeout(),
        prompt,
    );
    if let Err(e) = serve(&conn, broker).await {
        eprintln!("cannot export the broker: {e}");
        return ExitCode::FAILURE;
    }
    eprintln!("passkey-tpm-uvd ready");
    tokio::select! {
        _ = tokio::signal::ctrl_c() => ExitCode::SUCCESS,
        () = watchdog.closed() => {
            // Every request would now fail with CTAP2_ERR_OTHER; exit so systemd restarts us.
            eprintln!("TPM worker thread died; exiting");
            ExitCode::FAILURE
        }
    }
}
