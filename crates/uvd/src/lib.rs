//! passkey-tpm broker (ADR 0003): the only process that uses passkey keys in the TPM.
//!
//! Callers reach it over the system bus. The calling user is taken from the bus
//! (`GetConnectionUnixUser`), never from request data, and every operation is confined to
//! that user's credentials. Fingerprint verification runs here, against fprintd, for that
//! user only; a [`UvEvidence`] is created only from fprintd's `verify-match`. Requests are
//! served only while the calling user has an active session on a local seat
//! ([`passkey_tpm_uv::seat`]).
//!
//! Users without an enrolled fingerprint confirm presence instead (AD-022): the broker
//! sends a `PresenceRequested(id, prompt)` signal to the connection that made the `Ctap`
//! call and waits for `ConfirmPresence(id, allow)` from that same connection. Any front-end
//! (the agent today) can serve it; presence never replaces a fingerprint the core asked for.

use std::collections::HashMap;
use std::sync::{mpsc, Arc, Mutex};
use std::time::Duration;

use passkey_tpm_core::ctap2::{Authenticator, Pending, Step, UserInfo, UvOutcome};
use passkey_tpm_core::ctaphid::MAX_MSG;
use passkey_tpm_core::evidence::UvEvidence;
use passkey_tpm_core::tpm_iface::{TpmOps, Uid};
use passkey_tpm_uv::fprintd::{self, UvResult};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use zbus::message::Header;
use zbus::names::BusName;
use zbus::object_server::SignalEmitter;
use zbus::zvariant::ObjectPath;
use zbus::{fdo, interface, Connection};

pub use passkey_tpm_uv::seat::{Logind, SessionPolicy};

pub const BUS_NAME: &str = "io.github.dangerousplay.PasskeyTpm1";
pub const OBJECT_PATH: &str = "/io/github/dangerousplay/PasskeyTpm1";
/// CTAP status byte returned when the request is larger than maxMsgSize.
const STATUS_INVALID_LENGTH: u8 = 0x03;
const STATUS_OTHER: u8 = 0x7F;
/// CTAP2_ERR_OPERATION_DENIED: the caller isn't the user at the seat.
const STATUS_OPERATION_DENIED: u8 = 0x27;
/// Fingerprint scans allowed for one WebAuthn request before reporting a mismatch.
///
/// A single `verify-no-match` used to end the request, which forced the browser to start a
/// whole new WebAuthn operation after one badly placed finger. Retrying here keeps the same
/// request (and browser deadline) alive.
const MAX_UV_ATTEMPTS: u32 = 3;
/// Pause between retryable mismatches so the reader can settle and the user can reposition.
const UV_RETRY_DELAY: Duration = Duration::from_millis(500);

enum Job {
    Prepare {
        uid: Uid,
        info: UserInfo,
        request: Vec<u8>,
        reply: oneshot::Sender<Step>,
    },
    Complete {
        pending: Box<Pending>,
        outcome: UvOutcome,
        reply: oneshot::Sender<Vec<u8>>,
    },
}

/// Milliseconds since the worker started (monotonic; the authenticator's clock).
fn now_ms(start: std::time::Instant) -> u64 {
    u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX)
}

/// Handle to the thread that owns the TPM backend. TPM contexts aren't `Send`, and all TPM
/// commands must be serialised anyway, so one thread does all TPM work.
#[derive(Clone, Debug)]
pub struct TpmWorker {
    tx: mpsc::Sender<Job>,
    /// Cancelled when the worker thread ends, however it ends (see [`TpmWorker::closed`]).
    closed: CancellationToken,
}

impl TpmWorker {
    /// Spawns the worker; `make` builds the backend on the worker thread.
    ///
    /// # Errors
    /// If the thread can't be spawned.
    pub fn spawn<T, F>(make: F) -> std::io::Result<Self>
    where
        T: TpmOps,
        F: FnOnce() -> T + Send + 'static,
    {
        let (tx, rx) = mpsc::channel::<Job>();
        let closed = CancellationToken::new();
        // Dropped when the thread returns or unwinds, which marks the worker closed.
        let guard = closed.clone().drop_guard();
        std::thread::Builder::new()
            .name("passkey-tpm-tpm".into())
            .spawn(move || {
                let _guard = guard;
                let mut auth = Authenticator::new(make());
                let start = std::time::Instant::now();
                for job in rx {
                    match job {
                        Job::Prepare {
                            uid,
                            info,
                            request,
                            reply,
                        } => {
                            let _ = reply.send(auth.prepare(uid, info, &request, now_ms(start)));
                        }
                        Job::Complete {
                            pending,
                            outcome,
                            reply,
                        } => {
                            let _ = reply.send(auth.complete(pending, outcome, now_ms(start)));
                        }
                    }
                }
            })?;
        Ok(Self { tx, closed })
    }

    /// Resolves once the worker thread has ended (e.g. it panicked). Every later request
    /// would fail, so the daemon should exit non-zero and let systemd restart it (HARD-20).
    pub async fn closed(&self) {
        self.closed.cancelled().await;
    }

    async fn prepare(&self, uid: Uid, info: UserInfo, request: Vec<u8>) -> Option<Step> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Job::Prepare {
                uid,
                info,
                request,
                reply,
            })
            .ok()?;
        rx.await.ok()
    }

    async fn complete(&self, pending: Box<Pending>, outcome: UvOutcome) -> Option<Vec<u8>> {
        let (reply, rx) = oneshot::channel();
        self.tx
            .send(Job::Complete {
                pending,
                outcome,
                reply,
            })
            .ok()?;
        rx.await.ok()
    }
}

/// Resolves a uid to a login name (NSS, so authd/SSSD users work too).
pub trait UserLookup: Send + Sync {
    fn username(&self, uid: u32) -> Option<String>;
}

/// [`UserLookup`] through the system's NSS.
#[derive(Debug, Default, Clone, Copy)]
pub struct NssUsers;

impl UserLookup for NssUsers {
    fn username(&self, uid: u32) -> Option<String> {
        nix::unistd::User::from_uid(nix::unistd::Uid::from_raw(uid))
            .ok()
            .flatten()
            .map(|u| u.name)
    }
}

/// A presence confirmation the broker is waiting for.
struct PresenceWait {
    /// Unique bus name of the `Ctap` caller; only it may answer.
    caller: String,
    reply: oneshot::Sender<bool>,
}

/// The D-Bus service object.
pub struct Broker {
    worker: TpmWorker,
    fprintd: Connection,
    users: Box<dyn UserLookup>,
    sessions: Box<dyn SessionPolicy>,
    verify_timeout: Duration,
    cancels: Arc<Mutex<HashMap<u32, (u64, CancellationToken)>>>,
    presence: Mutex<HashMap<u64, PresenceWait>>,
    next_request: std::sync::atomic::AtomicU64,
}

impl std::fmt::Debug for Broker {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Broker")
            .field("verify_timeout", &self.verify_timeout)
            .finish_non_exhaustive()
    }
}

impl Broker {
    /// `fprintd` is the (system) bus connection used to reach fprintd; `sessions` decides
    /// which users are at a seat (production: [`Logind`]).
    #[must_use]
    pub fn new(
        worker: TpmWorker,
        fprintd: Connection,
        users: Box<dyn UserLookup>,
        sessions: Box<dyn SessionPolicy>,
        verify_timeout: Duration,
    ) -> Self {
        Self {
            worker,
            fprintd,
            users,
            sessions,
            verify_timeout,
            cancels: Arc::default(),
            presence: Mutex::default(),
            next_request: std::sync::atomic::AtomicU64::new(0),
        }
    }

    async fn caller_uid(conn: &Connection, header: &Header<'_>) -> fdo::Result<u32> {
        let sender = header
            .sender()
            .ok_or_else(|| fdo::Error::AccessDenied("no sender".into()))?;
        let dbus = fdo::DBusProxy::new(conn).await?;
        dbus.get_connection_unix_user(sender.clone().into()).await
    }

    /// Registers a cancel token for `uid`'s new request; a still-pending older request of the
    /// same user is cancelled (only one fingerprint prompt per user at a time). The agent
    /// relays one request at a time, so an older one still here was abandoned by the host.
    fn register_cancel(&self, uid: u32) -> (u64, CancellationToken) {
        let seq = self
            .next_request
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let token = CancellationToken::new();
        if let Ok(mut map) = self.cancels.lock() {
            if let Some((_, old)) = map.insert(uid, (seq, token.clone())) {
                old.cancel();
            }
        }
        (seq, token)
    }

    /// Removes `uid`'s token if it still belongs to request `seq`.
    fn clear_cancel(&self, uid: u32, seq: u64) {
        if let Ok(mut map) = self.cancels.lock() {
            if map.get(&uid).is_some_and(|(s, _)| *s == seq) {
                map.remove(&uid);
            }
        }
    }

    /// Runs up to [`MAX_UV_ATTEMPTS`] fingerprint scans within `verify_timeout`.
    ///
    /// Only a mismatch is retried: cancellation, timeout, reader errors and a match return
    /// immediately. Cancellation also wins during the pause between attempts.
    async fn verify_with_retries(&self, username: &str, cancel: &CancellationToken) -> UvResult {
        let deadline = tokio::time::Instant::now() + self.verify_timeout;
        for attempt in 1..=MAX_UV_ATTEMPTS {
            let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                return UvResult::TimedOut;
            }
            let result = fprintd::verify(&self.fprintd, username, remaining, cancel.clone()).await;
            if result != UvResult::NoMatch || attempt == MAX_UV_ATTEMPTS {
                return result;
            }
            #[allow(clippy::print_stderr)]
            {
                eprintln!("fingerprint mismatch; retrying ({attempt}/{MAX_UV_ATTEMPTS})");
            }
            let pause =
                UV_RETRY_DELAY.min(deadline.saturating_duration_since(tokio::time::Instant::now()));
            tokio::select! {
                biased;
                () = cancel.cancelled() => return UvResult::Cancelled,
                () = tokio::time::sleep(pause) => {}
            }
        }
        UvResult::NoMatch
    }

    /// Serves one request. `cancel` is registered before any await (HARD-12), so a Cancel
    /// that arrives while the session, fprintd or the TPM is still being asked is not lost.
    async fn run(
        &self,
        uid: u32,
        caller: &Caller<'_>,
        request: Vec<u8>,
        cancel: CancellationToken,
    ) -> Vec<u8> {
        if request.len() > MAX_MSG {
            return vec![STATUS_INVALID_LENGTH];
        }
        // Audit trail in the journal: which user asked for which CTAP command.
        #[allow(clippy::print_stderr)]
        {
            eprintln!(
                "request uid={uid} command={:#04x} len={}",
                request.first().copied().unwrap_or(0),
                request.len()
            );
        }
        let username = self.users.username(uid);
        let uv_enrolled = match &username {
            Some(name) => match fprintd::has_enrolled(&self.fprintd, name).await {
                Ok(enrolled) => enrolled,
                // fprintd can't be started or reached (no reader, not installed): logged so
                // it isn't mistaken for "no fingerprints", but advertised as no built-in UV
                // so clients fall back to the PIN instead of a UV request that must fail.
                Err(e) => {
                    #[allow(clippy::print_stderr)]
                    {
                        eprintln!("fprintd unavailable for uid={uid}: {e}");
                    }
                    false
                }
            },
            None => false,
        };
        let info = UserInfo { uv_enrolled };
        let Some(step) = self.worker.prepare(Uid(uid), info, request).await else {
            return vec![STATUS_OTHER];
        };
        let pending = match step {
            Step::Done(response) => return response,
            Step::NeedPresence(pending) => {
                let outcome = self.presence(caller, pending.rp_id(), &cancel).await;
                return self
                    .worker
                    .complete(pending, outcome)
                    .await
                    .unwrap_or_else(|| vec![STATUS_OTHER]);
            }
            Step::NeedUv(pending) => pending,
        };
        let outcome = match username {
            // Cancelled before the prompt: don't claim the reader at all.
            _ if cancel.is_cancelled() => UvOutcome::Cancelled,
            None => UvOutcome::Unavailable,
            Some(name) => {
                let result = self.verify_with_retries(&name, &cancel).await;
                match result {
                    // The only place evidence is created: a real fprintd match for this uid.
                    UvResult::Match => UvOutcome::Matched(UvEvidence::from_fprintd_match(uid)),
                    UvResult::NoMatch => UvOutcome::NoMatch,
                    UvResult::Cancelled => UvOutcome::Cancelled,
                    UvResult::TimedOut => UvOutcome::TimedOut,
                    UvResult::Unavailable(_) => UvOutcome::Unavailable,
                }
            }
        };
        self.worker
            .complete(pending, outcome)
            .await
            .unwrap_or_else(|| vec![STATUS_OTHER])
    }

    /// Asks the `Ctap` caller to confirm presence for `prompt` and waits for its answer,
    /// [`Broker::confirm_presence`], up to the verify timeout.
    async fn presence(
        &self,
        caller: &Caller<'_>,
        prompt: &str,
        cancel: &CancellationToken,
    ) -> UvOutcome {
        if cancel.is_cancelled() {
            return UvOutcome::Cancelled;
        }
        let id = self
            .next_request
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let (reply, answer) = oneshot::channel();
        if let Ok(mut map) = self.presence.lock() {
            map.insert(
                id,
                PresenceWait {
                    caller: caller.name.to_owned(),
                    reply,
                },
            );
        }
        let outcome = match Self::request_presence(caller, id, prompt).await {
            Err(e) => {
                #[allow(clippy::print_stderr)]
                {
                    eprintln!("cannot ask {} for presence: {e}", caller.name);
                }
                UvOutcome::Unavailable
            }
            Ok(()) => tokio::select! {
                biased;
                () = cancel.cancelled() => UvOutcome::Cancelled,
                () = tokio::time::sleep(self.verify_timeout) => UvOutcome::TimedOut,
                answer = answer => match answer {
                    Ok(true) => UvOutcome::Present,
                    Ok(false) => UvOutcome::Denied,
                    Err(_) => UvOutcome::Unavailable,
                },
            },
        };
        if let Ok(mut map) = self.presence.lock() {
            map.remove(&id);
        }
        outcome
    }

    /// Emits `PresenceRequested` to the caller only (unicast signal).
    async fn request_presence(caller: &Caller<'_>, id: u64, prompt: &str) -> zbus::Result<()> {
        let destination = BusName::try_from(caller.name)?;
        let emitter = SignalEmitter::from_parts(
            caller.conn.clone(),
            ObjectPath::from_static_str_unchecked(OBJECT_PATH),
        )
        .set_destination(destination);
        Self::presence_requested(&emitter, id, prompt).await
    }
}

/// The connection a `Ctap` call came in on and the caller's unique bus name.
struct Caller<'a> {
    conn: &'a Connection,
    name: &'a str,
}

#[interface(name = "io.github.dangerousplay.PasskeyTpm1")]
impl Broker {
    /// Processes one CTAP2 request (command byte + CBOR) for the calling user and returns
    /// the response (status byte + CBOR). May wait up to the verify timeout for a fingerprint.
    async fn ctap(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
        request: Vec<u8>,
    ) -> fdo::Result<Vec<u8>> {
        let uid = Self::caller_uid(conn, &header).await?;
        let name = header
            .sender()
            .ok_or_else(|| fdo::Error::AccessDenied("no sender".into()))?;
        let caller = Caller {
            conn,
            name: name.as_str(),
        };
        let (seq, cancel) = self.register_cancel(uid);
        let response = if self.sessions.is_active(uid).await {
            self.run(uid, &caller, request, cancel).await
        } else {
            #[allow(clippy::print_stderr)]
            {
                eprintln!("denied uid={uid}: no active seat session");
            }
            vec![STATUS_OPERATION_DENIED]
        };
        self.clear_cancel(uid, seq);
        Ok(response)
    }

    /// Answers a `PresenceRequested` signal: `allow` is the user's choice. Only the
    /// connection that made the `Ctap` call may answer it.
    async fn confirm_presence(
        &self,
        #[zbus(header)] header: Header<'_>,
        id: u64,
        allow: bool,
    ) -> fdo::Result<()> {
        let sender = header
            .sender()
            .ok_or_else(|| fdo::Error::AccessDenied("no sender".into()))?;
        let wait = {
            let mut map = self
                .presence
                .lock()
                .map_err(|_| fdo::Error::Failed("presence state poisoned".into()))?;
            match map.get(&id) {
                Some(w) if w.caller == sender.as_str() => map.remove(&id),
                Some(_) => {
                    return Err(fdo::Error::AccessDenied(
                        "not the caller of this request".into(),
                    ))
                }
                None => None,
            }
        };
        let wait =
            wait.ok_or_else(|| fdo::Error::InvalidArgs("no such presence request".into()))?;
        let _ = wait.reply.send(allow);
        Ok(())
    }

    /// Sent to the `Ctap` caller when a user without an enrolled fingerprint must confirm
    /// presence for `prompt` (a relying party or purpose). Answer with `ConfirmPresence`.
    #[zbus(signal)]
    async fn presence_requested(
        emitter: &SignalEmitter<'_>,
        id: u64,
        prompt: &str,
    ) -> zbus::Result<()>;

    /// Cancels the calling user's pending fingerprint request, if any.
    async fn cancel(
        &self,
        #[zbus(header)] header: Header<'_>,
        #[zbus(connection)] conn: &Connection,
    ) -> fdo::Result<()> {
        let uid = Self::caller_uid(conn, &header).await?;
        if let Ok(map) = self.cancels.lock() {
            if let Some((_, token)) = map.get(&uid) {
                token.cancel();
            }
        }
        Ok(())
    }
}

/// Exports `broker` on `conn` and claims [`BUS_NAME`].
///
/// # Errors
/// D-Bus errors (e.g. the name is already owned or the policy forbids owning it).
pub async fn serve(conn: &Connection, broker: Broker) -> zbus::Result<()> {
    conn.object_server().at(OBJECT_PATH, broker).await?;
    conn.request_name(BUS_NAME).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use passkey_tpm_tpm::adapter::TpmBackend;

    use super::TpmWorker;

    #[tokio::test]
    async fn closed_resolves_when_the_worker_thread_dies() {
        // HARD-20: e.g. the TPM context can't be created on the worker thread.
        let (die, wait) = std::sync::mpsc::channel::<()>();
        let worker = TpmWorker::spawn::<TpmBackend, _>(move || {
            let _ = wait.recv();
            panic!("no TPM")
        })
        .expect("spawn");
        assert!(
            tokio::time::timeout(Duration::from_millis(100), worker.closed())
                .await
                .is_err(),
            "open while the thread runs"
        );
        die.send(()).expect("worker waiting");
        tokio::time::timeout(Duration::from_secs(5), worker.closed())
            .await
            .expect("closed() resolves once the worker is gone");
    }
}
