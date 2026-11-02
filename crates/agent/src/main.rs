//! `passkey-tpm-agent`: per-user virtual FIDO security key backed by the passkey-tpm broker.
//!
//! The device exists only while this user has an active session on a local seat: after a
//! user switch the hidraw node's ACL moves to the new seat user, so the agent removes the
//! device while its user is in the background (HARD-01) and brings it back afterwards.
//!
//! For users without an enrolled fingerprint the broker asks this agent to confirm presence
//! (`PresenceRequested`, AD-022); the agent shows an Allow/Deny notification and answers
//! with `ConfirmPresence` on the same connection that made the `Ctap` call.
#![allow(clippy::print_stderr, clippy::print_stdout)]

mod prompt;

use std::process::ExitCode;
use std::sync::mpsc as std_mpsc;
use std::time::{Duration, Instant};

use futures_util::StreamExt;
use passkey_tpm_agent::{Effect, Hid};
use passkey_tpm_transport_uhid::{
    fido_device_params, DeviceParams, UhidDevice, UhidEvent, UhidWriter,
};
use passkey_tpm_uv::seat::{self, Logind, SessionPolicy};
use tokio::sync::mpsc;
use zbus::message::Type as MessageType;
use zbus::{Connection, MatchRule, MessageStream};

const BUS_NAME: &str = "io.github.dangerousplay.PasskeyTpm1";
const OBJECT_PATH: &str = "/io/github/dangerousplay/PasskeyTpm1";
const TICK: Duration = Duration::from_millis(100);
/// Default broker fingerprint window; the broker accepts the same
/// `PASSKEY_UV_TIMEOUT_SECS` override.
const DEFAULT_UV_TIMEOUT_SECS: u64 = 60;
/// Extra time on top of the broker's window so the broker reports the real
/// timeout/blocked status instead of the agent racing it.
const BROKER_HEADROOM_SECS: u64 = 15;

fn broker_timeout() -> Duration {
    let uv = std::env::var("PASSKEY_UV_TIMEOUT_SECS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .filter(|s| *s > 0)
        .unwrap_or(DEFAULT_UV_TIMEOUT_SECS);
    Duration::from_secs(uv.saturating_add(BROKER_HEADROOM_SECS))
}
const STATUS_OTHER: u8 = 0x7F;
/// Re-check of the seat state in case a logind signal was missed.
const SEAT_POLL: Duration = Duration::from_secs(2);

enum Input {
    Output(Vec<u8>),
    Reply(u64, Vec<u8>),
    DeviceGone,
    /// Whether this user is in the foreground on a seat (sent on every check).
    Seat(bool),
}

fn random_u32() -> u32 {
    let mut b = [0u8; 4];
    // A failing OS RNG leaves zeros, which `Hid` rejects and retries.
    let _ = getrandom::fill(&mut b);
    u32::from_ne_bytes(b)
}

async fn ctap(bus: &Connection, request: Vec<u8>) -> zbus::Result<Vec<u8>> {
    let reply = bus
        .call_method(
            Some(BUS_NAME),
            OBJECT_PATH,
            Some(BUS_NAME),
            "Ctap",
            &(request,),
        )
        .await?;
    reply.body().deserialize::<Vec<u8>>()
}

async fn cancel(bus: &Connection) -> zbus::Result<()> {
    bus.call_method(Some(BUS_NAME), OBJECT_PATH, Some(BUS_NAME), "Cancel", &())
        .await
        .map(|_| ())
}

/// A notification for the notification thread.
enum Note {
    /// "Touch the fingerprint reader" for this relying party.
    Fingerprint(String),
    /// Ask to allow request `id` for this relying party (no fingerprint enrolled).
    Presence { id: u64, rp: String },
}

/// Shows notifications in order on one thread, so a presence question replaces the
/// fingerprint prompt shown just before it for the same request. Presence answers are sent
/// to the broker through `bus` on `runtime`.
///
/// Informational only: the agent runs in the user's session and can be spoofed by
/// same-user malware (docs/threat-model.md, "prompt spoofing").
fn notifier(bus: Connection, runtime: tokio::runtime::Handle) -> std_mpsc::Sender<Note> {
    let (tx, rx) = std_mpsc::channel::<Note>();
    std::thread::spawn(move || {
        let mut last: Option<u32> = None;
        for note in rx {
            let mut n = notify_rust::Notification::new();
            n.appname("passkey-tpm")
                .icon("fingerprint")
                .timeout(notify_rust::Timeout::Milliseconds(30_000));
            match note {
                Note::Fingerprint(rp) => {
                    n.summary("Touch the fingerprint reader")
                        .body(&format!("to continue with {rp}"));
                    last = n.show().ok().map(|h| h.id());
                }
                Note::Presence { id, rp } => {
                    n.summary("Allow passkey-tpm?")
                        .body(&format!("{rp} wants to use your passkey."))
                        .action("allow", "Allow")
                        .action("deny", "Deny");
                    if let Some(previous) = last.take() {
                        n.id(previous);
                    }
                    let handle = match n.show() {
                        Ok(h) => h,
                        Err(e) => {
                            eprintln!("cannot show the presence notification: {e}");
                            continue;
                        }
                    };
                    let bus = bus.clone();
                    let runtime = runtime.clone();
                    // Wait on its own thread so later prompts aren't held up.
                    std::thread::spawn(move || {
                        handle.wait_for_action(|action| {
                            let allow = action == "allow";
                            runtime.spawn(async move {
                                if let Err(e) = confirm_presence(&bus, id, allow).await {
                                    eprintln!("ConfirmPresence failed: {e}");
                                }
                            });
                        });
                    });
                }
            }
        }
    });
    tx
}

async fn confirm_presence(bus: &Connection, id: u64, allow: bool) -> zbus::Result<()> {
    bus.call_method(
        Some(BUS_NAME),
        OBJECT_PATH,
        Some(BUS_NAME),
        "ConfirmPresence",
        &(id, allow),
    )
    .await
    .map(|_| ())
}

/// Forwards the broker's `PresenceRequested` signals to the notifier. Only signals from the
/// current owner of the broker's name count, so another client can't make the agent ask.
fn watch_presence(bus: Connection, notes: std_mpsc::Sender<Note>) {
    tokio::spawn(async move {
        let rule = MatchRule::builder()
            .msg_type(MessageType::Signal)
            .path(OBJECT_PATH)
            .and_then(|b| b.interface(BUS_NAME))
            .and_then(|b| b.member("PresenceRequested"))
            .map(|b| b.build());
        let stream = match rule {
            Ok(rule) => MessageStream::for_match_rule(rule, &bus, None).await,
            Err(e) => Err(e),
        };
        let mut stream = match stream {
            Ok(s) => s,
            Err(e) => {
                eprintln!("cannot watch presence requests: {e}");
                return;
            }
        };
        let dbus = match zbus::fdo::DBusProxy::new(&bus).await {
            Ok(p) => p,
            Err(e) => {
                eprintln!("cannot watch presence requests: {e}");
                return;
            }
        };
        while let Some(item) = stream.next().await {
            let Ok(msg) = item else { continue };
            let header = msg.header();
            let Some(sender) = header.sender() else {
                continue;
            };
            let Ok(name) = zbus::names::BusName::try_from(BUS_NAME) else {
                continue;
            };
            let owner = dbus.get_name_owner(name).await;
            if !owner.is_ok_and(|o| o.as_str() == sender.as_str()) {
                continue;
            }
            let Ok((id, rp)) = msg.body().deserialize::<(u64, String)>() else {
                continue;
            };
            if notes.send(Note::Presence { id, rp }).is_err() {
                return;
            }
        }
    });
}

/// The uid this agent runs as (owner of its own `/proc` entry).
fn own_uid() -> std::io::Result<u32> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").map(|m| m.uid())
}

/// Reports this user's seat state at start, after every logind change signal and every
/// [`SEAT_POLL`].
fn watch_seat(bus: Connection, uid: u32, tx: mpsc::UnboundedSender<Input>) {
    tokio::spawn(async move {
        let policy = Logind::new(bus.clone());
        let mut changes = match seat::changes(&bus).await {
            Ok(stream) => Some(stream),
            Err(e) => {
                eprintln!("cannot watch logind sessions, polling only: {e}");
                None
            }
        };
        let mut poll = tokio::time::interval(SEAT_POLL);
        loop {
            if tx.send(Input::Seat(policy.is_active(uid).await)).is_err() {
                return;
            }
            let signal = async {
                match changes.as_mut() {
                    Some(stream) => stream.next().await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                _ = poll.tick() => {}
                Some(()) = signal => {}
            }
        }
    });
}

/// The FIDO device parameters, with the owner's uid in the physical path (`HID_PHYS`) so
/// tools and tests can tell users' devices apart.
fn device_params(uid: u32) -> DeviceParams {
    let mut params = fido_device_params();
    params.phys = format!("passkey-tpm-agent/uid={uid}");
    params
}

/// Opens `/dev/uhid`, creates the device and starts the thread that forwards its events.
fn open_device(
    params: &DeviceParams,
    tx: &mpsc::UnboundedSender<Input>,
) -> std::io::Result<UhidWriter> {
    let mut device = UhidDevice::create(params)?;
    let writer = device.try_clone_writer()?;
    let reader_tx = tx.clone();
    std::thread::spawn(move || loop {
        match device.read_event() {
            Ok(UhidEvent::Output(data)) => {
                if reader_tx.send(Input::Output(data)).is_err() {
                    return;
                }
            }
            Ok(_) => {}
            Err(e) if e.kind() == std::io::ErrorKind::InvalidData => {
                eprintln!("ignoring uhid event: {e}");
            }
            Err(e) => {
                eprintln!("uhid read failed: {e}");
                let _ = reader_tx.send(Input::DeviceGone);
                return;
            }
        }
    });
    Ok(writer)
}

/// Asks for a fingerprint through the selected backend. Native/polkit are not built yet, so
/// they fall back to the notification rather than leaving the user without a prompt.
fn prompt_user(backend: prompt::Backend, rp: String, notes: &std_mpsc::Sender<Note>) {
    match backend {
        prompt::Backend::Terminal => {
            eprintln!("Touch the fingerprint reader to continue with {rp}");
        }
        prompt::Backend::Notification => {
            let _ = notes.send(Note::Fingerprint(rp));
        }
        prompt::Backend::Native | prompt::Backend::Polkit => {
            eprintln!(
                "{} prompt backend is not built yet; using a notification",
                backend.as_str()
            );
            let _ = notes.send(Note::Fingerprint(rp));
        }
    }
}

fn apply(
    effects: Vec<Effect>,
    writer: Option<&UhidWriter>,
    bus: &Connection,
    tx: &mpsc::UnboundedSender<Input>,
    notes: &std_mpsc::Sender<Note>,
    backend: prompt::Backend,
) {
    for effect in effects {
        match effect {
            Effect::Write(reports) => {
                // No device (user in the background): nobody to answer.
                let Some(writer) = writer else { continue };
                for report in reports {
                    if let Err(e) = writer.write_input(&report) {
                        eprintln!("uhid write failed: {e}");
                    }
                }
            }
            Effect::Broker { id, request } => {
                let bus = bus.clone();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let response =
                        match tokio::time::timeout(broker_timeout(), ctap(&bus, request)).await {
                            Ok(Ok(r)) => r,
                            Ok(Err(e)) => {
                                eprintln!("broker call failed: {e}");
                                vec![STATUS_OTHER]
                            }
                            Err(_) => vec![STATUS_OTHER],
                        };
                    let _ = tx.send(Input::Reply(id, response));
                });
            }
            Effect::Cancel => {
                let bus = bus.clone();
                tokio::spawn(async move {
                    if let Err(e) = cancel(&bus).await {
                        eprintln!("broker cancel failed: {e}");
                    }
                });
            }
            Effect::Prompt(rp) => prompt_user(backend, rp, notes),
        }
    }
}

fn probe_prompt() -> ExitCode {
    let detection = prompt::Detection::detect();
    let backend = prompt::select(
        std::env::var("PASSKEY_PROMPT").ok().as_deref(),
        &detection,
        detection.graphical(),
    );
    println!("{}", prompt::report(&detection, backend));
    ExitCode::SUCCESS
}

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args().nth(1).as_deref() == Some("--probe-prompt") {
        return probe_prompt();
    }
    let detection = prompt::Detection::detect();
    let backend = prompt::select(
        std::env::var("PASSKEY_PROMPT").ok().as_deref(),
        &detection,
        detection.graphical(),
    );
    eprintln!("{}", prompt::report(&detection, backend));
    let bus = match Connection::system().await {
        Ok(b) => b,
        Err(e) => {
            eprintln!("cannot connect to the system bus: {e}");
            return ExitCode::FAILURE;
        }
    };
    let uid = match own_uid() {
        Ok(uid) => uid,
        Err(e) => {
            eprintln!("cannot determine the agent's uid: {e}");
            return ExitCode::FAILURE;
        }
    };

    let params = device_params(uid);
    let (tx, mut rx) = mpsc::unbounded_channel();
    watch_seat(bus.clone(), uid, tx.clone());
    let notes = notifier(bus.clone(), tokio::runtime::Handle::current());
    watch_presence(bus.clone(), notes.clone());

    // `/dev/uhid` stays open for the agent's lifetime once opened; `present` tracks whether
    // the HID device currently exists on it.
    let mut writer: Option<UhidWriter> = None;
    let mut present = false;
    let start = Instant::now();
    let now_ms = || u64::try_from(start.elapsed().as_millis()).unwrap_or(u64::MAX);
    let mut hid = Hid::new(random_u32);
    let mut tick = tokio::time::interval(TICK);
    eprintln!("passkey-tpm-agent ready");
    loop {
        let link = if present { writer.as_ref() } else { None };
        tokio::select! {
            input = rx.recv() => match input {
                Some(Input::Output(data)) if present => apply(hid.on_output(&data, now_ms()), link, &bus, &tx, &notes, backend),
                Some(Input::Output(_)) => {}
                Some(Input::Reply(id, response)) => apply(hid.on_broker_reply(id, &response), link, &bus, &tx, &notes, backend),
                Some(Input::Seat(true)) if !present => {
                    let result = match &writer {
                        Some(w) => w.recreate(&params),
                        None => open_device(&params, &tx).map(|w| writer = Some(w)),
                    };
                    match result {
                        Ok(()) => {
                            present = true;
                            eprintln!("session active: virtual key added");
                        }
                        Err(e) => {
                            eprintln!("cannot create the virtual FIDO device via /dev/uhid: {e}");
                            return ExitCode::FAILURE;
                        }
                    }
                }
                Some(Input::Seat(false)) if present => {
                    apply(hid.reset(), None, &bus, &tx, &notes, backend);
                    present = false;
                    if let Some(Err(e)) = writer.as_ref().map(UhidWriter::remove_device) {
                        // Can't guarantee the device is gone: stop, which closes the handle.
                        eprintln!("cannot remove the virtual key: {e}");
                        return ExitCode::FAILURE;
                    }
                    eprintln!("session in the background: virtual key removed");
                }
                Some(Input::Seat(_)) => {}
                Some(Input::DeviceGone) | None => return ExitCode::FAILURE,
            },
            _ = tick.tick() => apply(hid.on_tick(now_ms()), link, &bus, &tx, &notes, backend),
            _ = tokio::signal::ctrl_c() => return ExitCode::SUCCESS,
        }
    }
}
