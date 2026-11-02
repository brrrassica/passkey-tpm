//! Desktop polkit authentication prompt.
//!
//! When the installed polkit policy and PAM stack support it, the broker asks polkit to
//! authenticate the calling user instead of driving fprintd directly. polkit forwards the
//! request to the desktop polkit agent, and `/etc/pam.d/polkit-1` supplies the actual
//! verification (Omarchy's agent shows its fingerprint card when `pam_fprintd.so` is in
//! that stack). This is the same mechanism Omarchy's own privileged actions use.
//!
//! The action must be owned by the broker's system user
//! (`org.freedesktop.policykit.owner`), because polkit 127 only lets uid 0 or an action
//! owner call `CheckAuthorization` for another identity. The subject is the caller's
//! `system-bus-name`, so polkit can resolve the caller's session and prompt on its seat.
//!
//! No `_keep` default is used: every passkey operation must authenticate again.

use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use zbus::zvariant::Value;
use zbus::Connection;

/// The polkit action gating fingerprint user verification.
pub const ACTION: &str = "io.github.dangerousplay.PasskeyTpm1.verify";
/// The installed action file. `available` requires it, so an old install falls back to
/// the direct fprintd path instead of asking polkit about an unknown action.
pub const ACTION_FILE: &str =
    "/usr/share/polkit-1/actions/io.github.dangerousplay.PasskeyTpm1.policy";
/// The PAM stack the desktop polkit agent authenticates through.
pub const PAM_STACK: &str = "/etc/pam.d/polkit-1";

const POLKIT_SERVICE: &str = "org.freedesktop.PolicyKit1";
const POLKIT_PATH: &str = "/org/freedesktop/PolicyKit1/Authority";
const POLKIT_INTERFACE: &str = "org.freedesktop.PolicyKit1.Authority";
/// `AllowUserInteraction`: show the desktop agent's dialog.
const ALLOW_USER_INTERACTION: u32 = 1;

static NEXT_CANCELLATION_ID: AtomicU64 = AtomicU64::new(0);

/// Outcome of asking polkit to authenticate the caller.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// polkit reports the caller is authorized.
    Authorized,
    /// The user dismissed the dialog or failed authentication.
    Denied,
    /// The broker cancelled the request (the browser gave up).
    Cancelled,
    /// No answer before the broker's verification deadline.
    TimedOut,
    /// polkit or the desktop agent could not be reached.
    Unavailable(String),
}

/// Whether the desktop prompt can be used: the action is installed and the polkit PAM
/// stack performs a fingerprint scan. Keeping `pam_fprintd` in the stack is what makes
/// Omarchy's agent render the fingerprint card instead of the password field alone.
#[must_use]
pub fn available() -> bool {
    Path::new(ACTION_FILE).is_file() && pam_uses_fprintd()
}

/// Whether `raw` (the contents of [`PAM_STACK`]) has `pam_fprintd.so` in an `auth` line.
///
/// Mirrors Omarchy's `fingerprintConfiguredFromPamConfig`: the module need not be first,
/// and a clamshell gate may precede it.
#[must_use]
pub fn pam_config_uses_fprintd(raw: &str) -> bool {
    raw.lines().any(|line| {
        let line = line.trim();
        !line.is_empty()
            && !line.starts_with('#')
            && line.starts_with("auth")
            && line.contains("pam_fprintd.so")
    })
}

fn pam_uses_fprintd() -> bool {
    std::fs::read_to_string(PAM_STACK).is_ok_and(|raw| pam_config_uses_fprintd(&raw))
}

fn subject(sender: &str) -> (&'static str, HashMap<String, Value<'static>>) {
    let mut details: HashMap<String, Value<'static>> = HashMap::new();
    details.insert("name".to_owned(), Value::new(sender.to_owned()));
    ("system-bus-name", details)
}

fn next_cancellation_id() -> String {
    let seq = NEXT_CANCELLATION_ID.fetch_add(1, Ordering::Relaxed);
    format!("passkey-tpm-{}-{seq}", std::process::id())
}

/// Asks polkit to authenticate `sender` (the caller's unique bus name) for [`ACTION`].
///
/// `timeout` bounds the whole dialog. `cancel` cancels a pending dialog as well; either
/// path asks polkit to drop it so a later request does not inherit a stale prompt.
pub async fn authorize(
    connection: &Connection,
    sender: &str,
    timeout: Duration,
    cancel: &CancellationToken,
) -> Outcome {
    let proxy =
        match zbus::Proxy::new(connection, POLKIT_SERVICE, POLKIT_PATH, POLKIT_INTERFACE).await {
            Ok(proxy) => proxy,
            Err(e) => return Outcome::Unavailable(format!("polkit proxy: {e}")),
        };

    let cancellation_id = next_cancellation_id();
    let details: HashMap<String, String> = HashMap::new();
    let body = (
        subject(sender),
        ACTION,
        details,
        ALLOW_USER_INTERACTION,
        cancellation_id.as_str(),
    );
    let call =
        proxy.call::<_, _, (bool, bool, HashMap<String, String>)>("CheckAuthorization", &body);
    tokio::pin!(call);

    let result = tokio::select! {
        biased;
        () = cancel.cancelled() => {
            cancel_pending(&proxy, &cancellation_id).await;
            return Outcome::Cancelled;
        }
        () = tokio::time::sleep(timeout) => {
            cancel_pending(&proxy, &cancellation_id).await;
            return Outcome::TimedOut;
        }
        result = &mut call => result,
    };

    match result {
        Ok((true, _, _)) => Outcome::Authorized,
        Ok((false, _, _)) => Outcome::Denied,
        Err(e) => Outcome::Unavailable(format!("polkit CheckAuthorization: {e}")),
    }
}

/// Best-effort cancellation: the dialog may already be gone, and the broker must not
/// block on the cleanup call.
async fn cancel_pending(proxy: &zbus::Proxy<'_>, cancellation_id: &str) {
    let _: Result<(), _> = proxy
        .call("CancelCheckAuthorization", &(cancellation_id,))
        .await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fprintd_is_detected_anywhere_in_the_auth_stack() {
        assert!(pam_config_uses_fprintd(
            "auth [success=1 default=ignore] pam_exec.so quiet /usr/bin/clamshell\nauth sufficient pam_fprintd.so\nauth required pam_unix.so\n"
        ));
        assert!(!pam_config_uses_fprintd("auth required pam_unix.so\n"));
        // A commented module must not count.
        assert!(!pam_config_uses_fprintd(
            "#auth sufficient pam_fprintd.so\n"
        ));
        // Only the auth stack counts, not account/session.
        assert!(!pam_config_uses_fprintd(
            "account sufficient pam_fprintd.so\n"
        ));
    }

    #[test]
    fn subject_is_the_callers_system_bus_name() {
        let (kind, details) = subject(":1.42");
        assert_eq!(kind, "system-bus-name");
        assert_eq!(details.get("name"), Some(&Value::new(":1.42".to_owned())));
    }
}
