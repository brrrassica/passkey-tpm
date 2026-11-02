//! Prompt backend selection and Omarchy detection (0.2.0 M4.1/M4.2).
//!
//! The full-screen layer-shell overlay (M4.3) is not part of this foundation, but the
//! selection logic is: [`Detection`] inspects the session, [`select`] honours
//! `PASSKEY_PROMPT=auto|native|polkit|notification|terminal`, and the agent uses the result
//! to decide how to ask for a fingerprint. Detection is advisory: an unavailable native
//! backend must fall through to a notification, never fail the passkey operation.

use std::path::{Path, PathBuf};

/// How the agent asks the user for a fingerprint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Backend {
    /// Full-screen Wayland layer-shell overlay (M4.3; not built yet).
    Native,
    /// polkit/desktop authentication dialog.
    Polkit,
    /// notify-rust toast (the current top-right notification).
    Notification,
    /// stderr prompt for TTY/SSH sessions.
    Terminal,
}

impl Backend {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Native => "native",
            Self::Polkit => "polkit",
            Self::Notification => "notification",
            Self::Terminal => "terminal",
        }
    }
}

/// Session facts collected once at agent start.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Detection {
    /// `omarchy` is on `PATH`.
    pub omarchy_command: bool,
    /// `OMARCHY_PATH` is set.
    pub omarchy_path: bool,
    /// `$HOME/.local/share/omarchy` exists.
    pub omarchy_data_dir: bool,
    /// `/etc/omarchy-release` exists.
    pub omarchy_release: bool,
    /// `XDG_CURRENT_DESKTOP` mentions Hyprland.
    pub hyprland_desktop: bool,
    /// The session is Wayland (`XDG_SESSION_TYPE` or `WAYLAND_DISPLAY`).
    pub wayland_session: bool,
    /// `hyprctl` is on `PATH`.
    pub hyprctl: bool,
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path).is_ok_and(|m| m.permissions().mode() & 0o111 != 0)
}

fn command_in_path(name: &str) -> bool {
    std::env::var_os("PATH").is_some_and(|paths| {
        std::env::split_paths(&paths).any(|dir| {
            let candidate = dir.join(name);
            candidate.is_file() && is_executable(&candidate)
        })
    })
}

fn non_empty_env(name: &str) -> bool {
    std::env::var_os(name).is_some_and(|v| !v.is_empty())
}

impl Detection {
    #[must_use]
    pub fn detect() -> Self {
        let wayland_by_type =
            std::env::var("XDG_SESSION_TYPE").is_ok_and(|v| v.eq_ignore_ascii_case("wayland"));
        Self {
            omarchy_command: command_in_path("omarchy"),
            omarchy_path: non_empty_env("OMARCHY_PATH"),
            omarchy_data_dir: std::env::var_os("HOME")
                .is_some_and(|home| PathBuf::from(home).join(".local/share/omarchy").is_dir()),
            omarchy_release: Path::new("/etc/omarchy-release").is_file(),
            hyprland_desktop: std::env::var("XDG_CURRENT_DESKTOP")
                .is_ok_and(|v| v.to_lowercase().contains("hyprland")),
            wayland_session: wayland_by_type || non_empty_env("WAYLAND_DISPLAY"),
            hyprctl: command_in_path("hyprctl"),
        }
    }

    /// Any positive Omarchy signal is enough; the individual facts are kept for diagnostics.
    #[must_use]
    pub fn is_omarchy(&self) -> bool {
        self.omarchy_command || self.omarchy_path || self.omarchy_data_dir || self.omarchy_release
    }

    /// Whether a graphical session exists at all (for choosing notification vs terminal).
    #[must_use]
    pub fn graphical(&self) -> bool {
        self.wayland_session || non_empty_env("DISPLAY")
    }

    /// The native overlay needs Omarchy/Hyprland on Wayland. `hyprctl` is reported but not
    /// required: it is useful evidence, not a hard gate.
    #[must_use]
    pub fn can_use_native(&self) -> bool {
        (self.is_omarchy() || self.hyprland_desktop) && self.wayland_session
    }

    fn summary(&self) -> String {
        let yes = |v: bool| if v { "yes" } else { "no" };
        format!(
            "omarchy: cmd={} path={} data={} release={}; hyprland={} wayland={} hyprctl={}",
            yes(self.omarchy_command),
            yes(self.omarchy_path),
            yes(self.omarchy_data_dir),
            yes(self.omarchy_release),
            yes(self.hyprland_desktop),
            yes(self.wayland_session),
            yes(self.hyprctl),
        )
    }
}

fn automatic_backend(detection: &Detection, graphical: bool) -> Backend {
    if detection.can_use_native() {
        Backend::Native
    } else if graphical {
        Backend::Notification
    } else {
        Backend::Terminal
    }
}

/// Resolves `PASSKEY_PROMPT` against the detected session.
///
/// An explicitly requested `native` backend that the session cannot support falls back the
/// same way `auto` would, so a stale environment variable cannot break passkey operations.
#[must_use]
pub fn select(requested: Option<&str>, detection: &Detection, graphical: bool) -> Backend {
    match requested.unwrap_or("auto").to_ascii_lowercase().as_str() {
        "native" if detection.can_use_native() => Backend::Native,
        "polkit" => Backend::Polkit,
        "notification" => Backend::Notification,
        "terminal" => Backend::Terminal,
        _ => automatic_backend(detection, graphical),
    }
}

/// Human-readable report for `passkey-tpm-agent --probe-prompt` and `verify.sh --prompt`.
#[must_use]
pub fn report(detection: &Detection, backend: Backend) -> String {
    let note = match backend {
        Backend::Native | Backend::Polkit => {
            "\nnote: this backend is not built yet; the agent falls back to a notification"
        }
        Backend::Notification | Backend::Terminal => "",
    };
    format!(
        "prompt backend: {}\ndetection: {}\ngraphical session: {}{note}",
        backend.as_str(),
        detection.summary(),
        if detection.graphical() { "yes" } else { "no" }
    )
}

#[cfg(test)]
mod tests {
    use super::{select, Backend, Detection};

    fn detection(omarchy: bool, hyprland: bool, wayland: bool) -> Detection {
        Detection {
            omarchy_command: omarchy,
            hyprland_desktop: hyprland,
            wayland_session: wayland,
            ..Detection::default()
        }
    }

    #[test]
    fn auto_prefers_native_on_omarchy_wayland() {
        let d = detection(true, true, true);
        assert_eq!(select(None, &d, true), Backend::Native);
    }

    #[test]
    fn auto_uses_notification_on_other_graphical_sessions() {
        let d = detection(false, false, true);
        assert_eq!(select(Some("auto"), &d, true), Backend::Notification);
    }

    #[test]
    fn auto_uses_terminal_without_a_graphical_session() {
        let d = detection(false, false, false);
        assert_eq!(select(Some("auto"), &d, false), Backend::Terminal);
    }

    #[test]
    fn explicit_native_falls_back_when_unsupported() {
        let d = detection(false, false, false);
        assert_eq!(select(Some("native"), &d, true), Backend::Notification);
        assert_eq!(select(Some("native"), &d, false), Backend::Terminal);
    }

    #[test]
    fn explicit_backends_are_honoured() {
        let d = detection(true, true, true);
        assert_eq!(select(Some("polkit"), &d, true), Backend::Polkit);
        assert_eq!(
            select(Some("notification"), &d, true),
            Backend::Notification
        );
        assert_eq!(select(Some("terminal"), &d, true), Backend::Terminal);
        assert_eq!(select(Some("native"), &d, true), Backend::Native);
    }

    #[test]
    fn hyprland_session_counts_as_native_capable() {
        let d = detection(false, true, true);
        assert_eq!(select(None, &d, true), Backend::Native);
    }
}
