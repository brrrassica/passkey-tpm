//! `cargo xtask dist [--destdir DIR] [--prefix /usr]`: release build and FHS install tree.
//!
//! Without `--destdir` it stages `target/dist/passkey-tpm-<version>/` and writes a tarball
//! next to it. Distribution recipes call it with `--destdir "$pkgdir"` (Arch), `%{buildroot}`
//! (Fedora) or `debian/passkey-tpm` (Debian), so every package installs the same files.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::runner::{cargo, exec, workspace_root, Error, Result};

/// What gets installed: (source relative to the workspace, destination, mode). `{prefix}`
/// is `--prefix` (default `/usr`), `{libexecdir}` is `--libexecdir` (default
/// `{prefix}/libexec`; Arch uses `/usr/lib`). Unit and D-Bus service files have their
/// `/usr/libexec` paths rewritten to the chosen libexecdir.
pub const INSTALL: &[(&str, &str, u32)] = &[
    (
        "target/release/passkey-tpm-uvd",
        "{libexecdir}/passkey-tpm/passkey-tpm-uvd",
        0o755,
    ),
    (
        "target/release/passkey-tpm-agent",
        "{libexecdir}/passkey-tpm/passkey-tpm-agent",
        0o755,
    ),
    (
        "target/release/passkey-tpm",
        "{prefix}/bin/passkey-tpm",
        0o755,
    ),
    (
        "target/release/passkey-tpm-tray",
        "{prefix}/bin/passkey-tpm-tray",
        0o755,
    ),
    // XDG autostart only reads $XDG_CONFIG_DIRS (/etc/xdg), whatever the prefix.
    (
        "packaging/xdg/passkey-tpm-tray.desktop",
        "/etc/xdg/autostart/passkey-tpm-tray.desktop",
        0o644,
    ),
    (
        "packaging/systemd/passkey-tpm-uvd.service",
        "{prefix}/lib/systemd/system/passkey-tpm-uvd.service",
        0o644,
    ),
    (
        "packaging/systemd/passkey-tpm-agent.service",
        "{prefix}/lib/systemd/user/passkey-tpm-agent.service",
        0o644,
    ),
    (
        "packaging/dbus/io.github.dangerousplay.PasskeyTpm1.conf",
        "{prefix}/share/dbus-1/system.d/io.github.dangerousplay.PasskeyTpm1.conf",
        0o644,
    ),
    (
        "packaging/dbus/io.github.dangerousplay.PasskeyTpm1.service",
        "{prefix}/share/dbus-1/system-services/io.github.dangerousplay.PasskeyTpm1.service",
        0o644,
    ),
    (
        "packaging/polkit/50-passkey-tpm-fprintd.rules",
        "{prefix}/share/polkit-1/rules.d/50-passkey-tpm-fprintd.rules",
        0o644,
    ),
    (
        "packaging/polkit/io.github.dangerousplay.PasskeyTpm1.policy",
        "{prefix}/share/polkit-1/actions/io.github.dangerousplay.PasskeyTpm1.policy",
        0o644,
    ),
    (
        "packaging/udev/70-passkey-tpm-uhid.rules",
        "{prefix}/lib/udev/rules.d/70-passkey-tpm-uhid.rules",
        0o644,
    ),
    (
        "packaging/modules-load/passkey-tpm.conf",
        "{prefix}/lib/modules-load.d/passkey-tpm.conf",
        0o644,
    ),
    (
        "packaging/sysusers/passkey-tpm.conf",
        "{prefix}/lib/sysusers.d/passkey-tpm.conf",
        0o644,
    ),
    (
        "README.md",
        "{prefix}/share/doc/passkey-tpm/README.md",
        0o644,
    ),
    (
        "SECURITY.md",
        "{prefix}/share/doc/passkey-tpm/SECURITY.md",
        0o644,
    ),
    (
        "docs/threat-model.md",
        "{prefix}/share/doc/passkey-tpm/threat-model.md",
        0o644,
    ),
    (
        "LICENSE-MIT",
        "{prefix}/share/licenses/passkey-tpm/LICENSE-MIT",
        0o644,
    ),
    (
        "LICENSE-APACHE",
        "{prefix}/share/licenses/passkey-tpm/LICENSE-APACHE",
        0o644,
    ),
];

const BINARIES: &[&str] = &[
    "passkey-tpm-uvd",
    "passkey-tpm-agent",
    "passkey-tpm-cli",
    "passkey-tpm-tray",
];

#[derive(Debug, PartialEq, Eq)]
struct Options {
    destdir: Option<PathBuf>,
    prefix: String,
    libexecdir: Option<String>,
    no_build: bool,
}

impl Options {
    fn libexecdir(&self) -> String {
        self.libexecdir
            .clone()
            .unwrap_or_else(|| format!("{}/libexec", self.prefix))
    }
}

impl Options {
    fn parse(args: &[String]) -> Result<Self> {
        let mut opts = Options {
            destdir: None,
            prefix: "/usr".into(),
            libexecdir: None,
            no_build: false,
        };
        let mut it = args.iter();
        while let Some(arg) = it.next() {
            match arg.as_str() {
                "--destdir" => {
                    opts.destdir = Some(
                        it.next()
                            .map(PathBuf::from)
                            .ok_or_else(|| Error::Msg("--destdir needs a value".into()))?,
                    );
                }
                "--prefix" => {
                    let p = it
                        .next()
                        .ok_or_else(|| Error::Msg("--prefix needs a value".into()))?;
                    if !p.starts_with('/') {
                        return Err(Error::Msg("--prefix must be absolute".into()));
                    }
                    opts.prefix = p.trim_end_matches('/').to_owned();
                }
                "--libexecdir" => {
                    let p = it
                        .next()
                        .ok_or_else(|| Error::Msg("--libexecdir needs a value".into()))?;
                    if !p.starts_with('/') {
                        return Err(Error::Msg("--libexecdir must be absolute".into()));
                    }
                    opts.libexecdir = Some(p.trim_end_matches('/').to_owned());
                }
                "--no-build" => opts.no_build = true,
                other => return Err(Error::Msg(format!("unexpected argument `{other}`"))),
            }
        }
        Ok(opts)
    }
}

/// `dest` with `{prefix}`/`{libexecdir}` substituted, relative so it joins onto a destdir.
fn destination(dest: &str, prefix: &str, libexecdir: &str) -> PathBuf {
    PathBuf::from(
        dest.replace("{libexecdir}", libexecdir)
            .replace("{prefix}", prefix)
            .trim_start_matches('/'),
    )
}

/// Files whose contents reference the helper binaries' install path.
fn references_libexec(src: &str) -> bool {
    src.starts_with("packaging/systemd/") || src.ends_with(".service")
}

fn version() -> Result<String> {
    let manifest = fs::read_to_string(workspace_root().join("Cargo.toml"))
        .map_err(|e| Error::Msg(e.to_string()))?;
    manifest
        .lines()
        .find_map(|l| {
            l.strip_prefix("version = \"")
                .and_then(|v| v.strip_suffix('"'))
        })
        .map(str::to_owned)
        .ok_or_else(|| Error::Msg("workspace version not found".into()))
}

/// Where a source file is read from: built artefacts (`target/...`) come from Cargo's
/// target directory, which honours `CARGO_TARGET_DIR`; everything else from the workspace.
fn source_path(ws: &Path, target_dir: &Path, src: &str) -> PathBuf {
    match src.strip_prefix("target/") {
        Some(rest) => target_dir.join(rest),
        None => ws.join(src),
    }
}

fn cargo_target_dir(ws: &Path) -> PathBuf {
    match std::env::var_os("CARGO_TARGET_DIR") {
        Some(dir) => ws.join(dir), // absolute paths replace `ws` in `join`
        None => ws.join("target"),
    }
}

fn install(root: &Path, prefix: &str, libexecdir: &str) -> Result {
    let ws = workspace_root();
    let target_dir = cargo_target_dir(&ws);
    for (src, dest, mode) in INSTALL {
        let target = root.join(destination(dest, prefix, libexecdir));
        if let Some(parent) = target.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| Error::Msg(format!("{}: {e}", parent.display())))?;
        }
        if references_libexec(src) {
            let text = fs::read_to_string(source_path(&ws, &target_dir, src))
                .map_err(|e| Error::Msg(format!("{src}: {e}")))?;
            let rewritten = text.replace(
                "/usr/libexec/passkey-tpm/",
                &format!("{libexecdir}/passkey-tpm/"),
            );
            fs::write(&target, rewritten).map_err(|e| Error::Msg(format!("{src}: {e}")))?;
        } else {
            fs::copy(source_path(&ws, &target_dir, src), &target)
                .map_err(|e| Error::Msg(format!("{src}: {e}")))?;
        }
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&target, fs::Permissions::from_mode(*mode))
            .map_err(|e| Error::Msg(e.to_string()))?;
    }
    Ok(())
}

pub fn run(args: &[String]) -> Result {
    let opts = Options::parse(args)?;
    if !opts.no_build {
        let mut build = cargo();
        build.args(["build", "--release", "--locked"]);
        for bin in BINARIES {
            build.args(["-p", bin]);
        }
        exec(&mut build)?;
    }
    match &opts.destdir {
        Some(destdir) => install(destdir, &opts.prefix, &opts.libexecdir()),
        None => {
            let name = format!("passkey-tpm-{}", version()?);
            let dist = workspace_root().join("target").join("dist");
            let root = dist.join(&name);
            let _ = fs::remove_dir_all(&root);
            install(&root, &opts.prefix, &opts.libexecdir())?;
            exec(
                Command::new("tar")
                    .current_dir(&dist)
                    .args(["--owner=0", "--group=0", "-czf"])
                    .arg(format!("{name}.tar.gz"))
                    .arg(&name),
            )?;
            println!("wrote {}", dist.join(format!("{name}.tar.gz")).display());
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_packaged_source_file_exists() {
        let ws = workspace_root();
        for (src, _, _) in INSTALL.iter().filter(|(s, _, _)| !s.starts_with("target/")) {
            assert!(ws.join(src).is_file(), "{src} missing");
        }
    }

    #[test]
    fn destinations_follow_the_prefix_and_are_unique() {
        let dests: Vec<PathBuf> = INSTALL
            .iter()
            .map(|(_, d, _)| destination(d, "/usr", "/usr/libexec"))
            .collect();
        assert!(dests
            .iter()
            .all(|d| d.starts_with("usr") || d.starts_with("etc/xdg/autostart")));
        let mut unique = dests.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), dests.len());
        assert_eq!(
            destination("{prefix}/bin/x", "/opt/pk", "/opt/pk/libexec"),
            PathBuf::from("opt/pk/bin/x")
        );
        assert_eq!(
            destination("{libexecdir}/passkey-tpm/a", "/usr", "/usr/lib"),
            PathBuf::from("usr/lib/passkey-tpm/a")
        );
    }

    #[test]
    fn built_artefacts_come_from_the_cargo_target_dir() {
        let ws = Path::new("/src/ws");
        let target = Path::new("/build/target");
        assert_eq!(
            source_path(ws, target, "target/release/passkey-tpm-uvd"),
            PathBuf::from("/build/target/release/passkey-tpm-uvd")
        );
        assert_eq!(
            source_path(ws, target, "README.md"),
            PathBuf::from("/src/ws/README.md")
        );
    }

    #[test]
    fn parses_options() {
        let args: Vec<String> = [
            "--destdir",
            "/tmp/x",
            "--prefix",
            "/usr/local/",
            "--no-build",
        ]
        .map(String::from)
        .to_vec();
        assert_eq!(
            Options::parse(&args).unwrap(),
            Options {
                destdir: Some("/tmp/x".into()),
                prefix: "/usr/local".into(),
                libexecdir: None,
                no_build: true
            }
        );
        assert!(Options::parse(&["--prefix".into(), "usr".into()]).is_err());
        let arch = Options::parse(&["--libexecdir".into(), "/usr/lib".into()]).unwrap();
        assert_eq!(arch.libexecdir(), "/usr/lib");
    }

    #[test]
    fn units_reference_libexec_so_they_can_be_rewritten() {
        let ws = workspace_root();
        for (src, _, _) in INSTALL.iter().filter(|(s, _, _)| references_libexec(s)) {
            let text = std::fs::read_to_string(ws.join(src)).unwrap();
            if src.contains("dbus") {
                continue; // D-Bus activation goes through SystemdService=, no binary path.
            }
            assert!(text.contains("/usr/libexec/passkey-tpm/"), "{src}");
        }
    }
}
