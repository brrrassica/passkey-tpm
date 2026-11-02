%global upstream_version 0.1.0-brrr1

Name:           passkey-tpm
# "~" sorts the pre-release before the final 0.1.0.
Version:        0.1.0~brrr1
Release:        1%{?dist}
Summary:        TPM-backed passkeys (FIDO2/WebAuthn) for Linux
License:        MIT OR Apache-2.0
URL:            https://github.com/brrrassica/passkey-tpm
Source0:        %{url}/archive/v%{upstream_version}/%{name}-%{upstream_version}.tar.gz
# COPR builds vendor crates (rust2rpm -V); a Fedora review would use system crates instead.
Source1:        %{name}-%{upstream_version}-vendor.tar.xz
Source2:        passkey-tpm.sysusers

BuildRequires:  cargo-rpm-macros >= 24
BuildRequires:  pkgconfig(tss2-esys)
BuildRequires:  systemd-rpm-macros
Requires:       fprintd
Requires:       polkit
Requires:       dbus
%{?sysusers_requires_compat}

%description
passkey-tpm is a FIDO2/WebAuthn authenticator whose credentials are bound to the
machine's TPM 2.0 and unlocked with fingerprint or PIN. A privileged broker holds the
TPM policy secrets; a per-user agent exposes a virtual security key.

%prep
%autosetup -n %{name}-%{upstream_version} -a1
%cargo_prep -v vendor

%build
%cargo_build -- -p passkey-tpm-uvd -p passkey-tpm-agent -p passkey-tpm-cli -p passkey-tpm-tray

%install
cargo run --offline -q -p xtask -- dist --no-build --destdir %{buildroot} --prefix %{_prefix} --libexecdir %{_libexecdir}

%check
%cargo_test -- -p passkey-tpm-core -p passkey-tpm-wire -p passkey-tpm-agent -p passkey-tpm-tray

%pre
%sysusers_create_compat %{SOURCE2}

%post
%systemd_post passkey-tpm-uvd.service
%systemd_user_post passkey-tpm-agent.service
%udev_rules_update

%preun
%systemd_preun passkey-tpm-uvd.service
%systemd_user_preun passkey-tpm-agent.service

%postun
%systemd_postun_with_restart passkey-tpm-uvd.service
%udev_rules_update

%files
%license LICENSE-MIT LICENSE-APACHE
%doc README.md SECURITY.md docs/threat-model.md
%{_bindir}/passkey-tpm
%{_bindir}/passkey-tpm-tray
%{_sysconfdir}/xdg/autostart/passkey-tpm-tray.desktop
%{_libexecdir}/passkey-tpm/
%{_unitdir}/passkey-tpm-uvd.service
%{_userunitdir}/passkey-tpm-agent.service
%{_datadir}/dbus-1/system.d/io.github.dangerousplay.PasskeyTpm1.conf
%{_datadir}/dbus-1/system-services/io.github.dangerousplay.PasskeyTpm1.service
%{_datadir}/polkit-1/rules.d/50-passkey-tpm-fprintd.rules
%{_udevrulesdir}/70-passkey-tpm-uhid.rules
%{_sysusersdir}/passkey-tpm.conf
%{_modulesloaddir}/passkey-tpm.conf

%changelog
* Tue Oct 13 2026 Davi Henrique <dangerousplay715@gmail.com> - 0.1.0~beta.2-1
- Second beta: tray icon, PIN + presence for users without a fingerprint

* Sun Oct 04 2026 Davi Henrique <dangerousplay715@gmail.com> - 0.1.0~beta.1-1
- First beta

* Sat Oct 03 2026 Davi Henrique <dangerousplay715@gmail.com> - 0.1.0-1
- Initial package
