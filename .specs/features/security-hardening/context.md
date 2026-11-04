# Security Hardening — Decisions on Gray Areas

## G1: Binding the authenticator to the seat user (decided 2026-10-04, AD-020)

**Decision:** both sides check, and both fail closed.

- **Broker (H5):** before serving `Ctap`, uvd asks logind whether the caller's uid has a session that is on a seat (`ListSessions`, non-empty seat) and `Active`. If not, it answers `CTAP2_ERR_OPERATION_DENIED` (0x27) and logs `denied uid=…`. Errors talking to logind count as "not active".
- **Agent (H6):** the agent watches logind (`SessionNew`/`SessionRemoved` on the Manager, `PropertiesChanged` on sessions, plus a 2 s poll). While its user isn't active on a seat it removes its HID device (`UHID_DESTROY`) and re-creates it on the same `/dev/uhid` handle when the user returns. On removal, the CTAPHID state is reset and an in-flight broker request is cancelled.

**Why both:** the broker check alone leaves a hole. Descriptors are only checked at open, so user B could open A's hidraw node while B is at the seat, keep the fd, and use it after A switches back, when the broker sees A as active again. Removing the device invalidates every descriptor (verified in the VM: `test_descriptor_opened_before_a_switch_stops_working`). The agent check alone isn't enough either, because the agent runs as the user and same-user code can skip it.

**Why by uid and not by caller PID:** the agent runs under `user@.service`, outside any login session, so `GetSessionByPID` doesn't resolve it.

**What we gave up:**
- A user with only a seatless session (SSH, `machinectl shell`) can't use the authenticator.
- A user logged in on two seats is served while either seat is active.
- Without logind, nothing works: Linux + systemd is the supported platform (AD-015).

**Residual risk:** for up to ~2 s after a switch (if the signal is missed) A's device still exists while B is active, so B could open it. That descriptor dies when the device is removed, and the broker refuses A's requests while A is in the background.

**Identification:** each agent's device carries `HID_PHYS=passkey-tpm-agent/uid=<uid>`, so tools and tests can tell users' devices apart.

## G2: silent probes (decided 2026-11-04, issue #5)

A silent (`up=false`) getAssertion without a pinUvAuthParam always gets `NO_CREDENTIALS`, before any credential lookup. With a valid token it gets a real assertion with UP=0 and UV=1, signed through the UV gate, and the token keeps its presence for the request that follows. Firefox (authenticator-rs `do_credential_list_filtering_ctap2`) filters allowList and excludeList this way with the PIN token, and drops every credential whose probe fails, so the old `UNSUPPORTED_OPTION` made allowList sign-in impossible.

## G3, G4

Still open. They're needed for phase 3 (H16, H13). The recommendations in the spec stand.

## Notes from the P1 implementation

- **H1:** `StartServiceByName` runs only when `net.reactivated.Fprint` has no owner. dbus-daemon 1.16 answers `ServiceUnknown` for an owned name that has no `.service` file, which would break a hand-started fprintd.
  - If fprintd can't be reached, uvd logs it and advertises no built-in UV, so clients fall back to the PIN.
  - A three-state `UserInfo` in core (enrolled / not enrolled / unavailable) would be cleaner. Deferred.
- **H3:** the fingerprint gesture path checks `UV_BLOCKED`, then `PIN_BLOCKED`, before prompting.
  - When a PIN token already supplied UV and the fingerprint is only needed for presence, only `PIN_BLOCKED` applies. That keeps the PIN usable as a fallback once fingerprint UV is blocked.
  - Trade-off: a PIN holder gets unlimited presence attempts.
  - `uv_failures` stays in memory, so it resets when the broker restarts.
  - Reset and Selection (`need_gesture`) are unchanged: reset must stay reachable when the PIN is blocked.
- **`MAX_UV_RETRIES` is 5** (`common.rs`), not 3 as the task text said.

## H8: wrong-PIN budget (decided in implementation, 2026-10-04)

**Choice:** a per-uid ledger of wrong-PIN failures in `<state>/da/<uid>`, kept outside the directory that `authenticatorReset` wipes. The other option was rate-limiting resets per uid.

**How it works:**
- One failure is charged before every PIN check that the TPM counts against its DA limit. It is refunded unless the TPM reports a wrong PIN.
- The budget is `min(8, maxTries − 1)`, so one uid can never lock out the TPM-wide DA counter.
- Failures are forgiven at the TPM's own recovery interval.
- When the budget is spent, PIN checks return `Lockout` without reaching the TPM.
- A corrupt ledger counts as spent.

**Follow-ups:**
- A recovery interval of 0 is read as "nothing forgiven". A uid that spends its budget stays blocked until an admin deletes its ledger.
- A correct PIN doesn't reset the ledger, because it doesn't reset the TPM counter either. So `PIN_AUTH_BLOCKED` can appear before the CTAP retries reach 0.
- `passkey-tpm user remove` doesn't delete the ledger. Harmless; keeping it is arguably right.
- `TpmOps::hmac` still returns a plain `[u8; 32]`. Wrapping it in `Zeroizing` completes HARD-17.
