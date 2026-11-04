# Security Hardening (code review 2026-10-04) — Specification

**Size:** Large (multi-component: agent, broker, core, tpm, packaging)
**Status:** 18 of 21 Verified (2026-11-04). Open: HARD-10 (G4), HARD-13 (G3), HARD-16 (PinRetries); HARD-21 (PKGBUILD checksum) is done at tag time.
**Source:** read-only code review of `main` @ a81da2f, 2026-10-04. The two High findings (F1 session isolation, F3 fprintd activation) were re-checked against the code; the rest must be re-confirmed at the start of their task (write the failing test first).

## Problem Statement

The review found a cross-user path on multi-seat / fast-user-switching machines, a likely total failure of fingerprint UV when fprintd is idle-exited, and several PIN/lockout, spec-conformance and robustness bugs. The beta (`.specs/features/beta-release/`) must not ship with the P1 items open.

## Goals

- [ ] No user can drive another user's authenticator, on any seat state (HARD-01)
- [ ] Fingerprint UV works when fprintd is not running (HARD-02)
- [ ] PIN retries and UV attempts are counted exactly as CTAP 2.1 and AD-010 say (HARD-03, HARD-04)
- [ ] Every finding is either fixed with a regression test or recorded as an accepted risk in STATE.md

## Out of Scope

| Feature | Reason |
|---|---|
| External security audit | M3 "Security review" item |
| Trusted prompt (broker-driven UI) | M4; only referenced by G1 |
| tss-esapi 8 migration (DA parameter bindings) | Blocked on a stable release (B-002) |

## Gray Areas (decide before the task starts)

| ID | Question | Options | Recommendation |
|---|---|---|---|
| G1 ✅ (both, AD-020) | How is the agent's device bound to an active session? | (a) agent watches logind `Session.Active` and destroys/recreates the uhid device; (b) uvd checks via logind that the caller's session is active on its seat; (c) both | (c): (a) closes the device-ACL hand-over, (b) is the enforcement point the agent can't skip |
| G2 ✅ (context.md) | Silent `up=false` probes (AD-012) | keep `UNSUPPORTED_OPTION` when a credential exists, or always `NO_CREDENTIALS` without UV (§6.2.2 step 7 for credProtect=3) | always `NO_CREDENTIALS` without UV; amend AD-012 |
| G3 | authenticatorReset timing (§6.6 "within 10 s of power-up") | 10 s after agent start; 10 s after device (re)creation; CLI-only reset | 10 s after device creation + CLI `passkey-tpm reset` for later |
| G4 | `/dev/uhid` access | keep `uaccess` (document risk); privileged helper that only creates the FIDO descriptor and passes the fd; uvd creates the device per active session | helper, M3; document risk in beta notes |

---

## User Stories

### P1: One user cannot reach another user's authenticator ⭐ MVP

**User Story**: As a user on a shared machine, I want my passkeys, PIN and retry counter to be unreachable from other local users, including after a fast user switch.

**Acceptance Criteria** (HARD-01):

1. WHEN user A's session becomes inactive THEN A's virtual FIDO device SHALL stop accepting CTAPHID traffic (G1)
2. WHEN a broker request arrives from a uid whose session is not active on a seat THEN uvd SHALL reject it with `CTAP2_ERR_OPERATION_DENIED` and log the uid (G1)
3. WHEN user B opens A's hidraw node after a switch THEN no request SHALL reach the broker as uid A (VM two-user test)

**Independent Test**: VM: two logind sessions, switch VTs, `fido2-token -I` from B against A's device fails; broker audit shows no `uid=A` request.

### P1: Fingerprint UV works with an idle fprintd ⭐ MVP

**User Story**: As a user, I want a fingerprint prompt even if fprintd exited after its idle timeout.

**Acceptance Criteria** (HARD-02):

1. WHEN `net.reactivated.Fprint` has no owner THEN `has_enrolled` and `verify` SHALL D-Bus-activate it (`StartServiceByName`) before `GetNameOwner`
2. WHEN activation fails THEN the broker SHALL report UV unavailable (not "not enrolled") and log the D-Bus error

**Independent Test**: integration-dbus test with an activatable mock fprintd that is not running at request time.

### P1: PIN retries and UV attempts counted correctly ⭐ MVP

**Acceptance Criteria**:

1. WHEN `verify_pin` fails with anything other than a wrong PIN (TPM lockout, unavailable) THEN the decremented retry counter SHALL be restored (HARD-03)
2. WHEN the fingerprint gesture path (`make_credential`/`get_assertion` → `gesture`) runs with `uv_failures >= MAX_UV_RETRIES` or `pin_retries == 0` THEN it SHALL fail with `UV_BLOCKED`/`PIN_BLOCKED` without prompting (HARD-04, AD-010)

**Independent Test**: core scenario tests with a mock `TpmOps` returning `Lockout`; gesture after 3 UV failures.

### P2: Shared-TPM and durability safety

1. WHEN a user repeats setPIN + wrong PINs + reset THEN the TPM-wide DA counter SHALL NOT be driven to lockout by one uid (per-uid budget surviving reset, or reset rate limit) (HARD-05)
2. WHEN the broker crashes at any point of PIN rotation THEN on restart the PIN SHALL be either the old or the new one, never unusable (persist-first + pending marker + repair on load; closes the STATE todo) (HARD-06)
3. WHEN any local uid calls a read-only method (`getInfo`) THEN no NV index or state dir SHALL be created; provisioning SHALL happen on makeCredential/setPin only, and a partial provision SHALL undefine what it created (HARD-09)
4. WHEN `/dev/uhid` access is granted THEN it SHALL only allow creating the FIDO device (G4) (HARD-10)

### P2: CTAP 2.1 conformance fixes

1. WHEN getAssertion has `up=false` and no valid UV THEN the response SHALL not reveal whether a credential exists (G2) (HARD-07)
2. WHEN getAssertion requests `hmac-secret` for a credential created without it THEN the assertion SHALL succeed with the extension output omitted (HARD-08)

### P3: Robustness and hygiene

| ID | WHEN | THEN SHALL |
|---|---|---|
| HARD-11 | CTAPHID INIT arrives on the in-flight CID, or on an unallocated non-broadcast CID | abort/cancel the in-flight request; reply `ERR_INVALID_CHANNEL` for unknown CIDs |
| HARD-12 | CTAPHID CANCEL arrives before the broker registered the request | the request is cancelled before any prompt |
| HARD-13 | authenticatorReset arrives outside the window chosen in G3 | `CTAP2_ERR_NOT_ALLOWED` |
| HARD-14 | credMgmt delete/update has a bad `pinUvAuthParam` | `PIN_AUTH_INVALID` before any credential lookup |
| HARD-15 | credMgmt `subCommandParams` arrive non-canonically encoded | the MAC is checked over the raw bytes (or the request is rejected as `INVALID_CBOR`) |
| HARD-16 | PIN retries are decremented/reset | the Verus-verified `PinRetries` type does it (or the claim is removed from docs) |
| HARD-17 | hmac-secret outputs or PIN hashes are held in memory | they live in `Zeroizing` buffers |
| HARD-18 | `passkey-tpm user remove` runs while uvd is up | the CLI refuses or uvd evicts the uid's cached `GateStore` |
| HARD-19 | `write_atomic` finds an existing temp file | it fails without deleting a file it didn't create |
| HARD-20 | the uvd TPM worker thread dies | uvd exits non-zero so systemd restarts it |
| HARD-21 | the PKGBUILD is released for a tag | `sha256sums` holds the tarball hash (no `SKIP`) |

---

## Edge Cases

- WHEN logind is unavailable (containers, CI) THEN uvd SHALL fail closed for HARD-01 unless an explicit test-only override is set
- WHEN two sessions of the same uid exist (SSH + graphical) THEN only a request from the active graphical seat SHALL be served (G1)
- WHEN the TPM DA counter is already in lockout at startup THEN getInfo SHALL still answer and PIN operations SHALL return `PIN_AUTH_BLOCKED` without decrementing retries

---

## Requirement Traceability

| ID | Story | Prio | Finding | Phase | Status |
|---|---|---|---|---|---|
| HARD-01 | Cross-user isolation | P1 | F1 | Execute | Verified (VM: 4 isolation scenarios) |
| HARD-02 | fprintd activation | P1 | F3 | Execute | Verified (integration-dbus) |
| HARD-03 | Retry restore on non-PIN errors | P1 | F4 | Execute | Verified (unit + Verus) |
| HARD-04 | UV/PIN-blocked in gesture path | P1 | F6 | Execute | Verified (unit + Verus) |
| HARD-05 | DA budget across reset | P2 | F5 | Execute | Verified (integration-tpm, DA maxTries 3 and 32) |
| HARD-06 | Crash-safe PIN rotation | P2 | F7 | Execute | Verified (integration-tpm fault injection after each step) |
| HARD-07 | up=false probe oracle | P2 | F8 | Execute | Verified (unit + Verus) |
| HARD-08 | hmac-secret on non-hmac credential | P2 | F9 | Execute | Verified (integration-tpm + unit) |
| HARD-09 | Lazy provisioning + cleanup | P2 | F10 | Execute | Verified (integration-tpm + VM) |
| HARD-10 | `/dev/uhid` least privilege | P2 | F2 | Design (G4) | Pending |
| HARD-11 | CTAPHID INIT handling | P3 | F11 | Execute | Verified (unit) |
| HARD-12 | Early cancel | P3 | F12 | Execute | Verified (integration-dbus) |
| HARD-13 | Reset window | P3 | F13 | Tasks (G3) | Pending |
| HARD-14 | credMgmt auth order | P3 | F14 | Execute | Verified (unit) |
| HARD-15 | credMgmt raw-bytes MAC | P3 | F15 | Execute | Verified (unit + proptest + fuzz target) |
| HARD-16 | Use verified `PinRetries` | P3 | F16 | Tasks | Pending |
| HARD-17 | Zeroize secrets | P3 | F17 | Execute | Verified (unit (type-pinned)) |
| HARD-18 | CLI user remove vs cache | P3 | F18 | Execute | Verified (unit + private bus) |
| HARD-19 | fsutil temp cleanup | P3 | F19 | Execute | Verified (unit) |
| HARD-20 | uvd exits on worker death | P3 | F22 | Execute | Verified (unit) |
| HARD-21 | PKGBUILD checksum | P3 | F21 | Tasks | Pending |

**Coverage:** 21 total, 21 mapped to tasks, 0 unmapped. (F20, tracked `.pyc`, already fixed in 1192a89.)

## Success Criteria

- [ ] VM two-user scenario extended with a session switch; no cross-user request
- [ ] Every HARD-* has a regression test (unit, integration-dbus, integration-tpm or vm-e2e per TESTING.md) or an accepted-risk entry
- [ ] Test count does not drop; `cargo xtask ci` green after each task
