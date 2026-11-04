# Security Hardening — Tasks

**Spec:** `.specs/features/security-hardening/spec.md`
**Design:** inline per task (fixes are local); G1–G4 decisions go to `context.md` in this folder
**Testing:** `.specs/codebase/TESTING.md`
**Status:** Phase 1 done; H8, H9, H11, H12, H14, H15, H17, H18, H20–H23 done (2026-10-04); H10/H13/H16 wait on G2–G4; H19, H24 open

Rule for every task: re-confirm the finding by writing the failing regression test first. If the test passes on unmodified code, mark the requirement "Not reproducible" with the evidence and skip the fix.

## Results

| Task | Status | Commit | Notes |
|---|---|---|---|
| H1 | ✅ | ecc2496, 61dcb13 | activation only when unowned (dbus-daemon 1.16 `ServiceUnknown` on owned names without .service); 2 activation tests reproduced the bug first; uvd keeps `uv=false` on fprintd errors (logged) |
| H2 | ✅ | 8ad6255 | `check_pin` restores the counter on non-`WrongPin` errors; test reproduced 3→2 on lockout |
| H3 | ✅ | fa0495d | `check_builtin_uv` / `check_pin_not_blocked` shared with the token path; PIN-UV + fingerprint-presence checks PIN block only (context.md) |
| H4 | ✅ | this commit | G1 = both checks, fail closed (context.md, AD-020) |
| H5 | ✅ | 1821259 | `passkey_tpm_uv::seat::Logind` (by uid; seatless sessions don't count); broker test + mock-logind tests |
| H6 | ✅ | 8f47348 | agent removes/re-creates the device on one `/dev/uhid` handle (`UhidWriter::remove_device`/`recreate`); `Hid::reset` cancels in-flight work; device `HID_PHYS` carries the uid |
| H7 | ✅ | 63a2cf8 | VM: autologin gettys on VT 2/3 + `chvt`; 41/41 scenarios green (needs `kbd` in the image) |

| H17 | ✅ | 315bccc | MAC check (`verify_auth_mac`) before lookup; RP scope still checked after |
| H20 | ✅ | cb1e553 | `Zeroizing` PIN hashes + hmac-secret output; `TpmOps::hmac` still returns a plain array (tpm crate) |
| H18 | ✅ | 4f7fcf6 | MAC over raw `subCommandParams` bytes (`cbor::map_value_raw`); Kani harness `skip_item_never_panics` added, **not run** (pinned Kani not installed) |
| H14 | ✅ | a0c3576 | INIT on busy CID aborts + Cancel; unknown CID → INVALID_CHANNEL; broker requests carry an id so late replies can't reach a new request |
| H15 | ✅ | 883df37 | cancel token registered as soon as the uid is known (before the seat check) |
| H23 | ✅ | 16318cf | `TpmWorker::closed()`; uvd exits non-zero when the worker ends |
| H21 | ✅ | 9728472 | CLI refuses `user remove` while the broker name has an owner (`--force` to override); D-Bus activation window remains |

| H11 | ✅ | 3412e96 | core skips the HMAC for credentials without hmac-secret keys (ED clear, no output); new swtpm-backed core test `crates/tpm/tests/ctap.rs` |
| H12 | ✅ | afa2a49 | only create_credential/change_pin provision; read-only calls answer as for an unregistered user; partial provisioning undefines what it created |
| H9 | ✅ | d7c68b1 | begin → persist pending (gates.v1 version 2 while pending) → redefine → clear; repair on load; fault-injected at all 5 steps |
| H8 | ✅ | 8899b1f | per-uid wrong-PIN ledger in `<state>/da/<uid>` that survives reset; budget = min(8, maxTries − 1), forgiven at the TPM recovery interval |
| H22 | ✅ | f151e62 | never deletes a pre-existing temp file; dir-fsync failure no longer triggers cleanup |

Gate after phase 1: `cargo xtask ci` green, 226 tests (217 before), Verus 103 verified / 0 errors.
Gate after H14–H23 batch: 240 tests, Verus 103 / 0 (fresh run).
Gate after H8–H22 batch (merged): 254 tests, Verus 103 / 0 (fresh), VM 41/41 (isolation gate test updated for lazy provisioning).

## Execution Plan

### Phase 1: P1 — beta blockers

```
H1 [P] ──────────────────────────┐
H2 [P] ──────────────────────────┤
H3 [P] ──────────────────────────┼──→ beta-release B9
H4 (G1 decision) → H5 → H6 → H7 ─┘
```

### Phase 2: P2 (after the beta tag, before 0.1.0)

```
H8 [P]   H9 [P]   H11 [P]   H12 [P]
H10a (G2 decision) → H10b
H13 (G4 design → own feature)
```

### Phase 3: P3 (any order, all parallel-safe)

```
H14 [P]  H15 [P]  H16 (G3) [P]  H17 [P]  H18 [P]  H19 [P]
H20 [P]  H21 [P]  H22 [P]  H23 [P]  H24 (at each tag)
```

---

## Phase 1 tasks

### H1: Activate fprintd before resolving its owner [P]

**What**: Call `org.freedesktop.DBus.StartServiceByName("net.reactivated.Fprint", 0)` in `name_owner` (or before each use), mapping failure to a distinct "UV unavailable" error.
**Where**: `crates/uv/src/fprintd.rs` (`name_owner`, ~l.152; callers ~l.220, ~l.287); error mapping in `crates/uvd/src/lib.rs` (~l.221)
**Depends on**: None
**Reuses**: `device_description`'s existing activation workaround in the same file
**Requirement**: HARD-02
**Done when**:
- [ ] Mock fprintd registered as an activatable service on the private test bus, not running at request time; `has_enrolled` and `verify` succeed
- [ ] Activation failure yields UV-unavailable, not `uv_enrolled=false`
**Tests**: integration-dbus (`crates/uv/tests/fprintd.rs`)
**Gate**: quick

### H2: Restore PIN retries when the PIN was not actually checked [P]

**What**: In clientPIN `getPinToken`/`changePin` flows, restore the pre-decrement counter when `verify_pin` returns `Lockout`/`Unavailable` (anything but `WrongPin`); return `PIN_AUTH_BLOCKED`/`NOT_ALLOWED` as appropriate. Keep AD-010 (decrement before check).
**Where**: `crates/core/src/ctap2/client_pin.rs` (~l.194–223)
**Depends on**: None
**Requirement**: HARD-03
**Done when**:
- [ ] Scenario test: mock `TpmOps::verify_pin` → `Lockout` leaves `pin_retries` unchanged
- [ ] Wrong PIN still decrements and persists before the TPM call
- [ ] `cargo xtask verus` green
**Tests**: unit + proof
**Gate**: quick + proof

### H3: Enforce UV and PIN blocks in the gesture path [P]

**What**: `gesture` checks `uv_failures >= MAX_UV_RETRIES` → `UV_BLOCKED` and `pin_retries == 0` → `PIN_BLOCKED` before prompting, same as `prepare_token_using_uv`. Persist `uv_failures` per uid alongside `pin_retries` (currently memory-only), or record why memory-only is acceptable.
**Where**: `crates/core/src/ctap2/make_credential.rs` (`gesture`, ~l.169–185); `crates/core/src/ctap2/client_pin.rs` (~l.298–304, shared helper); `crates/tpm/src/adapter.rs` if persisted
**Depends on**: None (touches `client_pin.rs` helper only by extraction; run after H2 if both edit the same function)
**Requirement**: HARD-04
**Done when**:
- [ ] Tests: 3 failed fingerprint attempts then makeCredential → `UV_BLOCKED` without a prompt; PIN-blocked user → `PIN_BLOCKED`
- [ ] Verus green
**Tests**: unit + proof
**Gate**: quick + proof

### H4: Decide G1 (session binding)

**What**: Record the G1 decision (recommended: both agent-side and uvd-side checks) in `context.md`; add the next AD-0xx to STATE.md.
**Where**: `.specs/features/security-hardening/context.md`, `.specs/project/STATE.md`
**Depends on**: None
**Requirement**: HARD-01
**Done when**:
- [ ] Decision recorded with the logind APIs used (`GetSessionByPID` / `Session.Active` / `Seat`) and the fail-closed rule
**Tests**: none

### H5: uvd rejects callers without an active seat session

**What**: Resolve the caller's PID from bus credentials → logind session; serve only if `Active` and on a seat; otherwise `OPERATION_DENIED` + audit log. Test-only override env var for CI (documented, ignored when not built with the test feature).
**Where**: `crates/uvd/src/lib.rs` (request entry), new `crates/uvd/src/logind.rs`
**Depends on**: H4
**Requirement**: HARD-01 (AC 2)
**Done when**:
- [ ] Mock logind on the private bus: active → served; inactive → denied; no logind → denied
**Tests**: integration-dbus (`crates/uvd/tests/broker.rs`)
**Gate**: quick

### H6: Agent drops the device while its session is inactive

**What**: Agent subscribes to its own session's `PropertiesChanged(Active)`; on inactive, destroys the uhid device (cancelling in-flight work); on active, recreates it.
**Where**: `crates/agent/src/main.rs` (~l.118), `crates/agent/src/lib.rs`
**Depends on**: H4
**Requirement**: HARD-01 (AC 1)
**Done when**:
- [ ] Unit test of the state transition (inactive → `Effect::Destroy`, active → `Effect::Create`)
- [ ] Manual or VM check that the hidraw node disappears on VT switch
**Tests**: unit (agent logic) — device lifecycle covered by H7
**Gate**: quick

### H7: VM scenario — session switch

**What**: Extend the two-user isolation test: alice active → switch to bob → bob opens alice's former hidraw path / enumerates FIDO devices; assert no request with `uid=<alice>` in the broker audit.
**Where**: `tests/vm/e2e/tests/test_40_isolation.py`, helpers in `tests/vm/e2e/pkt.py`
**Depends on**: H5, H6
**Requirement**: HARD-01 (AC 3)
**Done when**:
- [ ] Scenario fails on `main`, passes with H5+H6
**Tests**: vm-e2e
**Gate**: `cargo xtask vm`

## Phase 2 tasks

### H8: Per-uid wrong-PIN budget that survives reset [P]

**What**: Persist a per-uid DA budget (wrong PINs per rolling window) outside the state that `authenticatorReset` wipes; refuse PIN attempts when exhausted. Alternative: rate-limit resets per uid. Pick in the task, record in context.md.
**Where**: `crates/tpm/src/adapter.rs` (~l.327), `crates/core/src/ctap2/authn.rs` (~l.173)
**Depends on**: None
**Requirement**: HARD-05
**Done when**:
- [ ] integration-tpm: loop setPIN → 8 wrong → reset is stopped before the swtpm DA counter reaches `maxTries`
**Tests**: integration-tpm + unit
**Gate**: quick

### H9: Crash-safe PIN rotation [P]

**What**: Write the new gate store with a `pending_rotation` marker first, then undefine/redefine the NV index, then clear the marker; on load, repair a pending rotation (closes the STATE todo "re-define the PIN NV index").
**Where**: `crates/tpm/src/nvgate.rs` (~l.184), `crates/tpm/src/pin.rs` (~l.59, 92), `crates/tpm/src/adapter.rs` (~l.252), `crates/wire/src/gatestore.rs` (schema field)
**Depends on**: None
**Requirement**: HARD-06
**Done when**:
- [ ] Fault-injection test kills the flow after each step; PIN is old or new on restart, never unusable
- [ ] gatestore codec change has unit + proptest + fuzz target updated; Kani harness still bounded
**Tests**: integration-tpm + unit + bounded proof (wire)
**Gate**: quick (+ kani for wire, slow tier)

### H10a: Decide G2 (silent probe) — amend AD-012 ✅

**What**: Record the decision in context.md and amend AD-012 in STATE.md.
**Requirement**: HARD-07
**Tests**: none

### H10b: Silent probes don't reveal credential existence ✅

**What**: `up=false` without UV → `NO_CREDENTIALS` regardless; with a valid token → assertion with UP=0.
**Where**: `crates/core/src/ctap2/get_assertion.rs` (~l.76–84)
**Depends on**: H10a
**Requirement**: HARD-07
**Done when**:
- [x] Scenario tests for both branches
- [x] libfido2 VM check still passes (VM e2e: 42 passed)
**Tests**: unit + proof
**Gate**: quick + proof

### H11: Omit hmac-secret output for credentials created without it [P]

**What**: When `blobs.hmac` is `None`, skip the HMAC and omit the extension output instead of `Corrupt` → `NO_CREDENTIALS`.
**Where**: `crates/tpm/src/sign.rs` (~l.181–185), `crates/tpm/src/error.rs` (~l.79), `crates/core/src/ctap2/get_assertion.rs` (extension assembly)
**Depends on**: None
**Requirement**: HARD-08
**Done when**:
- [ ] integration-tpm: credential without hmac-secret + assertion requesting it → success, no extension output
**Tests**: integration-tpm + unit
**Gate**: quick

### H12: Lazy provisioning with cleanup [P]

**What**: `getInfo`/`pin_is_set` read state without provisioning; provision on makeCredential/setPin only; on partial failure, undefine the indexes created so far.
**Where**: `crates/tpm/src/adapter.rs` (~l.96–110)
**Depends on**: None (coordinate with H5: unauthenticated uids are already rejected there)
**Requirement**: HARD-09
**Done when**:
- [ ] integration-tpm: getInfo from a new uid creates no NV index; injected failure after the 2nd define leaves no index
**Tests**: integration-tpm
**Gate**: quick

### H13: Design the uhid least-privilege path (G4)

**What**: Compare (a) a privileged helper that only creates the FIDO report descriptor and passes the fd, (b) uvd creating the device per active session; pick one, write `.specs/features/uhid-helper/spec.md`. Meanwhile document the `uaccess` risk in the beta release notes and fix the misleading comment in the udev rule.
**Where**: `packaging/udev/70-passkey-tpm-uhid.rules` (comment), new feature folder
**Depends on**: H4 (session model)
**Requirement**: HARD-10
**Tests**: none (design)

## Phase 3 tasks (all [P], unit unless stated)

| Task | What | Where | Req | Tests |
|---|---|---|---|---|
| H14 | INIT on in-flight CID aborts + `Effect::Cancel`; unknown non-broadcast CID → `ERR_INVALID_CHANNEL` | `crates/agent/src/lib.rs` ~l.147–161 (and core `ctaphid.rs` if the rule belongs there) | HARD-11 | unit (+ proof if in core) |
| H15 | Register the cancel token at the start of `run`; check it before verify | `crates/uvd/src/lib.rs` ~l.237, 273–285 | HARD-12 | integration-dbus |
| H16 | Reset window per G3 (+ CLI reset if chosen) | `crates/core/src/ctap2/authn.rs` ~l.136, 173–180; `crates/cli` | HARD-13 | unit + proof |
| H17 | Verify `pinUvAuthParam` before credential lookup | `crates/core/src/ctap2/cred_mgmt.rs` ~l.95–98 | HARD-14 | unit |
| H18 | MAC over raw `subCommandParams` bytes (or reject non-canonical) | `crates/core/src/ctap2/cred_mgmt.rs` ~l.80, `crates/wire/src/cbor.rs` (raw span) | HARD-15 | unit + fuzz (wire) |
| H19 | Route retry counting through `PinRetries` (or drop the claim) | `crates/core/src/pin_retries.rs`, `client_pin.rs`, `crates/tpm/src/adapter.rs` ~l.274–291 | HARD-16 | unit + proof |
| H20 | `Zeroizing` for hmac-secret outputs and PIN hashes | `get_assertion.rs` ~l.232, `client_pin.rs` ~l.64, 199, 238 | HARD-17 | unit |
| H21 | `user remove` refuses while uvd runs, or D-Bus `Evict(uid)` | `crates/cli/src/main.rs` ~l.98–121, `crates/uvd` | HARD-18 | integration-dbus |
| H22 | Only clean up a temp file this call created | `crates/tpm/src/fsutil.rs` ~l.39–41 | HARD-19 | unit |
| H23 | uvd exits non-zero when the worker channel closes | `crates/uvd/src/main.rs` ~l.63 | HARD-20 | integration-dbus |
| H24 | Fill `sha256sums` at each tag (xtask helper or release checklist) | `packaging/arch/PKGBUILD`, `.SRCINFO` | HARD-21 | none |

---

## Validation

**Diagram ↔ definitions**

| Task | Depends on (definition) | Diagram | OK |
|---|---|---|---|
| H1, H2, H3 | None | [P] → B9 | ✅ |
| H4 | None | start of chain | ✅ |
| H5 | H4 | H4 → H5 | ✅ |
| H6 | H4 | H5 → H6 (serialised for review; no code dependency on H5) | ✅ |
| H7 | H5, H6 | H6 → H7 | ✅ |
| H8, H9, H11, H12 | None | [P] | ✅ |
| H10b | H10a | H10a → H10b | ✅ |
| H13 | H4 | phase 2 (after phase 1) | ✅ |
| H14–H24 | None | [P] | ✅ |

**Test co-location (TESTING.md matrix)**

| Task | Layer | Required | In task | OK |
|---|---|---|---|---|
| H1 | D-Bus service client | integration-dbus | yes | ✅ |
| H2, H3, H10b, H16, H19 | core state machine | unit + proof | yes | ✅ |
| H5, H15, H21, H23 | D-Bus services | integration-dbus | yes | ✅ |
| H6, H14 | agent (D-Bus/uhid service) | integration-dbus | unit + vm (H7) — agent has no private-bus harness yet | ⚠️ accepted: add harness if H6 logic grows |
| H7 | end to end | vm-e2e | yes | ✅ |
| H8, H9, H11, H12 | TPM shell | integration-tpm | yes | ✅ |
| H9, H18 (wire parts) | codecs | unit + bounded proof + fuzz | yes | ✅ |
| H4, H10a, H13, H24 | docs/config | none | none | ✅ |
| H17, H20, H22 | core / tpm helpers | unit | yes | ✅ |
