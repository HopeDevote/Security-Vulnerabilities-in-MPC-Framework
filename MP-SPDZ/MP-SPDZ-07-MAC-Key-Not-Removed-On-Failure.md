# MP-SPDZ v0.4.3: MAC-Failure Cleanup Executes unlink() Inside assert(), Targets the Wrong File, and Aborts — the Real MAC Key Survives

- **Vulnerability type**: Reachable Assertion (CWE-617); Improper Resource Shutdown or Release
  (CWE-404); side effect inside `assert` (disabled under NDEBUG)
- **Affected product**: MP-SPDZ v0.4.3
- **Affected components**: `Protocols/MAC_Check.hpp` (`mac_fail_remove`),
  `Processor/Online-Thread.hpp` (`Main_Func_With_Purge`); all SPDZ-family binaries
  (`mascot-party.x`, `spdz2k-party.x`, `chaigear-party.x`, …)
- **Severity**: High (the MAC-key survival part is security-critical)
- **Notable**: v0.4.3's changelog advertises a security fix ("Remove MAC key in case of
  failure", doc/security-fixes.rst). This report shows the fix is **ineffective** in default
  configurations.

## Summary

SPDZ requires that a MAC-check failure be a state-destroying event: the MAC key (and correlated
randomness) must never be reused afterwards, otherwise each failed check leaks another linear
equation on the honest parties' key shares. MP-SPDZ v0.4.3 implements the cleanup as
`assert(unlink(filename) == 0)` — the security-critical deletion is a side effect inside an
assert — and the resolved filename (`Mascot-Secrets-p-0-...`) is **not** the file that actually
holds the MAC key (`Mascot-Secrets-p-128-...`). In the default build, the missing file makes
the assertion fire: the process dies with SIGABRT *before* `throw mac_fail()`, the exception
recovery path (`purge_preprocessing`) is skipped, and the real MAC-key file is never deleted.

## Root Cause

```cpp
// Protocols/MAC_Check.hpp:157-167
template<class U>
void mac_fail_remove(const Player& P)
{
  string filename;
  if (U::needs_ot)
    filename = get_ot_secrets_filename<typename U::prep_type>(P);   // resolves to p-0 variant
  else
    filename = U::LivePrep::get_full_secrets_filename(P);
  cerr << "Removing " << filename << " because of MAC check failure" << endl;
  assert(unlink(filename.c_str()) == 0);   // line 165: side effect inside assert
  throw mac_fail();                        // never reached when the assert fires
}
```

Two independent defects:

1. **Side effect inside `assert`**: under `-DNDEBUG` the entire `unlink` call is compiled out —
   the MAC-key file always survives. (Separately observed: NDEBUG builds of this version do not
   even start the online VM, indicating further side-effect-bearing asserts exist.)
2. **Wrong filename + abort ordering**: the resolved `Mascot-Secrets-p-0-...` file normally does
   not exist; `unlink` returns -1; the assertion fails; SIGABRT kills the process before
   `throw mac_fail()`. The recovery path only purges preprocessing on *caught exceptions*:

```cpp
// Processor/Online-Thread.hpp — thread_info::Main_Func_With_Purge()
try { ti.Sub_Main_Func(); }
catch (setup_error&) { throw; }
catch (...) { purge_preprocessing(machine->get_N(), thread_num); throw; }
// abort() is not an exception → purge_preprocessing() is skipped
```

## Attack Preconditions

- A malicious party that deliberately fails a MAC check (standard malicious behavior, e.g.
  corrupting its opening value), or any operational failure that triggers `mac_fail_remove`
  (including the OT-failure path of report 04).

## Impact

- **The advertised 0.4.3 security fix is void in default builds**: the actual MAC-key file
  (`Mascot-Secrets-p-128-...`) is never removed; the next execution silently reloads the same
  MAC key. Since the check opens the `tau`/`delta` values *before* comparing to zero
  (`Commit_And_Open`, MAC_Check.hpp:227-253), every failed check under a reused key exposes one
  more linear equation on the honest key share — repeated failures accumulate toward key
  recovery (completing the chain of report 04).
- **Preprocessing reuse after abort**: with `purge_preprocessing()` skipped, one-shot Beaver
  triples from the failed run can be reused in the next, leaking differences of masked values
  across executions.
- Un-attributable crash: no `mac_fail` propagation, no peer blame.

## Proof of Concept (dynamically verified, default build with asserts enabled)

Malicious-party simulation: the evil party adds 1 to its own MAC-check opening contribution
(`EVILMAC` env-gated patch in `Tree_MAC_Check<U>::exchange`), which makes the subsequent
`Check()` fail at every party.

```bash
md5sum Player-Data/Mascot-Secrets-p-128-*-P0-2   # fingerprint before
./Server.x 2 17999 &
./mascot-party.x -IF Player-Data/Input -N 2 -pn 18000 -h 127.0.0.1 0 poc_mul &
EVILMAC=1 ./mascot-party.x -IF Player-Data/Input -N 2 -pn 18000 -h 127.0.0.1 1 poc_mul &
```

**Observed (both parties):**

```
P1 (evil):   [EVIL] party 1 corrupted its MAC-check opening
P1 (evil):   Removing Player-Data//Mascot-Secrets-p-0-a2c637fcbe0f2e3987f5553234227104f85ca3f9-P1-2 because of MAC check failure
P1 (evil):   mascot-party.x: ./Protocols/MAC_Check.hpp:175: void mac_fail_remove(...): Assertion `unlink(filename.c_str()) == 0' failed.
P0 (honest): Removing Player-Data//Mascot-Secrets-p-0-a2c637fcbe0f2e3987f5553234227104f85ca3f9-P0-2 because of MAC check failure
P0 (honest): ... Assertion `unlink(filename.c_str()) == 0' failed.
```

**Post-mortem:**

```bash
ls Player-Data/Mascot-Secrets-p-128-*-P0-2   # observed: real MAC-key file STILL PRESENT
ls Player-Data/Mascot-Secrets-p-128-*-P1-2   # observed: same on the other party
```

Evidence chain: (1) the cleanup path is reached; (2) it targets a non-existent `p-0` variant;
(3) the assert fires → SIGABRT before `throw mac_fail()`; (4) the real `p-128` key file is
never deleted; (5) on restart the same key is silently reloaded (demonstrated in report 04,
step 4: no "generating from scratch" message, computation succeeds).

## Static Verification

```bash
sed -n 157,167p Protocols/MAC_Check.hpp       # assert(unlink(...) == 0)
grep -rn "get_ot_secrets_filename" OT/        # trace filename → p-0 vs p-128 mismatch
ls Player-Data/Mascot-Secrets-*               # filenames actually produced at runtime
grep -n "purge_preprocessing" Processor/Online-Thread.hpp   # exception-only reachability
```

## Suggested Fix

- Never place side effects in `assert`. Replace with an unconditional call that still throws
  `mac_fail()`:

```cpp
if (unlink(filename.c_str()) != 0)
  cerr << "WARNING: could not remove " << filename << "; do NOT reuse the MAC key" << endl;
throw mac_fail();
```

- Unify the filename resolution with the code that writes the secrets file.
- Make `purge_preprocessing` reachable on abort, or convert the missing-file case into the
  typed `mac_fail` so the exception path runs.

## References

- MP-SPDZ v0.4.3 changelog / doc/security-fixes.rst: "Remove MAC key in case of failure"
- Issue report: https://github.com/data61/MP-SPDZ/issues/1789

## Discoverer

*(to be filled by reporter)*
