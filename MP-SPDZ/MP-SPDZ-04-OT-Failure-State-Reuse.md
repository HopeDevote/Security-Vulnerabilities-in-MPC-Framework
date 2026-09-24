# MP-SPDZ v0.4.3: OT-Thread Failure Kills the Process with exit(1) — Cleanup Never Runs, and the Persisted MAC Key / Base-OT State (Delta) Is Silently Reused After Restart

- **Vulnerability type**: Incomplete Cleanup (CWE-459); Improper Resource Shutdown or Release
  (CWE-404); Observable Internal Behavioral Discrepancy enabling a retry oracle (CWE-203)
- **Affected product**: MP-SPDZ v0.4.3
- **Affected components**: `OT/OTExtension.cpp` (`check_iteration`),
  `OT/NPartyTripleGenerator.hpp` (`run_ot_thread`), `OT/MascotMacKey.hpp`
  (`read_or_generate`), `OT/OTTripleSetup.cpp` (`get_fresh`); all OT-based dishonest-majority
  binaries (`mascot-party.x`, `spdz2k-party.x`, …)
- **Severity**: High (enables repeated probing of the MAC key across restarts)
- **Related**: report 07 / upstream issue
  [#1789](https://github.com/data61/MP-SPDZ/issues/1789) covers the *MAC-check* failure path,
  where cleanup runs but is buggy. This report covers the *OT-thread* failure path, where
  cleanup is **never run at all**; fixing #1789 does not affect this issue.

## Summary

The MASCOT/SPDZ MAC key Delta is reused as the base-OT choice bits (`base_receiver_inputs`,
asserted equal in `OT/OTMultiplier.hpp:125`) and persisted to disk in
`Player-Data/Mascot-Secrets-*`. When an OT worker thread fails — most notably on a KOS15
correlation-check failure — the exception is caught at the thread entry point and converted
into a bare `exit(1)`: no peer notification, no typed error, no invalidation of the persisted
secrets. On the next start, the same Delta is silently reloaded. Because the KOS15 check is a
pass/abort oracle on Delta (https://eprint.iacr.org/2022/192), an attacker can crash the
honest party, wait for the restart, and probe the *same* Delta again — iterating toward MAC
key recovery, after which authenticated shares can be forged.

## Root Cause

```cpp
// OT/OTExtension.cpp:146-154 — sender-side correlation check
if (eq_m128i(tmp1, received_t) && eq_m128i(tmp2, received_t2))
{ /* Check passed */ }
else
{
    cerr << "Correlation check failed\n";
    ...
    throw runtime_error("correlation check");   // untyped, no peer id
}
```

```cpp
// OT/NPartyTripleGenerator.hpp:36-43 — OT thread entry point
try { multiplier->multiply(); }
catch (exception& e)
{
    cerr << "Fatal error in OT thread: " << e.what() << endl;
    exit(1);   // kills the process; mac_fail_remove() is never called
}
```

```cpp
// OT/MascotMacKey.hpp:29-61 — restart reloads the same key material
os.input(filename);          // Mascot-Secrets-* reloads MAC key + base-OT setup
...
key.get_fresh().pack(os);    // get_fresh only advances derived PRG seeds
```

```cpp
// OT/OTTripleSetup.cpp:55-72
OTTripleSetup res = *this;   // base_receiver_inputs (= Delta) copied unchanged
```

## Attack Preconditions

- A malicious party able to tamper with OT-extension messages (e.g. the `u` matrix the
  receiver sends in `OTCorrelator<U>::correlate`, `OT/OTCorrelator.hpp:88-94`) — standard
  malicious-party capability; and
- the honest party's binary being restarted after the crash (operator or restart script),
  which is the natural operational response.

## Impact

- **Repeatable pass/abort oracle on Delta**: each tampered execution reveals one bit of
  information (check passes / process dies), and the state-reuse guarantee makes every retry
  probe the same Delta. Iterated probing recovers the global MAC key.
- **Total loss of malicious security after key recovery**: forged MACs let the attacker alter
  shares and outputs undetected.
- Un-attributable denial of service in the meantime: honest parties cannot distinguish the
  attack from a crash and receive no abort notification.

## Proof of Concept (dynamically verified)

Build: `USE_KOS=1`, `USE_NTL=1`, `-DINSECURE` (KOS15 is gated behind it). Note the KOS path
additionally requires implementing `TwoPartyPlayer::partial_broadcast` (a stub throwing
`not_implemented` at `Networking/Player.h:228`); a trivial two-party implementation
suffices and does not alter audited semantics.

Malicious-party simulation: the evil party flips one bit of the `u` matrix message, env-gated
in `OTCorrelator<U>::correlate` (honest-party code untouched):

```cpp
// OT/OTCorrelator.hpp, right after t1Slice.pack(os[0]);  (~line 92)
if (getenv("EVIL") and player->my_num() == atoi(getenv("EVIL")))
{
    os[0].get_data()[0] ^= 1;
    fprintf(stderr, "[EVIL] party %d corrupted u matrix message\n", player->my_num());
}
```

Test program (multiplication forces OT-based triple generation):

```
a = sint.get_input_from(0)
b = sint.get_input_from(1)
print_ln("product=%s", (a * b).reveal())
```

**Steps:**

```bash
# 1. baseline run (creates the secrets file)
./Server.x 2 17999 &
./mascot-party.x -IF Player-Data/Input -N 2 -pn 18000 -h 127.0.0.1 0 poc_mul &
./mascot-party.x -IF Player-Data/Input -N 2 -pn 18000 -h 127.0.0.1 1 poc_mul &
wait                                            # -> product=42
md5sum Player-Data/Mascot-Secrets-p-128-*-P0-2  # fingerprint

# 2. tampered run
EVIL=1 ./mascot-party.x -IF Player-Data/Input -N 2 -pn 18000 -h 127.0.0.1 1 poc_mul

# 3. secrets file after the crash
ls Player-Data/Mascot-Secrets-p-128-*-P0-2      # observed: STILL PRESENT

# 4. honest restart
./mascot-party.x ... 0 poc_mul & ./mascot-party.x ... 1 poc_mul & wait
# observed: product=42, and NO "generating from scratch" message
```

**Observed:**

```
P1 (evil):   [EVIL] party 1 corrupted u matrix message
P0 (honest): Correlation check failed
             q  = e1 38 53 c8 fd a5 51 88 89 66 14 d3 a8 f0 94 fe
             Fatal error in OT thread: correlation check
             (exit status 1; no Removing ... line — cleanup never attempted)
```

(Depending on timing, the poisoned triples may instead be caught later by the sacrifice MAC
check, surfacing via the report-07 path. Both outcomes leave the secrets file intact.)

Evidence chain: (1) the OT-thread failure kills the process with no cleanup; (2) the
`Mascot-Secrets-p-128-*` file survives; (3) the restart reloads the same Delta (no
regeneration message, computation succeeds); (4) steps 2-4 can be repeated indefinitely
against the unchanged Delta.

## Static Verification

```bash
sed -n 146,154p OT/OTExtension.cpp            # untyped throw on check failure
sed -n 36,43p  OT/NPartyTripleGenerator.hpp   # catch -> exit(1), no cleanup
sed -n 29,61p  OT/MascotMacKey.hpp            # read_or_generate reloads persisted secrets
sed -n 55,72p  OT/OTTripleSetup.cpp           # get_fresh keeps base_receiver_inputs
grep -n "base_receiver_inputs" OT/OTMultiplier.hpp   # line 125: asserted equal to Delta
```

## Suggested Fix

- Make the correlation-check failure a typed error (carrying the offending party id) and
  handle it explicitly in `run_ot_thread` instead of a generic `exit(1)`.
- On that failure type: notify peers, zeroize in-memory base-OT seeds / MAC key, and delete
  or taint-flag the `Mascot-Secrets-*` file so `read_or_generate` regenerates from scratch.
- `get_fresh()` must not silently reuse `base_receiver_inputs` after any abort; persisted
  state that has seen a failure must not be trusted again.

## References

- KOS15 selective-failure weakness: https://eprint.iacr.org/2022/192 (already cited in
  `OT/OTExtension.cpp:37`)
- Report 07 (MAC-check cleanup broken) and upstream issue
  [#1789](https://github.com/data61/MP-SPDZ/issues/1789): the MAC-check-path counterpart;
  the two issues need independent fixes at different locations.

## Discoverer

*(to be filled by reporter)*
