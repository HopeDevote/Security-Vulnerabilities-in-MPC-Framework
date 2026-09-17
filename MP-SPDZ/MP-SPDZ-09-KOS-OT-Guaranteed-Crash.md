# MP-SPDZ v0.4.3: KOS OT Extension Unusable at Runtime — partial_broadcast Unimplemented on TwoPartyPlayer (Guaranteed Crash)

- **Vulnerability type**: Improper Check or Handling of Exceptional Conditions (CWE-703);
  Uncaught Exception (CWE-248)
- **Affected product**: MP-SPDZ v0.4.3
- **Affected components**: `Networking/Player.h` (`TwoPartyPlayer`),
  `OT/OTExtension.cpp` (`check_correlation`), `Tools/Subroutines.cpp` (`Create_Random_Seed`) —
  any build/run using the in-tree KOS OT extension (`USE_KOS=1` or `--use-kos`)
- **Severity**: Medium (CVSS 3.1 estimate: 6.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

## Summary

The KOS OT-extension correlation check derives its challenge via `GlobalPRNG`, which runs the
commitment-based coin flip `Create_Random_Seed`. That coin flip calls
`P.partial_broadcast(...)`. In every real OT thread the player object is a `TwoPartyPlayer`,
for which `partial_broadcast` is **not implemented** — the base-class stub throws
`not_implemented()`. As a result, *any* real run of the KOS path dies with
"Fatal error: Case not implemented" at the first correlation check, before any check logic
executes. Beyond the availability impact, this means the KOS code path in v0.4.3 has never
been exercised in a real deployment — its security properties (see report 04) rest on an
untested implementation.

## Root Cause

```cpp
// Networking/Player.h:226-228 — base-class stub used by TwoPartyPlayer
virtual void partial_broadcast(const vector<bool>&,
    const vector<bool>&, vector<octetStream>&) const
{ throw not_implemented(); }
```

```cpp
// Tools/Subroutines.cpp:148-152 — the coin flip calls partial_broadcast
Commit(Comm_e[P.my_num()],Open_e[P.my_num()],e[P.my_num()],P.my_num());
P.partial_broadcast(my_parties, my_parties, Comm_e);
P.partial_broadcast(my_parties, my_parties, Open_e);
```

```cpp
// OT/OTExtension.cpp:51 — invoked from check_correlation via GlobalPRNG
GlobalPRNG G(*player);   // → SeedGlobally → Create_Random_Seed → partial_broadcast → throw
```

`TwoPartyPlayer` implements `Broadcast_Receive` but not `partial_broadcast`
(`Networking/Player.h:516-535`).

## Observed Behavior (dynamically verified)

Any honest 2-party or 3-party run of `mascot-party.x` / `chaigear-party.x` built with
`USE_KOS=1`:

```
WARNING: insecure OT extension (security of KOS15 is unclear, see https://eprint.iacr.org/2022/192.)
Fatal error: Case not implemented
```

gdb backtrace at the throw (verbatim):

```
#1 PlayerBase::partial_broadcast (this=<optimized out>) at Networking/Player.h:228
#2 Create_Random_Seed (seed=..., P=..., len=16, parties=std::vector<bool> of length 0)
   at Tools/Subroutines.cpp:150
```

The exception escapes a pthread entry function, terminating the process; peers observe only a
dropped connection (no typed abort, no blame) — the same failure-handling weakness described in
report 04.

## Impact

- **Availability**: the KOS OT-extension configuration cannot complete any run (guaranteed
  crash at the first correlation check).
- **Security posture**: the shipped KOS path is de facto untested dead code; any deployment
  believing it uses KOS with real networking is either crashing or (with a local workaround)
  running a code path that never received real-world validation, including the selective-abort
  oracle discussed in report 04.

## Suggested Fix

Implement `TwoPartyPlayer::partial_broadcast` (for two parties, a per-peer exchange is
trivially consistent), or make `Create_Random_Seed` use `Broadcast_Receive` (which
`TwoPartyPlayer` does implement) when only two parties are involved. Additionally, convert the
escape-from-pthread exception into a typed, peer-notified abort.

## References

- MP-SPDZ repository: https://github.com/data61/MP-SPDZ
- KOS15 security discussion: https://eprint.iacr.org/2022/192

## Discoverer

*(to be filled by reporter)*
