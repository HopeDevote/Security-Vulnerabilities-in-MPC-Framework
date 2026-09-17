# MP-SPDZ v0.4.3: SPDZ/MASCOT MAC Key (Δ) and Base-OT State Persist on Disk and Are Reused After OT Correlation-Check Failure

- **Vulnerability type**: Reusing a Nonce, Key Pair in Encryption (CWE-323); Improper
  Restriction of Security-relevant State after Abort (CWE-372 / CWE-664)
- **Affected product**: MP-SPDZ v0.4.3
- **Affected components**: OT-based malicious preprocessing — `OT/OTExtension.cpp`,
  `OT/NPartyTripleGenerator.hpp`, `OT/MascotMacKey.hpp`, `OT/OTTripleSetup.cpp` — used by
  `mascot-party.x`, `spdz2k-party.x`, and any protocol consuming `Mascot-Secrets-*` state
- **Severity**: High (CVSS 3.1 estimate: 7.4 — AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)

## Summary

In MASCOT-style preprocessing, the KOS OT-extension correlation check gives a malicious
receiver a pass/abort **oracle on Δ**, and Δ *is* the SPDZ/MASCOT MAC key
(`OTMultiplier.hpp:125` asserts they are equal). Extracting Δ requires **repeated** probing.
A safe implementation must therefore destroy all correlated secret state on any check failure.
MP-SPDZ v0.4.3 instead: (1) kills the process opaquely (`exit(1)`, no typed abort, no peer
notification), and (2) leaves the on-disk `Mascot-Secrets-*` file — containing Δ and the
base-OT state — untouched, and (3) silently reloads the *same* Δ on the next startup, giving
the attacker unlimited retries against an unchanged key.

## Root Cause

```cpp
// OT/OTExtension.cpp:146-154 — failure is untyped, un-attributed, non-state-destroying
if (eq_m128i(tmp1, received_t) && eq_m128i(tmp2, received_t2))
{ /* Check passed */ }
else
{
    cerr << "Correlation check failed\n";
    throw runtime_error("correlation check");
}
```

```cpp
// OT/NPartyTripleGenerator.hpp:36-43 — opaque process death, peers never notified
try { multiplier->multiply(); }
catch (exception& e)
{
    cerr << "Fatal error in OT thread: " << e.what() << endl;
    exit(1);
}
```

```cpp
// OT/MascotMacKey.hpp:29-61 — on restart, the same secrets file is reloaded
os.input(filename);        // PREP_DIR/Mascot-Secrets-...-P<i>-<n>
unpack(os);                // reloads MAC key + base OT setup
...
key.get_fresh().pack(os);  // get_fresh() only PRG-extends sender/receiver outputs

// OT/OTTripleSetup.cpp:55-72 — Δ is copied verbatim into the "fresh" setup
OTTripleSetup res = *this;   // base_receiver_inputs (Δ = MAC key bits) unchanged
```

The code itself acknowledges the check's weakness (`OT/OTExtension.cpp:37`: "security of KOS15
is unclear, see https://eprint.iacr.org/2022/192").

## Attack Preconditions

- A malicious protocol party (the malicious-security model explicitly permits one).
- The honest party is restarted after failures (standard operational behavior — scripts and
  operators routinely restart crashed parties). Every restart grants another probe against the
  same Δ.

## Impact

Repeated selective-abort probing across restarts extracts Δ bit-by-bit (KOS15-class attack,
eprint 2022/192). Since Δ is the MAC key, its recovery enables **forgery of authenticated
shares** — a complete break of SPDZ/MASCOT malicious security (undetectable tampering with all
honest parties' secrets). Even without full extraction, the path is an un-attributable denial
of service: honest parties cannot distinguish attack from failure and blindly retry.

## Proof of Concept (dynamically verified)

Malicious-party simulation: the evil party flips one byte of the u-matrix message in
`OTCorrelator::correlate` (the u message is fully receiver-controlled; this is within any
malicious receiver's capabilities). The patch is gated by an `EVIL` environment variable and
changes nothing when unset.

**Step 1 — baseline run (no attack); record the honest party's secrets fingerprint:**

```bash
./mascot-party.x -IF Player-Data/Input -N 2 -pn 18000 -h 127.0.0.1 0 poc_mul &
./mascot-party.x -IF Player-Data/Input -N 2 -pn 18000 -h 127.0.0.1 1 poc_mul &
# observed: product=42
md5sum Player-Data/Mascot-Secrets-p-128-*-P0-2
# observed: 74c8ed275739dade02de794ca96390b7
```

**Step 2 — attack run; evil party corrupts the u message:**

```bash
./mascot-party.x ... 0 poc_mul &            # honest P0
EVIL=1 ./mascot-party.x ... 1 poc_mul &     # malicious P1
```

Observed:

```
P1: [EVIL] party 1 corrupted u matrix message
P0: Removing Player-Data//Mascot-Secrets-p-0-...-P0-2 because of MAC check failure
P0: mascot-party.x: ./Protocols/MAC_Check.hpp:175: ... Assertion `unlink(...) == 0' failed.
```

The honest party's process dies from the check failure (here via the broken cleanup path — see
report 07 — which crashes before deleting anything; the peer is only notified by a dropped
connection).

**Step 3 — the real MAC-key file survives the abort:**

```bash
ls Player-Data/Mascot-Secrets-p-128-*-P0-2    # observed: still present
```

**Step 4 — restart: the same key material is silently reloaded:**

```bash
./mascot-party.x ... 0 poc_mul & ./mascot-party.x ... 1 poc_mul &
# observed: product=42 (success), and NO "generating from scratch" message —
# read_or_generate reloaded the existing secrets file instead of regenerating.
```

(The file's md5 changes between runs only because `get_fresh()` PRG-extends the derived seeds;
per `OTTripleSetup::get_fresh`, `base_receiver_inputs` — i.e. Δ — is copied unchanged.)

**Step 5 — repeat step 2 indefinitely: every probe targets the same Δ.**

## Static Verification

```bash
sed -n 55,72p OT/OTTripleSetup.cpp        # get_fresh copies base_receiver_inputs unchanged
sed -n 29,61p OT/MascotMacKey.hpp         # read_or_generate reload logic
sed -n 27,44p OT/NPartyTripleGenerator.hpp  # run_ot_thread: catch → exit(1)
grep -n "base_receiver_inputs" OT/OTMultiplier.hpp   # line 125: Δ asserted equal to MAC key
```

## Suggested Fix

Make the check failure a typed, terminal abort carrying the peer id; on that abort: notify all
peers, zeroize in-memory base-OT seeds/MAC key, and delete or taint-flag the
`Mascot-Secrets-*` file so `read_or_generate` regenerates from scratch. Never silently
`exit(1)` with the secrets file intact.

## References

- KOS15 selective-failure analysis: https://eprint.iacr.org/2022/192 (cited by the code itself)
- MP-SPDZ repository: https://github.com/data61/MP-SPDZ

## Discoverer

*(to be filled by reporter)*
