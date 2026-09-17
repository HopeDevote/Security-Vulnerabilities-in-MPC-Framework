# MP-SPDZ v0.4.3: Heap Out-of-Bounds Read in MaliciousShamirMC::reconstruct for n > 2t+1 (Private Output Path)

- **Vulnerability type**: Out-of-bounds Read (CWE-125); Improper Validation of Array Index
  (CWE-129)
- **Affected product**: MP-SPDZ v0.4.3
- **Affected components**: `malicious-shamir-party.x` —
  `Protocols/MaliciousShamirMC.hpp`, `Protocols/MaliciousShamirPO.hpp`,
  `Processor/SpecificPrivateOutput.h`
- **Severity**: High (CVSS 3.1 estimate: 7.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H, plus
  integrity concern below)

## Summary

Malicious Shamir sharing in MP-SPDZ supports any threshold with `2t < n`. The share-consistency
check, however, is sized for the minimal case `n = 2t+1`: the reconstruction-coefficient table
`reconstructions` is allocated with only `2t+2` entries. The **private-output** path passes all
`n` shares to `MaliciousShamirMC::reconstruct`, whose loop indexes `reconstructions[j]` up to
`shares.size() == n`. For any configuration with `n > 2t+1` this is a heap out-of-bounds read
(`std::vector::operator[]`, no bounds check) in security-critical verification code, and the
shares beyond index `2t+1` are never actually consistency-checked.

## Root Cause

```cpp
// Protocols/MaliciousShamirMC.hpp:25-28 — coefficient table sized 2t+2 only
reconstructions.resize(2 * threshold + 2);
for (int i = threshold + 1; i <= 2 * threshold + 1; i++)
    reconstructions[i] = ShamirMC<T>::get_reconstruction(P, i);
```

```cpp
// Protocols/MaliciousShamirMC.hpp:53-57 — but the loop runs to shares.size() == n
for (size_t j = threshold + 2; j <= shares.size(); j++)
{
    typename T::open_type check = 0;
    for (size_t k = 0; k < j; k++)
        check += shares[k] * reconstructions[j][k];   // j up to n; reconstructions has 2t+2
```

```cpp
// Protocols/MaliciousShamirPO.hpp:14 — private output collects ALL n shares
MaliciousShamirPO<T>::MaliciousShamirPO(Player& P) :
        P(P), shares(P.num_players())   // shares.size() == n
...
    return MC.reconstruct(shares);      // passes the full n-element vector
```

Call flow:

```
VM private-output instruction (e.g. sint.reveal_to(player))
  → Processor/Instruction.hpp:1147
  → SubProcessor<T>::private_output            Processor/Processor.hpp:1048
  → SpecificPrivateOutput<T>::finalize         Processor/SpecificPrivateOutput.h:58
  → MaliciousShamirPO<T>::finalize             shares has size n
  → MaliciousShamirMC<T>::reconstruct(shares)  Protocols/MaliciousShamirMC.hpp:57  ← OOB
```

Threshold validation permits the configuration:

```cpp
// Protocols/ShamirOptions.cpp:60-64 — only rejects 2t >= n and t < 1
// so e.g. -N 7 -T 2 (n=7, 2t+1=5) is accepted
```

Note: the regular public-opening path is *not* affected (`finalize_raw` resizes `shares` to
`2t+1` first); the bug is specific to private output.

## Attack Preconditions / Trigger Conditions

- Deployment runs `malicious-shamir-party.x` with `n > 2t+1` (e.g. `-N 7 -T 2`) — a legal,
  accepted configuration; and
- the MPC program performs a private output (`reveal_to`).

No malicious party is required to trigger the memory-safety fault (it fires deterministically);
a malicious party additionally benefits from the missing consistency check described below.

## Impact

- **Memory safety / DoS**: deterministic heap out-of-bounds read in verification code; in
  practice the process crashes (observed with ASan and by peer connection resets), aborting the
  computation.
- **Integrity**: if the OOB read happens to succeed (adjacent heap data), shares from parties at
  relative offsets ≥ 2t+1 are never verified against the reconstructed value — the
  all-n-shares-on-one-polynomial consistency guarantee silently does not hold, so a malicious
  party can equivocate on the private output value without detection.

## Proof of Concept (dynamically verified)

Build: AddressSanitizer build of `malicious-shamir-party.x` (no NDEBUG).

Program (`poc_privout.mpc`):

```
a = sint(42)
x = a.reveal_to(0)     # private output → MaliciousShamirPO::finalize
print_ln("done")
```

Run (7 parties, threshold 2 — a legal `2t < n` configuration):

```bash
for i in 0 1 2 3 4 5 6; do
  ./malicious-shamir-party.x -u -N 7 -T 2 -pn 21000 -h 127.0.0.1 $i poc_privout &
  sleep 2
done
```

**Observed ASan report on party 0 (verbatim):**

```
==1661==ERROR: AddressSanitizer: heap-buffer-overflow on address 0xffff80c06320
READ of size 8
    #0 std::vector<gfp_<0, 2>>::operator[]  /usr/include/c++/11/bits/stl_vector.h:1046
    #1 MaliciousShamirMC<...>::reconstruct(...)        Protocols/MaliciousShamirMC.hpp:57
    #2 SpecificPrivateOutput<...>::finalize(int)       Processor/SpecificPrivateOutput.h:58
    #3 SubProcessor<...>::private_output(...)          Processor/Processor.hpp:1048
    #4 Instruction::execute<...>                       Processor/Instruction.hpp:1147
...
0xffff80c06320 is located 0 bytes to the right of 144-byte region
```

Verification of the numbers: `reconstructions` holds `2t+2 = 6` elements of type
`vector<gfp>` (24 bytes each) = 144 bytes; the faulting access is exactly one element past the
region — the access for `j = 7 = n`. The stack trace matches the analyzed call flow frame by
frame. Other parties observe connection resets (party 0's process has crashed).

Control: the same program under the default `n = 2t+1` configuration completes normally, and a
program without private output completes normally at `-N 7 -T 2` — confirming the trigger is
precisely "n > 2t+1 + private output".

## Static Verification

```bash
sed -n 20,60p Protocols/MaliciousShamirMC.hpp   # resize(2t+2) vs loop to shares.size()
sed -n 10,20p Protocols/MaliciousShamirPO.hpp   # shares(P.num_players()) == n
grep -n "set_threshold" -A 15 Protocols/ShamirOptions.cpp  # only 2t < n is enforced
```

The bug is provable by pure arithmetic: with n=7, t=2 the table has 6 entries and the loop
accesses index 6 — out of bounds with certainty, no execution needed.

## Suggested Fix

Size and fill the reconstruction table for all n parties (private output collects n shares):

```cpp
int n = P.num_players();
reconstructions.resize(n + 1);
for (int i = threshold + 1; i <= n; i++)
    reconstructions[i] = ShamirMC<T>::get_reconstruction(P, i);
```

and add a runtime length guard at the top of `reconstruct`
(`if (shares.size() >= reconstructions.size()) throw ...`), not an `assert`.

## References

- MP-SPDZ repository: https://github.com/data61/MP-SPDZ

## Discoverer

*(to be filled by reporter)*
