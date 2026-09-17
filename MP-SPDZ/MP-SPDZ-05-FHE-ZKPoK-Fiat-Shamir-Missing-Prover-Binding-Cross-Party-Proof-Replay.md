# MP-SPDZ v0.4.3: Fiat-Shamir Challenge of FHE ZKPoK Binds No Prover Identity or Session — Cross-Party Proof Replay

- **Vulnerability type**: Authentication Bypass by Capture-Replay (CWE-294); Insufficient
  Verification of Data Authenticity (CWE-345); weak Fiat-Shamir transcript
- **Affected product**: MP-SPDZ v0.4.3
- **Affected components**: FHE offline zero-knowledge proofs of plaintext knowledge —
  `FHEOffline/Proof.cpp`, `FHEOffline/Producer.cpp`, `FHEOffline/Prover.cpp`,
  `FHEOffline/Verifier.cpp` — used by `chaigear-party.x` and other FHE-based input production
  (`Protocols/ChaiGearPrep.hpp`, `SimpleEncCommit` flows)
- **Severity**: High (CVSS 3.1 estimate: 7.5 — AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N)

## Summary

In ChaiGear-style input production, every party encrypts its inputs under a shared FHE public
key and proves knowledge of the plaintexts with a non-interactive ZKPoK whose challenge is
derived by Fiat-Shamir. The challenge is computed as `BLAKE2b-128(ciphertext bytes)` — it binds
**no prover identity, no session id, no public key, no domain separator**. Because all parties
prove under the *same* global key in a sequential loop, a malicious party that proves *after*
an honest party can forward the honest party's proof bytes verbatim as its own. Verification
recomputes the identical challenge and accepts. The malicious party thereby passes a proof of
knowledge for a plaintext it does not know.

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
// Tools/octetStream.cpp:95-102 — unkeyed BLAKE2b-128, no label/party/session/pk
void octetStream::hash(octetStream& output) const
{
  output.resize(crypto_generichash_BYTES_MIN);          // = 16 bytes
  crypto_generichash(output.data, crypto_generichash_BYTES_MIN, data, get_length(), NULL, 0);
}
```

Reachable call flow:

```
Protocols/ChaiGearPrep.hpp:196  buffer_inputs() → InputProducer<FD>::run(P, setup.pk, ...)
FHEOffline/Producer.cpp:545-620
  for j = 0 .. n-1 (sequential):
    [party j]  generate_proof → P.send_all(ciphertexts); P.send_all(cleartexts)
    [others]   Verifier<FD>(...).NIZKPoK(C, ciphertexts, cleartexts, pk)   // SAME pk for all
      → Stage_2: c.unpack(ciphertexts, pk)   // statement taken from the untrusted stream
  dd.reshare(ai, C[i], EC); ...              // "proven" ciphertexts become party j's inputs
```

## Attack Preconditions

- A malicious party whose turn to prove comes after an honest party (any j2 > j1 in the loop).
- No network or host compromise needed; replaying a previously broadcast proof is within the
  protocol's own message flow.

## Impact

- **Knowledge soundness break**: the verifier accepts a proof of plaintext knowledge from a
  party that does not know the plaintext.
- **Input independence break** (a required property of the SPDZ input protocol): the replayed
  ciphertexts are reshared and MAC'd as the malicious party's inputs, so the adversary's input
  is *tied to / equal to* an honest party's (unknown) input — e.g. copying an honest bid or
  vote in application-level protocols.
- Any proof whose ciphertext stream recurs can also be replayed across sessions/protocols,
  since no context is bound.

## Proof of Concept (dynamically verified)

Setup: 2-party ChaiGear run of a program that takes one secret input from each party. The
malicious party 1 (patch gated by `REPLAY=1`) captures party 0's proof bytes when acting as
verifier, then — instead of generating its own proof — broadcasts the captured bytes when its
turn comes. Honest-party code is unmodified (one logging line added to print the accepted
transcript hash).

```bash
echo 100 > Player-Data/Input-P0-0; echo 300 > Player-Data/Input-P1-0
./chaigear-party.x -IF Player-Data/Input -N 2 -pn 19500 -h 127.0.0.1 0 poc_replay &   # honest
sleep 8
REPLAY=1 ./chaigear-party.x -IF Player-Data/Input -N 2 -pn 19500 -h 127.0.0.1 1 poc_replay & # evil
```

**Observed logs (side by side):**

```
P1 (evil):   [EVIL] party 1 captured party 0's proof (63706832 bytes)
P1 (evil):   [verify] party 1 accepted proof from party 0 with transcript hash bc1e6e3d3784ed862bab4daf8f6784e2
P1 (evil):   [EVIL] party 1 replays captured proof as its own
P0 (honest): [verify] party 0 accepted proof from party 1 with transcript hash bc1e6e3d3784ed862bab4daf8f6784e2
P0 (honest): sum=49364773017026763761944078797714096230   ← run completes
```

Key evidence:

1. The transcript hash of "party 1's proof" accepted by honest party 0 is **bit-identical** to
   the hash of party 0's own earlier proof — a byte-for-byte replay.
2. The unmodified honest verifier (`Verifier::NIZKPoK`) returns normally — no exception.
3. The protocol continues: the replayed ciphertexts are reshared and MAC'd as party 1's inputs.
4. The garbage output (`sum` ≠ 400) itself demonstrates the adversary's ignorance: it passed a
   proof of *knowledge* for plaintexts it provably does not know.

## Static Verification

```bash
sed -n 36,42p FHEOffline/Proof.cpp      # challenge = hash(ciphertexts) only
sed -n 95,102p Tools/octetStream.cpp    # unkeyed BLAKE2b-128, no domain separation
sed -n 581,600p FHEOffline/Producer.cpp # sequential loop, single shared pk, statement from stream
```

The challenge input contains no quantity that varies with prover or session — replay acceptance
is a mathematical certainty, not an implementation accident.

## Suggested Fix

Bind the full context into the challenge, e.g.
`H("mpspdz-zkpopk" || sid || prover_id || pk_bytes || ciphertexts)`, with a 256-bit digest;
where the verifier knows the expected statement, hash the verifier's own copy rather than only
the stream contents.

## References

- MP-SPDZ repository: https://github.com/data61/MP-SPDZ
- Weak Fiat-Shamir / insufficient transcript binding: standard Fiat-Shamir pitfalls (cf. also
  the "Challenge Transcript Missing Required Values" class of issues)

## Discoverer

*(to be filled by reporter)*
