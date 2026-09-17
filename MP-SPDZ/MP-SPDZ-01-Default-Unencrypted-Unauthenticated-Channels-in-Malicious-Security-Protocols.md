# MP-SPDZ v0.4.3: Malicious-Security Protocols Default to Unencrypted, Unauthenticated Channels

- **Vulnerability type**: Cleartext Transmission of Sensitive Information (CWE-319); Missing Authentication for Critical Function (CWE-306)
- **Affected product**: MP-SPDZ v0.4.3 (https://github.com/data61/MP-SPDZ)
- **Affected components**: All malicious-security dishonest-majority protocol binaries: `mascot-party.x`, `spdz2k-party.x`, `cowgear-party.x`, `chaigear-party.x`, `hemi-party.x`, `lowgear-party.x`, `highgear-party.x`, ECDSA variants (`mascot-ecdsa-party.x`, `semi-ecdsa-party.x`), etc.
- **Severity**: High (CVSS 3.1 estimate: 7.4 — AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N)

## Summary

The UC/published security proofs of MP-SPDZ's malicious-security dishonest-majority protocols
assume **authenticated and confidential point-to-point channels**. The implementation, however,
defaults every one of these protocols to raw, unencrypted, unauthenticated TCP. TLS with mutual
certificate authentication (`CryptoPlayer`) exists but is only enabled when the operator
explicitly passes `--encrypted`. Unlike the honest-majority code path, the dishonest-majority
path emits **no warning** when running unencrypted.

## Root Cause

```cpp
// Processor/OnlineMachine.hpp:25 (constructor default)
use_encryption(false),

// Processor/OnlineMachine.hpp:99-110 (DishonestMajorityMachine)
opt.add("", 0, 0, 0, "Use encrypted channels.", "-e", "--encrypted");
online_opts.finalize(opt, argc, argv);
use_encryption = opt.isSet("--encrypted");     // line 110: plaintext unless user opts in

// Processor/Machine.hpp:91-94
if (use_encryption)
  P = new CryptoPlayer(N, id);   // TLS, mutual certificate auth
else
  P = new PlainPlayer(N, id);    // raw TCP: no TLS, no MAC, no handshake credentials
```

```cpp
// Networking/sockets.cpp:186-205 — the default channel
void send(int socket, octet* msg, size_t len) {
  while (i < len) { size_t j = send_non_blocking(socket, msg + i, len - i); ... }
}
// no encryption, no authentication tag, no session binding
```

Contrast with the honest-majority path, which encrypts by default and warns loudly otherwise:

```cpp
// Processor/HonestMajorityMachine.cpp:33-36
use_encryption = not opt.get("-u")->isSet;
if (not use_encryption)
    insecure("unencrypted communication");
```

## Attack Preconditions

- The victim parties run a dishonest-majority malicious-security protocol with default options
  (the documented standard way).
- The attacker is on the network path between any two parties (or can reach their listening
  ports). The attacker does **not** need to be a protocol participant and does **not** need to
  compromise any host.

## Impact

- **Confidentiality**: all protocol messages (shares, openings, commitments, OT matrices) are
  readable. Several protocol stages transmit masked secret material whose security depends on
  the channel assumptions.
- **Integrity**: messages can be injected, modified, dropped, or replayed. The malicious-security
  proofs are only meaningful over authenticated channels; tampering with unauthenticated
  auxiliary messages (base-OT seeds, commitments, consistency hashes) voids the security
  reduction.
- Chained with the unauthenticated identity claim (see report 02), this yields a full
  man-in-the-middle position over the entire computation.

## Proof of Concept (dynamically verified)

Environment: Docker ubuntu:22.04, MP-SPDZ v0.4.3 built from source (`USE_KOS=1, USE_NTL=1`).

**Step 1 — no certificates exist:**

```bash
ls Player-Data/*.pem | wc -l        # observed: 0
```

**Step 2 — a full 2-party MASCOT computation succeeds without any TLS material:**

```bash
./Server.x 2 17999 &
./mascot-party.x -N 2 -pn 18000 -h 127.0.0.1 0 poc_min &
./mascot-party.x -N 2 -pn 18000 -h 127.0.0.1 1 poc_min &
# observed on both parties: result=3
```

Had TLS been the default, the missing certificates would have aborted the run
(`check_ssl_file()`, Networking/CryptoPlayer.cpp:9-14).

**Step 3 — control: with `--encrypted` the same run refuses to start:**

```
Trying to run 128-bit computation (128-bit representation)
Cannot access Player-Data/P0.pem. Have you set up SSL?
```

**Step 4 — packet capture confirms zero TLS:**

```bash
tcpdump -i lo -w poc1.pcap portrange 17999-18010 &   # during the run of step 2
tcpdump -r poc1.pcap -XX | grep -c "1603"            # TLS handshake record bytes
# observed: 0 handshake records in 231 captured packets; all frames are
# "4-byte little-endian length + raw payload" (octetStream wire format)
```

## Static Verification (independent of PoC)

```bash
grep -n "use_encryption" Processor/OnlineMachine.hpp    # line 25 default false; line 110 opt-in
grep -n "use_encryption" Processor/Machine.hpp          # lines 91-94 PlainPlayer vs CryptoPlayer
```

## Suggested Fix

Default `use_encryption` to `true` in `DishonestMajorityMachine`, with an explicit
`--unencrypted` opt-out that triggers `insecure("unencrypted communication")`, mirroring
`HonestMajorityMachine.cpp:33-36`.

## References

- MP-SPDZ repository: https://github.com/data61/MP-SPDZ
- KOS15 OT extension security note cited by the code itself: https://eprint.iacr.org/2022/192
- MP-SPDZ networking documentation: https://mp-spdz.readthedocs.io/en/latest/networking.html

## Discoverer

*(to be filled by reporter)*
