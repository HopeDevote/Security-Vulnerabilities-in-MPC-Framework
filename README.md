# Security Vulnerabilities in MP-SPDZ v0.4.3

This repository documents security vulnerabilities discovered in
[MP-SPDZ](https://github.com/data61/MP-SPDZ) **v0.4.3**, a widely-used open-source framework
for secure multi-party computation (MPC).

All findings were confirmed by **static code audit** (call-flow traced to concrete code paths)
and **dynamic proof-of-concept verification** in Docker (ubuntu:22.04, aarch64), including
AddressSanitizer instrumentation and malicious-party simulation. Each report contains exact
reproduction steps, observed logs, and static verification commands for independent
confirmation.

## Vulnerability Index

| # | File | CWE | Severity |
|---|------|-----|----------|
| 01 | [Default Unencrypted/Unauthenticated Channels in Malicious-Security Protocols](MP-SPDZ/MP-SPDZ-01-Default-Unencrypted-Unauthenticated-Channels-in-Malicious-Security-Protocols.md) | CWE-319 / CWE-306 | High |
| 02 | [Unauthenticated Party Identity Claim — Connection-Slot Hijacking & Party-List Poisoning](MP-SPDZ/MP-SPDZ-02-Unauthenticated-Party-Identity-Claim-Connection-Slot-Hijacking.md) | CWE-306 | High |
| 03 | [Unauthenticated Length Prefix — Unbounded Memory Allocation (Remote DoS)](MP-SPDZ/MP-SPDZ-03-Unauthenticated-Length-Prefix-Unbounded-Memory-Allocation-Remote-DoS.md) | CWE-770 / CWE-400 | High |
| 04 | [MAC Key / Base-OT State (Δ) Reuse After OT Correlation-Check Failure](MP-SPDZ/MP-SPDZ-04-MAC-Key-BaseOT-State-Reuse-After-OT-Correlation-Check-Failure.md) | CWE-323 / CWE-372 | High |
| 05 | [FHE ZKPoK Fiat-Shamir Missing Prover Binding — Cross-Party Proof Replay](MP-SPDZ/MP-SPDZ-05-FHE-ZKPoK-Fiat-Shamir-Missing-Prover-Binding-Cross-Party-Proof-Replay.md) | CWE-294 / CWE-345 | High |
| 06 | [MaliciousShamirMC::reconstruct Heap OOB Read (n > 2t+1, Private Output)](MP-SPDZ/MP-SPDZ-06-MaliciousShamirMC-reconstruct-Heap-OOB-Read-n-greater-2t-plus-1.md) | CWE-125 / CWE-129 | High |
| 07 | [MAC-Failure Cleanup: unlink() Inside assert(), Wrong File, Real MAC Key Survives](MP-SPDZ/MP-SPDZ-07-MAC-Failure-Cleanup-Assert-Unlink-Wrong-File-MAC-Key-Survives.md) | CWE-617 / CWE-404 | Medium |
| 08 | [Commitment Open() size_t Integer Underflow — Remote Crash](MP-SPDZ/MP-SPDZ-08-Commitment-Open-SizeT-Integer-Underflow-Remote-Crash.md) | CWE-191 / CWE-770 | Medium |
| 09 | [KOS OT Extension Guaranteed Crash: partial_broadcast Not Implemented on TwoPartyPlayer](MP-SPDZ/MP-SPDZ-09-KOS-OT-Extension-partial-broadcast-NotImplemented-Guaranteed-Crash.md) | CWE-703 / CWE-248 | Medium |

## Affected Product

- **Product**: MP-SPDZ
- **Vendor**: data61 / CSIRO
- **Affected version**: 0.4.3 (latest release at audit time)
- **Repository**: https://github.com/data61/MP-SPDZ
- **Note**: v0.4.3's changelog advertises a security fix ("Remove MAC key in case of failure").
  Reports 04 and 07 demonstrate that this fix is ineffective in default configurations: the
  cleanup targets the wrong file and aborts inside `assert()` before the real MAC-key file is
  removed.

## Verification Methodology

- Full source builds (gcc, `USE_KOS=1`, `USE_NTL=1`), plus AddressSanitizer and NDEBUG
  comparison builds.
- Malicious parties simulated with environment-gated source patches that only alter what the
  *malicious* party transmits — a capability every malicious party has by definition in the
  malicious-security model. Honest-party code was never modified.
- Where a finding could not be demonstrated by black-box execution (e.g. cryptographic-strength
  issues), the report states so explicitly and gives the code-level proof.

## Directory Layout

```
MP-SPDZ/   one detailed report per vulnerability (CVE-oriented)
```

## Disclaimer

This research was conducted for defensive security purposes. The vulnerabilities are reported
to improve the security of the MP-SPDZ framework and its deployments.
