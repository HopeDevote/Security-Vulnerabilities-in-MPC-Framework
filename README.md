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
| 03 | [Unauthenticated Length Prefix — Unbounded Memory Allocation (Remote DoS)](MP-SPDZ/MP-SPDZ-03-Remote-Memory-Exhaustion-DoS.md) | CWE-770 / CWE-400 | High |
| 05 | [Fiat-Shamir Challenge Not Bound to Prover/Session — FHE ZKPoK Cross-Party Replay](MP-SPDZ/MP-SPDZ-05-FHE-ZKPoK-Replay.md) | CWE-345 / CWE-294 | High |
| 06 | [MaliciousShamirMC::reconstruct Heap OOB Read (n > 2t+1, Private Output)](MP-SPDZ/MP-SPDZ-06-Shamir-Heap-OOB-Read.md) | CWE-125 / CWE-129 | High |
| 07 | [MAC-Failure Cleanup: unlink() Inside assert(), Wrong File, Real MAC Key Survives](MP-SPDZ/MP-SPDZ-07-MAC-Key-Not-Removed-On-Failure.md) | CWE-617 / CWE-404 | Medium |
| 08 | [Commitment Open() size_t Integer Underflow — Remote Crash](MP-SPDZ/MP-SPDZ-08-Commitment-Underflow-Crash.md) | CWE-191 / CWE-770 | Medium |

## Affected Product

- **Product**: MP-SPDZ
- **Vendor**: data61 / CSIRO
- **Affected version**: 0.4.3 (latest release at audit time)
- **Repository**: https://github.com/data61/MP-SPDZ
- **Note**: v0.4.3's changelog advertises a security fix ("Remove MAC key in case of failure").
  Report 07 demonstrates that this fix is ineffective in default configurations: the cleanup
  targets the wrong file and aborts inside `assert()` before the real MAC-key file is removed.

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
MP-SPDZ/      one detailed report per vulnerability (CVE-oriented)
SCALE-MAMBA/  one detailed report per vulnerability (CVE-oriented)
```

---

# Security Vulnerabilities in SCALE-MAMBA

This repository additionally documents security vulnerabilities discovered in
[SCALE-MAMBA](https://github.com/KULeuven-COSIC/SCALE-MAMBA) (KU Leuven COSIC, master
`c111516`), an open-source framework for secure multi-party computation (MPC).

Findings were confirmed by **static code audit** (call-flow traced to concrete code paths)
and **dynamic proof-of-concept verification** in Docker (Ubuntu 20.04, x86_64), including
AddressSanitizer instrumentation and end-to-end multi-party execution with a malicious
party. Malicious parties are simulated with source patches that only alter what the
*malicious* party shares/sends — a capability every malicious party has by definition in the
malicious-security model. Honest-party code was never modified.

## Vulnerability Index (SCALE-MAMBA)

| # | File | CWE | Severity |
|---|------|-----|----------|
| 01 | [Missing Sacrifice Check in Mod2 Triple Generation (Gen_Checked_Triples)](SCALE-MAMBA/SCALE-MAMBA-01-Mod2-Sacrifice-Check-Missing.md) | CWE-358 / CWE-345 | High |

## Disclaimer

This research was conducted for defensive security purposes. The vulnerabilities are reported
to improve the security of the MP-SPDZ and SCALE-MAMBA frameworks and their deployments.
