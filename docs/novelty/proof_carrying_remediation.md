# Novelty 1: Proof-Carrying Remediation

## Executive Overview
Traditional dependency remediation tools (e.g., Dependabot, Renovate) operate on an **"upgrade and hope"** model. They generate pull requests that blindly bump dependencies to newer versions without verifying:
1. Whether the application was ever actually exposed to the underlying vulnerability.
2. Whether the upgrade genuinely severed the call path to the vulnerable code.
3. Whether the upgrade inadvertently introduced breaking API regressions.

**ACSA transforms remediation into "change, verify, and prove."**

---

## Architectural Mechanism
When ACSA formulates a remediation pull request, the PR carries a structured **ProofArtifact** containing:
- **Pre-Remediation Evidence Graph Digest**: Cryptographic SHA-256 hash of the initial reachability graph demonstrating the existing exposure path.
- **Post-Remediation Evidence Graph Digest**: Cryptographic SHA-256 hash of the reachability graph generated after applying the proposed fix, proving the path is severed.
- **Call-Path Delta**: Structural before/after graph diff highlighting the exact call edges that were severed or redirected.
- **Re-Verification Verdict**: Transition record confirming the verdict changed from `PROVEN_EXPOSURE` to `PROVEN_NOT_AFFECTED`.

```
[ Pre-Remediation Graph ]                [ Post-Remediation Graph ]
HTTP Route -> handler -> vuln_fn          HTTP Route -> handler -> sanitized_fn (path severed)
         |                                           |
         v                                           v
SHA256: 7f8a3...                            SHA256: 9e1b2...
                    \                      /
                     v                    v
                   [ ProofArtifact Embedded in PR ]
```

---

## Domain Model Integration
- Handled by `acsa.verification.models.ProofArtifact` and `acsa.verification.models.VerificationResult`.
- The `EvidenceGraph.digest()` method provides deterministic cryptographic fingerprints for pre- and post-remediation graph topologies.
