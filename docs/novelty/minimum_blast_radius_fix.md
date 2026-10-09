# Novelty 2: Minimum-Blast-Radius Fix

## Executive Overview
When a vulnerable dependency is identified, security teams typically jump straight to upgrading to the latest major or minor version. However, major version jumps frequently introduce breaking API changes, deprecations, and transitive dependency turmoil that delay deployment or break production systems.

**ACSA computes the Minimum-Blast-Radius Fix**: the smallest verified change that severes every proven exposure path while minimizing disruption to the application code base.

---

## Strategy Comparison Matrix

ACSA evaluates multiple remediation candidates across a blast-radius spectrum:

1. **Call-Site Guard / Sanitization Patch (Blast Radius ~0.05 - 0.20)**:
   - Introducing an input validation check or sanitizer at the application call site before delegating to the vulnerable dependency.
   - Zero changes to `package.json` or transitive dependencies.
2. **Minimal Patch Bump (Blast Radius ~0.10 - 0.30)**:
   - Upgrading to the smallest point release (e.g. `4.17.20` -> `4.17.21`) that fixes the vulnerable symbol without introducing other API changes.
3. **Minor Version Upgrade (Blast Radius ~0.40 - 0.60)**:
   - Upgrading to a backward-compatible minor release when no patch is available.
4. **Major Version Upgrade (Blast Radius ~0.70 - 1.00)**:
   - Upgrading to a new major release; considered the strategy of last resort due to breaking changes.

---

## Blast-Radius Scoring Equation
The blast-radius score ($B$) is evaluated using:
$$B = w_1 \cdot \Delta_{\text{version}} + w_2 \cdot N_{\text{transitive\_changes}} + w_3 \cdot N_{\text{call\_sites\_modified}}$$

Where:
- $\Delta_{\text{version}}$: SemVer jump magnitude (patch=0.1, minor=0.4, major=0.9).
- $N_{\text{transitive\_changes}}$: Number of transitive package shifts triggered by the upgrade.
- $N_{\text{call\_sites\_modified}}$: Number of call sites requiring signature or import updates.

---

## Domain Model Integration
- Handled by `acsa.remediation.models.RemediationCandidate` and `acsa.remediation.models.RemediationDecision`.
- Evaluates candidate options and records the justification in the authoritative `RemediationDecision`.
