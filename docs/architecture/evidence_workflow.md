# ACSA Evidence-First Workflow

ACSA rejects monolithic, unexplainable scoring models. Every conclusion is produced via a chain of verifiable evidence.

---

## The Eleven-Stage Evidence Chain

```
Repository
    ↓
Inventory Truth
    ↓
Vulnerability Intelligence
    ↓
Applicability
    ↓
Reachability
    ↓
Context
    ↓
Evidence Fusion
    ↓
Verdict
    ↓
Remediation
    ↓
Verification
    ↓
Proof
```

---

## Detailed Stage Definitions

1. **Repository**: Intake of source repositories and build targets within an isolated, path-validated sandbox.
2. **Inventory Truth**: Cross-referencing declared manifests, lockfiles, and SBOMs into a canonical component inventory while recording source contradictions.
3. **Vulnerability Intelligence**: Querying OSV and advisories with normalized PURLs to locate relevant vulnerability records.
4. **Applicability**: Confirming whether the exact installed version matches affected ranges.
5. **Reachability**: Constructing AST-derived import and call graphs to trace execution paths from application modules to dependency symbols.
6. **Context**: Evaluating entry points (e.g. Express HTTP routes), external user inputs, and configuration flags to establish exploitability feasibility.
7. **Evidence Fusion**: Merging all collected `Evidence` observations, identifying conflicting signals, and assessing holistic confidence.
8. **Verdict**: Assigning one of the 7 canonical verdicts (`PROVEN_EXPOSURE`, `PROVEN_AFFECTED`, `POTENTIALLY_AFFECTED`, `PROVEN_NOT_AFFECTED`, `UNKNOWN`, `CONTRADICTORY`, `NOT_VERIFIED`).
9. **Remediation**: Ranking candidate fixes via the **Minimum-Blast-Radius** algorithm to find the smallest change closing the exposure.
10. **Verification**: Executing re-analysis on the patched state to verify that the target call path is demonstrably severed.
11. **Proof**: Emitting a **ProofArtifact** with cryptographic before-and-after graph digests into the remediation PR.
