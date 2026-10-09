# Novelty 3: Contradiction-Aware Inventory

## Executive Overview
Traditional SCA tools assume that a single manifest file (`package.json`) or a single generated SBOM reflects the ground truth of what runs in an application. In real-world software supply chains:
- `package.json` declares broad ranges (e.g., `^4.17.0`) that may not reflect what was installed.
- `package-lock.json` might be stale or out of sync with the manifest.
- An SBOM generated during build time might exclude dynamic dependencies or include tools stripped during bundling.
- Shipped runtime artifacts (e.g. webpack/vite bundles) might tree-shake or omit packages entirely.

**Blindly trusting one file creates dangerous blind spots. ACSA reconciles all available sources and explicitly records contradictions.**

---

## Multi-Source Evidence Fusion

ACSA cross-examines 5 distinct layers of inventory evidence:
1. **Declared Manifest**: `package.json`
2. **Resolved Lockfile**: `package-lock.json` (v2 and v3 format)
3. **Reported SBOM**: CycloneDX 1.5 and SPDX 2.3/3.0
4. **Source Code AST**: Actual `import` and `require` statements found in application files.
5. **Packaged Artifact**: Files physically bundled into the output or runtime directory.

```
package.json (Declared)  ----+
package-lock.json (Resolved) -+---> [ CONTRADICTION ENGINE ] ---> Canonical Inventory Truth
CycloneDX SBOM (Reported)  --+                                  + Contradictions Logged
Source AST / Artifact  -----+                                  + TrustAssessment Scores
```

---

## Contradiction Taxonomy
When discrepancy is detected, ACSA creates a `Contradiction` record:
- **Version Discrepancy**: Lockfile resolves version `4.17.21`, but SBOM reports `4.17.19`.
- **Presence Discrepancy**: Package appears in manifest but is missing from lockfile or bundle.
- **Scope Discrepancy**: Package listed as `devDependencies` but directly bundled into production release.

---

## Domain Model Integration
- Handled by `acsa.inventory.models.Contradiction` and `acsa.inventory.models.TrustAssessment`.
- When contradictions remain unresolved, the component verdict defaults to `CONTRADICTORY` or `UNKNOWN` rather than guessing a false sense of security.
