# ACSA Five-Phase Technical Pipeline

Artifact-Centric Security Analysis (ACSA) operates as an evidence-driven pipeline that progressively reduces uncertainty from package-level discovery to artifact-level proof.

```
+---------------------------------------------------------------------------------------------------+
|                                      THE ACSA EVIDENCE PIPELINE                                   |
+---------------------------------------------------------------------------------------------------+
|  Phase 0: Foundation       ->  Platform, Domain Contracts, Verdicts, CLI, API, Test Harness      |
|  Phase 1: Ingestion        ->  package.json, lockfile v2/v3, CycloneDX/SPDX -> Canonical Inventory|
|  Phase 2: Truth + Intel    ->  Cross-Source Reconciliation, OSV Advisory Matching, Applicability  |
|  Phase 3: Reachability     ->  JavaScript/TypeScript AST, Import Graphs, Call Graphs, Symbols     |
|  Phase 4: Verdict & Proof  ->  Context, Multi-Source Evidence Fusion, Minimum Blast Fix, Proof PR  |
+---------------------------------------------------------------------------------------------------+
```

---

## Phase 0 — Foundation (Current Phase)
- **Role**: Establishes the architectural backbone, canonical Pydantic domain models, and shared contracts.
- **Key Deliverables**:
  - Typed domain models (`Repository`, `Component`, `Evidence`, `EvidenceGraph`, `Vulnerability`, `Finding`, `Verdict`, `Contradiction`, `RemediationCandidate`, `ProofArtifact`).
  - Canonical 7-verdict vocabulary with the non-negotiable rule: **`UNKNOWN != SAFE`**.
  - FastAPI operational backend (`GET /health`).
  - Typer CLI with system inspection and roadmap commands.
  - Security boundaries (workspace sandboxing, path traversal guards, secret redaction filter).

---

## Phase 1 — Ingestion & Inventory Truth (Planned)
- **Role**: Establishes what components are genuinely present in the target repository.
- **Inputs**:
  - `package.json` (declared dependencies)
  - `package-lock.json` v2/v3 (resolved dependencies)
  - CycloneDX / SPDX SBOMs (vendor/build-reported dependencies)
- **Key Concepts**:
  - PURL and npm namespace normalization.
  - Tracking source provenance for every observation.
  - Preserving discrepancies rather than silently ignoring conflicts.

---

## Phase 2 — Inventory Truth + Vulnerability Intelligence (Planned)
- **Role**: Determines which exact components and versions are subject to known advisories.
- **Inputs**: Canonical Component Inventory + OSV Advisory Feeds.
- **Key Concepts**:
  - Semantic version constraint matching against affected ranges.
  - Deterministic caching of vulnerability intelligence.
  - **Boundary**: Version applicability confirms a component is affected; it does **not** prove the vulnerable code is reached.

---

## Phase 3 — Reachability Analysis (Planned)
- **Role**: Discovers whether the application execution path reaches vulnerable functions or symbols.
- **Inputs**: JavaScript / TypeScript source code and build artifacts.
- **Key Concepts**:
  - AST parsing, import graph resolution, and inter-procedural call graph construction.
  - Mapping vulnerable functions/symbols identified from advisories to application call sites.
  - Classifying call path outcomes: `REACHED`, `NOT_REACHED`, `NOT_FOUND`, `UNKNOWN`.

---

## Phase 4 — Context, Evidence Fusion & Proof-Carrying Verdict (Planned)
- **Role**: Synthesizes all gathered evidence into explainable verdicts and verified fixes.
- **Inputs**: Inventory truth + Vulnerability data + Reachability graph + Application context.
- **Key Concepts**:
  - Entry-point tracing (HTTP routes, CLI arguments, event listeners).
  - External input feasibility assessment.
  - Evidence Fusion graph synthesis.
  - Selecting the **Minimum-Blast-Radius Fix** and generating **Proof-Carrying Remediation**.
