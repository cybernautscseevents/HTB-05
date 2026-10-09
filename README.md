# ACSA — Artifact-Centric Security Analysis

> **Don't just detect vulnerabilities. Prove their exposure. Find the fix. Verify the result.**

ACSA (Artifact-Centric Security Analysis) is a software supply-chain security project focused on JavaScript/TypeScript and npm repositories.

Traditional security tools can identify vulnerable dependencies, but a vulnerable package does not automatically mean an application is exposed. The vulnerable code might never be used, might not be included in the deployed application, or might not be reachable through an attacker-controlled input.

ACSA aims to investigate whether a vulnerability is relevant to a specific application and, eventually, help developers choose, validate, and verify a suitable remediation.

Its goal is to move beyond simply reporting vulnerabilities toward **evidence-driven security decisions and verified remediation**.

---

## 1. The Problem We Are Solving

Modern applications depend on many open-source libraries. These dependencies can introduce security vulnerabilities, but not every reported vulnerability represents the same level of risk.

For example:

- A vulnerable package may be installed but its vulnerable function may never be called.
- A transitive dependency may contain vulnerable code that the application does not reach.
- A development-only dependency may not be included in the production artifact.
- An automated dependency upgrade may introduce breaking changes or application regressions.
- A developer may receive a suggested fix but still be unsure whether it is safe to merge.

This creates two connected problems:

**Problem 1 — Understanding the actual risk**

Does the vulnerability affect this specific application, and what evidence supports that conclusion?

**Problem 2 — Safely removing the risk**

What is the most suitable fix for this application, and how can we verify that the fix addresses the vulnerability without breaking existing functionality?

### ACSA's Core Questions

1. What dependencies does the application actually contain?
2. Which vulnerabilities affect their exact versions?
3. Can the application reach the vulnerable code?
4. Can attacker-controlled input reach the vulnerable execution path?
5. What remediation options are available?
6. Does the proposed fix address the identified security risk?
7. What evidence can be provided to help the developer decide whether to accept the fix?

---

## 2. ACSA's Approach

ACSA is designed around an evidence-driven workflow:

```text
Repository / Software Artifact
              |
              v
    Inventory and Reconciliation
              |
              v
   Vulnerability Identification
              |
              v
     Exact-Version Applicability
              |
              v
       Code Reachability
              |
              v
   Context and Exposure Analysis
              |
              v
      Evidence-Based Verdict
              |
              v
       Remediation Candidates
              |
              v
       Fix Validation
              |
              v
     Post-Fix Security Analysis
              |
              v
    Evidence for Developer Review
```

The initial phases establish what is present, what is vulnerable, and what can be proven about exposure. The planned remediation stage will investigate suitable fixes and validate their results before presenting them for developer review.

**Important principle:** A generated fix must not automatically be considered safe or successful merely because it was created.

---

## 3. Key Features and Research Direction

### 3.1 Contradiction-Aware Inventory

ACSA compares multiple sources of dependency information rather than blindly trusting a single source.

Potential inputs include:

- `package.json`
- `package-lock.json`
- CycloneDX or SPDX Software Bill of Materials (SBOM) files
- Build or deployment artifact information, where available

For example, if the manifest, lockfile, and SBOM report different versions of the same package, ACSA should preserve the disagreement and identify which information still needs verification.

The objective is to establish a more reliable view of the application's dependencies before making security decisions.

### 3.2 Evidence-Based Reachability Analysis

ACSA aims to determine whether the application can reach a vulnerable function rather than treating every vulnerable dependency as automatically exposed.

The planned JavaScript/TypeScript analysis includes:

- Abstract Syntax Tree (AST) inspection
- Import and dependency relationship analysis
- Call-path tracing
- Vulnerable symbol mapping, where advisory information permits
- Identification of application entry points
- Analysis of paths involving potentially attacker-controlled input

Static analysis has limitations, particularly with dynamic imports, reflection, and runtime-dependent behavior. ACSA must preserve these limitations in its results instead of presenting uncertain conclusions as proven facts.

### 3.3 Minimum-Blast-Radius Remediation — Planned

The safest remediation is not necessarily the newest dependency version or the largest possible code change.

ACSA will investigate how to compare remediation candidates based on factors such as:

- Whether the proposed change addresses the identified vulnerability
- The size and scope of the change
- Potential breaking changes
- Changes to transitive dependencies
- Compatibility with the application's existing code
- Results from the application's available tests
- Whether the vulnerable execution path remains reachable

Potential remediation strategies include a dependency upgrade, a smaller compatible version update, an application-code change, a configuration change, or dependency replacement when appropriate.

The objective is to identify a **small, suitable, evidence-supported fix**, rather than blindly upgrading packages.

This feature is a planned research and implementation direction, not a claim that ACSA can currently calculate or guarantee the optimal fix.

### 3.4 Proof-Carrying Remediation — Planned

ACSA will investigate a remediation workflow in which a proposed fix is accompanied by evidence that helps developers evaluate it.

A future remediation report or pull request could include:

- The original vulnerability and affected dependency
- The evidence connecting the vulnerability to the application
- The selected remediation and the reason for choosing it
- The exact files and dependency versions changed
- Test results before and after the change, where available
- The results of post-fix vulnerability analysis
- Whether the previously identified vulnerable path remains reachable
- Any remaining uncertainty, compatibility concerns, or failed checks

The long-term goal is to create a **proof-carrying remediation**: a proposed change accompanied by reproducible evidence about what was checked and what the checks established.

ACSA must not claim that a vulnerability is fixed merely because a dependency version changed or a test suite passed. Each conclusion must be supported by the corresponding verification evidence.

### 3.5 Uncertainty-Guided Analysis — Planned

Static analysis cannot always establish a definitive answer.

For example, a dependency may be loaded through a dynamic import whose target depends on runtime configuration.

Instead of treating an inconclusive result as safe, ACSA will preserve the `UNKNOWN` verdict and identify the missing evidence.

A future version could suggest additional checks, such as running a relevant route with synthetic inputs in an isolated test environment.

Any dynamic testing must be explicitly scoped and safely isolated. A suggested probe is not proof of exposure or safety until the required evidence has actually been collected and evaluated.

---

## 4. Verdict Vocabulary

ACSA uses explicit verdicts to distinguish established evidence from unresolved questions.

| Verdict | Meaning |
|---|---|
| `PROVEN_EXPOSURE` | Evidence establishes that a relevant vulnerable execution path is exposed through the analyzed application context. |
| `PROVEN_AFFECTED` | Evidence establishes that the vulnerability affects the analyzed artifact, without necessarily proving external exploitability. |
| `POTENTIALLY_AFFECTED` | The available evidence indicates a possible impact, but uncertainty remains. |
| `PROVEN_NOT_AFFECTED` | Sufficient evidence establishes that the analyzed artifact and scope are not affected under the evaluated conditions. |
| `UNKNOWN` | The available evidence is insufficient to reach a reliable conclusion. |
| `CONTRADICTORY` | Relevant inventory or analysis sources contain unresolved conflicts. |
| `NOT_VERIFIED` | A proposed remediation has not completed the required post-fix verification. |

> **Critical principle: `UNKNOWN` does not mean `SAFE`.**

Likewise, a passing test suite alone does not prove that a vulnerability has been eliminated. ACSA must distinguish between tests that passed, security checks that passed, and conclusions that remain unverified.

---

## 5. Implementation Roadmap

| Phase | Focus | Status |
|---|---|---|
| Phase 0 | Engineering foundation, domain models, evidence graph, API, CLI, safety controls, and tests | Implemented |
| Phase 1 | Manifest, lockfile, and SBOM ingestion and inventory reconciliation | Planned |
| Phase 2 | Vulnerability intelligence, OSV integration, and version applicability | Planned |
| Phase 3 | JavaScript/TypeScript reachability analysis | Planned |
| Phase 4 | Context analysis, evidence fusion, and security verdicts | Planned |
| Phase 5 | Remediation selection, fix validation, post-fix analysis, and proof-carrying pull requests | Planned |

The roadmap separates current implementation from future goals. Each phase must be implemented and tested before its capabilities are presented as operational.

---

## 6. Planned Remediation Workflow

The remediation stage will investigate the following workflow:

```text
       Relevant Vulnerability
                 |
                 v
       Identify Possible Fixes
                 |
                 v
       Compare Remediation Options
                 |
                 v
      Select a Suitable Candidate
                 |
                 v
       Apply in an Isolated Workspace
                 |
                 v
       Run Available Application Tests
                 |
                 v
      Re-run Vulnerability Analysis
                 |
                 v
       Re-check Vulnerable Path
                 |
                 v
        Collect Verification Evidence
                 |
                 v
       Generate Reviewable Fix Report
                 |
                 v
      Developer Reviews and Approves
```

A candidate that fails required checks should not be presented as a verified fix. If checks are inconclusive, the result should remain unverified and explain what is missing.

### How could this help developers accept fixes?

Rather than asking a developer to trust a generic automated pull request, ACSA aims to provide a reviewable explanation:

- Why was this change recommended?
- Why was this candidate selected over other options?
- Which files and dependencies changed?
- Which tests ran, and what were their results?
- Was the original vulnerability rechecked?
- Does the previously identified exposure path remain?
- What risks or uncertainties remain?

The intended benefit is to reduce the effort needed to understand and review a proposed security fix. Developer acceptance is a goal to evaluate through real feedback, not something the system can guarantee.

---

## 7. Technical Architecture

The project is being developed with a modular architecture.

- **Language:** Python 3.11+
- **Target repositories:** JavaScript/TypeScript and npm
- **API:** FastAPI
- **CLI:** Typer
- **Domain models:** Pydantic
- **Vulnerability intelligence:** Open Source Vulnerabilities (OSV) database/API
- **Testing:** pytest
- **Code quality:** Ruff and mypy

The architecture separates repository ingestion, inventory reconciliation, vulnerability analysis, reachability, evidence evaluation, and remediation so that each stage can be tested independently.

### Security Boundaries

ACSA is intended to analyze untrusted third-party repositories safely.

Important safeguards include:

- Keeping credentials out of frontend interfaces
- Redacting secrets from logs
- Validating repository paths and preventing path traversal
- Isolating analysis workspaces
- Applying file-size limits and execution timeouts
- Avoiding arbitrary execution of target repository code
- Blocking npm lifecycle scripts during repository analysis

Any future remediation or test-execution functionality must maintain appropriate isolation and must not execute untrusted code without explicit sandboxing and resource controls.

---

## 8. Current Implementation Status

**Implemented: Phase 0 — Engineering Foundation**

- Project packaging and modular structure
- Typed domain models for repositories, components, vulnerabilities, findings, verdicts, evidence, contradictions, remediation candidates, verification results, and proof artifacts
- Verdict safety invariants
- Directed evidence graph with reachability operations and deterministic SHA-256 digests
- FastAPI health endpoint
- Typer CLI commands for version, status, and pipeline plan
- Path validation and workspace isolation primitives
- Secret masking in logs
- Test suite and GitHub Actions workflow

**Planned: Subsequent phases**

- [ ] Phase 1: Parse manifests, lockfiles, and SBOMs.
- [ ] Phase 2: Integrate OSV and reconcile vulnerability applicability.
- [ ] Phase 3: Implement JavaScript/TypeScript reachability analysis.
- [ ] Phase 4: Implement context analysis and evidence-backed verdicts.
- [ ] Phase 5: Implement remediation selection, isolated fix validation, post-fix security analysis, and reviewable remediation reports or pull requests.

The domain models and foundation primitives support the planned architecture; they do not mean the corresponding end-to-end analysis or remediation capabilities are already implemented.

---

## 9. How We Will Evaluate ACSA

A successful prototype should demonstrate more than the ability to find vulnerabilities.

Planned evaluation criteria include:

1. **Inventory accuracy:** Can ACSA identify and preserve disagreements between dependency sources?
2. **Reachability accuracy:** Can it distinguish a reachable vulnerable function from one it cannot establish as reachable?
3. **Uncertainty handling:** Does it preserve inconclusive cases instead of incorrectly marking them safe?
4. **Remediation suitability:** Does the proposed fix address the specific vulnerability while limiting unnecessary changes?
5. **Regression checks:** Do the available tests continue to pass after the change?
6. **Post-fix verification:** Does re-analysis establish that the original vulnerability or exposure path has been addressed?
7. **Developer usefulness:** Can a developer understand the recommendation and its supporting evidence well enough to review the change?

Results should be measured on a set of reproducible test repositories or deliberately designed benchmark applications. Any claims about reduced alert volume, remediation success, or developer acceptance should be supported by measured results.

---

## 10. Project Vision

ACSA aims to connect vulnerability detection with evidence-driven remediation.

Instead of stopping at a report that says a dependency is vulnerable, the long-term goal is to help answer:

- Does this vulnerability affect my application?
- What evidence establishes its exposure?
- What is a suitable way to remove the risk?
- Did the proposed fix pass the checks we ran?
- What evidence supports the post-fix conclusion?
- What still needs human review?

**Our goal is not simply to generate more security alerts or automatically modify dependencies. It is to help developers make safer, better-informed remediation decisions.**

> **ACSA — Don't just detect vulnerabilities. Prove their exposure. Find the fix. Verify the result.**
