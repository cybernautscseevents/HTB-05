# ACSA Phase 4: Context, Evidence Fusion & Verdict Analysis

## Overview

ACSA (Artifact-Centric Security Analysis) moves beyond superficial vulnerability alerts ("This package has a vulnerability") and simple call-graph queries ("The vulnerable symbol is called"). Phase 4 determines:

> **"Does the application expose a meaningful attacker-controlled path to the vulnerable functionality?"**

The pipeline synthesizes evidence across five progressive dimensions without fabricating exploitability:

```
Repository Artifacts
        |
        v
Canonical Inventory
        |
        v
Real OSV Intelligence
        |
        v
Exact Applicability
        |
        v
Static Reachability
        |
        v
Context (Attacker-Controlled Sources)
        |
        v
Evidence Fusion (Deterministic Logical Rules)
        |
        v
Authoritative Verdict
```

---

## 1. Exact Applicability

Applicability evaluates whether exact installed package versions identified from physical repository artifacts (`package-lock.json`, CycloneDX/SPDX SBOMs) match known advisory version ranges in the Open Source Vulnerability (OSV) database.

- **Exact Version Matching**: ACSA evaluates only exact resolved versions (e.g., `4.17.19`), ignoring declared semantic ranges (`^4.17.0`) to avoid false positives.
- **Applicability States**:
  - `APPLICABLE`: The exact installed version falls within the advisory's affected ranges.
  - `NOT_APPLICABLE`: The exact installed version is explicitly outside affected ranges or patched.
  - `UNKNOWN`: The advisory lacks machine-readable version boundaries.

---

## 2. Static Reachability

Static reachability inspects the application's JavaScript and TypeScript source code using AST parsing and call-graph resolution.

- **Symbol Extraction**: Vulnerable functions and symbols (e.g. `template`, `merge`, `parse`) are extracted from OSV advisories.
- **Reachability States**:
  - `REACHABLE`: A static call path exists from an application entry point or top-level source file to the vulnerable symbol.
  - `NOT_REACHABLE`: The package is imported or referenced, but the specific vulnerable symbol is not invoked anywhere in the call graph.
  - `UNKNOWN`: Reachability cannot be statically proven due to dynamic imports, computed member accesses (`obj[prop]`), or advisories lacking function/symbol metadata.

---

## 3. Context Analysis (Attacker-Controlled Inputs)

Context analysis inspects whether the vulnerable symbol invocation receives external input from recognized attacker-controlled sources:

- **Recognized Attacker Sources**:
  - Express.js: `req.body`, `req.query`, `req.params`, `req.headers`, `req.cookies`
  - Fastify: `request.body`, `request.query`, `request.params`, `request.headers`
  - HTTP / Web standards: incoming request callbacks, URL parameters
- **Conservative Data Flow**:
  - Direct flows: `lodash.template(req.body.template)`
  - Local variable propagation & destructuring: `const input = req.body.template; lodash.template(input)`
  - 1-hop function parameter propagation: `render(req.body.template)` -> `function render(tmpl) { lodash.template(tmpl); }`
- **Context States (`AttackerControlStatus`)**:
  - `CONFIRMED`: Static evidence demonstrates data flow from an external input source to the vulnerable sink.
  - `NOT_ESTABLISHED`: The vulnerable function is invoked using internal, static, or non-attacker data.
  - `UNKNOWN`: Complex dynamic flow, computed keys, or multi-hop inter-procedural propagation prevents static determination. Preserves `uncertainty_reason` and `missing_evidence`.

---

## 4. Evidence Fusion & Logical Verdict Rules

Evidence fusion combines all evidence layers using deterministic logical rules rather than arbitrary weighted scores:

| OSV Applicability | Static Reachability | Context / Attacker Control | Multi-Source Conflicts | Canonical Verdict | Meaning / Description |
|---|---|---|---|---|---|
| Applicable | `REACHABLE` | `CONFIRMED` | No | **`PROVEN_EXPOSURE`** | Static evidence confirms affected version, reachable symbol, and attacker-controlled input path. |
| Applicable | `REACHABLE` | `NOT_ESTABLISHED` | No | **`POTENTIALLY_AFFECTED`** | Component is affected and symbol is reachable, but attacker control is not established. |
| Applicable | `NOT_REACHABLE` | Any | No | **`PROVEN_AFFECTED`** | Exact version is affected, but static call-graph proves vulnerable symbol is not reachable. |
| Applicable | `UNKNOWN` | Any | No | **`UNKNOWN`** | Exact version is affected, but reachability is unknown (preserves uncertainty reason). |
| Applicable | `REACHABLE` | `UNKNOWN` | No | **`UNKNOWN`** | Vulnerable symbol is reachable, but dynamic flow prevents confirming attacker control. |
| Not Applicable | Any | Any | No | **`PROVEN_NOT_AFFECTED`** | Exact installed version is not affected by the advisory. |
| Any | Any | Any | Yes (e.g. SBOM affected vs lockfile safe) | **`CONTRADICTORY`** | Conflicting artifact observations yield materially divergent security conclusions. |
| Ambiguous / Unverified | Any | Any | No | **`NOT_VERIFIED`** | Insufficient evidence to establish applicability or truth. |

---

## 5. Authoritative Rules & Semantics

### `UNKNOWN != SAFE`
A verdict of `UNKNOWN` indicates incomplete evidence, dynamic language features, or lack of vulnerability symbol metadata. It must **never** be treated as safe or benign.

### Contradiction Preservation
If `package-lock.json` specifies `lodash@4.17.21` (unaffected) while an ingested `bom.json` specifies `lodash@4.17.19` (affected), ACSA preserves the conflict as `CONTRADICTORY` rather than silently collapsing or choosing the "most convenient" version.

### No Fabricated Exploitability
ACSA never claims exploitability without static evidence. Terminology is strictly conservative:
- `static evidence`
- `attacker-control evidence`
- `confidence/uncertainty`
- `potential exposure`
