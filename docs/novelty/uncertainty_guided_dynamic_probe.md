# Supporting Novelty: Uncertainty-Guided Dynamic Probe

## Executive Overview
Static analysis is powerful, but has fundamental theoretical and practical limits:
- Dynamic module resolution (`require(variable)` or `import(computedPath)`).
- Runtime reflection, `eval()`, and prototype manipulation.
- Conditional branches gated on complex external environment configurations.

When static analysis encounters these constructs, traditional tools either hallucinate a high-severity alert (causing false alarms) or silently ignore the path (creating false negatives).

**ACSA's philosophy: `UNKNOWN` is not `SAFE`. Instead, ACSA generates targeted dynamic probes to gather the missing runtime evidence.**

---

## How Dynamic Probing Works

```
[ Static Analysis Engine ]
          │
          ▼
   Dynamic Import /
  Ambiguous Branch?
          │
      YES │
          ▼
   Assign UNKNOWN
          │
          ▼
[ Dynamic Probe Planner ]
  - Identify relevant HTTP entry point / route
  - Generate minimum synthetic payload
  - Instrument module resolution hook
          │
          ▼
[ Isolated Probe Execution ]
  - Observe whether vulnerable symbol is loaded/executed
          │
          ▼
[ Re-synthesize Verdict ]
  - Update verdict to PROVEN_EXPOSURE or PROVEN_NOT_AFFECTED with dynamic evidence attached
```

---

## Security Boundaries for Dynamic Probes
Because executing untrusted repository code presents severe security risks, dynamic probes are bound by strict sandboxing rules:
1. **Isolated Ephemeral Workspaces**: Probes only execute inside temporary throwaway containers or isolated sandboxes.
2. **Never Execute Lifecycle Scripts**: Automatic execution of `preinstall`, `postinstall`, or build scripts is strictly prohibited.
3. **Hard Timeouts and Resource Quotas**: Probe executions are limited by strict time caps (e.g., 10 seconds) and memory limits.
