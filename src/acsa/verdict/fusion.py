from __future__ import annotations

import logging
from collections import defaultdict
from typing import TYPE_CHECKING

from acsa.context.models import AttackerControlStatus
from acsa.evidence.graph import EvidenceGraph
from acsa.evidence.models import Evidence, EvidenceEdge, EvidenceNode, EvidenceSource
from acsa.inventory.models import CanonicalInventory
from acsa.reachability.models import ReachabilityState
from acsa.verdict.vocabulary import Verdict
from acsa.vulnerability.models import ApplicabilityStatus

if TYPE_CHECKING:
    from acsa.vulnerability.models import Finding

logger = logging.getLogger(__name__)


class EvidenceFusionEngine:
    """Combines multi-phase evidence to produce definitive, evidence-backed security verdicts."""

    def fuse(
        self,
        inventory: CanonicalInventory,
        findings: list[Finding],
        graph: EvidenceGraph | None = None,
    ) -> tuple[list[Finding], list[Evidence], EvidenceGraph]:
        """Apply explicit, deterministic verdict rules and contradiction reconciliation.

        Returns:
            Tuple of (fused_findings, new_fusion_evidence, extended_evidence_graph)
        """
        evidence_graph = graph or EvidenceGraph()
        fusion_evidence: list[Evidence] = []

        # 1. Group findings by package name to check for multi-source contradictions
        findings_by_package: dict[str, list[Finding]] = defaultdict(list)
        for f in findings:
            findings_by_package[f.component.name].append(f)

        fused_findings: list[Finding] = []

        for pkg_name, pkg_findings in findings_by_package.items():
            # Check for contradiction: do different observations produce conflicting security conclusions?
            # Example: one observation is AFFECTED, another observation is NOT_AFFECTED
            has_affected = any(
                f.applicability_status == ApplicabilityStatus.AFFECTED for f in pkg_findings
            )
            has_not_affected = any(
                f.applicability_status == ApplicabilityStatus.NOT_AFFECTED for f in pkg_findings
            )
            # Distinct versions observed
            distinct_versions = {f.component.version for f in pkg_findings if f.component.version}

            is_contradictory = has_affected and has_not_affected and len(distinct_versions) > 1

            if is_contradictory:
                # Contradiction detected across artifact observations!
                # Identify artifacts, observed versions, and OSV results
                obs_details: list[dict[str, str | None]] = []
                for f in pkg_findings:
                    obs_details.append(
                        {
                            "artifact": f.source_artifact_path or "manifest",
                            "version": f.component.version,
                            "applicability": f.applicability_status.value,
                            "advisory_id": f.vulnerability.id,
                        }
                    )

                contradiction_desc = (
                    f"Contradictory inventory observations for '{pkg_name}': "
                    + ", ".join(
                        f"{d['artifact']} ({d['version']} -> {d['applicability']})"
                        for d in obs_details
                    )
                )

                ev = Evidence(
                    source=EvidenceSource.ARTIFACT_INSPECTION,
                    description=contradiction_desc,
                    confidence=1.0,
                    data={
                        "package": pkg_name,
                        "contradiction": True,
                        "observations": obs_details,
                    },
                )
                fusion_evidence.append(ev)

                # Annotate each finding with CONTRADICTORY verdict and evidence
                for f in pkg_findings:
                    combined_ev_ids = list(f.evidence_ids)
                    if ev.id not in combined_ev_ids:
                        combined_ev_ids.append(ev.id)

                    fused_f = f.model_copy(
                        update={
                            "verdict": Verdict.CONTRADICTORY,
                            "notes": contradiction_desc,
                            "evidence_ids": combined_ev_ids,
                        }
                    )
                    fused_findings.append(fused_f)
                    self._attach_verdict_to_graph(evidence_graph, fused_f, [ev.id])

            else:
                # No contradiction: apply deterministic logical verdict rules per finding
                for f in pkg_findings:
                    fused_f, new_evs = self._evaluate_finding_verdict(f)
                    fusion_evidence.extend(new_evs)
                    fused_findings.append(fused_f)
                    self._attach_verdict_to_graph(
                        evidence_graph, fused_f, [ev.id for ev in new_evs]
                    )

        return fused_findings, fusion_evidence, evidence_graph

    def _evaluate_finding_verdict(
        self, finding: Finding
    ) -> tuple[Finding, list[Evidence]]:
        """Evaluate deterministic verdict rules for an individual finding."""
        app_status = finding.applicability_status
        reach = finding.reachability
        ctx = finding.context

        verdict: Verdict
        notes: str
        confidence: float = 0.5

        uncertainty_reason: str | None = None
        missing_evidence: str | None = None

        # Rule 1: OSV says version not affected -> PROVEN_NOT_AFFECTED
        if app_status == ApplicabilityStatus.NOT_AFFECTED:
            verdict = Verdict.PROVEN_NOT_AFFECTED
            notes = (
                f"Concrete version {finding.component.version} is outside vulnerable ranges; "
                f"proven safe against {finding.vulnerability.id}."
            )
            confidence = 1.0

        # Rule 2: OSV says exact version affected
        elif app_status == ApplicabilityStatus.AFFECTED:
            # Check reachability
            if reach and reach.status == ReachabilityState.REACHABLE:
                # Check context / attacker control
                if ctx and ctx.status == AttackerControlStatus.CONFIRMED:
                    verdict = Verdict.PROVEN_EXPOSURE
                    flow_summary = " -> ".join(ctx.data_flow_path) if ctx.data_flow_path else ""
                    notes = (
                        f"Vulnerable symbol '{reach.target_symbol}' is reachable from application entry point "
                        f"and exposed to attacker-controlled input ({flow_summary})."
                    )
                    confidence = 0.95
                elif ctx and ctx.status == AttackerControlStatus.UNKNOWN:
                    verdict = Verdict.UNKNOWN
                    notes = (
                        f"Vulnerable symbol '{reach.target_symbol}' is reachable, but attacker control is "
                        f"unknown due to dynamic data flow ({ctx.uncertainty_reason}). UNKNOWN != SAFE."
                    )
                    uncertainty_reason = ctx.uncertainty_reason
                    missing_evidence = ctx.missing_evidence or "Runtime observation of input flow is required"
                    confidence = 0.4
                else:
                    # Attacker control NOT_ESTABLISHED
                    verdict = Verdict.POTENTIALLY_AFFECTED
                    notes = (
                        f"Vulnerable symbol '{reach.target_symbol}' is reachable from internal helper, "
                        f"but no external attacker-controlled input source was established."
                    )
                    confidence = 0.85

            elif reach and reach.status == ReachabilityState.NOT_REACHABLE:
                # Vulnerable symbol proven not reachable
                verdict = Verdict.PROVEN_AFFECTED
                sym_str = f"vulnerable symbol '{reach.target_symbol}'" if reach.target_symbol else "vulnerable routines"
                notes = (
                    f"Component '{finding.component.name}' installed version ({finding.component.version}) is affected by advisory "
                    f"{finding.vulnerability.id}, but {sym_str} is proven not reachable in application source code. "
                    "Component applicability confirms installed version vulnerability only; application exposure is not established."
                )
                confidence = 0.95

            else:
                # Reachability is UNKNOWN
                verdict = Verdict.UNKNOWN
                reason = reach.uncertainty_reason if reach else "Reachability not evaluated"
                notes = f"Advisory is applicable, but reachability is unknown: {reason}. UNKNOWN != SAFE."
                uncertainty_reason = reason
                missing_evidence = (
                    reach.missing_evidence
                    if reach and reach.missing_evidence
                    else "Resolution of reachability or dynamic symbol access is required"
                )
                confidence = 0.4

        else:
            # Applicability is UNKNOWN or insufficient evidence
            verdict = Verdict.UNKNOWN
            notes = "Advisory applicability could not be deterministically evaluated (UNKNOWN != SAFE)."
            uncertainty_reason = "Advisory applicability could not be deterministically evaluated"
            missing_evidence = "Machine-readable package version bounds from advisory are required"
            confidence = 0.3

        ev = Evidence(
            source=EvidenceSource.MANUAL_ASSERTION,
            description=f"ACSA Evidence Fusion Verdict: {verdict.value} - {notes}",
            confidence=confidence,
            data={
                "finding_id": finding.id,
                "advisory_id": finding.vulnerability.id,
                "package": finding.component.name,
                "version": finding.component.version,
                "verdict": verdict.value,
                "applicability": app_status.value,
                "reachability": reach.status.value if reach else None,
                "attacker_control": ctx.status.value if ctx else None,
                "uncertainty_reason": uncertainty_reason,
                "missing_evidence": missing_evidence,
            },
        )

        combined_ev_ids = list(finding.evidence_ids)
        if ev.id not in combined_ev_ids:
            combined_ev_ids.append(ev.id)

        fused_finding = finding.model_copy(
            update={
                "verdict": verdict,
                "notes": notes,
                "confidence": confidence,
                "evidence_ids": combined_ev_ids,
                "uncertainty_reason": uncertainty_reason,
                "missing_evidence": missing_evidence,
            }
        )
        return fused_finding, [ev]

    def _attach_verdict_to_graph(
        self,
        graph: EvidenceGraph,
        finding: Finding,
        new_evidence_ids: list[str],
    ) -> None:
        """Extend the EvidenceGraph with full end-to-end provenance edges.

        Complete Chain:
        artifact -> component/version -> OSV vulnerability -> vulnerable symbol ->
        source file -> HTTP entry point -> attacker-controlled input ->
        local variable / helper -> vulnerable function call -> verdict
        """
        comp_name = finding.component.name
        ver_str = finding.component.version or "unknown"
        vuln_id = finding.vulnerability.id
        artifact_path = finding.source_artifact_path or "package-lock.json"
        reach = finding.reachability
        ctx = finding.context

        # 1. Artifact Node
        art_node_id = f"art:{artifact_path}"
        if art_node_id not in graph.nodes:
            graph.add_node(
                EvidenceNode(
                    id=art_node_id,
                    node_type="artifact",
                    label=artifact_path,
                    properties={"artifact_path": artifact_path},
                )
            )

        # 2. Component Node
        comp_node_id = f"comp:{comp_name}@{ver_str}"
        if comp_node_id not in graph.nodes:
            graph.add_node(
                EvidenceNode(
                    id=comp_node_id,
                    node_type="component",
                    label=f"{comp_name}@{ver_str}",
                    properties={"package": comp_name, "version": ver_str},
                )
            )
        # Edge: Artifact -> Component
        graph.add_edge(
            EvidenceEdge(
                source=art_node_id,
                target=comp_node_id,
                relationship="declares",
                evidence_ids=finding.evidence_ids[:1],
                weight=1.0,
            )
        )

        # 3. OSV Advisory Node
        osv_node_id = f"osv:{vuln_id}"
        if osv_node_id not in graph.nodes:
            graph.add_node(
                EvidenceNode(
                    id=osv_node_id,
                    node_type="osv_advisory",
                    label=vuln_id,
                    properties={"advisory_id": vuln_id},
                )
            )
        # Edge: Component -> OSV
        graph.add_edge(
            EvidenceEdge(
                source=comp_node_id,
                target=osv_node_id,
                relationship="matches_advisory",
                evidence_ids=finding.evidence_ids[:1],
                weight=1.0,
            )
        )

        # 4. Final Verdict Node
        verdict_node_id = f"verdict:{finding.id}"
        graph.add_node(
            EvidenceNode(
                id=verdict_node_id,
                node_type="verdict",
                label=finding.verdict.value,
                properties={
                    "verdict": finding.verdict.value,
                    "confidence": finding.confidence,
                    "finding_id": finding.id,
                    "reason": finding.notes,
                    "uncertainty_reason": finding.uncertainty_reason,
                    "missing_evidence": finding.missing_evidence,
                },
            )
        )

        # If exposure established with HTTP route and Input source
        if ctx and ctx.status == AttackerControlStatus.CONFIRMED and ctx.source and reach:
            target_symbol = reach.target_symbol or (
                finding.vulnerability.vulnerable_symbols[0]
                if finding.vulnerability.vulnerable_symbols
                else "default"
            )

            # 4. Vulnerable Symbol Node
            sym_node_id = f"sym:{comp_name}.{target_symbol}"
            if sym_node_id not in graph.nodes:
                graph.add_node(
                    EvidenceNode(
                        id=sym_node_id,
                        node_type="vulnerable_symbol",
                        label=f"{comp_name}.{target_symbol}",
                        properties={"symbol": target_symbol, "package": comp_name},
                    )
                )
            # Edge: OSV -> Symbol
            graph.add_edge(
                EvidenceEdge(
                    source=osv_node_id,
                    target=sym_node_id,
                    relationship="defines_symbol",
                    evidence_ids=finding.evidence_ids[:1],
                    weight=1.0,
                )
            )

            # 5. Source File Node
            source_loc_str = str(ctx.source.location)
            src_node_id = f"file:{source_loc_str}"
            if src_node_id not in graph.nodes:
                graph.add_node(
                    EvidenceNode(
                        id=src_node_id,
                        node_type="source_file",
                        label=source_loc_str,
                        properties={"location": source_loc_str},
                    )
                )
            # Edge: Symbol -> Source File
            graph.add_edge(
                EvidenceEdge(
                    source=sym_node_id,
                    target=src_node_id,
                    relationship="located_in",
                    evidence_ids=finding.evidence_ids[:1],
                    weight=1.0,
                )
            )

            # 6. HTTP Entry Node
            entry_name = ctx.entry_point or "HTTP Entry"
            entry_node_id = f"http:{entry_name}"
            if entry_node_id not in graph.nodes:
                graph.add_node(
                    EvidenceNode(
                        id=entry_node_id,
                        node_type="entry_point",
                        label=entry_name,
                        properties={"entry_point": entry_name},
                    )
                )
            # Edge: Source File -> HTTP Entry
            graph.add_edge(
                EvidenceEdge(
                    source=src_node_id,
                    target=entry_node_id,
                    relationship="defines_route",
                    evidence_ids=finding.evidence_ids[:1],
                    weight=1.0,
                )
            )

            # 7. Input Source Node
            input_expr = ctx.source.expression
            input_node_id = f"input:{input_expr}"
            if input_node_id not in graph.nodes:
                graph.add_node(
                    EvidenceNode(
                        id=input_node_id,
                        node_type="input_source",
                        label=input_expr,
                        properties={"expression": input_expr, "source_type": ctx.source.source_type.value},
                    )
                )
            # Edge: HTTP Entry -> Input Source
            graph.add_edge(
                EvidenceEdge(
                    source=entry_node_id,
                    target=input_node_id,
                    relationship="receives_input",
                    evidence_ids=finding.evidence_ids[:1],
                    weight=1.0,
                )
            )

            # 8. Local Variable / Helper Node (if intermediate propagation step exists)
            last_flow_node_id = input_node_id
            for step in ctx.data_flow_steps:
                if step.step_type in ("variable_assignment", "parameter_passing"):
                    step_node_id = f"flow:{step.expression}"
                    if step_node_id not in graph.nodes:
                        graph.add_node(
                            EvidenceNode(
                                id=step_node_id,
                                node_type="data_flow",
                                label=step.expression,
                                properties={"step_type": step.step_type, "expression": step.expression},
                            )
                        )
                    graph.add_edge(
                        EvidenceEdge(
                            source=last_flow_node_id,
                            target=step_node_id,
                            relationship="propagates_to",
                            evidence_ids=finding.evidence_ids[:1],
                            weight=1.0,
                        )
                    )
                    last_flow_node_id = step_node_id

            # 9. Vulnerable Function Call / Sink Node
            sink_str = ctx.sink or f"{comp_name}.{reach.target_symbol}()"
            sink_node_id = f"sink:{sink_str}"
            if sink_node_id not in graph.nodes:
                graph.add_node(
                    EvidenceNode(
                        id=sink_node_id,
                        node_type="sink_call",
                        label=sink_str,
                        properties={"sink": sink_str},
                    )
                )
            # Edge: Last Flow Step -> Function Call
            graph.add_edge(
                EvidenceEdge(
                    source=last_flow_node_id,
                    target=sink_node_id,
                    relationship="flows_to",
                    evidence_ids=finding.evidence_ids[:1],
                    weight=1.0,
                )
            )

            # 10. Edge: Function Call -> Verdict
            graph.add_edge(
                EvidenceEdge(
                    source=sink_node_id,
                    target=verdict_node_id,
                    relationship="yields_verdict",
                    evidence_ids=new_evidence_ids,
                    weight=1.0,
                )
            )

        elif reach and reach.status == ReachabilityState.REACHABLE:
            # Reachable without attacker control
            target_symbol = reach.target_symbol or (
                finding.vulnerability.vulnerable_symbols[0]
                if finding.vulnerability.vulnerable_symbols
                else "default"
            )
            sym_node_id = f"sym:{comp_name}.{target_symbol}"
            if sym_node_id not in graph.nodes:
                graph.add_node(
                    EvidenceNode(
                        id=sym_node_id,
                        node_type="vulnerable_symbol",
                        label=f"{comp_name}.{target_symbol}",
                        properties={"symbol": target_symbol, "package": comp_name},
                    )
                )
            graph.add_edge(
                EvidenceEdge(
                    source=osv_node_id,
                    target=sym_node_id,
                    relationship="defines_symbol",
                    evidence_ids=finding.evidence_ids[:1],
                    weight=1.0,
                )
            )

            sink_str = f"{comp_name}.{reach.target_symbol}()"
            sink_node_id = f"sink:{sink_str}"
            if sink_node_id not in graph.nodes:
                graph.add_node(
                    EvidenceNode(
                        id=sink_node_id,
                        node_type="sink_call",
                        label=sink_str,
                        properties={"sink": sink_str},
                    )
                )
            graph.add_edge(
                EvidenceEdge(
                    source=sym_node_id,
                    target=sink_node_id,
                    relationship="reaches",
                    evidence_ids=finding.evidence_ids[:1],
                    weight=1.0,
                )
            )
            graph.add_edge(
                EvidenceEdge(
                    source=sink_node_id,
                    target=verdict_node_id,
                    relationship="yields_verdict",
                    evidence_ids=new_evidence_ids,
                    weight=1.0,
                )
            )

        else:
            # Not reachable / not affected / contradictory / unknown
            graph.add_edge(
                EvidenceEdge(
                    source=osv_node_id,
                    target=verdict_node_id,
                    relationship="yields_verdict",
                    evidence_ids=new_evidence_ids,
                    weight=1.0,
                )
            )
