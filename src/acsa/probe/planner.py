"""Uncertainty-Guided Dynamic Probe Planner."""

import logging
from typing import Any

from acsa.context.models import AttackerControlStatus
from acsa.evidence.graph import EvidenceGraph
from acsa.evidence.models import EvidenceEdge, EvidenceNode
from acsa.probe.models import ProbeSpecification, ProbeType
from acsa.probe.templates import ProbeTemplateFactory
from acsa.reachability.models import ReachabilityState
from acsa.verdict.vocabulary import Verdict
from acsa.vulnerability.models import Finding, VulnerabilityScanResult

logger = logging.getLogger(__name__)

SEVERITY_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "MODERATE": 2,
    "LOW": 3,
    "UNKNOWN": 4,
}

PROBE_TYPE_PRIORITY: dict[ProbeType, int] = {
    ProbeType.HTTP_INPUT_TO_SINK: 0,
    ProbeType.ROUTE_EXECUTION: 1,
    ProbeType.SYMBOL_INVOCATION: 2,
    ProbeType.MODULE_RESOLUTION: 3,
    ProbeType.DEPENDENCY_VERSION_CONFIRMATION: 4,
}


class ProbePlanner:
    """Analyzes UNKNOWN findings and generates safe, targeted dynamic probe specifications."""

    @classmethod
    def plan_for_finding(
        cls,
        finding: Finding,
        graph: EvidenceGraph | None = None,
    ) -> ProbeSpecification | None:
        """Inspect an individual finding and generate a ProbeSpecification if uncertain."""
        # Only plan probes when there is genuine uncertainty or missing evidence
        is_unknown = (
            finding.verdict == Verdict.UNKNOWN
            or (finding.reachability and finding.reachability.status == ReachabilityState.UNKNOWN)
            or (finding.context and finding.context.status == AttackerControlStatus.UNKNOWN)
            or bool(finding.uncertainty_reason)
            or bool(finding.missing_evidence)
        )

        if not is_unknown:
            return None

        comp_name = finding.component.name
        reach = finding.reachability
        ctx = finding.context

        # Extract entry point, target symbol, input source
        entry_point: str | None = None
        target_symbol: str | None = None
        input_source: str | None = None

        if reach:
            entry_point = reach.entry_point
            target_symbol = reach.target_symbol
        if ctx:
            if ctx.entry_point and not entry_point:
                entry_point = ctx.entry_point
            if ctx.source:
                input_source = ctx.source.expression

        # Formulate base uncertainty reason
        uncertainty = (
            finding.uncertainty_reason
            or (reach and reach.uncertainty_reason)
            or (finding.notes and "UNKNOWN" in finding.notes and finding.notes)
            or "Static analysis could not establish definitive call or data flow."
        )

        # Categorize probe type
        probe_data: dict[str, Any]
        unc_lower = uncertainty.lower()

        # 1. Dynamic require / dynamic import -> MODULE_RESOLUTION
        if (
            "dynamic require" in unc_lower
            or "require(" in unc_lower
            or "dynamic import" in unc_lower
            or "computed specifier" in unc_lower
            or "unresolved module" in unc_lower
        ):
            probe_data = ProbeTemplateFactory.module_resolution(
                component=comp_name,
                entry_point=entry_point,
                uncertainty_reason=uncertainty,
            )

        # 2. HTTP Input to Sink -> HTTP_INPUT_TO_SINK
        # Triggered when HTTP input or entry point exists alongside a sink, but data flow is dynamic/unknown
        elif (
            (input_source or (ctx and ctx.source) or "input" in unc_lower or "helper" in unc_lower or "property" in unc_lower)
            and (target_symbol or entry_point)
            and (ctx is None or ctx.status == AttackerControlStatus.UNKNOWN or "dynamic" in unc_lower)
        ):
            probe_data = ProbeTemplateFactory.http_input_to_sink(
                component=comp_name,
                symbol=target_symbol,
                entry_point=entry_point,
                input_source=input_source or "req.body.template",
                uncertainty_reason=uncertainty,
            )

        # 3. Dynamic Route Registration -> ROUTE_EXECUTION
        elif (
            comp_name in ("express", "koa", "fastify", "connect", "router")
            or "route" in unc_lower
            or "middleware" in unc_lower
            or "handler callback" in unc_lower
        ):
            probe_data = ProbeTemplateFactory.route_execution(
                component=comp_name,
                entry_point=entry_point or "POST /render",
                uncertainty_reason=uncertainty,
            )

        # 4. Dependency Version Confirmation -> DEPENDENCY_VERSION_CONFIRMATION
        elif (
            "lockfile" in unc_lower
            or "unregenerated" in unc_lower
            or "unlocked" in unc_lower
            or "dependency resolution" in unc_lower
        ):
            probe_data = ProbeTemplateFactory.dependency_version_confirmation(
                component=comp_name,
                manifest_constraint=finding.component.version,
                uncertainty_reason=uncertainty,
            )

        # 5. Symbol Invocation -> SYMBOL_INVOCATION
        else:
            probe_data = ProbeTemplateFactory.symbol_invocation(
                component=comp_name,
                symbol=target_symbol,
                entry_point=entry_point,
                uncertainty_reason=uncertainty,
            )

        # Assemble specification
        spec = ProbeSpecification(
            finding_id=finding.id,
            probe_type=ProbeType(str(probe_data["probe_type"])),
            target_component=comp_name,
            target_symbol=target_symbol,
            entry_point=entry_point,
            input_source=input_source,
            uncertainty_reason=uncertainty,
            missing_evidence=str(probe_data["missing_evidence"]),
            required_observation=str(probe_data["required_observation"]),
            success_condition=str(probe_data["success_condition"]),
            failure_condition=str(probe_data["failure_condition"]),
            safety_constraints=ProbeTemplateFactory.default_safety_constraints(),
            expected_verdict_if_confirmed=Verdict(str(probe_data["expected_verdict_if_confirmed"])),
            expected_verdict_if_not_confirmed=Verdict(str(probe_data["expected_verdict_if_not_confirmed"])),
            metadata={
                "vulnerability_id": finding.vulnerability.id,
                "advisory_summary": finding.vulnerability.summary,
            },
        )

        # Register in EvidenceGraph if provided
        if graph:
            cls._register_probe_in_graph(finding, spec, graph)

        return spec

    @classmethod
    def _register_probe_in_graph(
        cls,
        finding: Finding,
        spec: ProbeSpecification,
        graph: EvidenceGraph,
    ) -> None:
        """Add UNKNOWN -> MISSING_EVIDENCE -> PROBE_SPECIFICATION provenance chain to EvidenceGraph."""
        # 1. UNKNOWN Node
        unknown_node_id = f"verdict_unknown:{finding.id}"
        if not graph.get_node(unknown_node_id):
            graph.add_node(
                EvidenceNode(
                    id=unknown_node_id,
                    node_type="finding_verdict",
                    label=f"UNKNOWN: {finding.component.name}",
                    properties={
                        "finding_id": finding.id,
                        "verdict": finding.verdict.value,
                        "component": finding.component.name,
                    },
                )
            )

        # 2. MISSING_EVIDENCE Node
        missing_node_id = f"missing_evidence:{spec.probe_id}"
        graph.add_node(
            EvidenceNode(
                id=missing_node_id,
                node_type="missing_evidence",
                label=f"MISSING: {spec.probe_type.value}",
                properties={
                    "missing_evidence": spec.missing_evidence,
                    "uncertainty_reason": spec.uncertainty_reason,
                    "finding_id": finding.id,
                },
            )
        )

        # Edge: UNKNOWN -> MISSING_EVIDENCE
        graph.add_edge(
            EvidenceEdge(
                source=unknown_node_id,
                target=missing_node_id,
                relationship="requires",
                properties={"finding_id": finding.id},
            )
        )

        # 3. PROBE_SPECIFICATION Node
        probe_node_id = f"probe_spec:{spec.probe_id}"
        graph.add_node(
            EvidenceNode(
                id=probe_node_id,
                node_type="probe_specification",
                label=f"PROBE_{spec.probe_type.value}: {spec.target_component}",
                properties={
                    "probe_id": spec.probe_id,
                    "probe_type": spec.probe_type.value,
                    "target_symbol": spec.target_symbol or "",
                    "entry_point": spec.entry_point or "",
                },
            )
        )

        # Edge: MISSING_EVIDENCE -> PROBE_SPECIFICATION
        graph.add_edge(
            EvidenceEdge(
                source=missing_node_id,
                target=probe_node_id,
                relationship="addressed_by",
                properties={"probe_id": spec.probe_id},
            )
        )

    @classmethod
    def prioritize_probes(
        cls,
        probes: list[ProbeSpecification],
        finding_map: dict[str, Finding],
    ) -> list[ProbeSpecification]:
        """Rank probes deterministically without arbitrary numeric scores.

        Ordering dimensions:
        1. Criticality / Severity of finding
        2. Proximity to attacker input
        3. Proximity to vulnerable sink
        4. Ability to resolve final verdict
        5. Component name (alphabetical)
        6. Finding ID (alphabetical)
        """
        def sort_key(p: ProbeSpecification) -> tuple[int, int, int, int, str, str]:
            finding = finding_map.get(p.finding_id)
            sev_str = "UNKNOWN"
            if finding and finding.vulnerability.severity:
                sev_str = str(finding.vulnerability.severity).upper()

            # 1. Criticality rank
            crit_rank = SEVERITY_ORDER.get(sev_str, 4)

            # 2. Input proximity rank
            if p.input_source and p.entry_point:
                input_rank = 0
            elif p.entry_point:
                input_rank = 1
            else:
                input_rank = 2

            # 3. Sink proximity rank
            sink_rank = 0 if p.target_symbol else 1

            # 4. Probe type priority
            type_rank = PROBE_TYPE_PRIORITY.get(p.probe_type, 5)

            # 5. Deterministic tie-breakers
            return (crit_rank, input_rank, sink_rank, type_rank, p.target_component, p.finding_id)

        sorted_probes = sorted(probes, key=sort_key)

        # Assign priority rank (1-indexed)
        ranked_probes: list[ProbeSpecification] = []
        for idx, p in enumerate(sorted_probes, start=1):
            ranked_p = p.model_copy(update={"priority_rank": idx})
            ranked_probes.append(ranked_p)

        return ranked_probes

    @classmethod
    def plan_for_scan_result(
        cls,
        scan_result: VulnerabilityScanResult,
        graph: EvidenceGraph | None = None,
    ) -> list[ProbeSpecification]:
        """Generate a prioritized list of probe specifications across all findings in a scan."""
        finding_map = {f.id: f for f in scan_result.findings}
        raw_probes: list[ProbeSpecification] = []

        for finding in scan_result.findings:
            spec = cls.plan_for_finding(finding, graph=graph)
            if spec:
                raw_probes.append(spec)

        return cls.prioritize_probes(raw_probes, finding_map)
